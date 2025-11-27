import streamlit as st
import json
import secrets
import hashlib
from pathlib import Path
import gspread
from google.oauth2.service_account import Credentials
import os

# --- Configuración de página ---
st.set_page_config(
    page_title="Kapitaliza | CRM (Auth & GSheets test)",
    page_icon="💼",
    layout="wide",
)

# --- Paths y archivos ---
DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"

# --- Variables Google Sheets ---
USE_GSHEETS = True
GSHEET_ID = "1wD9D3OsSB4HXel1LIGo0h6xNdcjZEF-iHue-Hl4z1pg"

# --- Helpers de hashing (PBKDF2) ---
def _hash_pw_pbkdf2(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    if not salt_hex:
        salt_hex = secrets.token_hex(16)
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, 100_000)
    return salt_hex, dk.hex()

def _verify_pw(password: str, salt_hex: str, hash_hex: str) -> bool:
    _, hh = _hash_pw_pbkdf2(password, salt_hex)
    return secrets.compare_digest(hh, (hash_hex or ""))

# --- Usuarios (local simple + fallback) ---
def load_users() -> dict:
    """Carga usuarios desde `data/users.json` (estructura: {"users": [ {user, role, salt, hash} ]})"""
    try:
        if USERS_FILE.exists():
            return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {"users": []}

def save_users(obj: dict):
    try:
        USERS_FILE.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        st.error(f"Error guardando usuarios localmente: {e}")

def add_user(username: str, password: str, role: str = "member") -> tuple[bool, str]:
    uname = (username or "").strip()
    if not uname or not password:
        return False, "Usuario y contraseña obligatorios."
    if role not in ("admin", "member"):
        return False, "Rol inválido."
    data = load_users()
    # previene duplicado
    if any((u.get("user","") ).lower() == uname.lower() for u in data.get("users", [])):
        return False, "Ese usuario ya existe."
    salt_hex, hash_hex = _hash_pw_pbkdf2(password)
    data.setdefault("users", []).append({"user": uname, "role": role, "salt": salt_hex, "hash": hash_hex})
    save_users(data)
    return True, "Usuario creado."

def get_user(identifier: str) -> dict | None:
    ident = (identifier or "").strip().lower()
    data = load_users()
    for u in data.get("users", []):
        if (u.get("user","") or "").lower() == ident:
            return u
    return None

# --- Session state for auth ---
if "auth_user" not in st.session_state:
    st.session_state["auth_user"] = None

def current_user():
    return st.session_state.get("auth_user")

def do_rerun():
    try:
        if hasattr(st, "experimental_rerun"):
            st.experimental_rerun()
            return
    except Exception:
        pass
    # Fallback: toggle a key and stop
    st.session_state["_need_rerun"] = not st.session_state.get("_need_rerun", False)
    try:
        st.stop()
    except Exception:
        return

# --- Google Sheets credentials loader ---
_GS_CREDS = None

def _gs_credentials():
    """Carga credenciales desde `st.secrets` (si está) o desde `service_account.json` en workspace."""
    global _GS_CREDS
    if _GS_CREDS is not None:
        return _GS_CREDS
    # 1) Streamlit secrets
    try:
        if hasattr(st, "secrets") and isinstance(st.secrets, dict) and st.secrets:
            # buscar claves típicas del service account
            s = dict(st.secrets)
            if all(k in s for k in ("type","project_id","private_key_id","private_key")):
                sa = s
                sa["private_key"] = sa["private_key"].replace("\\n", "\n")
                scopes = ["https://www.googleapis.com/auth/spreadsheets"]
                _GS_CREDS = Credentials.from_service_account_info(sa, scopes=scopes)
                return _GS_CREDS
            if "service_account" in s and isinstance(s["service_account"], dict):
                sa = dict(s["service_account"])
                if "private_key" in sa:
                    sa["private_key"] = sa["private_key"].replace("\\n", "\n")
                scopes = ["https://www.googleapis.com/auth/spreadsheets"]
                _GS_CREDS = Credentials.from_service_account_info(sa, scopes=scopes)
                return _GS_CREDS
    except Exception:
        pass

    # 2) service_account.json local
    try:
        p = Path("service_account.json")
        if p.exists():
            sa = json.loads(p.read_text(encoding="utf-8"))
            if "private_key" in sa:
                sa["private_key"] = sa["private_key"].replace("\\n", "\n")
            scopes = ["https://www.googleapis.com/auth/spreadsheets"]
            _GS_CREDS = Credentials.from_service_account_info(sa, scopes=scopes)
            return _GS_CREDS
    except Exception:
        pass

    return None

def _gs_open_worksheet(tab_name: str):
    """Intenta abrir la hoja `GSHEET_ID` y retornar el worksheet `tab_name` (o None)."""
    try:
        creds = _gs_credentials()
        if creds is None:
            return None
        gc = gspread.authorize(creds)
        sh = gc.open_by_key(GSHEET_ID)
        try:
            ws = sh.worksheet(tab_name)
        except Exception:
            # si no existe, crear
            ws = sh.add_worksheet(title=tab_name, rows=100, cols=20)
        return ws
    except Exception:
        return None

# --- Test helper for GSheets connection ---
def test_gsheets_connection(show_toast: bool = True) -> bool:
    """
    Intenta autorizar con `_gs_credentials()` y abrir `GSHEET_ID`.
    Devuelve True si OK y muestra mensajes en sidebar/toast.
    """
    try:
        creds = _gs_credentials()
        if creds is None:
            st.sidebar.error("❌ No se encontraron credenciales de Google Sheets.")
            if show_toast:
                try: st.toast("No se encontraron credenciales de Google Sheets.", icon="❌")
                except: pass
            return False

        try:
            gc = gspread.authorize(creds)
        except Exception as e:
            st.sidebar.error(f"❌ Error autorizando credenciales: {e}")
            if show_toast:
                try: st.toast("Error autorizando credenciales Google Sheets.", icon="❌")
                except: pass
            return False

        try:
            sh = gc.open_by_key(GSHEET_ID)
            st.sidebar.success(f"✅ Conectado a Google Sheets: {sh.title}")
            if show_toast:
                try: st.toast("Conexión a Google Sheets OK", icon="✅")
                except: pass
            return True
        except Exception as e:
            st.sidebar.error(f"❌ No se pudo abrir la hoja: {e}")
            if show_toast:
                try: st.toast("No se pudo abrir la hoja de Google Sheets.", icon="❌")
                except: pass
            return False
    except Exception as e:
        st.sidebar.error(f"❌ Error en prueba de conexión: {e}")
        if show_toast:
            try: st.toast("Error en prueba de conexión Google Sheets.", icon="❌")
            except: pass
        return False

# --- UI: Sidebar login + prueba GSheets ---
st.sidebar.title("👤 CRM — Inicio de sesión")

# Si no hay usuarios, mostrar formulario para crear admin inicial
users_data = load_users()
if not users_data.get("users"):
    with st.sidebar.expander("Configurar administrador (primera vez)", expanded=True):
        st.write("No hay usuarios. Crea el primer administrador.")
        _user = st.text_input("Usuario admin", key="setup_user")
        _pw1 = st.text_input("Contraseña", type="password", key="setup_pw1")
        _pw2 = st.text_input("Confirmar", type="password", key="setup_pw2")
        if st.button("Crear administrador"):
            if not _user or not _pw1:
                st.error("Usuario y contraseña obligatorios.")
            elif _pw1 != _pw2:
                st.error("Las contraseñas no coinciden.")
            else:
                ok, msg = add_user(_user, _pw1, role="admin")
                if ok:
                    st.success("Administrador creado. Inicia sesión.")
                    do_rerun()
                else:
                    st.error(msg)

# Login form
if not current_user():
    with st.sidebar.form("login_form", clear_on_submit=True):
        st.markdown("### Iniciar sesión")
        luser = st.text_input("Usuario", key="login_user")
        lpw = st.text_input("Contraseña", type="password", key="login_pw")
        submitted = st.form_submit_button("Entrar")

    if submitted:
        u = get_user(luser)
        if u and _verify_pw(lpw, u.get("salt",""), u.get("hash","")):
            st.session_state["auth_user"] = {"user": u.get("user"), "role": u.get("role", "member")}
            # limpiar credenciales temporales
            for _k in ("login_pw", "login_user"):
                st.session_state.pop(_k, None)
            st.toast(f"Bienvenido, {st.session_state['auth_user']['user']}", icon="✅")
            do_rerun()
        else:
            st.error("Credenciales inválidas.")

if current_user():
    u = current_user()
    st.sidebar.markdown(f"**Usuario:** {u.get('user')} — _{u.get('role')}_")
    if st.sidebar.button("Cerrar sesión"):
        st.session_state["auth_user"] = None
        do_rerun()

# --- Botón para probar Google Sheets ---
st.sidebar.markdown("---")
st.sidebar.markdown("### 📂 Conexión Google Sheets")
if st.sidebar.button("Probar conexión Google Sheets", key="btn_test_gs"):
    with st.spinner("Probando conexión a Google Sheets..."):
        ok = test_gsheets_connection()
    if ok:
        st.success("Conexión verificada ✅")
    else:
        st.error("Fallo en la prueba de conexión. Revisa credenciales y permisos.")

# Información útil para el desarrollador
st.sidebar.caption("Coloca `service_account.json` en la raíz o configura `st.secrets` con las credenciales del service account.")

# --- Main placeholder ---
st.title("CRM — Auth & GSheets test")
if current_user():
    st.write(f"Hola {current_user().get('user')}, estás autenticado.")
else:
    st.info("Inicia sesión en el sidebar para continuar.")
