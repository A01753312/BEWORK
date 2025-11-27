import streamlit as st
import json
import secrets
import hashlib
from pathlib import Path
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

# === CONFIG GOOGLE SHEETS / DRIVE ===
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
    st.session_state["_need_rerun"] = not st.session_state.get("_need_rerun", False)
    try:
        st.stop()
    except Exception:
        return

# NOTE: OAuth2 Drive flow removed — using only service-account credentials

# --- Google Sheets credential helper (service account fallback) ---
_GS_CREDS = None

def _gs_credentials():
    global _GS_CREDS
    if _GS_CREDS is not None:
        return _GS_CREDS
    try:
        if hasattr(st, "secrets"):
            try:
                s = dict(st.secrets)
            except Exception:
                # Fallback: use as-is (streamlit may provide a secrets-like object)
                s = st.secrets
            if s:
                # Top-level service account keys present (your example)
                if all(k in s for k in ("type", "project_id", "private_key_id", "private_key")):
                    sa = dict(s)
                    if "private_key" in sa:
                        sa["private_key"] = sa["private_key"].replace("\\n", "\n")
                    scopes = ["https://www.googleapis.com/auth/spreadsheets"]
                    _GS_CREDS = Credentials.from_service_account_info(sa, scopes=scopes)
                    return _GS_CREDS
                # Or nested under `service_account` key
                if "service_account" in s and isinstance(s["service_account"], dict):
                    sa = dict(s["service_account"])
                    if "private_key" in sa:
                        sa["private_key"] = sa["private_key"].replace("\\n", "\n")
                    scopes = ["https://www.googleapis.com/auth/spreadsheets"]
                    _GS_CREDS = Credentials.from_service_account_info(sa, scopes=scopes)
                    return _GS_CREDS
    except Exception:
        pass

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

def test_gsheets_connection(show_toast: bool = True) -> bool:
    try:
        # Use only service-account credentials for automated checks
        creds = _gs_credentials()

        if creds is None:
            st.sidebar.error("❌ No se encontraron credenciales (service account).")
            if show_toast:
                try: st.toast("No se encontraron credenciales para Google.", icon="❌")
                except: pass
            return False

        try:
            gc = gspread.authorize(creds)
        except Exception as e:
            st.sidebar.error(f"❌ Error autorizando credenciales: {e}")
            if show_toast:
                try: st.toast("Error autorizando credenciales Google.", icon="❌")
                except: pass
            return False

        try:
            sh = gc.open_by_key(GSHEET_ID)
            st.session_state['gsheet_title'] = getattr(sh, 'title', None)
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

# --- UI: Sidebar login + Drive connect + prueba GSheets ---
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
                    # Auto-login after creating the initial admin to avoid double-login
                    st.session_state["auth_user"] = {"user": _user, "role": "admin"}
                    st.session_state["in_crm"] = True
                    st.session_state["gsheets_connected"] = False
                    st.session_state["gsheets_checked"] = False
                    st.success("Administrador creado y autenticado. Redirigiendo al CRM...")
                    do_rerun()
                else:
                    st.error(msg)

# Login inputs (single submit — avoids double-submit issues from st.form)
if not current_user():
    st.sidebar.markdown("### Iniciar sesión")
    luser = st.sidebar.text_input("Usuario", key="login_user")
    lpw = st.sidebar.text_input("Contraseña", type="password", key="login_pw")
    if st.sidebar.button("Entrar", key="login_btn"):
        u = get_user(luser)
        if u and _verify_pw(lpw, u.get("salt",""), u.get("hash","")):
            st.session_state["auth_user"] = {"user": u.get("user"), "role": u.get("role", "member")}
            # Limpieza de inputs de login
            for _k in ("login_pw", "login_user"):
                st.session_state.pop(_k, None)

            # Marcar que el usuario entró al CRM (un único inicio de sesión)
            st.session_state["in_crm"] = True
            # Inicializar flags para la comprobación de GSheets que se hará al mostrar el CRM
            st.session_state["gsheets_connected"] = False
            st.session_state["gsheets_checked"] = False

            try:
                st.toast(f"Bienvenido, {st.session_state['auth_user']['user']}", icon="✅")
            except Exception:
                pass
            do_rerun()
        else:
            st.sidebar.error("Credenciales inválidas.")

if current_user():
    u = current_user()
    st.sidebar.markdown(f"**Usuario:** {u.get('user')} — _{u.get('role')}_")
    if st.sidebar.button("Cerrar sesión"):
        # Limpiar estados relacionados a sesión y GSheets
        st.session_state["auth_user"] = None
        st.session_state["gsheets_connected"] = False
        st.session_state["gsheet_title"] = None
        st.session_state["in_crm"] = False
        do_rerun()

st.sidebar.caption("Para service account: coloca `service_account.json` o configura `st.secrets['service_account']`.")

# --- Main placeholder ---
st.title("CRM — Auth & Google Drive/Sheets Test")
if current_user():
    if st.session_state.get('in_crm'):
        # Usuario autenticado y redirigido al CRM principal
        # Ejecutar la comprobación de Google Sheets solo una vez al entrar al CRM
        if not st.session_state.get('gsheets_checked'):
            try:
                ok = test_gsheets_connection(show_toast=False)
                st.session_state['gsheets_connected'] = bool(ok)
                st.session_state['gsheets_checked'] = True
                if ok:
                    st.success(f"Google Sheets conectado: {st.session_state.get('gsheet_title') or GSHEET_ID}")
                else:
                    st.warning("No se pudo conectar a Google Sheets. Algunas funciones pueden no estar disponibles.")
            except Exception as e:
                st.session_state['gsheets_connected'] = False
                st.session_state['gsheets_checked'] = True
                st.error(f"Error comprobando Google Sheets: {e}")

        st.header("CRM — Panel Principal")
        st.write(f"Bienvenido, {current_user().get('user')}! Estás dentro del CRM.")
        gs_ok = st.session_state.get('gsheets_connected', False)
        gsheet_title = st.session_state.get('gsheet_title')
        if gs_ok:
            st.success(f"Google Sheets conectado: {gsheet_title or GSHEET_ID}")
        else:
            st.warning("Google Sheets no está conectado. Algunas funciones pueden no estar disponibles.")
        # Aquí iría el contenido real del CRM (listas, búsquedas, etc.)
        st.markdown("---")
        st.write("(Contenido del CRM pendiente de implementar)")
    else:
        st.write(f"Hola {current_user().get('user')}, estás autenticado.")
        st.info("Se verificará la conexión a Google Sheets automáticamente al iniciar sesión.")
else:
    st.info("Inicia sesión en el sidebar para continuar.")
