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
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
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

# === OAuth2 Drive (same flow as your original script) ===
if "drive_creds" not in st.session_state:
    st.session_state.drive_creds = None

# Read client config from st.secrets if available (keeps your original flow)
CLIENT_ID = st.secrets.get("GOOGLE_CLIENT_ID") if hasattr(st, "secrets") else None
CLIENT_SECRET = st.secrets.get("GOOGLE_CLIENT_SECRET") if hasattr(st, "secrets") else None
REDIRECT_URI = st.secrets.get("REDIRECT_URI") if hasattr(st, "secrets") else None

# Scopes
SCOPES = [
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/spreadsheets"
]

# Sidebar: Drive connect/disconnect using OAuth2 web flow
st.sidebar.markdown("---")
st.sidebar.markdown("### 📂 Conexión a Google Drive")

def _build_auth_url():
    cid = CLIENT_ID
    cres = CLIENT_SECRET
    ruri = REDIRECT_URI
    if not (cid and cres and ruri) and hasattr(st, "secrets"):
        s = dict(st.secrets)
        if "web" in s and isinstance(s["web"], dict):
            cid = cid or s["web"].get("client_id")
            cres = cres or s["web"].get("client_secret")
            ruri = ruri or (s["web"].get("redirect_uris") or [None])[0]

    if not (cid and ruri):
        return None

    scope_str = "%20".join([s.replace("https://www.googleapis.com/auth/", "https://www.googleapis.com/auth/") for s in SCOPES])
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?response_type=code&client_id={cid}"
        f"&redirect_uri={ruri}"
        f"&scope={scope_str}"
        f"&access_type=offline&prompt=consent"
    )
    return auth_url

auth_url = _build_auth_url()
if not st.session_state.get("drive_creds"):
    if auth_url:
        st.sidebar.markdown(f"[🔐 Conectar con Google Drive]({auth_url})")
    else:
        st.sidebar.info("Configura `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` y `REDIRECT_URI` en `st.secrets` para usar OAuth2.")
else:
    st.sidebar.success("✅ Conectado a Google Drive")
    if st.sidebar.button("🔌 Desconectar Drive", help="Cerrar sesión de Google Drive"):
        st.session_state.drive_creds = None
        if "processed_auth_code" in st.session_state:
            del st.session_state.processed_auth_code
        st.experimental_set_query_params()
        st.sidebar.success("Google Drive desconectado")
        st.experimental_rerun()

# Procesar el parámetro de autorización devuelto por Google
query_params = st.experimental_get_query_params()
if "code" in query_params and not st.session_state.get("drive_creds"):
    code = query_params.get("code")
    if isinstance(code, list):
        code = code[0]

    if "processed_auth_code" not in st.session_state or st.session_state.processed_auth_code != code:
        try:
            client_config = None
            if hasattr(st, "secrets"):
                s = dict(st.secrets)
                if all(k in s for k in ("GOOGLE_CLIENT_ID","GOOGLE_CLIENT_SECRET","REDIRECT_URI")):
                    client_config = {
                        "web": {
                            "client_id": s["GOOGLE_CLIENT_ID"],
                            "client_secret": s["GOOGLE_CLIENT_SECRET"],
                            "redirect_uris": [s.get("REDIRECT_URI")],
                            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                            "token_uri": "https://oauth2.googleapis.com/token",
                        }
                    }
                elif "web" in s and isinstance(s["web"], dict):
                    client_config = {"web": s["web"]}

            if not client_config:
                client_config = {
                    "web": {
                        "client_id": CLIENT_ID,
                        "client_secret": CLIENT_SECRET,
                        "redirect_uris": [REDIRECT_URI],
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                    }
                }

            flow = Flow.from_client_config(client_config, scopes=SCOPES)
            flow.redirect_uri = client_config["web"].get("redirect_uris", [None])[0]
            flow.fetch_token(code=code)
            st.session_state.drive_creds = flow.credentials
            st.session_state.processed_auth_code = code
            st.experimental_set_query_params()
            st.success("✅ Autenticación exitosa con Google Drive")
            st.experimental_rerun()
        except Exception as e:
            st.experimental_set_query_params()
            st.session_state.processed_auth_code = None
            st.sidebar.error(f"Error en la autenticación: {e}")

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
        creds = None
        if st.session_state.get("drive_creds"):
            creds = st.session_state.get("drive_creds")
        else:
            creds = _gs_credentials()

        if creds is None:
            st.sidebar.error("❌ No se encontraron credenciales (OAuth o service account).")
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
            for _k in ("login_pw", "login_user"):
                st.session_state.pop(_k, None)

            # Prueba automática de Google Sheets al iniciar sesión
            try:
                ok = test_gsheets_connection()
                st.session_state["gsheets_connected"] = bool(ok)
                if ok:
                    try:
                        st.toast("Conexión a Google Sheets verificada", icon="✅")
                    except Exception:
                        pass
                else:
                    st.sidebar.warning("No se pudo conectar a Google Sheets. Revisa credenciales y permisos.")
            except Exception as e:
                st.session_state["gsheets_connected"] = False
                st.sidebar.error(f"Error verificando Google Sheets: {e}")

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

st.sidebar.caption("Para OAuth2: configura `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` y `REDIRECT_URI` en `st.secrets` (o carga el JSON del cliente en `st.secrets['web']`).\nPara service account: coloca `service_account.json` o configura `st.secrets['service_account']`.")

# --- Main placeholder ---
st.title("CRM — Auth & Google Drive/Sheets Test")
if current_user():
    st.write(f"Hola {current_user().get('user')}, estás autenticado.")
else:
    st.info("Inicia sesión en el sidebar para continuar.")
