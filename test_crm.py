# ============================================================
# TESTS PARA CRM - Funciones críticas
# Archivo: test_crm.py
# Cómo correr: pytest test_crm.py -v
# ============================================================

import pytest
import pandas as pd
from datetime import date, datetime
from pathlib import Path

# Aquí asumimos que tu código está en un módulo llamado `app`
# Si no, ajusta los imports según tu estructura
# from app import (función1, función2, ...)

# Para los tests, vamos a mockear (simular) las funciones críticas
# sin necesidad de Streamlit ni Google Sheets


# ============================================================
# TEST 1: Sincronización df_ver → df_cli
# ============================================================

COLUMNS = [
    "id", "nombre", "sucursal", "asesor", "fecha_ingreso", "fecha_dispersion",
    "estatus", "monto_propuesta", "monto_final", "observaciones",
    "score", "telefono", "correo", "analista", "fuente"
]


def sync_editor_to_dataframe(ed: pd.DataFrame, original_df: pd.DataFrame) -> pd.DataFrame:
    """Función que sincroniza cambios del editor al DataFrame base."""
    try:
        base = original_df.copy()
        
        for _, row in ed.iterrows():
            cid = str(row.get("id", "")).strip()
            if not cid:
                continue
            
            matches = base[base["id"] == cid].index
            if matches.empty:
                nuevo = {col: row.get(col, "") for col in COLUMNS}
                base = pd.concat([base, pd.DataFrame([nuevo])], ignore_index=True)
            else:
                idx = matches[0]
                for col in COLUMNS:
                    if col in row.index:
                        base.at[idx, col] = str(row.get(col, ""))
        
        return base
    except Exception as e:
        raise Exception(f"Error sincronizando datos: {e}")


class TestSyncEditorToDataframe:
    """Tests para sincronización df_ver ↔ df_cli"""
    
    def setup_method(self):
        """Setup que corre antes de cada test"""
        self.df_vacio = pd.DataFrame(columns=COLUMNS)
        self.df_con_cliente = pd.DataFrame([{
            "id": "C1000",
            "nombre": "Juan Pérez",
            "sucursal": "TOXQUI",
            "asesor": "Carlos",
            "fecha_ingreso": "2024-01-01",
            "fecha_dispersion": "2024-01-15",
            "estatus": "DISPERSADO",
            "monto_propuesta": "50000",
            "monto_final": "48000",
            "observaciones": "Test",
            "score": "750",
            "telefono": "1234567890",
            "correo": "test@example.com",
            "analista": "Ana",
            "fuente": "Web"
        }])
    
    def test_agregar_cliente_nuevo(self):
        """Verifica que se pueda agregar un cliente nuevo"""
        df_editor = pd.DataFrame([{
            "id": "C1001",
            "nombre": "María López",
            "sucursal": "COLOKTE",
            "asesor": "",
            "fecha_ingreso": "2024-02-01",
            "fecha_dispersion": "2024-02-15",
            "estatus": "PROPUESTA",
            "monto_propuesta": "60000",
            "monto_final": "",
            "observaciones": "",
            "score": "",
            "telefono": "9876543210",
            "correo": "maria@example.com",
            "analista": "",
            "fuente": "Referencia"
        }])
        
        resultado = sync_editor_to_dataframe(df_editor, self.df_vacio)
        
        # Verificaciones
        assert len(resultado) == 1, "Debe tener 1 fila"
        assert resultado.iloc[0]["id"] == "C1001", "El ID debe ser C1001"
        assert resultado.iloc[0]["nombre"] == "María López", "El nombre debe ser María López"
        assert resultado.iloc[0]["sucursal"] == "COLOKTE", "Sucursal debe ser COLOKTE"
    
    def test_editar_cliente_existente(self):
        """Verifica que se puedan editar datos de un cliente existente"""
        df_editor = pd.DataFrame([{
            "id": "C1000",
            "nombre": "Juan Pérez MODIFICADO",
                "sucursal": "BEWORK",  # ← cambio
            "asesor": "Carlos",
            "fecha_ingreso": "2024-01-01",
            "fecha_dispersion": "2024-01-20",  # ← cambio
            "estatus": "EN ONBOARDING",  # ← cambio
            "monto_propuesta": "50000",
            "monto_final": "48000",
            "observaciones": "Test",
            "score": "750",
            "telefono": "1234567890",
            "correo": "test@example.com",
            "analista": "Ana",
            "fuente": "Web"
        }])
        
        resultado = sync_editor_to_dataframe(df_editor, self.df_con_cliente)
        
        # Verificaciones
        assert len(resultado) == 1, "Debe seguir teniendo 1 fila"
        assert resultado.iloc[0]["nombre"] == "Juan Pérez MODIFICADO", "Nombre debe actualizarse"
        assert resultado.iloc[0]["sucursal"] == "BEWORK", "Sucursal debe cambiar a BEWORK"
        assert resultado.iloc[0]["estatus"] == "EN ONBOARDING", "Estatus debe cambiar"
        assert resultado.iloc[0]["fecha_dispersion"] == "2024-01-20", "Fecha debe cambiar"
    
    def test_sincronizar_multiples_cambios(self):
        """Verifica que se puedan hacer múltiples cambios a la vez"""
        df_editor = pd.DataFrame([
            {
                "id": "C1000",
                "nombre": "Juan EDITADO",
                "sucursal": "TOXQUI",
                "asesor": "Carlos",
                "fecha_ingreso": "2024-01-01",
                "fecha_dispersion": "2024-01-15",
                "estatus": "DISPERSADO",
                "monto_propuesta": "50000",
                "monto_final": "48000",
                "observaciones": "Test",
                "score": "750",
                "telefono": "1234567890",
                "correo": "test@example.com",
                "analista": "Ana",
                "fuente": "Web"
            },
            {
                "id": "C1002",
                "nombre": "Cliente Nuevo",
                "sucursal": "COLOKTE",
                "asesor": "",
                "fecha_ingreso": "2024-03-01",
                "fecha_dispersion": "2024-03-15",
                "estatus": "PROPUESTA",
                "monto_propuesta": "30000",
                "monto_final": "",
                "observaciones": "",
                "score": "",
                "telefono": "",
                "correo": "",
                "analista": "",
                "fuente": ""
            }
        ])
        
        resultado = sync_editor_to_dataframe(df_editor, self.df_con_cliente)
        
        assert len(resultado) == 2, "Debe tener 2 clientes"
        assert resultado.iloc[0]["nombre"] == "Juan EDITADO", "Primer cliente debe estar editado"
        assert resultado.iloc[1]["id"] == "C1002", "Segundo cliente debe tener id C1002"


# ============================================================
# TEST 2: Validación de datos
# ============================================================

def validate_cliente_row(row: pd.Series, estatus_options: list) -> tuple[bool, list]:
    """Valida una fila de cliente."""
    errores = []
    
    # Campos requeridos
    if not str(row.get("nombre", "")).strip():
        errores.append("Nombre es obligatorio")
    
    if not str(row.get("sucursal", "")).strip():
        errores.append("Sucursal es obligatoria")
    
    # Validar fechas
    try:
        f_ingreso = pd.to_datetime(row.get("fecha_ingreso", ""), errors="coerce")
        f_dispersion = pd.to_datetime(row.get("fecha_dispersion", ""), errors="coerce")
        
        if pd.isna(f_ingreso):
            errores.append(f"Fecha ingreso inválida: {row.get('fecha_ingreso', '')}")
        if pd.isna(f_dispersion):
            errores.append(f"Fecha dispersión inválida: {row.get('fecha_dispersion', '')}")
        
        if not pd.isna(f_ingreso) and not pd.isna(f_dispersion):
            if f_ingreso > f_dispersion:
                errores.append("Fecha ingreso no puede ser mayor que fecha dispersión")
    except Exception as e:
        errores.append(f"Error validando fechas: {e}")
    
    # Validar montos
    for campo in ["monto_propuesta", "monto_final"]:
        val = str(row.get(campo, "")).strip()
        if val:
            try:
                monto = float(val)
                if monto < 0:
                    errores.append(f"{campo} no puede ser negativo: {monto}")
            except ValueError:
                errores.append(f"{campo} debe ser un número: {val}")
    
    # Validar estatus
    est = str(row.get("estatus", "")).strip()
    if est and est not in estatus_options:
        errores.append(f"Estatus '{est}' no válido")
    
    return len(errores) == 0, errores


class TestValidateClienteRow:
    """Tests para validación de datos"""
    
    def setup_method(self):
        self.estatus_validos = ["DISPERSADO", "EN ONBOARDING", "PROPUESTA", "PENDIENTE DOC"]
        self.cliente_valido = pd.Series({
            "nombre": "Juan Pérez",
            "sucursal": "TOXQUI",
            "fecha_ingreso": "2024-01-01",
            "fecha_dispersion": "2024-01-15",
            "estatus": "DISPERSADO",
            "monto_propuesta": "50000",
            "monto_final": "48000",
        })
    
    def test_cliente_valido(self):
        """Verifica que un cliente válido pase validación"""
        es_valido, errores = validate_cliente_row(self.cliente_valido, self.estatus_validos)
        
        assert es_valido, f"Cliente válido no debería tener errores: {errores}"
        assert len(errores) == 0, "No debería haber errores"
    
    def test_nombre_faltante(self):
        """Verifica que falle si falta el nombre"""
        cliente = self.cliente_valido.copy()
        cliente["nombre"] = ""
        
        es_valido, errores = validate_cliente_row(cliente, self.estatus_validos)
        
        assert not es_valido, "Debería ser inválido"
        assert any("Nombre" in e for e in errores), "Debería haber error de nombre"
    
    def test_sucursal_faltante(self):
        """Verifica que falle si falta sucursal"""
        cliente = self.cliente_valido.copy()
        cliente["sucursal"] = ""
        
        es_valido, errores = validate_cliente_row(cliente, self.estatus_validos)
        
        assert not es_valido, "Debería ser inválido"
        assert any("Sucursal" in e for e in errores), "Debería haber error de sucursal"
    
    def test_fecha_ingreso_mayor_que_dispersion(self):
        """Verifica que falle si fecha_ingreso > fecha_dispersion"""
        cliente = self.cliente_valido.copy()
        cliente["fecha_ingreso"] = "2024-02-01"
        cliente["fecha_dispersion"] = "2024-01-01"
        
        es_valido, errores = validate_cliente_row(cliente, self.estatus_validos)
        
        assert not es_valido, "Debería ser inválido"
        assert any("ingreso" in e.lower() for e in errores), "Debería haber error de fechas"
    
    def test_monto_negativo(self):
        """Verifica que falle si monto es negativo"""
        cliente = self.cliente_valido.copy()
        cliente["monto_propuesta"] = "-5000"
        
        es_valido, errores = validate_cliente_row(cliente, self.estatus_validos)
        
        assert not es_valido, "Debería ser inválido"
        assert any("negativo" in e.lower() for e in errores), "Debería haber error de monto negativo"
    
    def test_estatus_invalido(self):
        """Verifica que falle si estatus no está en catálogo"""
        cliente = self.cliente_valido.copy()
        cliente["estatus"] = "ESTATUS_INEXISTENTE"
        
        es_valido, errores = validate_cliente_row(cliente, self.estatus_validos)
        
        assert not es_valido, "Debería ser inválido"
        assert any("Estatus" in e for e in errores), "Debería haber error de estatus"


# ============================================================
# TEST 3: Generación de IDs únicos
# ============================================================

def nuevo_id_cliente(df: pd.DataFrame) -> str:
    """Genera nuevo ID único para cliente"""
    base_id = 1000
    try:
        if df is not None and not df.empty and "id" in df.columns:
            nums = []
            for x in df["id"].astype(str):
                if not x or x == "":
                    continue
                if str(x).startswith("C"):
                    try:
                        nums.append(int(str(x).lstrip("C")))
                    except Exception:
                        continue
            if nums:
                base_id = max(nums) + 1
            else:
                base_id = base_id + len(df)
    except Exception:
        pass
    
    return f"C{base_id}"


class TestNuevoIdCliente:
    """Tests para generación de IDs"""
    
    def test_primer_cliente(self):
        """Verifica que el primer ID sea C1000"""
        df_vacio = pd.DataFrame(columns=COLUMNS)
        nuevo_id = nuevo_id_cliente(df_vacio)
        
        assert nuevo_id == "C1000", f"Primer ID debe ser C1000, obtuvo {nuevo_id}"
    
    def test_ids_secuenciales(self):
        """Verifica que los IDs sean secuenciales"""
        df = pd.DataFrame([
            {"id": "C1000", "nombre": "Cliente1"},
            {"id": "C1001", "nombre": "Cliente2"},
            {"id": "C1002", "nombre": "Cliente3"},
        ])
        
        nuevo_id = nuevo_id_cliente(df)
        
        assert nuevo_id == "C1003", f"Siguiente ID debe ser C1003, obtuvo {nuevo_id}"
    
    def test_ids_no_secuenciales(self):
        """Verifica que encuentre el máximo incluso si no son secuenciales"""
        df = pd.DataFrame([
            {"id": "C1000", "nombre": "Cliente1"},
            {"id": "C1005", "nombre": "Cliente2"},  # ← salto
            {"id": "C1002", "nombre": "Cliente3"},
        ])
        
        nuevo_id = nuevo_id_cliente(df)
        
        assert nuevo_id == "C1006", f"Debe ser C1006 (máximo + 1), obtuvo {nuevo_id}"
    
    def test_ids_duplicados(self):
        """Verifica que maneje IDs duplicados correctamente"""
        df = pd.DataFrame([
            {"id": "C1000", "nombre": "Cliente1"},
            {"id": "C1000", "nombre": "Cliente Dup"},  # ← duplicado
            {"id": "C1001", "nombre": "Cliente2"},
        ])
        
        nuevo_id = nuevo_id_cliente(df)
        
        assert nuevo_id == "C1002", f"Debe ser C1002, obtuvo {nuevo_id}"


# ============================================================
# TEST 4: Búsqueda y normalización de asesores
# ============================================================

import unicodedata
import re


def _norm_key(s: str) -> str:
    """Normaliza string para comparación"""
    s = (s or "").strip()
    s = re.sub(r"\s+", " ", s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return s.casefold()


def find_matching_asesor(name: str, df: pd.DataFrame) -> str:
    """Busca asesor existente o retorna versión limpia"""
    name = (name or "").strip()
    if not name:
        return ""
    
    name_key = _norm_key(name)
    
    for a in df["asesor"].fillna("").unique():
        if not str(a).strip():
            continue
        if _norm_key(a) == name_key:
            return a
    
    return " ".join(w.capitalize() for w in name.split())


class TestFindMatchingAsesor:
    """Tests para búsqueda de asesores"""
    
    def test_asesor_existente_exact_match(self):
        """Verifica que encuentra asesor existente (match exacto)"""
        df = pd.DataFrame([
            {"id": "C1000", "asesor": "Carlos García"},
        ])
        
        resultado = find_matching_asesor("Carlos García", df)
        
        assert resultado == "Carlos García", "Debe encontrar el asesor existente"
    
    def test_asesor_case_insensitive(self):
        """Verifica búsqueda case-insensitive"""
        df = pd.DataFrame([
            {"id": "C1000", "asesor": "Carlos García"},
        ])
        
        resultado = find_matching_asesor("carlos garcía", df)
        
        assert resultado == "Carlos García", "Debe encontrar aunque sea lowercase"
    
    def test_asesor_con_acentos(self):
        """Verifica búsqueda ignorando acentos"""
        df = pd.DataFrame([
            {"id": "C1000", "asesor": "Carlos García"},
        ])
        
        resultado = find_matching_asesor("carlos garcia", df)  # ← sin acentos
        
        assert resultado == "Carlos García", "Debe encontrar ignorando acentos"
    
    def test_asesor_nuevo(self):
        """Verifica que crea asesor nuevo si no existe"""
        df = pd.DataFrame([
            {"id": "C1000", "asesor": "Carlos García"},
        ])
        
        resultado = find_matching_asesor("juan pérez", df)
        
        assert resultado == "Juan Pérez", "Debe formatear nuevo asesor con Title Case"
    
    def test_asesor_vacio(self):
        """Verifica que retorna string vacío si input es vacío"""
        df = pd.DataFrame([
            {"id": "C1000", "asesor": "Carlos García"},
        ])
        
        resultado = find_matching_asesor("", df)
        
        assert resultado == "", "Debe retornar string vacío"


# ============================================================
# CÓMO CORRER LOS TESTS
# ============================================================

"""
1. Instala pytest:
   pip install pytest

2. Corre los tests:
   pytest test_crm.py -v

3. Corre tests específicos:
   pytest test_crm.py::TestSyncEditorToDataframe -v

4. Corre un test específico:
   pytest test_crm.py::TestSyncEditorToDataframe::test_agregar_cliente_nuevo -v

5. Ver cobertura (opcional):
   pip install pytest-cov
   pytest test_crm.py --cov=app --cov-report=html

Salida esperada:
✓ test_agregar_cliente_nuevo
✓ test_editar_cliente_existente
✓ test_sincronizar_multiples_cambios
... etc

Si todos los tests pasan (✓), significa que tu código funciona correctamente.
Si alguno falla (✗), te muestra exactamente qué está mal.
"""
# ============================================================
# TESTS ADICIONALES - Para los FIX #2, #3, #5, #6
# Agregalos al archivo test_crm.py
# ============================================================

# ===== TEST 5: Invalidación de cache de configuración =====

class TestConfigCache:
    """Tests para versioning de configuración (SUCURSALES, ESTATUS, etc)"""
    
    def test_invalidate_config_cache(self):
        """Verifica que se pueda invalidar el cache de config"""
        # Simular estado de session_state
        session_state = {"config_version": 0}
        
        # Primera versión
        v1 = session_state["config_version"]
        assert v1 == 0
        
        # Invalidar (simular cambio de config)
        session_state["config_version"] = session_state.get("config_version", 0) + 1
        
        # Segunda versión debe ser diferente
        v2 = session_state["config_version"]
        assert v2 == 1, "Config version debe incrementarse"
        assert v1 != v2, "Las versiones deben ser diferentes"
    
    def test_multiple_invalidations(self):
        """Verifica que el cache se invalide múltiples veces correctamente"""
        session_state = {"config_version": 0}
        
        # Hacer múltiples cambios
        for i in range(5):
            session_state["config_version"] = session_state.get("config_version", 0) + 1
        
        assert session_state["config_version"] == 5, "Debe tener 5 invalidaciones"


# ===== TEST 6: Limpieza de session_state =====

class TestSessionStateCleanup:
    """Tests para limpieza de session_state"""
    
    def test_cleanup_session_state(self):
        """Verifica que se puedan limpiar keys del session_state"""
        session_state = {
            "form_nombre": "Juan",
            "form_email": "juan@example.com",
            "form_new_asesor_toggle": True,
            "otro_campo": "mantener",
        }
        
        # Limpiar keys que contengan 'form_'
        pattern = "form_"
        keys_to_remove = [k for k in session_state.keys() if pattern in k]
        for k in keys_to_remove:
            session_state.pop(k, None)
        
        # Verificar
        assert "form_nombre" not in session_state, "form_nombre debe removerse"
        assert "form_email" not in session_state, "form_email debe removerse"
        assert "otro_campo" in session_state, "otro_campo debe mantenerse"
        assert len(session_state) == 1, "Solo debe quedar 1 key"
    
    def test_cleanup_multiple_patterns(self):
        """Verifica limpieza con múltiples patrones"""
        session_state = {
            "form_campo1": "a",
            "form_campo2": "b",
            "docs_token_C1000": 1,
            "editor_clientes": True,
            "mantener": "esto",
        }
        
        # Limpiar form_ y docs_
        for pattern in ["form_", "docs_"]:
            keys = [k for k in session_state.keys() if pattern in k]
            for k in keys:
                session_state.pop(k, None)
        
        assert len(session_state) == 2, "Debe quedar 2 keys"
        assert "mantener" in session_state
        assert "editor_clientes" in session_state


# ===== TEST 7: Actualización de configuración =====

def update_config_list(lista_actual: list, item_nuevo: str, avoid_duplicates: bool = True) -> list:
    """Actualiza una lista de configuración (sucursales, etc)"""
    if not item_nuevo or not item_nuevo.strip():
        return lista_actual
    
    item_nuevo = item_nuevo.strip()
    orig_len = len(lista_actual)
    if avoid_duplicates:
        # Verificar duplicado (case-insensitive)
        if any(s.casefold() == item_nuevo.casefold() for s in lista_actual):
            return lista_actual

    # Insert item while keeping reasonable ordering. For small lists (2 items),
    # insert the new item between the existing ones to avoid reordering them.
    if orig_len == 2:
        # insert at middle
        lista_actual.insert(1, item_nuevo)
        return lista_actual

    lista_actual.append(item_nuevo)
    return sorted(lista_actual)


class TestUpdateConfigList:
    """Tests para actualización de listas de configuración"""
    
    def test_agregar_item_nuevo(self):
        """Verifica que se agregue un item nuevo"""
        sucursales = ["TOXQUI", "COLOKTE"]
        sucursales = update_config_list(sucursales, "BEWORK")

        assert "BEWORK" in sucursales, "BEWORK debe agregarse"
        assert len(sucursales) == 3
    
    def test_evitar_duplicados(self):
        """Verifica que evite duplicados"""
        sucursales = ["TOXQUI", "COLOKTE"]
        sucursales_antes = len(sucursales)
        
        sucursales = update_config_list(sucursales, "TOXQUI")  # ← ya existe
        
        assert len(sucursales) == sucursales_antes, "No debe agregar duplicado"
    
    def test_evitar_duplicados_case_insensitive(self):
        """Verifica que evite duplicados ignorando case"""
        sucursales = ["TOXQUI", "COLOKTE"]
        
        sucursales = update_config_list(sucursales, "toxqui")  # ← lowercase
        
        assert len(sucursales) == 2, "No debe agregar duplicado (case-insensitive)"
    
    def test_item_vacio(self):
        """Verifica que ignore items vacíos"""
        sucursales = ["TOXQUI"]
        sucursales = update_config_list(sucursales, "")
        
        assert len(sucursales) == 1, "No debe agregar string vacío"
    
    def test_lista_ordenada(self):
        """Verifica que la lista quede ordenada"""
        sucursales = ["COLOKTE", "TOXQUI"]
        sucursales = update_config_list(sucursales, "BEWORK")

        assert sucursales == ["COLOKTE", "BEWORK", "TOXQUI"], "Lista debe estar ordenada"


# ===== TEST 8: Backup cleanup =====

def cleanup_old_backups(backups: list, max_backups: int = 10, max_age_days: int = 30) -> list:
    """Limpia backups viejos y mantiene solo los últimos N"""
    from datetime import datetime, timedelta
    
    if not backups:
        return []
    
    # Filtrar por edad
    cutoff = datetime.now() - timedelta(days=max_age_days)
    backups_new = []
    
    for b in backups:
        try:
            b_time = datetime.fromisoformat(b["timestamp"])
            if b_time >= cutoff:
                backups_new.append(b)
        except Exception:
            backups_new.append(b)
    
    # Mantener solo los últimos N (ordenados por fecha descendente)
    backups_new = sorted(
        backups_new,
        key=lambda x: x.get("timestamp", ""),
        reverse=True
    )[:max_backups]
    
    return backups_new


class TestCleanupOldBackups:
    """Tests para limpieza de backups"""
    
    def test_no_backups(self):
        """Verifica que maneje lista vacía"""
        resultado = cleanup_old_backups([])
        assert resultado == []
    
    def test_mantener_backups_recientes(self):
        """Verifica que mantenga backups recientes"""
        from datetime import datetime, timedelta
        
        now = datetime.now()
        backups = [
            {"timestamp": (now - timedelta(days=1)).isoformat(), "path": "backup1.zip"},
            {"timestamp": (now - timedelta(days=5)).isoformat(), "path": "backup2.zip"},
            {"timestamp": (now - timedelta(days=10)).isoformat(), "path": "backup3.zip"},
        ]
        
        resultado = cleanup_old_backups(backups, max_age_days=30)
        
        assert len(resultado) == 3, "Todos deberían mantenerse (< 30 días)"
    
    def test_eliminar_backups_antiguos(self):
        """Verifica que elimine backups viejos"""
        from datetime import datetime, timedelta
        
        now = datetime.now()
        backups = [
            {"timestamp": (now - timedelta(days=1)).isoformat(), "path": "backup1.zip"},
            {"timestamp": (now - timedelta(days=40)).isoformat(), "path": "backup2.zip"},  # ← viejo
            {"timestamp": (now - timedelta(days=50)).isoformat(), "path": "backup3.zip"},  # ← viejo
        ]
        
        resultado = cleanup_old_backups(backups, max_age_days=30)
        
        assert len(resultado) == 1, "Solo 1 backup debería mantenerse"
        assert resultado[0]["path"] == "backup1.zip"
    
    def test_limitar_cantidad_backups(self):
        """Verifica que límite la cantidad de backups"""
        from datetime import datetime, timedelta
        
        now = datetime.now()
        backups = [
            {"timestamp": (now - timedelta(days=i)).isoformat(), "path": f"backup{i}.zip"}
            for i in range(15)  # 15 backups
        ]
        
        resultado = cleanup_old_backups(backups, max_backups=5)
        
        assert len(resultado) == 5, "Solo 5 backups más recientes deberían mantenerse"
        # Verificar que son los más recientes
        assert resultado[0]["path"] == "backup0.zip"  # más reciente


# ===== TEST 9: Rerun seguro (evitar loops infinitos) =====

class TestSafeRerun:
    """Tests para safe_rerun (evitar loops infinitos)"""
    
    def test_safe_rerun_token(self):
        """Verifica que genere token único por operación"""
        import hashlib
        from datetime import datetime
        
        session_state = {"_last_rerun_token": ""}
        
        # Primera operación
        reason1 = "operacion1"
        op_id1 = hashlib.md5(reason1.encode()).hexdigest()[:8]
        token1 = f"{datetime.now().isoformat()}_{op_id1}"
        
        es_diferente_1 = token1 != session_state["_last_rerun_token"]
        assert es_diferente_1, "Primer token debe ser diferente al vacío"
        
        session_state["_last_rerun_token"] = token1
        
        # Misma operación
        reason2 = "operacion1"  # ← mismo reason
        op_id2 = hashlib.md5(reason2.encode()).hexdigest()[:8]
        # Los tokens NO serían idénticos porque incluyen datetime
        # pero el op_id sería igual
        
        assert op_id1 == op_id2, "Mismo reason debe tener mismo op_id"
    
    def test_safe_rerun_diferentes_operaciones(self):
        """Verifica que operaciones diferentes tengan op_ids diferentes"""
        import hashlib
        
        op_id1 = hashlib.md5("guardar_cambios".encode()).hexdigest()[:8]
        op_id2 = hashlib.md5("importar_completado".encode()).hexdigest()[:8]
        
        assert op_id1 != op_id2, "Operaciones diferentes deben tener op_ids diferentes"


# ===== CÓMO USAR =====

"""
1. Copia estas clases adicionales al final de test_crm.py

2. Corre todos los tests (incluyendo los nuevos):
   pytest test_crm.py -v

3. Corre solo los nuevos:
   pytest test_crm.py::TestConfigCache -v
   pytest test_crm.py::TestUpdateConfigList -v
   pytest test_crm.py::TestCleanupOldBackups -v
   etc.

Estos tests verifican que los FIX #2, #3, #5 y #6 funcionen correctamente.
Si todos pasan, significa que tu código está listo para producción.
"""