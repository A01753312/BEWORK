#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test completo para el sistema CRM - Clientes BEWORK
Este archivo prueba todas las funciones principales del sistema CRM
para asegurar que todo está funcionando correctamente.

Ejecutar con: python test_crm_completo.py
"""

import os
import sys
import json
import pandas as pd
import tempfile
import shutil
from pathlib import Path
from datetime import date, datetime
import unittest
from unittest.mock import patch, MagicMock

# Agregar el directorio actual al path para importar el módulo CRM
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Importar funciones del CRM
try:
    from crm import (
        cargar_clientes, guardar_clientes, cargar_y_corregir_clientes,
        _fix_missing_or_duplicate_ids, nuevo_id_cliente,
        safe_name, find_matching_asesor, canonicalize_from_catalog,
        subir_docs, listar_docs_cliente, carpeta_docs_cliente,
        load_sucursales, save_sucursales, load_estatus, save_estatus,
        cargar_historial, append_historial,
        DATA_DIR, CLIENTES_CSV, DOCS_DIR, HISTORIAL_CSV,
        COLUMNS, ESTATUS_OPCIONES, SEGUNDO_ESTATUS_OPCIONES, SUCURSALES
    )
    print("✅ Importación del módulo CRM exitosa")
except ImportError as e:
    print(f"❌ Error al importar el módulo CRM: {e}")
    sys.exit(1)

class TestCRMCompleto(unittest.TestCase):
    """Clase de pruebas para el sistema CRM completo"""
    
    def setUp(self):
        """Configuración inicial para cada test"""
        # Crear directorio temporal para pruebas
        self.test_dir = tempfile.mkdtemp()
        self.original_data_dir = DATA_DIR
        
        # Redirigir DATA_DIR a directorio temporal
        import crm
        crm.DATA_DIR = Path(self.test_dir)
        crm.CLIENTES_CSV = crm.DATA_DIR / "clientes.csv"
        crm.DOCS_DIR = crm.DATA_DIR / "docs"
        crm.HISTORIAL_CSV = crm.DATA_DIR / "historial.csv"
        
        # Crear directorios necesarios
        crm.DATA_DIR.mkdir(exist_ok=True)
        crm.DOCS_DIR.mkdir(exist_ok=True)
        
        print(f"🔧 Configurando test en directorio temporal: {self.test_dir}")
    
    def tearDown(self):
        """Limpieza después de cada test"""
        # Limpiar directorio temporal
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        
        # Restaurar DATA_DIR original
        import crm
        crm.DATA_DIR = self.original_data_dir
        crm.CLIENTES_CSV = crm.DATA_DIR / "clientes.csv"
        crm.DOCS_DIR = crm.DATA_DIR / "docs"
        crm.HISTORIAL_CSV = crm.DATA_DIR / "historial.csv"
        
        print(f"🧹 Limpieza del test completada")

    def test_01_funciones_auxiliares(self):
        """Test 1: Verificar funciones auxiliares"""
        print("\n📋 Test 1: Funciones auxiliares")
        
        # Test safe_name
        nombre_seguro = safe_name("José María O'Connor")
        self.assertIsInstance(nombre_seguro, str)
        self.assertNotIn("/", nombre_seguro)
        print(f"   ✅ safe_name: '{nombre_seguro}'")
        
        # Test canonicalize_from_catalog
        catalog = ["DISPERSADO", "EN ONBOARDING", "PENDIENTE CLIENTE"]
        resultado = canonicalize_from_catalog("dispersado", catalog)
        self.assertEqual(resultado, "DISPERSADO")
        print(f"   ✅ canonicalize_from_catalog: '{resultado}'")
        
        # Test nuevo_id_cliente
        df_vacio = pd.DataFrame(columns=COLUMNS)
        nuevo_id = nuevo_id_cliente(df_vacio)
        self.assertTrue(nuevo_id.startswith("C"))
        print(f"   ✅ nuevo_id_cliente: '{nuevo_id}'")

    def test_02_gestion_clientes_basica(self):
        """Test 2: Gestión básica de clientes"""
        print("\n👤 Test 2: Gestión básica de clientes")
        
        # Crear DataFrame de clientes de prueba
        clientes_test = pd.DataFrame([
            {
                "id": "C1000",
                "nombre": "Juan Pérez",
                "sucursal": "TOXQUI",
                "asesor": "María González",
                "fecha_ingreso": "2024-01-15",
                "fecha_dispersion": "2024-01-20",
                "estatus": "DISPERSADO",
                "monto_propuesta": "100000",
                "monto_final": "95000",
                "segundo_estatus": "",
                "observaciones": "Cliente de prueba",
                "score": "750",
                "telefono": "5551234567",
                "correo": "juan.perez@test.com",
                "analista": "Ana López",
                "fuente": "Referral"
            },
            {
                "id": "C1001",
                "nombre": "María Rodríguez",
                "sucursal": "COLOKTE",
                "asesor": "Carlos Sánchez",
                "fecha_ingreso": "2024-01-16",
                "fecha_dispersion": "",
                "estatus": "EN ONBOARDING",
                "monto_propuesta": "75000",
                "monto_final": "",
                "segundo_estatus": "PEND.DOC.PARA EVALUACION",
                "observaciones": "",
                "score": "680",
                "telefono": "5557654321",
                "correo": "maria.rodriguez@test.com",
                "analista": "Roberto Kim",
                "fuente": "Landing"
            }
        ])
        
        # Guardar clientes
        guardar_clientes(clientes_test)
        self.assertTrue(Path(self.test_dir, "clientes.csv").exists())
        print("   ✅ Guardado de clientes exitoso")
        
        # Cargar clientes
        clientes_cargados = cargar_clientes()
        self.assertEqual(len(clientes_cargados), 2)
        self.assertEqual(clientes_cargados.iloc[0]["nombre"], "Juan Pérez")
        print(f"   ✅ Carga de clientes exitosa: {len(clientes_cargados)} clientes")
        
        # Test cargar_y_corregir_clientes
        clientes_corregidos = cargar_y_corregir_clientes()
        self.assertEqual(len(clientes_corregidos), 2)
        print("   ✅ Carga y corrección de clientes exitosa")

    def test_03_correccion_ids(self):
        """Test 3: Corrección de IDs duplicados/vacíos"""
        print("\n🔧 Test 3: Corrección de IDs")
        
        # Crear DataFrame con IDs problemáticos
        df_problematico = pd.DataFrame([
            {"id": "", "nombre": "Sin ID 1", "sucursal": "TOXQUI", "asesor": "Test"},
            {"id": "C1000", "nombre": "ID Duplicado 1", "sucursal": "COLOKTE", "asesor": "Test"},
            {"id": "C1000", "nombre": "ID Duplicado 2", "sucursal": "BEWORK", "asesor": "Test"},
            {"id": "", "nombre": "Sin ID 2", "sucursal": "TOXQUI", "asesor": "Test"}
        ])
        
        # Agregar columnas faltantes
        for col in COLUMNS:
            if col not in df_problematico.columns:
                df_problematico[col] = ""
        
        # Corregir IDs
        df_corregido = _fix_missing_or_duplicate_ids(df_problematico)
        
        # Verificar que no hay IDs vacíos
        ids_vacios = df_corregido["id"].str.strip() == ""
        self.assertEqual(ids_vacios.sum(), 0)
        print("   ✅ No hay IDs vacíos después de la corrección")
        
        # Verificar que no hay IDs duplicados
        ids_duplicados = df_corregido["id"].duplicated().sum()
        self.assertEqual(ids_duplicados, 0)
        print("   ✅ No hay IDs duplicados después de la corrección")
        
        # Verificar que todos los IDs tienen formato correcto
        ids_correctos = df_corregido["id"].str.startswith("C").all()
        self.assertTrue(ids_correctos)
        print("   ✅ Todos los IDs tienen formato correcto (C####)")

    def test_04_gestion_asesores(self):
        """Test 4: Gestión de asesores"""
        print("\n👥 Test 4: Gestión de asesores")
        
        # Crear DataFrame con variaciones de nombres de asesores
        df_asesores = pd.DataFrame([
            {"id": "C1000", "nombre": "Cliente 1", "asesor": "María González"},
            {"id": "C1001", "nombre": "Cliente 2", "asesor": "maria gonzalez"},  # minúsculas
            {"id": "C1002", "nombre": "Cliente 3", "asesor": "MARÍA GONZÁLEZ"},  # mayúsculas
            {"id": "C1003", "nombre": "Cliente 4", "asesor": "  María González  "},  # espacios
            {"id": "C1004", "nombre": "Cliente 5", "asesor": "Carlos Sánchez"}
        ])
        
        # Agregar columnas faltantes
        for col in COLUMNS:
            if col not in df_asesores.columns:
                df_asesores[col] = ""
        
        # Test find_matching_asesor
        asesor_normalizado = find_matching_asesor("maria gonzalez", df_asesores)
        self.assertEqual(asesor_normalizado, "María González")
        print(f"   ✅ Normalización de asesor: '{asesor_normalizado}'")
        
        # Test con asesor nuevo
        asesor_nuevo = find_matching_asesor("Roberto Kim", df_asesores)
        self.assertEqual(asesor_nuevo, "Roberto Kim")
        print(f"   ✅ Asesor nuevo: '{asesor_nuevo}'")

    def test_05_gestion_documentos(self):
        """Test 5: Gestión de documentos"""
        print("\n📁 Test 5: Gestión de documentos")
        
        # Crear cliente para prueba de documentos
        cliente_id = "C1000"
        cliente_nombre = "Juan Pérez Test"
        
        # Test carpeta_docs_cliente
        carpeta = carpeta_docs_cliente(cliente_id)
        self.assertTrue(carpeta.exists())
        self.assertTrue(carpeta.is_dir())
        print(f"   ✅ Carpeta de documentos creada: {carpeta}")
        
        # Crear archivo de prueba
        archivo_test = carpeta / "test_documento.pdf"
        archivo_test.write_text("Contenido de prueba del documento PDF")
        
        # Test listar_docs_cliente
        docs = listar_docs_cliente(cliente_id)
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0].name, "test_documento.pdf")
        print(f"   ✅ Listado de documentos: {len(docs)} archivos encontrados")
        
        # Simular subida de archivos (mock)
        class MockFile:
            def __init__(self, name, content):
                self.name = name
                self.content = content.encode('utf-8')
            
            def getbuffer(self):
                return self.content
        
        mock_files = [MockFile("estado_cuenta.pdf", "Contenido estado cuenta")]
        
        # Test subir_docs
        archivos_subidos = subir_docs(cliente_id, mock_files, prefijo="estado_")
        self.assertEqual(len(archivos_subidos), 1)
        print(f"   ✅ Subida de documentos: {len(archivos_subidos)} archivos subidos")
        
        # Verificar que el archivo se guardó
        docs_actualizados = listar_docs_cliente(cliente_id)
        self.assertEqual(len(docs_actualizados), 2)  # archivo original + nuevo
        print(f"   ✅ Total de documentos después de subida: {len(docs_actualizados)}")

    def test_06_historial_movimientos(self):
        """Test 6: Historial de movimientos"""
        print("\n📋 Test 6: Historial de movimientos")
        
        # Test append_historial
        cliente_id = "C1000"
        nombre_cliente = "Juan Pérez"
        
        append_historial(
            cid=cliente_id,
            nombre=nombre_cliente,
            estatus_old="PENDIENTE CLIENTE",
            estatus_new="DISPERSADO",
            seg_old="",
            seg_new="DISPERSADO",
            observaciones="Cambio de estatus por test",
            action="ESTATUS MODIFICADO",
            actor="test_user"
        )
        
        # Verificar que se creó el archivo de historial
        self.assertTrue(Path(self.test_dir, "historial.csv").exists())
        print("   ✅ Archivo de historial creado")
        
        # Test cargar_historial
        historial = cargar_historial()
        self.assertEqual(len(historial), 1)
        self.assertEqual(historial.iloc[0]["id"], cliente_id)
        self.assertEqual(historial.iloc[0]["action"], "ESTATUS MODIFICADO")
        print(f"   ✅ Carga de historial: {len(historial)} registros")
        
        # Agregar otro movimiento
        append_historial(
            cid=cliente_id,
            nombre=nombre_cliente,
            estatus_old="DISPERSADO",
            estatus_new="DISPERSADO",
            seg_old="",
            seg_new="",
            observaciones="Documentos subidos: estado_cuenta.pdf",
            action="DOCUMENTOS",
            actor="test_user"
        )
        
        # Verificar múltiples registros
        historial_actualizado = cargar_historial()
        self.assertEqual(len(historial_actualizado), 2)
        print(f"   ✅ Historial actualizado: {len(historial_actualizado)} registros")

    def test_07_catalogos_configuracion(self):
        """Test 7: Catálogos y configuración"""
        print("\n⚙️ Test 7: Catálogos y configuración")
        
        # Test load_sucursales y save_sucursales
        sucursales_test = ["TOXQUI", "COLOKTE", "BEWORK", "NUEVA_SUCURSAL"]
        save_sucursales(sucursales_test)
        sucursales_cargadas = load_sucursales()
        self.assertEqual(len(sucursales_cargadas), 4)
        self.assertIn("NUEVA_SUCURSAL", sucursales_cargadas)
        print(f"   ✅ Gestión de sucursales: {len(sucursales_cargadas)} sucursales")
        
        # Test load_estatus y save_estatus
        estatus_test = ESTATUS_OPCIONES + ["NUEVO_ESTATUS_TEST"]
        save_estatus(estatus_test)
        estatus_cargados = load_estatus()
        self.assertIn("NUEVO_ESTATUS_TEST", estatus_cargados)
        print(f"   ✅ Gestión de estatus: {len(estatus_cargados)} opciones")
        
        # Verificar columnas obligatorias
        self.assertIn("id", COLUMNS)
        self.assertIn("nombre", COLUMNS)
        self.assertIn("estatus", COLUMNS)
        print(f"   ✅ Columnas definidas: {len(COLUMNS)} columnas")

    def test_08_integracion_completa(self):
        """Test 8: Integración completa del flujo"""
        print("\n🔄 Test 8: Integración completa")
        
        # 1. Crear cliente
        cliente_nuevo = pd.DataFrame([{
            "id": "",  # ID vacío para que se genere automáticamente
            "nombre": "Cliente Integración",
            "sucursal": "TOXQUI",
            "asesor": "Asesor Test",
            "fecha_ingreso": date.today().strftime("%Y-%m-%d"),
            "fecha_dispersion": "",
            "estatus": "PENDIENTE CLIENTE",
            "monto_propuesta": "50000",
            "monto_final": "",
            "segundo_estatus": "",
            "observaciones": "Cliente creado por test de integración",
            "score": "700",
            "telefono": "5551234567",
            "correo": "integracion@test.com",
            "analista": "Test Analyst",
            "fuente": "Test"
        }])
        
        # Agregar columnas faltantes
        for col in COLUMNS:
            if col not in cliente_nuevo.columns:
                cliente_nuevo[col] = ""
        
        # 2. Guardar y cargar con corrección de IDs
        guardar_clientes(cliente_nuevo)
        clientes = cargar_y_corregir_clientes()
        
        cliente_id = clientes.iloc[0]["id"]
        self.assertTrue(cliente_id.startswith("C"))
        print(f"   ✅ Cliente creado con ID: {cliente_id}")
        
        # 3. Subir documento
        class MockFile:
            def __init__(self, name, content):
                self.name = name
                self.content = content.encode('utf-8')
            def getbuffer(self):
                return self.content
        
        mock_doc = [MockFile("solicitud_completa.pdf", "Contenido de solicitud")]
        docs_subidos = subir_docs(cliente_id, mock_doc, prefijo="solic_")
        self.assertEqual(len(docs_subidos), 1)
        print(f"   ✅ Documento subido: {docs_subidos[0]}")
        
        # 4. Cambiar estatus y registrar historial
        append_historial(
            cid=cliente_id,
            nombre="Cliente Integración",
            estatus_old="PENDIENTE CLIENTE",
            estatus_new="EN ONBOARDING",
            seg_old="",
            seg_new="PEND.DOC.PARA EVALUACION",
            observaciones="Cambio de estatus por test de integración",
            action="ESTATUS MODIFICADO",
            actor="test_integration"
        )
        
        # 5. Verificar historial
        historial = cargar_historial()
        self.assertGreater(len(historial), 0)
        print(f"   ✅ Historial registrado: {len(historial)} movimientos")
        
        # 6. Verificar documentos
        docs = listar_docs_cliente(cliente_id)
        self.assertEqual(len(docs), 1)
        print(f"   ✅ Documentos verificados: {len(docs)} archivos")
        
        print("   🎉 ¡Flujo de integración completo exitoso!")

def ejecutar_test_diagnostico():
    """Ejecuta un diagnóstico rápido del sistema"""
    print("🔍 DIAGNÓSTICO RÁPIDO DEL SISTEMA CRM")
    print("=" * 50)
    
    # 1. Verificar importaciones
    try:
        import streamlit
        print("✅ Streamlit disponible")
    except ImportError:
        print("❌ Streamlit NO disponible")
    
    try:
        import pandas as pd
        print("✅ Pandas disponible")
    except ImportError:
        print("❌ Pandas NO disponible")
    
    try:
        import gspread
        print("✅ Gspread disponible")
    except ImportError:
        print("❌ Gspread NO disponible (opcional para Google Sheets)")
    
    # 2. Verificar directorios
    print(f"\n📁 Directorio de datos: {DATA_DIR}")
    print(f"   Existe: {'✅' if DATA_DIR.exists() else '❌'}")
    
    print(f"📁 Directorio de documentos: {DOCS_DIR}")
    print(f"   Existe: {'✅' if DOCS_DIR.exists() else '❌'}")
    
    # 3. Verificar archivos principales
    print(f"\n📄 Archivo de clientes: {CLIENTES_CSV}")
    print(f"   Existe: {'✅' if CLIENTES_CSV.exists() else '❌'}")
    
    print(f"📄 Archivo de historial: {HISTORIAL_CSV}")
    print(f"   Existe: {'✅' if HISTORIAL_CSV.exists() else '❌'}")
    
    # 4. Verificar configuración
    print(f"\n⚙️ Columnas definidas: {len(COLUMNS)}")
    print(f"⚙️ Opciones de estatus: {len(ESTATUS_OPCIONES)}")
    print(f"⚙️ Opciones segundo estatus: {len(SEGUNDO_ESTATUS_OPCIONES)}")
    print(f"⚙️ Sucursales: {len(SUCURSALES)}")
    
    # 5. Test básico de carga
    try:
        df = cargar_clientes()
        print(f"✅ Carga de clientes exitosa: {len(df)} registros")
    except Exception as e:
        print(f"❌ Error al cargar clientes: {e}")
    
    print("\n" + "=" * 50)

def main():
    """Función principal para ejecutar todos los tests"""
    print("🧪 INICIANDO TESTS COMPLETOS DEL SISTEMA CRM")
    print("=" * 60)
    
    # Ejecutar diagnóstico inicial
    ejecutar_test_diagnostico()
    
    print("\n🧪 EJECUTANDO TESTS UNITARIOS")
    print("=" * 60)
    
    # Ejecutar tests unitarios
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    print("\n🎉 TESTS COMPLETADOS")
    print("=" * 60)
    print("✅ Si todos los tests pasaron, el sistema CRM está funcionando correctamente")
    print("❌ Si hay tests fallidos, revisa los errores mostrados arriba")
    print("\n📝 RECOMENDACIONES:")
    print("   - Ejecuta este test después de cualquier cambio importante")
    print("   - Usa 'python test_crm_completo.py' para verificar el sistema")
    print("   - Los tests crean archivos temporales que se limpian automáticamente")

if __name__ == "__main__":
    main()