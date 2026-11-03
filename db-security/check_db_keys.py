import pyodbc
from dotenv import load_dotenv
import os

load_dotenv()

SQL_SERVER = os.environ.get('SQL_SERVER')
SQL_DATABASE = os.environ.get('SQL_DATABASE')
SQL_USER = os.environ.get('SQL_USER')
SQL_PASSWORD = os.environ.get('SQL_PASSWORD')
SQL_DRIVER = os.environ.get('SQL_DRIVER', '{ODBC Driver 18 for SQL Server}')

conn_str = (
    f"DRIVER={SQL_DRIVER};"
    f"SERVER={SQL_SERVER},1433;"
    f"DATABASE={SQL_DATABASE};"
    f"UID={SQL_USER};"
    f"PWD={SQL_PASSWORD};"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
)

print("Consultando metadata de Always Encrypted en la Base de Datos...")
conn = pyodbc.connect(conn_str)
cursor = conn.cursor()

print("\n--- 1. COLUMN MASTER KEYS (CMK) ---")
cursor.execute("SELECT name, key_store_provider_name, key_path, allow_enclave_computations FROM sys.column_master_keys")
for row in cursor.fetchall():
    print(f"Name: {row[0]}")
    print(f"Provider: {row[1]}")
    print(f"Key Path: {row[2]}")
    print(f"Allow Enclave: {row[3]}")

print("\n--- 2. COLUMN ENCRYPTION KEYS (CEK) ---")
cursor.execute("""
    SELECT cek.name, cekv.column_master_key_id, cmk.name as cmk_name, cekv.encryption_algorithm_name,
           len(cekv.encrypted_value) as val_len
    FROM sys.column_encryption_keys cek
    JOIN sys.column_encryption_key_values cekv ON cek.column_encryption_key_id = cekv.column_encryption_key_id
    JOIN sys.column_master_keys cmk ON cekv.column_master_key_id = cmk.column_master_key_id
""")
for row in cursor.fetchall():
    print(f"CEK Name: {row[0]}, CMK Name: {row[2]}, Algorithm: {row[3]}, Encrypted Value Length: {row[4]}")

print("\n--- 3. COLUMNAS ENCRIPTADAS EN 'accounts' ---")
cursor.execute("""
    SELECT c.name as column_name, c.encryption_type_desc, cek.name as cek_name
    FROM sys.columns c
    JOIN sys.column_encryption_keys cek ON c.column_encryption_key_id = cek.column_encryption_key_id
    WHERE c.object_id = OBJECT_ID('accounts')
""")
for row in cursor.fetchall():
    print(f"Columna: {row[0]}, Encriptación: {row[1]}, CEK: {row[2]}")

cursor.close()
conn.close()
print("\nListo!")

