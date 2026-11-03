import pyodbc
from dotenv import load_dotenv
import os
import urllib.request
import urllib.error
import json
import base64
from azure.identity import AzureCliCredential, InteractiveBrowserCredential, ChainedTokenCredential

load_dotenv()

SQL_SERVER = os.environ.get('SQL_SERVER')
SQL_DATABASE = os.environ.get('SQL_DATABASE')
SQL_USER = os.environ.get('SQL_USER')
SQL_PASSWORD = os.environ.get('SQL_PASSWORD')
SQL_DRIVER = os.environ.get('SQL_DRIVER', '{ODBC Driver 18 for SQL Server}')

print("=" * 70)
print("TEST REAL DE UNWRAP CON ECEK DESDE LA BASE DE DATOS")
print("=" * 70)

# 1. Obtener ECEK de la BD
conn_str = (
    f"DRIVER={SQL_DRIVER};"
    f"SERVER={SQL_SERVER},1433;"
    f"DATABASE={SQL_DATABASE};"
    f"UID={SQL_USER};"
    f"PWD={SQL_PASSWORD};"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
)
conn = pyodbc.connect(conn_str)
cursor = conn.cursor()

cursor.execute("""
    SELECT cmk.key_path, cekv.encrypted_value, cekv.encryption_algorithm_name
    FROM sys.column_encryption_key_values cekv
    JOIN sys.column_master_keys cmk ON cekv.column_master_key_id = cmk.column_master_key_id
""")
row = cursor.fetchone()
if not row:
    print("ERROR: No se encontró ningún Column Encryption Key en la base de datos.")
    exit(1)

key_path = row[0]
raw_ecek = row[1]
alg = row[2]
cursor.close()
conn.close()

print(f"Key Path: {key_path}")
print(f"Algorithm: {alg}")
print(f"Longitud de ECEK en BD: {len(raw_ecek)} bytes")

# Formato de ECEK en SQL Server Always Encrypted:
# El ECEK en SQL Server tiene una cabecera:
# [version: 1 byte (0x01)]
# [key_path_length: 2 bytes]
# [ciphertext_length: 2 bytes]
# [key_path: n bytes]
# [ciphertext: m bytes]
# [signature: 32 bytes]
# Vamos a extraer el ciphertext real de la cabecera si aplica:
version = raw_ecek[0]
print(f"Formato ECEK Version: {version}")

# 2. Obtener Token de Key Vault
print("\nObteniendo token de Azure Key Vault...")
credential = ChainedTokenCredential(AzureCliCredential(), InteractiveBrowserCredential())
token = credential.get_token("https://vault.azure.net/.default").token

# 3. Probar unwrapkey en Key Vault con el ciphertext
# Para SQL Server v1:
# Offset 0: version (1 byte)
# Offset 1..2: key_path_length (uint16 little endian)
# Offset 3..4: ciphertext_length (uint16 little endian)
# Offset 5..5+key_path_len: key path string
# Siguiente: ciphertext de RSA (típicamente 256 o 512 bytes)
# Últimos 32 bytes: HMAC-SHA256 signature
key_path_len = int.from_bytes(raw_ecek[1:3], byteorder='little')
ciphertext_len = int.from_bytes(raw_ecek[3:5], byteorder='little')
print(f"KeyPathLen en cabecera: {key_path_len}")
print(f"CiphertextLen en cabecera: {ciphertext_len}")

header_len = 1 + 2 + 2 + key_path_len
ciphertext = raw_ecek[header_len : header_len + ciphertext_len]
print(f"Bytes de Ciphertext extraídos: {len(ciphertext)}")

# Convertir a base64url para Azure Key Vault API
cipher_b64 = base64.urlsafe_b64encode(ciphertext).decode('utf-8').rstrip('=')

unwrap_url = f"{key_path}/unwrapkey?api-version=7.4"
payload = json.dumps({
    "alg": "RSA-OAEP",
    "value": cipher_b64
}).encode('utf-8')

req = urllib.request.Request(
    unwrap_url,
    data=payload,
    headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
)

try:
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read().decode('utf-8'))
        decrypted_cek_b64 = result.get('value')
        decrypted_cek = base64.urlsafe_b64decode(decrypted_cek_b64 + '==')
        print(f"\n[+] ¡ÉXITO TOTAL! Key Vault desencriptó el CEK correctamente.")
        print(f"    Longitud de la clave CEK desencriptada: {len(decrypted_cek)} bytes (esperado: 32 bytes para AES-256).")
except urllib.error.HTTPError as e:
    err_body = e.read().decode('utf-8')
    print(f"\n[-] ERROR de Key Vault (HTTP {e.code}):")
    print(err_body)
except Exception as e:
    print(f"\n[-] Error: {e}")

print("=" * 70)

