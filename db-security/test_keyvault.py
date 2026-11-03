import urllib.request
import urllib.error
import json
import base64
from azure.identity import AzureCliCredential, InteractiveBrowserCredential, ChainedTokenCredential

AKV_TOKEN_SCOPE = "https://vault.azure.net/.default"
KEY_NAME = "Always-Encrypted-Auto1"
KEY_VERSION = "6f0bf1db22a1478b8f73b99db91c0c31"
BASE_URL = f"https://kv-poc-dbsecurity.vault.azure.net/keys/{KEY_NAME}/{KEY_VERSION}"

print("=" * 70)
print("DIAGNÓSTICO COMPLETO DE AZURE KEY VAULT")
print("=" * 70)

# 1. Obtener Token
print("\n[PASO 1] Obteniendo token de autenticación...")
credential = ChainedTokenCredential(AzureCliCredential(), InteractiveBrowserCredential())
try:
    token_obj = credential.get_token(AKV_TOKEN_SCOPE)
    token = token_obj.token
    print(" -> Token obtenido exitosamente.")
except Exception as e:
    print(f" -> ERROR crítico obteniendo token: {e}")
    exit(1)

# 2. Consultar la Key (GET)
print(f"\n[PASO 2] Verificando existencia y permisos de lectura (GET) de la clave...")
get_url = f"{BASE_URL}?api-version=7.4"
req_get = urllib.request.Request(get_url, headers={"Authorization": f"Bearer {token}"})

try:
    with urllib.request.urlopen(req_get) as response:
        data = json.loads(response.read().decode('utf-8'))
        print(f" -> ÉXITO (HTTP {response.status})")
        print(f"    - Key ID: {data.get('key', {}).get('kid')}")
        print(f"    - Tipo: {data.get('key', {}).get('kty')}")
        print(f"    - Operaciones permitidas en la key: {data.get('key', {}).get('key_ops')}")
        print(f"    - Estado Enabled: {data.get('attributes', {}).get('enabled')}")
except urllib.error.HTTPError as e:
    body = e.read().decode('utf-8')
    print(f" -> FALLO en GET (HTTP {e.code} {e.reason}):")
    try:
        print(json.dumps(json.loads(body), indent=2))
    except Exception:
        print(body)
except Exception as e:
    print(f" -> Error inesperado: {e}")

# 3. Probar Operación Criptográfica de Desencriptado (UNWRAPKEY / RSA_OAEP)
print(f"\n[PASO 3] Probando operación criptográfica (POST unwrapKey con RSA-OAEP)...")
unwrap_url = f"{BASE_URL}/unwrapkey?api-version=7.4"
# Simulamos un bloque de prueba de 256 bytes en base64url
dummy_cipher = base64.urlsafe_b64encode(b"0" * 256).decode('utf-8').rstrip('=')
payload = json.dumps({
    "alg": "RSA-OAEP",
    "value": dummy_cipher
}).encode('utf-8')

req_unwrap = urllib.request.Request(
    unwrap_url,
    data=payload,
    headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
)

try:
    with urllib.request.urlopen(req_unwrap) as response:
        print(f" -> ÉXITO (HTTP {response.status}): Tienes permiso de 'unwrapKey'!")
except urllib.error.HTTPError as e:
    body = e.read().decode('utf-8')
    print(f" -> RESPUESTA DE KEY VAULT (HTTP {e.code} {e.reason}):")
    try:
        err = json.loads(body)
        print(json.dumps(err, indent=2))
        
        # Analizar el mensaje
        inner_msg = err.get("error", {}).get("message", "")
        code = err.get("error", {}).get("code", "")
        print("\n--- ANÁLISIS DEL DIAGNÓSTICO ---")
        if e.code == 403:
            print("[!] Permiso DENEGADO (403 Forbidden).")
            print("    Detalle:", inner_msg)
        elif "InvalidParameter" in code or "BadPaddingException" in inner_msg or "padding" in inner_msg.lower() or "RSA" in inner_msg:
            print("[+] ¡TIENES PERMISOS DE UNWRAPKEY! (El error de padding es esperado porque usamos datos ficticios).")
        else:
            print(f"[?] Código de error: {code}")
            print(f"    Mensaje: {inner_msg}")
    except Exception:
        print(body)
except Exception as e:
    print(f" -> Error inesperado: {e}")

print("\n" + "=" * 70)
