import re

with open(r'C:\Windows\System32\msodbcsql18.dll', 'rb') as f:
    content = f.read()

# Search ascii strings
ascii_strs = set(re.findall(rb'[A-Za-z0-9_:\/\.\-\?=&]{6,}', content))
# Search utf16 strings
utf16_strs = set(re.findall(rb'(?:[A-Za-z0-9_:\/\.\-\?=&]\x00){6,}', content))

print("=== AKV / KeyVault keywords in msodbcsql18.dll ===")
for s in sorted(ascii_strs):
    if b'KeyVault' in s or b'vault' in s.lower() or b'keystore' in s.lower():
        print("ASCII:", s.decode('ascii', errors='ignore'))

for s in sorted(utf16_strs):
    decoded = s.decode('utf-16le', errors='ignore')
    if 'KeyVault' in decoded or 'vault' in decoded.lower() or 'keystore' in decoded.lower() or 'always' in decoded.lower():
        print("UTF16:", decoded)

