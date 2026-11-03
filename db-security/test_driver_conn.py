import pyodbc

# Test various connection strings to see what ODBC Driver 18 accepts for KeyStoreAuthentication
configs = [
    {
        "desc": "KeyVaultInteractive without principal",
        "conn_str": "DRIVER={ODBC Driver 18 for SQL Server};SERVER=poc-sql-security.database.windows.net,1433;DATABASE=poc-security-db;UID=varfmx21_admin;PWD=y&M5T$&32#vxdWP9a6Gf2z$eu4EhstdvuH@f$z*FYCGFP7JY3DXn&xSVMfyJayrD;Encrypt=yes;TrustServerCertificate=no;ColumnEncryption=Enabled;KeyStoreAuthentication=KeyVaultInteractive;"
    },
    {
        "desc": "ActiveDirectoryInteractive as DB auth + ColumnEncryption",
        "conn_str": "DRIVER={ODBC Driver 18 for SQL Server};SERVER=poc-sql-security.database.windows.net,1433;DATABASE=poc-security-db;Authentication=ActiveDirectoryInteractive;UID=608321@student.fontys.nl;Encrypt=yes;TrustServerCertificate=no;ColumnEncryption=Enabled;"
    }
]

print("Python pyodbc tester")

