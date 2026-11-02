-- Esquema para Azure SQL Database / SQL Server

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'accounts')
BEGIN
    CREATE TABLE accounts (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        salt VARBINARY(16) NOT NULL,
        pepper_version INT NOT NULL,
        argon2_params NVARCHAR(MAX) NOT NULL
    );
END;
