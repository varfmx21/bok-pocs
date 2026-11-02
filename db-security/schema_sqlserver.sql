-- 1. BASELINE TABLE PROVISIONING (In case the database environment is clean)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'accounts')
BEGIN
    CREATE TABLE accounts (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(100) COLLATE Latin1_General_BIN2 NOT NULL UNIQUE,
        salt VARBINARY(16) NOT NULL,
        pepper_version INT NOT NULL,
        argon2_params NVARCHAR(MAX) NOT NULL,
        full_name NVARCHAR(100) COLLATE Latin1_General_BIN2 NULL,
        phone VARCHAR(20) COLLATE Latin1_General_BIN2 NULL,
        national_id VARCHAR(30) COLLATE Latin1_General_BIN2 NULL,
        birth_date DATE NULL
    );
END;
GO

-- 2. DYNAMIC COLUMN UPGRADE & COLLATION ALTERATION
-- Safely appends new PII attributes with required cryptographic properties
IF EXISTS (SELECT * FROM sys.tables WHERE name = 'accounts')
BEGIN
    -- Add full_name (Target: Always Encrypted - Randomized)
    IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('accounts') AND name = 'full_name')
        ALTER TABLE accounts ADD full_name NVARCHAR(100) COLLATE Latin1_General_BIN2 NULL;

    -- Add phone (Target: Always Encrypted - Randomized)
    IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('accounts') AND name = 'phone')
        ALTER TABLE accounts ADD phone VARCHAR(20) COLLATE Latin1_General_BIN2 NULL;

    -- Add national_id (Target: Always Encrypted - Randomized)
    IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('accounts') AND name = 'national_id')
        ALTER TABLE accounts ADD national_id VARCHAR(30) COLLATE Latin1_General_BIN2 NULL;

    -- Add birth_date (Target: Always Encrypted - Randomized. Date types do not require text collation)
    IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('accounts') AND name = 'birth_date')
        ALTER TABLE accounts ADD birth_date DATE NULL;

    ALTER TABLE accounts ALTER COLUMN email VARCHAR(100) COLLATE Latin1_General_BIN2 NOT NULL;
END;
GO
