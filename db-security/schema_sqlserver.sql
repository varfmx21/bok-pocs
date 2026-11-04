CREATE TABLE accounts (
    id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pepper_version INT NOT NULL,
    argon2_params NVARCHAR(MAX) NOT NULL,    
    email VARCHAR(100) COLLATE Latin1_General_BIN2 NOT NULL,
    full_name NVARCHAR(100) COLLATE Latin1_General_BIN2 NULL,
    phone VARCHAR(20) COLLATE Latin1_General_BIN2 NULL,
    national_id VARCHAR(30) COLLATE Latin1_General_BIN2 NULL,
    birth_date DATE NULL
);
GO

-- Execute whent SMMS create the awlays encrypted column
CREATE UNIQUE INDEX UX_accounts_email ON accounts (email);