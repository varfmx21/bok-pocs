# Secure password storage

A small Flask application that stores user accounts in MariaDB. Passwords are
processed with Argon2id and an application pepper before they are stored.

> This project is for local development and learning. The application currently
> runs Flask with `debug=True`; do not expose it directly to the internet.

## Requirements

- Linux
- Python 3.14 or newer
- MariaDB server and client
- A MariaDB user that can access the `login` database

## 1. Install system packages

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install mariadb-server mariadb-client python3-venv
```

Start MariaDB and enable it at boot:

```bash
sudo systemctl enable --now mariadb
```

Check that the server is running:

```bash
sudo systemctl status mariadb
```

## 2. Create a Python virtual environment

From the project directory:

```bash
cd <your dir>/bok-pocs/secure-password-storage
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Activate the virtual environment again whenever you open a new terminal:

```bash
source .venv/bin/activate
```

## 3. Create the MariaDB user

Open MariaDB as an administrator:

```bash
sudo mariadb
```

Run the following SQL. Replace the password with a strong password of your
choice:

```sql
CREATE USER 'bok_app'@'localhost' IDENTIFIED BY 'replace-with-a-strong-password';
GRANT ALL PRIVILEGES ON `login`.* TO 'bok_app'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

## 4. Create the database and table

The schema creates the `login` database and the `accounts` table:

```bash
sudo mariadb -u root -p < schema.sql
```

Verify that the table exists:

```bash
mariadb -u bok_app -p -e "USE login; DESCRIBE accounts;"
```

If `accounts` already existed before the current schema was added, run the
necessary `ALTER TABLE` migration before starting the application. The
`CREATE TABLE IF NOT EXISTS` statement does not add missing columns to an
existing table.

## 5. Configure environment variables

Create a local `.env` file from the example:

```bash
cp .env.example .env
```

Edit `.env` and set values for every variable:

```dotenv
MYSQL_USER=bok_app
MYSQL_PASSWORD=replace-with-a-strong-password
SECRET_KEY_FLASK=generate-a-long-random-value
PEPPER=generate-a-different-long-random-value
PEPPER_VERSION=1
```

Generate secure random values with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

The application reads environment variables directly; it does not load `.env`
automatically. Export the variables before starting Flask:

```bash
set -a
source .env
set +a
```

Keep `.env` private and do not commit it to Git.

## 6. Run the application

With the virtual environment active and the variables exported:

```bash
python app.py
```

Open the application in a browser:

- Login: <http://127.0.0.1:5000/login>
- Registration: <http://127.0.0.1:5000/register>

Stop the server with `Ctrl+C`.