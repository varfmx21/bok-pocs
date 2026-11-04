import json
import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, session
import pyodbc
import re
import hmac
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from dotenv import load_dotenv

load_dotenv()

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=Type.ID
)

pepper = os.environ.get('PEPPER')
pepper_version = os.environ.get('PEPPER_VERSION')

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY_FLASK')

def get_db_connection():
    connection_string = (os.environ.get('AZURE_SQL_CONNECTIONSTRING'))
    return pyodbc.connect(connection_string)

def row_to_dict(cursor, row):
    if not row:
        return None
    columns = [column[0] for column in cursor.description]
    return dict(zip(columns, row))

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.setinputsizes([(pyodbc.SQL_VARCHAR, 50, 0)])
        cursor.execute('SELECT id, username, password, salt FROM accounts WHERE username = ?', (username,))
        account = row_to_dict(cursor, cursor.fetchone())
        cursor.close()
        conn.close()

        login_success = False
        try:
            if account:
                possible_argon2id_hash_raw = ph.hash(
                    password,
                    salt=account['salt']
                )

                possible_hmac_hash = hmac.new(
                    key=pepper.encode('utf-8'),
                    msg=possible_argon2id_hash_raw.encode('utf-8'),
                    digestmod='sha256'
                ).hexdigest()

                if hmac.compare_digest(possible_hmac_hash, account['password']):
                    login_success = True
                    print(f"Login successful for user: {username}")
                else:
                    login_success = False
                    print(f"Login failed for user: {username} - Incorrect password.")
        except (VerifyMismatchError, InvalidHashError):
            login_success = False

        if login_success and account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            user_id = account['id']

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username, email, national_id, phone FROM accounts WHERE id = ?", (user_id,))
            account_data = row_to_dict(cursor, cursor.fetchone())
            cursor.close()
            conn.close()

            return render_template('index.html', msg='Logged in successfully!', account=account_data)
        else:
            msg = 'Incorrect username/password!'

    if 'loggedin' in session:
        user_id = session.get('id')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username, email, national_id, phone FROM accounts WHERE id = ?", (user_id,))
        account_data = row_to_dict(cursor, cursor.fetchone())
        cursor.close()
        conn.close()
        return render_template('index.html', account=account_data)

    return render_template('login.html', msg=msg)


@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        national_id = request.form.get('national_id')
        birth_date_raw = request.form.get('birth_Date') or request.form.get('birth_date')
        birth_date = None
        if birth_date_raw:
            try:
                birth_date = datetime.date.fromisoformat(birth_date_raw)
            except (ValueError, TypeError):
                birth_date = birth_date_raw

        custom_salt = os.urandom(16)

        argon2id_hash_raw = ph.hash(
            password,
            salt=custom_salt
        )

        hmac_hash = hmac.new(
            key=pepper.encode('utf-8'),
            msg=argon2id_hash_raw.encode('utf-8'),
            digestmod='sha256'
        ).hexdigest()

        argon2_config = {
            "t": ph.time_cost,
            "m": ph.memory_cost,
            "p": ph.parallelism,
            "l": ph.hash_len,
            "v": ph.type.value
        }
        argon2_params_json = json.dumps(argon2_config)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.setinputsizes(
            [(pyodbc.SQL_VARCHAR, 50, 0), 
             (pyodbc.SQL_VARCHAR, 100, 0)]
        )
        cursor.execute(
            'SELECT id, username, email FROM accounts WHERE username = ? OR email = ?',
            (username, email)
        )
        account = row_to_dict(cursor, cursor.fetchone())

        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only letters and numbers!'
        elif not username or not password or not email or not full_name or not phone or not national_id or not birth_date:
            msg = 'Please fill out the form!'
        else:
            cursor.setinputsizes([
                (pyodbc.SQL_VARCHAR, 50, 0),    # username
                (pyodbc.SQL_VARCHAR, 255, 0),   # password
                (pyodbc.SQL_VARCHAR, 100, 0),   # email
                (pyodbc.SQL_VARBINARY, 16, 0),  # salt
                pyodbc.SQL_INTEGER,             # pepper_version
                (pyodbc.SQL_WVARCHAR, 0, 0),    # argon2_params
                (pyodbc.SQL_WVARCHAR, 100, 0),  # full_name (Always Encrypted)
                (pyodbc.SQL_VARCHAR, 20, 0),    # phone (Always Encrypted)
                (pyodbc.SQL_VARCHAR, 30, 0),    # national_id (Always Encrypted)
                pyodbc.SQL_TYPE_DATE            # birth_date (Always Encrypted)
            ])
            cursor.execute(
                '''
                INSERT INTO accounts
                    (username, password, email, salt, pepper_version, argon2_params, full_name, phone, national_id, birth_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (username, hmac_hash, email, custom_salt, pepper_version, argon2_params_json, full_name, phone, national_id, birth_date)
            )
            conn.commit()
            msg = 'You have successfully registered!'

        cursor.close()
        conn.close()

    return render_template('register.html', msg=msg)


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, threaded=False)
