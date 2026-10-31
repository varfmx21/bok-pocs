import json
import os
from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import hmac
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, InvalidHashError

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=Type.ID
)

custom_salt = os.urandom(16)
pepper = os.environ.get('PEPPER')
pepper_version= os.environ.get('PEPPER_VERSION')

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY_FLASK')

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = 'login'

mysql = MySQL(app)

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username, ))
        account = cursor.fetchone()
        login = False
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
                    login = True
                    print("Login successful for user:", username)
                else:
                    login = False
                    print("Login failed for user:", username, "- Incorrect password.")
        except (VerifyMismatchError, InvalidHashError):
            login = False

        if login and account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            return render_template('index.html', msg='Logged in successfully!')
        else:
            msg = 'Incorrect username/password!'
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
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

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

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
        'SELECT * FROM accounts WHERE username = %s OR email = %s',
        (username, email)
        )
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only letters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            cursor.execute(
                '''
                INSERT INTO accounts
                    (username, password, email, salt, pepper_version, argon2_params)
                VALUES (%s, %s, %s, %s, %s, %s)
                ''',
                (username, hmac_hash, email, custom_salt, pepper_version, argon2_params_json)
            )
            mysql.connection.commit()
            msg = 'You have successfully registered!'
    return render_template('register.html', msg=msg)

if __name__ == '__main__':
    app.run(debug=True)