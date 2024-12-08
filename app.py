import logging
import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, session
from pymongo import MongoClient
from cryptography.fernet import Fernet
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from datetime import timedelta

# Configurar logger
logging.basicConfig(level=logging.DEBUG)

# Cargar variables de entorno
load_dotenv(dotenv_path='variables.env')

# Inicializar la app Flask
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_secret_key")
app.permanent_session_lifetime = timedelta(minutes=30)

# Configuración de MySQL
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_PORT'] = int(os.getenv('MYSQL_PORT', 3306))

mysql = MySQL(app)
bcrypt = Bcrypt(app)

# Configuración de MongoDB
try:
    client = MongoClient(os.getenv('MONGO_URI', 'mongodb://localhost:27017/'))
    db = client['Users_Tasks']
    todos_collection = db['Tasks']
except Exception as e:
    app.logger.error("Error al conectar a MongoDB: %s", str(e))

# Cargar clave para cifrado
key_path = "secret.key"
if os.path.exists(key_path):
    with open(key_path, "rb") as key_file:
        key = key_file.read()
else:
    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)
cipher_suite = Fernet(key)

# Configuración de OAuth
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    api_base_url='https://www.googleapis.com/oauth2/v2/',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

# Funciones auxiliares
def get_mysql_cursor():
    try:
        return mysql.connection.cursor()
    except Exception as e:
        app.logger.error("Error al obtener cursor MySQL: %s", str(e))
        return None

def validate_todo_data(todo_name):
    return todo_name.strip() if todo_name else None

# Rutas
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            cursor = get_mysql_cursor()
            if cursor:
                cursor.execute("""INSERT INTO users (username, email, firstname, lastname, password)
                                  VALUES (%s, %s, %s, %s, %s)""",
                               (username, email, firstname, lastname, hashed_password))
                mysql.connection.commit()
                cursor.close()
                flash('Usuario registrado exitosamente.')
                return redirect(url_for('login'))
        except Exception as e:
            app.logger.error("Error al registrar usuario: %s", str(e))
            flash('Error al registrar usuario. Por favor, inténtelo nuevamente.')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'loggedin' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        try:
            cursor = get_mysql_cursor()
            if cursor:
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()
                cursor.close()

                if user and bcrypt.check_password_hash(user[4], password_candidate):
                    session['loggedin'] = True
                    session['username'] = user[1]
                    session['email'] = user[2]
                    flash('Inicio de sesión exitoso.')
                    return redirect(url_for('home'))
                else:
                    flash('Credenciales incorrectas.')
        except Exception as e:
            app.logger.error("Error al iniciar sesión: %s", str(e))
            flash('Error al iniciar sesión. Por favor, inténtelo nuevamente.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión.')
    return redirect(url_for('login'))

@app.route("/", methods=["GET", "POST"])
@app.route("/home", methods=["GET", "POST"])
def home():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    user_id = session.get('username')

    if request.method == "POST":
        todo_name = validate_todo_data(request.form.get("todo_name", ""))
        priority = request.form.get("priority", "3")

        if todo_name:
            try:
                encrypted_name = cipher_suite.encrypt(todo_name.encode()).decode()
                todos_collection.insert_one({
                    'user_id': user_id,
                    'id': str(uuid.uuid4()),
                    'name': encrypted_name,
                    'checked': False,
                    'priority': priority
                })
                flash('Tarea añadida exitosamente.')
            except Exception as e:
                app.logger.error("Error al agregar tarea: %s", str(e))
                flash('Error al agregar tarea.')

    todos = todos_collection.find({'user_id': user_id})
    decrypted_todos = []
    for todo in todos:
        try:
            decrypted_name = cipher_suite.decrypt(todo['name'].encode()).decode()
            decrypted_todos.append({
                'id': todo['id'],
                'name': decrypted_name,
                'checked': todo['checked'],
                'priority': todo['priority']
            })
        except Exception:
            app.logger.error("Error al descifrar tarea.")
            continue

    return render_template("home.html", todos=decrypted_todos)

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))