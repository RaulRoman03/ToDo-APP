import logging
import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, session
from pymongo import MongoClient
from cryptography.fernet import Fernet
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from datetime import timedelta
import psycopg2
from psycopg2 import sql

# Configurar logger
logging.basicConfig(level=logging.DEBUG)

# Cargar variables de entorno
load_dotenv(dotenv_path='variables.env')

# Inicializar la app Flask
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_secret_key")  # Cargar clave secreta desde las variables de entorno
app.permanent_session_lifetime = timedelta(minutes=30)

# Configuración de PostgreSQL
app.config['POSTGRES_HOST'] = os.getenv('POSTGRES_HOST')
app.config['POSTGRES_USER'] = os.getenv('POSTGRES_USER')
app.config['POSTGRES_PASSWORD'] = os.getenv('POSTGRES_PASSWORD')
app.config['POSTGRES_DB'] = os.getenv('POSTGRES_DB')
app.config['POSTGRES_PORT'] = int(os.getenv('POSTGRES_PORT', 5432))

# Conexión a PostgreSQL
def get_postgres_connection():
    try:
        conn = psycopg2.connect(
            host=app.config['POSTGRES_HOST'],
            user=app.config['POSTGRES_USER'],
            password=app.config['POSTGRES_PASSWORD'],
            dbname=app.config['POSTGRES_DB'],
            port=app.config['POSTGRES_PORT']
        )
        return conn
    except Exception as e:
        app.logger.error("Error al conectar a PostgreSQL: %s", str(e))
        return None

# Inicializar bcrypt
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
def get_postgres_cursor():
    conn = get_postgres_connection()
    if conn:
        return conn.cursor()
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
            cursor = get_postgres_cursor()
            if cursor:
                cursor.execute("""INSERT INTO users (username, email, firstname, lastname, password)
                                  VALUES (%s, %s, %s, %s, %s)""",
                               (username, email, firstname, lastname, hashed_password))
                cursor.connection.commit()
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
            cursor = get_postgres_cursor()
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

@app.route('/login/google')
def login_google():
    # Redirigir a Google para iniciar sesión
    return google.authorize_redirect(redirect_uri=url_for('login_callback', _external=True))

@app.route('/google/callback')
def login_callback():
    try:
        # Obtener el token de Google
        google_token = google.authorize_access_token()

        # Obtener la información del usuario de Google
        user_info = google.parse_id_token(google_token)

        # Verificar si el ID del token es válido
        if user_info:
            session['loggedin'] = True
            session['username'] = user_info['name']
            session['email'] = user_info['email']
            flash('Inicio de sesión exitoso con Google.')
            return redirect(url_for('home'))  # Redirige a la página principal

    except Exception as e:
        app.logger.error("Error en callback de Google: %s", str(e))
        flash('Hubo un error al iniciar sesión con Google. Inténtalo de nuevo.')
        return redirect(url_for('login'))  # Redirige a la página de login

    return redirect(url_for('login'))

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
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))