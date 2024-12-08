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
if app.secret_key == "default_secret_key":
    app.logger.warning("Usando clave secreta predeterminada. Esto no es seguro para producción.")
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

def get_postgres_cursor():
    conn = get_postgres_connection()
    if conn:
        return conn.cursor(), conn  # Devolver también la conexión para usar 'with'
    return None, None

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
print("GOOGLE_CLIENT_ID:", os.getenv('GOOGLE_CLIENT_ID'))
print("GOOGLE_CLIENT_SECRET:", os.getenv('GOOGLE_CLIENT_SECRET'))
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
            cursor, conn = get_postgres_cursor()
            if cursor:
                cursor.execute("""INSERT INTO users (username, email, firstname, lastname, password)
                                  VALUES (%s, %s, %s, %s, %s)""",
                               (username, email, firstname, lastname, hashed_password))
                conn.commit()  # Asegúrate de hacer commit desde la conexión
                cursor.close()
                conn.close()  # Cerrar la conexión explícitamente
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
            cursor, conn = get_postgres_cursor()
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
    state = str(uuid.uuid4())  # Generar un nuevo valor de estado
    session['oauth_state'] = state  # Guardarlo en la sesión
    redirect_uri = url_for('login_callback', _external=True)  # Corregido aquí
    return google.authorize_redirect(redirect_uri, state=state)

@app.route('/google/callback')
def login_callback():
    try:
        # Verificar el estado antes de continuar
        if request.args.get('state') != session.get('oauth_state'):
            raise Exception("State mismatch error!")

        # Continuar con la autenticación de Google
        token = google.authorize_access_token()
        user_info = google.get('userinfo').json()

        # Verificar si el usuario ya existe en la base de datos
        connection = get_postgres_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", [user_info['email']])
        user = cursor.fetchone()

        if not user:
            # Crear un nuevo usuario si no existe
            hashed_password = bcrypt.generate_password_hash(str(uuid.uuid4())).decode('utf-8')
            cursor.execute(""" 
                INSERT INTO users (username, email, firstname, lastname, password) 
                VALUES (%s, %s, %s, %s, %s)
            """, (user_info['email'], user_info['email'], user_info['given_name'], user_info['family_name'], hashed_password))
            connection.commit()

        cursor.close()

        # Iniciar sesión y almacenar información en la sesión
        session['loggedin'] = True
        session['username'] = user_info['email']
        session['email'] = user_info['email']
        session['name'] = user_info['name']
        session['picture'] = user_info.get('picture', '')

        flash('Inicio de sesión con Google exitoso.')
        return redirect(url_for('home'))

    except Exception as e:
        flash(f"Error durante la autenticación con Google: {e}")
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
                
                # Insertar la tarea en PostgreSQL
                cursor, conn = get_postgres_cursor()
                if cursor:
                    cursor.execute("""INSERT INTO tasks (user_id, name, checked, priority) 
                                    VALUES (%s, %s, %s, %s)""",
                                   (user_id, encrypted_name, False, priority))
                    conn.commit()
                    cursor.close()
                    conn.close()
                
                flash('Tarea añadida exitosamente.')
            except Exception as e:
                app.logger.error("Error al agregar tarea: %s", str(e))
                flash('Error al agregar tarea.')

    # Consultar las tareas desde PostgreSQL
    try:
        cursor, conn = get_postgres_cursor()
        if cursor:
            cursor.execute("SELECT * FROM tasks WHERE user_id = %s", (user_id,))
            tasks = cursor.fetchall()
            decrypted_todos = []

            for task in tasks:
                try:
                    decrypted_name = cipher_suite.decrypt(task[1].encode()).decode()  # Asegúrate de que 'task[1]' es el nombre cifrado
                    decrypted_todos.append({**task, 'name': decrypted_name})
                except Exception as e:
                    app.logger.error("Error al descifrar tarea: %s", str(e))
            
            cursor.close()
            conn.close()

        return render_template('home.html', todos=decrypted_todos)
    except Exception as e:
        app.logger.error("Error al obtener tareas: %s", str(e))
        return render_template('home.html', todos=[])

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))