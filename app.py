import logging
from flask import Flask, render_template, url_for, request, redirect, flash, session
from pymongo import MongoClient
from cryptography.fernet import Fernet
import cryptography
import uuid
import os
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import MySQLdb.cursors
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from datetime import timedelta
import secrets

# Configuración del logger para ver los logs de depuración
logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)

# Usar FLASK_SECRET_KEY desde la variable de entorno
app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_secret_key")  # Valor por defecto si no está configurada

# MongoDB connection (para la lista de tareas)
client = MongoClient('mongodb://localhost:27017/')
db = client['Users_Tasks']
todos_collection = db['Tasks']

# Cargar o generar una clave para cifrado (para tareas y datos de usuarios)
key_path = "secret.key"
if os.path.exists(key_path):
    with open(key_path, "rb") as key_file:
        key = key_file.read()
else:
    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)
cipher_suite = Fernet(key)

# Configuración de MySQL (para registro y login)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'Users_Login'

# Inicializando MySQL y Bcrypt
mysql = MySQL(app)
bcrypt = Bcrypt(app)

# Cargar variables de entorno para OAuth
load_dotenv(dotenv_path='variables.env')

# Verificar que las variables de entorno estén cargando correctamente
app.logger.debug(f"GOOGLE_CLIENT_ID: {os.getenv('GOOGLE_CLIENT_ID')}")
app.logger.debug(f"GOOGLE_CLIENT_SECRET: {os.getenv('GOOGLE_CLIENT_SECRET')}")

app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Solo para desarrollo local
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    api_base_url='https://www.googleapis.com/oauth2/v2/',
    client_kwargs={'scope': 'openid email profile'},
    # Usa la URL de descubrimiento de Google
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)


# ------------- RUTAS PARA REGISTRO Y LOGIN (SQL) -----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        # Cifrar la contraseña
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Guardar usuario en la base de datos SQL
        cursor = mysql.connection.cursor()
        cursor.execute("""INSERT INTO users (username, email, firstname, lastname, password) 
                          VALUES (%s, %s, %s, %s, %s)""", (username, email, firstname, lastname, hashed_password))
        mysql.connection.commit()
        cursor.close()

        flash('Usuario registrado exitosamente.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'loggedin' in session:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        # Verificar si el usuario existe en la base de datos SQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s", [username])
        user = cursor.fetchone()
        cursor.close()

        if user:
            # Verificar la contraseña
            if bcrypt.check_password_hash(user['password'], password_candidate):
                session['loggedin'] = True
                session['username'] = username
                session['email'] = user['email']
                flash('Inicio de sesión exitoso.')
                app.logger.debug(f"Session after login: {session}")  # Output para verificar la sesión
                return redirect(url_for('home'))
            else:
                flash('Contraseña incorrecta.')
        else:
            flash('Usuario no encontrado.')

    return render_template('login.html')

# ------------- RUTAS DE LOGIN CON GOOGLE -----------------
@app.route('/google/login')
def login_google():
    nonce = secrets.token_urlsafe(16)  # Genera un nonce único
    session['nonce'] = nonce  # Guarda el nonce en la sesión
    redirect_uri = url_for('google_callback', _external=True)
    app.logger.debug(f"Redirigiendo a Google con URI: {redirect_uri}, Estado: {nonce}")
    return google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/google/callback')
def google_callback():
    app.logger.debug("Callback de Google recibido.")
    nonce = session.pop('nonce', None)
    try:
        token = google.authorize_access_token()
        app.logger.debug(f"Token recibido de Google: {token}")

        user_info = google.get('userinfo').json()
        app.logger.debug(f"Información del usuario: {user_info}")

        # Verificar el JWT
        if nonce and token.get('id_token'):
            id_token = token['id_token']
            decoded_token = google.decode_id_token(id_token)
            app.logger.debug(f"Token decodificado: {decoded_token}")

            # Verifica que el nonce coincide con el que guardaste
            if decoded_token.get('nonce') != nonce:
                raise ValueError('El nonce no coincide con el esperado.')

        # Verificar si el usuario existe en la base de datos
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE email = %s", [user_info['email']])
        user = cursor.fetchone()

        if not user:
            # Crear un nuevo usuario si no existe
            hashed_password = bcrypt.generate_password_hash(str(uuid.uuid4())).decode('utf-8')
            cursor.execute("""INSERT INTO users (username, email, firstname, lastname, password) 
                              VALUES (%s, %s, %s, %s, %s)""",
                           (user_info['email'], user_info['email'], user_info['given_name'],
                            user_info['family_name'], hashed_password))
            mysql.connection.commit()

        cursor.close()

        # Iniciar sesión y almacenar información en la sesión
        session['loggedin'] = True
        session['username'] = user_info['email']
        session['email'] = user_info['email']
        session['name'] = user_info['name']
        session['picture'] = user_info.get('picture', '')

        flash('Inicio de sesión con Google exitoso.')
        app.logger.debug(f"Sesión después del login: {session}")  # Verifica la sesión
        return redirect(url_for('home'))

    except Exception as e:
        flash(f"Error durante la autenticación con Google: {e}")
        app.logger.error(f"Error durante la autenticación con Google: {e}")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('username', None)
    session.pop('email', None)
    session.pop('name', None)
    session.pop('picture', None)
    flash('Has cerrado sesión.')
    return redirect(url_for('home'))

# ------------- RUTAS PARA LA LISTA DE TAREAS (MongoDB) -----------------
@app.route("/", methods=["GET", "POST"])
@app.route("/home", methods=["GET", "POST"])
def home():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    user_id = session.get('username')

    if request.method == "POST":
        todo_name = request.form.get("todo_name", "").strip()
        priority = request.form.get("priority", "3")
        if todo_name:
            encrypted_name = cipher_suite.encrypt(todo_name.encode()).decode()
            todos_collection.insert_one({
                'user_id': user_id,
                'id': str(uuid.uuid4()),
                'name': encrypted_name,
                'checked': False,
                'priority': priority
            })
    
    todos = todos_collection.find({'user_id': user_id})
    decrypted_todos = []
    for todo in todos:
        try:
            decrypted_name = cipher_suite.decrypt(todo['name'].encode()).decode()
            priority = todo['priority']
            decrypted_todos.append({
                'id': todo['id'],
                'name': decrypted_name,
                'checked': todo['checked'],
                'priority': priority
            })
        except cryptography.fernet.InvalidToken:
            app.logger.warning(f"No se pudo desencriptar la tarea: {todo['name']}")
    
    return render_template("home.html", todos=decrypted_todos)

# Configurar y correr la aplicación
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))  # Usa PORT desde la variable de entorno si está disponible