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

# Configurar logger
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Cargar variables de entorno
load_dotenv(dotenv_path='variables.env')

# Inicializar la app Flask
app = Flask(__name__, template_folder='templates')
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
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = os.getenv('GOOGLE_DISCOVERY_URL')
GOOGLE_SCOPES = os.getenv('GOOGLE_SCOPES', 'openid profile email')
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url=GOOGLE_DISCOVERY_URL,
    client_kwargs={'scope': GOOGLE_SCOPES}
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
                conn.commit()
                cursor.close()
                conn.close()
                flash('Usuario registrado exitosamente.')
                return redirect(url_for('login'))
        except Exception as e:
            app.logger.error("Error al registrar usuario: %s", str(e))
            flash('Error al registrar usuario. Por favor, inténtelo nuevamente.')

    return render_template('register')

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
                    return redirect(url_for('index'))
                else:
                    flash('Credenciales incorrectas.')

        except Exception as e:
            app.logger.error("Error al iniciar sesión: %s", str(e))
            flash('Error al iniciar sesión. Por favor, inténtelo nuevamente.')

    return render_template('index')

@app.route('/login/google')
def login_google():
    state = str(uuid.uuid4())
    session['oauth_state'] = state
    redirect_uri = url_for('login_callback', _external=True)
    return google.authorize_redirect(redirect_uri, state=state)

@app.route('/google/callback')
def login_callback():
    try:
        if request.args.get('state') != session.get('oauth_state'):
            raise Exception("State mismatch error!")

        token = google.authorize_access_token()

        session['google_token'] = token

        user_info_response = google.get('https://www.googleapis.com/oauth2/v1/userinfo')
        if user_info_response.status_code != 200:
            raise Exception("Error al obtener información del usuario desde Google.")
        user_info = user_info_response.json()

        connection = get_postgres_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", [user_info['email']])
        user = cursor.fetchone()

        if not user:
            hashed_password = bcrypt.generate_password_hash(str(uuid.uuid4())).decode('utf-8')
            cursor.execute(""" 
                INSERT INTO users (username, email, firstname, lastname, password) 
                VALUES (%s, %s, %s, %s, %s)
            """, (user_info['email'], user_info['email'], user_info['given_name'], user_info['family_name'], hashed_password))
            connection.commit()

        cursor.close()

        session['loggedin'] = True
        session['username'] = user_info['email']
        session['email'] = user_info['email']
        session['name'] = user_info['name']
        session['picture'] = user_info.get('picture', '')

        flash('Inicio de sesión con Google exitoso.')
        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f"Error durante la autenticación con Google: {e}")
        flash(f"Error durante la autenticación con Google: {e}")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión.')
    return redirect(url_for('login'))

@app.route("/", methods=["GET", "POST"])
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
            try:
                encrypted_name = cipher_suite.encrypt(todo_name.encode()).decode()
                todos_collection.insert_one({
                    'user_id': user_id,
                    'id': str(uuid.uuid4()),
                    'name': encrypted_name,
                    'checked': False,
                    'priority': priority
                })
                flash("Tarea añadida exitosamente.")
            except Exception as e:
                app.logger.error("Error al guardar tarea en MongoDB: %s", str(e))
                flash("Error al guardar la tarea.")
    
    try:
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
            except Exception as e:
                app.logger.error("Error al descifrar tarea: %s", str(e))
        
        return render_template("index", todos=decrypted_todos)
    except Exception as e:
        app.logger.error("Error al cargar tareas desde MongoDB: %s", str(e))
        flash("Error al cargar las tareas.")
        return render_template("login", todos=[])

@app.route("/checked/<todo_id>", methods=["POST"])
def checked_todo(todo_id):
    todo = todos_collection.find_one({'id': todo_id})
    if todo:
        new_checked_state = not todo['checked']
        todos_collection.update_one(
            {'id': todo_id},
            {'$set': {'checked': new_checked_state}}
        )
    return redirect(url_for("home"))

@app.route("/delete/<todo_id>", methods=["POST"])
def delete_todo(todo_id):
    todos_collection.delete_one({'id': todo_id})
    return redirect(url_for("index"))

@app.route("/edit_todo/<todo_id>", methods=["POST"])
def edit_todo(todo_id):
    new_content = request.form.get('new_text', "").strip()
    new_priority = request.form.get('priority', "3")

    if new_content:
        encrypted_name = cipher_suite.encrypt(new_content.encode()).decode()

        result = todos_collection.update_one(
            {'id': todo_id},
            {'$set': {'name': encrypted_name, 'priority': new_priority}}
        )

        if result.modified_count == 0:
            print("No document was updated. Check the todo_id.")
    else:
        print("No new content provided.")
    
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)