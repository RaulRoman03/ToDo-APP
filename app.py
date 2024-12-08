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

app = Flask(__name__)

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

# Configurar OAuth
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Solo para desarrollo local
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'}
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
                return redirect(url_for('home'))
            else:
                flash('Contraseña incorrecta.')
        else:
            flash('Usuario no encontrado.')

    return render_template('login.html')

# OAuth 2.0 Login
@app.route('/google/login')
def google_login():
    state = str(uuid.uuid4())  # Generar un nuevo valor de estado
    session['oauth_state'] = state  # Guardarlo en la sesión
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri, state=state)

@app.route('/google/callback')
def google_callback():
    try:
        # Verificar el estado antes de continuar
        if request.args.get('state') != session.get('oauth_state'):
            raise Exception("State mismatch error!")

        # Continuar con la autenticación de Google
        token = google.authorize_access_token()
        user_info = google.get('userinfo').json()

        # Verificar si el usuario ya existe en la base de datos
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
        return redirect(url_for('home'))

    except Exception as e:
        flash(f"Error durante la autenticación con Google: {e}")
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
            print(f"InvalidToken error for todo ID: {todo['id']}")
    return render_template("index.html", items=decrypted_todos)

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
    return redirect(url_for("home"))

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

    return redirect(url_for("home"))

# ------------- EJECUCIÓN DE LA APLICACIÓN -------------
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))  # Usa PORT desde la variable de entorno si está disponible