from unittest.mock import patch, MagicMock
import pytest
from app import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_login_google_redirect(client):
    # Creamos un mock de la función `authorize_redirect` de la integración con OAuth
    with patch('app.google.authorize_redirect') as mock_oauth_redirect:
        mock_oauth_redirect.return_value = None  # Evitamos cualquier llamada real
        
        response = client.get('/login/google')  # Hacemos la llamada al endpoint
        mock_oauth_redirect.assert_called_once()  # Verificamos que se llamó a `authorize_redirect`
        
        # Aseguramos que la respuesta fue la esperada (en este caso, un redireccionamiento)
        assert response.status_code == 302  # 302 es el código de redirección HTTP

def test_login_callback_success(client):
    # Simulamos la respuesta del OAuth con un token de acceso válido
    with patch('app.google.authorize_access_token') as mock_oauth_token, \
         patch('app.google.get') as mock_oauth_user_info:
        
        # Simulamos un token de acceso válido
        mock_oauth_token.return_value = {"access_token": "fake_token"}
        
        # Simulamos los datos de usuario que devolvería Google
        mock_oauth_user_info.return_value.status_code = 200
        mock_oauth_user_info.return_value.json.return_value = {
            'email': 'testuser@example.com',
            'given_name': 'Test',
            'family_name': 'User'
        }
        
        # Llamada al callback de Google
        response = client.get('/google/callback?state=fake_state')  # Suponiendo que el estado coincide
        mock_oauth_token.assert_called_once()
        mock_oauth_user_info.assert_called_once()

        # Verificamos que el usuario se haya autenticado y redirigido correctamente
        assert response.status_code == 302  # Redirección después de iniciar sesión
        assert 'google_token' in client.session  # Verificamos que el token de Google esté en la sesión
        assert client.session['username'] == 'testuser@example.com'  # Verificamos que el email esté en la sesión

def test_login_callback_error(client):
    # Simulamos un error en la respuesta de Google (por ejemplo, si no se encuentra el estado)
    with patch('app.google.authorize_access_token') as mock_oauth_token:
        mock_oauth_token.side_effect = Exception("OAuth error")
        
        # Llamada al callback de Google que simula un error
        response = client.get('/google/callback?state=fake_state')
        
        mock_oauth_token.assert_called_once()
        
        # Verificamos que se maneja correctamente el error y se redirige al login
        assert response.status_code == 302
        assert 'Error durante la autenticación con Google' in response.data.decode()