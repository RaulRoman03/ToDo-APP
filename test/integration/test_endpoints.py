import pytest
from app import app

@pytest.fixture
def client():
    app.testing = True
    with app.test_client() as client:
        yield client

def test_home_redirect_to_login(client):
    response = client.get("/")
    assert response.status_code == 302  # Redirección
    assert "/login" in response.location

def test_register_page(client):
    response = client.get("/register")
    assert response.status_code == 200
    assert b"Registro" in response.data  # Ajusta según el contenido de tu template

def test_login_page(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Inicio de Sesion" in response.data  # Ajusta según el contenido de tu template

def test_register_user(client, monkeypatch):
    # Mock PostgreSQL cursor y conexión
    def mock_get_postgres_cursor():
        class MockCursor:
            def execute(self, query, params):
                pass

            def close(self):
                pass

        class MockConn:
            def commit(self):
                pass

            def close(self):
                pass

        return MockCursor(), MockConn()

    monkeypatch.setattr("app.get_postgres_cursor", mock_get_postgres_cursor)

    data = {
        "firstname": "John",
        "lastname": "Doe",
        "email": "john.doe@example.com",
        "username": "johndoe",
        "password": "securepassword"
    }
    response = client.post("/register", data=data)
    assert response.status_code == 302  # Redirección
    assert "/login" in response.location

def test_login_user(client, monkeypatch):
    # Mock PostgreSQL cursor y usuario
    def mock_get_postgres_cursor():
        class MockCursor:
            def execute(self, query, params):
                self.user = ("johndoe", "john.doe@example.com", "John", "Doe", "$2b$12$...")
            
            def fetchone(self):
                return self.user

            def close(self):
                pass

        class MockConn:
            def close(self):
                pass

        return MockCursor(), MockConn()

    monkeypatch.setattr("app.get_postgres_cursor", mock_get_postgres_cursor)

    data = {"username": "johndoe", "password": "securepassword"}
    response = client.post("/login", data=data)
    assert response.status_code == 302  # Redirección
    assert "/home" in response.location