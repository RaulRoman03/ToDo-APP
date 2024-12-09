import pytest
from app import validate_todo_data, get_postgres_connection

def test_validate_todo_data_valid_input():
    # Caso válido: elimina espacios y retorna el nombre limpio
    assert validate_todo_data("  Task Name  ") == "Task Name"

def test_validate_todo_data_empty_input():
    # Caso de entrada vacía: retorna None
    assert validate_todo_data("   ") is None

def test_validate_todo_data_none_input():
    # Caso de entrada None: retorna None
    assert validate_todo_data(None) is None

def test_get_postgres_connection_invalid_credentials(monkeypatch):
    # Caso de credenciales inválidas para PostgreSQL: debe retornar None
    monkeypatch.setenv('POSTGRES_USER', 'invalid_user')
    monkeypatch.setenv('POSTGRES_PASSWORD', 'invalid_password')
    monkeypatch.setenv('POSTGRES_DB', 'invalid_db')
    conn = get_postgres_connection()
    assert conn is None