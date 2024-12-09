import pytest
from app import validate_todo_data, get_postgres_connection

def test_validate_todo_data_valid_input():
    assert validate_todo_data("  Task Name  ") == "Task Name"

def test_validate_todo_data_empty_input():
    assert validate_todo_data("   ") is None

def test_get_postgres_connection_invalid_credentials(monkeypatch):
    monkeypatch.setenv('POSTGRES_USER', 'invalid_user')
    conn = get_postgres_connection()
    assert conn is None