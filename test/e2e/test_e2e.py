from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time

BASE_URL = "https://todo-app-yxyk.onrender.com"  # Cambia esto por la URL de tu aplicación en producción

def setup_driver():
    """Inicializa el navegador."""
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")  # Ejecuta el navegador en modo headless
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    return webdriver.Chrome(options=options)

def test_user_registration():
    driver = setup_driver()
    driver.get(f"{BASE_URL}/register")

    # Completar el formulario de registro
    driver.find_element(By.NAME, "firstname").send_keys("Test")
    driver.find_element(By.NAME, "lastname").send_keys("User")
    driver.find_element(By.NAME, "email").send_keys("testuser@example.com")
    driver.find_element(By.NAME, "username").send_keys("testuser")
    driver.find_element(By.NAME, "password").send_keys("password123")
    driver.find_element(By.XPATH, "//button[contains(text(), 'Register')]").click()

    time.sleep(3)
    assert "login" in driver.current_url, "Redirección fallida después del registro"
    driver.quit()

def test_login():
    driver = setup_driver()
    driver.get(f"{BASE_URL}/login")

    # Completar el formulario de inicio de sesión
    driver.find_element(By.NAME, "username").send_keys("testuser")
    driver.find_element(By.NAME, "password").send_keys("password123")
    driver.find_element(By.XPATH, "//button[contains(text(), 'Login')]").click()

    time.sleep(3)
    assert "home" in driver.current_url, "Inicio de sesión fallido"
    driver.quit()

def test_task_creation():
    driver = setup_driver()
    driver.get(f"{BASE_URL}/login")

    # Iniciar sesión
    driver.find_element(By.NAME, "username").send_keys("testuser")
    driver.find_element(By.NAME, "password").send_keys("password123")
    driver.find_element(By.XPATH, "//button[contains(text(), 'Login')]").click()

    # Crear una nueva tarea
    driver.find_element(By.NAME, "todo_name").send_keys("Nueva tarea E2E")
    driver.find_element(By.XPATH, "//button[contains(text(), 'Add Task')]").click()

    time.sleep(3)
    tasks = [task.text for task in driver.find_elements(By.CLASS_NAME, "task-name")]
    assert "Nueva tarea E2E" in tasks, "La tarea no fue creada exitosamente"
    driver.quit()

def test_logout():
    driver = setup_driver()
    driver.get(f"{BASE_URL}/login")

    # Iniciar sesión
    driver.find_element(By.NAME, "username").send_keys("testuser")
    driver.find_element(By.NAME, "password").send_keys("password123")
    driver.find_element(By.XPATH, "//button[contains(text(), 'Login')]").click()

    # Cerrar sesión
    driver.find_element(By.LINK_TEXT, "Logout").click()

    time.sleep(3)
    assert "login" in driver.current_url, "Cierre de sesión fallido"
    driver.quit()