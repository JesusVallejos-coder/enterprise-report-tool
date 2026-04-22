# config.py
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # Base de datos
    DB_SERVER = os.getenv('DB_SERVER')
    DB_NAME = os.getenv('DB_NAME')
    DB_USER = os.getenv('DB_USER')
    DB_PASS = os.getenv('DB_PASS')

    # Seguridad
    SECRET_KEY = os.getenv('SECRET_KEY', 'clave_temporal_cambiar')
    SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 30))
    MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

    # Rutas
    BASE_DIR = os.path.abspath(os.getcwd())
    BASE_INVENTARIO = os.path.abspath(
        os.getenv('BASE_INVENTARIO', os.path.join(BASE_DIR, 'INVENTARIO'))
    )

    # Rate limiting
    RATE_LIMIT_STORAGE_URI = os.getenv('RATE_LIMIT_STORAGE_URI', 'memory://')

    # Conexión SQL Server
    CONN_STR = (
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={DB_SERVER};"
        f"DATABASE={DB_NAME};"
        f"UID={DB_USER};"
        f"PWD={DB_PASS};"
        "Encrypt=yes;"
        "TrustServerCertificate=yes;"
        "Connection Timeout=60;"
    )
