#  Enterprise Report Tool

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Flask](https://img.shields.io/badge/Flask-3.1-green)
![License](https://img.shields.io/badge/License-Private-red)
![Docker](https://img.shields.io/badge/Docker-Ready-blue)
![SQL Server](https://img.shields.io/badge/SQL%20Server-ODBC%2017-red)
![Pandas](https://img.shields.io/badge/Pandas-2.2-purple)

Sistema web de análisis y consulta de inventario en tiempo real, desarrollado con **Python + Flask**, conectado a **SQL Server** y orientado a operaciones logísticas. Permite a los clientes consultar su stock, movimientos, trazabilidad por número de serie y rotación de mercadería, con exportación a Excel.

---

##  Funcionalidades

- **Dashboard** — vista general con estadísticas en tiempo real (stock total, ingresos del día)
- **Ingresos y Egresos** — consulta detallada por mes, año o rango de fechas personalizado
- **Movimientos Seriados** — seguimiento de artículos con número de serie por período
- **Stock Detallado** — estado actual del inventario con antigüedad por tramos (0-30, 31-60, 61-90 días...)
- **Tracking por Serial** — trazabilidad completa de un artículo desde su ingreso hasta su egreso
- **Rotación de Inventario** — reporte de rotación con clasificación por antigüedad y colores, exportable a Excel formateado
- **Exportación a Excel** — todas las consultas pueden descargarse en `.xlsx` con un clic
- **Descarga de Inventarios Cíclicos** — acceso a archivos de inventario organizados por cliente y período

---

##  Seguridad implementada

- Autenticación con **contraseñas hasheadas** (`werkzeug.security`)
- **Rate limiting** en login (5 intentos/min) y rutas generales (200/día, 50/hora) con `flask-limiter`
- Todas las consultas SQL usan **parámetros** — sin riesgo de SQL Injection
- **Sanitización de inputs** en todos los formularios (prevención XSS)
- Protección contra **path traversal** en descarga de archivos
- Rutas sensibles (`.env`, `usuarios.json`, `config.py`) bloqueadas con 404
- **Logging de accesos** con IP, user agent y resultado (exitoso/fallido)
- Variables de entorno con `python-dotenv` — ninguna credencial en el código
- Sesiones con timeout configurable

---

##  Tecnologías

| Tecnología | Uso |
|---|---|
| Python 3.11 | Lenguaje principal |
| Flask 3.1 | Framework web |
| SQL Server | Base de datos |
| pyodbc | Conexión a SQL Server |
| pandas | Procesamiento de datos |
| openpyxl / xlsxwriter | Exportación a Excel |
| Werkzeug | Seguridad y hashing |
| flask-limiter | Rate limiting |
| Waitress | Servidor WSGI producción |
| Docker | Containerización |

---

##  Instalación local

### Requisitos previos
- Python 3.11+
- ODBC Driver 17 for SQL Server instalado
- Acceso a una instancia de SQL Server

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/JesusVallejos-coder/enterprise-report-tool.git
cd enterprise-report-tool

# 2. Crear entorno virtual
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/Mac

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Configurar variables de entorno
cp .env.example .env
# Editar .env con tus credenciales de SQL Server y SECRET_KEY

# 5. Crear el primer usuario
python crear_usuario.py

# 6. Correr la aplicación
python app.py
```

La app estará disponible en `http://localhost:5050`

---

##  Docker

```bash
# Construir imagen
docker build -t enterprise-report-tool .

# Correr contenedor
docker run -p 5050:5050 --env-file .env enterprise-report-tool
```

---

##  Estructura del proyecto

```
enterprise-report-tool/
├── app.py          # Aplicación principal Flask (rutas y lógica)
├── config.py            # Configuración desde variables de entorno
├── queries.py           # Todas las consultas SQL centralizadas
├── auth_decorator.py    # Decorador de autenticación para rutas protegidas
├── logging_config.py    # Configuración de logs de aplicación y accesos
├── crear_usuario.py     # Script para crear/gestionar usuarios
├── requirements.txt     # Dependencias Python
├── Dockerfile           # Imagen Docker
├── .env.example         # Plantilla de variables de entorno
├── templates/           # Plantillas HTML (Jinja2)
│   ├── base.html        # Layout principal
│   ├── login.html       # Pantalla de inicio de sesión
│   ├── dashboard.html   # Dashboard principal
│   ├── table.html       # Vista genérica de tablas
│   ├── filtro_fecha.html# Selector de fechas/períodos
│   ├── tracking.html    # Trazabilidad por serial
│   ├── rotacion.html    # Reporte de rotación
│   ├── ciclicos.html    # Listado de inventarios cíclicos
│   ├── archivos.html    # Archivos por período
│   └── 404.html         # Página de error
└── static/
    ├── css/style.css    # Estilos personalizados
    └── img/             # Imágenes
```

---

##  Variables de entorno

Crear un archivo `.env` basado en `.env.example`:

```env
# Base de datos SQL Server
DB_SERVER=tu_servidor
DB_NAME=tu_base_de_datos
DB_USER=tu_usuario
DB_PASS=tu_contraseña

# Seguridad
# Generar con: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=tu_clave_secreta_generada

# Configuración de sesión
SESSION_TIMEOUT=30
MAX_LOGIN_ATTEMPTS=5
```

---

##  Autor

**Jesús Vallejos**
- GitHub: [@JesusVallejos-coder](https://github.com/JesusVallejos-coder)

---

## 📄 Licencia

Este proyecto es de uso privado. No está autorizado su uso, distribución o modificación sin permiso expreso del autor.
