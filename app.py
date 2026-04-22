import datetime
import io
import json
import logging
import os
import re
import secrets
import time
import unicodedata
from io import BytesIO

import pandas as pd
import pyodbc
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

from auth_decorator import login_required
from config import Config
from logging_config import setup_logging
from queries import (
    EGRESOS_DETALLADOS,
    EGRESOS_POR_MES,
    EGRESOS_POR_RANGO,
    INGRESOS_DETALLADOS,
    INGRESOS_POR_MES,
    INGRESOS_POR_RANGO,
    MOVIMIENTOS_SERIADOS_POR_MES,
    MOVIMIENTOS_SERIADOS_POR_RANGO,
    ROTACION_EGRESOS,
    ROTACION_INGRESOS,
    STOCK_CANTIDAD,
    STOCK_DETALLADO,
    TRACKING_POR_SERIAL,
)

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=Config.SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE=Config.SESSION_COOKIE_SAMESITE,
    SESSION_COOKIE_SECURE=Config.SESSION_COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(minutes=Config.SESSION_TIMEOUT),
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

access_logger = setup_logging()
logger = logging.getLogger(__name__)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=Config.RATE_LIMIT_STORAGE_URI,
)


def normalizar_usuario(usuario):
    """Normaliza el nombre de usuario para una comparación segura."""
    if not usuario:
        return usuario
    usuario = usuario.upper().strip()
    usuario = unicodedata.normalize("NFKD", usuario)
    usuario = usuario.encode("ascii", "ignore").decode("ascii")
    usuario = re.sub(r"[\.\s\-]+", "_", usuario)
    return usuario


def ejecutar_consulta(query, params=None):
    """Ejecuta consultas SQL parametrizadas."""
    try:
        with pyodbc.connect(Config.CONN_STR, timeout=30) as conn:
            if params:
                if not isinstance(params, (list, tuple)):
                    params = [params]
                df = pd.read_sql(query, conn, params=params)
            else:
                df = pd.read_sql(query, conn)
        return df
    except pyodbc.Error as exc:
        logger.error(f"Error en base de datos: {exc}")
        raise Exception("Error al consultar la base de datos") from exc
    except Exception as exc:
        logger.error(f"Error inesperado: {exc}")
        raise


def exportar_a_excel(df, nombre_archivo):
    """Exporta un DataFrame a Excel de forma segura."""
    try:
        output = BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Datos")
        output.seek(0)

        nombre_archivo = re.sub(r"[^\w\-_\. ]", "", nombre_archivo)

        return send_file(
            output,
            as_attachment=True,
            download_name=nombre_archivo,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except Exception as exc:
        logger.error(f"Error exportando Excel: {exc}")
        abort(500)


def log_acceso(usuario, intento_exitoso=True):
    """Registra intentos de acceso y eventos de sesión."""
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "Desconocido")
    estado = "EXITOSO" if intento_exitoso else "FALLIDO"
    access_logger.info(f"{estado} - Usuario: {usuario} - IP: {ip} - UA: {user_agent}")


def sanitizar_entrada(valor):
    """Sanitiza cadenas recibidas desde formularios."""
    if valor is None:
        return ""
    if isinstance(valor, str):
        valor = re.sub(r'[<>"\']', "", valor)
        return valor.strip()
    return valor


def generar_csrf_token():
    """Genera o devuelve el token CSRF de la sesión."""
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validar_csrf():
    """Valida el token CSRF enviado por formulario o header."""
    token_sesion = session.get("_csrf_token")
    token_request = request.form.get("_csrf_token") or request.headers.get("X-CSRFToken")
    return bool(
        token_sesion and token_request and secrets.compare_digest(token_sesion, token_request)
    )


def validar_periodo(anio, mes):
    """Valida filtros de año y mes."""
    if not (anio and mes and anio.isdigit() and mes.isdigit()):
        return False
    return 2000 <= int(anio) <= 2100 and 1 <= int(mes) <= 12


def validar_fecha_iso(valor):
    """Valida una fecha ISO YYYY-MM-DD."""
    try:
        return datetime.date.fromisoformat(valor)
    except (TypeError, ValueError):
        return None


def validar_rango_fechas(desde, hasta):
    """Valida un rango de fechas ISO."""
    fecha_desde = validar_fecha_iso(desde)
    fecha_hasta = validar_fecha_iso(hasta)
    if not fecha_desde or not fecha_hasta or fecha_desde > fecha_hasta:
        return None, None
    return fecha_desde, fecha_hasta


def resolver_base_inventario():
    """Resuelve una carpeta base de inventario válida."""
    candidatos = [Config.BASE_INVENTARIO, os.path.join(Config.BASE_DIR, "Inventario")]
    for candidato in candidatos:
        ruta = os.path.abspath(candidato)
        if os.path.isdir(ruta):
            return ruta
    return os.path.abspath(Config.BASE_INVENTARIO)


def es_ruta_segura(base_real, ruta_real):
    """Comprueba que la ruta real permanezca dentro de la base esperada."""
    try:
        return os.path.commonpath([base_real, ruta_real]) == base_real
    except ValueError:
        return False


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": generar_csrf_token}


@app.before_request
def aplicar_controles_seguridad():
    if request.endpoint == "static":
        return None

    if request.method == "POST" and not validar_csrf():
        logger.warning(f"CSRF inválido para {request.path} desde IP {request.remote_addr}")
        abort(400)

    if "usuario" not in session:
        return None

    ahora = datetime.datetime.utcnow()
    ultimo_acceso = session.get("last_activity")
    if ultimo_acceso:
        try:
            ultimo = datetime.datetime.fromisoformat(ultimo_acceso)
            if ahora - ultimo > datetime.timedelta(minutes=Config.SESSION_TIMEOUT):
                usuario = session.get("usuario", "Desconocido")
                log_acceso(f"{usuario} - SESION_EXPIRADA", intento_exitoso=False)
                session.clear()
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Sesión expirada"}), 401
                flash("La sesión expiró por inactividad. Inicie sesión nuevamente.", "warning")
                return redirect(url_for("login"))
        except ValueError:
            session.pop("last_activity", None)

    session.permanent = True
    session["last_activity"] = ahora.isoformat()
    return None


@app.after_request
def agregar_headers_seguridad(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://cdn.datatables.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://code.jquery.com https://cdn.datatables.net; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "connect-src 'self' https://cdn.datatables.net; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.route("/", methods=["GET", "POST"])
@limiter.limit(lambda: f"{Config.MAX_LOGIN_ATTEMPTS} per minute")
def login():
    if request.method == "POST":
        usuario = sanitizar_entrada(request.form.get("usuario", ""))
        contrasena = request.form.get("contrasena", "")

        if not usuario or not contrasena:
            return render_template("login.html", error="Complete todos los campos")

        try:
            with open("usuarios.json", "r", encoding="utf-8") as file:
                usuarios = json.load(file)

            usuario_normalizado = normalizar_usuario(usuario)
            usuario_encontrado = None

            for usuario_key in usuarios.keys():
                if normalizar_usuario(usuario_key) == usuario_normalizado:
                    usuario_encontrado = usuario_key
                    break

            if usuario_encontrado and check_password_hash(usuarios[usuario_encontrado], contrasena):
                session.clear()
                session["usuario"] = usuario_encontrado
                session["cliente"] = usuario_encontrado
                session["login_time"] = datetime.datetime.utcnow().isoformat()
                session["last_activity"] = datetime.datetime.utcnow().isoformat()
                session.permanent = True
                generar_csrf_token()
                log_acceso(usuario_encontrado, intento_exitoso=True)

                flash("Bienvenido al sistema", "success")
                return redirect(url_for("dashboard"))

            time.sleep(1)
            log_acceso(usuario, intento_exitoso=False)
            return render_template("login.html", error="Credenciales inválidas")

        except FileNotFoundError:
            logger.error("Archivo usuarios.json no encontrado")
            return render_template("login.html", error="Error interno del servidor")
        except Exception as exc:
            logger.error(f"Error en login: {exc}")
            return render_template("login.html", error="Error interno del servidor")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/consulta/<tipo>")
@login_required
def consulta(tipo):
    usuario = session.get("usuario")

    consultas = {
        "ingresos": {"query": INGRESOS_DETALLADOS, "titulo": "Ingresos Detallados"},
        "egresos": {"query": EGRESOS_DETALLADOS, "titulo": "Egresos Detallados"},
        "stock_detallado": {"query": STOCK_DETALLADO, "titulo": "Stock Detallado"},
        "stock_cantidad": {"query": STOCK_CANTIDAD, "titulo": "Stock en Cantidad"},
    }

    if tipo not in consultas:
        flash("Tipo de consulta no válido", "error")
        return redirect(url_for("dashboard"))

    try:
        consulta_info = consultas[tipo]
        df = ejecutar_consulta(consulta_info["query"], [usuario])

        if request.args.get("exportar") == "excel":
            return exportar_a_excel(df, f"{tipo}.xlsx")

        return render_template(
            "table.html",
            titulo=consulta_info["titulo"],
            columnas=df.columns.tolist(),
            datos=df.values.tolist(),
        )
    except Exception as exc:
        logger.error(f"Error en consulta {tipo}: {exc}")
        flash("Error al obtener los datos", "error")
        return redirect(url_for("dashboard"))


@app.route("/seleccionar_anio/<tipo>", methods=["GET", "POST"])
@login_required
def seleccionar_anio(tipo):
    if tipo not in ["ingresos", "egresos"]:
        flash("Tipo no válido", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        anio = sanitizar_entrada(request.form.get("anio", ""))
        mes = sanitizar_entrada(request.form.get("mes", ""))
        desde = sanitizar_entrada(request.form.get("desde", ""))
        hasta = sanitizar_entrada(request.form.get("hasta", ""))

        if anio and mes and validar_periodo(anio, mes):
            return redirect(url_for("seleccionar_anio", tipo=tipo, anio=anio, mes=mes))
        if desde and hasta and all(validar_rango_fechas(desde, hasta)):
            return redirect(url_for("seleccionar_anio", tipo=tipo, desde=desde, hasta=hasta))

        flash("Elegí una opción válida: año/mes o rango de fechas.", "warning")
        return redirect(request.url)

    anio = request.args.get("anio")
    mes = request.args.get("mes")
    desde = request.args.get("desde")
    hasta = request.args.get("hasta")
    exportar = request.args.get("exportar")

    if not ((anio and mes) or (desde and hasta)):
        return render_template("filtro_fecha.html", tipo=tipo)

    if anio and mes and not validar_periodo(anio, mes):
        flash("El período seleccionado no es válido.", "warning")
        return redirect(url_for("seleccionar_anio", tipo=tipo))
    if desde and hasta and not all(validar_rango_fechas(desde, hasta)):
        flash("El rango de fechas no es válido.", "warning")
        return redirect(url_for("seleccionar_anio", tipo=tipo))

    usuario = session.get("usuario")

    try:
        if tipo == "ingresos":
            if anio and mes:
                query = INGRESOS_POR_MES
                params = [usuario, anio, mes]
                titulo = f"Ingresos Detallados - {mes}/{anio}"
            else:
                query = INGRESOS_POR_RANGO
                params = [usuario, desde, hasta]
                titulo = f"Ingresos Detallados - {desde} a {hasta}"
        else:
            if anio and mes:
                query = EGRESOS_POR_MES
                params = [usuario, anio, mes]
                titulo = f"Egresos Detallados - {mes}/{anio}"
            else:
                query = EGRESOS_POR_RANGO
                params = [usuario, desde, hasta]
                titulo = f"Egresos Detallados - {desde} a {hasta}"

        df = ejecutar_consulta(query, params)

        if exportar == "excel":
            if anio and mes:
                nombre = f"{tipo}_{mes}_{anio}.xlsx"
            else:
                nombre = f"{tipo}_{desde}_a_{hasta}.xlsx"
            return exportar_a_excel(df, nombre)

        return render_template(
            "table.html",
            titulo=titulo,
            columnas=df.columns.tolist(),
            datos=df.values.tolist(),
        )
    except Exception as exc:
        logger.error(f"Error en seleccionar_anio {tipo}: {exc}")
        flash("Error al obtener los datos", "error")
        return redirect(url_for("dashboard"))


@app.route("/ingresos_seriados", methods=["GET", "POST"])
@login_required
def ingresos_seriados():
    return procesar_movimientos_seriados("Ingresos")


@app.route("/egresos_seriados", methods=["GET", "POST"])
@login_required
def egresos_seriados():
    return procesar_movimientos_seriados("Egresos")


def procesar_movimientos_seriados(tipo_operacion):
    usuario = session.get("usuario")

    if request.method == "POST":
        anio = sanitizar_entrada(request.form.get("anio", ""))
        mes = sanitizar_entrada(request.form.get("mes", ""))
        desde = sanitizar_entrada(request.form.get("desde", ""))
        hasta = sanitizar_entrada(request.form.get("hasta", ""))

        if anio and mes and validar_periodo(anio, mes):
            return redirect(url_for(f"{tipo_operacion.lower()}_seriados", anio=anio, mes=mes))
        if desde and hasta and all(validar_rango_fechas(desde, hasta)):
            return redirect(
                url_for(f"{tipo_operacion.lower()}_seriados", desde=desde, hasta=hasta)
            )

        return render_template(
            "filtro_fecha.html",
            tipo=f"{tipo_operacion.lower()}_seriados",
            error="Elegí una opción válida.",
        )

    anio = request.args.get("anio")
    mes = request.args.get("mes")
    desde = request.args.get("desde")
    hasta = request.args.get("hasta")
    exportar = request.args.get("exportar")

    if not ((anio and mes) or (desde and hasta)):
        return render_template("filtro_fecha.html", tipo=f"{tipo_operacion.lower()}_seriados")

    if anio and mes and not validar_periodo(anio, mes):
        flash("El período seleccionado no es válido.", "warning")
        return redirect(url_for(f"{tipo_operacion.lower()}_seriados"))
    if desde and hasta and not all(validar_rango_fechas(desde, hasta)):
        flash("El rango de fechas no es válido.", "warning")
        return redirect(url_for(f"{tipo_operacion.lower()}_seriados"))

    try:
        if anio and mes:
            query = MOVIMIENTOS_SERIADOS_POR_MES
            params = [usuario, tipo_operacion, anio, mes]
            titulo = f"{tipo_operacion} Seriados - {mes}/{anio}"
        else:
            query = MOVIMIENTOS_SERIADOS_POR_RANGO
            params = [usuario, tipo_operacion, desde, hasta]
            titulo = f"{tipo_operacion} Seriados - {desde} a {hasta}"

        df = ejecutar_consulta(query, params)

        if exportar == "excel":
            if anio and mes:
                nombre = f"{tipo_operacion.lower()}_{mes}_{anio}.xlsx"
            else:
                nombre = f"{tipo_operacion.lower()}_{desde}_a_{hasta}.xlsx"
            return exportar_a_excel(df, nombre)

        return render_template(
            "table.html",
            titulo=titulo,
            columnas=df.columns.tolist(),
            datos=df.values.tolist(),
        )
    except Exception as exc:
        logger.error(f"Error en {tipo_operacion} seriados: {exc}")
        flash("Error al obtener los datos", "error")
        return redirect(url_for("dashboard"))


@app.route("/consulta/rotacion", methods=["GET", "POST"])
@login_required
def consulta_rotacion():
    if request.method == "POST":
        try:
            fecha_inicio = sanitizar_entrada(request.form.get("fecha_inicio", ""))
            fecha_fin = sanitizar_entrada(request.form.get("fecha_fin", ""))

            if not fecha_inicio or not fecha_fin:
                flash("Debe completar ambas fechas", "warning")
                return redirect(url_for("consulta_rotacion"))
            if not all(validar_rango_fechas(fecha_inicio, fecha_fin)):
                flash("El rango de fechas no es válido", "warning")
                return redirect(url_for("consulta_rotacion"))

            output = exportar_rotacion_excel(fecha_inicio, fecha_fin)
            return send_file(
                output,
                as_attachment=True,
                download_name="rotacion_inventario.xlsx",
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        except Exception as exc:
            logger.error(f"Error en rotación: {exc}")
            flash("Error al generar el reporte", "error")
            return redirect(url_for("consulta_rotacion"))

    return render_template("rotacion.html")


def exportar_rotacion_excel(fecha_inicio, fecha_fin):
    usuario = session.get("usuario")

    df = ejecutar_consulta(ROTACION_EGRESOS, [usuario, fecha_inicio, fecha_fin])
    df_ingresos = ejecutar_consulta(ROTACION_INGRESOS, [usuario])

    df_ingresos.rename(columns={"FECHA_COMPROBANTE": "FECHA_INGRESO"}, inplace=True)
    df_ingresos = df_ingresos.drop_duplicates(subset=["NRO_SERIE"], keep="first")

    df = df.merge(df_ingresos[["NRO_SERIE", "FECHA_INGRESO"]], on="NRO_SERIE", how="left")
    df["ANTIGÜEDAD"] = (
        pd.to_datetime(df["F_OPERACION"]) - pd.to_datetime(df["FECHA_INGRESO"], errors="coerce")
    ).dt.days

    def clasificar_periodicidad(dias):
        if pd.isna(dias):
            return "Sin Fecha de Ingreso", "gray"
        if dias <= 30:
            return "0-30 días", "green"
        if dias <= 60:
            return "31-60 días", "yellow"
        if dias <= 90:
            return "61-90 días", "orange"
        if dias <= 120:
            return "91-120 días", "lightcoral"
        if dias <= 180:
            return "121-180 días", "red"
        if dias <= 365:
            return "181-365 días", "blue"
        return "Más de 365 días", "gray"

    df[["PERIODICIDAD", "COLOR"]] = df["ANTIGÜEDAD"].apply(
        lambda dias: pd.Series(clasificar_periodicidad(dias))
    )

    df.rename(columns={"F_OPERACION": "FECHA DE EGRESO"}, inplace=True)
    colores = df["COLOR"].copy()
    df.drop(columns=["COLOR"], inplace=True)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Egresos")
        workbook = writer.book
        worksheet = writer.sheets["Egresos"]

        color_map = {
            "green": "#C6EFCE",
            "yellow": "#FFEB9C",
            "orange": "#F4B084",
            "lightcoral": "#F08080",
            "red": "#FFC7CE",
            "blue": "#BDD7EE",
            "gray": "#D9D9D9",
        }

        col_index = df.columns.get_loc("PERIODICIDAD")

        for row_idx, color in enumerate(colores, start=1):
            fmt = workbook.add_format(
                {"bg_color": color_map.get(color, "#FFFFFF"), "border": 1}
            )
            worksheet.write(row_idx, col_index, df.loc[row_idx - 1, "PERIODICIDAD"], fmt)

    output.seek(0)
    return output


@app.route("/tracking", methods=["GET", "POST"])
@login_required
def tracking():
    movimientos = None

    if request.method == "POST":
        nro_serie = sanitizar_entrada(request.form.get("nro_serie", ""))

        if not nro_serie:
            flash("Debe ingresar un número de serie", "warning")
            return render_template("tracking.html", movimientos=None)
        if len(nro_serie) > 100:
            flash("El número de serie ingresado es demasiado largo.", "warning")
            return render_template("tracking.html", movimientos=None)

        usuario = session.get("usuario")
        movimientos = ejecutar_consulta(TRACKING_POR_SERIAL, [usuario, nro_serie])

        if movimientos.empty:
            flash(f"No se encontraron movimientos para el serial: {nro_serie}", "info")

    return render_template("tracking.html", movimientos=movimientos)


@app.route("/api/stats")
@login_required
def get_stats():
    """API para estadísticas rápidas del dashboard."""
    usuario = session.get("usuario")
    try:
        stock_query = """
            SELECT COUNT(*) as total
            FROM [DB_EMPRESA].[dbo].[VW_STOCK]
            WHERE [COD. CLIENTE] = ?
        """
        stock_total = ejecutar_consulta(stock_query, [usuario]).iloc[0]["total"]

        hoy = datetime.datetime.now().strftime("%Y-%m-%d")
        ingresos_query = """
            SELECT COUNT(*) as total
            FROM [DB_EMPRESA].[dbo].[VW_INGRESOS_DETALLADO]
            WHERE CLIENTE_ID = ? AND CAST(FECHA_INGRESO AS DATE) = ?
        """
        ingresos_hoy = ejecutar_consulta(ingresos_query, [usuario, hoy]).iloc[0]["total"]

        return jsonify(
            {
                "stock_total": int(stock_total),
                "ingresos_hoy": int(ingresos_hoy),
                "ultima_actualizacion": datetime.datetime.now().strftime("%H:%M:%S"),
            }
        )
    except Exception as exc:
        logger.error(f"Error en API stats: {exc}")
        return jsonify({"error": "Error al obtener estadísticas"}), 500


BASE_INVENTARIO = resolver_base_inventario()


@app.route("/descargar-inventario")
@login_required
def listar_ciclicos():
    cliente = session.get("cliente")
    if not cliente:
        return redirect(url_for("login"))

    ruta_cliente = os.path.join(BASE_INVENTARIO, cliente)
    if not os.path.exists(ruta_cliente):
        flash(f"No se encontró la carpeta para el cliente: {cliente}", "warning")
        return render_template("ciclicos.html", carpetas=[], cliente=cliente)

    try:
        subcarpetas = sorted(
            [
                nombre
                for nombre in os.listdir(ruta_cliente)
                if os.path.isdir(os.path.join(ruta_cliente, nombre))
            ]
        )
    except Exception as exc:
        logger.error(f"Error listando carpetas: {exc}")
        flash("Error al acceder a los archivos", "error")
        subcarpetas = []

    return render_template("ciclicos.html", carpetas=subcarpetas, cliente=cliente)


@app.route("/descargar-inventario/<ciclico>")
@login_required
def listar_archivos(ciclico):
    cliente = session.get("cliente")
    if not cliente:
        return redirect(url_for("login"))

    if ".." in ciclico or "/" in ciclico or "\\" in ciclico:
        abort(403)

    ruta = os.path.join(BASE_INVENTARIO, cliente, ciclico)
    ruta_real = os.path.realpath(ruta)
    base_real = os.path.realpath(os.path.join(BASE_INVENTARIO, cliente))

    if not es_ruta_segura(base_real, ruta_real):
        abort(403)

    if not os.path.exists(ruta):
        flash(f"No se encontró la carpeta {ciclico}", "warning")
        return redirect(url_for("listar_ciclicos"))

    try:
        archivos = sorted(
            [f for f in os.listdir(ruta) if os.path.isfile(os.path.join(ruta, f))]
        )
    except Exception as exc:
        logger.error(f"Error listando archivos: {exc}")
        flash("Error al acceder a los archivos", "error")
        archivos = []

    return render_template("archivos.html", archivos=archivos, ciclico=ciclico, cliente=cliente)


@app.route("/descargar-inventario/<ciclico>/<archivo>")
@login_required
def descargar_archivo(ciclico, archivo):
    cliente = session.get("cliente")
    if not cliente:
        return redirect(url_for("login"))

    if ".." in ciclico or "/" in ciclico or "\\" in ciclico:
        abort(403)
    if ".." in archivo or "/" in archivo or "\\" in archivo:
        abort(403)

    ruta = os.path.join(BASE_INVENTARIO, cliente, ciclico)
    archivo_path = os.path.join(ruta, archivo)

    ruta_real = os.path.realpath(archivo_path)
    base_real = os.path.realpath(os.path.join(BASE_INVENTARIO, cliente))

    if not es_ruta_segura(base_real, ruta_real):
        abort(403)

    if not os.path.isfile(archivo_path):
        abort(404)

    return send_from_directory(ruta, archivo, as_attachment=True)


@app.route("/usuarios.json")
@app.route("/.env")
@app.route("/queries.py")
@app.route("/config.py")
def deny_sensitive_files():
    """Niega el acceso a archivos sensibles."""
    abort(404)


@app.route("/logout", methods=["POST"])
def logout():
    usuario = session.get("usuario", "Desconocido")
    log_acceso(f"{usuario} - LOGOUT", intento_exitoso=True)
    session.clear()
    flash("Sesión cerrada correctamente", "info")
    return redirect(url_for("login"))


@app.errorhandler(400)
def bad_request_error(error):
    logger.warning(f"400 error: {request.path} desde IP {request.remote_addr}")
    return "Solicitud inválida", 400


@app.errorhandler(403)
def forbidden_error(error):
    logger.warning(f"403 error: {request.path} desde IP {request.remote_addr}")
    return "Acceso prohibido", 403


@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f"404 error: {request.path}")
    return "Página no encontrada", 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}")
    return "Error interno del servidor", 500


if __name__ == "__main__":
    from waitress import serve

    port = int(os.getenv("PORT", 5050))
    logger.info(f"Iniciando aplicación en modo producción con Waitress en puerto {port}")
    serve(app, host="0.0.0.0", port=port)
