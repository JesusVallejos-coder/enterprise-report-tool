# auth_decorator.py
from functools import wraps
from flask import session, redirect, url_for, flash

def login_required(f):
    """
    Decorador para proteger rutas que requieren autenticación
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario' not in session:
            flash('Debe iniciar sesión para acceder', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function