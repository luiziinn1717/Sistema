from functools import wraps
from flask import session, redirect, url_for, abort, flash, request, current_app
from models.usuario import Usuario
from models.core import db
from flask_login import current_user

def login_required(login_endpoint=None, default_redirect_route=None):
    """
    Decorator para checar se o usuário está logado.
    Redireciona para o login correto do blueprint.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')

            if not user_id:
                flash('Você precisa estar logado para acessar esta página.', 'warning')

                # Se login_endpoint for função, pega o nome do endpoint
                if callable(login_endpoint):
                    endpoint_name = login_endpoint.__name__
                    blueprint = login_endpoint.__module__.split('.')[-1]
                    endpoint = f"{blueprint}.{endpoint_name}"
                elif isinstance(login_endpoint, str):
                    endpoint = login_endpoint
                elif request.blueprint == 'cadastro_bp':
                    endpoint = 'cadastro_bp.login'
                elif request.blueprint == 'juridico_bp':
                    endpoint = 'juridico_bp.login'
                else:
                    endpoint = 'login'

                if default_redirect_route:
                    return redirect(url_for(default_redirect_route))
                else:
                    return redirect(url_for(endpoint))

            user = Usuario.query.get(user_id)
            if not user or not user.ativo:
                session.clear()
                flash('Sua sessão expirou ou sua conta foi desativada.', 'warning')

              
                if callable(login_endpoint):
                    endpoint_name = login_endpoint.__name__
                    blueprint = login_endpoint.__module__.split('.')[-1]
                    endpoint = f"{blueprint}.{endpoint_name}"
                elif isinstance(login_endpoint, str):
                    endpoint = login_endpoint
                elif request.blueprint == 'cadastro_bp':
                    endpoint = 'cadastro_bp.login'
                elif request.blueprint == 'juridico_bp':
                    endpoint = 'juridico_bp.login'
                else:
                    endpoint = 'login'

                if default_redirect_route:
                    return redirect(url_for(default_redirect_route))
                else:
                    return redirect(url_for(endpoint))

            return f(*args, **kwargs)
        return decorated_function

    if callable(login_endpoint):
        return decorator(login_endpoint)
    return decorator


def has_permission(user_id, permission_name):
    user = Usuario.query.get(user_id)
    if not user or not user.role:
        return False
    return any(p.nome == permission_name for p in user.role.permissions)

def require_permission(permission_name):
    """
    Decorador para restringir acesso a rota baseado em permissão.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id or not has_permission(user_id, permission_name):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def permission_required(permission_name):
    """
    Decorador compatível com Flask-Login.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if not current_user.has_permission(permission_name):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def handle_db_error(func):
    """
    Decorador para tratar erros de banco de dados.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Erro de banco de dados: {e}")
            flash("Ocorreu um erro no banco de dados. Tente novamente.", "error")
            return redirect(request.referrer or url_for('index'))
    return wrapper