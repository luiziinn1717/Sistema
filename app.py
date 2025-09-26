from flask import Flask, redirect, url_for, session, flash, render_template
from flask_cors import CORS
import os
import logging
from datetime import datetime, timedelta
from models import db, Usuario
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_login import login_required

from config.settings import Config
from blueprints.juridico import juridico_bp
from blueprints.cadastro import cadastro_bp

app = Flask(__name__)
app.config.from_object(Config)

CORS(app)

csrf = CSRFProtect()
csrf.init_app(app)

limiter = Limiter(app=app, default_limits=["200 per day", "50 per hour"], key_func=get_remote_address)

Talisman(app, force_https=Config.FLASK_ENV == 'production')

@app.after_request
def security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if not app.debug:
    logging.basicConfig(level=logging.INFO)

if not app.config.get('SQLALCHEMY_DATABASE_URI'):
    app.logger.error("DATABASE_URL não configurada!")
    raise ValueError("DATABASE_URL é obrigatória para funcionamento da aplicação")

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db.init_app(app)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

@app.before_request
def check_session_timeout():
    if 'user_id' in session:
        if 'last_activity' not in session:
            session['last_activity'] = datetime.utcnow().replace(tzinfo=None)
        
        last_activity = session['last_activity']
        if hasattr(last_activity, 'tzinfo') and last_activity.tzinfo is not None:
            last_activity = last_activity.replace(tzinfo=None)
        
        if datetime.utcnow() - last_activity > timedelta(hours=2):
            session.clear()
            flash("Sua sessão expirou. Por favor, faça login novamente.", "info")
        
        session['last_activity'] = datetime.utcnow().replace(tzinfo=None)

# Registrando blueprints
app.register_blueprint(juridico_bp, url_prefix="/juridico")
app.register_blueprint(cadastro_bp, url_prefix="/cadastro")

@app.route("/")
def index():
    return render_template("index.html")

# --- Inicialização do banco de dados se não existir ---
if __name__ == "__main__":
    instance_path = os.path.join(app.root_path, 'instance')
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)

    db_path = os.path.join(instance_path, 'propostas.db')

    with app.app_context():
        db.create_all()  # Cria todas as tabelas se não existirem

    app.run(debug=Config.DEBUG, host='0.0.0.0')