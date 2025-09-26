# blueprints/auth_bp.py
from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from models import Usuario, db
from datetime import datetime

auth_bp = Blueprint('auth_bp', __name__)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        usuario = Usuario.query.filter_by(username=username, ativo=True).first()
        
        if usuario and usuario.check_password(password):
            # Sessão unificada
            session['user_id'] = usuario.id
            session['username'] = usuario.username
            session['full_name'] = usuario.nome_completo
            session['last_activity'] = datetime.utcnow().isoformat()

            # Salva permissões do usuário
            session['permissions'] = [p.nome for p in usuario.role.permissions] if usuario.role else []

            usuario.ultimo_login = datetime.utcnow()
            db.session.commit()

            flash("Login realizado com sucesso!", "success")
            return redirect(url_for("index"))
        else:
            flash("Credenciais inválidas!", "danger")

    return render_template("login.html")
