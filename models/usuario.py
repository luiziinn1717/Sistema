# models/usuario.py
from . import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from .core import Role 

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    nome_completo = db.Column(db.String(255), nullable=False)
    cargo = db.Column(db.String(100), nullable=True)
    departamento = db.Column(db.String(100), nullable=True)
    telefone = db.Column(db.String(20), nullable=True)
    ativo = db.Column(db.Boolean, default=True)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    ultimo_login = db.Column(db.DateTime, nullable=True)

    # Relacionamento com Role
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    role = db.relationship("Role", backref="usuarios")

    # --- Métodos ---
    def set_password(self, password):
        """Cria hash seguro da senha."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifica se a senha informada é válida."""
        return check_password_hash(self.password_hash, password)

    def has_permission(self, permission_name):
        """Verifica se o usuário possui determinada permissão via Role."""
        if not self.role or not self.role.permissions:
            return False

        return any(p.nome == permission_name for p in self.role.permissions)

    def __repr__(self):
        return f'<Usuario {self.username}>'
