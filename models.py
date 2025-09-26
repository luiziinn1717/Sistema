from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class Usuario(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    nome_completo = db.Column(db.String(255), nullable=False)
    cargo = db.Column(db.String(100), nullable=True)
    departamento = db.Column(db.String(100), nullable=True)
    telefone = db.Column(db.String(20), nullable=True)
    ativo = db.Column(db.Boolean, default=True)
    data_criacao = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    ultimo_login = db.Column(db.DateTime, nullable=True)

    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    role = db.relationship('Role', back_populates='usuarios')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<Usuario {self.username}>'
    
    def has_permission(self, permission_name):
        if self.role and self.role.permissions:
            return any(p.nome == permission_name for p in self.role.permissions)
        return False

    def is_admin(self):
        return self.role and self.role.nome == 'Admin'


class Processos(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    numero_processo = db.Column(db.String(100), nullable=True)
    operadora_nome = db.Column(db.String(100), nullable=True)
    vara_local = db.Column(db.String(255), nullable=True)
    autor = db.Column(db.String(255), nullable=True)
    reu = db.Column(db.String(255), nullable=True)
    tipo_de_demandas = db.Column(db.String(255), nullable=True)
    grupo_de_causas = db.Column(db.String(255), nullable=True)
    causa_padronizado = db.Column(db.String(255), nullable=True)
    resumo_do_objeto = db.Column(db.String(255), nullable=True)
    ultimo_andamento = db.Column(db.String(255), nullable=True)
    data_citacao = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(100), nullable=True)
    liminar_deferida = db.Column(db.String(255), nullable=True)
    valor_da_causa = db.Column(db.Float, nullable=True)
    risco_economico = db.Column(db.Float, nullable=True)
    valor_de_condenacao = db.Column(db.Float, nullable=True)
    data_de_pagamento = db.Column(db.Date, nullable=True)
    avaliacao_de_risco = db.Column(db.String(255), nullable=True)
    observacao = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Proposta {self.numero_processo}>'

class Proposta(db.Model):
    id = db.Column(db.Integer, primary_key=True)


    tipo_contrato = db.Column(db.String(100), nullable=True)
    numero_proposta = db.Column(db.String(100), nullable=True)
    operadora_nome = db.Column(db.String(100), nullable=True)
    cliente_contratante = db.Column(db.String(255), nullable=True)
    quantidade_vidas = db.Column(db.Integer, nullable=True)
    vendedor = db.Column(db.String(255), nullable=True)
    corretora = db.Column(db.String(255), nullable=True)
    data_criacao = db.Column(db.Date, nullable=True)
    data_vigencia = db.Column(db.Date, nullable=True)
    valor = db.Column(db.Float, nullable=True)

    
    colaborador = db.Column(db.String(255), nullable=True)
    data_analise = db.Column(db.Date, nullable=True)
    realizou_entrevista_medica = db.Column(db.String(50), nullable=True)
    status_area_medica = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(100), nullable=True)
    motivo_declinio = db.Column(db.String(255), nullable=True)
    responsavel_digitacao = db.Column(db.String(255), nullable=True)
    data_cadastro_facplan = db.Column(db.Date, nullable=True)
    api_facplan = db.Column(db.String(50), nullable=True)
    data_envio_operadora = db.Column(db.Date, nullable=True)
    digitacao_api = db.Column(db.String(50), nullable=True)
    responsavel_efetivacao = db.Column(db.String(255), nullable=True)
    data_efetivacao = db.Column(db.Date, nullable=True)
    data_implantacao = db.Column(db.Date, nullable=True)
    responsavel_geracao = db.Column(db.String(255), nullable=True)
    data_geracao_boleto = db.Column(db.Date, nullable=True)
    observacao = db.Column(db.Text, nullable=True)
    conferencia = db.Column(db.String(50), nullable=True)
    colaborador_devolucao = db.Column(db.String(255), nullable=True)
    dt_critica_operadora = db.Column(db.Date, nullable=True)
    dt_resolvido_quali = db.Column(db.Date, nullable=True)
    origem_devolucao = db.Column(db.String(100), nullable=True)
    status_devolucao = db.Column(db.String(100), nullable=True)
    motivo_devolucao = db.Column(db.String(255), nullable=True)
    descricao_devolucao = db.Column(db.Text, nullable=True)

    locked_by = db.Column(db.String(100), nullable=True)   
    locked_at = db.Column(db.DateTime, nullable=True)    


class HistoricoAlteracao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    proposta_id = db.Column(db.Integer, db.ForeignKey('proposta.id', ondelete="CASCADE"), nullable=False)
    usuario = db.Column(db.String(255), nullable=False)
    campo_alterado = db.Column(db.String(255), nullable=False)
    valor_anterior = db.Column(db.Text, nullable=True)
    valor_novo = db.Column(db.Text, nullable=True)
    data_alteracao = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    proposta = db.relationship(
        'Proposta',
        backref=db.backref('historicos', lazy=True, cascade="all, delete-orphan")
    )

    @property
    def proposta_numero(self):
        if self.proposta_id:
            proposta = Proposta.query.get(self.proposta_id)
            return proposta.numero_proposta if proposta else None
        return None

    def __repr__(self):
        return f'<HistoricoAlteracao {self.campo_alterado} - {self.data_alteracao}>'


class LogAcesso(db.Model):
    __tablename__ = 'log_acesso'

    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(100), nullable=False)
    acao = db.Column(db.String(200), nullable=False)
    data_hora = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    ip = db.Column(db.String(50))
    detalhes = db.Column(db.Text)

    def __repr__(self):
        return f'<LogAcesso {self.usuario} - {self.acao} - {self.data_hora}>'


# --- Relação N:N entre Role e Permission ---
role_permissions = db.Table(
    'role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True)
)


class Domain(db.Model):
    __tablename__ = "domains"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), unique=True, nullable=False)
    descricao = db.Column(db.String(200))

    def __repr__(self):
        return f"<Domain {self.nome}>"


class Permission(db.Model):
    __tablename__ = "permissions"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), unique=True, nullable=False)
    dominio_id = db.Column(db.Integer, db.ForeignKey('domains.id'))
    domain = db.relationship("Domain", backref="permissions")

    def __repr__(self):
        return f"<Permission {self.nome}>"


class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), unique=True, nullable=False)
    permissions = db.relationship('Permission', secondary=role_permissions, backref='roles')

    usuarios = db.relationship('Usuario', back_populates='role')

    def __repr__(self):
        return f"<Role {self.nome}>"
