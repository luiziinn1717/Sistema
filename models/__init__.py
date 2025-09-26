from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from .usuario import Usuario
from .core import Proposta, HistoricoAlteracao, LogAcesso, Role, Permission, Domain, role_permissions, Processos

