# security/session_manager.py
from datetime import datetime, timedelta
from flask import session, flash, redirect, url_for, request
from functools import wraps
import secrets

class SessionManager:
    """Gerenciador centralizado de sessões"""
    
    @staticmethod
    def create_session(user):
        """Cria uma nova sessão segura para o usuário"""
        session.clear()  # Limpa qualquer sessão anterior
        session['user_id'] = user.id
        session['username'] = user.username
        session['nome_completo'] = user.nome_completo
        session['role_id'] = user.role_id if user.role_id else None
        session['session_token'] = secrets.token_hex(16)
        session['last_activity'] = datetime.utcnow()
        session['ip_address'] = request.remote_addr
        session.permanent = True
        
    @staticmethod
    def validate_session():
        """Valida a sessão atual"""
        if 'user_id' not in session:
            return False
            
        # Verifica timeout (2 horas)
        if 'last_activity' in session:
            last_activity = session['last_activity']
            if isinstance(last_activity, str):
                last_activity = datetime.fromisoformat(last_activity)
            
            if datetime.utcnow() - last_activity > timedelta(hours=2):
                session.clear()
                return False
                
        # Verifica mudança de IP (opcional - pode ser desabilitado para redes com IP dinâmico)
        if 'ip_address' in session:
            if session['ip_address'] != request.remote_addr:
                # Log de segurança
                from models import LogAcesso, db
                log = LogAcesso(
                    usuario=session.get('username', 'unknown'),
                    acao='Sessão invalidada - Mudança de IP',
                    ip=request.remote_addr,
                    detalhes=f"IP original: {session['ip_address']}"
                )
                db.session.add(log)
                db.session.commit()
                session.clear()
                return False
        
        # Atualiza última atividade
        session['last_activity'] = datetime.utcnow()
        return True
    
    @staticmethod
    def destroy_session():
        """Destrói a sessão de forma segura"""
        session.clear()
        session.permanent = False

def login_required(f):
    """Decorador melhorado para rotas que requerem login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not SessionManager.validate_session():
            flash('Sua sessão expirou ou é inválida. Por favor, faça login novamente.', 'info')
            # Determina o blueprint correto para redirect
            if request.blueprint == 'cadastro_bp':
                return redirect(url_for('cadastro_bp.login'))
            else:
                return redirect(url_for('juridico.login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorador para rotas que requerem privilégios de admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not SessionManager.validate_session():
            flash('Por favor, faça login primeiro.', 'error')
            return redirect(url_for('juridico.login'))
            
        from models import Usuario
        user = Usuario.query.get(session['user_id'])
        
        if not user or not user.role or user.role.nome not in ['admin', 'supervisao']:
            flash('Acesso negado. Privilégios administrativos necessários.', 'error')
            return redirect(url_for('index'))
            
        return f(*args, **kwargs)
    return decorated_function