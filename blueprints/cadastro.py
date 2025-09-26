from flask import (
    Blueprint, render_template, request, redirect, url_for, flash,
    session, jsonify, send_file, current_app, abort
)
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
import os
import pandas as pd
import logging
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from models import db, Proposta, HistoricoAlteracao, Usuario, LogAcesso, Role, Permission
from utils.decorators import login_required as base_login_required, require_permission
from utils.validators import read_excel_file, map_columns, identify_missing_fields, convert_date_columns, convert_numeric_columns
from flask_login import current_user
from werkzeug.utils import secure_filename
from flask import current_app

#def cadastro_login_required(f):
#    return base_login_required(login_endpoint='cadastro_bp.login')(f)
#def juridico_login_required(f):
#   return base_login_required(login_endpoint='juridico_bp.login')(f)

from utils.validators import sanitize_input, parse_date_safe, parse_decimal_safe

cadastro_bp = Blueprint('cadastro_bp', __name__, 
 template_folder='../templates/cadastro',
 static_folder='../static')
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'xlsx'}

# Mapeamento de colunas para upload de planilha
COLUMN_MAPPING = {
    'contrato': 'tipo_contrato',
    'oper_propnum': 'numero_proposta',
    'contratante_nome': 'cliente_contratante',
    'beneficiarios': 'quantidade_vidas',
    'vendedor_nome': 'vendedor',
    'corretora_nome': 'corretora',
    'data_criacao': 'data_criacao',
    'data_vigencia': 'data_vigencia',
    'operadora': 'operadora_nome',
    'valor': 'valor',
}

# Campos obrigatórios da planilha
REQUIRED_FIELDS = [
    'tipo_contrato', 'numero_proposta', 'cliente_contratante',
    'quantidade_vidas', 'vendedor', 'corretora',
    'data_criacao', 'data_vigencia', 'valor', 'operadora_nome'
]

# ===== FUNÇÕES DE LOGGING =====
def registrar_alteracao(proposta_id, usuario, campo, valor_anterior, valor_novo):
    """Registra uma alteração no histórico."""
    try:
        str_valor_anterior = str(valor_anterior) if valor_anterior is not None else ''
        str_valor_novo = str(valor_novo) if valor_novo is not None else ''
        
        if str_valor_anterior != str_valor_novo:
            historico = HistoricoAlteracao(
                proposta_id=proposta_id,
                usuario=usuario,
                campo_alterado=campo,
                valor_anterior=str_valor_anterior,
                valor_novo=str_valor_novo
            )
            db.session.add(historico)
            return True
        return False
    except Exception as e:
        current_app.logger.error(f"Erro ao registrar alteração: {e}")
        return False

def registrar_acesso(acao, detalhes=None):
    """Registra acesso e ações dos usuários."""
    try:
        log = LogAcesso(
            usuario=session.get('user', 'Anônimo'),
            acao=acao,
            ip=request.remote_addr,
            detalhes=detalhes
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Erro ao registrar acesso: {e}")

#@cadastro_bp.route('/login', methods=['GET', 'POST'])
#def login():
#    if request.method == 'POST':
#        username = request.form['username']
#        password = request.form['password']

#        usuario = Usuario.query.filter_by(username=username, ativo=True).first()
#        if usuario and usuario.check_password(password) and (
#            usuario.has_permission("cadastro_visualizar_propostas") or usuario.has_permission("sistema_visualizar_usuarios")
#        ):
            # Limpar sessão do outro módulo
#            session.pop('juridico_user_id', None)
#            session.pop('juridico_user', None)
#            session.pop('juridico_nome_completo', None)
#            session.pop('juridico_last_activity', None)

            # Sessão Cadastro
#            session['cadastro_user_id'] = usuario.id
#            session['cadastro_user'] = usuario.username
#            session['cadastro_nome_completo'] = usuario.nome_completo
#            session['cadastro_last_activity'] = datetime.utcnow()

#            usuario.ultimo_login = datetime.utcnow()
#            db.session.commit()

#            registrar_acesso('Login realizado com sucesso', f'Usuário: {username}')
#            flash('Login realizado com sucesso!', 'success')
#            return redirect(url_for('cadastro_bp.propostas'))

#        flash('Credenciais inválidas!', 'error')
#        registrar_acesso('Tentativa de login falhou', f'Usuário: {username}')

#    registrar_acesso('Página de login acessada')
#    return render_template('login_cadastro.html')

@cadastro_bp.route('/logout')

def logout():
    registrar_acesso('Logout realizado', f'Usuário: {session.get("cadastro_user")}')
    session.pop('cadastro_user_id', None)
    session.pop('cadastro_user', None)
    session.pop('cadastro_nome_completo', None)
    session.pop('cadastro_last_activity', None)
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('cadastro_bp.login'))

@cadastro_bp.route('/perfil')

def perfil():
    usuario = Usuario.query.get(session['cadastro_user_id'])
    registrar_acesso('Perfil visualizado', f'Usuário: {usuario.username}')
    return render_template('perfil.html',base_template='base_cadastro.html', usuario=usuario)

@cadastro_bp.route('/perfil/editar', methods=['GET', 'POST'])

def editar_perfil():
    usuario = Usuario.query.get(session['cadastro_user_id'])
    
    try:
        roles = Role.query.all()
    except Exception as e:
        current_app.logger.error(f"Erro ao carregar roles: {e}")
        roles = []
        flash('Sistema de papéis não disponível no momento.', 'warning')
    
    if request.method == 'POST':
        campos_alterados = []
        
        nome_completo_sanitized = sanitize_input(request.form['nome_completo'])
        email_sanitized = sanitize_input(request.form['email'])
        departamento_sanitized = sanitize_input(request.form['departamento'])
        telefone_sanitized = sanitize_input(request.form['telefone'])

        if usuario.nome_completo != nome_completo_sanitized:
            campos_alterados.append('nome_completo')
        if usuario.email != email_sanitized:
            campos_alterados.append('email')
        if usuario.departamento != departamento_sanitized:
            campos_alterados.append('departamento')
        if usuario.telefone != telefone_sanitized:
            campos_alterados.append('telefone')
        
        try:
            if 'role_id' in request.form and request.form['role_id']:
                new_role_id = int(request.form['role_id'])
                if usuario.role_id != new_role_id:
                    campos_alterados.append('cargo/role')
                    usuario.role_id = new_role_id
        except (ValueError, TypeError):
            pass

        usuario.nome_completo = nome_completo_sanitized
        usuario.email = email_sanitized
        usuario.departamento = departamento_sanitized
        usuario.telefone = telefone_sanitized
        
        if request.form['nova_senha']:
            if usuario.check_password(request.form['senha_atual']):
                usuario.set_password(request.form['nova_senha'])
                campos_alterados.append('senha')
                flash('Perfil e senha atualizados com sucesso!', 'success')
            else:
                flash('Senha atual incorreta!', 'error')
                return render_template('editar_perfil.html',base_template='base_cadastro.html', usuario=usuario, roles=roles)
        else:
            flash('Perfil atualizado com sucesso!', 'success')
        
        db.session.commit()
        
        if campos_alterados:
            registrar_acesso('Perfil editado', f'Campos alterados: {", ".join(campos_alterados)}')
        
        return redirect(url_for('cadastro_bp.perfil'))
    
    registrar_acesso('Edição de perfil acessada')
    return render_template('editar_perfil.html',base_template='base_cadastro.html', usuario=usuario, roles=roles)

@cadastro_bp.route('/usuarios')

@require_permission('sistema_visualizar_usuarios')
def usuarios():
    usuarios_list = Usuario.query.all()
    registrar_acesso('Lista de usuários visualizada')
    return render_template('usuarios.html', base_template='base_cadastro.html', usuarios=usuarios_list)

@cadastro_bp.route('/usuarios/novo', methods=['GET', 'POST'])

@require_permission('sistema_criar_usuario')
def novo_usuario():
    try:
        roles = Role.query.all()
        if not roles:
            default_role = Role(nome='Usuário')
            db.session.add(default_role)
            db.session.commit()
            roles = [default_role]
    except Exception as e:
        current_app.logger.error(f"Erro ao carregar roles: {e}")
        roles = []
        flash('Sistema de papéis não disponível no momento.', 'warning')
    
    if request.method == 'POST':
        try:
            username_sanitized = sanitize_input(request.form['username'])
            email_sanitized = sanitize_input(request.form['email'])
            nome_completo_sanitized = sanitize_input(request.form['nome_completo'])
            departamento_sanitized = sanitize_input(request.form['departamento'])
            telefone_sanitized = sanitize_input(request.form['telefone'])
            password = request.form['password']

            if Usuario.query.filter_by(username=username_sanitized).first():
                flash('Nome de usuário já existe!', 'error')
                return render_template('novo_usuario.html', roles=roles)
            
            if Usuario.query.filter_by(email=email_sanitized).first():
                flash('Email já está em uso!', 'error')
                return render_template('novo_usuario.html', roles=roles)
            
            usuario = Usuario()
            usuario.username = username_sanitized
            usuario.email = email_sanitized
            usuario.nome_completo = nome_completo_sanitized
            usuario.departamento = departamento_sanitized
            usuario.telefone = telefone_sanitized
            usuario.set_password(password)
            
            if roles and 'role_id' in request.form and request.form['role_id']:
                usuario.role_id = int(request.form['role_id'])
            else:
                usuario.role_id = roles[0].id if roles else None
            
            db.session.add(usuario)
            db.session.commit()
            
            registrar_acesso('Novo usuário criado', f'Usuário: {usuario.username}')
            flash('Usuário criado com sucesso!', 'success')
            return redirect(url_for('cadastro_bp.usuarios'))
        
        except IntegrityError:
            db.session.rollback()
            flash('Erro de integridade ao criar usuário. Verifique os dados.', 'error')
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Erro ao criar usuário: {e}")
            flash(f'Erro ao criar usuário: {str(e)}', 'error')
            return render_template('novo_usuario.html',base_template='base_cadastro.html', roles=roles)
    
    registrar_acesso('Criação de usuário acessada')
    return render_template('novo_usuario.html',base_template='base_cadastro.html', roles=roles)

@cadastro_bp.route('/usuarios/delete/<int:id>', methods=['POST'])

@require_permission('sistema_deletar_usuario')
def delete_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    if usuario.id == session.get("user_id"):
        flash("Você não pode excluir o seu próprio usuário.", "error")
        return redirect(url_for("cadastro_bp.usuarios"))
    try:
        db.session.delete(usuario)
        db.session.commit()
        registrar_acesso('Usuário excluído', f'Usuário ID: {id}, Username: {usuario.username}')
        flash("Usuário excluído com sucesso!", "success")
    except IntegrityError:
        db.session.rollback()
        flash("Não foi possível excluir o usuário devido a registros relacionados.", "error")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Erro ao excluir usuário: {e}")
        flash("Erro ao excluir usuário!", "error")
    return redirect(url_for("cadastro_bp.usuarios"))

@cadastro_bp.route('/usuarios/editar/<int:id>', methods=['GET', 'POST'])

@require_permission('sistema_editar_usuario')
def editar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    
    try:
        roles = Role.query.all()
    except Exception as e:
        current_app.logger.error(f"Erro ao carregar roles: {e}")
        roles = []

    if request.method == 'POST':
        try:
            nome_completo_sanitized = sanitize_input(request.form['nome_completo'])
            email_sanitized = sanitize_input(request.form['email'])
            departamento_sanitized = sanitize_input(request.form['departamento'])
            telefone_sanitized = sanitize_input(request.form['telefone'])
            
            usuario.nome_completo = nome_completo_sanitized
            usuario.email = email_sanitized
            usuario.departamento = departamento_sanitized
            usuario.telefone = telefone_sanitized
            
            if 'role_id' in request.form and request.form['role_id']:
                usuario.role_id = int(request.form['role_id'])

            if request.form['nova_senha']:
                usuario.set_password(request.form['nova_senha'])
            
            db.session.commit()
            registrar_acesso('Usuário editado', f'Usuário ID: {id}, Username: {usuario.username}')
            flash("Usuário atualizado com sucesso!", "success")
            return redirect(url_for("cadastro_bp.usuarios"))
        except IntegrityError:
            db.session.rollback()
            flash('Erro de integridade ao editar usuário. Verifique os dados.', 'error')
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Erro ao editar usuário: {e}")
            flash("Erro ao atualizar usuário!", "error")

    return render_template("editar_usuario.html", base_template='base_cadastro.html', usuario=usuario, roles=roles)

@cadastro_bp.route('/usuarios/toggle/<int:id>', methods=['POST'])

@require_permission('sistema_ativar_desativar_usuario')
def toggle_usuario(id):
    usuario = Usuario.query.get_or_404(id)

    if usuario.id == session.get("user_id"):
        flash("Você não pode desativar o seu próprio usuário.", "error")
        return redirect(url_for("cadastro_bp.usuarios"))

    try:
        usuario.ativo = not usuario.ativo
        db.session.commit()

        if usuario.ativo:
            flash(f"Usuário {usuario.username} ativado com sucesso!", "success")
            registrar_acesso('Usuário ativado', f'Usuário ID: {id}, Username: {usuario.username}')
        else:
            flash(f"Usuário {usuario.username} desativado com sucesso!", "warning")
            registrar_acesso('Usuário desativado', f'Usuário ID: {id}, Username: {usuario.username}')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Erro ao ativar/desativar usuário: {e}")
        flash("Erro ao alterar status do usuário!", "error")

    return redirect(url_for("cadastro_bp.usuarios"))

@cadastro_bp.route('/propostas')

@require_permission('cadastro_visualizar_propostas')
def propostas():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    status_filter = sanitize_input(request.args.get('status', ''))
    cliente_filter = sanitize_input(request.args.get('cliente', ''))
    vendedor_filter = sanitize_input(request.args.get('vendedor', ''))
    data_inicio = sanitize_input(request.args.get('data_inicio', ''))
    data_fim = sanitize_input(request.args.get('data_fim', ''))
    operadora_filter = sanitize_input(request.args.get('operadora_nome', ''))
    
    query = Proposta.query.options(joinedload(Proposta.historicos))
    
    if status_filter:
        query = query.filter(Proposta.status.ilike(f'%{status_filter}%'))
    if operadora_filter:
        query = query.filter(Proposta.operadora_nome.ilike(f'%{operadora_filter}%'))
    if cliente_filter:
        query = query.filter(Proposta.cliente_contratante.ilike(f'%{cliente_filter}%'))
    if vendedor_filter:
        query = query.filter(Proposta.vendedor.ilike(f'%{vendedor_filter}%'))
    
    if data_inicio:
        data_inicio_dt = parse_date_safe(data_inicio)
        if data_inicio_dt:
            query = query.filter(Proposta.data_criacao >= data_inicio_dt)
        else:
            flash('Formato de Data Início inválido. Use YYYY-MM-DD.', 'error')
    if data_fim:
        data_fim_dt = parse_date_safe(data_fim)
        if data_fim_dt:
            query = query.filter(Proposta.data_criacao <= data_fim_dt)
        else:
            flash('Formato de Data Fim inválido. Use YYYY-MM-DD.', 'error')
            
    propostas_paginadas = query.order_by(Proposta.data_criacao.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    filters = {
    'status': status_filter,
    'cliente': cliente_filter,
    'vendedor': vendedor_filter,
    'data_inicio': data_inicio,
    'data_fim': data_fim,
    'operadora_nome': operadora_filter
}

    registrar_acesso('Listagem de propostas visualizada')
    return render_template(
    'propostas.html', 
    pagination=propostas_paginadas,
    propostas=propostas_paginadas.items,
    status_filter=status_filter, 
    cliente_filter=cliente_filter, 
    vendedor_filter=vendedor_filter, 
    data_inicio=data_inicio, 
    data_fim=data_fim, 
    operadora_filter=operadora_filter,
    filters=filters
)


@cadastro_bp.route('/propostas/edit/<int:id>', methods=['GET', 'POST'])

@require_permission('cadastro_editar_proposta')
def edit_proposta(id):
    proposta = Proposta.query.get_or_404(id)

    if proposta.locked_by and proposta.locked_by != session.get("user") and proposta.locked_at and (datetime.utcnow() - proposta.locked_at) < timedelta(minutes=5):
        flash(f"Proposta bloqueada por {proposta.locked_by}. Tente novamente mais tarde.", "warning")
        return redirect(url_for('cadastro_bp.propostas'))

    if request.method == 'POST':
        try:
            campos_alterados = []
            form_data = request.form.to_dict()
            
            campos_atualizaveis = [
                'tipo_contrato', 'numero_proposta', 'cliente_contratante', 'quantidade_vidas',
                'vendedor', 'corretora', 'data_criacao', 'data_vigencia', 'valor', 'operadora_nome',
                'colaborador', 'data_analise', 'realizou_entrevista_medica', 'status_area_medica',
                'status', 'motivo_declinio', 'responsavel_digitacao', 'data_cadastro_facplan',
                'api_facplan', 'data_envio_operadora', 'digitacao_api', 'responsavel_efetivacao',
                'data_efetivacao', 'data_implantacao', 'responsavel_geracao', 'data_geracao_boleto',
                'observacao', 'conferencia', 'colaborador_devolucao', 'dt_critica_operadora',
                'dt_resolvido_quali', 'origem_devolucao', 'status_devolucao', 'motivo_devolucao',
                'descricao_devolucao'
            ]

            campos_data = [
                'data_criacao', 'data_vigencia', 'data_analise', 'data_cadastro_facplan',
                'data_envio_operadora', 'data_efetivacao', 'data_implantacao',
                'data_geracao_boleto', 'dt_critica_operadora', 'dt_resolvido_quali'
            ]
            campos_numericos = ['quantidade_vidas', 'valor']

            for campo in campos_atualizaveis:
                if campo in form_data:
                    valor_anterior = getattr(proposta, campo)
                    valor_bruto = form_data[campo]
                    
                    if campo in campos_data:
                        valor_novo = parse_date_safe(valor_bruto)
                    elif campo in campos_numericos:
                        valor_novo = parse_decimal_safe(valor_bruto)
                    else:
                        valor_novo = sanitize_input(valor_bruto)

                    if registrar_alteracao(proposta.id, session['user'], campo, valor_anterior, valor_novo):
                        setattr(proposta, campo, valor_novo)
                        campos_alterados.append(campo)
            
            proposta.locked_by = None 
            proposta.locked_at = None
            db.session.commit()
            
            if campos_alterados:
                registrar_acesso('Proposta editada', f'Proposta ID: {id}, Campos alterados: {", ".join(campos_alterados)}')
            
            flash('Proposta atualizada com sucesso!', 'success')
            return redirect(url_for('cadastro_bp.propostas'))
        except IntegrityError:
            db.session.rollback()
            flash('Erro de integridade ao atualizar proposta. Verifique os dados.', 'error')
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Erro ao atualizar proposta: {e}")
            flash(f'Erro ao atualizar proposta: {str(e)}', 'error')

    # Bloqueia a proposta para edição
    proposta.locked_by = session.get("user")
    proposta.locked_at = datetime.utcnow()
    db.session.commit()
    
    registrar_acesso('Edição de proposta acessada', f'Proposta ID: {id}')
    return render_template('edit_proposta.html', proposta=proposta)

@cadastro_bp.route('/propostas/liberar/<int:id>', methods=['POST'])

def liberar_proposta(id):
    proposta = Proposta.query.get_or_404(id)
    if proposta.locked_by == session.get("user"):
        proposta.locked_by = None
        proposta.locked_at = None
        db.session.commit()
        flash("Proposta liberada com sucesso!", "info")
    return "", 204

@cadastro_bp.route('/propostas/new', methods=['GET', 'POST'])

@require_permission('cadastro_criar_proposta')
def new_proposta():
    if request.method == 'POST':
        try:
            proposta = Proposta()
            
            # Preencher campos básicos e sanitizar
            proposta.tipo_contrato = sanitize_input(request.form['tipo_contrato'])
            proposta.numero_proposta = sanitize_input(request.form['numero_proposta'])
            proposta.cliente_contratante = sanitize_input(request.form['cliente_contratante'])
            proposta.quantidade_vidas = parse_decimal_safe(request.form['quantidade_vidas'])
            proposta.vendedor = sanitize_input(request.form['vendedor'])
            proposta.corretora = sanitize_input(request.form['corretora'])
            proposta.data_criacao = parse_date_safe(request.form['data_criacao'])
            proposta.data_vigencia = parse_date_safe(request.form['data_vigencia'])
            proposta.valor = parse_decimal_safe(request.form['valor'])
            proposta.operadora_nome = sanitize_input(request.form['operadora_nome'])

            # Colaborador logado
            proposta.colaborador = session['user']
            
            db.session.add(proposta)
            db.session.commit()
            
            # REGISTRAR CRIAÇÃO DA PROPOSTA
            historico = HistoricoAlteracao(
                proposta_id=proposta.id,
                usuario=session['user'],
                campo_alterado='CRIAÇÃO',
                valor_anterior=None,
                valor_novo='Proposta criada manualmente'
            )
            db.session.add(historico)
            db.session.commit()
            
            registrar_acesso('Nova proposta criada', f'Proposta ID: {proposta.id}, Número: {proposta.numero_proposta}')
            flash('Proposta criada com sucesso!', 'success')
            return redirect(url_for('cadastro_bp.propostas'))
        except IntegrityError:
            db.session.rollback()
            flash('Erro de integridade ao criar proposta. Verifique os dados.', 'error')
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Erro ao criar proposta: {e}")
            flash(f'Erro ao criar proposta: {str(e)}', 'error')
    
    registrar_acesso('Criação de proposta acessada')
    return render_template('new_proposta.html')

@cadastro_bp.route('/propostas/delete/<int:id>', methods=['POST'])

@require_permission('cadastro_deletar_proposta')
def delete_proposta(id):
    try:
        proposta = Proposta.query.get_or_404(id)
        numero_proposta = proposta.numero_proposta or str(proposta.id)

        # Excluir históricos relacionados antes de excluir a proposta
        HistoricoAlteracao.query.filter_by(proposta_id=proposta.id).delete()

        historico = HistoricoAlteracao(
            proposta_id=proposta.id,
            usuario=session['user'],
            campo_alterado='EXCLUSÃO',
            valor_anterior=f'Proposta {numero_proposta}',
            valor_novo=None
        )
        db.session.add(historico)

        db.session.delete(proposta)
        db.session.commit()

        registrar_acesso('Proposta excluída', f'Proposta ID: {id}, Número: {numero_proposta}')
        flash('Proposta excluída com sucesso!', 'success')

    except IntegrityError:
        db.session.rollback()
        flash('Não foi possível excluir a proposta devido a registros relacionados.', 'error')
    except Exception as e:
        db.session.rollback()
        registrar_acesso('Erro ao excluir proposta', f'Erro: {str(e)}')
        flash('Erro ao excluir proposta!', 'error')
        current_app.logger.error(f"Erro ao excluir proposta: {e}")

    return redirect(url_for('cadastro_bp.propostas'))
    
@cadastro_bp.route("/upload", methods=["GET", "POST"])

@require_permission('cadastro_upload_planilha')
def upload():
    if request.method == "POST":
        if "file" not in request.files:
            flash("Nenhum arquivo selecionado!", "error")
            return redirect(request.url)

        file = request.files["file"]
        if file.filename == "":
            flash("Nenhum arquivo selecionado!", "error")
            return redirect(request.url)

        sobrepor_duplicatas = request.form.get("sobrepor_duplicatas") == "on"

        if file and file.filename.endswith(".xlsx"):
            filename = secure_filename(file.filename)

            # Pasta de upload
            upload_folder = current_app.config.get("UPLOAD_FOLDER", "uploads")
            os.makedirs(upload_folder, exist_ok=True)

            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)

            # Processar planilha
            df = read_excel_file(file_path)
            if df is None:
                registrar_acesso("Erro no processamento de planilha", "Arquivo inválido ou corrompido")
                flash("Erro ao processar a planilha!", "error")
                return redirect(request.url)

            # Mapear e converter colunas
            df_mapped = map_columns(df, COLUMN_MAPPING)
            missing_fields = identify_missing_fields(df_mapped, REQUIRED_FIELDS)
            df_mapped = convert_date_columns(df_mapped, ["data_criacao", "data_vigencia"])
            df_mapped = convert_numeric_columns(df_mapped, ["quantidade_vidas", "valor"])

            propostas_novas = 0
            propostas_atualizadas = 0
            propostas_duplicadas = 0

            for _, row in df_mapped.iterrows():
                numero_proposta = (
                    str(row["numero_proposta"]).strip()
                    if "numero_proposta" in df_mapped.columns and pd.notna(row["numero_proposta"])
                    else None
                )

                proposta_existente = None
                if numero_proposta:
                    proposta_existente = Proposta.query.filter_by(numero_proposta=numero_proposta).first()

                if proposta_existente:
                    if sobrepor_duplicatas:
                        for field in REQUIRED_FIELDS:
                            if field in df_mapped.columns and pd.notna(row[field]):
                                valor_anterior = getattr(proposta_existente, field)
                                valor_novo = row[field]

                                if registrar_alteracao(
                                    proposta_existente.id,
                                    current_user,
                                    field,
                                    valor_anterior,
                                    valor_novo
                                ):
                                    setattr(proposta_existente, field, valor_novo)
                        propostas_atualizadas += 1
                    else:
                        propostas_duplicadas += 1
                        continue
                else:
                    proposta = Proposta()
                    for field in REQUIRED_FIELDS:
                        if field in df_mapped.columns:
                            setattr(proposta, field, row[field] if pd.notna(row[field]) else None)
                    proposta.colaborador = current_user

                    db.session.add(proposta)
                    db.session.flush()

                    usuario_id = int(current_user.get_id())

                    with db.session.no_autoflush:
                        historico = HistoricoAlteracao(
                            proposta_id=proposta.id,
                            usuario=usuario_id,
                            campo_alterado="CRIAÇÃO",
                            valor_anterior=None,
                            valor_novo="Proposta criada via upload de planilha"
                            )
                        
                    db.session.add(historico)

                    propostas_novas += 1

            db.session.commit()

            # Mensagem final
            mensagem = "Planilha processada com sucesso! "
            if propostas_novas > 0:
                mensagem += f"{propostas_novas} novas propostas importadas. "
            if propostas_atualizadas > 0:
                mensagem += f"{propostas_atualizadas} propostas atualizadas. "
            if propostas_duplicadas > 0:
                mensagem += f"{propostas_duplicadas} propostas duplicadas ignoradas."

            registrar_acesso("Upload de planilha processado", mensagem)
            flash(mensagem, "success")
            return redirect(url_for("cadastro_bp.propostas"))
        else:
            registrar_acesso("Tentativa de upload com formato inválido", f"Arquivo: {file.filename}")
            flash("Formato de arquivo inválido! Use apenas .xlsx", "error")

    registrar_acesso("Página de upload acessada")
    return render_template("upload.html")

@cadastro_bp.route('/export_excel')

@require_permission('cadastro_exportar_dados')
def export_excel():
    status_filter = sanitize_input(request.args.get('status', ''))
    cliente_filter = sanitize_input(request.args.get('cliente', ''))
    vendedor_filter = sanitize_input(request.args.get('vendedor', ''))
    data_inicio = sanitize_input(request.args.get('data_inicio', ''))
    data_fim = sanitize_input(request.args.get('data_fim', ''))
    operadora_filter = sanitize_input(request.args.get('operadora_nome', ''))
    
    query = Proposta.query
    
    if status_filter:
        query = query.filter(Proposta.status.ilike(f'%{status_filter}%'))
    if operadora_filter:
        query = query.filter(Proposta.operadora_nome.ilike(f'%{operadora_filter}%'))
    if cliente_filter:
        query = query.filter(Proposta.cliente_contratante.ilike(f'%{cliente_filter}%'))
    if vendedor_filter:
        query = query.filter(Proposta.vendedor.ilike(f'%{vendedor_filter}%'))
    if data_inicio:
        data_inicio_dt = parse_date_safe(data_inicio)
        if data_inicio_dt:
            query = query.filter(Proposta.data_criacao >= data_inicio_dt)
    if data_fim:
        data_fim_dt = parse_date_safe(data_fim)
        if data_fim_dt:
            query = query.filter(Proposta.data_criacao <= data_fim_dt)
    
    propostas_list = query.all()
    
    data = []
    for proposta in propostas_list:
        data.append({
            'ID': proposta.id,
            'Tipo Contrato': proposta.tipo_contrato,
            'Número Proposta': proposta.numero_proposta,
            'Operadora': proposta.operadora_nome,
            'Cliente/Contratante': proposta.cliente_contratante,
            'Quantidade Vidas': proposta.quantidade_vidas,
            'Vendedor': proposta.vendedor,
            'Corretora': proposta.corretora,
            'Data Criação': proposta.data_criacao.strftime('%d/%m/%Y') if proposta.data_criacao else '',
            'Data Vigência': proposta.data_vigencia.strftime('%d/%m/%Y') if proposta.data_vigencia else '',
            'Valor': proposta.valor,
            'Colaborador': proposta.colaborador,
            'Data Análise': proposta.data_analise.strftime('%d/%m/%Y') if proposta.data_analise else '',
            'Entrevista Médica': proposta.realizou_entrevista_medica,
            'Status Área Médica': proposta.status_area_medica,
            'Status': proposta.status,
            'Motivo Declínio': proposta.motivo_declinio,
            'Colaborador Analise': proposta.colaborador,
            'Responsável Digitação': proposta.responsavel_digitacao,
            'Data Cadastro FACPLAN': proposta.data_cadastro_facplan.strftime('%d/%m/%Y') if proposta.data_cadastro_facplan else '',
            'API FACPLAN': proposta.api_facplan,
            'Data Envio Operadora': proposta.data_envio_operadora.strftime('%d/%m/%Y') if proposta.data_envio_operadora else '',
            'Digitação/API': proposta.digitacao_api,
            'Responsável Efetivação': proposta.responsavel_efetivacao,
            'Data Efetivação': proposta.data_efetivacao.strftime('%d/%m/%Y') if proposta.data_efetivacao else '',
            'Data Implantação': proposta.data_implantacao.strftime('%d/%m/%Y') if proposta.data_implantacao else '',
            'Responsável Geração': proposta.responsavel_geracao,
            'Data Geração Boleto': proposta.data_geracao_boleto.strftime('%d/%m/%Y') if proposta.data_geracao_boleto else '',
            'Observação': proposta.observacao,
            'Conferência': proposta.conferencia,
            'Colaborador Digitação': proposta.colaborador,
            'Colaborador Devolução': proposta.colaborador_devolucao,
            'DT Crítica Operadora': proposta.dt_critica_operadora.strftime('%d/%m/%Y') if proposta.dt_critica_operadora else '',
            'DT Resolvido Quali': proposta.dt_resolvido_quali.strftime('%d/%m/%Y') if proposta.dt_resolvido_quali else '',
            'Origem Devolução': proposta.origem_devolucao,
            'Status Devolução': proposta.status_devolucao,
            'Motivo Devolução': proposta.motivo_devolucao,
            'Descrição Devolução': proposta.descricao_devolucao
        })
    
    df = pd.DataFrame(data)
    
    filename = f'propostas_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    df.to_excel(filepath, index=False)
    
    registrar_acesso('Exportação Excel realizada', f'Arquivo: {filename}, Registros: {len(propostas_list)}')
    
    return send_file(filepath, as_attachment=True, download_name=filename)

# ===== ROTAS DE LOGS =====
@cadastro_bp.route('/logs')

@require_permission('sistema_ver_logs')
def visualizar_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    tipo_log = request.args.get('tipo', 'alteracoes')  # 'alteracoes' ou 'acessos'

    # Inicializa todas as variáveis
    usuario_filter = ''
    campo_filter = ''
    proposta_id_filter = ''
    acao_filter = ''

    if tipo_log == 'acessos':
        query = LogAcesso.query
        usuario_filter = sanitize_input(request.args.get('usuario', ''))
        acao_filter = sanitize_input(request.args.get('acao', ''))

        if usuario_filter:
            query = query.filter(LogAcesso.usuario.ilike(f'%{usuario_filter}%'))
        if acao_filter:
            query = query.filter(LogAcesso.acao.ilike(f'%{acao_filter}%'))

        logs = query.order_by(LogAcesso.data_hora.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        template = 'logs_acessos.html'
    else:
        query = HistoricoAlteracao.query
        usuario_filter = sanitize_input(request.args.get('usuario', ''))
        campo_filter = sanitize_input(request.args.get('campo', ''))
        proposta_id_filter = sanitize_input(request.args.get('proposta_id', ''))

        if usuario_filter:
            query = query.filter(HistoricoAlteracao.usuario.ilike(f'%{usuario_filter}%'))
        if campo_filter:
            query = query.filter(HistoricoAlteracao.campo_alterado.ilike(f'%{campo_filter}%'))
        if proposta_id_filter.isdigit():
            query = query.filter(HistoricoAlteracao.proposta_id == int(proposta_id_filter))

        logs = query.order_by(HistoricoAlteracao.data_alteracao.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        template = 'logs_alteracoes.html'

    registrar_acesso('Logs do sistema visualizados', f'Tipo: {tipo_log}')
    return render_template(
        template,
        logs=logs,
        tipo_log=tipo_log,
        usuario_filter=usuario_filter,
        campo_filter=campo_filter,
        proposta_id_filter=proposta_id_filter,
        acao_filter=acao_filter,  # agora sempre existe
        base_template='base_cadastro.html'
    )

@cadastro_bp.route('/manutencao')
def manutencao():
    return render_template("manutencao.html")








