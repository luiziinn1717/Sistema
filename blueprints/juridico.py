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

from models import db, Processos, HistoricoAlteracao, Usuario, LogAcesso, Role, Permission
from utils.decorators import login_required as base_login_required, require_permission

#def juridico_login_required(f):
#    return base_login_required(login_endpoint='juridico_bp.login')(f)

#def cadastro_login_required(f):
#    return base_login_required(login_endpoint='cadastro_bp.login')(f)

from utils.validators import sanitize_input, parse_date_safe, parse_decimal_safe


juridico_bp = Blueprint(
    'juridico_bp',
    __name__,
    template_folder='../templates/juridico',
    static_folder='../static'
)

def registrar_alteracao(proposta_id, usuario, campo, valor_anterior, valor_novo):
    """Registra uma alteração no histórico (retorna True se adicionou)."""
    try:
        str_valor_anterior = '' if valor_anterior is None else str(valor_anterior)
        str_valor_novo = '' if valor_novo is None else str(valor_novo)

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
        current_app.logger.exception("Erro ao registrar alteração: %s", e)
        return False

def registrar_acesso(acao, detalhes=None):
    """Registra acesso (tenta não falhar em caso de erro)."""
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
        current_app.logger.debug("Erro ao registrar acesso: %s", e)

@juridico_bp.before_app_request
def log_all_requests():
    """Registra acesso a todas as rotas (aplicável ao app inteiro)."""
    if request.endpoint and request.endpoint not in ['static', 'favicon']:
        registrar_acesso(f'Acesso à {request.endpoint}', f'Path: {request.path}')

#@juridico_bp.route('/login', methods=['GET', 'POST'])
#def login():
#    if request.method == 'POST':
#        username = sanitize_input(request.form.get('username', '')).strip()
#        password = request.form.get('password', '')
#
#        usuario = Usuario.query.filter_by(username=username, ativo=True).first()
#        if usuario and usuario.check_password(password) and (
#            usuario.has_permission("juridico_visualizar_propostas") or 
#            usuario.has_permission("sistema_visualizar_usuarios")
#        ):
            # Limpar sessão do outro módulo
#            session.pop('cadastro_user_id', None)
#            session.pop('cadastro_user', None)
#            session.pop('cadastro_nome_completo', None)
#            session.pop('cadastro_last_activity', None)

            # Sessão Jurídico
#            session['juridico_user_id'] = usuario.id
#            session['juridico_user'] = usuario.username
#            session['juridico_nome_completo'] = usuario.nome_completo
#            session['juridico_last_activity'] = datetime.utcnow()

#            usuario.ultimo_login = datetime.utcnow()
#            db.session.commit()

#            registrar_acesso('Login realizado com sucesso', f'Usuário: {username}')
#            flash('Login realizado com sucesso!', 'success')
#            return redirect(url_for('juridico_bp.propostas'))

#        flash('Credenciais inválidas!', 'error')
#        registrar_acesso('Tentativa de login falhou', f'Usuário: {username}')

#    registrar_acesso('Página de login acessada')
#    return render_template('login_juridico.html')


@juridico_bp.route('/logout')

def logout():
    registrar_acesso('Logout realizado', f'Usuário: {session.get("juridico_user")}')
    session.pop('juridico_user_id', None)
    session.pop('juridico_user', None)
    session.pop('juridico_nome_completo', None)
    session.pop('juridico_last_activity', None)
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('juridico_bp.login'))

@juridico_bp.route("/perfil")

def perfil():
    usuario = Usuario.query.get(session['juridico_user_id'])
    registrar_acesso('Perfil visualizado', f'Usuário: {usuario.username}')
    return render_template('perfil.html',base_template='base_juridico.html', usuario=usuario)


@juridico_bp.route("/perfil/editar", methods=["GET", "POST"])

def editar_perfil():
    usuario = Usuario.query.get(session['juridico_user_id'])
    try:
        roles = Role.query.all()
    except Exception:
        roles = []
        flash('Sistema de papéis não disponível no momento.', 'warning')

    if request.method == 'POST':
        campos_alterados = []
        nome = sanitize_input(request.form.get('nome_completo', ''))
        email = sanitize_input(request.form.get('email', ''))
        departamento = sanitize_input(request.form.get('departamento', ''))
        telefone = sanitize_input(request.form.get('telefone', ''))

        if usuario.nome_completo != nome:
            campos_alterados.append('nome_completo')
            usuario.nome_completo = nome
        if usuario.email != email:
            campos_alterados.append('email')
            usuario.email = email
        if usuario.departamento != departamento:
            campos_alterados.append('departamento')
            usuario.departamento = departamento
        if usuario.telefone != telefone:
            campos_alterados.append('telefone')
            usuario.telefone = telefone

        role_id_raw = request.form.get('role_id')
        if role_id_raw:
            try:
                new_role_id = int(role_id_raw)
                if usuario.role_id != new_role_id:
                    campos_alterados.append('cargo/role')
                    usuario.role_id = new_role_id
            except (ValueError, TypeError):
                pass

        nova_senha = request.form.get('nova_senha', '')
        if nova_senha:
            senha_atual = request.form.get('senha_atual', '')
            if usuario.check_password(senha_atual):
                usuario.set_password(nova_senha)
                campos_alterados.append('senha')
                flash('Perfil e senha atualizados com sucesso!', 'success')
            else:
                flash('Senha atual incorreta!', 'error')
                return render_template('editar_perfil.html',base_template='base_juridico.html', usuario=usuario, roles=roles)
        else:
            flash('Perfil atualizado com sucesso!', 'success')

        db.session.commit()
        if campos_alterados:
            registrar_acesso('Perfil editado', f'Campos alterados: {", ".join(campos_alterados)}')

        return redirect(url_for('juridico_bp.perfil'))

    registrar_acesso('Edição de perfil acessada')
    return render_template('editar_perfil.html',base_template='base_juridico.html', usuario=usuario, roles=roles)


@juridico_bp.route("/usuarios")

@require_permission('sistema_visualizar_usuarios')
def usuarios():
    usuarios_list = Usuario.query.all()
    registrar_acesso('Lista de usuários visualizada')
    return render_template('usuarios.html',base_template='base_juridico.html', usuarios=usuarios_list)


@juridico_bp.route("/usuarios/novo", methods=["GET", "POST"])

@require_permission('sistema_criar_usuario')
def novo_usuario():
    try:
        roles = Role.query.all()
        if not roles:
            default_role = Role(nome='Usuário')
            db.session.add(default_role)
            db.session.commit()
            roles = [default_role]
    except Exception:
        roles = []
        flash('Sistema de papéis não disponível no momento.', 'warning')

    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        nome_completo = sanitize_input(request.form.get('nome_completo', ''))
        departamento = sanitize_input(request.form.get('departamento', ''))
        telefone = sanitize_input(request.form.get('telefone', ''))
        password = request.form.get('password', '')

        if Usuario.query.filter_by(username=username).first():
            flash('Nome de usuário já existe!', 'error')
            return render_template('novo_usuario.html', roles=roles)
        if Usuario.query.filter_by(email=email).first():
            flash('Email já está em uso!', 'error')
            return render_template('novo_usuario.html',base_template='base_juridico.html', roles=roles)

        usuario = Usuario(
            username=username,
            email=email,
            nome_completo=nome_completo,
            departamento=departamento,
            telefone=telefone
        )
        usuario.set_password(password)

        role_id = None
        if 'role_id' in request.form and request.form['role_id']:
            try:
                role_id = int(request.form['role_id'])
                usuario.role_id = role_id
            except (ValueError, TypeError):
                pass
        else:
            if roles:
                usuario.role_id = roles[0].id

        db.session.add(usuario)
        db.session.commit()

        registrar_acesso('Novo usuário criado', f'Usuário: {usuario.username}')
        flash('Usuário criado com sucesso!', 'success')
        return redirect(url_for('juridico_bp.usuarios'))

    registrar_acesso('Criação de usuário acessada')
    return render_template('novo_usuario.html',base_template='base_juridico.html', roles=roles)


@juridico_bp.route("/usuarios/editar/<int:id>", methods=["GET", "POST"])

@require_permission('sistema_editar_usuario')
def editar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    try:
        roles = Role.query.all()
    except Exception:
        roles = []

    if request.method == 'POST':
        usuario.nome_completo = sanitize_input(request.form.get('nome_completo', usuario.nome_completo))
        usuario.email = sanitize_input(request.form.get('email', usuario.email))
        usuario.departamento = sanitize_input(request.form.get('departamento', usuario.departamento))
        usuario.telefone = sanitize_input(request.form.get('telefone', usuario.telefone))

        if 'role_id' in request.form and request.form['role_id']:
            try:
                usuario.role_id = int(request.form['role_id'])
            except (ValueError, TypeError):
                pass

        nova = request.form.get('nova_senha', '')
        if nova:
            usuario.set_password(nova)

        db.session.commit()
        flash("Usuário atualizado com sucesso!", "success")
        return redirect(url_for('juridico_bp.usuarios'))

    return render_template('editar_usuario.html',base_template='base_juridico.html', usuario=usuario, roles=roles)


@juridico_bp.route("/usuarios/delete/<int:id>", methods=["POST"])

@require_permission('sistema_deletar_usuario')
def delete_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    if usuario.id == session.get("user_id"):
        flash("Você não pode excluir o seu próprio usuário.", "error")
        return redirect(url_for("juridico_bp.usuarios"))
    try:
        db.session.delete(usuario)
        db.session.commit()
        flash("Usuário excluído com sucesso!", "success")
    except IntegrityError:
        db.session.rollback()
        flash("Não foi possível excluir o usuário devido a registros relacionados.", "error")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Erro ao excluir usuário: {e}")
        flash("Erro ao excluir usuário!", "error")
    return redirect(url_for('juridico_bp.usuarios'))


@juridico_bp.route("/usuarios/toggle/<int:id>", methods=["POST"])

@require_permission('sistema_ativar_desativar_usuario')
def toggle_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    if usuario.id == session.get("user_id"):
        flash("Você não pode desativar o seu próprio usuário.", "error")
        return redirect(url_for("juridico_bp.usuarios"))
    try:
        usuario.ativo = not usuario.ativo
        db.session.commit()
        flash(f"Usuário {usuario.username} atualizado!", "success")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Erro ao ativar/desativar usuário: {e}")
        flash("Erro ao alterar status do usuário!", "error")
    return redirect(url_for('juridico_bp.usuarios'))


@juridico_bp.route("/")

def root_index():
    return redirect(url_for('juridico_bp.propostas'))


@juridico_bp.route("/propostas")

@require_permission('juridico_visualizar_propostas')
def propostas():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)

    query = Processos.query
    filters = {}

    status_filter = sanitize_input(request.args.get('status', ''))
    operadora_filter = sanitize_input(request.args.get('operadora', ''))
    tipo_de_demandas_filter = sanitize_input(request.args.get('tipo_de_demandas', ''))
    data_de_pagamento = sanitize_input(request.args.get('data_de_pagamento', ''))

    if status_filter:
        query = query.filter(Processos.status == status_filter)
        filters['status'] = status_filter
    if operadora_filter:
        query = query.filter(Processos.operadora_nome == operadora_filter)
        filters['operadora'] = operadora_filter
    if tipo_de_demandas_filter:
        query = query.filter(Processos.tipo_de_demandas == tipo_de_demandas_filter)
    if data_de_pagamento:
        dt = parse_date_safe(data_de_pagamento)
        if dt:
            query = query.filter(Processos.data_de_pagamento >= dt)
            filters['data_de_pagamento'] = data_de_pagamento
        else:
            flash('Formato de Data de Pagamento inválido. Use YYYY-MM-DD.', 'error')

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    propostas_list = pagination.items

    base_query = Processos.query
    operadoras = [o[0] for o in base_query.with_entities(Processos.operadora_nome)
                    .filter(Processos.operadora_nome.isnot(None))
                    .distinct()
                    .order_by(Processos.operadora_nome)
                    .all() if o[0]]
    tipo_de_demandas = [v[0] for v in base_query.with_entities(Processos.tipo_de_demandas)
                    .filter(Processos.tipo_de_demandas.isnot(None))
                    .distinct()
                    .order_by(Processos.tipo_de_demandas)
                    .all() if v[0]]
    status_list = [s[0] for s in base_query.with_entities(Processos.status)
                    .filter(Processos.status.isnot(None))
                    .distinct()
                    .order_by(Processos.status)
                    .all() if s[0]]

    registrar_acesso('Lista de propostas visualizada', f'Filtros aplicados: {filters}')
    return render_template(
        "propostas.html",
        propostas=propostas_list,
        pagination=pagination,
        per_page=per_page,
        filters=filters,
        operadoras=operadoras,
        tipo_de_demandas=tipo_de_demandas,
        status_list=status_list,
    )


@juridico_bp.route("/propostas/new", methods=["GET", "POST"])

@require_permission('juridico_criar_proposta')
def new_proposta():
    if request.method == 'POST':
        try:
            proposta = Processos()
            proposta.numero_processo = sanitize_input(request.form.get('numero_processo', ''))
            proposta.vara_local = sanitize_input(request.form.get('vara_local', ''))
            proposta.autor = sanitize_input(request.form.get('autor', ''))
            proposta.reu = sanitize_input(request.form.get('reu', ''))
            proposta.operadora_nome = sanitize_input(request.form.get('operadora_nome', ''))

            data_citacao_str = sanitize_input(request.form.get('data_citacao', ''))
            proposta.data_citacao = parse_date_safe(data_citacao_str)
            if not proposta.data_citacao and data_citacao_str:
                flash('Formato de Data Citação inválido. Use YYYY-MM-DD.', 'error')
                return render_template('new_proposta.html')

            valor_str = sanitize_input(request.form.get('valor_da_causa', ''))
            proposta.valor_da_causa = parse_decimal_safe(valor_str)
            if not proposta.valor_da_causa and valor_str:
                flash('Formato de Valor da Causa inválido.', 'error')
                return render_template('new_proposta.html')

            proposta.locked_by = None
            proposta.locked_at = None
            proposta.colaborador = session.get('user')

            db.session.add(proposta)
            db.session.commit()

            historico = HistoricoAlteracao(
                proposta_id=proposta.id,
                usuario=session.get('user'),
                campo_alterado='CRIAÇÃO',
                valor_anterior=None,
                valor_novo='Proposta jurídica criada manualmente'
            )
            db.session.add(historico)
            db.session.commit()

            registrar_acesso('Nova proposta jurídica criada', f'Proposta ID: {proposta.id}, Número: {proposta.numero_processo}')
            flash('Proposta jurídica criada com sucesso!', 'success')
            return redirect(url_for('juridico_bp.propostas'))
        except IntegrityError:
            db.session.rollback()
            flash('Erro de integridade ao criar proposta. Verifique os dados.', 'error')
        except Exception as e:
            db.session.rollback()
            logging.error(f"Erro ao criar proposta jurídica: {e}")
            flash(f'Erro ao criar proposta jurídica: {str(e)}', 'error')

    registrar_acesso('Criação de proposta jurídica acessada')
    return render_template('new_proposta.html')


@juridico_bp.route("/propostas/edit/<int:id>", methods=["GET", "POST"])

@require_permission('juridico_editar_proposta')
def edit_proposta(id):
    proposta = Processos.query.get_or_404(id)

    if proposta.locked_by and proposta.locked_by != session.get("user") and \
       datetime.utcnow() - proposta.locked_at < timedelta(minutes=5):
        flash(f'Esta proposta está sendo editada por {proposta.locked_by}. Tente novamente mais tarde.', 'warning')
        return redirect(url_for('juridico.propostas'))

    if request.method == 'POST':
        try:
            campos_alterados = []
            campos_data = ['data_citacao', 'data_de_pagamento']
            campos_monetarios = ['valor_da_causa', 'risco_economico', 'valor_de_condenacao']

            for campo in request.form:
                if campo.startswith('csrf_token'):
                    continue

                valor_anterior = getattr(proposta, campo)
                valor_bruto = sanitize_input(request.form[campo])

                if campo in campos_data:
                    valor_novo = parse_date_safe(valor_bruto)
                    if not valor_novo and valor_bruto:
                        flash(f'Formato de {campo.replace("_", " ").title()} inválido. Use YYYY-MM-DD.', 'error')
                        return render_template('edit_proposta.html', proposta=proposta)
                elif campo in campos_monetarios:
                    valor_novo = parse_decimal_safe(valor_bruto)
                    if not valor_novo and valor_bruto:
                        flash(f'Formato de {campo.replace("_", " ").title()} inválido.', 'error')
                        return render_template('edit_proposta.html', proposta=proposta)
                else:
                    valor_novo = valor_bruto

                if valor_novo != valor_anterior:
                    registrar_alteracao(proposta.id, session.get('user'), campo, valor_anterior, valor_novo)
                    setattr(proposta, campo, valor_novo)
                    campos_alterados.append(campo)

            proposta.locked_by = None  # Libera o lock após a edição
            proposta.locked_at = None
            db.session.commit()

            if campos_alterados:
                registrar_acesso('Proposta editada', f'Proposta ID: {id}, Campos alterados: {", ".join(campos_alterados)}')

            flash('Proposta atualizada com sucesso!', 'success')
            return redirect(url_for('juridico_bp.propostas'))
        except IntegrityError:
            db.session.rollback()
            flash('Erro de integridade ao editar proposta. Verifique os dados.', 'error')
        except Exception as e:
            db.session.rollback()
            logging.error(f"Erro ao editar proposta jurídica: {e}")
            flash(f'Erro ao editar proposta jurídica: {str(e)}', 'error')

    # Marca lock para edição
    proposta.locked_by = session.get("user")
    proposta.locked_at = datetime.utcnow()
    db.session.commit()

    registrar_acesso('Edição de proposta acessada', f'Proposta ID: {id}')
    return render_template('edit_proposta.html', proposta=proposta)


@juridico_bp.route("/propostas/liberar/<int:id>", methods=["POST"])

def liberar_proposta(id):
    proposta = Processos.query.get_or_404(id)
    if proposta.locked_by == session.get("user"):
        proposta.locked_by = None
        proposta.locked_at = None
        db.session.commit()
    return ("", 204)


@juridico_bp.route("/propostas/delete/<int:id>", methods=["POST"])

@require_permission('deletar_proposta')
def delete_proposta(id):
    try:
        proposta = Processos.query.get_or_404(id)
        numero_processo = proposta.numero_processo or str(proposta.id)

        HistoricoAlteracao.query.filter_by(proposta_id=proposta.id).delete()

        historico = HistoricoAlteracao(
            proposta_id=proposta.id,
            usuario=session.get('user'),
            campo_alterado='EXCLUSÃO',
            valor_anterior=f'Proposta {numero_processo}',
            valor_novo=None
        )
        db.session.add(historico)
        db.session.delete(proposta)
        db.session.commit()

        registrar_acesso('Proposta excluída', f'Proposta ID: {id}, Número: {numero_processo}')
        flash('Proposta excluída com sucesso!', 'success')
    except IntegrityError:
        db.session.rollback()
        flash('Não foi possível excluir a proposta devido a registros relacionados.', 'error')
    except Exception as e:
        db.session.rollback()
        registrar_acesso('Erro ao excluir proposta', f'Erro: {str(e)}')
        flash('Erro ao excluir proposta!', 'error')
        current_app.logger.exception("Erro ao excluir proposta: %s", e)

    return redirect(url_for('juridico_bp.propostas'))


@juridico_bp.route("/propostas/export_excel")

@require_permission('juridico_exportar_dados')
def export_excel():
    status_filter = sanitize_input(request.args.get('status',''))
    operadora_filter = sanitize_input(request.args.get('operadora',''))
    tipo_de_demandas_filter = sanitize_input(request.args.get('tipo_de_demandas',''))
    data_de_pagamento = sanitize_input(request.args.get('data_de_pagamento',''))

    query = Processos.query
    if status_filter:
        query = query.filter(Processos.status.ilike(f'%{status_filter}%'))
    if operadora_filter:
        query = query.filter(Processos.operadora_nome.ilike(f'%{operadora_filter}%'))
    if tipo_de_demandas_filter:
        query = query.filter(Processos.tipo_de_demandas.ilike(f'%{tipo_de_demandas_filter}%'))
    if data_de_pagamento:
        dt = parse_date_safe(data_de_pagamento)
        if dt:
            query = query.filter(Processos.data_de_pagamento == dt)
        else:
            flash('Formato de Data de Pagamento inválido. Use YYYY-MM-DD.', 'error')

    propostas_list = query.all()
    data = []
    for proposta in propostas_list:
        data.append({
            'ID': proposta.id,
            'N.º PROCESSO': proposta.numero_processo,
            'Operadora': proposta.operadora_nome,
            'Vara/Local trámite': proposta.vara_local,
            'Data Citação': proposta.data_citacao,
            'Autor': proposta.autor,
            'Réu': proposta.reu,
            'Tipo de demandas': proposta.tipo_de_demandas,
            'Grupo de causas': proposta.grupo_de_causas,
            'Causa padronizado': proposta.causa_padronizado,
            'Resumo do objeto': proposta.resumo_do_objeto,
            'Último andamento': proposta.ultimo_andamento,
            'Status': proposta.status,
            'Liminar deferida': proposta.liminar_deferida,
            'Valor da causa': proposta.valor_da_causa,
            'Risco econômico': proposta.risco_economico,
            'Valor de condenação': proposta.valor_de_condenacao,
            'Data de pagamento': proposta.data_de_pagamento,
            'Avaliação risco': proposta.avaliacao_de_risco,
            'Observação': proposta.observacao
        })

    df = pd.DataFrame(data)

    filename = f'propostas_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')

    os.makedirs(upload_folder, exist_ok=True)

    filepath = os.path.join(upload_folder, filename)
    df.to_excel(filepath, index=False)

    registrar_acesso('Exportação Excel realizada', f'Arquivo: {filename}, Registros: {len(propostas_list)}')
    return send_file(filepath, as_attachment=True, download_name=filename)

@juridico_bp.route("/logs")

@require_permission('sistema_ver_logs')
def visualizar_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    tipo_log = request.args.get('tipo', 'alteracoes')

    # Valores padrão
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

        logs = query.order_by(LogAcesso.data_hora.desc()).paginate(page=page, per_page=per_page, error_out=False)
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
        if proposta_id_filter:
            query = query.filter(HistoricoAlteracao.proposta_id == proposta_id_filter)

        logs = query.order_by(HistoricoAlteracao.data_alteracao.desc()).paginate(page=page, per_page=per_page, error_out=False)
        template = 'logs_alteracoes.html'

    registrar_acesso('Logs do sistema visualizados', f'Tipo: {tipo_log}')
    return render_template(
        template,
        logs=logs,
        tipo_log=tipo_log,
        usuario_filter=usuario_filter,
        campo_filter=campo_filter,
        proposta_id_filter=proposta_id_filter,
        acao_filter=acao_filter,
        base_template='base_juridico.html'
    )