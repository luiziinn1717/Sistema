import sys
from app import app, db
from models import Usuario, Domain, Permission, Role
from datetime import datetime, timezone

def init_database():
    """Limpa o banco de dados e recria todas as tabelas."""
    with app.app_context():
        print("Iniciando a reinicialização do banco de dados...")
        db.drop_all()
        db.create_all()
        print("✓ Banco de dados resetado e tabelas recriadas com sucesso!")

def seed_data():
    """Popula o banco de dados com dados iniciais (domínios, permissões, roles e usuário admin)."""
    with app.app_context():
        print("\nIniciando a inserção de dados (seeding)...")

        # ===== 1. DOMÍNIOS =====
        dominios = {
            "sistema": "Gerenciamento de usuários, roles e logs do sistema.",
            "juridico": "Módulo de propostas do departamento Jurídico.",
            "cadastro": "Módulo de propostas do departamento de Cadastro.",
            "usuario": "Ações relacionadas ao próprio perfil do usuário."
        }
        for nome, desc in dominios.items():
            domain = Domain.query.filter_by(nome=nome).first()
            if not domain:
                db.session.add(Domain(nome=nome, descricao=desc))
        db.session.commit()
        print("✓ Domínios criados ou já existentes.")

        # ===== 2. PERMISSÕES =====
        permissions_list = [
            'sistema_visualizar_usuarios', 'sistema_criar_usuario', 'sistema_editar_usuario',
            'sistema_deletar_usuario', 'sistema_ativar_desativar_usuario',
            'sistema_ver_logs', 'juridico_visualizar_propostas', 'juridico_criar_proposta', 'juridico_editar_proposta',
            'juridico_deletar_proposta', 'juridico_exportar_dados', 'juridico_upload_planilha',
            'cadastro_visualizar_propostas', 'cadastro_criar_proposta', 'cadastro_editar_proposta',
            'cadastro_deletar_proposta', 'cadastro_exportar_dados', 'cadastro_upload_planilha',
            'usuario_editar_proprio_perfil'
        ]
        for perm_name in permissions_list:
            perm = Permission.query.filter_by(nome=perm_name).first()
            if not perm:
                db.session.add(Permission(nome=perm_name))
        db.session.commit()
        print("✓ Permissões criadas ou já existentes.")

        # ===== 3. ROLES E PERMISSÕES =====
        roles_permissions = {
            "Admin": permissions_list,
            "Analista Juridico": [
                'juridico_visualizar_propostas', 'juridico_criar_proposta', 'juridico_editar_proposta',
                'juridico_deletar_proposta', 'juridico_exportar_dados', 'juridico_upload_planilha',
                'usuario_editar_proprio_perfil'
            ],
            "Analista Cadastro": [
                'cadastro_visualizar_propostas', 'cadastro_criar_proposta', 'cadastro_editar_proposta',
                'cadastro_deletar_proposta', 'cadastro_exportar_dados', 'cadastro_upload_planilha',
                'usuario_editar_proprio_perfil'
            ],
            "Assistente Juridico": [
                'juridico_visualizar_propostas', 'juridico_criar_proposta', 'juridico_editar_proposta',
                'usuario_editar_proprio_perfil'
            ],
            "Assistente Cadastro": [
                'cadastro_visualizar_propostas', 'cadastro_criar_proposta', 'cadastro_editar_proposta',
                'usuario_editar_proprio_perfil', 'cadastro_upload_planilha'
            ]
        }

        for role_name, perms_names in roles_permissions.items():
            role = Role.query.filter_by(nome=role_name).first()
            if not role:
                role = Role(nome=role_name)
                db.session.add(role)
                db.session.commit()
            # Atualiza permissões da Role
            role.permissions = Permission.query.filter(Permission.nome.in_(perms_names)).all()
        db.session.commit()
        print("✓ Roles criadas/atualizadas com permissões.")

        # ===== 4. USUÁRIO ADMIN =====
        admin_user = Usuario.query.filter_by(username="lfsilva").first()
        admin_role = Role.query.filter_by(nome="Admin").first()

        if not admin_user:
            admin_user = Usuario(
                username="lfsilva",
                email="admin@sistema.com",
                nome_completo="Administrador do Sistema",
                cargo="Administrador",
                departamento="TI",
                role=admin_role,
                data_criacao=datetime.now(timezone.utc)
            )
            admin_user.set_password("15k07A")
            db.session.add(admin_user)
            db.session.commit()
            print("✓ Usuário administrador 'lfsilva' criado com sucesso.")
        else:
            # Corrige role caso esteja errada
            if admin_user.role != admin_role:
                admin_user.role = admin_role
                db.session.commit()
                print("✓ Role do usuário admin corrigida para 'Admin'.")
            else:
                print("✓ Usuário administrador 'lfsilva' já existe e está correto.")

        # ===== 5. USUÁRIOS ADICIONAIS =====
        analista_cadastro_role = Role.query.filter_by(nome="Analista Cadastro").first()
        analista_juridico_role = Role.query.filter_by(nome="Analista Juridico").first()

        if not Usuario.query.filter_by(username="analista_cadastro").first():
            analista_cadastro_user = Usuario(
                username="analista_cadastro",
                email="cadastro@sistema.com",
                nome_completo="Analista de Cadastro",
                cargo="Analista",
                departamento="Cadastro",
                role=analista_cadastro_role,
                data_criacao=datetime.now(timezone.utc)
            )
            analista_cadastro_user.set_password("SenhaCadastro!23")
            db.session.add(analista_cadastro_user)
            print("✓ Usuário 'analista_cadastro' criado com sucesso.")

        if not Usuario.query.filter_by(username="analista_juridico").first():
            analista_juridico_user = Usuario(
                username="analista_juridico",
                email="juridico@sistema.com",
                nome_completo="Analista Jurídico",
                cargo="Analista",
                departamento="Jurídico",
                role=analista_juridico_role,
                data_criacao=datetime.now(timezone.utc)
            )
            analista_juridico_user.set_password("SenhaJuridico!23")
            db.session.add(analista_juridico_user)
            print("✓ Usuário 'analista_juridico' criado com sucesso.")
        db.session.commit()

if __name__ == "__main__":
    print("="*42)
    print("===   INICIALIZAÇÃO DO BANCO DE DADOS  ===")
    print("="*42)
    try:
        init_database()
        seed_data()
        print("\n✅ Processo de inicialização concluído com sucesso!")
    except Exception as e:
        print(f"\n❌ Ocorreu um erro durante a inicialização: {e}")
    print("="*42)