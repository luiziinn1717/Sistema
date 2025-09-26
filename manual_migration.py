# migrate_db.py
from app import app, db
from models import Usuario, Role, Permission, Domain, role_permissions

def migrate_database():
    with app.app_context():
        try:
            # Add the role_id column to usuario table            db.session.execute(db.text("ALTER TABLE usuario ADD COLUMN role_id INTEGER"))
            db.session.commit()
            print("Added role_id column to usuario table")
            
            # Create the new tables
            db.create_all()
            print("Created new tables (roles, permissions, domains, role_permissions)")
            
            # Create default roles and permissions
            admin_role = Role(nome='Administrador')
            user_role = Role(nome='Usuário')
            
            # Create some domains
            domains = [
                Domain(nome='propostas', descricao='Gerenciamento de propostas'),
                Domain(nome='usuarios', descricao='Gerenciamento de usuários'),
                Domain(nome='logs', descricao='Visualização de logs')
            ]
            
            # Create permissions
            permissions = [
                Permission(nome='criar', dominio_id=1),
                Permission(nome='editar', dominio_id=1),
                Permission(nome='deletar', dominio_id=1),
                Permission(nome='visualizar', dominio_id=1),
                Permission(nome='criar', dominio_id=2),
                Permission(nome='editar', dominio_id=2),
                Permission(nome='deletar', dominio_id=2),
                Permission(nome='visualizar', dominio_id=2),
                Permission(nome='visualizar', dominio_id=3)
            ]
            
            db.session.add_all([admin_role, user_role] + domains + permissions)
            db.session.commit()
            
            # Assign all permissions to admin role
            for perm in permissions:
                db.session.execute(
                    role_permissions.insert().values(role_id=admin_role.id, permission_id=perm.id)
                )
            
            # Assign basic permissions to user role
            basic_perms = [1, 2, 4, 8, 9]  # IDs of basic permissions
            for perm_id in basic_perms:
                db.session.execute(
                    role_permissions.insert().values(role_id=user_role.id, permission_id=perm_id)
                )
            
            # Set admin role for existing users (or default to user role)
            usuarios = Usuario.query.all()
            for usuario in usuarios:
                usuario.role_id = admin_role.id if usuario.username == 'admin' else user_role.id

            
            db.session.commit()

            # Create a default admin user if not exists
            if not Usuario.query.filter_by(username='admin').first():
                admin_user = Usuario(username='admin', email='admin@example.com', nome_completo='Administrador', role_id=admin_role.id)
                admin_user.set_password('admin')
                db.session.add(admin_user)
                db.session.commit()
                print('Created default admin user.')
            
            print("Migration completed successfully!")            
        except Exception as e:
            db.session.rollback()
            print(f"Migration error: {e}")
            raise

if __name__ == '__main__':
    migrate_database()

