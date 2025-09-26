# check_database.py
from app import app, db
from sqlalchemy import inspect

def check_database():
    with app.app_context():
        inspector = inspect(db.engine)
        
        # Check all tables
        tables = inspector.get_table_names()
        print("Tables in database:", tables)
        
        # Check usuario table columns
        if 'usuario' in tables:
            columns = inspector.get_columns('usuario')
            print("\nColumns in usuario table:")
            for col in columns:
                print(f"  - {col['name']} ({str(col['type'])})")
        
        # Check if roles table exists
        if 'roles' in tables:
            columns = inspector.get_columns('roles')
            print("\nColumns in roles table:")
            for col in columns:
                print(f"  - {col['name']} ({str(col['type'])})")

if __name__ == '__main__':
    check_database()