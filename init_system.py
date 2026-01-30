import json
import os
from database import init_db, SessionLocal, Rule, User, SystemMetadata
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def migrate_rules():
    db = SessionLocal()
    if db.query(Rule).first():
        print("Rules already migrated.")
        db.close()
        return

    rules_path = 'rules.json'
    if os.path.exists(rules_path):
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules_data = json.load(f)
            for key, details in rules_data.items():
                rule = Rule(
                    rule_key=key,
                    pattern=details['pattern'],
                    severity=details['severity'],
                    category=details.get('category', 'n/a'),
                    description=details.get('description', ''),
                    is_active=True
                )
                db.add(rule)
        meta = SystemMetadata(key="rules_version", value="1")
        db.add(meta)
        
        db.commit()
        print(f"{len(rules_data)} rules migrated to database.")
    db.close()

def create_admin():
    db = SessionLocal()
    if db.query(User).filter(User.username == "admin").first():
        print("Admin user already exists.")
        db.close()
        return

    hashed_password = pwd_context.hash("admin123")
    admin = User(username="admin", password_hash=hashed_password)
    db.add(admin)
    db.commit()
    print("Admin user created (admin / admin123).")
    db.close()

if __name__ == "__main__":
    init_db()
    migrate_rules()
    create_admin()
