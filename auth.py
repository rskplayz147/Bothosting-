import sqlite3
import bcrypt
from datetime import datetime

class AuthManager:
    def __init__(self, db_path):
        self.db_path = db_path

    def hash_password(self, password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password, hashed):
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

    def register(self, username, password, email):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            hashed = self.hash_password(password)
            c.execute('INSERT INTO users (username, password, email, created_at) VALUES (?, ?, ?, ?)',
                      (username, hashed, email, datetime.now().isoformat()))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def login(self, username, password):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT id, username, password, role FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user and self.check_password(password, user[2]):
            return {'id': user[0], 'username': user[1], 'role': user[3]}
        return None

    def set_role(self, user_id, role):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
        conn.commit()
        conn.close()

    def delete_user(self, user_id):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        c.execute('DELETE FROM files WHERE user_id = ?', (user_id,))
        c.execute('DELETE FROM processes WHERE file_id IN (SELECT id FROM files WHERE user_id = ?)', (user_id,))
        conn.commit()
        conn.close()

    def get_all_users(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT id, username, email, role, created_at FROM users')
        users = [{'id': row[0], 'username': row[1], 'email': row[2], 'role': row[3], 'created_at': row[4]} 
                 for row in c.fetchall()]
        conn.close()
        return users