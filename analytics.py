import sqlite3
from datetime import datetime

class AnalyticsManager:
    def __init__(self, db_path):
        self.db_path = db_path

    def log_action(self, user_id, file_id, action, details):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('INSERT INTO analytics (user_id, file_id, action, timestamp, details) VALUES (?, ?, ?, ?, ?)',
                  (user_id, file_id, action, datetime.now().isoformat(), details))
        conn.commit()
        conn.close()

    def get_user_analytics(self, user_id):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT action, timestamp, details FROM analytics WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100',
                  (user_id,))
        analytics = [{'action': row[0], 'timestamp': row[1], 'details': row[2]} for row in c.fetchall()]
        conn.close()
        return analytics