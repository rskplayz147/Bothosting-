import schedule
import time
import threading
import sqlite3

class Scheduler:
    def __init__(self):
        self.jobs = {}

    def schedule_task(self, file_id, user_id, schedule_str):
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT filename, filetype FROM files WHERE id = ? AND user_id = ?', (file_id, user_id))
        file = c.fetchone()
        conn.close()
        if not file:
            return {'success': False, 'error': 'File not found'}
        
        try:
            job = schedule.every().day.at(schedule_str).do(self.run_task, file_id, user_id)
            self.jobs[file_id] = job
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def run_task(self, file_id, user_id):
        from process_manager import process_manager
        process_manager.control_file(file_id, 'start', user_id, 'user_bots')

    def start(self):
        def run_schedule():
            while True:
                schedule.run_pending()
                time.sleep(1)
        threading.Thread(target=run_schedule, daemon=True).start()