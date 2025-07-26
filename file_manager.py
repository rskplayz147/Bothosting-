import os
import sqlite3
import aiofiles
import zipfile
import json
from werkzeug.utils import secure_filename
from datetime import datetime

class FileManager:
    def __init__(self, upload_folder, allowed_extensions):
        self.upload_folder = upload_folder
        self.allowed_extensions = allowed_extensions

    async def upload_file(self, file, user_id, max_files):
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM files WHERE user_id = ?', (user_id,))
        if c.fetchone()[0] >= max_files:
            conn.close()
            return {'success': False, 'error': f'Max {max_files} files allowed'}
        
        if not file or not self.allowed_file(file.filename):
            conn.close()
            return {'success': False, 'error': 'Invalid file type'}
        
        filename = secure_filename(file.filename)
        filetype = filename.rsplit('.', 1)[1].lower()
        user_folder = os.path.join(self.upload_folder, str(user_id))
        os.makedirs(user_folder, exist_ok=True)
        filepath = os.path.join(user_folder, filename)
        
        async with aiofiles.open(filepath, 'wb') as f:
            await f.write(file.read())
        
        if filetype == 'zip':
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                zip_ref.extractall(user_folder)
            os.remove(filepath)
            extracted_files = [f for f in os.listdir(user_folder) if self.allowed_file(f)]
            for extracted in extracted_files:
                extracted_filetype = extracted.rsplit('.', 1)[1].lower()
                c.execute('INSERT INTO files (user_id, filename, filetype, upload_date, status, locked) VALUES (?, ?, ?, ?, ?, ?)',
                          (user_id, extracted, extracted_filetype, datetime.now().isoformat(), 'stopped', 0))
        else:
            c.execute('INSERT INTO files (user_id, filename, filetype, upload_date, status, locked) VALUES (?, ?, ?, ?, ?, ?)',
                      (user_id, filename, filetype, datetime.now().isoformat(), 'stopped', 0))
        
        conn.commit()
        conn.close()
        return {'success': True, 'filename': filename}

    def delete_file(self, file_id, user_id):
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT filename, locked FROM files WHERE id = ? AND user_id = ?', (file_id, user_id))
        file = c.fetchone()
        if not file:
            conn.close()
            return {'success': False, 'error': 'File not found'}
        if file[1]:
            conn.close()
            return {'success': False, 'error': 'Cannot delete locked file'}
        
        filepath = os.path.join(self.upload_folder, str(user_id), file[0])
        if os.path.exists(filepath):
            os.remove(filepath)
        
        c.execute('DELETE FROM files WHERE id = ?', (file_id,))
        c.execute('DELETE FROM processes WHERE file_id = ?', (file_id,))
        conn.commit()
        conn.close()
        return {'success': True, 'filename': file[0]}

    def get_user_files(self, user_id):
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT id, filename, filetype, status, locked FROM files WHERE user_id = ?', (user_id,))
        files = [{'id': row[0], 'name': row[1], 'type': row[2], 'status': row[3], 'locked': bool(row[4])} 
                 for row in c.fetchall()]
        conn.close()
        return files

    def get_file_info(self, file_id, user_id):
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT filename, settings FROM files WHERE id = ? AND user_id = ?', (file_id, user_id))
        file = c.fetchone()
        conn.close()
        if not file:
            return {'success': False, 'error': 'File not found'}
        settings = json.loads(file[1]) if file[1] else {'env': {}, 'args': []}
        return {'success': True, 'file': {'id': file_id, 'name': file[0], 'settings': settings}}

    def update_settings(self, file_id, user_id, settings):
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT 1 FROM files WHERE id = ? AND user_id = ?', (file_id, user_id))
        if not c.fetchone():
            conn.close()
            return {'success': False, 'error': 'File not found'}
        c.execute('UPDATE files SET settings = ? WHERE id = ?', (json.dumps(settings), file_id))
        conn.commit()
        conn.close()
        return {'success': True}

    def allowed_file(self, filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in self.allowed_extensions