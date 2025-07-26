import subprocess
import threading
import psutil
import os
import sqlite3
import json
import logging
from datetime import datetime

class ProcessManager:
    def __init__(self):
        self.running_processes = {}
        self.process_logs = {}
        self.process_locks = {}

    def control_file(self, file_id, action, user_id, upload_folder):
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT filename, filetype, locked, settings FROM files WHERE id = ? AND user_id = ?', 
                  (file_id, user_id))
        file = c.fetchone()
        if not file:
            conn.close()
            return {'success': False, 'error': 'File not found'}
        
        filename, filetype, locked, settings = file
        if locked and action not in ['unlock', 'stop']:
            conn.close()
            return {'success': False, 'error': 'File is locked'}
        
        filepath = os.path.join(upload_folder, str(user_id), filename)
        
        if action == 'start':
            if file_id in self.running_processes and self.running_processes[file_id].poll() is None:
                conn.close()
                return {'success': False, 'error': 'File is already running'}
            try:
                cmd = ['python', filepath] if filetype == 'py' else ['node', filepath]
                env = os.environ.copy()
                if settings:
                    settings_dict = json.loads(settings)
                    env.update(settings_dict.get('env', {}))
                    cmd.extend(settings_dict.get('args', []))
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    env=env
                )
                self.running_processes[file_id] = process
                self.process_logs[file_id] = []
                self.process_locks[file_id] = threading.Lock()
                
                threading.Thread(target=self.collect_logs, args=(file_id, process)).start()
                threading.Thread(target=self.monitor_process, args=(file_id, process, filepath, filetype)).start()
                
                c.execute('INSERT INTO processes (file_id, pid, start_time, last_checked) VALUES (?, ?, ?, ?)',
                          (file_id, process.pid, datetime.now().isoformat(), datetime.now().isoformat()))
                c.execute('UPDATE files SET status = ? WHERE id = ?', ('running', file_id))
                conn.commit()
                conn.close()
                return {'success': True, 'message': 'Script started successfully'}
            except Exception as e:
                conn.close()
                return {'success': False, 'error': f'Error starting script: {str(e)}'}

        elif action == 'stop':
            if file_id not in self.running_processes:
                conn.close()
                return {'success': False, 'error': 'Script is not running'}
            
            with self.process_locks.get(file_id, threading.Lock()):
                process = self.running_processes[file_id]
                try:
                    parent = psutil.Process(process.pid)
                    for child in parent.children(recursive=True):
                        child.terminate()
                    parent.terminate()
                    process.wait(timeout=5)
                except psutil.NoSuchProcess:
                    pass
                except Exception as e:
                    logging.error(f"Error stopping file_id {file_id}: {str(e)}")
                
                del self.running_processes[file_id]
                if file_id in self.process_logs:
                    del self.process_logs[file_id]
                if file_id in self.process_locks:
                    del self.process_locks[file_id]
                
                c.execute('DELETE FROM processes WHERE file_id = ?', (file_id,))
                c.execute('UPDATE files SET status = ? WHERE id = ?', ('stopped', file_id))
                conn.commit()
                conn.close()
                return {'success': True, 'message': 'Script stopped successfully'}

        elif action == 'restart':
            self.control_file(file_id, 'stop', user_id, upload_folder)
            import time
            time.sleep(1)
            return self.control_file(file_id, 'start', user_id, upload_folder)

        elif action == 'lock':
            c.execute('UPDATE files SET locked = 1 WHERE id = ?', (file_id,))
            conn.commit()
            conn.close()
            return {'success': True, 'message': 'File locked successfully'}

        elif action == 'unlock':
            c.execute('UPDATE files SET locked = 0 WHERE id = ?', (file_id,))
            conn.commit()
            conn.close()
            return {'success': True, 'message': 'File unlocked successfully'}

        conn.close()
        return {'success': False, 'error': 'Invalid action'}

    def collect_logs(self, file_id, process):
        self.process_logs[file_id] = []
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                self.process_logs[file_id].append(output.strip())
                logging.info(f"Log for file_id {file_id}: {output.strip()}")

    def monitor_process(self, file_id, process, filepath, filetype):
        while True:
            if process.poll() is not None:
                logging.warning(f"Process {file_id} crashed with code {process.poll()}. Restarting...")
                try:
                    cmd = ['python', filepath] if filetype == 'py' else ['node', filepath]
                    new_process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True
                    )
                    self.running_processes[file_id] = new_process
                    threading.Thread(target=self.collect_logs, args=(file_id, new_process)).start()
                    self.update_process_status(file_id, 'running')
                except Exception as e:
                    logging.error(f"Failed to restart process {file_id}: {str(e)}")
                    self.update_process_status(file_id, f'error: {str(e)}')
                    break
            try:
                p = psutil.Process(process.pid)
                cpu_usage = p.cpu_percent(interval=1)
                memory_usage = p.memory_info().rss / 1024 / 1024  # MB
                conn = sqlite3.connect('bot_data.db')
                c = conn.cursor()
                c.execute('UPDATE processes SET cpu_usage = ?, memory_usage = ?, last_checked = ? WHERE file_id = ?',
                          (cpu_usage, memory_usage, datetime.now().isoformat(), file_id))
                conn.commit()
                conn.close()
            except psutil.NoSuchProcess:
                break
            time.sleep(5)

    def update_process_status(self, file_id, status):
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('UPDATE files SET status = ? WHERE id = ?', (status, file_id))
        c.execute('UPDATE processes SET last_checked = ? WHERE file_id = ?',
                  (datetime.now().isoformat(), file_id))
        conn.commit()
        conn.close()

    def get_logs(self, file_id, user_id):
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT 1 FROM files WHERE id = ? AND user_id = ?', (file_id, user_id))
        if not c.fetchone():
            conn.close()
            return {'error': 'Access denied'}
        conn.close()
        return self.process_logs.get(file_id, [])[-100:]

    def get_status(self, file_id, user_id):
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT status FROM files WHERE id = ? AND user_id = ?', (file_id, user_id))
        status = c.fetchone()
        conn.close()
        if not status:
            return {'error': 'File not found'}
        return {'status': status[0]}

    def restore_processes(self, upload_folder):
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT file_id, filename, filetype, user_id FROM files WHERE status = ?', ('running',))
        running_files = c.fetchall()
        
        for file_id, filename, filetype, user_id in running_files:
            filepath = os.path.join(upload_folder, str(user_id), filename)
            try:
                cmd = ['python', filepath] if filetype == 'py' else ['node', filepath]
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                self.running_processes[file_id] = process
                self.process_logs[file_id] = []
                self.process_locks[file_id] = threading.Lock()
                threading.Thread(target=self.collect_logs, args=(file_id, process)).start()
                threading.Thread(target=self.monitor_process, args=(file_id, process, filepath, filetype)).start()
                logging.info(f"Restored process for file_id {file_id}")
            except Exception as e:
                logging.error(f"Failed to restore process for file_id {file_id}: {str(e)}")
        conn.close()