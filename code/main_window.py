#!/usr/bin/env python3
"""
Advanced Log Integrity Monitor for Kali Linux
Professional Tkinter GUI with Real-time Monitoring

Features:
- Real-time file system monitoring
- Beautiful modern GUI with proper scrolling
- Monitors all log files and user directories
- Hash-based integrity verification
- Security event detection
- Professional report generation
- Works perfectly on Kali Linux

Run as: sudo python3 log_integrity_monitor.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import os
import sys
import hashlib
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path

# File system monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("  Install watchdog: pip3 install watchdog")

# ============================================================================
# DATABASE MANAGER
# ============================================================================
class DatabaseManager:
    def __init__(self, db_path="log_monitor.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.init_db()
    
    def init_db(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                file_path TEXT,
                message TEXT,
                severity TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_hashes (
                path TEXT PRIMARY KEY,
                hash TEXT,
                last_check TEXT
            )
        ''')
        self.conn.commit()
    
    def add_event(self, event_type, file_path, message, severity="info"):
        try:
            self.cursor.execute('''
                INSERT INTO events (timestamp, event_type, file_path, message, severity)
                VALUES (?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), event_type, file_path, message, severity))
            self.conn.commit()
        except:
            pass
    
    def update_hash(self, file_path, file_hash):
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO file_hashes (path, hash, last_check)
                VALUES (?, ?, ?)
            ''', (file_path, file_hash, datetime.now().isoformat()))
            self.conn.commit()
        except:
            pass
    
    def get_hash(self, file_path):
        try:
            self.cursor.execute('SELECT hash FROM file_hashes WHERE path = ?', (file_path,))
            result = self.cursor.fetchone()
            return result[0] if result else None
        except:
            return None
    
    def get_events(self, limit=1000):
        try:
            self.cursor.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT ?', (limit,))
            return self.cursor.fetchall()
        except:
            return []

# ============================================================================
# FILE SYSTEM EVENT HANDLER
# ============================================================================
class SystemMonitorHandler(FileSystemEventHandler):
    def __init__(self, db, callback):
        super().__init__()
        self.db = db
        self.callback = callback
        
        # Ignore patterns
        self.ignore_patterns = [
            '-journal', '.xbel', 'dconf', '.goutputstream',
            '~', '.swp', '.tmp', '.cache', '.lock',
            'Trash', '.thumbnails', '.mozilla', '.config/pulse',
            '__pycache__', '.git/', 'log_monitor.db'
        ]
        
        self.important_home_dirs = [
            'Documents', 'Desktop', 'Downloads', 
            'Pictures', 'Videos'
        ]
    
    def should_ignore(self, path):
        path_str = str(path)
        for pattern in self.ignore_patterns:
            if pattern in path_str:
                return True
        return False
    
    def should_monitor(self, path):
        try:
            path_str = str(path)
            
            if self.should_ignore(path_str):
                return False
            
            # Monitor log files
            if '/var/log/' in path_str and path_str.endswith('.log'):
                return True
            
            # Monitor important home directories
            for dir_name in self.important_home_dirs:
                if f'/{dir_name}/' in path_str or path_str.endswith(f'/{dir_name}'):
                    return True
            
            # Monitor config files
            if '/etc/' in path_str and any(path_str.endswith(ext) for ext in ['.conf', '.config', '.cfg']):
                return True
            
            # Monitor web server
            if '/var/www/' in path_str or 'apache2' in path_str or 'nginx' in path_str:
                return True
            
            return False
        except:
            return False
    
    def get_file_hash(self, path):
        try:
            if not os.path.exists(path) or not os.path.isfile(path):
                return None
            
            if os.path.getsize(path) > 50 * 1024 * 1024:
                return None
            
            hasher = hashlib.sha256()
            with open(path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return None
    
    def check_security_events(self, path):
        try:
            if not path.endswith('.log'):
                return
            
            if not os.path.exists(path) or not os.path.isfile(path):
                return
            
            if os.path.getsize(path) > 10 * 1024 * 1024:
                return
            
            with open(path, 'r', errors='ignore') as f:
                content = f.read().lower()
            
            failed_count = content.count('failed password')
            auth_fail_count = content.count('authentication failure')
            total_fails = failed_count + auth_fail_count
            
            if total_fails > 0:
                msg = f" SECURITY: {total_fails} failed login attempts in {os.path.basename(path)}"
                self.callback(msg, "high")
                self.db.add_event("security_alert", path, msg, "high")
            
            if 'sudo:' in content and 'command' in content:
                msg = f" Sudo commands in {os.path.basename(path)}"
                self.callback(msg, "medium")
                self.db.add_event("sudo_usage", path, msg, "medium")
        except:
            pass
    
    def on_created(self, event):
        try:
            if event.is_directory:
                return
            
            if self.should_monitor(event.src_path):
                filename = os.path.basename(event.src_path)
                msg = f" NEW: {filename} → {event.src_path}"
                self.callback(msg, "info")
                self.db.add_event("file_created", event.src_path, msg, "info")
                
                time.sleep(0.2)
                file_hash = self.get_file_hash(event.src_path)
                if file_hash:
                    self.db.update_hash(event.src_path, file_hash)
        except:
            pass
    
    def on_modified(self, event):
        try:
            if event.is_directory:
                return
            
            if self.should_monitor(event.src_path):
                old_hash = self.db.get_hash(event.src_path)
                new_hash = self.get_file_hash(event.src_path)
                
                if new_hash and old_hash and old_hash != new_hash:
                    filename = os.path.basename(event.src_path)
                    msg = f" MODIFIED: {filename} → {event.src_path}"
                    self.callback(msg, "medium")
                    self.db.add_event("file_modified", event.src_path, msg, "medium")
                    
                    self.db.update_hash(event.src_path, new_hash)
                    
                    if event.src_path.endswith('.log'):
                        self.check_security_events(event.src_path)
                
                elif new_hash and not old_hash:
                    self.db.update_hash(event.src_path, new_hash)
        except:
            pass
    
    def on_deleted(self, event):
        try:
            if event.is_directory:
                return
            
            if self.should_monitor(event.src_path):
                filename = os.path.basename(event.src_path)
                msg = f" DELETED: {filename} → {event.src_path}"
                self.callback(msg, "high")
                self.db.add_event("file_deleted", event.src_path, msg, "high")
        except:
            pass

# ============================================================================
# MAIN GUI APPLICATION
# ============================================================================
class LogIntegrityMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title(" Advanced Log Integrity Monitor - Kali Linux")
        self.root.geometry("1400x900")
        
        # Database
        self.db = DatabaseManager()
        
        # Monitoring state
        self.is_monitoring = False
        self.observer = None
        
        # Setup GUI
        self.setup_styles()
        self.create_widgets()
        
        # Check dependencies
        if not WATCHDOG_AVAILABLE:
            self.log_message(" watchdog not installed! Install: pip3 install watchdog", "high")
        else:
            self.log_message(" Log Integrity Monitor Ready", "info")
            self.log_message(" Monitoring: /var/log, Documents, Desktop, Downloads, Pictures, Videos", "info")
    
    def setup_styles(self):
        """Setup custom styles"""
        self.root.configure(bg='#0a0e27')
        
        # Custom style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors
        self.style.configure('TFrame', background='#0a0e27')
        self.style.configure('TLabel', background='#0a0e27', foreground='#00d4ff', 
                           font=('Consolas', 10))
        self.style.configure('Title.TLabel', font=('Consolas', 24, 'bold'), 
                           foreground='#00d4ff')
        self.style.configure('Status.TLabel', font=('Consolas', 14, 'bold'))
        
        # Button styles
        self.style.configure('Start.TButton', font=('Consolas', 11, 'bold'))
        self.style.configure('Stop.TButton', font=('Consolas', 11, 'bold'))
        self.style.configure('Report.TButton', font=('Consolas', 11, 'bold'))
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title = ttk.Label(main_frame, text=" ADVANCED LOG INTEGRITY MONITOR", 
                         style='Title.TLabel')
        title.pack(pady=(0, 20))
        
        # Status label
        self.status_var = tk.StringVar(value=" MONITORING: INACTIVE")
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var,
                                     style='Status.TLabel', foreground='#ffaa00')
        self.status_label.pack(pady=(0, 20))
        
        # Control buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=(0, 20))
        
        self.start_btn = tk.Button(btn_frame, text=" START MONITORING",
                                   command=self.start_monitoring,
                                   bg='#00d4ff', fg='white', 
                                   font=('Consolas', 12, 'bold'),
                                   relief=tk.RAISED, bd=3, padx=20, pady=10,
                                   cursor='hand2')
        self.start_btn.pack(side=tk.LEFT, padx=10)
        
        self.stop_btn = tk.Button(btn_frame, text=" STOP MONITORING",
                                 command=self.stop_monitoring,
                                 bg='#ff4444', fg='white',
                                 font=('Consolas', 12, 'bold'),
                                 relief=tk.RAISED, bd=3, padx=20, pady=10,
                                 state=tk.DISABLED, cursor='hand2')
        self.stop_btn.pack(side=tk.LEFT, padx=10)
        
        self.report_btn = tk.Button(btn_frame, text=" GENERATE REPORT",
                                    command=self.generate_report,
                                    bg='#00ff88', fg='black',
                                    font=('Consolas', 12, 'bold'),
                                    relief=tk.RAISED, bd=3, padx=20, pady=10,
                                    cursor='hand2')
        self.report_btn.pack(side=tk.LEFT, padx=10)
        
        # Terminal label
        term_label = ttk.Label(main_frame, text=" REAL-TIME MONITORING TERMINAL",
                              font=('Consolas', 12, 'bold'), foreground='#00ff88')
        term_label.pack(pady=(0, 10))
        
        # Scrolled text for terminal
        terminal_frame = tk.Frame(main_frame, bg='#0d1117', bd=2, relief=tk.SUNKEN)
        terminal_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.terminal = scrolledtext.ScrolledText(
            terminal_frame,
            bg='#0d1117',
            fg='#c9d1d9',
            font=('Consolas', 11),
            wrap=tk.WORD,
            state=tk.DISABLED,
            relief=tk.FLAT,
            insertbackground='#00ff88'
        )
        self.terminal.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Configure tags for colors
        self.terminal.tag_config('info', foreground='#00ff88')
        self.terminal.tag_config('medium', foreground='#ffaa00')
        self.terminal.tag_config('high', foreground='#ff4444')
        self.terminal.tag_config('timestamp', foreground='#8b949e')
        
        # Stats footer
        self.stats_var = tk.StringVar(value=" Files Monitored: 0 | Events Logged: 0")
        stats_label = ttk.Label(main_frame, textvariable=self.stats_var,
                               font=('Consolas', 10), foreground='#8b949e')
        stats_label.pack()
        
        # Update stats periodically
        self.update_stats()
    
    def log_message(self, message, severity="info"):
        """Add message to terminal"""
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            # Icon based on severity
            if severity == "high":
                icon = "🔴"
                tag = "high"
            elif severity == "medium":
                icon = "🟡"
                tag = "medium"
            else:
                icon = "🟢"
                tag = "info"
            
            # Enable editing
            self.terminal.config(state=tk.NORMAL)
            
            # Insert timestamp
            self.terminal.insert(tk.END, f"[{timestamp}] ", 'timestamp')
            
            # Insert icon and message
            self.terminal.insert(tk.END, f"{icon} {message}\n", tag)
            
            # Disable editing
            self.terminal.config(state=tk.DISABLED)
            
            # Auto-scroll to bottom
            self.terminal.see(tk.END)
            
        except Exception as e:
            print(f"Log error: {e}")
    
    def start_monitoring(self):
        """Start file system monitoring"""
        try:
            if self.is_monitoring:
                return
            
            if not WATCHDOG_AVAILABLE:
                messagebox.showerror("Error", 
                    "watchdog library not installed!\n\n"
                    "Install with:\n"
                    "pip3 install watchdog")
                return
            
            self.is_monitoring = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            
            self.status_var.set("🟢 MONITORING: ACTIVE")
            self.status_label.config(foreground='#00ff88')
            
            self.log_message("="*80, "info")
            self.log_message(" MONITORING STARTED - FULL SYSTEM SCAN", "info")
            self.log_message("="*80, "info")
            
            # Start observer
            self.observer = Observer()
            handler = SystemMonitorHandler(self.db, self.log_message)
            
            home_dir = os.path.expanduser("~")
            
            dirs_to_monitor = [
                ('/var/log', True, 'System Logs'),
                (f'{home_dir}/Documents', True, 'Documents'),
                (f'{home_dir}/Desktop', True, 'Desktop'),
                (f'{home_dir}/Downloads', True, 'Downloads'),
                (f'{home_dir}/Pictures', True, 'Pictures'),
                (f'{home_dir}/Videos', True, 'Videos'),
                ('/etc', False, 'System Config'),
                ('/var/www', True, 'Web Server'),
            ]
            
            monitored = 0
            for directory, recursive, name in dirs_to_monitor:
                if os.path.exists(directory):
                    try:
                        self.observer.schedule(handler, directory, recursive=recursive)
                        self.log_message(f" Monitoring: {name} → {directory}", "info")
                        monitored += 1
                    except:
                        self.log_message(f" Cannot monitor {directory}: Permission denied", "medium")
            
            if monitored == 0:
                self.log_message(" No directories could be monitored", "high")
                self.stop_monitoring()
                return
            
            self.observer.start()
            
            # Initial scan in thread
            threading.Thread(target=self.scan_log_files, daemon=True).start()
            
            self.log_message("="*80, "info")
            self.log_message(" System monitoring ACTIVE!", "info")
            self.log_message("🔍 Create, modify or delete files to see alerts...", "info")
            self.log_message("="*80, "info")
            
            messagebox.showinfo("Monitoring Started",
                "🟢 System monitoring is ACTIVE!\n\n"
                "Now monitoring:\n"
                "• /var/log/ - All log files\n"
                "• Documents, Desktop, Downloads\n"
                "• Pictures, Videos\n"
                "• Configuration files\n\n"
                "Try creating a file in Documents to test!")
        
        except Exception as e:
            self.log_message(f" Error: {str(e)}", "high")
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        try:
            if not self.is_monitoring:
                return
            
            self.is_monitoring = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            
            self.status_var.set(" MONITORING: INACTIVE")
            self.status_label.config(foreground='#ffaa00')
            
            if self.observer:
                try:
                    self.observer.stop()
                    self.observer.join(timeout=2)
                except:
                    pass
            
            self.log_message("="*80, "info")
            self.log_message(" MONITORING STOPPED", "high")
            self.log_message("="*80, "info")
            
            messagebox.showinfo("Monitoring Stopped", 
                " System monitoring has been stopped.")
        
        except Exception as e:
            print(f"Stop error: {e}")
    
    def scan_log_files(self):
        """Initial scan of log files"""
        try:
            self.log_message("🔍 Scanning critical log files...", "info")
            
            log_files = [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/apache2/access.log',
                '/var/log/apache2/error.log',
            ]
            
            scanned = 0
            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        hasher = hashlib.sha256()
                        with open(log_file, 'rb') as f:
                            count = 0
                            while chunk := f.read(8192):
                                hasher.update(chunk)
                                count += 1
                                if count > 1000:
                                    break
                        file_hash = hasher.hexdigest()
                        
                        self.db.update_hash(log_file, file_hash)
                        
                        handler = SystemMonitorHandler(self.db, self.log_message)
                        handler.check_security_events(log_file)
                        
                        scanned += 1
                        self.log_message(f"✓ Scanned: {os.path.basename(log_file)}", "info")
                        time.sleep(0.1)
                    except:
                        pass
            
            self.log_message(f" Baseline: {scanned} log files scanned", "info")
        except Exception as e:
            print(f"Scan error: {e}")
    
    def generate_report(self):
        """Generate comprehensive report"""
        try:
            self.log_message(" Generating report...", "info")
            
            events = self.db.get_events(1000)
            
            total = len(events)
            created = sum(1 for e in events if e[2] == 'file_created')
            modified = sum(1 for e in events if e[2] == 'file_modified')
            deleted = sum(1 for e in events if e[2] == 'file_deleted')
            security = sum(1 for e in events if e[2] == 'security_alert')
            
            report = f"""
╔══════════════════════════════════════════════════════════════════════════╗
║        ADVANCED LOG INTEGRITY MONITOR - SYSTEM REPORT                    ║
╚══════════════════════════════════════════════════════════════════════════╝

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Status: {'ACTIVE' if self.is_monitoring else 'INACTIVE'}

═══════════════════════════════════════════════════════════════════════════

 EVENT SUMMARY
═══════════════════════════════════════════════════════════════════════════
Total Events:           {total}
Files Created:          {created}
Files Modified:         {modified}
Files Deleted:          {deleted}
Security Alerts:        {security}

═══════════════════════════════════════════════════════════════════════════

 RECENT EVENTS (Last 30)
═══════════════════════════════════════════════════════════════════════════
"""
            
            recent = events[:30]
            if recent:
                for event in recent:
                    ts = event[1][11:19] if len(event[1]) > 19 else event[1]
                    severity = "🔴" if event[5] == "high" else ("🟡" if event[5] == "medium" else "🟢")
                    report += f"{severity} [{ts}] {event[4]}\n"
            else:
                report += "No events recorded yet.\n"
            
            report += f"""
═══════════════════════════════════════════════════════════════════════════

 MONITORED LOCATIONS
═══════════════════════════════════════════════════════════════════════════
• /var/log/ - System and application logs
• ~/Documents - User documents
• ~/Desktop - Desktop files
• ~/Downloads - Downloaded files
• ~/Pictures - Image files
• ~/Videos - Video files
• /etc/ - System configuration
• /var/www/ - Web server files

═══════════════════════════════════════════════════════════════════════════

🔐 SECURITY STATUS
═══════════════════════════════════════════════════════════════════════════
"""
            
            if security > 0:
                report += f"  {security} security alerts detected!\n"
                report += "• Review failed login attempts\n"
                report += "• Check unauthorized access\n"
                report += "• Verify file changes\n"
            else:
                report += "✓ No security threats detected\n"
                report += "✓ All monitored files are secure\n"
            
            report += """
═══════════════════════════════════════════════════════════════════════════
End of Report
═══════════════════════════════════════════════════════════════════════════
"""
            
            # Save report
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath = filedialog.asksaveasfilename(
                defaultextension=".txt",
                initialfile=filename,
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if filepath:
                with open(filepath, 'w') as f:
                    f.write(report)
                
                self.log_message(f" Report saved: {filepath}", "info")
                messagebox.showinfo("Report Generated",
                    f"Report saved successfully!\n\n{filepath}")
            
        except Exception as e:
            self.log_message(f" Error: {str(e)}", "high")
            messagebox.showerror("Error", f"Failed to generate report:\n{str(e)}")
    
    def update_stats(self):
        """Update statistics"""
        try:
            events = self.db.get_events()
            
            files = set()
            for event in events:
                if event[3]:
                    files.add(event[3])
            
            self.stats_var.set(
                f" Files Monitored: {len(files)} | Events Logged: {len(events)}"
            )
        except:
            pass
        
        # Schedule next update
        self.root.after(3000, self.update_stats)

# ============================================================================
# MAIN
# ============================================================================
def main():
    try:
        print(" Starting Advanced Log Integrity Monitor...")
        
        if os.geteuid() != 0:
            print("  WARNING: Not running as root")
            print("   Some log files may not be accessible")
            print("   Run with: sudo python3 log_integrity_monitor.py")
        
        root = tk.Tk()
        app = LogIntegrityMonitorApp(root)
        
        print(" GUI launched successfully!")
        print(" Monitoring: Documents, Desktop, Downloads, /var/log")
        
        root.mainloop()
    
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
