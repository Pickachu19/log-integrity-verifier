# Log Integrity Monitor for Kali Linux

A **professional, GUI-based Log Integrity Monitoring tool** built using **Python and Tkinter** for Kali Linux.  
This tool monitors critical system logs and user directories in **real time**, detects **unauthorized changes**, and generates **security reports**.

---

## Features

✔ Real-time file system monitoring  
✔ Hash-based integrity verification (SHA-256)  
✔ Monitors critical system logs (`/var/log`)  
✔ Monitors important user directories (Documents, Desktop, Downloads, etc.)  
✔ Detects file creation, modification, and deletion  
✔ Identifies security events such as:
- Failed login attempts
- Authentication failures
- Suspicious sudo usage  
✔ SQLite database for persistent event storage  
✔ Professional Tkinter GUI with color-coded alerts  
✔ Detailed security report generation  
✔ Fully compatible with **Kali Linux**

---

##  Monitored Locations

- `/var/log/` – System & authentication logs  
- `~/Documents`  
- `~/Desktop`  
- `~/Downloads`  
- `~/Pictures`  
- `~/Videos`  
- `/etc/` – Configuration files  
- `/var/www/` – Web server files  

---

##  Requirements

- Kali Linux  
- Python **3.8+**  
- Root privileges (recommended)  

### Python Libraries
- `tkinter`
- `watchdog`
- `sqlite3` (built-in)
- `hashlib` (built-in)

---

##  Installation

### Step 1: Clone or Copy Project
```bash
git clone <your-repository-url>
cd log-integrity-monitor
