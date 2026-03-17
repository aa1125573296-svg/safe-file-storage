# 🛡️ SafeFileBox: Advanced Secure Storage & Malware Analysis Platform

## 📖 About the Project
**SafeFileBox** is a Flask-based security ecosystem designed for personal and corporate users to ensure both physical and virtual security of files. This project is not just a “Cloud Storage” solution; it is a defensive platform equipped with an internal **Cyber Threat Intelligence (CTI)** module.

The core mission of the project is to encrypt every byte uploaded by the user and perform an immediate reputation analysis to detect malicious content (malware).

---

## ✨ Key Technical Features

### 1. 🔐 Cryptographic Protection (AES-256)
- **Zero-Knowledge Encryption:** Files are encrypted using AES-256. The encryption key is derived from the user's password and is never stored on the server.
- **Binary Obfuscation:** Files are stored as encrypted `.bin` blobs with UUID filenames. This ensures that even in the event of a server breach, the original file names and contents remain inaccessible.

### 2. 🔍 Malware Analysis & Threat Intelligence
- **VirusTotal API v3:** Real-time SHA-256 hash analysis against 70+ global antivirus engines.
- **YARA Rules Integration:** Performs static analysis to detect suspicious strings and malicious code blocks within the file structure.
- **Automated Risk Scoring:** Files are categorized as `LOW`, `MEDIUM`, `HIGH`, or `UNKNOWN` based on multi-engine detection results.

### 3. 📊 Admin & CTI Dashboard
- **Audit Logs:** Full visibility into user activities including login attempts, file uploads, and deletions, tagged with IP addresses and User-Agent data.
- **Threat Landscape:** Statistical visualization of detected threats and blocked malicious upload attempts.
- **Global File Oversight:** Monitoring the security status of all files stored within the ecosystem.

### 4. 🛡️ System Hardening
- **CSRF Protection:** Secure form handling to prevent Cross-Site Request Forgery.
- **XSS Prevention:** Input sanitization and context-aware escaping via Jinja2.
- **Secure File Handling:** Strict filename sanitization to prevent Path Traversal attacks.

---

## 🛠️ Technology Stack

- **Backend:** Python Flask 3.x
- **Authentication:** Flask-Login
- **Database:** SQLite3
- **Encryption:** PyCryptodome (AES-256)
- **Security Analysis:** YARA, VirusTotal API v3
- **UI Framework:** Bootstrap 5.3 (Responsive Design)

---

## 📂 Project Structure

```text
.
├── app.py                  # Main application logic and routing
├── db.py                   # SQLite database management module
├── config.py               # API keys and secret configurations
├── crypto_utils.py         # AES encryption/decryption functions
├── scan_utils.py           # VirusTotal and YARA scan logic
├── security_utils.py       # Admin decorators and security middleware
├── static/                 # CSS, JavaScript, and assets
├── templates/              # HTML templates (Jinja2)
├── uploads_enc/            # Encrypted file storage (Git-ignored)
└── temp_dec/               # Temporary directory for decrypted downloads
🚀 Installation & Setup
1. System Requirements
Python 3.10 or higher

A VirusTotal API Key (Free or Premium)

2. Step-by-Step Installation
Bash
# 1. Clone the repository
git clone [https://github.com/ravanorucov/safe-file-storage.git](https://github.com/ravanorucov/safe-file-storage.git)
cd safe-file-storage

# 2. Create and activate a virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# 3. Install required packages
pip install -r requirements.txt

# 4. Set the API key (Edit config.py or use .env)
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

# 5. Run the application
python app.py

# 6. Make an existing user an admin
python set_admin.py

### 7. Database Reset (Clean Start)
If you want to clear all users and logs, simply run the reset script:
python reset_database.py
