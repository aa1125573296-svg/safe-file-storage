import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev_change_me")

    MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
    MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
    MYSQL_USER = os.getenv("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
    MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "safefilebox1")

    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", "10485760"))

    ALLOWED_EXTENSIONS = set(
        os.getenv("ALLOWED_EXTENSIONS", "pdf,png,jpg,js,jpeg,docx,txt,css,zip,pcap").split(",")
    )

    VT_API_KEY = os.getenv("VT_API_KEY", "")

    BASE_DIR = os.getcwd()
    STORAGE_ENC = os.path.join(BASE_DIR, "storage", "encrypted")
    STORAGE_TMP = os.path.join(BASE_DIR, "storage", "tmp")
