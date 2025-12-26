import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.absolute()

DATABASE_DIR = PROJECT_ROOT / "db"
DATABASE_PATH = DATABASE_DIR / "chain.db"

EVIDENCE_DIR = PROJECT_ROOT / "evidence"
MAX_FILE_SIZE = 100 * 1024 * 1024

REPORTS_DIR = PROJECT_ROOT / "reports"

os.makedirs(DATABASE_DIR, exist_ok=True)
os.makedirs(EVIDENCE_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

STREAMLIT_THEME = "light"
STREAMLIT_LAYOUT = "centered"

APP_VERSION = "1.0.0"
APP_TITLE = "Digital Chain of Custody"
