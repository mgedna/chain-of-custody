# 🚀 Quick Start Guide

## First Time Setup

### Windows
```powershell
cd chain_of_custody
.\setup.ps1
```

### Linux/macOS
```bash
cd chain_of_custody
chmod +x setup.sh
./setup.sh
source .venv/bin/activate
```

---

## Start Application

### Windows
```powershell
.\.venv\Scripts\Activate.ps1
streamlit run app.py
```

### Linux/macOS
```bash
source .venv/bin/activate
streamlit run app.py
```

Opens at: **http://localhost:8501**

---

## Demo: Tampering Detection

```bash
python demo_alteration.py
```

Shows:
- ✓ Evidence added with hash
- ✓ Transfer 1 → VALID
- 🚨 File secretly modified
- ✗ Transfer 2 → ALTERED
- 📊 Report with tamper detection

---

## Project Structure

```
chain_of_custody/
├── app.py                    # Streamlit UI
├── demo_alteration.py        # Tampering demo
├── config.py                 # Configuration
├── README.md                 # Full documentation
├── requirements.txt          # Dependencies
├── setup.ps1 / setup.sh      # Setup scripts
│
├── core/
│   ├── database.py          # SQL operations
│   ├── custody.py           # Business logic
│   ├── hashing.py           # Cryptography
│   ├── storage.py           # File storage
│   ├── audit.py             # Audit logging
│   └── report.py            # Reports
│
├── db/                       # Database (auto-created)
├── evidence/                 # Evidence storage (auto-created)
└── reports/                  # Report exports (auto-created)
```

---

## Features

### 5 Tabs in App

1. **Add Evidence** 📁
   - Upload files
   - System creates secure copy
   - Shows SHA-256 hash

2. **Custody Transfer** 🔄
   - Add custodians
   - Transfer evidence between users
   - Automatic integrity check

3. **Integrity Check** ✅
   - Upload file to verify
   - Compare with original hash
   - Detect tampering

4. **Report** 📊
   - View transfer history
   - Download as TXT or PDF
   - Shows status (✓ VALID / ✗ ALTERED)

5. **Audit Log** 📝
   - All system actions logged
   - Filter by status
   - Expandable details

---

## Database

**Auto-created on first run:** `db/chain.db`

Tables:
- `probes` - Digital evidence
- `users` - Custodians
- `transfers` - Transfer history
- `audit_log` - System audit trail

---

## Common Issues

### "Port already in use"
```bash
streamlit run app.py --server.port 8502
```

### "Database locked"
1. Close Streamlit app
2. Delete `db/chain.db`
3. Restart

### Python not found
- Install Python 3.11+
- Ensure it's in PATH

---

## File Locations

- **Database**: `db/chain.db`
- **Evidence**: `evidence/probe_*.ext`
- **Reports**: `reports/chain_of_custody_*.pdf`
- **Config**: `config.py`

---

## Support

📖 **Full Documentation**: See `README.md`
🐛 **Issues**: Check terminal output and `db/` directory
📊 **Demo**: Run `python demo_alteration.py`

---

Made with 🔒 for forensic integrity
