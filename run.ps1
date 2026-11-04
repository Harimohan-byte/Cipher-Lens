# Safe Localhost Launcher for Cipher-Lens Dashboard
# Binds strictly to 127.0.0.1:8501 to prevent subnet exposure (ERR-01)
Write-Host "Starting Cipher-Lens on http://127.0.0.1:8501..." -ForegroundColor Cyan
.venv\Scripts\streamlit run src/cipher_lens/ui/app.py --server.address 127.0.0.1 --server.port 8501

