# Zwykły Windows PowerShell, katalog z projektem, bez administratora.
# Podmień XXXXXXX na prawdziwe hasło. Tego pliku potem nie wysyłaj na GitHub
# (repozytorium jest publiczne).
# Uruchomienie w tym samym oknie, w którym potem odpalisz haca:
#   . .\ustaw-hasla.ps1

$env:HACA_CRED_NVR01_USERNAME = "admin"
$env:HACA_CRED_NVR01_PASSWORD = "XXXXXXX"

$env:HACA_CRED_PTZ01_USERNAME = "admin"
$env:HACA_CRED_PTZ01_PASSWORD = "XXXXXXX"

$env:HACA_CRED_CAM01_USERNAME = "admin"
$env:HACA_CRED_CAM01_PASSWORD = "XXXXXXX"
