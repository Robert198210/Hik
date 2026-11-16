# Zwykły Windows PowerShell, katalog projektu, bez administratora.
# Audyt na żywo, zapis do raports\raport.html (nadpisuje) i wysyłka na GitHub.
# Nie dodaje ustaw-hasla.ps1.

Set-Location $PSScriptRoot
. .\ustaw-hasla.ps1

python -m haca audit `
  --config haca.laptop.yaml `
  --devices devices.laptop.yaml `
  --format html,json,md `
  --out raports `
  --basename raport
$code = $LASTEXITCODE
if ($code -ne 0 -and $code -ne 3) {
  exit $code
}

git add -- raports/raport.html raports/raport.json raports/raport.md
git diff --cached --quiet
if ($LASTEXITCODE -eq 0) {
  Write-Host "raports bez zmian"
  exit 0
}
git commit -m "Update live audit report"
git push
exit 0
