# Jedna komenda na laptopie: .\report
# Odczyt NVR i kamer, propozycje Gemini, zapis reports\report.* i wysylka na GitHub.
# Zwykly Windows PowerShell, katalog projektu, bez administratora.
# Nie dodaje ustaw-hasla.ps1.

Set-Location $PSScriptRoot
. .\ustaw-hasla.ps1

git pull --ff-only
if ($LASTEXITCODE -ne 0) {
  Write-Host "git pull nie doszedl. Audyt i tak startuje."
}

$py = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
  $py = "python"
}

& $py -c "import google.genai" 2>$null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Brak pakietu Gemini. Instaluje go raz..."
  & $py -m pip install -e ".[ai]"
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

& $py -m haca audit `
  --config haca.laptop.yaml `
  --devices devices.laptop.yaml `
  --format html,json,md `
  --out reports `
  --basename report `
  --ai
$code = $LASTEXITCODE
if ($code -ne 0 -and $code -ne 3) {
  exit $code
}

$jsonPath = Join-Path $PSScriptRoot "reports\report.json"
$report = Get-Content -Raw -Encoding UTF8 $jsonPath | ConvertFrom-Json
if ($null -eq $report.ai) {
  Write-Host "AI: brak sekcji w raporcie"
} else {
  $proposals = @($report.findings | Where-Object { $_.source -eq "ai_validated" }).Count
  $reason = $report.ai.reason
  if (-not $reason) { $reason = "" }
  Write-Host ("AI: {0} {1}" -f $report.ai.status, $reason)
  if ($report.ai.detail) { Write-Host ("AI detail: {0}" -f $report.ai.detail) }
  Write-Host ("Propozycje AI: {0}" -f $proposals)
  if ($report.ai.summary) {
    Write-Host $report.ai.summary
  }
}

git add -- reports/report.html reports/report.json reports/report.md
git diff --cached --quiet
if ($LASTEXITCODE -eq 0) {
  Write-Host "reports bez zmian"
  exit 0
}
if (-not (git config user.email)) {
  git config user.email "Robert198210@users.noreply.github.com"
  git config user.name "Robert198210"
}
git commit -m "Update live audit report"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
git push
exit $LASTEXITCODE
