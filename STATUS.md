# HACA — bieżący stan

Last updated: 2026-11-17

Nowy czat: przeczytaj ten plik zanim cokolwiek zmienisz. Na końcu sesji, jeśli stan się zmienił, zaktualizuj ten plik (data, commity, raport, otwarte sprawy). Nie wpisuj haseł.

## Gdzie

- Repo: `/var/fpwork/ambrosew/skrypty/HIK/haca`
- GitHub: `https://github.com/Robert198210/Hik.git` (`origin/main`)
- Laptop: `C:\programy\hik`, jedna komenda `.\report` (sam robi `git pull` i uruchamia się ponownie z dysku)
- Przed opisem kodu: `git fetch origin main`. Lokalny `HEAD` bywa za GitHubem.

## Zasady

- Tylko odczyt. Program nie zapisuje ustawień i nie restartuje NVR.
- Nie otwieraj `/var/fpwork/ambrosew/skrypty/Hikvision/**`.
- Nie uruchamiaj ponownie QA Phase 3.
- Hasła tylko w `ustaw-hasla.ps1` na laptopie. Nie commituj tego pliku ze zmienionym hasłem.
- Pisz do użytkownika po polsku.

## Kod i konfiguracja

- Ostatni kod na `origin/main`: `c4901ca` (CMR od północy do północy następnego dnia liczy się jako pełny dzień).
- Ostatni raport na GitHubie: `dfab218` (2026-11-16 20:57), pliki `reports/report.html`, `report.json`, `report.md`.
- Profil laptopa: `requirements.laptop.yaml`, `time_source: ntp` (hash `7a020e…`). Przykład w `config/requirements.example.yaml` zostaje przy `nvr_sync`.
- Urządzenia: NVR `192.168.1.200` DS-7616NXI-K2(D), PTZ `192.168.1.201`, kamera stała `192.168.1.202`.
- Gemini: `gemini-3.8-flash`, klucz w Windows Credential Manager (`haca` / `gemini_api_key`).

## Ostatni raport (dfab218)

- Gemini: `ok`.
- Czas NTP: konfliktu `R-TIME-001` nie ma.
- Fałszywy `R-REC-001` (harmonogram CMR) nie wrócił.
- Ścieżki NVR **101** i **201** (kanał 1, main i sub) nadal `Enable=false`, mimo zielonego harmonogramu i restartu NVR. Zostaje `R-REC-002` (informacja). Drugiej kamery ten alarm nie dotyczy.
- Jedyny `CONFIRMED`: `R-VCA-001`, PTZ, silnik przekroczenia linii wyłączony.
- Do decyzji w profilu: Hik-Connect, tryb PTZ, HTTPS, notify center dla `cam01`.
