# HACA — bieżący stan

Last updated: 2026-11-17

Nowy czat: przeczytaj ten plik zanim cokolwiek zmienisz. Na końcu sesji, jeśli stan się zmienił, zaktualizuj ten plik (data, commity, raport, otwarte sprawy). Nie wpisuj haseł.

## Gdzie

- Repo: `/var/fpwork/ambrosew/skrypty/HIK/haca`
- GitHub: `https://github.com/Robert198210/Hik.git` (`origin/main`)
- Laptop: `C:\programy\hik`, jedna komenda `.\report` (sam robi `git pull` i uruchamia się ponownie z dysku). W trakcie wypisuje wybrane komunikaty: odpowiedź NVR i kamer, czas i sieć, harmonogram, detekcja, dziennik, nagrania 101/201, porównanie z profilem, Gemini, zapis raportu, wysyłka na GitHub.
- Przed opisem kodu: `git fetch origin main`. Lokalny `HEAD` bywa za GitHubem.

## Zasady

- Tylko odczyt. Program nie zapisuje ustawień i nie restartuje NVR.
- Nie otwieraj `/var/fpwork/ambrosew/skrypty/Hikvision/**`.
- Nie uruchamiaj ponownie QA Phase 3.
- Hasła tylko w `ustaw-hasla.ps1` na laptopie. Nie commituj tego pliku ze zmienionym hasłem.
- Pisz do użytkownika po polsku.

## Kod i konfiguracja

- Ostatni kod: paczka do Gemini zawiera rodzaje wpisów dziennika, nagrania per tor, braki z powodem i uzasadnienia reguł. Polecenie tłumaczy tylko odczytane wartości i nie dopowiada ścieżek z pamięci. Poprzedni odczyt dziennika kamer: `d859779`. Kod postępu: `3f27ba0`. Odczyt nagrań: `09b6bf8`.
- Ostatni raport na GitHubie: `8780c51` (2026-11-17 15:10). Audyt trwał około 26 s. Gemini: `ok`, polecenie `2026-11-16-v1`, 3728 tokenów wejścia.
- Profil laptopa: `requirements.laptop.yaml`, `time_source: ntp` (hash `7a020e…`). Przykład w `config/requirements.example.yaml` zostaje przy `nvr_sync`.
- Urządzenia: NVR `192.168.1.200` DS-7616NXI-K2(D), PTZ `192.168.1.201`, kamera stała `192.168.1.202`.
- Gemini: `gemini-3.8-flash`, klucz w Windows Credential Manager (`haca` / `gemini_api_key`).

## Ustalenie 2026-11-17 — logi a analiza

Nie włączać logu debug. Odczyt nagrań potwierdzony na żywym NVR w `496e4c3`:

- `POST /ISAPI/ContentMgmt/search` na torach 101 i 201 zwrócił odcinki (17 i 23 w ostatnich 24 h). `R-REC-002` jest informacją, nie „za mało danych”. Flaga `Enable` nadal `false`. Znaczniki człowiek/pojazd zostają ręczne.
- `POST /ISAPI/ContentMgmt/logSearch` na NVR jest odczytany. W `8780c51` PTZ i kamera stała nadal mają `logs.search_matches`: `parse_error`, już po poprawce `d859779` (drugie i trzecie zapytanie oraz naprawa UTF-16). Sprawa otwarta.
- Z odpowiedzi wypadają `userName`, adresy i `playbackURI`, zanim trafią do bazy.
- Dual-VCA i „Save Camera VCA Data” nadal ręczne.

## Ostatni raport (8780c51)

- Gemini: `ok`.
- Czas NTP: konfliktu `R-TIME-001` nie ma.
- Fałszywy `R-REC-001` (harmonogram CMR) nie wrócił.
- Ścieżki NVR **101** i **201** nadal `Enable=false`. Wyszukanie nagrań znalazło 17 odcinków na 101 i 23 na 201 w ostatnich 24 h (`R-REC-002`, informacja). Drugiej kamery ten alarm nie dotyczy.
- Jedyny `CONFIRMED`: `R-VCA-001`, PTZ, silnik przekroczenia linii wyłączony.
- Do decyzji w profilu: Hik-Connect, tryb PTZ, HTTPS, notify center dla `cam01`.
