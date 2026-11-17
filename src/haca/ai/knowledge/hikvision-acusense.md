# Hikvision analytics and recording (checked reference)

Each point is a checked public fact for this audit. It is not a device reading. A menu path that is not written here must not be invented.

## What puts human and vehicle marks on the NVR timeline

- The camera rule needs its human/vehicle target filter, the stream needs Dual-VCA (VCA information carried on the video), and the NVR needs the option usually named "Save Camera VCA Data". That NVR option ships off. Public descriptions place it under Storage, Advanced, but the exact page depends on firmware.
- When those items are listed under evidence.gaps as manual_check, they were not read. Do not state that they are on or off.
- "Notify Surveillance Center" pushes an alarm to Hik-Connect or an alarm host. It does not draw marks on the local timeline.

## Logs

- The ordinary system log (alarm, exception, operation, information) is what log search reads. Do not recommend a debug log.
- Recorders commonly accept a log search for `log.std-cgi.com`. Many cameras expect the domain `log.hikvision.com` and reject a timestamp that ends in `Z`.
- A gap on `logs.search_matches` means the reply was not read. It does not mean the camera has an empty log.

## Recordings

- Video presence is a search of tracks 101 (main) and 201 (sub). `Enable=false` on a track does not mean the disk has no video; the search can still return segments.
- Human and vehicle marks on the playback timeline stay a manual check even when segments exist.
- Continuous recording fills the disk. Event recording exists only when the camera emits the event and the recorder stores it.

## Detection and PTZ

- A line-crossing or field engine that is off produces no events for that rule, even when a line or zone is drawn.
- A PTZ patrol or park action can move the camera off the coordinates of a line or field rule.
