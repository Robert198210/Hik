# Hikvision analytics and recording (generic reference)

Each point below is curated public-domain knowledge for audit reasoning only — not device-specific data.

## Camera-side analytics vs NVR analytics

- Many installations run VCA on cameras and send metadata to the NVR, or use NVR "by camera" smart modes.
  (Public: Hikvision product documentation describes local vs remote VCA deployment patterns.)

## Hikvision protocol vs ONVIF for smart metadata

- Native Hikvision ISAPI often exposes richer event and VCA linkage than ONVIF event profiles alone.
  (Public: ONVIF Core specification vs vendor ISAPI guides.)

## Dual-VCA and timeline markers

- "Save VCA data" / similar options affect whether search and playback show analytic markers on the timeline.
  (Public: NVR user manuals — smart search / VCA playback sections.)

## Continuous vs event recording

- Continuous recording increases storage load; event-only recording depends on reliable event generation and linkage.
  (Public: generic CCTV storage planning guides.)

## SMR disks and intelligent search

- SMR/CMR class affects sustained write patterns; intelligent video search assumes indexed event metadata.
  (Public: storage vendor SMR documentation; Hikvision HDD compatibility notes.)

## VCA rules and PTZ movement

- Line crossing / field detection rules may interact with PTZ patrol or tracking — rule coordinates can become
  invalid after preset moves. (Public: PTZ VCA deployment best-practice articles.)