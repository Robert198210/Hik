## Summary

- classifications: {'CONFIRMED_CONFLICT': 1, 'POTENTIAL_CONFLICT': 1, 'INFO': 6}
- severities: {'high': 1, 'medium': 1, 'info': 6}

## Needs decision

- `devices.cam01.notify_center_required` — notify_center_required unset; linedetection trigger lacks center
- `devices.ptz01.ptz_mode` — PTZ mode undecided in ORP
- `system.hik_connect` — Hik-Connect policy undecided in ORP
- `system.https_required` — HTTP enabled and HTTPS disabled; https_required unspecified

## Findings

- **R-VCA-001** CONFIRMED_CONFLICT
  - devices: ptz01
  - Line crossing required but engine disabled
  - evidence: `smart.line_detection` `enabled` = `false`
  - ORP: devices.ptz01.required_events

- **ai** POTENTIAL_CONFLICT
  - devices: ptz01
  - current → recommended: `frozenset()` → `frozenset({'center'})`
  - The ORP explicitly requires notify_center_required=true for ptz01. Verified setting linkage.linedetection_notifications is currently empty (frozenset()), meaning line crossing events will not push alerts to the surveillance center or Hik-Connect.
  - evidence: `event.triggers` `triggers[linedetection].methods` = `frozenset()`

- **R-HIKC-001** INFO
  - devices: nvr01
  - current → recommended: `true` → `—`
  - Hik-Connect policy undecided in ORP
  - evidence: `platform.ezviz` `enabled` = `true`
  - ORP: system.hik_connect
- **R-LINK-001** INFO
  - devices: nvr01, cam01
  - notify_center_required unset; linedetection trigger lacks center
  - evidence: `event.triggers` `notificationMethod` = `['record']`
  - ORP: devices.cam01.notify_center_required
- **R-PTZ-001** INFO
  - devices: ptz01
  - PTZ mode undecided in ORP
  - evidence: `ptz.park_action` `enabled` = `False`
  - ORP: devices.ptz01.ptz_mode
- **R-REC-002** INFO
  - devices: nvr01
  - current → recommended: `17` → `—`
  - Track flag is false and a schedule is present. Recording search returned 17 video segment(s) on this track in the last 24 hours. Human/vehicle timeline markers stay a manual check.
  - evidence: `record.tracks` `Enable` = `false`
  - evidence: `content.record_search` `track[101].segments` = `17`
- **R-REC-002** INFO
  - devices: nvr01
  - current → recommended: `23` → `—`
  - Track flag is false and a schedule is present. Recording search returned 23 video segment(s) on this track in the last 24 hours. Human/vehicle timeline markers stay a manual check.
  - evidence: `record.tracks` `Enable` = `false`
  - evidence: `content.record_search` `track[201].segments` = `23`
- **R-SEC-001** INFO
  - devices: nvr01
  - HTTP enabled and HTTPS disabled; https_required unspecified
  - evidence: `security.admin_accesses` `HTTPS.enabled` = `false`
  - ORP: system.https_required

## Coverage matrix

Verified 72 of 129 settings in HACA catalog v1. The catalog does not cover every Hikvision setting.

### nvr01
- analytics: {'VERIFIED_ISAPI': 1, 'NOT_APPLICABLE': 6, 'NOT_IMPLEMENTED_IN_HACA': 3}
- identity: {'VERIFIED_ISAPI': 2}
- linkage: {'VERIFIED_ISAPI': 1}
- network: {'VERIFIED_ISAPI': 1}
- platform: {'VERIFIED_ISAPI': 1}
- ptz: {'NOT_APPLICABLE': 4}
- recording: {'VERIFIED_ISAPI': 4, 'INACCESSIBLE': 1, 'NOT_IMPLEMENTED_IN_HACA': 1}
- security: {'VERIFIED_ISAPI': 6}
- storage: {'INACCESSIBLE': 3, 'NOT_IMPLEMENTED_IN_HACA': 1}
- streaming: {'VERIFIED_ISAPI': 5, 'INACCESSIBLE': 1}
- time: {'VERIFIED_ISAPI': 2}

### ptz01
- analytics: {'INACCESSIBLE': 2, 'VERIFIED_ISAPI': 5, 'NOT_IMPLEMENTED_IN_HACA': 1, 'NOT_APPLICABLE': 2}
- identity: {'VERIFIED_ISAPI': 2}
- linkage: {'VERIFIED_ISAPI': 1}
- network: {'VERIFIED_ISAPI': 1}
- platform: {'VERIFIED_ISAPI': 1}
- ptz: {'VERIFIED_ISAPI': 4}
- recording: {'NOT_APPLICABLE': 6}
- security: {'VERIFIED_ISAPI': 4, 'NOT_APPLICABLE': 2}
- storage: {'NOT_APPLICABLE': 4}
- streaming: {'VERIFIED_ISAPI': 6}
- time: {'VERIFIED_ISAPI': 2}

### cam01
- analytics: {'INACCESSIBLE': 1, 'VERIFIED_ISAPI': 6, 'NOT_IMPLEMENTED_IN_HACA': 1, 'NOT_APPLICABLE': 2}
- identity: {'VERIFIED_ISAPI': 2}
- linkage: {'VERIFIED_ISAPI': 1}
- network: {'VERIFIED_ISAPI': 1}
- platform: {'VERIFIED_ISAPI': 1}
- ptz: {'NOT_APPLICABLE': 4}
- recording: {'NOT_APPLICABLE': 6}
- security: {'VERIFIED_ISAPI': 4, 'NOT_APPLICABLE': 2}
- storage: {'NOT_APPLICABLE': 4}
- streaming: {'VERIFIED_ISAPI': 6}
- time: {'VERIFIED_ISAPI': 2}

## Manual checks (not inspectable via ISAPI)

- manual.dual_vca
- manual.hdd_model_smr
- manual.nvr_local_smart_analysis
- manual.nvr_save_vca_data
- manual.playback_markers

## Unsupported / inaccessible

- nvr01 `streaming.main.bitrate` — field_absent
- nvr01 `recording.pre_post_record` — field_absent
- nvr01 `storage.hdd_status` — field_absent
- nvr01 `storage.hdd_capacity` — field_absent
- nvr01 `storage.hdd_free_space` — field_absent
- ptz01 `logs.search_matches` — parse_error
- ptz01 `analytics.detection_targets` — field_absent
- cam01 `logs.search_matches` — parse_error

## Method and limitations

Candidate ISAPI endpoints; coverage is limited to the HACA catalog.
