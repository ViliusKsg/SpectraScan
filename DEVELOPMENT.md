# SpectraScan — Development Notes

## Local Setup

- **Local folder**: `C:\GitHub\SpectraScan`
- **Remote repo**: https://github.com/ViliusKsg/SpectraScan
- **Sync**: `git pull` / `git push` (branch: `main`)

## What Was Done

### v3.0 — Initial Release (2026-05-18)

1. **Touch screen fix** — Touch was incorrectly marked as "defective" (TD_STATUS always 0). 
   Ran calibration test (`TouchCalibrationTest.ino`) which confirmed touch works perfectly.
   Removed `AUTO_TAB_MS` auto-tab workaround and "defective" comments.

2. **Source code cleanup** — Renamed from `WiFi_BLE_Scanner.ino` to `SpectraScan.ino`.
   Translated Lithuanian header/comments to English for open-source.

3. **GitHub repo created** — MIT license, README with features/hardware/build instructions, photos.

## Build & Flash Workflow

### Compile
```powershell
$arduino = "C:\Program Files (x86)\Arduino\arduino_debug.exe"
& $arduino --verify --board "esp32:esp32:esp32s3:CDCOnBoot=cdc,PartitionScheme=huge_app" --pref "build.path=C:\temp\arduino_build" "C:\GitHub\SpectraScan\firmware\SpectraScan\SpectraScan.ino"
```

### Flash (esptool directly — Arduino IDE upload is broken)
```powershell
$esptool = "C:\Users\vilius\AppData\Local\Arduino15\packages\esp32\tools\esptool_py\4.5\esptool.exe"
& $esptool --chip esp32s3 --port COM5 --baud 921600 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 80m --flash_size 8MB `
  0x0000  "C:\temp\arduino_build\SpectraScan.ino.bootloader.bin" `
  0x8000  "C:\temp\arduino_build\SpectraScan.ino.partitions.bin" `
  0xe000  "C:\Users\vilius\AppData\Local\Arduino15\packages\esp32\hardware\esp32\2.0.7\tools\partitions\boot_app0.bin" `
  0x10000 "C:\temp\arduino_build\SpectraScan.ino.bin"
```

### Why not Arduino IDE upload?
Arduino IDE 1.8.19 has a bug where the esptool path becomes `___REMOVE___/esptool.exe`. 
Workaround: compile with `--verify`, then flash manually with esptool.

## Key Architecture

### Source: `firmware/SpectraScan/SpectraScan.ino` (~1670 lines)

| Section | Lines (approx) | Purpose |
|---------|----------------|---------|
| Header + defines | 1-100 | Pin config, timing constants, limits |
| Data structures | 100-250 | AP, BLE, Alert, Station, EAPOL structs |
| WiFi promiscuous | 250-500 | Channel hopping, frame parsing, beacon/deauth/EAPOL |
| BLE scanning | 500-700 | AirTag, Flipper, skimmer detection |
| Display + LVGL | 700-850 | TFT init, touch read callback, LVGL setup |
| UI tabs | 850-1400 | WiFi table, spectrum chart, BLE list, alerts, summary |
| Main loop | 1400-1670 | Task scheduling, tab updates, serial commands |

### Touch Read (`touch_read_cb`, ~line 756)
```cpp
// Reads FT6336U via I2C (addr 0x38)
// Register 0x02 = TD_STATUS (touch count)
// Register 0x03-0x06 = X/Y coordinates
// Maps rawX/rawY directly to screen (no transformation needed)
```

### Key Defines to Modify
```cpp
#define MAX_APS      60    // Max tracked WiFi APs
#define MAX_BLES     60    // Max tracked BLE devices
#define MAX_ALERTS   30    // Alert history size
#define MAX_STAS     40    // Max tracked WiFi stations
#define CHAN_DWELL_MS 150  // ms per channel during hopping
#define BLE_EXPIRE_MS 60000  // BLE device timeout
```

## Dependencies

| Library | Version | Config needed |
|---------|---------|---------------|
| TFT_eSPI | 2.5.43 | `User_Setup_Select.h` → FNK0086A_2.8_CFG1_240x320_ST7789 |
| LVGL | 8.4.0 | `lv_conf.h`: LV_FONT_MONTSERRAT_12 = 1 |
| Arduino-FT6336U | 1.0.2 | — |
| ESP32 board package | 2.0.7 | — |

## Board Settings (Arduino IDE)

- Board: ESP32S3 Dev Module
- USB CDC On Boot: **Enabled**
- Partition Scheme: **Huge APP (3MB No OTA/1MB SPIFFS)**
- Flash Size: 8MB
- PSRAM: OPI PSRAM

## Known Issues

- Arduino IDE upload broken (`___REMOVE___` path bug) → use esptool directly
- Serial Monitor via PowerShell doesn't work with USB CDC after reset → use Arduino IDE Serial Monitor
- TFT_eSPI warns about TOUCH_CS not defined → safe to ignore (we use FT6336U I2C touch, not SPI touch)

## Git Workflow
```powershell
cd C:\GitHub\SpectraScan
git add -A
git commit -m "description"
git push
```

## Future Ideas

- [ ] Add screenshots to README from device photos
- [ ] OTA update support
- [ ] SD card logging
- [ ] Web interface via WiFi AP mode
- [ ] GPS module for wardriving
- [ ] Export scan results to PCAP format
