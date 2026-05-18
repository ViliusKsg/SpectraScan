# Hardware Reference

## Freenove ESP32-S3 FNK0086

- **MCU**: ESP32-S3R8 (Xtensa LX7 dual-core, 240 MHz)
- **Flash**: 8 MB
- **PSRAM**: 8 MB
- **Display**: 2.8" IPS TFT, ST7789 controller, 240×320 resolution
- **Touch**: FT6336U capacitive touch controller (I2C address 0x38)
- **USB**: USB-C with native USB CDC

## Pinout

```
TFT (SPI - HSPI):
  MOSI  = GPIO 11
  SCLK  = GPIO 12
  CS    = GPIO 10
  DC    = GPIO 13
  RST   = GPIO 14
  BL    = GPIO 45

Touch (I2C):
  SDA   = GPIO 2
  SCL   = GPIO 1
  INT   = GPIO 21 (optional)
```

## Power

- USB-C: 5V input
- Typical consumption: ~180 mA (WiFi + BLE + display)
