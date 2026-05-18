/*
 * SpectraScan.ino — v3.0
 * https://github.com/ViliusKsg/SpectraScan
 *
 * ESP32-S3 portable wireless security auditor
 * WiFi & BLE scanner with touch TFT display
 *
 * Features:
 *   - Passive promiscuous mode (no probe requests transmitted)
 *   - Channel hopping 1-13 with real-time spectrum analyzer
 *   - Station (client) detection from data frame DS bits
 *   - EAPOL 4-way handshake + PMKID passive capture (hashcat -m 22000)
 *   - Open network automatic alerting
 *   - WPS detection from Vendor Specific IE
 *   - Deauth/Disassoc attack detection with alerts
 *   - AirTag tracking detection (Apple FindMy)
 *   - Flipper Zero detection (CID 0x0BA0)
 *   - BLE skimmer heuristic (anonymous, strong signal, unknown CID)
 *   - 6 UI tabs: WiFi, Spectrum, Stations, BLE, Alerts, Summary
 *
 * Hardware:
 *   ESP32-S3R8 (8 MB PSRAM) — Freenove FNK0086
 *   ST7789 240x320 TFT (SPI, HSPI)
 *   FT6336U capacitive touch (I2C SDA=2, SCL=1)
 *
 * Dependencies:
 *   TFT_eSPI v2.5.43   — User_Setup: FNK0086A_2.8_CFG1_240x320_ST7789
 *   LVGL v8.4.0        — lv_conf.h: LV_FONT_MONTSERRAT_12 = 1
 *   Arduino-FT6336U v1.0.2
 *
 * Build: Arduino IDE, ESP32S3 Dev Module, board package 2.0.7
 *        Partition: Huge APP (3MB No OTA), USB CDC On Boot: Enabled
 *
 * License: MIT
 */

#include <Arduino.h>
#include <Wire.h>
#include <lvgl.h>
#include <TFT_eSPI.h>
#include <FT6336U.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_coexist.h"   // WiFi > BLE prioritetas
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

// ================================================================
// Hardware pins
// ================================================================
#define PIN_TFT_BL  45
#define PIN_SDA      2
#define PIN_SCL      1

// ================================================================
// Screen
// ================================================================
#define SCR_W  240
#define SCR_H  320
#define TAB_H   34

// ================================================================
// Scan limits & timing
// ================================================================
#define MAX_APS           60
#define MAX_BLES          60
#define MAX_ALERTS        30
#define MAX_STAS          40
#define MAX_EAPOL          8
#define BLE_SCAN_SEC       5
#define BLE_EXPIRE_MS  60000UL
#define STA_EXPIRE_MS 120000UL
#define CHAN_DWELL_MS    150UL
#define SPECT_UPDATE_MS 1500UL
#define WIFI_TABLE_MS   2000UL
#define BLE_RESCAN_MS  10000UL
#define BLE_EXPIRE_CHK 15000UL
#define FRAME_Q_SIZE      48


// ================================================================
// Frame event tipai
// ================================================================
#define FEV_BEACON     0
#define FEV_PROBE_REQ  1
#define FEV_DEAUTH     2
#define FEV_DISASSOC   3
#define FEV_STATION    4
#define FEV_EAPOL      5
// Alert-only event types (stored in AlertEvent.type, not queued as FrameEvent)
#define ALT_OPEN_NET  10
#define ALT_EAPOL_CAP 11

// ================================================================
// Duomenu strukturos
// ================================================================
struct APInfo {
    char     ssid[33];
    uint8_t  bssid[6];
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  enc;
    char     vendor[12];
    uint32_t lastSeen;
    bool     hasWPS;        // WPS IE detected in beacon
    bool     openAlerted;   // already added to alerts
};

struct STAInfo {
    uint8_t  mac[6];        // Client MAC address
    uint8_t  bssid[6];      // AP this client is associated with
    int8_t   rssi;
    uint32_t lastSeen;
};

struct EAPOLCapture {
    uint8_t  bssid[6];      // AP MAC
    uint8_t  sta[6];        // Client MAC
    char     ssid[33];      // AP SSID (from AP list)
    uint8_t  msgNum;        // EAPOL-Key message 1..4
    uint8_t  pmkid[16];     // PMKID (valid if hasPMKID==true)
    bool     hasPMKID;
    uint32_t timestamp;
};

struct BLEInfo {
    char     mac[18];
    char     name[25];
    int8_t   rssi;
    char     mfg[12];
    uint32_t lastSeen;
    bool     isAirTag;
    bool     isFlipper;
    bool     isSkimmer;
};

struct AlertEvent {
    uint8_t  type;
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  src[6];
    uint8_t  dst[6];
    uint8_t  reason;
    uint32_t timestamp;
};

struct FrameEvent {
    uint8_t  evType;
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  bssid[6];
    uint8_t  src[6];
    uint8_t  dst[6];
    uint8_t  enc;
    uint8_t  reason;
    char     ssid[33];
    bool     hasWPS;           // FEV_BEACON: WPS IE found
    uint8_t  eapolMsg;         // FEV_EAPOL: message number 1-4
    uint8_t  eapolPMKID[16];   // FEV_EAPOL: PMKID bytes
    bool     eapolHasPMKID;    // FEV_EAPOL: PMKID found in key data
};

// ================================================================
// Globalus stovimas
// ================================================================
static APInfo   apList[MAX_APS];
static int      apCount = 0;

static STAInfo  staList[MAX_STAS];
static int      staCount = 0;
static volatile bool staListDirty = false;
static SemaphoreHandle_t staMutex  = nullptr;

static EAPOLCapture eapolList[MAX_EAPOL];
static int          eapolCount = 0;

static BLEInfo  bleList[MAX_BLES];
static int      bleCount = 0;
static volatile bool bleListDirty = false;
static SemaphoreHandle_t bleMutex = nullptr;

static AlertEvent alertList[MAX_ALERTS];
static int        alertCount = 0;
static SemaphoreHandle_t alertMutex = nullptr;
static volatile bool alertsDirty = false;

static volatile uint32_t chanPktCount[14];
static uint32_t displayPktCount[14];
static uint32_t spectLastMs = 0;

static uint8_t  currentChannel = 1;
static uint32_t chanHopMs = 0;

static QueueHandle_t frameQ = nullptr;

static BLEScan  *pBLEScan      = nullptr;
static bool      bleScanActive = false;
static uint32_t  bleScanStartMs = 0;
static uint32_t  lastBleMs = 0;

// ================================================================
// Hardware instancijos
// ================================================================
static TFT_eSPI tft(SCR_W, SCR_H);
static FT6336U  ft6336(PIN_SDA, PIN_SCL, -1, -1);

// ================================================================
// LVGL
// ================================================================
static lv_disp_draw_buf_t disp_draw_buf;
static lv_color_t         lv_draw_buf[SCR_W * 15];

static lv_obj_t *tabview    = nullptr;
static lv_obj_t *wifiTable  = nullptr;
static lv_obj_t *spectChart = nullptr;
static lv_chart_series_t *spectSer = nullptr;
static lv_obj_t *bleTable   = nullptr;
static lv_obj_t *alertTable = nullptr;
static lv_obj_t *statusLbl  = nullptr;
static lv_obj_t *alertBadge = nullptr;
static int       alertBadgeCount = 0;
static lv_obj_t *staTable   = nullptr;
static lv_obj_t *summaryLbl = nullptr;

// ================================================================
// OUI lookup lentele (WiFi)
// ================================================================
struct OUIEntry { uint8_t oui[3]; const char *name; };
static const OUIEntry OUI_TABLE[] = {
    {{0x00,0x50,0xF2}, "Microsoft"},
    {{0xFC,0xFB,0xFB}, "Apple"},    {{0x00,0x17,0xF2}, "Apple"},
    {{0xAC,0x37,0x43}, "Apple"},    {{0x00,0x26,0xBB}, "Apple"},
    {{0xA4,0xC3,0xF0}, "Apple"},    {{0x3C,0x22,0xFB}, "Apple"},
    {{0xB8,0x27,0xEB}, "Raspb.Pi"}, {{0xDC,0xA6,0x32}, "Raspb.Pi"},
    {{0xE4,0x5F,0x01}, "Raspb.Pi"},
    {{0x18,0x60,0x24}, "Samsung"},  {{0x8C,0x77,0x12}, "Samsung"},
    {{0x78,0x40,0xE4}, "Samsung"},
    {{0x00,0x1D,0x25}, "Netgear"},  {{0xA0,0x21,0xB7}, "Netgear"},
    {{0x9C,0xD3,0x6D}, "Netgear"},
    {{0x00,0x18,0xE7}, "Cisco"},    {{0x00,0x0F,0x24}, "Cisco"},
    {{0x58,0xBF,0xEA}, "Cisco"},
    {{0xC4,0x12,0xF5}, "TP-Link"},  {{0x50,0xC7,0xBF}, "TP-Link"},
    {{0xEC,0x08,0x6B}, "TP-Link"},  {{0x14,0xEB,0xB6}, "TP-Link"},
    {{0x54,0xAF,0x97}, "TP-Link"},
    {{0xB0,0x4E,0x26}, "Huawei"},   {{0x40,0x4D,0xF2}, "Huawei"},
    {{0x00,0x46,0x4B}, "Google"},   {{0xF4,0xF5,0xDB}, "Google"},
    {{0xE8,0x65,0xD4}, "ASUSTek"},  {{0x10,0xBF,0x48}, "ASUSTek"},
    {{0xF0,0x2F,0x74}, "ASUSTek"},
    {{0x00,0x23,0x54}, "Belkin"},
    {{0x94,0x10,0x3E}, "MikroTik"}, {{0x4C,0x5E,0x0C}, "MikroTik"},
    {{0xCC,0x2D,0xE0}, "Ubiquiti"}, {{0x00,0x27,0x22}, "Ubiquiti"},
    {{0xF0,0x9F,0xC2}, "Ubiquiti"}, {{0xFC,0xEC,0xDA}, "Ubiquiti"},
    {{0x00,0x11,0x22}, "Zyxel"},
    {{0xD4,0x20,0xB0}, "D-Link"},   {{0x00,0x21,0x91}, "D-Link"},
    {{0x00,0x1C,0xF0}, "D-Link"},
    {{0xAC,0x9E,0x17}, "ASUS"},
};
#define OUI_COUNT (sizeof(OUI_TABLE)/sizeof(OUI_TABLE[0]))

static const char* lookupVendor(const uint8_t *mac) {
    for (size_t i = 0; i < OUI_COUNT; i++) {
        if (mac[0]==OUI_TABLE[i].oui[0] &&
            mac[1]==OUI_TABLE[i].oui[1] &&
            mac[2]==OUI_TABLE[i].oui[2])
            return OUI_TABLE[i].name;
    }
    return "";
}

// ================================================================
// BLE company ID lookup
// ================================================================
static const char* lookupBLEMfg(uint16_t cid) {
    switch(cid) {
        case 0x004C: return "Apple";
        case 0x0006: return "Microsoft";
        case 0x0075: return "Samsung";
        case 0x00E0: return "Google";
        case 0x01D1: return "Xiaomi";
        case 0x0499: return "Ruuvi";
        case 0x0059: return "Nordic SC";
        case 0x0157: return "Espressif";
        case 0x02FF: return "Espressif";
        case 0x0BA0: return "Flipper";
        case 0x038F: return "Tile";
        case 0x004F: return "Nordic SC";
        case 0x0000: return "Ericsson";
        case 0x0002: return "Intel";
        case 0x000F: return "Broadcom";
        case 0x001D: return "Qualcomm";
        default:     return nullptr;
    }
}

// ================================================================
// Sifravimo pavadinimai
// ================================================================
static const char* encStr(uint8_t e) {
    switch(e) {
        case WIFI_AUTH_OPEN:            return "OPEN";
        case WIFI_AUTH_WEP:             return "WEP";
        case WIFI_AUTH_WPA_PSK:         return "WPA";
        case WIFI_AUTH_WPA2_PSK:        return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-E";
        case WIFI_AUTH_WPA3_PSK:        return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK:   return "WP2/3";
        case WIFI_AUTH_WAPI_PSK:        return "WAPI";
        default:                        return "?";
    }
}

// ================================================================
// 802.11 beacon IE parser
// Kvieciamas is promiscuous callback (WiFi task kontekstas)
// ================================================================
static void parseBeaconIEs(const uint8_t *ies, int ies_len,
                            char *ssid_out, uint8_t privacy_bit,
                            uint8_t *enc_out, bool *wps_out = nullptr)
{
    ssid_out[0] = '\0';
    bool hasRSN  = false;
    bool hasWPA3 = false;
    bool hasWPA1 = false;
    if (wps_out) *wps_out = false;

    int pos = 0;
    while (pos + 2 <= ies_len) {
        uint8_t tag = ies[pos];
        uint8_t len = ies[pos + 1];
        if (pos + 2 + len > ies_len) break;
        const uint8_t *d = &ies[pos + 2];

        if (tag == 0 && len > 0 && len <= 32) {
            memcpy(ssid_out, d, len);
            ssid_out[len] = '\0';
        }
        else if (tag == 48 && len >= 4) {
            hasRSN = true;
            if (len >= 8) {
                uint16_t pc = (uint16_t)(d[4]) | (uint16_t)((uint16_t)(d[5]) << 8);
                int akm_off = 6 + pc * 4;
                if (akm_off + 2 <= len) {
                    uint16_t ac = (uint16_t)(d[akm_off]) |
                                  (uint16_t)((uint16_t)(d[akm_off+1]) << 8);
                    akm_off += 2;
                    for (uint16_t a = 0; a < ac && akm_off + 4 <= len;
                                        a++, akm_off += 4) {
                        if (d[akm_off + 3] == 8) hasWPA3 = true;
                    }
                }
            }
        }
        else if (tag == 221 && len >= 4) {
            if (d[0]==0x00 && d[1]==0x50 && d[2]==0xF2 && d[3]==0x01)
                hasWPA1 = true;
            // WPS (Wi-Fi Simple Config) — security weakness
            if (wps_out && d[0]==0x00 && d[1]==0x50 && d[2]==0xF2 && d[3]==0x04)
                *wps_out = true;
        }

        pos += 2 + len;
    }

    if      (hasWPA3 && hasRSN) *enc_out = WIFI_AUTH_WPA2_WPA3_PSK;
    else if (hasWPA3)           *enc_out = WIFI_AUTH_WPA3_PSK;
    else if (hasRSN && hasWPA1) *enc_out = WIFI_AUTH_WPA_WPA2_PSK;
    else if (hasRSN)            *enc_out = WIFI_AUTH_WPA2_PSK;
    else if (hasWPA1)           *enc_out = WIFI_AUTH_WPA_PSK;
    else if (privacy_bit)       *enc_out = WIFI_AUTH_WEP;
    else                        *enc_out = WIFI_AUTH_OPEN;
}

// ================================================================
// Promiscuous WiFi callback
// Vykdomas WiFi task kontekste — tik enqueue + counter
// ================================================================
static volatile uint32_t promiscCallCount = 0;

static void promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    promiscCallCount++;
    if (!frameQ) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int frame_len = (int)pkt->rx_ctrl.sig_len;

    if (frame_len < 10) return;

    uint8_t ch = pkt->rx_ctrl.channel;
    if (ch >= 1 && ch <= 13) {
        chanPktCount[ch - 1]++;
    }

    uint8_t fc0   = frame[0];
    uint8_t ftype = (fc0 >> 2) & 0x03;
    uint8_t fsub  = (fc0 >> 4) & 0x0F;

    // ---- Management frames: beacon, probe req, deauth, disassoc ----
    if (type == WIFI_PKT_MGMT && ftype == 0 && frame_len >= 24) {
        FrameEvent ev;
        memset(&ev, 0, sizeof(ev));
        ev.channel = ch;
        ev.rssi    = pkt->rx_ctrl.rssi;
        memcpy(ev.dst,   &frame[4],  6);
        memcpy(ev.src,   &frame[10], 6);
        memcpy(ev.bssid, &frame[16], 6);

        if (fsub == 8 || fsub == 5) {  // Beacon or Probe Response
            ev.evType = FEV_BEACON;
            if (frame_len < 37) return;
            uint8_t privacy = (frame[34] >> 4) & 0x01;
            parseBeaconIEs(&frame[36], frame_len - 36,
                           ev.ssid, privacy, &ev.enc, &ev.hasWPS);
            xQueueSend(frameQ, &ev, 0);
        }
        else if (fsub == 4) {  // Probe Request
            ev.evType = FEV_PROBE_REQ;
            if (frame_len >= 26) {
                uint8_t dummy_enc;
                parseBeaconIEs(&frame[24], frame_len - 24,
                               ev.ssid, 0, &dummy_enc);
            }
            xQueueSend(frameQ, &ev, 0);
        }
        else if (fsub == 12 || fsub == 10) {  // Deauth or Disassoc
            ev.evType = (fsub == 12) ? FEV_DEAUTH : FEV_DISASSOC;
            ev.reason = (frame_len >= 26) ? frame[24] : 0;
            xQueueSend(frameQ, &ev, 0);
        }
        return;
    }

    // ---- Data frames: station detection + EAPOL capture ----
    if (type == WIFI_PKT_DATA && ftype == 2 && frame_len >= 24) {
        uint8_t fc1     = frame[1];
        uint8_t to_ds   = fc1 & 0x01;
        uint8_t from_ds = (fc1 >> 1) & 0x01;

        // Skip WDS (both bits set) and IBSS (neither bit set)
        if (to_ds == from_ds) return;

        uint8_t staMac[6], apBssid[6];
        if (to_ds && !from_ds) {
            // STA→AP: A1=BSSID, A2=STA, A3=DA
            memcpy(apBssid, &frame[4],  6);
            memcpy(staMac,  &frame[10], 6);
        } else {
            // AP→STA: A1=STA, A2=BSSID, A3=SA
            memcpy(staMac,  &frame[4],  6);
            memcpy(apBssid, &frame[10], 6);
        }

        // Skip broadcast/multicast station MACs
        if (staMac[0] & 0x01) return;

        // Station dedup cache — avoids flooding queue with same MAC
        // (WiFi task context only, no mutex needed)
        static uint8_t sCache[24][6];
        static uint8_t sCacheNext = 0;
        bool inCache = false;
        for (int ci = 0; ci < 24; ci++) {
            if (memcmp(sCache[ci], staMac, 6) == 0) { inCache = true; break; }
        }
        if (!inCache) {
            memcpy(sCache[sCacheNext], staMac, 6);
            sCacheNext = (sCacheNext + 1) % 24;
            FrameEvent sev;
            memset(&sev, 0, sizeof(sev));
            sev.evType  = FEV_STATION;
            sev.channel = ch;
            sev.rssi    = pkt->rx_ctrl.rssi;
            memcpy(sev.src,   staMac,  6);
            memcpy(sev.bssid, apBssid, 6);
            xQueueSend(frameQ, &sev, 0);
        }

        // EAPOL detection
        // QoS data (subtype bit3=1) adds 2-byte QoS ctrl → 26-byte header
        uint8_t hdrLen = ((fsub & 0x08) != 0) ? 26 : 24;
        if (frame_len < hdrLen + 8) return;

        const uint8_t *llc = &frame[hdrLen];
        // LLC+SNAP header for EAPOL: AA AA 03 00 00 00 88 8E
        if (!(llc[0]==0xAA && llc[1]==0xAA && llc[2]==0x03 &&
              llc[3]==0x00 && llc[4]==0x00 && llc[5]==0x00 &&
              llc[6]==0x88 && llc[7]==0x8E)) return;

        const uint8_t *eapol = &frame[hdrLen + 8];
        int eapolLen = frame_len - hdrLen - 8;
        if (eapolLen < 4) return;

        // EAPOL type 3 = EAPOL-Key
        if (eapol[1] != 3) return;
        // Minimum EAPOL-Key header: 99 bytes
        if (eapolLen < 99) return;

        // Key Information field at eapol[5..6] (big-endian)
        uint16_t keyInfo = ((uint16_t)eapol[5] << 8) | eapol[6];
        bool keyAck = (keyInfo & 0x0080) != 0;  // bit 7
        bool keyMic = (keyInfo & 0x0100) != 0;  // bit 8
        bool secure = (keyInfo & 0x0200) != 0;  // bit 9

        // Identify message number
        uint8_t msgNum = 0;
        if      ( keyAck && !keyMic && !secure) msgNum = 1;  // AP→STA: ANonce
        else if (!keyAck &&  keyMic && !secure) msgNum = 2;  // STA→AP: SNonce
        else if ( keyAck &&  keyMic &&  secure) msgNum = 3;  // AP→STA: GTK
        else if (!keyAck &&  keyMic &&  secure) msgNum = 4;  // STA→AP: complete
        if (msgNum == 0) return;

        FrameEvent eev;
        memset(&eev, 0, sizeof(eev));
        eev.evType   = FEV_EAPOL;
        eev.channel  = ch;
        eev.rssi     = pkt->rx_ctrl.rssi;
        eev.eapolMsg = msgNum;
        memcpy(eev.bssid, apBssid, 6);
        memcpy(eev.src,   staMac,  6);

        // Message 1: search key data for PMKID KDE
        // EAPOL-Key header = 99 bytes; key_data_length at eapol[97..98]
        if (msgNum == 1 && eapolLen > 99) {
            uint16_t kdLen = ((uint16_t)eapol[97] << 8) | eapol[98];
            if (kdLen >= 22 && eapolLen >= 99 + (int)kdLen) {
                const uint8_t *kd = &eapol[99];
                // PMKID KDE: DD 14 00 0F AC 04 [16-byte PMKID]
                for (int ki = 0; ki + 22 <= (int)kdLen; ki++) {
                    if (kd[ki]==0xDD && kd[ki+1]==0x14 &&
                        kd[ki+2]==0x00 && kd[ki+3]==0x0F &&
                        kd[ki+4]==0xAC && kd[ki+5]==0x04) {
                        memcpy(eev.eapolPMKID, &kd[ki+6], 16);
                        eev.eapolHasPMKID = true;
                        break;
                    }
                }
            }
        }
        xQueueSend(frameQ, &eev, 0);
        return;
    }
}

// ================================================================
// Helper: prideti alert ivykį (thread-safe)
// ================================================================
static void addAlert(uint8_t type, uint8_t channel, int8_t rssi,
                     const uint8_t *src, const uint8_t *dst, uint8_t reason)
{
    if (!alertMutex) return;
    if (xSemaphoreTake(alertMutex, pdMS_TO_TICKS(5)) != pdTRUE) return;
    AlertEvent *a;
    if (alertCount < MAX_ALERTS) {
        a = &alertList[alertCount++];
    } else {
        memmove(&alertList[0], &alertList[1], (MAX_ALERTS-1)*sizeof(AlertEvent));
        a = &alertList[MAX_ALERTS-1];
    }
    a->type      = type;
    a->channel   = channel;
    a->rssi      = rssi;
    a->reason    = reason;
    a->timestamp = millis();
    if (src) memcpy(a->src, src, 6); else memset(a->src, 0, 6);
    if (dst) memcpy(a->dst, dst, 6); else memset(a->dst, 0, 6);
    alertsDirty  = true;
    xSemaphoreGive(alertMutex);
}

// ================================================================
// Frame event apdorojimas (vykdomas main loop)
// ================================================================
static void processFrameEvent(const FrameEvent &ev)
{
    if (ev.evType == FEV_BEACON) {
        uint32_t now = millis();
        for (int i = 0; i < apCount; i++) {
            if (memcmp(apList[i].bssid, ev.bssid, 6) == 0) {
                apList[i].rssi     = ev.rssi;
                apList[i].lastSeen = now;
                if (ev.ssid[0] && !apList[i].ssid[0]) {
                    strncpy(apList[i].ssid, ev.ssid, 32);
                    apList[i].ssid[32] = '\0';
                }
                // Update WPS flag if newly detected
                if (ev.hasWPS && !apList[i].hasWPS) {
                    apList[i].hasWPS = true;
                    Serial.printf("[WPS] %s %02X:%02X:%02X:%02X:%02X:%02X\n",
                        apList[i].ssid[0] ? apList[i].ssid : "(hidden)",
                        apList[i].bssid[0], apList[i].bssid[1], apList[i].bssid[2],
                        apList[i].bssid[3], apList[i].bssid[4], apList[i].bssid[5]);
                }
                // First-time open network alert
                if (apList[i].enc == WIFI_AUTH_OPEN && !apList[i].openAlerted) {
                    apList[i].openAlerted = true;
                    addAlert(ALT_OPEN_NET, apList[i].channel, apList[i].rssi,
                             apList[i].bssid, apList[i].bssid, 0);
                    Serial.printf("[!OPEN] %s %02X:%02X:%02X:%02X:%02X:%02X ch%d\n",
                        apList[i].ssid[0] ? apList[i].ssid : "(hidden)",
                        apList[i].bssid[0], apList[i].bssid[1], apList[i].bssid[2],
                        apList[i].bssid[3], apList[i].bssid[4], apList[i].bssid[5],
                        apList[i].channel);
                }
                return;
            }
        }
        if (apCount < MAX_APS) {
            APInfo &ap = apList[apCount];
            strncpy(ap.ssid, ev.ssid, 32);
            ap.ssid[32]     = '\0';
            memcpy(ap.bssid, ev.bssid, 6);
            ap.rssi         = ev.rssi;
            ap.channel      = ev.channel;
            ap.enc          = ev.enc;
            ap.lastSeen     = now;
            ap.hasWPS       = ev.hasWPS;
            ap.openAlerted  = false;
            strncpy(ap.vendor, lookupVendor(ev.bssid), 11);
            ap.vendor[11] = '\0';
            apCount++;
            Serial.printf("[AP+] CH%2d %4d dBm %-6s%s %02X:%02X:%02X:%02X:%02X:%02X %s\n",
                ap.channel, (int)ap.rssi, encStr(ap.enc),
                ap.hasWPS ? "[W]" : "",
                ap.bssid[0], ap.bssid[1], ap.bssid[2],
                ap.bssid[3], ap.bssid[4], ap.bssid[5],
                ap.ssid[0] ? ap.ssid : "(hidden)");
            // Alert: open network
            if (ap.enc == WIFI_AUTH_OPEN) {
                ap.openAlerted = true;
                addAlert(ALT_OPEN_NET, ap.channel, ap.rssi, ap.bssid, ap.bssid, 0);
                Serial.printf("[!OPEN] %s %02X:%02X:%02X:%02X:%02X:%02X ch%d\n",
                    ap.ssid[0] ? ap.ssid : "(hidden)",
                    ap.bssid[0], ap.bssid[1], ap.bssid[2],
                    ap.bssid[3], ap.bssid[4], ap.bssid[5], ap.channel);
            }
        }
    }
    else if (ev.evType == FEV_DEAUTH || ev.evType == FEV_DISASSOC) {
        addAlert(ev.evType, ev.channel, ev.rssi, ev.src, ev.dst, ev.reason);
        Serial.printf("[ALERT] %s ch%d rssi=%d "
                      "src=%02X:%02X:%02X dst=%02X:%02X:%02X rsn=%d\n",
            ev.evType == FEV_DEAUTH ? "DEAUTH" : "DISASSOC",
            ev.channel, (int)ev.rssi,
            ev.src[0], ev.src[1], ev.src[2],
            ev.dst[0], ev.dst[1], ev.dst[2],
            ev.reason);
    }
    else if (ev.evType == FEV_STATION) {
        if (!staMutex) return;
        if (xSemaphoreTake(staMutex, pdMS_TO_TICKS(5)) != pdTRUE) return;
        uint32_t now = millis();
        for (int i = 0; i < staCount; i++) {
            if (memcmp(staList[i].mac, ev.src, 6) == 0) {
                staList[i].rssi     = ev.rssi;
                staList[i].lastSeen = now;
                memcpy(staList[i].bssid, ev.bssid, 6);
                staListDirty = true;
                xSemaphoreGive(staMutex);
                return;
            }
        }
        if (staCount < MAX_STAS) {
            STAInfo &s = staList[staCount];
            memcpy(s.mac,   ev.src,   6);
            memcpy(s.bssid, ev.bssid, 6);
            s.rssi     = ev.rssi;
            s.lastSeen = now;
            staCount++;
            staListDirty = true;
            Serial.printf("[STA+] %02X:%02X:%02X:%02X:%02X:%02X -> AP ..%02X:%02X:%02X rssi=%d\n",
                s.mac[0],s.mac[1],s.mac[2],s.mac[3],s.mac[4],s.mac[5],
                s.bssid[3],s.bssid[4],s.bssid[5], (int)s.rssi);
        }
        xSemaphoreGive(staMutex);
    }
    else if (ev.evType == FEV_EAPOL) {
        // Store capture (ring buffer)
        EAPOLCapture *ep;
        if (eapolCount < MAX_EAPOL) {
            ep = &eapolList[eapolCount++];
        } else {
            memmove(&eapolList[0], &eapolList[1], (MAX_EAPOL-1)*sizeof(EAPOLCapture));
            ep = &eapolList[MAX_EAPOL-1];
        }
        memcpy(ep->bssid, ev.bssid, 6);
        memcpy(ep->sta,   ev.src,   6);
        ep->msgNum    = ev.eapolMsg;
        ep->hasPMKID  = ev.eapolHasPMKID;
        ep->timestamp = millis();
        ep->ssid[0]   = '\0';
        if (ev.eapolHasPMKID) memcpy(ep->pmkid, ev.eapolPMKID, 16);
        // Lookup SSID from known APs
        for (int i = 0; i < apCount; i++) {
            if (memcmp(apList[i].bssid, ev.bssid, 6) == 0) {
                strncpy(ep->ssid, apList[i].ssid, 32);
                ep->ssid[32] = '\0';
                break;
            }
        }

        Serial.printf("[EAPOL] MSG%d AP=%02X:%02X:%02X:%02X:%02X:%02X "
                      "STA=%02X:%02X:%02X:%02X:%02X:%02X SSID=\"%s\" rssi=%d\n",
            ev.eapolMsg,
            ev.bssid[0],ev.bssid[1],ev.bssid[2],ev.bssid[3],ev.bssid[4],ev.bssid[5],
            ev.src[0],  ev.src[1],  ev.src[2],  ev.src[3],  ev.src[4],  ev.src[5],
            ep->ssid[0] ? ep->ssid : "?", (int)ev.rssi);

        if (ev.eapolHasPMKID) {
            // hashcat -m 22000 format: WPA*01*PMKID*BSSID*STA*SSID_HEX*
            char pmkHex[33], bssidHex[13], staHex[13], ssidHex[65];
            for (int i=0;i<16;i++) snprintf(&pmkHex[i*2],  3, "%02x", ev.eapolPMKID[i]);
            for (int i=0;i<6; i++) snprintf(&bssidHex[i*2],3, "%02x", ev.bssid[i]);
            for (int i=0;i<6; i++) snprintf(&staHex[i*2],  3, "%02x", ev.src[i]);
            ssidHex[0] = '\0';
            for (int i=0; ep->ssid[i] && i<32; i++)
                snprintf(&ssidHex[i*2], 3, "%02x", (uint8_t)ep->ssid[i]);
            Serial.printf("[PMKID] WPA*01*%s*%s*%s*%s*\n",
                          pmkHex, bssidHex, staHex, ssidHex);
        }

        // Add to alerts tab
        addAlert(ALT_EAPOL_CAP, ev.channel, ev.rssi, ev.bssid, ev.src, ev.eapolMsg);
    }
}

// ================================================================
// LVGL display flush
// ================================================================
static void disp_flush_cb(lv_disp_drv_t *drv,
                           const lv_area_t *area,
                           lv_color_t *color_p)
{
    uint32_t w = (uint32_t)(area->x2 - area->x1 + 1);
    uint32_t h = (uint32_t)(area->y2 - area->y1 + 1);
    tft.startWrite();
    tft.setAddrWindow(area->x1, area->y1, w, h);
    tft.pushColors((uint16_t *)&color_p->full, w * h, true);
    tft.endWrite();
    lv_disp_flush_ready(drv);
}

// ================================================================
// LVGL touch read
// ================================================================
static void touch_read_cb(lv_indev_drv_t *drv, lv_indev_data_t *data)
{
    (void)drv;
    uint8_t tdStatus = 0;
    Wire.beginTransmission(0x38);
    Wire.write(0x02);
    Wire.endTransmission(false);
    delayMicroseconds(100);
    if (Wire.requestFrom(0x38, 1) == 1) {
        tdStatus = Wire.read();
    }
    uint8_t touchCount = tdStatus & 0x0F;

    if (touchCount > 0) {
        uint8_t buf[4] = {0};
        Wire.beginTransmission(0x38);
        Wire.write(0x03);
        Wire.endTransmission(false);
        if (Wire.requestFrom(0x38, 4) == 4) {
            buf[0] = Wire.read();
            buf[1] = Wire.read();
            buf[2] = Wire.read();
            buf[3] = Wire.read();
        }
        uint16_t rawX = ((buf[0] & 0x0F) << 8) | buf[1];
        uint16_t rawY = ((buf[2] & 0x0F) << 8) | buf[3];
        if (rawX < SCR_W && rawY < SCR_H) {
            data->state   = LV_INDEV_STATE_PR;
            data->point.x = (lv_coord_t)rawX;
            data->point.y = (lv_coord_t)rawY;
        } else {
            data->state = LV_INDEV_STATE_REL;
        }
    } else {
        data->state = LV_INDEV_STATE_REL;
    }
}

// ================================================================
// Display + LVGL inicializacija
// ================================================================
static void initDisplay()
{
    Serial.println("[INIT] ft6336.begin()...");
    ft6336.begin();
    // I2C probe to verify touch chip responds
    Wire.beginTransmission(0x38);
    uint8_t i2cErr = Wire.endTransmission();
    Serial.printf("[INIT] FT6336U I2C probe: %s (err=%d)\n",
        i2cErr == 0 ? "OK" : "FAIL", i2cErr);

    Serial.println("[INIT] lv_init()...");
    lv_init();

    Serial.println("[INIT] tft.begin()...");
    tft.begin();
    tft.setRotation(0);
    Serial.println("[INIT] TFT OK");

    // Re-init I2C after TFT SPI init (tft.begin may affect bus)
    Wire.begin(PIN_SDA, PIN_SCL);
    delay(50);

    Serial.println("[INIT] FT6336U touch OK");

    tft.fillScreen(TFT_BLUE);
    Serial.println("[INIT] TFT fillScreen(BLUE) done");

    lv_disp_draw_buf_init(&disp_draw_buf, lv_draw_buf, nullptr, SCR_W * 15);

    static lv_disp_drv_t disp_drv;
    lv_disp_drv_init(&disp_drv);
    disp_drv.hor_res  = SCR_W;
    disp_drv.ver_res  = SCR_H;
    disp_drv.flush_cb = disp_flush_cb;
    disp_drv.draw_buf = &disp_draw_buf;
    lv_disp_drv_register(&disp_drv);

    static lv_indev_drv_t indev_drv;
    lv_indev_drv_init(&indev_drv);
    indev_drv.type    = LV_INDEV_TYPE_POINTER;
    indev_drv.read_cb = touch_read_cb;
    lv_indev_drv_register(&indev_drv);
    Serial.println("[INIT] LVGL registered OK");
}

// ================================================================
// BLE callback — AirTag / Flipper / skimmer detection
// Runs in BLE stack FreeRTOS task
// ================================================================
class BLECb : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice dev) override {
        if (!bleMutex) return;
        if (xSemaphoreTake(bleMutex, pdMS_TO_TICKS(10)) != pdTRUE) return;

        std::string macStr = dev.getAddress().toString();
        uint32_t now = millis();

        for (int i = 0; i < bleCount; i++) {
            if (macStr == bleList[i].mac) {
                bleList[i].rssi     = dev.getRSSI();
                bleList[i].lastSeen = now;
                bleListDirty = true;
                xSemaphoreGive(bleMutex);
                return;
            }
        }

        if (bleCount < MAX_BLES) {
            BLEInfo &e = bleList[bleCount];
            strncpy(e.mac, macStr.c_str(), 17);
            e.mac[17]   = '\0';
            e.rssi      = dev.getRSSI();
            e.lastSeen  = now;
            e.isAirTag  = false;
            e.isFlipper = false;
            e.isSkimmer = false;

            if (dev.haveName() && dev.getName().length() > 0) {
                strncpy(e.name, dev.getName().c_str(), 24);
                e.name[24] = '\0';
            } else {
                snprintf(e.name, sizeof(e.name), "%.8s..", macStr.c_str());
            }

            e.mfg[0] = '\0';
            if (dev.haveManufacturerData()) {
                std::string md = dev.getManufacturerData();
                if (md.length() >= 2) {
                    uint16_t cid = (uint8_t)md[0] |
                                   ((uint16_t)(uint8_t)md[1] << 8);
                    const char *m = lookupBLEMfg(cid);
                    if (m) { strncpy(e.mfg, m, 11); e.mfg[11] = '\0'; }
                    else   { snprintf(e.mfg, sizeof(e.mfg), "0x%04X", cid); }

                    // AirTag: Apple CID + FindMy payload (type=0x12 len=0x19)
                    if (cid == 0x004C && md.length() >= 4 &&
                        (uint8_t)md[2] == 0x12 && (uint8_t)md[3] == 0x19) {
                        e.isAirTag = true;
                        strncpy(e.mfg, "AirTag!", 11);
                    }
                    // Flipper Zero
                    else if (cid == 0x0BA0) {
                        e.isFlipper = true;
                        strncpy(e.mfg, "Flipper!", 11);
                    }
                }
            }

            // Skimerio heuristika: bekardis + stiprus signalas + nezinomas CID
            if (!dev.haveName() && dev.getRSSI() > -60 &&
                !e.isAirTag && !e.isFlipper &&
                e.mfg[0] == '0' && e.mfg[1] == 'x')
            {
                e.isSkimmer = true;
            }

            bleCount++;
            bleListDirty = true;

            if (e.isAirTag || e.isFlipper || e.isSkimmer) {
                Serial.printf("[BLE!] %-8s %s rssi=%d\n",
                    e.isAirTag ? "AirTag" : e.isFlipper ? "Flipper" : "SKIMMER?",
                    e.mac, (int)e.rssi);
            }
        }

        xSemaphoreGive(bleMutex);
    }
};

// ================================================================
// BLE irasu valymas po BLE_EXPIRE_MS
// ================================================================
static void expireBLEEntries()
{
    if (!bleMutex) return;
    if (xSemaphoreTake(bleMutex, pdMS_TO_TICKS(10)) != pdTRUE) return;

    uint32_t now = millis();
    int i = 0;
    while (i < bleCount) {
        if (now - bleList[i].lastSeen > BLE_EXPIRE_MS) {
            Serial.printf("[BLE-] expired %s\n", bleList[i].mac);
            memmove(&bleList[i], &bleList[i + 1],
                    (bleCount - i - 1) * sizeof(BLEInfo));
            bleCount--;
            bleListDirty = true;
        } else {
            i++;
        }
    }
    xSemaphoreGive(bleMutex);
}

// ================================================================
// STA irasu valymas po STA_EXPIRE_MS
// ================================================================
static void expireStaEntries()
{
    if (!staMutex) return;
    if (xSemaphoreTake(staMutex, pdMS_TO_TICKS(10)) != pdTRUE) return;
    uint32_t now = millis();
    int i = 0;
    while (i < staCount) {
        if (now - staList[i].lastSeen > STA_EXPIRE_MS) {
            memmove(&staList[i], &staList[i+1], (staCount-i-1)*sizeof(STAInfo));
            staCount--;
            staListDirty = true;
        } else {
            i++;
        }
    }
    xSemaphoreGive(staMutex);
}

// ================================================================
// UI helper: bendra lenteles stilistika
// ================================================================
static void styleTable(lv_obj_t *tbl)
{
    lv_obj_set_style_bg_color(tbl, lv_color_make(18,18,18), LV_PART_MAIN);
    lv_obj_set_style_bg_color(tbl, lv_color_make(28,28,28),
                              LV_PART_ITEMS | LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(tbl, lv_color_make(45,45,45),
                              LV_PART_ITEMS | LV_STATE_CHECKED);
    lv_obj_set_style_text_font(tbl, &lv_font_montserrat_12,
                               LV_PART_ITEMS | LV_STATE_DEFAULT);
    lv_obj_set_style_pad_top(tbl,    2, LV_PART_ITEMS);
    lv_obj_set_style_pad_bottom(tbl, 2, LV_PART_ITEMS);
    lv_obj_set_style_pad_left(tbl,   3, LV_PART_ITEMS);
    lv_obj_set_style_pad_right(tbl,  3, LV_PART_ITEMS);
    lv_obj_set_style_border_color(tbl, lv_color_make(55,55,55),
                                  LV_PART_ITEMS);
    lv_obj_set_style_border_width(tbl, 1, LV_PART_ITEMS);
    lv_obj_set_style_border_side(tbl,
        LV_BORDER_SIDE_BOTTOM | LV_BORDER_SIDE_RIGHT,
        LV_PART_ITEMS);
}

// --- WiFi tab -------------------------------------------------
static void buildWifiTab(lv_obj_t *parent)
{
    lv_obj_set_style_bg_color(parent, lv_color_black(), 0);
    lv_obj_set_scroll_dir(parent, LV_DIR_VER);

    statusLbl = lv_label_create(parent);
    lv_label_set_text(statusLbl, "Monitor mode...");
    lv_obj_set_style_text_color(statusLbl, lv_color_make(100,220,100), 0);
    lv_obj_set_style_text_font(statusLbl, &lv_font_montserrat_12, 0);
    lv_obj_align(statusLbl, LV_ALIGN_TOP_LEFT, 2, 2);

    alertBadge = lv_label_create(parent);
    lv_label_set_text(alertBadge, "");
    lv_obj_set_style_text_color(alertBadge, lv_color_make(255,60,60), 0);
    lv_obj_set_style_text_font(alertBadge, &lv_font_montserrat_12, 0);
    lv_obj_align(alertBadge, LV_ALIGN_TOP_RIGHT, -2, 2);

    // SSID | CH | dBm | Enc/Vendor | BSSID (pask. 3 oktetai)
    wifiTable = lv_table_create(parent);
    lv_table_set_col_cnt(wifiTable, 5);
    lv_table_set_col_width(wifiTable, 0, 70);
    lv_table_set_col_width(wifiTable, 1, 22);
    lv_table_set_col_width(wifiTable, 2, 30);
    lv_table_set_col_width(wifiTable, 3, 46);
    lv_table_set_col_width(wifiTable, 4, 50);
    lv_obj_set_width(wifiTable, SCR_W - 2);
    lv_obj_align(wifiTable, LV_ALIGN_TOP_LEFT, 1, 18);

    lv_table_set_cell_value(wifiTable, 0, 0, "SSID");
    lv_table_set_cell_value(wifiTable, 0, 1, "CH");
    lv_table_set_cell_value(wifiTable, 0, 2, "dBm");
    lv_table_set_cell_value(wifiTable, 0, 3, "Enc");
    lv_table_set_cell_value(wifiTable, 0, 4, "BSSID");

    styleTable(wifiTable);
    lv_obj_set_style_text_color(wifiTable, lv_color_make(200,200,255),
                                LV_PART_ITEMS | LV_STATE_DEFAULT);
}

// --- Spectrogram tab ------------------------------------------
static void buildSpectTab(lv_obj_t *parent)
{
    lv_obj_set_style_bg_color(parent, lv_color_black(), 0);

    lv_obj_t *title = lv_label_create(parent);
    lv_label_set_text(title, "2.4 GHz Channel Activity (pkts/1.5s)");
    lv_obj_set_style_text_color(title, lv_color_make(180,180,255), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_12, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 2);

    spectChart = lv_chart_create(parent);
    lv_obj_set_size(spectChart, SCR_W - 6, 220);
    lv_obj_align(spectChart, LV_ALIGN_TOP_MID, 0, 22);
    lv_chart_set_type(spectChart, LV_CHART_TYPE_BAR);
    lv_chart_set_range(spectChart, LV_CHART_AXIS_PRIMARY_Y, 0, 50);
    lv_chart_set_point_count(spectChart, 13);
    lv_chart_set_div_line_count(spectChart, 4, 0);
    lv_chart_set_zoom_x(spectChart, 256);

    lv_obj_set_style_bg_color(spectChart, lv_color_make(8,8,8), 0);
    lv_obj_set_style_border_color(spectChart, lv_color_make(70,70,70), 0);
    lv_obj_set_style_border_width(spectChart, 1, 0);
    lv_obj_set_style_line_color(spectChart, lv_color_make(45,45,45), LV_PART_MAIN);
    lv_obj_set_style_text_color(spectChart, lv_color_make(160,160,160), 0);
    lv_obj_set_style_text_font(spectChart, &lv_font_montserrat_12, 0);

    spectSer = lv_chart_add_series(spectChart, lv_color_make(0,210,0),
                                   LV_CHART_AXIS_PRIMARY_Y);
    for (int i = 0; i < 13; i++)
        lv_chart_set_value_by_id(spectChart, spectSer, (uint16_t)i, 0);

    lv_obj_t *chLbl = lv_label_create(parent);
    lv_label_set_text(chLbl, "1  2  3  4  5  6  7  8  9  10 11 12 13");
    lv_obj_set_style_text_color(chLbl, lv_color_make(160,160,160), 0);
    lv_obj_set_style_text_font(chLbl, &lv_font_montserrat_12, 0);
    lv_obj_align_to(chLbl, spectChart, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 3);

    lv_obj_t *legend = lv_label_create(parent);
    lv_label_set_text(legend, "Y: paketai/1.5s | channel hopping ch1-13");
    lv_obj_set_style_text_color(legend, lv_color_make(110,110,110), 0);
    lv_obj_set_style_text_font(legend, &lv_font_montserrat_12, 0);
    lv_obj_set_width(legend, SCR_W - 4);
    lv_label_set_long_mode(legend, LV_LABEL_LONG_WRAP);
    lv_obj_align(legend, LV_ALIGN_BOTTOM_MID, 0, -2);
}

// --- BLE tab --------------------------------------------------
static void buildBleTab(lv_obj_t *parent)
{
    lv_obj_set_style_bg_color(parent, lv_color_black(), 0);
    lv_obj_set_scroll_dir(parent, LV_DIR_VER);

    lv_obj_t *title = lv_label_create(parent);
    lv_label_set_text(title, "BLE 60s exp | [AT]=AirTag [FZ]=Flipper");
    lv_obj_set_style_text_color(title, lv_color_make(120,200,255), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_12, 0);
    lv_obj_align(title, LV_ALIGN_TOP_LEFT, 2, 2);

    bleTable = lv_table_create(parent);
    lv_table_set_col_cnt(bleTable, 3);
    lv_table_set_col_width(bleTable, 0, 110);
    lv_table_set_col_width(bleTable, 1,  30);
    lv_table_set_col_width(bleTable, 2,  78);
    lv_obj_set_width(bleTable, SCR_W - 2);
    lv_obj_align(bleTable, LV_ALIGN_TOP_LEFT, 1, 18);

    lv_table_set_cell_value(bleTable, 0, 0, "Name / MAC");
    lv_table_set_cell_value(bleTable, 0, 1, "dBm");
    lv_table_set_cell_value(bleTable, 0, 2, "Mfg / Threat");

    styleTable(bleTable);
    lv_obj_set_style_text_color(bleTable, lv_color_make(200,200,255),
                                LV_PART_ITEMS | LV_STATE_DEFAULT);
}

// --- Alerts tab -----------------------------------------------
static void buildAlertsTab(lv_obj_t *parent)
{
    lv_obj_set_style_bg_color(parent, lv_color_black(), 0);
    lv_obj_set_scroll_dir(parent, LV_DIR_VER);

    lv_obj_t *title = lv_label_create(parent);
    lv_label_set_text(title, "Saugumo ivykiai (Deauth / EAPOL / OPEN)");
    lv_obj_set_style_text_color(title, lv_color_make(255,80,80), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_12, 0);
    lv_obj_align(title, LV_ALIGN_TOP_LEFT, 2, 2);

    alertTable = lv_table_create(parent);
    lv_table_set_col_cnt(alertTable, 3);
    lv_table_set_col_width(alertTable, 0,  58);
    lv_table_set_col_width(alertTable, 1,  92);
    lv_table_set_col_width(alertTable, 2,  68);
    lv_obj_set_width(alertTable, SCR_W - 2);
    lv_obj_align(alertTable, LV_ALIGN_TOP_LEFT, 1, 18);

    lv_table_set_cell_value(alertTable, 0, 0, "Type");
    lv_table_set_cell_value(alertTable, 0, 1, "Source MAC");
    lv_table_set_cell_value(alertTable, 0, 2, "Age/Info");

    styleTable(alertTable);
    lv_obj_set_style_text_color(alertTable, lv_color_make(255,150,150),
                                LV_PART_ITEMS | LV_STATE_DEFAULT);
}

// --- STA (Client Stations) tab --------------------------------
static void buildStaTab(lv_obj_t *parent)
{
    lv_obj_set_style_bg_color(parent, lv_color_black(), 0);
    lv_obj_set_scroll_dir(parent, LV_DIR_VER);

    lv_obj_t *title = lv_label_create(parent);
    lv_label_set_text(title, "Clients detected (2min expiry)");
    lv_obj_set_style_text_color(title, lv_color_make(100,255,200), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_12, 0);
    lv_obj_align(title, LV_ALIGN_TOP_LEFT, 2, 2);

    staTable = lv_table_create(parent);
    lv_table_set_col_cnt(staTable, 3);
    lv_table_set_col_width(staTable, 0, 100);
    lv_table_set_col_width(staTable, 1,  30);
    lv_table_set_col_width(staTable, 2,  88);
    lv_obj_set_width(staTable, SCR_W - 2);
    lv_obj_align(staTable, LV_ALIGN_TOP_LEFT, 1, 18);

    lv_table_set_cell_value(staTable, 0, 0, "Client MAC");
    lv_table_set_cell_value(staTable, 0, 1, "dBm");
    lv_table_set_cell_value(staTable, 0, 2, "AP last 3");

    styleTable(staTable);
    lv_obj_set_style_text_color(staTable, lv_color_make(180,255,180),
                                LV_PART_ITEMS | LV_STATE_DEFAULT);
}

// --- Summary tab ----------------------------------------------
static void buildSummaryTab(lv_obj_t *parent)
{
    lv_obj_set_style_bg_color(parent, lv_color_black(), 0);

    summaryLbl = lv_label_create(parent);
    lv_label_set_long_mode(summaryLbl, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(summaryLbl, SCR_W - 8);
    lv_obj_align(summaryLbl, LV_ALIGN_TOP_LEFT, 4, 4);
    lv_obj_set_style_text_color(summaryLbl, lv_color_make(210,210,210), 0);
    lv_obj_set_style_text_font(summaryLbl, &lv_font_montserrat_12, 0);
    lv_label_set_text(summaryLbl, "Scanning...");
}

// --- Viso UI kurimas ------------------------------------------
static void buildUI()
{
    lv_obj_set_style_bg_color(lv_scr_act(), lv_color_black(), 0);
    lv_obj_set_style_bg_opa(lv_scr_act(), LV_OPA_COVER, 0);

    tabview = lv_tabview_create(lv_scr_act(), LV_DIR_TOP, TAB_H);
    lv_obj_set_size(tabview, SCR_W, SCR_H);
    lv_obj_set_pos(tabview, 0, 0);
    lv_obj_set_style_bg_color(tabview, lv_color_black(), 0);

    lv_obj_t *btns = lv_tabview_get_tab_btns(tabview);
    lv_obj_set_style_bg_color(btns, lv_color_make(12,12,24), 0);
    lv_obj_set_style_text_color(btns, lv_color_make(200,200,200),
                                LV_PART_ITEMS | LV_STATE_DEFAULT);
    lv_obj_set_style_text_color(btns, lv_color_make(0,230,0),
                                LV_PART_ITEMS | LV_STATE_CHECKED);
    lv_obj_set_style_border_side(btns, LV_BORDER_SIDE_BOTTOM,
                                 LV_PART_ITEMS | LV_STATE_CHECKED);
    lv_obj_set_style_border_color(btns, lv_color_make(0,230,0),
                                  LV_PART_ITEMS | LV_STATE_CHECKED);
    lv_obj_set_style_border_width(btns, 2,
                                  LV_PART_ITEMS | LV_STATE_CHECKED);
    lv_obj_set_style_text_font(btns, &lv_font_montserrat_12,
                               LV_PART_ITEMS | LV_STATE_DEFAULT);

    lv_obj_t *t1 = lv_tabview_add_tab(tabview, "WiFi");
    lv_obj_t *t2 = lv_tabview_add_tab(tabview, "Spec");
    lv_obj_t *t3 = lv_tabview_add_tab(tabview, "STA");
    lv_obj_t *t4 = lv_tabview_add_tab(tabview, "BLE");
    lv_obj_t *t5 = lv_tabview_add_tab(tabview, "Alrt");
    lv_obj_t *t6 = lv_tabview_add_tab(tabview, "Sum");

    buildWifiTab(t1);
    buildSpectTab(t2);
    buildStaTab(t3);
    buildBleTab(t4);
    buildAlertsTab(t5);
    buildSummaryTab(t6);
}

// ================================================================
// UI atnaujinimo funkcijos
// ================================================================

static void updateWifiTable()
{
    if (!wifiTable) return;
    lv_table_set_row_cnt(wifiTable, (uint16_t)(apCount + 1));

    char buf[24];
    for (int i = 0; i < apCount; i++) {
        APInfo &ap = apList[i];
        uint16_t row = (uint16_t)(i + 1);

        const char *ssid = ap.ssid[0] ? ap.ssid : "(hidden)";
        if (strlen(ssid) > 9) {
            char tmp[11];
            memcpy(tmp, ssid, 8);
            tmp[8] = '.'; tmp[9] = '.'; tmp[10] = '\0';
            lv_table_set_cell_value(wifiTable, row, 0, tmp);
        } else {
            lv_table_set_cell_value(wifiTable, row, 0, ssid);
        }

        snprintf(buf, sizeof(buf), "%d", (int)ap.channel);
        lv_table_set_cell_value(wifiTable, row, 1, buf);

        snprintf(buf, sizeof(buf), "%d", (int)ap.rssi);
        lv_table_set_cell_value(wifiTable, row, 2, buf);

        if (ap.vendor[0])
            snprintf(buf, sizeof(buf), "%.4s/%s%s", ap.vendor,
                     encStr(ap.enc), ap.hasWPS ? "[W]" : "");
        else
            snprintf(buf, sizeof(buf), "%s%s",
                     encStr(ap.enc), ap.hasWPS ? "[W]" : "");
        lv_table_set_cell_value(wifiTable, row, 3, buf);

        snprintf(buf, sizeof(buf), "%02x:%02x:%02x",
                 ap.bssid[3], ap.bssid[4], ap.bssid[5]);
        lv_table_set_cell_value(wifiTable, row, 4, buf);
    }

    if (statusLbl) {
        char sbuf[42];
        snprintf(sbuf, sizeof(sbuf), "APs:%d ch%d", apCount, (int)currentChannel);
        lv_label_set_text(statusLbl, sbuf);
    }
}

static void updateSpectChart()
{
    if (!spectChart || !spectSer) return;

    uint32_t maxVal = 1;
    for (int i = 0; i < 13; i++) {
        displayPktCount[i] = chanPktCount[i];
        chanPktCount[i] = 0;
        if (displayPktCount[i] > maxVal) maxVal = displayPktCount[i];
    }

    lv_coord_t top = (lv_coord_t)(maxVal < 10 ? 20 : maxVal * 110 / 100);
    lv_chart_set_range(spectChart, LV_CHART_AXIS_PRIMARY_Y, 0, top);

    for (int i = 0; i < 13; i++) {
        lv_chart_set_value_by_id(spectChart, spectSer, (uint16_t)i,
                                 (lv_coord_t)displayPktCount[i]);
    }
    lv_chart_refresh(spectChart);
}

static void updateBleTable()
{
    if (!bleTable || !bleMutex) return;
    if (xSemaphoreTake(bleMutex, pdMS_TO_TICKS(20)) != pdTRUE) return;

    bleListDirty = false;
    int snap = bleCount;
    lv_table_set_row_cnt(bleTable, (uint16_t)(snap + 1));

    char buf[12];
    for (int i = 0; i < snap; i++) {
        BLEInfo &e = bleList[i];
        uint16_t row = (uint16_t)(i + 1);

        char nameBuf[28];
        if      (e.isAirTag)   snprintf(nameBuf, sizeof(nameBuf), "[AT] %s", e.name);
        else if (e.isFlipper)  snprintf(nameBuf, sizeof(nameBuf), "[FZ] %s", e.name);
        else if (e.isSkimmer)  snprintf(nameBuf, sizeof(nameBuf), "[SK?]%s", e.name);
        else                   strncpy(nameBuf, e.name, 27);
        nameBuf[27] = '\0';
        lv_table_set_cell_value(bleTable, row, 0, nameBuf);

        snprintf(buf, sizeof(buf), "%d", (int)e.rssi);
        lv_table_set_cell_value(bleTable, row, 1, buf);
        lv_table_set_cell_value(bleTable, row, 2, e.mfg[0] ? e.mfg : "-");
    }

    xSemaphoreGive(bleMutex);
}

static void updateAlertTable()
{
    if (!alertTable || !alertMutex) return;
    if (xSemaphoreTake(alertMutex, pdMS_TO_TICKS(20)) != pdTRUE) return;

    alertsDirty = false;
    int snap = alertCount;
    lv_table_set_row_cnt(alertTable, (uint16_t)(snap + 1));

    uint32_t now = millis();
    char buf[24];
    for (int i = 0; i < snap; i++) {
        AlertEvent &a = alertList[snap - 1 - i];
        uint16_t row = (uint16_t)(i + 1);

        const char *typStr = "?";
        if      (a.type == FEV_DEAUTH)    typStr = "DEAUTH";
        else if (a.type == FEV_DISASSOC)  typStr = "DISASC";
        else if (a.type == ALT_OPEN_NET)  typStr = "!OPEN";
        else if (a.type == ALT_EAPOL_CAP) typStr = "EAPOL";
        snprintf(buf, sizeof(buf), "%s ch%d", typStr, (int)a.channel);
        lv_table_set_cell_value(alertTable, row, 0, buf);

        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 a.src[0], a.src[1], a.src[2],
                 a.src[3], a.src[4], a.src[5]);
        lv_table_set_cell_value(alertTable, row, 1, buf);

        uint32_t age = (now - a.timestamp) / 1000UL;
        snprintf(buf, sizeof(buf), "%lus r=%d",
                 (unsigned long)age, (int)a.reason);
        lv_table_set_cell_value(alertTable, row, 2, buf);
    }

    xSemaphoreGive(alertMutex);

    if (alertBadge && snap > alertBadgeCount) {
        char badge[16];
        snprintf(badge, sizeof(badge), "!%d ATK", snap);
        lv_label_set_text(alertBadge, badge);
        alertBadgeCount = snap;
    }
}

static void updateStaTable()
{
    if (!staTable || !staMutex) return;
    if (xSemaphoreTake(staMutex, pdMS_TO_TICKS(20)) != pdTRUE) return;

    staListDirty = false;
    int snap = staCount;
    lv_table_set_row_cnt(staTable, (uint16_t)(snap + 1));

    char buf[20];
    for (int i = 0; i < snap; i++) {
        STAInfo &s = staList[i];
        uint16_t row = (uint16_t)(i + 1);

        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 s.mac[0],s.mac[1],s.mac[2],s.mac[3],s.mac[4],s.mac[5]);
        lv_table_set_cell_value(staTable, row, 0, buf);

        snprintf(buf, sizeof(buf), "%d", (int)s.rssi);
        lv_table_set_cell_value(staTable, row, 1, buf);

        snprintf(buf, sizeof(buf), "%02X:%02X:%02X",
                 s.bssid[3], s.bssid[4], s.bssid[5]);
        lv_table_set_cell_value(staTable, row, 2, buf);
    }
    xSemaphoreGive(staMutex);
}

static void updateSummaryTab()
{
    if (!summaryLbl) return;

    int cntOpen=0, cntWPS=0, cntWPA3=0, cntWPA2=0, cntWPA=0, cntWEP=0, cntHidden=0;
    for (int i = 0; i < apCount; i++) {
        if (apList[i].enc == WIFI_AUTH_OPEN) cntOpen++;
        if (apList[i].hasWPS)               cntWPS++;
        if (!apList[i].ssid[0])             cntHidden++;
        switch (apList[i].enc) {
            case WIFI_AUTH_WPA3_PSK:
            case WIFI_AUTH_WPA2_WPA3_PSK:   cntWPA3++; break;
            case WIFI_AUTH_WPA2_PSK:
            case WIFI_AUTH_WPA2_ENTERPRISE: cntWPA2++; break;
            case WIFI_AUTH_WPA_PSK:
            case WIFI_AUTH_WPA_WPA2_PSK:    cntWPA++;  break;
            case WIFI_AUTH_WEP:             cntWEP++;  break;
        }
    }
    int cntAirTag=0, cntSkimmer=0;
    if (bleMutex && xSemaphoreTake(bleMutex, pdMS_TO_TICKS(5))==pdTRUE) {
        for (int i=0;i<bleCount;i++) {
            if (bleList[i].isAirTag)  cntAirTag++;
            if (bleList[i].isSkimmer) cntSkimmer++;
        }
        xSemaphoreGive(bleMutex);
    }
    int deauthCnt=0;
    if (alertMutex && xSemaphoreTake(alertMutex, pdMS_TO_TICKS(5))==pdTRUE) {
        for (int i=0;i<alertCount;i++)
            if (alertList[i].type==FEV_DEAUTH || alertList[i].type==FEV_DISASSOC)
                deauthCnt++;
        xSemaphoreGive(alertMutex);
    }
    int staSnap=0;
    if (staMutex && xSemaphoreTake(staMutex, pdMS_TO_TICKS(5))==pdTRUE) {
        staSnap = staCount; xSemaphoreGive(staMutex);
    }
    uint32_t up = millis()/1000UL;
    char buf[380];
    snprintf(buf, sizeof(buf),
        "=== SCAN SUMMARY ===\n"
        "Uptime: %02lu:%02lu:%02lu\n\n"
        "--- WiFi ---\n"
        "APs: %d  |  STA: %d\n"
        "OPEN:   %d %s\n"
        "WPS:    %d %s\n"
        "WPA3:   %d\n"
        "WPA2:   %d\n"
        "WPA:    %d\n"
        "WEP:    %d %s\n"
        "Hidden: %d\n\n"
        "--- Threats ---\n"
        "Deauth: %d\n"
        "EAPOL:  %d\n\n"
        "--- BLE ---\n"
        "Total:  %d\n"
        "AirTag: %d\n"
        "Skim?:  %d %s",
        (unsigned long)(up/3600),
        (unsigned long)((up%3600)/60),
        (unsigned long)(up%60),
        apCount, staSnap,
        cntOpen,   cntOpen   > 0 ? "[!RISK]" : "",
        cntWPS,    cntWPS    > 0 ? "[WARN]"  : "",
        cntWPA3, cntWPA2, cntWPA,
        cntWEP,    cntWEP    > 0 ? "[!WEAK]" : "",
        cntHidden,
        deauthCnt, eapolCount,
        bleCount, cntAirTag,
        cntSkimmer, cntSkimmer > 0 ? "[!CHECK]" : "");
    lv_label_set_text(summaryLbl, buf);
}

// ================================================================
// Channel hopper
// ================================================================
static void hopChannel()
{
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
}

// ================================================================
// BLE skenavimo valdymas
// ================================================================
static void startBleScan()
{
    if (bleScanActive || !pBLEScan) return;
    pBLEScan->clearResults();
    pBLEScan->start(BLE_SCAN_SEC, /*is_continue=*/false);
    bleScanActive  = true;
    bleScanStartMs = millis();
    Serial.println("[BLE] Scan started");
}

static void checkBleScan()
{
    if (!bleScanActive) return;
    if (millis() - bleScanStartMs < (BLE_SCAN_SEC + 1) * 1000UL) return;
    pBLEScan->stop(); delay(50);
    bleScanActive = false;
    lastBleMs     = millis();
    Serial.printf("[BLE] Done: %d devices\n", bleCount);
    updateBleTable();
}

// ================================================================
// Arduino setup
// ================================================================
void setup()
{
    Serial.begin(115200);
    delay(1500);  // Daugiau laiko USB-CDC enumerate
    Serial.println("\n==================================================");
    Serial.println("  ESP32-S3 Security Scanner v3.0");
    Serial.println("  Promiscuous + BLE | Freenove FNK0086");
    Serial.println("==================================================");
    Serial.printf("  Free heap: %u bytes\n", ESP.getFreeHeap());

    Serial.println("[1/6] initDisplay...");
    initDisplay();
    Serial.println("[2/6] buildUI...");
    buildUI();
    lv_task_handler();
    Serial.println("[2/6] UI rendered OK");

    bleMutex = xSemaphoreCreateMutex();
    if (!bleMutex) {
        Serial.println("[FATAL] bleMutex kurimas nepavyko");
        while (true) delay(1000);
    }
    alertMutex = xSemaphoreCreateMutex();
    if (!alertMutex) {
        Serial.println("[FATAL] alertMutex kurimas nepavyko");
        while (true) delay(1000);
    }
    staMutex = xSemaphoreCreateMutex();
    if (!staMutex) {
        Serial.println("[FATAL] staMutex kurimas nepavyko");
        while (true) delay(1000);
    }
    frameQ = xQueueCreate(FRAME_Q_SIZE, sizeof(FrameEvent));
    if (!frameQ) {
        Serial.println("[FATAL] frameQ kurimas nepavyko");
        while (true) delay(1000);
    }
    Serial.println("[3/6] Mutexes + queue OK");

    // WiFi promiscuous rezimas — naudojam ESP-IDF API tiesiogiai
    Serial.println("[4/6] WiFi promiscuous...");
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    delay(100);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuous_cb);
    // Enable data frames for station + EAPOL detection
    wifi_promiscuous_filter_t promis_filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    esp_wifi_set_promiscuous_filter(&promis_filter);
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    currentChannel = 1;
    chanHopMs = millis();
    Serial.println("[4/6] WiFi promiscuous ON");

    // WiFi pirmenybe priesais BLE
    Serial.println("[5/6] Coex + BLE init...");
    esp_coex_preference_set(ESP_COEX_PREFER_WIFI);
    Serial.println("[WiFi] coex=WIFI set");

    BLEDevice::init("");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new BLECb(), /*wantDuplicates=*/true);
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(100);
    pBLEScan->setWindow(99);
    Serial.println("[5/6] BLE init OK");

    Serial.println("[6/6] Pradedamas BLE skenavimas...");
    startBleScan();
    Serial.printf("[DONE] Setup complete! Free heap: %u\n", ESP.getFreeHeap());
}

// ================================================================
// Arduino loop
// ================================================================
void loop()
{
    uint32_t now = millis();

    // LVGL tick (v8 reikalavimas animacijoms ir input timeout)
    static uint32_t lastTickMs = 0;
    uint32_t tickElapsed = now - lastTickMs;
    if (tickElapsed > 0) {
        lv_tick_inc(tickElapsed);
        lastTickMs = now;
    }
    lv_task_handler();

    // Channel hopping
    if (now - chanHopMs >= CHAN_DWELL_MS) {
        hopChannel();
        chanHopMs = now;
    }

    // Frame event eiles issalinimas (iki 8 per iteracija)
    FrameEvent ev;
    int processed = 0;
    while (processed < 8 && xQueueReceive(frameQ, &ev, 0) == pdTRUE) {
        processFrameEvent(ev);
        processed++;
    }

    // WiFi lenteles atnaujinimas
    static uint32_t lastWifiUpdateMs = 0;
    if (now - lastWifiUpdateMs >= WIFI_TABLE_MS) {
        updateWifiTable();
        lastWifiUpdateMs = now;
        // Debug: ar promiscuous callback kviečiamas?
        static uint32_t lastPromDbg = 0;
        if (now - lastPromDbg >= 5000) {
            Serial.printf("[DBG] promisc_calls=%u apCount=%d qFree=%d\n",
                promiscCallCount, apCount,
                frameQ ? (int)uxQueueSpacesAvailable(frameQ) : -1);
            lastPromDbg = now;
        }
    }

    // Spektogramos atnaujinimas
    if (now - spectLastMs >= SPECT_UPDATE_MS) {
        updateSpectChart();
        spectLastMs = now;
    }

    // BLE scan ciklas
    checkBleScan();
    if (!bleScanActive && now - lastBleMs >= BLE_RESCAN_MS) {
        startBleScan();
    }

    // BLE pasibaigusiu irasu valymas
    static uint32_t lastExpireMs = 0;
    if (now - lastExpireMs >= BLE_EXPIRE_CHK) {
        expireBLEEntries();
        expireStaEntries();
        lastExpireMs = now;
    }

    if (bleListDirty)  updateBleTable();
    if (alertsDirty)   updateAlertTable();
    if (staListDirty)  updateStaTable();

    // Summary tab update every 5s
    static uint32_t lastSumMs = 0;
    if (now - lastSumMs >= 5000) {
        updateSummaryTab();
        lastSumMs = now;
    }

    // Serial tab control: send '1'-'6' to switch tabs
    while (Serial.available()) {
        char c = Serial.read();
        if (c >= '1' && c <= '6') {
            uint8_t t = c - '1';
            lv_tabview_set_act(tabview, t, LV_ANIM_ON);
            Serial.printf("[TAB] Switched to tab %d\n", t + 1);
        }
    }
}
