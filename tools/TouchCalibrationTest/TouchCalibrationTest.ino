/*
 * TouchCalibrationTest.ino — FT6336U Touch Diagnostics
 * https://github.com/ViliusKsg/SpectraScan
 * 
 * Hardware: Freenove ESP32-S3 FNK0086 (ST7789 240x320, FT6336U touch)
 * 
 * Tests:
 *   1. Chip info & register dump
 *   2. Raw touch data stream (5 seconds)
 *   3. Crosshair accuracy — 5 points with offset/swap/inversion detection
 *   4. Grid hit test — 3x4 grid (12 cells)
 *   5. Free draw mode (10 seconds)
 * 
 * Serial output: 115200 baud — full diagnostics via Serial
 * On-screen: visual feedback for each test
 *
 * Use this tool to verify touch hardware before modifying SpectraScan firmware.
 */

#include <Arduino.h>
#include <Wire.h>
#include <TFT_eSPI.h>

// Hardware pins
#define PIN_TFT_BL  45
#define PIN_SDA      2
#define PIN_SCL      1

// Screen
#define SCR_W  240
#define SCR_H  320

// FT6336U I2C address
#define FT_ADDR  0x38

// FT6336U registers
#define FT_REG_TD_STATUS   0x02
#define FT_REG_P1_XH       0x03
#define FT_REG_P1_XL       0x04
#define FT_REG_P1_YH       0x05
#define FT_REG_P1_YL       0x06
#define FT_REG_CHIP_ID     0xA3
#define FT_REG_FW_VER      0xA6
#define FT_REG_THRESH      0x80
#define FT_REG_CTRL        0x86
#define FT_REG_MODE        0xA4

TFT_eSPI tft = TFT_eSPI();

// ================================================================
// I2C helpers
// ================================================================
uint8_t ft_readReg(uint8_t reg) {
    Wire.beginTransmission(FT_ADDR);
    Wire.write(reg);
    Wire.endTransmission(false);
    if (Wire.requestFrom((int)FT_ADDR, 1) == 1) {
        return Wire.read();
    }
    return 0xFF;
}

void ft_writeReg(uint8_t reg, uint8_t val) {
    Wire.beginTransmission(FT_ADDR);
    Wire.write(reg);
    Wire.write(val);
    Wire.endTransmission();
}

bool ft_readTouch(uint16_t &x, uint16_t &y, uint8_t &touches) {
    Wire.beginTransmission(FT_ADDR);
    Wire.write(FT_REG_TD_STATUS);
    Wire.endTransmission(false);
    
    if (Wire.requestFrom((int)FT_ADDR, 5) != 5) {
        touches = 0;
        return false;
    }
    
    uint8_t tdStatus = Wire.read();
    uint8_t xh = Wire.read();
    uint8_t xl = Wire.read();
    uint8_t yh = Wire.read();
    uint8_t yl = Wire.read();
    
    touches = tdStatus & 0x0F;
    x = ((xh & 0x0F) << 8) | xl;
    y = ((yh & 0x0F) << 8) | yl;
    
    return (touches > 0);
}

// ================================================================
// Test 1: Chip info & raw register dump
// ================================================================
void testChipInfo() {
    Serial.println("\n========================================");
    Serial.println("  TEST 1: FT6336U Chip Info");
    Serial.println("========================================");
    
    // I2C probe
    Wire.beginTransmission(FT_ADDR);
    uint8_t err = Wire.endTransmission();
    Serial.printf("I2C probe 0x%02X: %s (err=%d)\n", FT_ADDR, err == 0 ? "OK" : "FAIL", err);
    
    if (err != 0) {
        Serial.println("!!! Touch chip not responding. Check wiring.");
        return;
    }
    
    uint8_t chipId = ft_readReg(FT_REG_CHIP_ID);
    uint8_t fwVer  = ft_readReg(FT_REG_FW_VER);
    uint8_t thresh = ft_readReg(FT_REG_THRESH);
    uint8_t ctrl   = ft_readReg(FT_REG_CTRL);
    uint8_t mode   = ft_readReg(FT_REG_MODE);
    
    Serial.printf("Chip ID:    0x%02X (expected 0x64 for FT6336U)\n", chipId);
    Serial.printf("FW Version: 0x%02X\n", fwVer);
    Serial.printf("Threshold:  %d\n", thresh);
    Serial.printf("CTRL reg:   0x%02X (0=keep active, 1=auto sleep)\n", ctrl);
    Serial.printf("MODE reg:   0x%02X (0=working, 4=factory)\n", mode);
    
    // Force active mode
    ft_writeReg(FT_REG_CTRL, 0x00);
    Serial.println("Set CTRL=0x00 (keep active, no auto-sleep)");
    
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.setTextSize(1);
    tft.setCursor(10, 10);
    tft.printf("FT6336U Info:");
    tft.setCursor(10, 30);
    tft.printf("Chip: 0x%02X FW: 0x%02X", chipId, fwVer);
    tft.setCursor(10, 50);
    tft.printf("Thresh: %d  Ctrl: 0x%02X", thresh, ctrl);
    tft.setCursor(10, 80);
    tft.setTextColor(TFT_YELLOW);
    tft.printf("Touch screen now...");
    tft.setCursor(10, 100);
    tft.printf("(watching 5 seconds)");
}

// ================================================================
// Test 2: Raw touch data stream (5 seconds)
// ================================================================
void testRawStream() {
    Serial.println("\n========================================");
    Serial.println("  TEST 2: Raw Touch Data (5s)");
    Serial.println("  Touch the screen repeatedly!");
    Serial.println("========================================");
    Serial.println("Format: TD_STATUS | touches | rawX | rawY | event");
    Serial.println("---");
    
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_CYAN, TFT_BLACK);
    tft.setCursor(10, 10);
    tft.printf("TEST 2: Raw Touch Data");
    tft.setCursor(10, 30);
    tft.printf("Touch anywhere!");
    tft.setCursor(10, 50);
    tft.printf("Watch Serial output...");
    
    uint32_t start = millis();
    int touchEvents = 0;
    
    while (millis() - start < 5000) {
        // Read full touch packet
        Wire.beginTransmission(FT_ADDR);
        Wire.write(0x00);  // Start from reg 0x00
        Wire.endTransmission(false);
        
        uint8_t buf[7];
        if (Wire.requestFrom((int)FT_ADDR, 7) == 7) {
            for (int i = 0; i < 7; i++) buf[i] = Wire.read();
        }
        
        uint8_t tdStatus = buf[2];
        uint8_t touches = tdStatus & 0x0F;
        uint8_t event = (buf[3] >> 6) & 0x03; // 0=down, 1=up, 2=contact
        uint16_t rawX = ((buf[3] & 0x0F) << 8) | buf[4];
        uint16_t rawY = ((buf[5] & 0x0F) << 8) | buf[6];
        
        if (touches > 0) {
            const char* evNames[] = {"DOWN", "UP", "CONTACT", "???"};
            Serial.printf("TD=0x%02X | touches=%d | X=%3d Y=%3d | %s\n",
                          tdStatus, touches, rawX, rawY, evNames[event]);
            
            // Draw dot on screen
            tft.fillCircle(rawX, rawY, 3, TFT_RED);
            touchEvents++;
        }
        
        delay(20);
    }
    
    Serial.printf("\n>>> Total touch events in 5s: %d\n", touchEvents);
    if (touchEvents == 0) {
        Serial.println("!!! NO TOUCHES DETECTED - TD_STATUS never > 0");
        Serial.println("    Possible causes:");
        Serial.println("    - Touch panel flex cable loose");
        Serial.println("    - FT6336U INT pin issue");
        Serial.println("    - Chip in sleep mode (try CTRL=0x00)");
    }
}

// ================================================================
// Test 3: Crosshair accuracy test (tap 5 marked positions)
// ================================================================
struct CalPoint {
    int16_t screenX, screenY;  // Where we draw the target
    int16_t touchX, touchY;    // Where the user actually touched
    bool captured;
};

#define NUM_CAL_POINTS 5
CalPoint calPoints[NUM_CAL_POINTS] = {
    {SCR_W/2, SCR_H/2, 0, 0, false},   // Center
    {30, 30, 0, 0, false},              // Top-left
    {SCR_W-30, 30, 0, 0, false},        // Top-right
    {30, SCR_H-30, 0, 0, false},        // Bottom-left
    {SCR_W-30, SCR_H-30, 0, 0, false},  // Bottom-right
};

void drawCrosshair(int16_t x, int16_t y, uint16_t color) {
    tft.drawLine(x-15, y, x+15, y, color);
    tft.drawLine(x, y-15, x, y+15, color);
    tft.drawCircle(x, y, 10, color);
}

bool waitForTouch(uint16_t &x, uint16_t &y, uint32_t timeout_ms) {
    uint32_t start = millis();
    bool wasPressed = false;
    uint16_t lastX = 0, lastY = 0;
    
    // Wait for press
    while (millis() - start < timeout_ms) {
        uint8_t touches;
        uint16_t tx, ty;
        if (ft_readTouch(tx, ty, touches)) {
            wasPressed = true;
            lastX = tx;
            lastY = ty;
        } else if (wasPressed) {
            // Was pressed, now released — return last position
            x = lastX;
            y = lastY;
            return true;
        }
        delay(20);
    }
    
    // If still pressing at timeout, use last pos
    if (wasPressed) {
        x = lastX;
        y = lastY;
        return true;
    }
    return false;
}

void testCrosshair() {
    Serial.println("\n========================================");
    Serial.println("  TEST 3: Crosshair Accuracy");
    Serial.println("  Tap EXACTLY on each crosshair!");
    Serial.println("========================================");
    
    for (int i = 0; i < NUM_CAL_POINTS; i++) {
        tft.fillScreen(TFT_BLACK);
        tft.setTextColor(TFT_WHITE);
        tft.setCursor(10, SCR_H/2 - 40);
        tft.printf("Tap crosshair #%d", i+1);
        tft.setCursor(10, SCR_H/2 - 20);
        tft.printf("Target: (%d, %d)", calPoints[i].screenX, calPoints[i].screenY);
        
        drawCrosshair(calPoints[i].screenX, calPoints[i].screenY, TFT_GREEN);
        
        uint16_t tx, ty;
        if (waitForTouch(tx, ty, 10000)) {
            calPoints[i].touchX = tx;
            calPoints[i].touchY = ty;
            calPoints[i].captured = true;
            
            // Show where they actually touched
            tft.fillCircle(tx, ty, 5, TFT_RED);
            
            int16_t dx = tx - calPoints[i].screenX;
            int16_t dy = ty - calPoints[i].screenY;
            float dist = sqrt(dx*dx + dy*dy);
            
            Serial.printf("Point %d: Target(%3d,%3d) -> Touch(%3d,%3d) | "
                          "Offset: dx=%+4d dy=%+4d dist=%.1fpx\n",
                          i+1, calPoints[i].screenX, calPoints[i].screenY,
                          tx, ty, dx, dy, dist);
            
            delay(800);
        } else {
            Serial.printf("Point %d: TIMEOUT (no touch)\n", i+1);
            calPoints[i].captured = false;
        }
    }
    
    // Summary
    Serial.println("\n--- Accuracy Summary ---");
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_GREEN);
    tft.setCursor(10, 10);
    tft.printf("Accuracy Results:");
    
    float totalDist = 0;
    int captured = 0;
    int avgDx = 0, avgDy = 0;
    
    for (int i = 0; i < NUM_CAL_POINTS; i++) {
        if (calPoints[i].captured) {
            int16_t dx = calPoints[i].touchX - calPoints[i].screenX;
            int16_t dy = calPoints[i].touchY - calPoints[i].screenY;
            float dist = sqrt(dx*dx + dy*dy);
            totalDist += dist;
            avgDx += dx;
            avgDy += dy;
            captured++;
            
            tft.setCursor(10, 30 + i*20);
            tft.printf("#%d: dx=%+d dy=%+d (%.0fpx)", i+1, dx, dy, dist);
        }
    }
    
    if (captured > 0) {
        avgDx /= captured;
        avgDy /= captured;
        float avgDist = totalDist / captured;
        
        Serial.printf("\nAvg offset: dx=%+d, dy=%+d\n", avgDx, avgDy);
        Serial.printf("Avg distance: %.1f px\n", avgDist);
        Serial.printf("Points captured: %d/%d\n", captured, NUM_CAL_POINTS);
        
        tft.setCursor(10, 140);
        tft.setTextColor(TFT_YELLOW);
        tft.printf("Avg: dx=%+d dy=%+d", avgDx, avgDy);
        tft.setCursor(10, 160);
        tft.printf("Avg dist: %.1f px", avgDist);
        
        // Diagnosis
        tft.setCursor(10, 200);
        tft.setTextColor(TFT_CYAN);
        if (avgDist < 10) {
            tft.printf("GOOD - minimal offset");
            Serial.println("DIAGNOSIS: Touch calibration OK (< 10px avg)");
        } else if (abs(avgDx) > 20 || abs(avgDy) > 20) {
            tft.printf("OFFSET: needs X/Y correction");
            Serial.println("DIAGNOSIS: Systematic offset — needs calibration correction");
            Serial.printf("  Suggested: subtract dx=%d, dy=%d from raw coords\n", avgDx, avgDy);
        } else {
            tft.printf("ROTATION: X/Y may be swapped");
            Serial.println("DIAGNOSIS: Possible X/Y swap or rotation mismatch");
        }
        
        // Check for X/Y swap pattern
        bool possibleSwap = false;
        for (int i = 0; i < NUM_CAL_POINTS; i++) {
            if (calPoints[i].captured) {
                int dx = abs(calPoints[i].touchX - calPoints[i].screenX);
                int dy = abs(calPoints[i].touchY - calPoints[i].screenY);
                // If touch X correlates more with screen Y...
                int dxSwap = abs(calPoints[i].touchX - calPoints[i].screenY);
                int dySwap = abs(calPoints[i].touchY - calPoints[i].screenX);
                if (dxSwap + dySwap < dx + dy - 30) {
                    possibleSwap = true;
                }
            }
        }
        if (possibleSwap) {
            Serial.println("WARNING: X/Y axes may be SWAPPED!");
            Serial.println("  Try: swap rawX <-> rawY in touch_read_cb");
            tft.setCursor(10, 230);
            tft.setTextColor(TFT_RED);
            tft.printf("!!! X/Y SWAPPED !!!");
        }
        
        // Check for inversion
        bool xInverted = false, yInverted = false;
        int leftTouch = 0, rightTouch = 0;
        int topTouch = 0, bottomTouch = 0;
        int cnt = 0;
        for (int i = 0; i < NUM_CAL_POINTS; i++) {
            if (!calPoints[i].captured) continue;
            if (calPoints[i].screenX < SCR_W/2) leftTouch += calPoints[i].touchX;
            else rightTouch += calPoints[i].touchX;
            if (calPoints[i].screenY < SCR_H/2) topTouch += calPoints[i].touchY;
            else bottomTouch += calPoints[i].touchY;
        }
        // If touching left side gives higher X values -> X inverted
        if (leftTouch > rightTouch && captured >= 3) {
            xInverted = true;
            Serial.println("WARNING: X axis appears INVERTED!");
            Serial.printf("  Try: rawX = %d - rawX\n", SCR_W - 1);
        }
        if (topTouch > bottomTouch && captured >= 3) {
            yInverted = true;
            Serial.println("WARNING: Y axis appears INVERTED!");
            Serial.printf("  Try: rawY = %d - rawY\n", SCR_H - 1);
        }
    }
}

// ================================================================
// Test 4: Grid test — 3x4 grid, tap each cell
// ================================================================
void testGrid() {
    Serial.println("\n========================================");
    Serial.println("  TEST 4: Grid Test (3x4)");
    Serial.println("  Tap each highlighted cell!");
    Serial.println("========================================");
    
    const int cols = 3, rows = 4;
    int cellW = SCR_W / cols;
    int cellH = SCR_H / rows;
    int hits = 0, misses = 0;
    
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++) {
            tft.fillScreen(TFT_BLACK);
            
            // Draw grid
            for (int i = 0; i <= cols; i++)
                tft.drawLine(i * cellW, 0, i * cellW, SCR_H, TFT_DARKGREY);
            for (int i = 0; i <= rows; i++)
                tft.drawLine(0, i * cellH, SCR_W, i * cellH, TFT_DARKGREY);
            
            // Highlight target cell
            int cx = c * cellW + cellW/2;
            int cy = r * cellH + cellH/2;
            tft.fillRect(c * cellW + 2, r * cellH + 2, cellW - 4, cellH - 4, TFT_NAVY);
            tft.fillCircle(cx, cy, 8, TFT_GREEN);
            
            tft.setTextColor(TFT_WHITE);
            tft.setCursor(5, SCR_H - 15);
            tft.printf("Tap green dot [%d,%d]", c, r);
            
            uint16_t tx, ty;
            if (waitForTouch(tx, ty, 8000)) {
                // Check if touch landed in correct cell
                int touchCol = tx / cellW;
                int touchRow = ty / cellH;
                
                bool hit = (touchCol == c && touchRow == r);
                if (hit) {
                    hits++;
                    tft.fillCircle(tx, ty, 5, TFT_GREEN);
                    Serial.printf("  [%d,%d] HIT  — target(%3d,%3d) touch(%3d,%3d)\n",
                                  c, r, cx, cy, tx, ty);
                } else {
                    misses++;
                    tft.fillCircle(tx, ty, 5, TFT_RED);
                    tft.drawLine(cx, cy, tx, ty, TFT_RED);
                    Serial.printf("  [%d,%d] MISS — target(%3d,%3d) touch(%3d,%3d) "
                                  "landed in [%d,%d]\n",
                                  c, r, cx, cy, tx, ty, touchCol, touchRow);
                }
                delay(500);
            } else {
                Serial.printf("  [%d,%d] TIMEOUT\n", c, r);
            }
        }
    }
    
    // Results
    Serial.printf("\n>>> Grid results: %d/%d hits (%.0f%% accuracy)\n",
                  hits, hits + misses, 
                  (hits + misses > 0) ? hits * 100.0 / (hits + misses) : 0);
    
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_GREEN);
    tft.setCursor(10, 10);
    tft.printf("Grid Test Results:");
    tft.setCursor(10, 40);
    tft.printf("Hits: %d / %d", hits, hits + misses);
    tft.setCursor(10, 60);
    tft.printf("Accuracy: %.0f%%", 
               (hits + misses > 0) ? hits * 100.0 / (hits + misses) : 0);
    
    if (misses > hits) {
        tft.setCursor(10, 100);
        tft.setTextColor(TFT_RED);
        tft.printf("BAD - coordinate mismatch!");
        Serial.println("DIAGNOSIS: Significant coordinate mismatch detected");
    }
}

// ================================================================
// Test 5: Continuous finger tracking (draw mode)
// ================================================================
void testDraw() {
    Serial.println("\n========================================");
    Serial.println("  TEST 5: Draw Mode (10s)");
    Serial.println("  Draw on screen to verify tracking");
    Serial.println("========================================");
    
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE);
    tft.setCursor(10, 5);
    tft.printf("DRAW TEST (10s) - draw!");
    
    // Draw border reference
    tft.drawRect(0, 0, SCR_W, SCR_H, TFT_DARKGREY);
    tft.drawLine(SCR_W/2, 0, SCR_W/2, SCR_H, TFT_DARKGREY);
    tft.drawLine(0, SCR_H/2, SCR_W, SCR_H/2, TFT_DARKGREY);
    
    uint32_t start = millis();
    uint16_t lastX = 0, lastY = 0;
    bool lastPressed = false;
    
    while (millis() - start < 10000) {
        uint8_t touches;
        uint16_t tx, ty;
        bool pressed = ft_readTouch(tx, ty, touches);
        
        if (pressed) {
            if (lastPressed && abs((int)tx - (int)lastX) < 50 && abs((int)ty - (int)lastY) < 50) {
                tft.drawLine(lastX, lastY, tx, ty, TFT_CYAN);
            }
            tft.fillCircle(tx, ty, 2, TFT_CYAN);
            lastX = tx;
            lastY = ty;
            lastPressed = true;
        } else {
            lastPressed = false;
        }
        delay(15);
    }
    
    Serial.println("Draw test complete.");
}

// ================================================================
// SETUP & LOOP
// ================================================================
void setup() {
    Serial.begin(115200);
    delay(500);
    
    Serial.println("\n\n╔══════════════════════════════════════╗");
    Serial.println("║  FT6336U Touch Calibration Test      ║");
    Serial.println("║  Freenove ESP32-S3 FNK0086           ║");
    Serial.println("╚══════════════════════════════════════╝");
    
    // TFT init
    pinMode(PIN_TFT_BL, OUTPUT);
    digitalWrite(PIN_TFT_BL, HIGH);
    tft.init();
    tft.setRotation(0);  // Portrait: 240x320
    tft.fillScreen(TFT_BLACK);
    
    // I2C for touch
    Wire.begin(PIN_SDA, PIN_SCL);
    Wire.setClock(400000);
    delay(100);
    
    Serial.println("\nRunning all tests sequentially...");
    Serial.println("Make sure to interact with touch screen!\n");
    
    // Test 1: Chip info
    testChipInfo();
    delay(2000);
    
    // Test 2: Raw data stream
    testRawStream();
    delay(1000);
    
    // Test 3: Crosshair accuracy
    testCrosshair();
    delay(3000);
    
    // Test 4: Grid test
    testGrid();
    delay(3000);
    
    // Test 5: Draw mode
    testDraw();
    
    // Final screen
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_GREEN);
    tft.setCursor(10, 10);
    tft.printf("ALL TESTS COMPLETE");
    tft.setCursor(10, 30);
    tft.printf("Check Serial for results");
    tft.setCursor(10, 60);
    tft.setTextColor(TFT_YELLOW);
    tft.printf("Press RESET to re-run");
    
    Serial.println("\n\n========================================");
    Serial.println("  ALL TESTS COMPLETE");
    Serial.println("  Check output above for diagnosis.");
    Serial.println("  Press RESET to re-run.");
    Serial.println("========================================");
}

void loop() {
    // Nothing — tests run once in setup
    delay(1000);
}
