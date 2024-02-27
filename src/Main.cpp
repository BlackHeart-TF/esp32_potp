/**
* [status: in developing]
* Portable EAP Protected One-Time Password (EAP-POTP) or GoogleAuthenticator
* hardware for provides two-factor user authentication.

* This is a PlatformIO DIY project for WeMOS like board with ESP32 and
* OLED SSD1306 display, see materials and instructions on:
* https://github.com/hpsaturn/esp32_potp
*
* Before, please setup your WiFi on secrets.load.sample and run:
* cp secrets.load.sample secrets.load
* chmod 755 secrets.load
* export PLATFORMIO_BUILD_FLAGS=`bash ./secrets.load`
*
* Build and run:
* platformio run --target upload
* platformio run --target upload --upload-port 192.168.x.x
*/

#include <Arduino.h>
#include <SSD1306.h>

#include <sys/time.h>
#include <string.h>
#include <time.h>
#include "WiFiManager.h"
#include "esp_sleep.h"
#include "sha1.h"
#include "TOTP.h"
#include "lwip/err.h"
#include "apps/sntp/sntp.h"
#include <base64.h>
#include "font_spaceage.h"

/**************************   USER VARS   **********************************/
// firmware version from git rev-list command

#define DPAD_PIN A0

String VERSION_CODE = "v";
#ifdef SRC_REV
int VCODE = SRC_REV;
#else
int VCODE = 0;
#endif

const char* base32String = "JBSWY3DPEHPK3PXP";

SSD1306Wire display(0x3c,21,22); //set pins for the OLED display using Wire library

#define SLEEP_TIMEOUT 15000

#define KEY_REPEAT_INTERVAL 500 // Repeat interval in milliseconds

/**************************   STATIC INITIALIZERS   **********************************/
TOTP* totp;
char code[7];
unsigned long lastActivityTime = 0; // Stores the last activity time

WiFiManager wifi(&display);
// Power vars
unsigned long poweroff = 0;
bool isPowerOff = false;
// Touche keys setup
#define THRESHOLD 75
int touch2count = 0;
int touch3count = 0;

unsigned long lastPressTime = 0; // Timestamp of the last press event
String lastDirection = "Idle"; // The last direction that was pressed

/**************************   POWER METHODS   **********************************/

void reboot(){
  Serial.println("-->Process Reboot..");
  ESP.restart();
}

void suspend(){
  Serial.println("-->Process Suspend..");
  isPowerOff=true;
  display.clear();
  display.setFont(ArialMT_Plain_10);
  int16_t x1, y1;
  uint16_t w, h;
  const char* text = "Suspending..";
  display.setTextAlignment(TEXT_ALIGN_CENTER_BOTH);
  display.drawString(display.getWidth()/2, display.getHeight()/2, "Suspending..");
  display.display();
  delay(500);
  display.clear();
  display.display();
  wifi.disableWifi();
  esp_sleep_enable_touchpad_wakeup();
  esp_deep_sleep_start();
}

/**************************   NTP HANDLING   **********************************/

static void initSNTP(void) {
  Serial.println("-->Initializing SNTP");
  configTime(0,0,"pool.ntp.org");
}

static void getTimeFromSNTP(void) {
  initSNTP();
  // wait for time to be set
  time_t now = 0;
  struct tm timeinfo = {0};
  int retry = 0;
  const int retry_count = 20;
  Serial.print("-->Waiting for system time to be set.");
  while (timeinfo.tm_year < (2016 - 1900) && ++retry < retry_count) {
    Serial.print(".");
    delay(10);
    time(&now);
    localtime_r(&now, &timeinfo);
  }
  Serial.println("ready.");
}

/****************************** DPAD HANDLING **********************************/

String processDpadPress() {
    // Define direction based on sensorValue as before
    int sensorValue = analogRead(DPAD_PIN);
    if(sensorValue == 4095) return "Idle";
    else if(sensorValue < 100) return "Down";
    else if(sensorValue > 650 && sensorValue < 730) return "Left";
    else if(sensorValue > 1450 && sensorValue < 1610) return "Up";
    else if(sensorValue > 3140 && sensorValue < 3340) return "Right";
    else return "Unknown";
}

void sendDirectionEvent(String direction) {
    unsigned long currentTime = millis(); // Get the current time
    if (direction == "Idle") {
        // Reset when no direction is pressed
        //lastPressTime = 0;
        //lastDirection = "Idle";
    } else if (direction != lastDirection || (currentTime - lastPressTime >= KEY_REPEAT_INTERVAL && lastPressTime != 0)) {
        // Send event if a new direction is pressed or if the repeat interval has passed
        //Serial.println(direction);
        //lastPressTime = currentTime; // Update the last press time
        //lastDirection = direction; // Update the last direction
    }
}

/****************************** KEY HANDLING **********************************/

size_t base32Decode(const char* encoded, uint8_t* decoded, size_t maxDecodedLen) {
    size_t inputLength = strlen(encoded);
    if (inputLength % 8 != 0) {
        // Base32 length should be a multiple of 8
        return 0;
    }

    size_t outputLength = inputLength * 5 / 8;
    if (outputLength > maxDecodedLen) {
        // Output buffer is too small
        return 0;
    }

    const char base32Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    size_t decodedIndex = 0, buffer = 0, bitsLeft = 0;
    for (size_t i = 0; i < inputLength; ++i) {
        char c = encoded[i];
        size_t value;

        if (c >= 'A' && c <= 'Z') value = c - 'A';
        else if (c >= '2' && c <= '7') value = c - '2' + 26;
        else return 0; // Invalid character

        buffer = (buffer << 5) | value;
        bitsLeft += 5;

        if (bitsLeft >= 8) {
            decoded[decodedIndex++] = (buffer >> (bitsLeft - 8)) & 0xFF;
            bitsLeft -= 8;
        }
    }

    return decodedIndex;
}

TOTP DecodeKey(const char* encoded) {
 size_t decodedLen = strlen(encoded) * 5 / 8;

  // Allocate memory for the decoded key
  uint8_t* hmacKey = new uint8_t[decodedLen];
  
  // Decode the base32 encoded key
  size_t actualDecodedLen = base32Decode(encoded, hmacKey, decodedLen);
  //hmacKey = new uint8_t[10]{'H','e','l','l','o','!',0xde,0xad,0xbe,0xef};

  if (actualDecodedLen > 0) {
  //   Serial.println("Decoded Bytes:");
  //   for (size_t i = 0; i < actualDecodedLen; i++) {
  //     Serial.print("Index: ");Serial.println(i);
  //     // Print each byte in hexadecimal format
  //     if (hmacKey[i] < 16) {
  //       Serial.print("0"); // Print leading zero for values less than 0x10
  //     }
  //     Serial.print(hmacKey[i], HEX);
  //     Serial.print(" "); // Separate bytes for readability
  //   }
  } else {
    Serial.println("Decoding failed or buffer too small.");
  }
  //Serial.print(actualDecodedLen);
  TOTP totp = TOTP(hmacKey, actualDecodedLen);
  return totp;
}

/************************** DISPLAY HANDLING **********************************/

void showWelcome(){
  isPowerOff=false;
  display.clear();
  display.setTextAlignment(TEXT_ALIGN_CENTER_BOTH);
  display.setFont(ArialMT_Plain_10);
  display.drawString(display.getWidth()/2, display.getHeight()/2, "ESP-2FA");
  display.display();
  Serial.println("-->Welcome screen ready");
  delay(500); // TODO: remove if bluetooth will be scan
}

void showTime(char timebuf[]) {
  display.setFont(ArialMT_Plain_10);
  display.setTextAlignment(TEXT_ALIGN_CENTER_BOTH);
  display.drawString(display.getWidth() / 2, ((display.getHeight()/ 2)-24),timebuf);
}

void showRevisionCode(){
  display.setFont(ArialMT_Plain_10);
  display.setTextAlignment(TEXT_ALIGN_RIGHT);
  display.drawString(display.getWidth()-5,display.getHeight()-10, VERSION_CODE+VCODE);
}

void showOTPCode(String OTPcode){
  display.setFont(ArialMT_Plain_24);
  display.drawString(display.getWidth() / 2, (display.getHeight()/ 2)+5, OTPcode);
}

void calcOTPCodeAndPrintScreen() {
  time_t now;
  struct tm timeinfo;
  char timebuf[64];
  char *newCode = totp->getCode(time(&now));
  localtime_r(&now, &timeinfo);
  strftime(timebuf, sizeof(timebuf),"%Y %a, %d %b %H:%M:%S", &timeinfo);
  if (strcmp(code, newCode) != 0) {
    strcpy(code, newCode);
    if (timeinfo.tm_year < (2016 - 1900)) {
      Serial.println("Time is not set yet! PRESS RIGHT BUTTON! (connect to NTP)");
    } else {
      Serial.print(timebuf);
      Serial.print(" ==> OTP code: [");
      Serial.print(code);
      Serial.println("]");
    }
  }
  display.clear();
  // show current time (clock)
  showTime(timebuf);
  // show OTP code
  showOTPCode(code);
  // show revision code
  showRevisionCode();
  // print display
  display.display();
}

/******************************************************************************
*****************************   S E T U P   ***********************************
******************************************************************************/

void setup() {
  Serial.begin(115200);
  Serial.println();
  Serial.println("== ESP32 Booting ==");
  lastActivityTime = millis();
  // display setup
  display.init();
  display.flipScreenVertically();
  display.setContrast(128);
  display.clear();
  Serial.println("-->OLED ready");
  wifi.disableWifi();
  // Init touch callbacks
  pinMode(T4, INPUT);
  pinMode(T3, INPUT);
  touchAttachInterrupt(T4,[](){},75);
  Serial.println("-->Buttons ready");
  // Set timezone for America/Bogota
  setenv("TZ", "<-05>5", 1);
  tzset();
  TOTP ntotp = DecodeKey(base32String);
  totp = &ntotp;
  // Splash Window
  showWelcome();
  Serial.println("== Setup ready ==");
}

/******************************************************************************
*****************************    L O O P    ***********************************
******************************************************************************/

void loop() {
  if (wifi.isWifiEnable) // OTA mode
    ArduinoOTA.handle();
  else                   // OTPcode mode
    calcOTPCodeAndPrintScreen();

 int touch2Value = touchRead(T4);
  // touch LEFT capture
  if (touch2Value < THRESHOLD) {
    if (touch2count++ > 10) {
      lastActivityTime = millis();
      Serial.println("Touch 2 (GPIO2) reached");
      touch2count = 0;
      if (isPowerOff)
        showWelcome();
      else
        suspend();
    }
  }
  else
    touch2count = 0;

  // touch RIGTH capture
  int touch3Value = touchRead(T3);
  if (touch3Value < THRESHOLD) {
    if (touch3count++ > 5) {
      lastActivityTime = millis();
      Serial.println("Touch 3 (GPIO15) reached");
      touch3count = 0;
      if (wifi.isWifiEnable) wifi.disableWifi();
      else if (wifi.init()) getTimeFromSNTP();
      delay(200);
    }
  }
  else
    touch3count = 0;

  String direction = processDpadPress();
  Serial.print(direction);
  sendDirectionEvent(direction);

  if (millis() - lastActivityTime >= SLEEP_TIMEOUT) {
    Serial.println("No activity detected for 5 seconds. Going to deep sleep.");
    delay(100); // Short delay to ensure the Serial message is sent before sleeping

    // Enter deep sleep
    suspend();
  }
  delay(10);
}
