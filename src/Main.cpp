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

/**************************   USER VARS   **********************************/
// firmware version from git rev-list command
String VERSION_CODE = "v";
#ifdef SRC_REV
int VCODE = SRC_REV;
#else
int VCODE = 0;
#endif

const char* base32String = "JBSWY3DPEHPK3PXP";

SSD1306Wire display(0x3c, 25, 26); //set pins for the OLED display using Wire library

#define SLEEP_TIMEOUT 15000

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

/****************************** KEY HANDLING **********************************/

size_t base32Decode(const char* encoded, uint8_t* decoded, size_t maxDecodedLen) {
  size_t inputLength = strlen(encoded);
  if (inputLength % 8 != 0) {
    // Base32 length should be multiple of 8
    return 0;
  }

  size_t outputLength = inputLength * 5 / 8;
  if (outputLength > maxDecodedLen) {
    // Output buffer is too small
    return 0;
  }

  size_t decodedIndex = 0;
  for (size_t i = 0; i < inputLength; i += 8) {
    uint32_t buffer = 0;

    for (size_t j = 0; j < 8; ++j) {
      buffer <<= 5;

      if (encoded[i + j] >= 'A' && encoded[i + j] <= 'Z') {
        buffer |= encoded[i + j] - 'A';
      } else if (encoded[i + j] >= '2' && encoded[i + j] <= '7') {
        buffer |= encoded[i + j] - '2' + 26;
      } else {
        // Invalid character in input
        return 0;
      }
    }

    for (size_t j = 0; j < 5; ++j) {
      if (decodedIndex < outputLength) {
        decoded[decodedIndex++] = (buffer >> (24 - j * 8)) & 0xFF;
      }
    }
  }

  return decodedIndex;
}

TOTP DecodeKey(const char* encoded) {
 size_t decodedLen = strlen(encoded) * 5 / 8;

  // Allocate memory for the decoded key
  uint8_t* hmacKey = new uint8_t[decodedLen];//{0xea,0x41,0x68,0x5c,0x9b,0x10,0x13,0x5d,0x8c,0xa0,0x35,0x05,0x38,0xcb,0xa9,0x96,0x75,0xa0,0x5a,0xaf};
  
  // Decode the base32 encoded key
  size_t actualDecodedLen = base32Decode(encoded, hmacKey, decodedLen);
  if (actualDecodedLen > 0) {
    Serial.println("Decoded Bytes:");
    for (size_t i = 0; i < actualDecodedLen; i++) {
      // Print each byte in hexadecimal format
      if (hmacKey[i] < 16) {
        Serial.print("0"); // Print leading zero for values less than 0x10
      }
      Serial.print(hmacKey[i], HEX);
      Serial.print(" "); // Separate bytes for readability
    }
  } else {
    Serial.println("Decoding failed or buffer too small.");
  }
  Serial.print(actualDecodedLen);
  TOTP totp = TOTP(hmacKey, actualDecodedLen);
  return totp;
}

/************************** DISPLAY HANDLING **********************************/

void showWelcome(){
  isPowerOff=false;
  display.clear();
  display.setTextAlignment(TEXT_ALIGN_CENTER_BOTH);
  display.setFont(ArialMT_Plain_16);
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

  if (millis() - lastActivityTime >= SLEEP_TIMEOUT) {
    Serial.println("No activity detected for 5 seconds. Going to deep sleep.");
    delay(100); // Short delay to ensure the Serial message is sent before sleeping

    // Enter deep sleep
    suspend();
  }
  delay(10);
}
