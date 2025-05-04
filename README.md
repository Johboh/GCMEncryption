# GCMEncryption
[![PlatformIO CI](https://github.com/Johboh/GCMEncryption/actions/workflows/platformio.yaml/badge.svg)](https://registry.platformio.org/libraries/johboh/GCMEncryption)
[![ESP-IDF CI](https://github.com/Johboh/GCMEncryption/actions/workflows/espidf.yaml/badge.svg)](https://components.espressif.com/components/johboh/gcmencryption)
[![Arduino IDE](https://github.com/Johboh/GCMEncryption/actions/workflows/arduino_cli.yaml/badge.svg)](https://downloads.arduino.cc/libraries/logs/github.com/Johboh/GCMEncryption/)
[![GitHub release](https://img.shields.io/github/release/Johboh/GCMEncryption.svg)](https://github.com/Johboh/GCMEncryption/releases)
[![Clang-format](https://github.com/Johboh/GCMEncryption/actions/workflows/clang-format.yaml/badge.svg)](https://github.com/Johboh/GCMEncryption)

Arduino (using Arduino IDE or PlatformIO) and ESP-IDF (using Espressif IoT Development Framework or PlatformIO) compatible library for encrypting and decrypting messages to be sent over protocols like ESP-NOW, 802.15.4 and similar.

### Installation
#### PlatformIO (Arduino or ESP-IDF):
Add the following to `libs_deps`:
```
   Johboh/GCMEncryption
```
#### Arduino IDE:
Search for `GCMEncryption` by `johboh` in the library manager.
#### Espressif IoT Development Framework:
In your existing `idf_component.yml` or in a new `idf_component.yml` next to your main component:
```
dependencies:
  johboh/gcmencryption:
    version: ">=0.2.1"
```

#### Arduino IDE:
Search for `GCMEncryption` by `johboh` in the library manager. See note about version above.

### Examples
- [Using Arduino IDE/CLI or Platform IO Arduino](examples/arduino/integration/integration.ino)
- [ESP-IDF framework](examples/espidf/integration/main/main.cpp)

### Compatibility
- ESP32 only
