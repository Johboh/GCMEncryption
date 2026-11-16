#pragma once

#include <cstddef>
#include <cstdint>
#include <random>

inline void esp_fill_random(void *buf, size_t len) {
  static std::random_device rd;
  uint8_t *p = static_cast<uint8_t *>(buf);
  for (size_t i = 0; i < len; ++i) {
    p[i] = static_cast<uint8_t>(rd());
  }
}
