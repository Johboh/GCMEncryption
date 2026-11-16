// Copyright (c) Johan Böhlin
// SPDX-License-Identifier: GPL-3.0-or-later

#include <GCMEncryption.h>
#include <algorithm>
#include <cstring>
#include <esp_log.h>
#include <esp_random.h>

#define KEY_SIZE_IN_BITS (16 * 8) // Assuming 16 bytes key size.
#define SECRET_LENGTH 8           // Hardcoded to 8 bytes.

#pragma pack(push, 1)

/**
 * Compact header used when extended_size is false (wire-compatible with 0.x).
 */
struct GCMEncryptionHeader {
  uint8_t iv[8];  // Random initialization vector.
  uint8_t tag[8]; // GCM authentication tag.
  // Followed by uint8_t payload length and encrypted payload.
};

/**
 * Hardened header used when extended_size is true.
 */
struct GCMEncryptionExtendedHeader {
  uint8_t iv[12];  // Random initialization vector (96-bit standard GCM nonce).
  uint8_t tag[16]; // GCM authentication tag (128-bit full tag).
  // Followed by uint16_t payload length and encrypted payload.
};

#pragma pack(pop)

namespace {
struct HeaderLayout {
  size_t header_size;
  size_t iv_size;
  size_t tag_size;
  size_t length_field_size;
  size_t max_packet_size;
};

HeaderLayout getHeaderLayout(bool extended_size) {
  if (extended_size) {
    return {sizeof(GCMEncryptionExtendedHeader), sizeof(GCMEncryptionExtendedHeader::iv),
            sizeof(GCMEncryptionExtendedHeader::tag), sizeof(uint16_t), UINT16_MAX};
  }
  return {sizeof(GCMEncryptionHeader), sizeof(GCMEncryptionHeader::iv), sizeof(GCMEncryptionHeader::tag),
          sizeof(uint8_t), UINT8_MAX};
}

void secureZero(void *ptr, size_t len) {
  volatile uint8_t *p = static_cast<volatile uint8_t *>(ptr);
  while (len--) {
    *p++ = 0;
  }
}

struct ZeroOnExit {
  void *ptr;
  size_t len;
  ~ZeroOnExit() {
    if (ptr != nullptr && len > 0) {
      secureZero(ptr, len);
    }
  }
};
} // namespace

GCMEncryption::GCMEncryption(const char *key, const char *secret, bool extended_size) : _extended_size(extended_size) {
  mbedtls_gcm_init(&_aes);
  if (key == nullptr || secret == nullptr) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Key or secret is null");
    return;
  }
  std::memcpy(_secret, secret, SECRET_LENGTH);
  int r =
      mbedtls_gcm_setkey(&_aes, MBEDTLS_CIPHER_ID_AES, reinterpret_cast<const unsigned char *>(key), KEY_SIZE_IN_BITS);
  if (r != 0) {
    secureZero(_secret, sizeof(_secret));
    ESP_LOGE(GCMEncryptionLog::TAG, "Failed to set GCM key (error %d)", r);
    return;
  }
  _initialized = true;
}

GCMEncryption::~GCMEncryption() {
  mbedtls_gcm_free(&_aes);
  secureZero(_secret, sizeof(_secret));
}

const std::vector<uint8_t> GCMEncryption::encrypt(const void *input_message, const size_t input_length) {
  if (!_initialized) {
    ESP_LOGE(GCMEncryptionLog::TAG, "GCMEncryption is not initialized");
    return std::vector<uint8_t>();
  }

  if (input_message == nullptr || input_length == 0) {
    ESP_LOGE(GCMEncryptionLog::TAG,
             "Input payload is either null or length is zero. We need at least one byte to encrypt");
    return std::vector<uint8_t>();
  }

  const HeaderLayout layout = getHeaderLayout(_extended_size);
  auto remaining_allowed_size_for_payload =
      (layout.max_packet_size - layout.header_size - layout.length_field_size - SECRET_LENGTH);
  if (input_length > remaining_allowed_size_for_payload) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Input length %zu exceeds max allowed payload size %zu", input_length,
             remaining_allowed_size_for_payload);
    return std::vector<uint8_t>();
  }

  // Total buffer to encrypt needs to be at least 16 bytes.
  // At the start of the buffer, we will include the _secret so we can
  // verify the integrity of the message.
  // So the size of the buffer to encrypt will be the input length + size of _secret
  // which we force to be SECRET_LENGTH.
  size_t total_length = SECRET_LENGTH + input_length;
  // We need at least 16 bytes, but we don't need a multiple of 16 bytes.
  // If smaller than 16, round up.
  uint16_t payload_length = std::max(static_cast<size_t>(16), total_length);

  // Build the payload we want to encrypt by adding the secret first.
  // Then add the actual message. Zero-initialize so any padding up to 16 bytes is deterministic.
  std::unique_ptr<uint8_t[]> input(new (std::nothrow) uint8_t[payload_length]());
  if (input == nullptr) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Failed to allocate memory for input buffer");
    return std::vector<uint8_t>();
  }
  ZeroOnExit input_guard{input.get(), payload_length};
  std::memcpy(input.get(), _secret, SECRET_LENGTH);
  std::memcpy(input.get() + SECRET_LENGTH, input_message, input_length);

  size_t wire_length = layout.header_size + layout.length_field_size + payload_length;
  std::vector<uint8_t> wire_buffer(wire_length);
  uint8_t *iv = wire_buffer.data();
  uint8_t *tag = wire_buffer.data() + layout.iv_size;
  uint8_t *encrypted = wire_buffer.data() + layout.header_size + layout.length_field_size;

  // Generate a random IV.
  esp_fill_random(iv, layout.iv_size);
  std::memcpy(wire_buffer.data() + layout.header_size, &payload_length, layout.length_field_size);

#ifdef GCM_ENCRYPTION_HAS_MUTEX
  std::lock_guard<std::mutex> lock(_mutex);
#endif

  int r = mbedtls_gcm_crypt_and_tag(&_aes, MBEDTLS_GCM_ENCRYPT, payload_length, iv, layout.iv_size, nullptr, 0,
                                    input.get(), encrypted, layout.tag_size, tag);
  if (r != 0) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Failed to encrypt payload (error %d)", r);
    return std::vector<uint8_t>();
  }

  return wire_buffer;
}

const std::vector<uint8_t> GCMEncryption::decrypt(const std::vector<uint8_t> &input_message) {
  return decrypt(input_message.data(), input_message.size());
}

const std::vector<uint8_t> GCMEncryption::decrypt(const void *input_message, const size_t input_length) {
  if (!_initialized) {
    ESP_LOGE(GCMEncryptionLog::TAG, "GCMEncryption is not initialized");
    return std::vector<uint8_t>();
  }

  if (input_message == nullptr) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Input message is null");
    return std::vector<uint8_t>();
  }

  const HeaderLayout layout = getHeaderLayout(_extended_size);
  size_t header_and_length_size = layout.header_size + layout.length_field_size;
  if (input_length < header_and_length_size + SECRET_LENGTH + 1) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Input payload length is too short");
    return std::vector<uint8_t>();
  }

  const uint8_t *message_bytes = static_cast<const uint8_t *>(input_message);
  const uint8_t *iv = message_bytes;
  const uint8_t *tag = message_bytes + layout.iv_size;

  // If we have no secret, something is off. No point in continuing at all in that case.
  // Or if we ONLY have a secret. It's technically valid, but also off.
  const uint8_t *payload_length_start = message_bytes + layout.header_size;
  size_t payload_length = 0;
  if (_extended_size) {
    uint16_t len = 0;
    std::memcpy(&len, payload_length_start, sizeof(uint16_t));
    payload_length = len;
  } else {
    payload_length = *payload_length_start;
  }

  if (payload_length <= SECRET_LENGTH) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Input payload length is too short");
    return std::vector<uint8_t>();
  }

  if (payload_length > input_length - header_and_length_size) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Input payload length exceeds provided buffer size");
    return std::vector<uint8_t>();
  }

  std::unique_ptr<uint8_t[]> decrypted(new (std::nothrow) uint8_t[payload_length]);
  if (decrypted == nullptr) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Failed to allocate memory for decryption buffer");
    return std::vector<uint8_t>();
  }
  ZeroOnExit decrypted_guard{decrypted.get(), payload_length};
  const uint8_t *encrypted = message_bytes + header_and_length_size;

  int r = 0;
  {
#ifdef GCM_ENCRYPTION_HAS_MUTEX
    std::lock_guard<std::mutex> lock(_mutex);
#endif
    r = mbedtls_gcm_auth_decrypt(&_aes, payload_length, iv, layout.iv_size, nullptr, 0, tag, layout.tag_size, encrypted,
                                 decrypted.get());
  }

  if (r != 0) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Failed to decrypt payload. Authentication tag or keys are invalid");
    return std::vector<uint8_t>();
  }

  // Verify secret in constant time. Its always first.
  uint8_t diff = 0;
  for (size_t i = 0; i < SECRET_LENGTH; i++) {
    diff |= decrypted[i] ^ _secret[i];
  }
  if (diff != 0) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Failed to decrypt payload. Secret is invalid");
    return std::vector<uint8_t>();
  }

  return std::vector<uint8_t>(decrypted.get() + SECRET_LENGTH, decrypted.get() + payload_length);
}
