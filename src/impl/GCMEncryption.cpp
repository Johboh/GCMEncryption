#include <GCMEncryption.h>
#include <cstring>
#include <esp_log.h>
#include <esp_random.h>

#define KEY_SIZE_IN_BITS (16 * 8) // Assuming 16 bytes key size.
#define SECRET_LENGTH 8           // Hardcoded to 8 bytes.

#pragma pack(1)

/**
 * This is the most outer message, encaplsulating all other messages that are sent.
 * Data after this message contains the encryped data.
 */
struct GCMEncryptionHeader {
  uint8_t iv[8];  // Random initialization vector.
  uint8_t tag[8]; // GCM authentication tag.
  // Following here is either an uint8_t or uint16_t for size, depending on extended_size in constructor, describing the
  // payload buffer length in bytes.
  // The encrypted payload is appended after this struct, and is of length specified just earlier.
};

#pragma pack(0)

GCMEncryption::GCMEncryption(const char *key, const char *secret, bool extended_size)
    : _secret(secret), _extended_size(extended_size) {
  mbedtls_gcm_init(&_aes);
  mbedtls_gcm_setkey(&_aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char *)key, KEY_SIZE_IN_BITS);
}

GCMEncryption::~GCMEncryption() { mbedtls_gcm_free(&_aes); }

const std::vector<uint8_t> GCMEncryption::encrypt(const void *input_message, const size_t input_length) {
  if (input_message == nullptr || input_length == 0) {
    ESP_LOGE(GCMEncryptionLog::TAG,
             "Input payload is either null or length is zero. We need at least one byte to encrypt");
    return std::vector<uint8_t>();
  }

  // Generate a random 8 bytes IV.
  GCMEncryptionHeader header;
  esp_fill_random(header.iv, sizeof(header.iv));

  size_t length_field_size = _extended_size ? sizeof(uint16_t) : sizeof(uint8_t);
  size_t length_field_max_value = _extended_size ? __UINT16_MAX__ : __UINT8_MAX__;
  auto remaining_allowed_size_for_payload =
      (length_field_max_value - sizeof(GCMEncryptionHeader) - length_field_size - SECRET_LENGTH);
  if (input_length > remaining_allowed_size_for_payload) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Input length %d exceedes max allowed payload size %d", input_length,
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
  uint16_t payload_length = std::max((size_t)16, total_length);
  std::unique_ptr<uint8_t[]> encrypted(new (std::nothrow) uint8_t[payload_length]);
  if (encrypted == nullptr) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Failed to allocate memory for encryption buffer");
    return std::vector<uint8_t>();
  }

  // Build the payload we want to encrypt by adding the secret first.
  // Then add the actual message.
  std::unique_ptr<uint8_t[]> input(new (std::nothrow) uint8_t[total_length]);
  if (input == nullptr) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Failed to allocate memory for input buffer");
    return std::vector<uint8_t>();
  }
  std::memcpy(input.get(), _secret, SECRET_LENGTH);
  std::memcpy(input.get() + SECRET_LENGTH, input_message, input_length);

  mbedtls_gcm_crypt_and_tag(&_aes, MBEDTLS_GCM_ENCRYPT, payload_length, header.iv, sizeof(header.iv), nullptr, 0,
                            input.get(), encrypted.get(), sizeof(header.tag), header.tag);

  // We now have or encrypted payload.
  // We want to send the outer GCMEncryptionHeader followed by the length and the encrypted payload.
  size_t wire_length = sizeof(GCMEncryptionHeader) + payload_length + length_field_size;
  std::unique_ptr<uint8_t[]> wire_buffer(new (std::nothrow) uint8_t[wire_length]);
  if (wire_buffer == nullptr) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Failed to allocate memory for wire buffer");
    return std::vector<uint8_t>();
  }
  std::memcpy(wire_buffer.get(), &header, sizeof(GCMEncryptionHeader));
  std::memcpy(wire_buffer.get() + sizeof(GCMEncryptionHeader), &payload_length, length_field_size);
  std::memcpy(wire_buffer.get() + sizeof(GCMEncryptionHeader) + length_field_size, encrypted.get(), payload_length);

  return std::vector<uint8_t>(wire_buffer.get(), wire_buffer.get() + wire_length);
}

const std::vector<uint8_t> GCMEncryption::decrypt(const std::vector<uint8_t> &input_message) {
  size_t length_field_size = _extended_size ? sizeof(uint16_t) : sizeof(uint8_t);
  auto minimum_expected_payload_size = sizeof(GCMEncryptionHeader) + length_field_size + SECRET_LENGTH;

  if (input_message.size() < minimum_expected_payload_size) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Input payload length is too short");
    return std::vector<uint8_t>();
  }

  return decrypt(input_message.data());
}

const std::vector<uint8_t> GCMEncryption::decrypt(const void *input_message) {
  GCMEncryptionHeader *header = (GCMEncryptionHeader *)input_message;

  // If we have no secret, something is off. No point in continue at all in that case.
  // Or if we ONLY have a secret. Its technically valid, but also off.
  auto payload_length_start = static_cast<const uint8_t *>(input_message) + sizeof(GCMEncryptionHeader);
  size_t payload_length = 0;
  if (_extended_size) {
    payload_length = *((uint16_t *)payload_length_start);
  } else {
    payload_length = *((uint8_t *)payload_length_start);
  }
  if (payload_length <= SECRET_LENGTH) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Input payload length is too short");
    return std::vector<uint8_t>();
  }

  std::unique_ptr<uint8_t[]> decrypted(new (std::nothrow) uint8_t[payload_length]);
  if (decrypted == nullptr) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Failed to allocate memory for decryption buffer");
    return std::vector<uint8_t>();
  }
  size_t length_field_size = _extended_size ? sizeof(uint16_t) : sizeof(uint8_t);
  uint8_t *encrypted = (uint8_t *)input_message + sizeof(GCMEncryptionHeader) + length_field_size;

  int r = mbedtls_gcm_crypt_and_tag(&_aes, MBEDTLS_GCM_DECRYPT, payload_length, header->iv, sizeof(header->iv), nullptr,
                                    0, encrypted, decrypted.get(), sizeof(header->tag), header->tag);

  if (r != 0) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Failed to decrypt payload. Secret or keys are wrong");
    return std::vector<uint8_t>();
  }

  // Verify secret. Its always first.
  if (memcmp(decrypted.get(), _secret, SECRET_LENGTH) != 0) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Failed to decrypt payload. Secret is invalid");
    return std::vector<uint8_t>();
  }

  // Copy message without secret so we can return a pointer to something that can be free:d.
  size_t output_message_length = payload_length - SECRET_LENGTH;
  std::unique_ptr<uint8_t[]> output_message(new (std::nothrow) uint8_t[output_message_length]);
  if (output_message == nullptr) {
    ESP_LOGE(GCMEncryptionLog::TAG, "Failed to allocate memory for output buffer");
    return std::vector<uint8_t>();
  }
  std::memcpy(output_message.get(), decrypted.get() + SECRET_LENGTH, output_message_length);

  return std::vector<uint8_t>(output_message.get(), output_message.get() + output_message_length);
}
