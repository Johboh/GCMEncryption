// Copyright (c) Johan Böhlin
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef __GCM_ENCRYPTION_H__
#define __GCM_ENCRYPTION_H__

#include <cstddef>
#include <cstdint>
#include <esp_err.h>
#include <esp_idf_version.h>
#include <memory>
#include <vector>

#if __has_include(<mutex>) && defined(__GTHREADS)
#include <mutex>
#define GCM_ENCRYPTION_HAS_MUTEX 1
#endif

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(6, 0, 0)
#include <mbedtls/esp_debug.h> // Weird, yes, don't know the correct include for 6.0.
#else
#include <mbedtls/gcm.h>
#endif

namespace GCMEncryptionLog {
const char TAG[] = "GCMEncryption";
} // namespace GCMEncryptionLog

/**
 * @brief Encrypt and decrypt byte arrays using AES-128-GCM.
 */
class GCMEncryption {
public:
  /**
   * @brief Construct a new GCMEncryption object
   *
   * @param key Encryption key used for AES-128-GCM. Must be exact 16 bytes long. \0 does not count.
   * @param secret Used to validate the integrity of the messages. We expect the decrypted payload to contain this
   * string. Must be exact 8 bytes long. \0 does not count.
   * @param extended_size Selects between compact and extended/hardened packet formats. Must match on sender and
   * receiver. When false, uses a compact 8-byte IV, 8-byte GCM tag, and 1-byte length field (max 230-byte message),
   * suitable for transports with small maximum packet sizes (such as ESP-NOW or IEEE 802.15.4) and wire-compatible
   * with earlier versions. When true, uses hardened GCM parameters (12-byte IV, 16-byte GCM tag) and a 2-byte length
   * field (max 65497-byte message).
   */
  GCMEncryption(const char *key, const char *secret, bool extended_size = false);
  virtual ~GCMEncryption();

public:
  /**
   * @brief Encrypt a message.
   * This function encrypts the provided message and appends it after an encryption header.
   *
   * @param message Pointer to the message to encrypt.
   * @param length Size of the message in bytes. The maximum supported message length is 65497 bytes if `extended_size`
   * is set to true in the constructor, or 230 bytes if `extended_size` is false.
   * @return A vector containing the encrypted message. This will be larger than the original message due to the added
   * encryption header and other metadata. Returns an empty vector on failure.
   *
   * @note The minimal size of the encrypted vector is 46 bytes when `extended_size` is true, and 33 bytes when
   * `extended_size` is false. If the message length is between 1 and 8 bytes, the encrypted vector size will remain
   * at this minimal size. Starting from a message length of 9 bytes, the encrypted vector size will increase linearly
   * with the input message length.
   */
  const std::vector<uint8_t> encrypt(const void *message, const size_t length);

  /**
   * @brief Decrypt an encrypted message. This message is assumed to contain the Encryption Header.
   *
   * @param message pointer to the message buffer to decrypt.
   * @param length size of the message buffer in bytes.
   * @return the decrypted message. This will be smaller than the original message. Empty vector on failure.
   */
  const std::vector<uint8_t> decrypt(const void *message, const size_t length);

  /**
   * @brief Decrypt an encrypted message. This message is assumed to contain the Encryption Header.
   *
   * @param message the message to decrypt.
   * @return the decrypted message. This will be smaller than the original message. Empty vector on failure.
   */
  const std::vector<uint8_t> decrypt(const std::vector<uint8_t> &message);

private:
  uint8_t _secret[8]{};
  bool _extended_size;
  bool _initialized = false;
  mbedtls_gcm_context _aes;
#ifdef GCM_ENCRYPTION_HAS_MUTEX
  std::mutex _mutex;
#endif
};

#endif // __GCM_ENCRYPTION_H__