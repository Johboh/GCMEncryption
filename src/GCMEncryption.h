#ifndef __GCM_ENCRYPTION_H__
#define __GCM_ENCRYPTION_H__

#include <cstdint>
#include <esp_err.h>
#include <mbedtls/gcm.h>
#include <memory>
#include <vector>

namespace GCMEncryptionLog {
const char TAG[] = "GCMEncryption";
} // namespace GCMEncryptionLog

/**
 * @brief Encrypt and decrypt byte arrays. Useful for sending encrypted data on things like ESP-NOW, 802.15.4 or other
 * protocols.
 */
class GCMEncryption {
public:
  /**
   * @brief Construct a new GCMEncryption object
   *
   * @param key Encyption key used for our own packet encryption (GCM). Must be exact 16 bytes long. \0 does not count.
   * @param secret Used to validate the integrity of the messages. We expect the decrypted payload to contain this
   * string. Must be exact 8 bytes long. \0 does not count.
   * @param extended_size if true, maximum supported message length is 65510 bytes, else 231 bytes. Must be setup with
   * the same size on both the sender and the reciving side. Reason for having this is for backward compatibility with
   * existing users who expects the size to be 231 bytes.
   */
  GCMEncryption(const char *key, const char *secret, bool extended_size = false);
  virtual ~GCMEncryption();

public:
  /**
   * @brief Encrypt a message.
   * This function encrypts the provided message and appends it after an encryption header.
   *
   * @param message Pointer to the message to encrypt.
   * @param length Size of the message in bytes. The maximum supported message length is 65510 bytes if `extended_size`
   * is set to true in the constructor, or 231 bytes if `extended_size` is false.
   * @return A vector containing the encrypted message. This will be larger than the original message due to the added
   * encryption header and other metadata. Returns an empty vector on failure.
   *
   * @note The minimal size of the encrypted vector is 34 bytes when `extended_size` is true, and 33 bytes when
   * `extended_size` is false. If the message length is between 0 and 8 bytes, the encrypted vector size will remain
   * at this minimal size. Starting from a message length of 9 bytes, the encrypted vector size will increase linearly
   * with the input message length.
   */
  const std::vector<uint8_t> encrypt(const void *message, const size_t length);

  /**
   * @brief Decrypt an ecrypted message. This message is assumed to contain the Encryption Header.
   *
   * @param message the message to decrypt.
   * @return the decrypted message. This will be smaller then the original message. Empty vector on failure.
   */
  const std::vector<uint8_t> decrypt(const void *message);

  /**
   * @brief Decrypt an ecrypted message. This message is assumed to contain the Encryption Header.
   *
   * @param message the message to decrypt.
   * @return the decrypted message. This will be smaller then the original message. Empty vector on failure.
   */
  const std::vector<uint8_t> decrypt(const std::vector<uint8_t> &message);

private:
  const char *_secret;
  bool _extended_size;
  mbedtls_gcm_context _aes;
};

#endif // __GCM_ENCRYPTION_H__