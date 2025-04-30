#ifndef __GCM_ENCRYPTION_H__
#define __GCM_ENCRYPTION_H__

#include <cstdint>
#include <esp_err.h>
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

public:
  /**
   * @brief Encrypt an array.
   * This array will be encryped and placed after an Encryption Header.
   *
   * @param message pointer to the message to encrypt.
   * @param length size of the message. Maximum supported message length is 65510 bytes if extended_size is true in
   * constructor, else if false, 231 bytes.
   * @return the encrypted message. This will be larger then the original message. Empty vector on failure. The
   * encryption overhead is 26 bytes when extended_size is true, and 25 bytes for when extended_size is false.
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
  const char *_key;
  const char *_secret;
  bool _extended_size;
};

#endif // __GCM_ENCRYPTION_H__