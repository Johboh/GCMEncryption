#include <Arduino.h>
#include <GCMEncryption.h>

// Encyption key used for our own packet encryption (GCM).
// The key should be the same for both the encoder and the decoder.
const char encryption_key[] = "0123456789ABCDEF"; // Must be exact 16 bytes long. \0 does not count.

// Used to validate the integrity of the messages.
// The secret should be the same for both the encoder and the decoder.
const char encryption_secret[] = "01234567"; // Must be exact 8 bytes long. \0 does not count.

GCMEncryption _gcm_encryption(encryption_key, encryption_secret);

void setup() {
  std::string message("I'm a secret");
  auto encrypted = _gcm_encryption.encrypt(message.c_str(), message.size());
  auto decrypted = _gcm_encryption.decrypt(encrypted);
  std::string result(decrypted.begin(), decrypted.end());
  Serial.println("GCM encrypt decrypt result:" + String(result.c_str()));
}

void loop() {}
