#include <GCMEncryption.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string>

// Encyption key used for our own packet encryption (GCM).
// The key should be the same for both the encoder and the decoder.
const char encryption_key[] = "0123456789ABCDEF"; // Must be exact 16 bytes long. \0 does not count.

// Used to validate the integrity of the messages.
// The secret should be the same for both the encoder and the decoder.
const char encryption_secret[] = "01234567"; // Must be exact 8 bytes long. \0 does not count.

GCMEncryption _gcm_encryption(encryption_key, encryption_secret);

extern "C" {
void app_main();
}

void app_main(void) {
  std::string message("I'm a secret");
  auto encrypted = _gcm_encryption.encrypt(message.c_str(), message.size());
  auto decrypted = _gcm_encryption.decrypt(encrypted);
  std::string result(decrypted.begin(), decrypted.end());
  ESP_LOGI("main", "GCM encrypt decrypt result: %s", result.c_str());

  while (1) {
    vTaskDelay(500 / portTICK_PERIOD_MS);
    fflush(stdout);
  }
}
