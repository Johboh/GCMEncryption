// Copyright (c) Johan Böhlin
// SPDX-License-Identifier: GPL-3.0-or-later

#include <GCMEncryption.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#define TEST_ASSERT(cond)                                                                                              \
  do {                                                                                                                 \
    if (!(cond)) {                                                                                                     \
      std::fprintf(stderr, "Assertion failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__);                               \
      std::abort();                                                                                                    \
    }                                                                                                                  \
  } while (0)

namespace {

void testCompactRoundTripAndLimits(const char *key, const char *secret) {
  GCMEncryption gcm(key, secret, false);

  // Normal message round-trip via both decrypt overloads.
  const std::string msg = "Hello, encrypted world!";
  const auto enc = gcm.encrypt(msg.data(), msg.size());
  TEST_ASSERT(enc.size() == 16 + 1 + 8 + msg.size());

  const auto dec_vec = gcm.decrypt(enc);
  TEST_ASSERT(dec_vec.size() == msg.size());
  TEST_ASSERT(std::memcmp(dec_vec.data(), msg.data(), msg.size()) == 0);

  const auto dec_ptr = gcm.decrypt(enc.data(), enc.size());
  TEST_ASSERT(dec_ptr == dec_vec);

  // Trailing unauthenticated bytes beyond wire_length should still decrypt cleanly without OOB.
  auto padded = enc;
  padded.push_back(0xAA);
  padded.push_back(0xBB);
  TEST_ASSERT(gcm.decrypt(padded) == dec_vec);

  // Short messages (1..8 bytes) pad deterministically to minimal 33-byte wire packet and return 8 bytes.
  for (size_t len = 1; len <= 8; ++len) {
    std::vector<uint8_t> short_msg(len, static_cast<uint8_t>('A' + len));
    const auto short_enc = gcm.encrypt(short_msg.data(), short_msg.size());
    TEST_ASSERT(short_enc.size() == 33);
    const auto short_dec = gcm.decrypt(short_enc);
    TEST_ASSERT(short_dec.size() == 8);
    TEST_ASSERT(std::memcmp(short_dec.data(), short_msg.data(), len) == 0);
    for (size_t i = len; i < 8; ++i) {
      TEST_ASSERT(short_dec[i] == 0);
    }
  }

  // 9-byte message grows linearly: 16 header + 1 length + 8 secret + 9 msg = 34 bytes.
  const std::vector<uint8_t> nine_bytes(9, 0x55);
  const auto nine_enc = gcm.encrypt(nine_bytes.data(), nine_bytes.size());
  TEST_ASSERT(nine_enc.size() == 34);
  TEST_ASSERT(gcm.decrypt(nine_enc) == nine_bytes);

  // Maximum compact payload size: 230 bytes -> 255 bytes on wire.
  const std::vector<uint8_t> max_payload(230, 0x3C);
  const auto max_enc = gcm.encrypt(max_payload.data(), max_payload.size());
  TEST_ASSERT(max_enc.size() == 255);
  TEST_ASSERT(gcm.decrypt(max_enc) == max_payload);

  // Exceeding maximum compact payload size (231 bytes) must fail.
  const std::vector<uint8_t> over_max(231, 0x3C);
  TEST_ASSERT(gcm.encrypt(over_max.data(), over_max.size()).empty());
}

void testExtendedRoundTripAndLimits(const char *key, const char *secret) {
  GCMEncryption gcm(key, secret, true);

  // Short message (1..8 bytes) produces minimal 46-byte wire packet (12 IV + 16 tag + 2 len + 16 min payload).
  const std::string short_msg = "Hi";
  const auto short_enc = gcm.encrypt(short_msg.data(), short_msg.size());
  TEST_ASSERT(short_enc.size() == 46);
  const auto short_dec = gcm.decrypt(short_enc);
  TEST_ASSERT(short_dec.size() == 8);
  TEST_ASSERT(short_dec[0] == 'H' && short_dec[1] == 'i');
  for (size_t i = 2; i < 8; ++i) {
    TEST_ASSERT(short_dec[i] == 0);
  }

  // Medium payload (> 255 bytes).
  std::vector<uint8_t> medium(512);
  for (size_t i = 0; i < medium.size(); ++i) {
    medium[i] = static_cast<uint8_t>(i & 0xFF);
  }
  const auto med_enc = gcm.encrypt(medium.data(), medium.size());
  TEST_ASSERT(med_enc.size() == 28 + 2 + 8 + medium.size());
  TEST_ASSERT(gcm.decrypt(med_enc) == medium);

  // Maximum extended payload size: 65497 bytes -> 65535 bytes on wire.
  const std::vector<uint8_t> max_payload(65497, 0x7A);
  const auto max_enc = gcm.encrypt(max_payload.data(), max_payload.size());
  TEST_ASSERT(max_enc.size() == 65535);
  TEST_ASSERT(gcm.decrypt(max_enc) == max_payload);

  // Exceeding maximum extended payload size (65498 bytes) must fail.
  const std::vector<uint8_t> over_max(65498, 0x7A);
  TEST_ASSERT(gcm.encrypt(over_max.data(), over_max.size()).empty());
}

void testCrossModeMismatch(const char *key, const char *secret) {
  GCMEncryption compact(key, secret, false);
  GCMEncryption extended(key, secret, true);

  const std::string msg = "Cross mode compatibility check";
  const auto compact_enc = compact.encrypt(msg.data(), msg.size());
  const auto extended_enc = extended.encrypt(msg.data(), msg.size());

  TEST_ASSERT(!compact_enc.empty());
  TEST_ASSERT(!extended_enc.empty());
  TEST_ASSERT(extended.decrypt(compact_enc).empty());
  TEST_ASSERT(compact.decrypt(extended_enc).empty());
}

void testAuthenticationAndBoundsChecks(const char *key, const char *secret, bool extended_size) {
  GCMEncryption gcm(key, secret, extended_size);
  const size_t iv_size = extended_size ? 12 : 8;
  const size_t tag_size = extended_size ? 16 : 8;
  const size_t len_size = extended_size ? 2 : 1;
  const size_t header_size = iv_size + tag_size;

  const std::string msg = "Authenticated payload 0123456789";
  const auto enc = gcm.encrypt(msg.data(), msg.size());
  TEST_ASSERT(!enc.empty());

  // Flip every byte in IV -> must fail.
  for (size_t i = 0; i < iv_size; ++i) {
    auto tampered = enc;
    tampered[i] ^= 0x01;
    TEST_ASSERT(gcm.decrypt(tampered).empty());
  }

  // Flip every byte in GCM tag -> must fail.
  for (size_t i = 0; i < tag_size; ++i) {
    auto tampered = enc;
    tampered[iv_size + i] ^= 0x80;
    TEST_ASSERT(gcm.decrypt(tampered).empty());
  }

  // Flip ciphertext byte in _secret prefix and in message body -> must fail, and input buffer must not be mutated.
  const size_t ct_offset = header_size + len_size;
  for (size_t i = ct_offset; i < enc.size(); ++i) {
    auto tampered = enc;
    tampered[i] ^= 0x01;
    const auto snapshot = tampered;
    TEST_ASSERT(gcm.decrypt(tampered.data(), tampered.size()).empty());
    TEST_ASSERT(tampered == snapshot);
  }

  // Zeroed tag on valid ciphertext -> must fail.
  {
    auto zero_tag = enc;
    std::memset(zero_tag.data() + iv_size, 0, tag_size);
    TEST_ASSERT(gcm.decrypt(zero_tag).empty());
  }

  // Wrong key -> must fail.
  const char wrong_key[] = "FEDCBA9876543210";
  GCMEncryption wrong_key_gcm(wrong_key, secret, extended_size);
  TEST_ASSERT(wrong_key_gcm.decrypt(enc).empty());

  // Same key, wrong secret -> tag succeeds at GCM layer, secret check must reject.
  const char wrong_secret[] = "76543210";
  GCMEncryption wrong_secret_gcm(key, wrong_secret, extended_size);
  TEST_ASSERT(wrong_secret_gcm.decrypt(enc).empty());

  // Oversized payload_length field -> must fail cleanly without OOB read.
  auto oversized = enc;
  oversized[header_size] = 0xFF;
  if (extended_size) {
    oversized[header_size + 1] = 0xFF;
  }
  TEST_ASSERT(gcm.decrypt(oversized).empty());

  // Off-by-one payload_length (claims 1 byte more than buffer provides) -> must fail without OOB read.
  {
    auto off_by_one = enc;
    const size_t remaining = off_by_one.size() - ct_offset;
    const uint16_t claimed = static_cast<uint16_t>(remaining + 1);
    std::memcpy(off_by_one.data() + header_size, &claimed, len_size);
    TEST_ASSERT(gcm.decrypt(off_by_one).empty());
  }

  // Undersized payload_length field (<= SECRET_LENGTH) -> must fail.
  for (uint8_t bad_len : {uint8_t(0), uint8_t(1), uint8_t(8)}) {
    auto undersized = enc;
    undersized[header_size] = bad_len;
    if (extended_size) {
      undersized[header_size + 1] = 0;
    }
    TEST_ASSERT(gcm.decrypt(undersized).empty());
  }

  // Truncated inputs for every length < enc.size() -> must fail cleanly.
  for (size_t trunc = 0; trunc < enc.size(); ++trunc) {
    TEST_ASSERT(gcm.decrypt(enc.data(), trunc).empty());
  }
}

void testWireFormatCompatibilityWithMbedtls(const char *key, const char *secret) {
  // Verify compact (0.x) wire format matches raw mbedTLS AES-128-GCM (8-byte IV, 8-byte tag, 1-byte length).
  mbedtls_gcm_context raw_ctx;
  mbedtls_gcm_init(&raw_ctx);
  TEST_ASSERT(mbedtls_gcm_setkey(&raw_ctx, MBEDTLS_CIPHER_ID_AES, reinterpret_cast<const unsigned char *>(key), 128) ==
              0);

  const std::string msg = "Wire compat check";
  uint8_t iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint8_t tag[8] = {0};
  std::vector<uint8_t> pt(8 + msg.size());
  std::memcpy(pt.data(), secret, 8);
  std::memcpy(pt.data() + 8, msg.data(), msg.size());
  std::vector<uint8_t> ct(pt.size());

  TEST_ASSERT(mbedtls_gcm_crypt_and_tag(&raw_ctx, MBEDTLS_GCM_ENCRYPT, pt.size(), iv, sizeof(iv), nullptr, 0, pt.data(),
                                        ct.data(), sizeof(tag), tag) == 0);

  std::vector<uint8_t> legacy_wire;
  legacy_wire.insert(legacy_wire.end(), iv, iv + sizeof(iv));
  legacy_wire.insert(legacy_wire.end(), tag, tag + sizeof(tag));
  legacy_wire.push_back(static_cast<uint8_t>(pt.size()));
  legacy_wire.insert(legacy_wire.end(), ct.begin(), ct.end());

  GCMEncryption compact(key, secret, false);
  const auto dec = compact.decrypt(legacy_wire);
  TEST_ASSERT(dec.size() == msg.size());
  TEST_ASSERT(std::memcmp(dec.data(), msg.data(), msg.size()) == 0);

  // Also verify compact.encrypt() can be decrypted by raw mbedtls_gcm_auth_decrypt.
  const auto enc = compact.encrypt(msg.data(), msg.size());
  TEST_ASSERT(enc.size() == 16 + 1 + 8 + msg.size());
  const uint8_t enc_len = enc[16];
  TEST_ASSERT(enc_len == 8 + msg.size());
  std::vector<uint8_t> raw_pt(enc_len);
  TEST_ASSERT(mbedtls_gcm_auth_decrypt(&raw_ctx, enc_len, enc.data(), 8, nullptr, 0, enc.data() + 8, 8, enc.data() + 17,
                                       raw_pt.data()) == 0);
  TEST_ASSERT(std::memcmp(raw_pt.data(), secret, 8) == 0);
  TEST_ASSERT(std::memcmp(raw_pt.data() + 8, msg.data(), msg.size()) == 0);

  // Also verify extended.encrypt() uses 12-byte IV, 16-byte tag, and 2-byte length via raw mbedtls_gcm_auth_decrypt.
  GCMEncryption extended(key, secret, true);
  const auto ext_enc = extended.encrypt(msg.data(), msg.size());
  TEST_ASSERT(ext_enc.size() == 28 + 2 + 8 + msg.size());
  uint16_t ext_len = 0;
  std::memcpy(&ext_len, ext_enc.data() + 28, sizeof(uint16_t));
  TEST_ASSERT(ext_len == 8 + msg.size());
  std::vector<uint8_t> ext_raw_pt(ext_len);
  TEST_ASSERT(mbedtls_gcm_auth_decrypt(&raw_ctx, ext_len, ext_enc.data(), 12, nullptr, 0, ext_enc.data() + 12, 16,
                                       ext_enc.data() + 30, ext_raw_pt.data()) == 0);
  TEST_ASSERT(std::memcmp(ext_raw_pt.data(), secret, 8) == 0);
  TEST_ASSERT(std::memcmp(ext_raw_pt.data() + 8, msg.data(), msg.size()) == 0);

  mbedtls_gcm_free(&raw_ctx);
}

void testLifecycleAndEdgeCases(const char *key, const char *secret) {
  // Invalid constructor args fail closed.
  GCMEncryption null_key(nullptr, secret);
  TEST_ASSERT(null_key.encrypt("abc", 3).empty());
  TEST_ASSERT(null_key.decrypt("abc", 3).empty());

  GCMEncryption null_secret(key, nullptr);
  TEST_ASSERT(null_secret.encrypt("abc", 3).empty());
  TEST_ASSERT(null_secret.decrypt("abc", 3).empty());

  // Invalid encrypt / decrypt arguments.
  GCMEncryption gcm(key, secret);
  TEST_ASSERT(gcm.encrypt(nullptr, 5).empty());
  TEST_ASSERT(gcm.encrypt("abc", 0).empty());
  TEST_ASSERT(gcm.decrypt(nullptr, 40).empty());
  TEST_ASSERT(gcm.decrypt(std::vector<uint8_t>()).empty());

  // Heap-allocated key and secret freed immediately after construction (catches dangling pointers).
  std::unique_ptr<GCMEncryption> heap_owned;
  {
    auto heap_key = std::make_unique<char[]>(17);
    auto heap_secret = std::make_unique<char[]>(9);
    std::memcpy(heap_key.get(), "HEAPKEY012345678", 16);
    std::memcpy(heap_secret.get(), "HEAPSEC1", 8);
    heap_owned = std::make_unique<GCMEncryption>(heap_key.get(), heap_secret.get(), true);
    std::memset(heap_key.get(), 0xFF, 16);
    std::memset(heap_secret.get(), 0xFF, 8);
  }
  const std::string msg = "Owned secret";
  const auto enc1 = heap_owned->encrypt(msg.data(), msg.size());
  const auto enc2 = heap_owned->encrypt(msg.data(), msg.size());
  TEST_ASSERT(!enc1.empty() && !enc2.empty());
  TEST_ASSERT(enc1 != enc2); // Random IVs produce distinct ciphertexts.
  const auto dec1 = heap_owned->decrypt(enc1);
  TEST_ASSERT(dec1.size() == msg.size());
  TEST_ASSERT(std::memcmp(dec1.data(), msg.data(), msg.size()) == 0);

  // Concurrent encrypt/decrypt across threads on a shared instance.
  std::vector<std::thread> workers;
  for (int t = 0; t < 4; ++t) {
    workers.emplace_back([&heap_owned, t]() {
      for (int i = 0; i < 50; ++i) {
        const std::string payload = "thread-" + std::to_string(t) + "-msg-" + std::to_string(i);
        const auto c = heap_owned->encrypt(payload.data(), payload.size());
        TEST_ASSERT(!c.empty());
        const auto p = heap_owned->decrypt(c);
        TEST_ASSERT(p.size() == payload.size());
        TEST_ASSERT(std::memcmp(p.data(), payload.data(), payload.size()) == 0);
      }
    });
  }
  for (auto &w : workers) {
    w.join();
  }
}

} // namespace

extern "C" {
void app_main();
}

void app_main(void) {
  const char key[] = "0123456789ABCDEF";
  const char secret[] = "01234567";

  testCompactRoundTripAndLimits(key, secret);
  testExtendedRoundTripAndLimits(key, secret);
  testCrossModeMismatch(key, secret);
  testAuthenticationAndBoundsChecks(key, secret, false);
  testAuthenticationAndBoundsChecks(key, secret, true);
  testWireFormatCompatibilityWithMbedtls(key, secret);
  testLifecycleAndEdgeCases(key, secret);

  std::printf("All GCMEncryption tests passed.\n");
  std::fflush(stdout);
  std::exit(0);
}
