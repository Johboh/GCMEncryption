// Copyright (c) Johan Böhlin
// SPDX-License-Identifier: GPL-3.0-or-later

#include <GCMEncryption.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

void testCompactRoundTripAndLimits(const char *key, const char *secret) {
  GCMEncryption gcm(key, secret, false);

  // Normal message round-trip via both decrypt overloads.
  const std::string msg = "Hello, encrypted world!";
  const auto enc = gcm.encrypt(msg.data(), msg.size());
  assert(enc.size() == 16 + 1 + 8 + msg.size());

  const auto dec_vec = gcm.decrypt(enc);
  assert(dec_vec.size() == msg.size());
  assert(std::memcmp(dec_vec.data(), msg.data(), msg.size()) == 0);

  const auto dec_ptr = gcm.decrypt(enc.data(), enc.size());
  assert(dec_ptr == dec_vec);

  // Trailing unauthenticated bytes beyond wire_length should still decrypt cleanly without OOB.
  auto padded = enc;
  padded.push_back(0xAA);
  padded.push_back(0xBB);
  assert(gcm.decrypt(padded) == dec_vec);

  // Short messages (1..8 bytes) pad deterministically to minimal 33-byte wire packet and return 8 bytes.
  for (size_t len = 1; len <= 8; ++len) {
    std::vector<uint8_t> short_msg(len, static_cast<uint8_t>('A' + len));
    const auto short_enc = gcm.encrypt(short_msg.data(), short_msg.size());
    assert(short_enc.size() == 33);
    const auto short_dec = gcm.decrypt(short_enc);
    assert(short_dec.size() == 8);
    assert(std::memcmp(short_dec.data(), short_msg.data(), len) == 0);
    for (size_t i = len; i < 8; ++i) {
      assert(short_dec[i] == 0);
    }
  }

  // 9-byte message grows linearly: 16 header + 1 length + 8 secret + 9 msg = 34 bytes.
  const std::vector<uint8_t> nine_bytes(9, 0x55);
  const auto nine_enc = gcm.encrypt(nine_bytes.data(), nine_bytes.size());
  assert(nine_enc.size() == 34);
  assert(gcm.decrypt(nine_enc) == nine_bytes);

  // Maximum compact payload size: 230 bytes -> 255 bytes on wire.
  const std::vector<uint8_t> max_payload(230, 0x3C);
  const auto max_enc = gcm.encrypt(max_payload.data(), max_payload.size());
  assert(max_enc.size() == 255);
  assert(gcm.decrypt(max_enc) == max_payload);

  // Exceeding maximum compact payload size (231 bytes) must fail.
  const std::vector<uint8_t> over_max(231, 0x3C);
  assert(gcm.encrypt(over_max.data(), over_max.size()).empty());
}

void testExtendedRoundTripAndLimits(const char *key, const char *secret) {
  GCMEncryption gcm(key, secret, true);

  // Short message (1..8 bytes) produces minimal 46-byte wire packet (12 IV + 16 tag + 2 len + 16 min payload).
  const std::string short_msg = "Hi";
  const auto short_enc = gcm.encrypt(short_msg.data(), short_msg.size());
  assert(short_enc.size() == 46);
  const auto short_dec = gcm.decrypt(short_enc);
  assert(short_dec.size() == 8);
  assert(short_dec[0] == 'H' && short_dec[1] == 'i');
  for (size_t i = 2; i < 8; ++i) {
    assert(short_dec[i] == 0);
  }

  // Medium payload (> 255 bytes).
  std::vector<uint8_t> medium(512);
  for (size_t i = 0; i < medium.size(); ++i) {
    medium[i] = static_cast<uint8_t>(i & 0xFF);
  }
  const auto med_enc = gcm.encrypt(medium.data(), medium.size());
  assert(med_enc.size() == 28 + 2 + 8 + medium.size());
  assert(gcm.decrypt(med_enc) == medium);

  // Maximum extended payload size: 65497 bytes -> 65535 bytes on wire.
  const std::vector<uint8_t> max_payload(65497, 0x7A);
  const auto max_enc = gcm.encrypt(max_payload.data(), max_payload.size());
  assert(max_enc.size() == 65535);
  assert(gcm.decrypt(max_enc) == max_payload);

  // Exceeding maximum extended payload size (65498 bytes) must fail.
  const std::vector<uint8_t> over_max(65498, 0x7A);
  assert(gcm.encrypt(over_max.data(), over_max.size()).empty());
}

void testCrossModeMismatch(const char *key, const char *secret) {
  GCMEncryption compact(key, secret, false);
  GCMEncryption extended(key, secret, true);

  const std::string msg = "Cross mode compatibility check";
  const auto compact_enc = compact.encrypt(msg.data(), msg.size());
  const auto extended_enc = extended.encrypt(msg.data(), msg.size());

  assert(!compact_enc.empty());
  assert(!extended_enc.empty());
  assert(extended.decrypt(compact_enc).empty());
  assert(compact.decrypt(extended_enc).empty());
}

void testAuthenticationAndBoundsChecks(const char *key, const char *secret, bool extended_size) {
  GCMEncryption gcm(key, secret, extended_size);
  const size_t iv_size = extended_size ? 12 : 8;
  const size_t tag_size = extended_size ? 16 : 8;
  const size_t len_size = extended_size ? 2 : 1;
  const size_t header_size = iv_size + tag_size;

  const std::string msg = "Authenticated payload 0123456789";
  const auto enc = gcm.encrypt(msg.data(), msg.size());
  assert(!enc.empty());

  // Flip every byte in IV -> must fail.
  for (size_t i = 0; i < iv_size; ++i) {
    auto tampered = enc;
    tampered[i] ^= 0x01;
    assert(gcm.decrypt(tampered).empty());
  }

  // Flip every byte in GCM tag -> must fail.
  for (size_t i = 0; i < tag_size; ++i) {
    auto tampered = enc;
    tampered[iv_size + i] ^= 0x80;
    assert(gcm.decrypt(tampered).empty());
  }

  // Flip ciphertext byte in _secret prefix and in message body -> must fail.
  const size_t ct_offset = header_size + len_size;
  for (size_t i = ct_offset; i < enc.size(); ++i) {
    auto tampered = enc;
    tampered[i] ^= 0x01;
    assert(gcm.decrypt(tampered).empty());
  }

  // Wrong key -> must fail.
  const char wrong_key[] = "FEDCBA9876543210";
  GCMEncryption wrong_key_gcm(wrong_key, secret, extended_size);
  assert(wrong_key_gcm.decrypt(enc).empty());

  // Same key, wrong secret -> tag succeeds at GCM layer, secret check must reject.
  const char wrong_secret[] = "76543210";
  GCMEncryption wrong_secret_gcm(key, wrong_secret, extended_size);
  assert(wrong_secret_gcm.decrypt(enc).empty());

  // Oversized payload_length field -> must fail cleanly without OOB read.
  auto oversized = enc;
  oversized[header_size] = 0xFF;
  if (extended_size) {
    oversized[header_size + 1] = 0xFF;
  }
  assert(gcm.decrypt(oversized).empty());

  // Undersized payload_length field (<= SECRET_LENGTH) -> must fail.
  for (uint8_t bad_len : {uint8_t(0), uint8_t(1), uint8_t(8)}) {
    auto undersized = enc;
    undersized[header_size] = bad_len;
    if (extended_size) {
      undersized[header_size + 1] = 0;
    }
    assert(gcm.decrypt(undersized).empty());
  }

  // Truncated inputs for every length < enc.size() -> must fail cleanly.
  for (size_t trunc = 0; trunc < enc.size(); ++trunc) {
    assert(gcm.decrypt(enc.data(), trunc).empty());
  }
}

void testWireFormatCompatibilityWithMbedtls(const char *key, const char *secret) {
  // Verify compact (0.x) wire format matches raw mbedTLS AES-128-GCM (8-byte IV, 8-byte tag, 1-byte length).
  mbedtls_gcm_context raw_ctx;
  mbedtls_gcm_init(&raw_ctx);
  assert(mbedtls_gcm_setkey(&raw_ctx, MBEDTLS_CIPHER_ID_AES, reinterpret_cast<const unsigned char *>(key), 128) == 0);

  const std::string msg = "Wire compat check";
  uint8_t iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint8_t tag[8] = {0};
  std::vector<uint8_t> pt(8 + msg.size());
  std::memcpy(pt.data(), secret, 8);
  std::memcpy(pt.data() + 8, msg.data(), msg.size());
  std::vector<uint8_t> ct(pt.size());

  assert(mbedtls_gcm_crypt_and_tag(&raw_ctx, MBEDTLS_GCM_ENCRYPT, pt.size(), iv, sizeof(iv), nullptr, 0, pt.data(),
                                   ct.data(), sizeof(tag), tag) == 0);

  std::vector<uint8_t> legacy_wire;
  legacy_wire.insert(legacy_wire.end(), iv, iv + sizeof(iv));
  legacy_wire.insert(legacy_wire.end(), tag, tag + sizeof(tag));
  legacy_wire.push_back(static_cast<uint8_t>(pt.size()));
  legacy_wire.insert(legacy_wire.end(), ct.begin(), ct.end());

  GCMEncryption compact(key, secret, false);
  const auto dec = compact.decrypt(legacy_wire);
  assert(dec.size() == msg.size());
  assert(std::memcmp(dec.data(), msg.data(), msg.size()) == 0);

  // Also verify compact.encrypt() can be decrypted by raw mbedtls_gcm_auth_decrypt.
  const auto enc = compact.encrypt(msg.data(), msg.size());
  assert(enc.size() == 16 + 1 + 8 + msg.size());
  const uint8_t enc_len = enc[16];
  assert(enc_len == 8 + msg.size());
  std::vector<uint8_t> raw_pt(enc_len);
  assert(mbedtls_gcm_auth_decrypt(&raw_ctx, enc_len, enc.data(), 8, nullptr, 0, enc.data() + 8, 8, enc.data() + 17,
                                  raw_pt.data()) == 0);
  assert(std::memcmp(raw_pt.data(), secret, 8) == 0);
  assert(std::memcmp(raw_pt.data() + 8, msg.data(), msg.size()) == 0);

  mbedtls_gcm_free(&raw_ctx);
}

void testLifecycleAndEdgeCases(const char *key, const char *secret) {
  // Invalid constructor args fail closed.
  GCMEncryption null_key(nullptr, secret);
  assert(null_key.encrypt("abc", 3).empty());
  assert(null_key.decrypt("abc", 3).empty());

  GCMEncryption null_secret(key, nullptr);
  assert(null_secret.encrypt("abc", 3).empty());
  assert(null_secret.decrypt("abc", 3).empty());

  // Invalid encrypt / decrypt arguments.
  GCMEncryption gcm(key, secret);
  assert(gcm.encrypt(nullptr, 5).empty());
  assert(gcm.encrypt("abc", 0).empty());
  assert(gcm.decrypt(nullptr, 40).empty());
  assert(gcm.decrypt(std::vector<uint8_t>()).empty());

  // Temporary secret buffer overwritten after construction.
  char temp_secret[9] = "TEMPSEC1";
  GCMEncryption own_secret(key, temp_secret, true);
  std::memset(temp_secret, 0, sizeof(temp_secret));
  const std::string msg = "Owned secret";
  const auto enc1 = own_secret.encrypt(msg.data(), msg.size());
  const auto enc2 = own_secret.encrypt(msg.data(), msg.size());
  assert(!enc1.empty() && !enc2.empty());
  assert(enc1 != enc2); // Random IVs produce distinct ciphertexts.
  const auto dec1 = own_secret.decrypt(enc1);
  assert(dec1.size() == msg.size());
  assert(std::memcmp(dec1.data(), msg.data(), msg.size()) == 0);

  // Concurrent encrypt/decrypt across threads on a shared instance.
  std::vector<std::thread> workers;
  for (int t = 0; t < 4; ++t) {
    workers.emplace_back([&own_secret, t]() {
      for (int i = 0; i < 50; ++i) {
        const std::string payload = "thread-" + std::to_string(t) + "-msg-" + std::to_string(i);
        const auto c = own_secret.encrypt(payload.data(), payload.size());
        assert(!c.empty());
        const auto p = own_secret.decrypt(c);
        assert(p.size() == payload.size());
        assert(std::memcmp(p.data(), payload.data(), payload.size()) == 0);
      }
    });
  }
  for (auto &w : workers) {
    w.join();
  }
}

} // namespace

int main() {
  const char key[] = "0123456789ABCDEF";
  const char secret[] = "01234567";

  testCompactRoundTripAndLimits(key, secret);
  testExtendedRoundTripAndLimits(key, secret);
  testCrossModeMismatch(key, secret);
  testAuthenticationAndBoundsChecks(key, secret, false);
  testAuthenticationAndBoundsChecks(key, secret, true);
  testWireFormatCompatibilityWithMbedtls(key, secret);
  testLifecycleAndEdgeCases(key, secret);

  std::cout << "All GCMEncryption tests passed.\n";
  return 0;
}
