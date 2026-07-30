/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include "endian.h"
#include "sha256.hpp"

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <nettle/hmac.h>

#include <array>
#include <string>

using ::testing::Test;

struct Sha256TestCase {
  std::string key;
  std::string data;
  std::string hmac;
};

// From Request for Comments: 4231
// https://datatracker.ietf.org/doc/html/rfc4231
std::array<struct Sha256TestCase, 7> const sha256TestCases{
    {// Test Case 1
     {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
      "0b0b0b0b",          // (20 bytes)
      "4869205468657265",  // ("Hi There")
      "b0344c61d8db38535ca8afceaf0bf12b"
      "881dc200c9833da726e9376c2e32cff7"},
     // Test Case 2
     {"4a656665",                         // ("Jefe")
      "7768617420646f2079612077616e7420"  // ("what do ya want ")
      "666f72206e6f7468696e673f",         // ("for nothing?")
      "5bdcc146bf60754e6a042426089575c7"
      "5a003f089d2739839dec58b964ec3843"},
     // Test Case 3
     {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaa",  // (20 bytes)
      "dddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddd"
      "dddd",  // (50 bytes)
      "773ea91e36800e46854db8ebd09181a7"
      "2959098b3ef8c122d9635514ced565fe"},
     // Test Case 4
     {"0102030405060708090a0b0c0d0e0f10"
      "111213141516171819",  // (25 bytes)
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
      "cdcd",  // (50 bytes)
      "82558a389a443c0ea4cc819899f2083a"
      "85f0faa3e578f8077a2e3ff46729665b"},
     // Test Case 5
     {"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
      "0c0c0c0c",                         // (20 bytes)
      "546573742057697468205472756e6361"  // ("Test With Trunca")
      "74696f6e",                         // ("tion")
      "a3b6167473100ee06e0c796c2955552b"},
     // Test Case 6
     {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaa",                           // (131 bytes)
      "54657374205573696e67204c61726765"  // ("Test Using Large")
      "72205468616e20426c6f636b2d53697a"  // ("r Than Block-Siz")
      "65204b6579202d2048617368204b6579"  // ("e Key - Hash Key")
      "204669727374",                     // (" First")
      "60e431591ee0b67f0d8a26aacbf5b77f"
      "8e0bc6213728c5140546040f0ee37f54"},
     // Test Case 7
     {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaa",  // (131 bytes)
      "54686973206973206120746573742075"
      // ("This is a test u")
      "73696e672061206c6172676572207468"
      // ("sing a larger th")
      "616e20626c6f636b2d73697a65206b65"
      // ("an block-size ke")
      "7920616e642061206c61726765722074"
      // ("y and a larger t")
      "68616e20626c6f636b2d73697a652064"
      // ("han block-size d")
      "6174612e20546865206b6579206e6565"
      // ("ata. The key nee")
      "647320746f2062652068617368656420"
      // ("ds to be hashed ")
      "6265666f7265206265696e6720757365"
      // ("before being use")
      "642062792074686520484d414320616c"
      // ("d by the HMAC al")
      "676f726974686d2e",
      // ("gorithm.")
      "9b09ffa71b942fcb27635fbcd5b0e944"
      "bfdc63644f0713938a7f51535c3a35e2"}}};

extern std::vector<uint8_t> hexStringToByteArray(const std::string& hexString);

TEST(TestSuiteSha256, rfc4231VersusNettle) {
  std::for_each(
      sha256TestCases.begin(), sha256TestCases.end(),
      [](const struct Sha256TestCase& sha256_test_case) {
        auto key           = hexStringToByteArray(sha256_test_case.key);
        auto data          = hexStringToByteArray(sha256_test_case.data);
        auto expected_hmac = hexStringToByteArray(sha256_test_case.hmac);

        EXPECT_GE(SHA256_DIGEST_SIZE, expected_hmac.size());

        uint8_t hmac[expected_hmac.size()];
        memset(&hmac, 0, sizeof(hmac));

        struct hmac_sha256_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        hmac_sha256_set_key(
            &ctx, key.size(), (static_cast<uint8_t*>(key.data())));
        hmac_sha256_update(
            &ctx, data.size(), static_cast<uint8_t*>(data.data()));
        hmac_sha256_digest(&ctx, expected_hmac.size(), hmac);
        for (int i = 0; i < expected_hmac.size(); i++) {
          EXPECT_EQ(expected_hmac.at(i), hmac[i]);
        }
      });
}
