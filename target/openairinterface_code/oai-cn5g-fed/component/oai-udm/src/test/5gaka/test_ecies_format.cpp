/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include <endian.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <nettle/hmac.h>
#include <array>
#include <string>
#include "authentication_algorithms_with_5gaka.hpp"

using ::testing::Test;

struct EciesTestCase {
  std::string suci;
  std::string mcc;
  std::string mnc;
  std::string msin;
  std::string routing_indicator;
  std::string protection_scheme_id;
  std::string hn_public_key_id;
  std::string scheme_output1;
  std::string home_network_private_key;
  std::string home_network_public_key;
  std::string ephemeral_private_key;
  std::string ephemeral_public_key;
  std::string ephemeral_shared_key;
  std::string ephemeral_enc_key;
  std::string plain_text_block;
  std::string cipher_text_value;
  std::string ephemeral_mac_key;
  std::string mac_tag_value;
  std::string scheme_output2;
};

std::array<struct EciesTestCase, 1> const eciesFormatTestCases{
    {// Test Case 3GPP TS 33.501 version 17.12.0 Release 17 C.4.3.1
     // IMSI-based SUPI
     {
         "suci-0-274-012-678-1-27-"
         "b2e92f836055a255837debf850b528997ce0201c"
         "b82adfe4be1f587d07d8457dcb02352410cddd9e730ef3fa87",  // suci
         "274",                                                 // mcc
         "012",                                                 // mnc
         "001002086",                                           // msin
         "678",        // routing_indicator
         "1",          // protection_scheme_id
         "27",         // hn_public_key_id
         "001002086",  // scheme_output1
         "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38b"
         "d1d",  // home_network_private_key
         "5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a"
         "650",  // home_network_public_key
         "c80949f13ebe61af4ebdbd293ea4f942696b9e815d7e8f0096bbf6ed7de62"
         "256",  // ephemeral_private_key
         "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d84"
         "57d",  // ephemeral_public_key
         "028ddf890ec83cdf163947ce45f6ec1a0e3070ea5fe57e2b1f05139f3e824"
         "22a",                               // ephemeral_shared_key
         "2ba342cabd2b3b1e5e4e890da11b65f6",  // ephemeral_enc_key
         "00012080f6",                        // plain_text_block
         "cb02352410",                        // cipher_text_value
         "d9846966fb7cf5fcf11266c5957dea60b83fff2b7c940690a4bfe57b1eb52"
         "bd2",               // ephemeral_mac_key
         "cddd9e730ef3fa87",  // mac_tag_value
         "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d84"
         "57d"
         "cb02352410cddd9e730ef3fa87"  // scheme_output2
     }}};

TEST(TestSuiteEcies, suciFormat) {
  std::for_each(
      eciesFormatTestCases.begin(), eciesFormatTestCases.end(),
      [](const struct EciesTestCase& ecies_test_case) {
        std::string suci;
        std::string mcc;
        std::string mnc;
        std::string msin;
        std::string routing_indicator;
        std::string protection_scheme_id;
        std::string hn_public_key_id;
        std::string scheme_output2;
        std::string eccEphemeralPublicKey;
        std::string ciphertext;
        std::string mac_tag_value;
        std::string error;

        bool success = Authentication_5gaka::suciFromString(
            ecies_test_case.suci, mcc, mnc, routing_indicator,
            protection_scheme_id, hn_public_key_id, scheme_output2,
            eccEphemeralPublicKey, ciphertext, mac_tag_value, error);
        if (!success) {
          std::cerr << error << std::endl;
        }

        EXPECT_TRUE(success);
        EXPECT_EQ(ecies_test_case.mcc, mcc);
        EXPECT_EQ(ecies_test_case.mnc, mnc);
        EXPECT_EQ(ecies_test_case.routing_indicator, routing_indicator);
        EXPECT_EQ(ecies_test_case.protection_scheme_id, protection_scheme_id);
        EXPECT_EQ(ecies_test_case.hn_public_key_id, hn_public_key_id);
        EXPECT_EQ(ecies_test_case.scheme_output2, scheme_output2);
        EXPECT_EQ(ecies_test_case.ephemeral_public_key, eccEphemeralPublicKey);
        EXPECT_EQ(ecies_test_case.cipher_text_value, ciphertext);
        EXPECT_EQ(ecies_test_case.mac_tag_value, mac_tag_value);
      });
}
