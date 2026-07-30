/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <cryptopp/aes.h>
#include <cryptopp/asn.h>
#include <cryptopp/ccm.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/dh2.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pubkey.h>
#include <cryptopp/xed25519.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>

#include <iostream>
using std::cout;
using std::endl;
using std::ostream;
#include <cstddef>
#include <stdexcept>  // std::out_of_range
using std::byte;

#include "authentication_algorithms_with_5gaka.hpp"
#include "conversions.hpp"
#include "logger.hpp"
#include "string.hpp"
#include "utils.hpp"

/*
5.8.2 Subscriber privacy related requirements to UDM and SIDF from ETSI TS 133
501 V17.12.0 The SIDF is responsible for de-concealment of the SUCI and shall
fulfil the following requirements: -The SIDF shall be a service offered by UDM.
-The SIDF shall resolve the SUPI from the SUCI based on the protection scheme
used to generate the SUCI. The Home Network Private Key used for subscriber
privacy shall be protected from physical attacks in the UDM. The UDM shall hold
the Home Network Public Key Identifier(s) for the private/public key pair(s)
used for subscriber privacy. The algorithm used for subscriber privacy shall be
executed in the secure environment of the UDM.

§6.12.5 Subscription identifier de-concealing function (SIDF) from ETSI TS 133
501 V17.12.0 SIDF is responsible for de-concealing the SUPI from the SUCI. When
the Home Network Public Key is used for encryption of SUPI, the SIDF shall use
the Home Network Private Key that is securely stored in the home operator's
network to decrypt the SUCI. The de-concealment shall take place at the UDM.
Access rights to the SIDF shall be defined, such that only a network element of
the home network is allowed to request SIDF.

Profile A
When using SUPI protection scheme Profile A, the key must be an X25519 Private
Key.

Generate a key pair and save the private key to a file called
hnpk_profile_a.pem: openssl genpkey -algorithm x25519 -outform pem -out
hnpk_profile_a.pem

Get the corresponding public key and save it to a file called
hnpk_profile_a.pub: openssl pkey -in hnpk_profile_a.pem -pubout -out
hnpk_profile_a.pub

Profile B
When using SUPI protection scheme Profile B, the key must be an Elliptic Curve
Private Key using curve prime256v1.

Generate a key pair and save the private key to a file called
hnpk_profile_b.pem: openssl genpkey -algorithm ec -pkeyopt
ec_paramgen_curve:prime256v1 -outform pem -out hnpk_profile_b.pem

Get the corresponding public key and save it to a file called
hnpk_profile_b.pub: openssl pkey -in hnpk_profile_b.pem -pubout -out
hnpk_profile_b.pub
*/

// const int kNullScheme                               = 0x0;
// const int kProfileA                                 = 0x1;
// const int kProfileB                                 = 0x2;
const int kHomeKeyDigitLength                       = 64;
const int kProfileAEccEphemeralPublicKeyDigitLength = 64;
const int kProfileBEccEphemeralPublicKeyDigitLength = 66;
const int kIcbDigitLength                           = 32;
const int kEphemeralEncKeyDigitLength               = 32;
const int kMacTagValueDigitLength                   = 16;
const size_t kProfileAMacKeyLengh                   = 32;
const size_t kProfileAEncKeyLength                  = 16;
const size_t kIcbLength                             = 16;
const size_t kProfileAMacLength                     = 8;
//------------------------------------------------------------------------------
bool Authentication_5gaka::suciFromString(
    const std::string& suci, std::string& mcc, std::string& mnc,
    std::string& routingIndicator, std::string& protectionSchemeId,
    std::string& hnpkId, std::string& schemeOutput,
    std::string& eccEphemeralPublicKey, std::string& ciphertext,
    std::string& macTagValue, std::string& error) {
  /*
String identifying a SUPI or a SUCI.              suci-0-    MCC   -    MNC -
ROUTINGIND - Pattern:
"^(imsi-[0-9]{5,15}|nai-.+|gli-.+|gci-.+|suci-(0-[0-9]{3}-[0-9]{2,3}|[1-7]-.+)-[0-9]{1,4}-(0-0-.+|[a-fA-F1-9]-([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])-[a-fA-F0-9]+)|.+)$"

 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 |s|u|c|i|-|0|-| MCC |-|MNC.-
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 */
  mcc                   = {};
  mnc                   = {};
  routingIndicator      = {};
  protectionSchemeId    = {};
  hnpkId                = {};
  schemeOutput          = {};
  eccEphemeralPublicKey = {};
  ciphertext            = {};
  macTagValue           = {};
  if (suci.find("suci-0-") == 0) {
    try {
      // Extract MCC
      mcc = suci.substr(7, 3);

      // Extract MNC
      if (suci.at(10) != '-') {
        error = "Malformatted SUCI";
        return false;
      }
      size_t pos = 0;
      if ((pos = suci.find_first_of('-', 11)) == std::string::npos) {
        error = "Malformatted SUCI";
        return false;
      }
      size_t mnc_lenth = pos - 11;
      mnc              = suci.substr(11, mnc_lenth);

      // Extract routing indicator
      size_t start_pos = pos + 1;
      if ((pos = suci.find_first_of('-', start_pos)) == std::string::npos) {
        error = "Malformatted SUCI for routing indicator";
        return false;
      }
      size_t routing_indicator_length = pos - start_pos;
      routingIndicator = suci.substr(start_pos, routing_indicator_length);

      // Extract Protection Scheme Id
      start_pos = pos + 1;
      if ((pos = suci.find_first_of('-', start_pos)) == std::string::npos) {
        error = "Malformatted SUCI for Protection Scheme Id";
        return false;
      }
      size_t protection_scheme_id_length = pos - start_pos;
      protectionSchemeId = suci.substr(start_pos, protection_scheme_id_length);

      // Home Network Public Key Id
      start_pos = pos + 1;
      if ((pos = suci.find_first_of('-', start_pos)) == std::string::npos) {
        error = "Malformatted SUCI for Home Network Public Key Id";
        return false;
      }
      size_t hnpk_id_length = pos - start_pos;
      hnpkId                = suci.substr(start_pos, hnpk_id_length);

      // Scheme output
      start_pos = pos + 1;

      int protection_scheme_id_int = std::stoi(protectionSchemeId);
      schemeOutput                 = suci.substr(start_pos, std::string::npos);
      switch (protection_scheme_id_int) {
        case kNullScheme:
          break;
        case kEciesSchemeProfileA:
          eccEphemeralPublicKey =
              schemeOutput.substr(0, kProfileAEccEphemeralPublicKeyDigitLength);
          ciphertext = schemeOutput.substr(
              kProfileAEccEphemeralPublicKeyDigitLength,
              schemeOutput.length() -
                  kProfileAEccEphemeralPublicKeyDigitLength -
                  kMacTagValueDigitLength);
          macTagValue = schemeOutput.substr(
              schemeOutput.length() - kMacTagValueDigitLength,
              std::string::npos);
          break;
        case kEciesSchemeProfileB:
          eccEphemeralPublicKey =
              schemeOutput.substr(0, kProfileBEccEphemeralPublicKeyDigitLength);
          ciphertext = schemeOutput.substr(
              kProfileBEccEphemeralPublicKeyDigitLength,
              schemeOutput.length() -
                  kProfileBEccEphemeralPublicKeyDigitLength -
                  kMacTagValueDigitLength);
          macTagValue = schemeOutput.substr(
              schemeOutput.length() - kMacTagValueDigitLength,
              std::string::npos);
          break;
        default:
          error = std::string("Unsupported protection scheme identifier ")
                      .append(protectionSchemeId);
          return false;
      }
    } catch (const std::out_of_range& oor) {
      error =
          std::string("Malformatted SUCI: Out of range ").append(oor.what());
      return false;
    }
    return true;
  } else {
    error = std::string("Malformatted SUCI-0-: ").append(suci);
    return false;
  }
}

//------------------------------------------------------------------------------
constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

std::string byte_array_2_hex_string(unsigned char* data, int len) {
  std::string s(len * 2, ' ');
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }
  return s;
}
//------------------------------------------------------------------------------
bool Authentication_5gaka::suciSidfProfileA(
    const std::string& homeNetworkPrivateKey,
    const std::string& homeNetworkPublicKey,
    const std::string& eccEphemeralPublicKey, const std::string& ciphertext,
    const std::string& macTagValue, const std::string& routingIndicator,
    std::string& plainText, std::string& error) {
  // -EC domain parameters:         Curve25519
  // -EC Diffie-Hellman primitive:  X25519
  // -point compression:            N/A
  // -KDF:           ANSI-X9.63-KDF
  // -Hash:          SHA-256
  // -SharedInfo1:   (the ephemeral public key octet string)
  // -MAC:           HMAC–SHA-256
  // -mackeylen      32 octets (256 bits)
  // -maclen:        8 octets (64 bits)
  // -SharedInfo2:   the empty string
  // -ENC:           AES–128 in CTR mode
  // -enckeylen:     16 octets (128 bits)
  // -icblen:        16 octets (128 bits)
  // -backwards compatibility mode: false

  std::string hexCodePrivate;
  CryptoPP::StringSource(
      homeNetworkPrivateKey, true,
      new CryptoPP::HexDecoder(new CryptoPP::StringSink(hexCodePrivate)));
  auto homeNetworkPrivateKeyChar =
      std::vector<unsigned char>(hexCodePrivate.begin(), hexCodePrivate.end());

  std::string hexCodePublic;
  CryptoPP::StringSource(
      homeNetworkPublicKey, true,
      new CryptoPP::HexDecoder(new CryptoPP::StringSink(hexCodePublic)));
  auto homeNetworkPublicKeyChar =
      std::vector<unsigned char>(hexCodePublic.begin(), hexCodePublic.end());

  std::string hexCodeEphemeralPublic;
  CryptoPP::StringSource(
      eccEphemeralPublicKey, true,
      new CryptoPP::HexDecoder(
          new CryptoPP::StringSink(hexCodeEphemeralPublic)));
  auto ephemeralPublicKeyChar = std::vector<unsigned char>(
      hexCodeEphemeralPublic.begin(), hexCodeEphemeralPublic.end());

  std::string hex_code_ciphertext;
  CryptoPP::StringSource(
      ciphertext, true,
      new CryptoPP::HexDecoder(new CryptoPP::StringSink(hex_code_ciphertext)));
  auto ciphertext_char = std::vector<unsigned char>(
      hex_code_ciphertext.begin(), hex_code_ciphertext.end());

  CryptoPP::x25519 ecdh(
      homeNetworkPublicKeyChar.data(), homeNetworkPrivateKeyChar.data());

  /*
  From SEC 1 Ver. 2.0
  Input: The input to the decryption operation is:
    1. A triple of octet strings C = (R, EM, D) or an octet string C,
  which is the ciphertext.
    2. (Optional) Two octet strings SharedInfo 1 and SharedInfo 2 which
  consist of some data shared by U and V . Output: An octet string M which
  is the decryption of C, or “invalid”.

  Actions: Decrypt C as follows:
    1. If C is an octet string and the leftmost octet of C is 0216 or 0316
  , parse the leftmost d(log2 q)/8e + 1 octets of C as an octet string R,
  the rightmost maclen octets of C as an octet string D, and the remaining
  octets of C as an octet string EM . If the leftmost octet of C is 0416 ,
  parse the leftmost 2d(log2 q)/8e + 1 octets of C as an octet string R,
  the rightmost maclen octets of C as an octet string D, and the remaining
  octets of C as an octet string EM . If the leftmost octet of C is not
  0216 , 0316 , or 0416 , output “invalid” and stop.
    2. Convert the octet string R to an elliptic curve point R = (xR , yR
  ) associated with the elliptic curve domain parameters T established
  during the setup procedure using the conversion routine specified in
  Section 2.3.4. If the conversion routine outputs “invalid”, output
  “invalid” and stop.
    3. If the elliptic curve Diffie-Hellman primitive is being used,
  receive an assurance that R is a valid elliptic curve public key using
  one of the methods specified in Section 3.2.2. If the elliptic curve
  cofactor Diffie-Hellman primitive is being used, receive an assurance
  that R is at least a partially valid elliptic curve public key using one
  of the methods specified in Section 3.2.2 or Section 3.2.3. If an
  appropriate assurance is not obtained, output “invalid” and stop.
    4. Decide whether to use the elliptic curve Diffie-Hellman primitive
  or the elliptic curve cofactor Diffie-Hellman primitive according to the
  convention established during the setup procedure. Use the chosen
  Diffie-Hellman primitive specified in Section 3.3 to derive a shared
  secret field element z ∈ Fq from V ’s secret key dV established during
  the key deployment procedure and the public key R. If the Diffie-Hellman
  primitive outputs “invalid”, output “invalid” and stop.
    5. Convert z ∈ Fq to an octet string Z using the conversion routine
  specified in Section 2.3.5.
    6. Use the key derivation function KDF established during the setup
  procedure to generate keying data K of length enckeylen + icblen +
  mackeylen octets from Z and [SharedInfo 1 ]. If the key derivation
  function outputs “invalid”, output “invalid” and stop.
    7. Parse the leftmost enckeylen octets of K as an encryption key EK,
  the middle icblen octets of K as an ICB, and the rightmost mackeylen
  octets of K as a MAC key MK.
    8. Use the tag checking operation of the MAC scheme MAC established
  during the setup pro- cedure to check that D is the tag on EM k
  [SharedInfo 2 ] under M K. If the MAC scheme outputs “invalid”, output
  “invalid” and stop.
    9. Use the decryption operation of the symmetric encryption scheme ENC
  established during the setup procedure to decrypt EM under EK as M . If
  the encryption scheme outputs “invalid”, output “invalid” and stop.
    10. Output M .
    */

  //--------------------------------------------------------------------
  //   4. Decide whether to use the elliptic curve Diffie-Hellman primitive
  // or the elliptic curve cofactor Diffie-Hellman primitive according to the
  // convention established during the setup procedure. Use the chosen
  // Diffie-Hellman primitive specified in Section 3.3 to derive a shared
  // secret field element z ∈ Fq from V ’s secret key dV established during
  // the key deployment procedure and the public key R. If the Diffie-Hellman
  // primitive outputs “invalid”, output “invalid” and stop.
  CryptoPP::SecByteBlock shared(ecdh.AgreedValueLength());
  if (!ecdh.Agree(
          shared, homeNetworkPrivateKeyChar.data(),
          ephemeralPublicKeyChar.data())) {
    error = "Failed to reach shared secret";
    return false;
  }
  //--------------------------------------------------------------------
  // 5. Convert z ∈ Fq to an octet string Z using the conversion routine
  // specified in Section 2.3.5.

  //--------------------------------------------------------------------
  //  6. Use the key derivation function KDF established during the setup
  // procedure to generate keying data K of length enckeylen + icblen +
  // mackeylen octets from Z and [SharedInfo 1 ]. If the key derivation
  // function outputs “invalid”, output “invalid” and stop.
  EVP_KDF* kdf;
  EVP_KDF_CTX* kctx;
  unsigned char
      out_kdf[kProfileAEncKeyLength + kIcbLength + kProfileAMacKeyLengh];
  OSSL_PARAM params[4], *p = params;

  kdf  = EVP_KDF_fetch(NULL, "X963KDF", NULL);
  kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);

  char sha256_comp_warn[] = {SN_sha256};
  *p++                    = OSSL_PARAM_construct_utf8_string(
      OSSL_KDF_PARAM_DIGEST, (char*) sha256_comp_warn, strlen(SN_sha256));
  *p++ = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_SECRET, reinterpret_cast<unsigned char*>(shared.data()),
      static_cast<size_t>(shared.size()));
  *p++ = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_INFO, ephemeralPublicKeyChar.data(),
      static_cast<size_t>(ephemeralPublicKeyChar.size()));
  *p = OSSL_PARAM_construct_end();
  if (EVP_KDF_derive(kctx, out_kdf, sizeof(out_kdf), params) <= 0) {
    error = "EVP_KDF_derive";
    return false;
  }
  EVP_KDF_CTX_free(kctx);
  //--------------------------------------------------------------------
  // 7. Parse the leftmost enckeylen octets of K as an encryption key EK,
  // the middle icblen octets of K as an ICB, and the rightmost mackeylen
  // octets of K as a MAC key MK.
  CryptoPP::SecByteBlock ephemeral_enc_key_bin(out_kdf, kProfileAEncKeyLength);
  CryptoPP::SecByteBlock icb_bin(&out_kdf[kProfileAEncKeyLength], kIcbLength);
  CryptoPP::SecByteBlock mac_key_bin(
      &out_kdf[kProfileAEncKeyLength + kIcbLength], kProfileAMacKeyLengh);
  // std::string mk_str, ephemeral_enc_key_str, icb_str;
  // ephemeral_enc_key_str.clear();
  // CryptoPP::StringSource ss_eph_deco_key(
  //     ephemeral_enc_key_bin, ephemeral_enc_key_bin.size(), true,
  //     new CryptoPP::HexEncoder(
  //         new CryptoPP::StringSink(ephemeral_enc_key_str)));
  // // cout << "ephemeral_enc_key: " << ephemeral_enc_key_str << endl;
  // icb_str.clear();
  // CryptoPP::StringSource ss_icb(
  //     icb_bin, icb_bin.size(), true,
  //     new CryptoPP::HexEncoder(new CryptoPP::StringSink(icb_str)));
  // // cout << "ICB: " << icb_str << endl;
  // mk_str.clear();
  // CryptoPP::StringSource ss_mac(
  //     mac_key_bin, mac_key_bin.size(), true,
  //     new CryptoPP::HexEncoder(new CryptoPP::StringSink(mk_str)));
  // cout << "MK: " << mk_str << endl;
  //--------------------------------------------------------------------
  // 8. Use the tag checking operation of the MAC scheme MAC established
  // during the setup procedure to check that D is the tag on EM k
  // [SharedInfo 2 ] under M K. If the MAC scheme outputs “invalid”, output
  // “invalid” and stop.
  std::string mac;
  try {
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(mac_key_bin, mac_key_bin.size());

    CryptoPP::StringSource ss2(
        ciphertext_char.data(), ciphertext_char.size(), true,
        new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)));
  } catch (const CryptoPP::Exception& e) {
    error = "HMAC: Invalid";
    return false;
  }
  mac.resize(kProfileAMacLength);
  std::string mac_computed_str;
  CryptoPP::StringSource ss_mac_str(
      mac, true,
      new CryptoPP::HexEncoder(new CryptoPP::StringSink(mac_computed_str)));
  std::transform(
      mac_computed_str.begin(), mac_computed_str.end(),
      mac_computed_str.begin(), ::tolower);

  if (macTagValue.compare(mac_computed_str) != 0) {
    error = "HMAC: MAC tag do not match";
    Logger::udm_ueau().debug("MAC computed %s", mac_computed_str);
    Logger::udm_ueau().debug("MACTagValue %s", macTagValue);
    return false;
  }
  //--------------------------------------------------------------------
  // 9. Use the decryption operation of the symmetric encryption scheme ENC
  // established during the setup procedure to decrypt EM under EK as M . If
  // the encryption scheme outputs “invalid”, output “invalid” and stop.
  std::string recovered;
  try {
    if (kProfileAEncKeyLength != CryptoPP::AES::DEFAULT_KEYLENGTH) {
      error = "AES key length";
      return false;
    }
    if (kIcbLength != CryptoPP::AES::BLOCKSIZE) {
      error = "AES CTR block size";
      return false;
    }
    CryptoPP::SecByteBlock key(kProfileAEncKeyLength);
    std::memcpy(key, out_kdf, kProfileAEncKeyLength);

    CryptoPP::byte ctr[kIcbLength];
    std::memcpy(ctr, &out_kdf[kProfileAEncKeyLength], kIcbLength);

    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption d;
    d.SetKeyWithIV(key, kProfileAEncKeyLength, ctr);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(
        ciphertext_char.data(), ciphertext_char.size(), true,
        new CryptoPP::StreamTransformationFilter(
            d, new CryptoPP::StringSink(recovered)));
  } catch (const CryptoPP::Exception& e) {
    error = e.what();
    return false;
  }

  CryptoPP::StringSource ss_recovered_str(
      recovered, true,
      new CryptoPP::HexEncoder(new CryptoPP::StringSink(plainText)));
  // MSIN can contain 'F' if original length is odd
  std::transform(
      plainText.begin(), plainText.end(), plainText.begin(), ::tolower);
  return true;
}
//------------------------------------------------------------------------------
bool unswapMsinPairedDigits(
    const std::string& swMsin, std::string& msin, std::string& error) {
  if (swMsin.length() & 1) {
    error = "odd msin length";
    return false;
  }

  msin.reserve(swMsin.length());
  for (int i = 0; i < (swMsin.length() >> 1); i++) {
    msin.push_back(swMsin[2 * i + 1]);
    msin.push_back(swMsin[2 * i]);
  }
  if ((msin[msin.length() - 1] == 'f') || (msin[msin.length() - 1] == 'F')) {
    msin.pop_back();
  }
  return true;
}
//------------------------------------------------------------------------------
bool Authentication_5gaka::suciSidf(
    const std::vector<subscriber_profile_t>& subscriber_profiles,
    const std::string& suci, std::string& routingIndicator, std::string& imsi,
    std::string& error) {
  std::string mcc;
  std::string mnc;
  std::string swapped_msin;
  std::string msin;
  std::string protection_scheme_id;
  std::string hnpk_id;
  std::string scheme_output;
  std::string ephemeral_public_key;
  std::string cipher_text_value;
  std::string mac_tag_value;
  imsi                              = {};
  error                             = {};
  std::string homeNetworkPublicKey  = {};
  std::string homeNetworkPrivateKey = {};
  if (suciFromString(
          suci, mcc, mnc, routingIndicator, protection_scheme_id, hnpk_id,
          scheme_output, ephemeral_public_key, cipher_text_value, mac_tag_value,
          error)) {
    int protection_scheme_id_int = std::stoi(protection_scheme_id);
    if (!getSubscriberProfile(
            protection_scheme_id_int, hnpk_id, subscriber_profiles,
            homeNetworkPrivateKey, homeNetworkPublicKey)) {
      error = "Failed to get subscriber profile";
      return false;
    }

    switch (protection_scheme_id_int) {
      case kNullScheme:
        msin = scheme_output;
        break;
      case kEciesSchemeProfileA:
        if (!suciSidfProfileA(
                homeNetworkPrivateKey, homeNetworkPublicKey,
                ephemeral_public_key, cipher_text_value, mac_tag_value,
                routingIndicator, swapped_msin, error)) {
          return false;
        }
        break;
      default:
        error =
            "Unsupported protection scheme identifier " + protection_scheme_id;
        return false;
    }

    imsi = "imsi-" + mcc + mnc;
    if (unswapMsinPairedDigits(swapped_msin, msin, error)) {
      imsi.append(msin);
      return true;
    }
    return false;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
bool Authentication_5gaka::getSubscriberProfile(
    uint8_t protection_scheme_id_int, const std::string& hnpk_id,
    const std::vector<subscriber_profile_t>& subscriber_profiles,
    std::string& homeNetworkPrivateKey, std::string& homeNetworkPublicKey) {
  for (const auto& profile : subscriber_profiles) {
    if ((profile.protection_scheme == protection_scheme_id_int) &&
        (profile.home_network_public_key_id == hnpk_id)) {
      homeNetworkPrivateKey = profile.home_network_private_key;
      homeNetworkPublicKey  = profile.home_network_public_key;
      return true;
    }
  }
  return false;
}
