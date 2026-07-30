/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduAddress.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"
#include "string.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduAddress::PduAddress() : Type4NasIe(), si6lla_(false) {
  SetLengthIndicator(kPduAddressContentMinimumLength);
}

//------------------------------------------------------------------------------
PduAddress::PduAddress(uint8_t iei)
    : Type4NasIe(kIeiPduAddress), si6lla_(false) {
  SetLengthIndicator(kPduAddressContentMinimumLength);
}

//------------------------------------------------------------------------------
PduAddress::~PduAddress() {}

//------------------------------------------------------------------------------
bool PduAddress::Validate(int len) const {
  // Validate length/IE
  if (!Type4NasIe::Validate(len)) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the length of the header (IEI/Length) "
        "of "
        "this IE (%d octet(s))",
        len);
    return false;
  }
  // Validate PDU session type value
  if (pdu_session_type_ == kPduAddressPduSessionTypeIpv4) {
    if (!ipv4_address_.has_value()) return false;
  } else if (pdu_session_type_ == kPduAddressPduSessionTypeIpv6) {
    if (!ipv6_address_.has_value()) return false;
  } else if (pdu_session_type_ == kPduAddressPduSessionTypeIpv4v6) {
    if (!ipv4_address_.has_value()) return false;
    if (!ipv6_address_.has_value()) return false;
  }
  return true;
}
//------------------------------------------------------------------------------
void PduAddress::SetSi6lla(bool si6lla) {
  si6lla_ = si6lla;
}
//------------------------------------------------------------------------------
bool PduAddress::GetSi6lla() const {
  return si6lla_;
}
//------------------------------------------------------------------------------
void PduAddress::SetPduSessionType(uint8_t pdu_session_type) {
  pdu_session_type_ = pdu_session_type & 0x07;  // 3 bits
}
//------------------------------------------------------------------------------
uint8_t PduAddress::GetPduSessionType() const {
  return pdu_session_type_;
}
//------------------------------------------------------------------------------
void PduAddress::SetIpv4Address(struct in_addr ipv4_address) {
  ipv4_address_ = std::make_optional<struct in_addr>(ipv4_address);
}
//------------------------------------------------------------------------------
std::optional<struct in_addr> PduAddress::GetIpv4Address() const {
  return ipv4_address_;
}
//------------------------------------------------------------------------------
void PduAddress::SetIpv6Address(struct in6_addr ipv6_address) {
  ipv6_address_ = std::make_optional<struct in6_addr>(ipv6_address);
  SetLengthIndicator(9);  // TODO: Remove hardcoded value
}
//------------------------------------------------------------------------------
std::optional<struct in6_addr> PduAddress::GetIpv6Address() const {
  return ipv6_address_;
}

//------------------------------------------------------------------------------
void PduAddress::SetIpv4v6Address(
    struct in_addr ipv4_address, struct in6_addr ipv6_address) {
  ipv4_address_ = std::make_optional<struct in_addr>(ipv4_address);
  ipv6_address_ = std::make_optional<struct in6_addr>(ipv6_address);
  SetLengthIndicator(13);  // TODO: Remove hardcoded value
}

//------------------------------------------------------------------------------
void PduAddress::GetIpv4v6Address(
    std::optional<struct in_addr>& ipv4_address,
    std::optional<struct in6_addr>& ipv6_address) const {
  ipv4_address = ipv4_address_;
  ipv6_address = ipv6_address_;
}

//------------------------------------------------------------------------------
void PduAddress::SetSmfIpv6LinkLocalAddress(
    struct in6_addr smf_ipv6_link_local_address) {
  smf_ipv6_link_local_address_ =
      std::make_optional<struct in6_addr>(smf_ipv6_link_local_address);
}

//------------------------------------------------------------------------------
std::optional<struct in6_addr> PduAddress::GetSmfIpv6LinkLocalAddress() const {
  return smf_ipv6_link_local_address_;
}

//------------------------------------------------------------------------------
int PduAddress::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  // Validate the IE first
  if (!Validate(len)) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the length of the header (IEI/Length) "
        "of "
        "this IE (%d octet(s))",
        len);
    return KEncodeDecodeError;
  }

  int ie_len = GetIeLength();

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // Octet 3: SI6LLA + PDU Session Type Value
  uint8_t octet3 = (si6lla_ << 3) | (pdu_session_type_ & 0x07);
  ENCODE_U8(buf + encoded_size, octet3, encoded_size);

  // PDU address information
  bstring str;
  if (pdu_session_type_ == kPduAddressPduSessionTypeIpv4) {
    if (ipv4_address_.has_value()) {
      str = bfromcstralloc(4, "\0");
      oai::utils::ipv4_to_bstring(ipv4_address_.value(), str);
    }
  } else if (pdu_session_type_ == kPduAddressPduSessionTypeIpv6) {
    if (ipv6_address_.has_value()) {
      str = bfromcstralloc(8, "\0");
      // 8 octets for interface identifier for the IPv6 link local address
      unsigned char bitstream_addr[8];
      for (int i = 0; i < 8; i++)
        bitstream_addr[i] = (uint8_t) ((ipv6_address_.value()).s6_addr[i + 8]);
      memcpy(str->data, bitstream_addr, sizeof(bitstream_addr));
    }
  } else if (pdu_session_type_ == kPduAddressPduSessionTypeIpv4v6) {
    str = bfromcstralloc(12, "\0");
    oai::utils::ipv4v6_to_pdu_address_information(
        ipv4_address_.value(), ipv6_address_.value(), str);
  }

  int size = encode_bstring(str, (buf + encoded_size), len - encoded_size);
  encoded_size += size;

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduAddress::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (len < kPduAddressMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kPduAddressMinimumLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;

  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;
  // Octet 3: SI6LLA + PDU Session Type Value
  uint8_t octet3 = {};
  DECODE_U8(buf + decoded_size, octet3, decoded_size);
  pdu_session_type_ = octet3 & 0x07;  // 3 less significant bits
  si6lla_           = (octet3 >> 3) & 0x01;

  // PDU address information
  bstring str;
  uint8_t decoded_bstring_size = 0;
  if (pdu_session_type_ == kPduAddressPduSessionTypeIpv4) {
    decoded_bstring_size =
        decode_bstring(&str, 4, (buf + decoded_size), len - decoded_size);
    if (decoded_bstring_size != 4) return KEncodeDecodeError;
    decoded_size += 4;
    struct in_addr ipv4_address;
    oai::utils::bstring_to_ipv4(str, ipv4_address);
    ipv4_address_ = std::make_optional<struct in_addr>(ipv4_address);
  } else if (pdu_session_type_ == kPduAddressPduSessionTypeIpv6) {
    decoded_bstring_size =
        decode_bstring(&str, 8, (buf + decoded_size), len - decoded_size);
    if (decoded_bstring_size != 8) return KEncodeDecodeError;
    decoded_size += 8;
    struct in6_addr ipv6_address;
    // 8 octets for interface identifier for the IPv6 link local address
    for (int i = 0; i < 8; i++) ipv6_address.s6_addr[i + 8] = str->data[i];
    ipv6_address_ = std::make_optional<struct in6_addr>(ipv6_address);
  } else if (pdu_session_type_ == kPduAddressPduSessionTypeIpv4v6) {
    decoded_bstring_size =
        decode_bstring(&str, 12, (buf + decoded_size), len - decoded_size);
    if (decoded_bstring_size != 12) return KEncodeDecodeError;
    decoded_size += 12;
    struct in_addr ipv4_address;
    struct in6_addr ipv6_address;
    oai::utils::pdu_address_information_to_ipv4v6(
        str, ipv4_address, ipv6_address);
    ipv4_address_ = std::make_optional<struct in_addr>(ipv4_address);
    ipv6_address_ = std::make_optional<struct in6_addr>(ipv6_address);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
