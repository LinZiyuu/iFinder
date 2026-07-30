/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowDescriptionParameter.hpp"

#include "3gpp_24.501.hpp"
#include "3gpp_commons.h"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
QosFlowDescriptionParameter::QosFlowDescriptionParameter()
    : length_(0), contents_() {
  SetContentsLength();
}

//------------------------------------------------------------------------------
QosFlowDescriptionParameter::~QosFlowDescriptionParameter() {}

//------------------------------------------------------------------------------
uint8_t QosFlowDescriptionParameter::GetLength() const {
  return (length_ + 2);  // 1 for parameter identifier, 1 for length and actual
                         // length of the contents
}

//------------------------------------------------------------------------------
uint8_t QosFlowDescriptionParameter::GetContentsLength() const {
  return length_;
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::SetContentsLength() {
  // Calculate the actual length
  length_ = blength(contents_);
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::SetIdentifier(uint8_t id) {
  identifier_ = id;
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::GetIdentifier(uint8_t& id) const {
  id = identifier_;
}

//------------------------------------------------------------------------------
uint8_t QosFlowDescriptionParameter::GetIdentifier() const {
  return identifier_;
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::SetContents(const bstring& contents) {
  contents_ = contents;
  SetContentsLength();
}

//------------------------------------------------------------------------------
bstring QosFlowDescriptionParameter::GetContents() const {
  return contents_;
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::GetContents(bstring& contents) const {
  contents = contents_;
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::Set5qi(uint8_t _5qi) {
  identifier_ = kQosFlowDescriptionParameterIdentifier5qi;
  length_     = 1;
  contents_   = blk2bstr(&_5qi, 1);
  SetContentsLength();
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::Get5qi(std::optional<uint8_t>& _5qi) const {
  if ((identifier_ == kQosFlowDescriptionParameterIdentifier5qi) &&
      (length_ == 1)) {
    _5qi =
        std::make_optional<uint8_t>(*((uint8_t*) bdata(contents_)));  // 1 octet
  }
}

//------------------------------------------------------------------------------
std::optional<uint8_t> QosFlowDescriptionParameter::Get5qi() const {
  if ((identifier_ == kQosFlowDescriptionParameterIdentifier5qi) &&
      (length_ == 1)) {
    return std::make_optional<uint8_t>(
        *((uint8_t*) bdata(contents_)));  // 1 octet
  } else {
    return std::nullopt;
  }
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::SetBitRate(const BitRate& bit_rate) {
  length_ = 3;
  uint8_t content[3];
  content[0] = bit_rate.unit;
  content[1] = bit_rate.value >> 8;                  // 8 most significant bits
  content[2] = (uint8_t) (bit_rate.value & 0x00ff);  // 8 less significant bits
  contents_  = blk2bstr(&content, 3);
  SetContentsLength();
}
//------------------------------------------------------------------------------
std::optional<BitRate> QosFlowDescriptionParameter::GetBitRate() const {
  if (length_ == 3) {
    BitRate bit_rate = {};
    bit_rate.unit    = *((uint8_t*) bdata(contents_));
    bit_rate.value   = (*((uint8_t*) bdata(contents_) + 1) << 8) |
                     *((uint8_t*) bdata(contents_) + 2);
    return std::optional<BitRate>(bit_rate);
  } else {
    return std::nullopt;
  }
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::SetGfbrUplink(const BitRate& gfbr_uplink) {
  identifier_ = kQosFlowDescriptionParameterIdentifierGfbrUplink;
  SetBitRate(gfbr_uplink);
}
//------------------------------------------------------------------------------

void QosFlowDescriptionParameter::GetGfbrUplink(
    std::optional<BitRate>& gfbr_uplink) const {
  if ((identifier_ == kQosFlowDescriptionParameterIdentifierGfbrUplink)) {
    gfbr_uplink = GetBitRate();
  }
}

//------------------------------------------------------------------------------
std::optional<BitRate> QosFlowDescriptionParameter::GetGfbrUplink() const {
  if (identifier_ == kQosFlowDescriptionParameterIdentifierGfbrUplink) {
    return GetBitRate();
  } else {
    return std::nullopt;
  }
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::SetGfbrDownlink(
    const BitRate& gfbr_downlink) {
  identifier_ = kQosFlowDescriptionParameterIdentifierGfbrDownlink;
  SetBitRate(gfbr_downlink);
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::GetGfbrDownlink(
    std::optional<BitRate>& gfbr_downlink) const {
  if ((identifier_ == kQosFlowDescriptionParameterIdentifierGfbrDownlink)) {
    gfbr_downlink = GetBitRate();
  }
}

//------------------------------------------------------------------------------
std::optional<BitRate> QosFlowDescriptionParameter::GetGfbrDownlink() const {
  if (identifier_ == kQosFlowDescriptionParameterIdentifierGfbrDownlink) {
    return GetBitRate();
  } else {
    return std::nullopt;
  }
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::SetMfbrUplink(const BitRate& mfbr_uplink) {
  identifier_ = kQosFlowDescriptionParameterIdentifierMfbrUplink;
  SetBitRate(mfbr_uplink);
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::GetMfbrUplink(
    std::optional<BitRate>& mfbr_uplink) const {
  if ((identifier_ == kQosFlowDescriptionParameterIdentifierMfbrUplink)) {
    mfbr_uplink = GetBitRate();
  }
}

//------------------------------------------------------------------------------
std::optional<BitRate> QosFlowDescriptionParameter::GetMfbrUplink() const {
  if (identifier_ == kQosFlowDescriptionParameterIdentifierMfbrUplink) {
    return GetBitRate();
  } else {
    return std::nullopt;
  }
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::SetMfbrDownlink(
    const BitRate& mfbr_downlink) {
  identifier_ = kQosFlowDescriptionParameterIdentifierMfbrDownlink;
  SetBitRate(mfbr_downlink);
}

//------------------------------------------------------------------------------
void QosFlowDescriptionParameter::GetMfbrDownlink(
    std::optional<BitRate>& mfbr_downlink) const {
  if ((identifier_ == kQosFlowDescriptionParameterIdentifierMfbrDownlink)) {
    mfbr_downlink = GetBitRate();
  }
}

//------------------------------------------------------------------------------
std::optional<BitRate> QosFlowDescriptionParameter::GetMfbrDownlink() const {
  if (identifier_ == kQosFlowDescriptionParameterIdentifierMfbrDownlink) {
    return GetBitRate();
  } else {
    return std::nullopt;
  }
}

//------------------------------------------------------------------------------
int QosFlowDescriptionParameter::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug(
      "Encoding QosFlowDescriptionParameter");

  int encoded_size = 0;

  // Validate the buffer's length and Encode IEI/Length (later)
  if (len < GetLength()) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the length of this IE (%d "
        "octet)",
        length_);
    return KEncodeDecodeError;
  }

  // Parameter Identifier
  ENCODE_U8(buf + encoded_size, identifier_, encoded_size);

  // Length
  ENCODE_U8(buf + encoded_size, length_, encoded_size);

  // Parameter contents
  int encoded_content_size =
      encode_bstring(contents_, (buf + encoded_size), len - encoded_size);
  encoded_size += encoded_content_size;

  oai::logger::logger_common::nas().debug(
      "Encoded QosFlowDescriptionParameter, len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int QosFlowDescriptionParameter::Decode(const uint8_t* const buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding QosFlowDescriptionParameter");
  if (len < kQosFlowDescriptionParameterMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kQosFlowDescriptionParameterMinimumLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;

  // Parameter Identifier
  DECODE_U8(buf + decoded_size, identifier_, decoded_size);

  // Length
  DECODE_U8(buf + decoded_size, length_, decoded_size);

  // Parameter contents
  uint8_t decoded_bstring_size = decode_bstring(
      &contents_, length_, (buf + decoded_size), len - decoded_size);

  if (decoded_bstring_size > 0) decoded_size += length_;

  oai::logger::logger_common::nas().debug(
      "Decoded QosFlowDescriptionParameter (len %d)", decoded_size);
  return decoded_size;
}
