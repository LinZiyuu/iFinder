/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SorTransparentContainer.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
SorTransparentContainer::SorTransparentContainer()
    : Type6NasIe(kIeiSorTransparentContainer), header_(), sor_mac_i_() {
  SetLengthIndicator(kSorTransparentContainerContentMinimumLength);
}

//------------------------------------------------------------------------------
SorTransparentContainer::SorTransparentContainer(
    uint8_t header,
    const uint8_t (&value)[kSorTransparentContainerIeMacLength]) {
  header_ = header;
  for (int i = 0; i < 16; i++) {
    this->sor_mac_i_[i] = value[i];
  }
  SetLengthIndicator(kSorTransparentContainerContentMinimumLength);
}

//------------------------------------------------------------------------------
SorTransparentContainer::~SorTransparentContainer() {}

//------------------------------------------------------------------------------
void SorTransparentContainer::GetValue(
    uint8_t (&value)[kSorTransparentContainerIeMacLength]) const {
  for (int i = 0; i < 16; i++) {
    value[i] = sor_mac_i_[i];
  }
}

//------------------------------------------------------------------------------
int SorTransparentContainer::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int ie_len = GetIeLength();

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length (later)
  int len_pos = 0;
  int encoded_header_size =
      Type6NasIe::Encode(buf + encoded_size, len, len_pos);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // Header
  ENCODE_U8(buf + encoded_size, header_, encoded_size);
  // SOR-MAC-I
  for (int i = 0; i < 16; i++) {
    ENCODE_U8(buf + encoded_size, sor_mac_i_[i], encoded_size);
  }

  // TODO: Encode spare for the rest
  uint8_t spare = 0;
  int spare_len = ie_len - encoded_size;
  for (int i = 0; i < spare_len; i++) {
    ENCODE_U8(buf + encoded_size, spare, encoded_size);
  }

  // Encode length
  int encoded_len_ie = 0;
  ENCODE_U16(buf + len_pos, encoded_size - GetHeaderLength(), encoded_len_ie);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int SorTransparentContainer::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  if (len < kSorTransparentContainerMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kSorTransparentContainerMinimumLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type6NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  DECODE_U8(buf + decoded_size, header_, decoded_size);
  // Decode SOR-MAC-I
  for (int i = 0; i < 16; i++) {
    DECODE_U8(buf + decoded_size, sor_mac_i_[i], decoded_size);
  }

  // TODO: decode the rest as spare for now
  uint8_t spare = 0;
  for (int i = 0; i < (GetLengthIndicator() -
                       kSorTransparentContainerContentMinimumLength);
       i++) {
    DECODE_U8(buf + decoded_size, spare, decoded_size);
  }

  oai::logger::logger_common::nas().debug("Decoded SOR-MAC-I");

  for (int j = 0; j < 16; j++) {
    oai::logger::logger_common::nas().debug("Value 0x%2x", sor_mac_i_[j]);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
