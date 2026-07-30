/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ExtendedProtocolConfigurationOptions.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"
#include "conversions.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ExtendedProtocolConfigurationOptions::ExtendedProtocolConfigurationOptions()
    : Type6NasIe(kIeiExtendedProtocolConfigurationOptions), ext_(1), spare_(0) {
  SetLengthIndicator(kExtendedProtocolConfigurationOptionsContentMinimumLength);
}

//------------------------------------------------------------------------------
void ExtendedProtocolConfigurationOptions::SetLength() {
  // Calculate the actual length
  uint32_t length =
      kExtendedProtocolConfigurationOptionsContentMinimumLength;  // Extension
                                                                  // and
                                                                  // Configuration
                                                                  // Protocol;

  if (protocol_or_container_ids.size() > 0) {
    for (auto p : protocol_or_container_ids) {
      length +=
          (p.length_of_protocol_id_contents +
           3);  // 2 for protocol ID, 1 for Length of protocol ID contents
    }
  }
  SetLengthIndicator(length);
}

//------------------------------------------------------------------------------
void ExtendedProtocolConfigurationOptions::SetConfigurationProtocol(
    uint8_t configuration_protocol) {
  configuration_protocol_ = configuration_protocol;
}

//------------------------------------------------------------------------------
void ExtendedProtocolConfigurationOptions::GetConfigurationProtocol(
    uint8_t& configuration_protocol) const {
  configuration_protocol = configuration_protocol_;
}

//------------------------------------------------------------------------------
bool ExtendedProtocolConfigurationOptions::AddProtocolOrContainerId(
    const pco_protocol_or_container_id_t& id) {
  uint32_t new_length =
      GetLengthIndicator() + id.length_of_protocol_id_contents + 3;
  if (new_length > kExtendedProtocolConfigurationOptionsMaximumLength)
    return false;
  protocol_or_container_ids.push_back(id);
  SetLengthIndicator(new_length);
  return true;
}

//------------------------------------------------------------------------------
void ExtendedProtocolConfigurationOptions::GetProtocolOrContainerIds(
    std::vector<pco_protocol_or_container_id_t>& ids) const {
  ids.assign(
      protocol_or_container_ids.begin(), protocol_or_container_ids.end());
}

//------------------------------------------------------------------------------
void ExtendedProtocolConfigurationOptions::SetProtocolOrContainerIds(
    const std::vector<pco_protocol_or_container_id_t>& ids) {
  protocol_or_container_ids.assign(ids.begin(), ids.end());
  SetLength();
}

//------------------------------------------------------------------------------
void ExtendedProtocolConfigurationOptions::Set(
    const protocol_configuration_options_t& conf_opt) {
  ext_                    = conf_opt.ext;
  spare_                  = conf_opt.spare;
  configuration_protocol_ = conf_opt.configuration_protocol;
  protocol_or_container_ids.assign(
      conf_opt.protocol_or_container_ids.begin(),
      conf_opt.protocol_or_container_ids.end());
  SetLength();
}

//------------------------------------------------------------------------------
void ExtendedProtocolConfigurationOptions::Get(
    protocol_configuration_options_t& conf_opt) const {
  conf_opt.ext                    = ext_;
  conf_opt.spare                  = spare_;
  conf_opt.configuration_protocol = configuration_protocol_;
  conf_opt.protocol_or_container_ids.assign(
      protocol_or_container_ids.begin(), protocol_or_container_ids.end());
  conf_opt.num_protocol_or_container_id = protocol_or_container_ids.size();
}

//------------------------------------------------------------------------------
protocol_configuration_options_t ExtendedProtocolConfigurationOptions::Get()
    const {
  protocol_configuration_options_t conf_opt = {};
  conf_opt.ext                              = ext_;
  conf_opt.spare                            = spare_;
  conf_opt.configuration_protocol           = configuration_protocol_;
  conf_opt.protocol_or_container_ids.assign(
      protocol_or_container_ids.begin(), protocol_or_container_ids.end());
  conf_opt.num_protocol_or_container_id = protocol_or_container_ids.size();
  return conf_opt;
}

//------------------------------------------------------------------------------
int ExtendedProtocolConfigurationOptions::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());
  int encoded_size = 0;

  // Validate the buffer's length and Encode IEI/Length (later)
  int len_pos         = 0;
  int encoded_ie_size = Type6NasIe::Encode(buf + encoded_size, len, len_pos);
  if (encoded_ie_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_ie_size;

  // Octet3
  uint8_t octet3 = {};
  octet3         = 0x80 | spare_ | configuration_protocol_;
  ENCODE_U8(buf + encoded_size, octet3, encoded_size);
  // uint32_t new_length = GetLengthIndicator();
  for (int i = 0; i < protocol_or_container_ids.size(); i++) {
    ENCODE_U16(
        buf + encoded_size, protocol_or_container_ids[i].protocol_id,
        encoded_size);
    ENCODE_U8(
        buf + encoded_size,
        protocol_or_container_ids[i].length_of_protocol_id_contents,
        encoded_size);
    bstring b_str = nullptr;
  oai:
    utils::conv::string_to_bstring(
        protocol_or_container_ids[i].protocol_id_contents, b_str);
    encoded_ie_size =
        encode_bstring(b_str, (buf + encoded_size), len - encoded_size);
    encoded_size += encoded_ie_size;
    // Calulate the new length
    //  new_length +=
    //  protocol_or_container_ids[i].length_of_protocol_id_contents + 3; //2 for
    //  ID and 1 for length
  }
  // SetLengthIndicator(new_length);

  // Encode length
  int encoded_len_ie = 0;
  ENCODE_U16(buf + len_pos, encoded_size - GetHeaderLength(), encoded_len_ie);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int ExtendedProtocolConfigurationOptions::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());
  int decoded_size = 0;

  // IEI and Length
  int decoded_header_size = Type6NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;
  uint16_t ie_len = 0;
  ie_len          = GetLengthIndicator();

  if (len < GetIeLength()) {
    oai::logger::logger_common::nas().error(
        "Len is less than %d", GetIeLength());
    return KEncodeDecodeError;
  }

  // Octet 3
  uint8_t octet3 = {};
  DECODE_U8(buf + decoded_size, octet3, decoded_size);
  configuration_protocol_ = octet3 & 0x07;

  // Decode Protocol/Container list
  while (decoded_size < GetIeLength()) {
    pco_protocol_or_container_id_t pco_id = {};
    DECODE_U16(buf + decoded_size, pco_id.protocol_id, decoded_size);
    DECODE_U8(
        buf + decoded_size, pco_id.length_of_protocol_id_contents,
        decoded_size);
    if (pco_id.length_of_protocol_id_contents > 0) {
      bstring b_str = nullptr;

      int decoded_bstring_size = decode_bstring(
          &b_str, pco_id.length_of_protocol_id_contents, (buf + decoded_size),
          len - decoded_size);
      if (decoded_bstring_size > 0) {
      oai:
        utils::conv::bstring_to_string(b_str, pco_id.protocol_id_contents);
        decoded_size += pco_id.length_of_protocol_id_contents;
      }
    }
    oai::logger::logger_common::nas().debug(
        "Decoded PCO ID 0x%x", pco_id.protocol_id);
    protocol_or_container_ids.push_back(pco_id);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
