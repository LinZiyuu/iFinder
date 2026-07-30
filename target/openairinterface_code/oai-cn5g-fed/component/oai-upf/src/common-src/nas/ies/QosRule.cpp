/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosRule.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
QosRule::QosRule()
    : length_(kQosRuleMinimumLength), segregation_(false), dqr_bit_(false) {}

//------------------------------------------------------------------------------
QosRule::~QosRule() {}

//------------------------------------------------------------------------------
uint16_t QosRule::GetLengthIndicator() const {
  return length_;
}

//------------------------------------------------------------------------------
void QosRule::SetLengthIndicator() {
  // Calculate the actual length
  length_ = 1;  // Rule Operation Code + DQR + Number of packet filters
  for (int i = 0; i < number_of_packet_filters_; i++) {
    if (rule_operation_code_ ==
        kQosRuleRuleOperationCodeModifyExistingQosRuleAndDeletePacketFilters) {
      length_++;  // 1 octet for each packet filter
    } else if (
        (rule_operation_code_ == kQosRuleRuleOperationCodeCreateNewQosRule) or
        (rule_operation_code_ ==
         kQosRuleRuleOperationCodeModifyExistingQosRuleAndAddPacketFilters) or
        (rule_operation_code_ ==
         kQosRuleRuleOperationCodeModifyExistingQosRuleAndReplaceAllPacketFilters)) {
      if (pf_create_and_modify_and_replace_list_.has_value()) {
        for (auto p : pf_create_and_modify_and_replace_list_.value()) {
          length_ +=
              1;  // octet 8- packet filter direction + packet filter identifier
          length_ += 1;                 // length of packet filter
          length_ += p.content.length;  // packet filter content
        }
      }
    }
  }

  if (precedence_.has_value()) length_ += 1;
  if (segregation_ or qfi_.has_value()) length_ += 1;
}

//------------------------------------------------------------------------------
uint16_t QosRule::GetIeLength() const {
  return (
      GetLengthIndicator() + 3);  // 1 for QoS rule ID, 2 for length of QoSRule
}

//------------------------------------------------------------------------------
void QosRule::SetQosRuleId(uint8_t rule_id) {
  qos_rule_id_ = rule_id;
}

//------------------------------------------------------------------------------
void QosRule::GetQosRuleId(uint8_t& rule_id) const {
  rule_id = qos_rule_id_;
}

//------------------------------------------------------------------------------
uint8_t QosRule::GetQosRuleId() const {
  return qos_rule_id_;
}

//------------------------------------------------------------------------------
void QosRule::SetRuleOperationCode(uint8_t code) {
  rule_operation_code_ = code & 0x07;  // 3 bits
}

//------------------------------------------------------------------------------
void QosRule::GetRuleOperationCode(uint8_t& code) const {
  code = rule_operation_code_;
}

//------------------------------------------------------------------------------
uint8_t QosRule::GetRuleOperationCode() const {
  return rule_operation_code_;
}

//------------------------------------------------------------------------------
void QosRule::SetDqrBit(bool dqr) {
  dqr_bit_ = dqr;
}
//------------------------------------------------------------------------------
void QosRule::GetDqrBit(bool& dqr) const {
  dqr = dqr_bit_;
}

//------------------------------------------------------------------------------
bool QosRule::GetDqrBit() const {
  return dqr_bit_;
}

//------------------------------------------------------------------------------
void QosRule::SetNumberOfPacketFilters(uint8_t no_pf) {
  number_of_packet_filters_ = no_pf & 0x0f;  // 4 bits
}

//------------------------------------------------------------------------------
void QosRule::GetNumberOfPacketFilters(uint8_t& no_pf) const {
  no_pf = number_of_packet_filters_;
}
//------------------------------------------------------------------------------
uint8_t QosRule::GetNumberOfPacketFilters() const {
  return number_of_packet_filters_;
}

//------------------------------------------------------------------------------
void QosRule::SetPacketFilterModifyAndDeleteList(
    const std::vector<PacketFilterModifyAndDelete>& list) {
  pf_modify_and_delete_list_ =
      std::make_optional<std::vector<PacketFilterModifyAndDelete>>(list);
  SetLengthIndicator();
}

//------------------------------------------------------------------------------
void QosRule::GetPacketFilterModifyAndDeleteList(
    std::optional<std::vector<PacketFilterModifyAndDelete>>& list) const {
  list = pf_modify_and_delete_list_;
}
//------------------------------------------------------------------------------
std::optional<std::vector<PacketFilterModifyAndDelete>>
QosRule::GetPacketFilterModifyAndDeleteList() const {
  return pf_modify_and_delete_list_;
}

//------------------------------------------------------------------------------
void QosRule::SetPacketFilterCreateAndModifyAndReplaceList(
    const std::vector<PacketFilterCreateAndModifyAndReplace>& list) {
  pf_create_and_modify_and_replace_list_ =
      std::make_optional<std::vector<PacketFilterCreateAndModifyAndReplace>>(
          list);
  SetLengthIndicator();
}

//------------------------------------------------------------------------------
void QosRule::GetPacketFilterCreateAndModifyAndReplaceList(
    std::optional<std::vector<PacketFilterCreateAndModifyAndReplace>>& list)
    const {
  list = pf_create_and_modify_and_replace_list_;
}

std::optional<std::vector<PacketFilterCreateAndModifyAndReplace>>
QosRule::GetPacketFilterCreateAndModifyAndReplaceList() const {
  return pf_create_and_modify_and_replace_list_;
}

//------------------------------------------------------------------------------
void QosRule::AddPacketFilterCreateAndModifyAndReplace(
    const PacketFilterCreateAndModifyAndReplace& packet_filter) {
  if (pf_create_and_modify_and_replace_list_.has_value()) {
    pf_create_and_modify_and_replace_list_.value().push_back(packet_filter);
  } else {
    std::vector<PacketFilterCreateAndModifyAndReplace> packet_filter_list;
    packet_filter_list.push_back(packet_filter);
    pf_create_and_modify_and_replace_list_ =
        std::make_optional<std::vector<PacketFilterCreateAndModifyAndReplace>>(
            packet_filter_list);
  }
  SetLengthIndicator();
}

//------------------------------------------------------------------------------
void QosRule::SetPrecedence(uint8_t precedence) {
  precedence_ = std::make_optional<uint8_t>(precedence);
  SetLengthIndicator();
}

//------------------------------------------------------------------------------
void QosRule::GetPrecedence(std::optional<uint8_t>& precedence) const {
  precedence = precedence_;
}
//------------------------------------------------------------------------------
std::optional<uint8_t> QosRule::GetPrecedence() const {
  return precedence_;
}

//------------------------------------------------------------------------------
void QosRule::SetSegregation(bool segregation) {
  segregation_ = segregation;
  SetLengthIndicator();
}

//------------------------------------------------------------------------------
void QosRule::GetSegregation(bool& segregation) const {
  segregation = segregation_;
}

//------------------------------------------------------------------------------
bool QosRule::GetSegregation() const {
  return segregation_;
}

//------------------------------------------------------------------------------
void QosRule::SetQfi(uint8_t qfi) {
  qfi_ = qfi & 0x3f;  // 6 bits
  SetLengthIndicator();
}

//------------------------------------------------------------------------------
void QosRule::GetQfi(std::optional<uint8_t>& qfi) const {
  qfi = qfi_;
}

//------------------------------------------------------------------------------
std::optional<uint8_t> QosRule::GetQfi() const {
  return qfi_;
}

//------------------------------------------------------------------------------
int QosRule::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding QosRule");

  int encoded_size = 0;

  // Validate the buffer's length and Encode IEI/Length (later)
  if (len < length_) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the length of this IE (%d "
        "octet)",
        length_);
    return KEncodeDecodeError;
  }

  // QoS Rule Identifier
  ENCODE_U8(buf + encoded_size, qos_rule_id_, encoded_size);

  // Length
  ENCODE_U16(buf + encoded_size, GetLengthIndicator(), encoded_size);

  // Octet 7 - Rule operation code, DQR bit, Number of packet filters
  uint8_t octet_7 = ((rule_operation_code_ & 0x07) << 5) | (dqr_bit_ << 4) |
                    (number_of_packet_filters_ & 0x0f);
  ENCODE_U8(buf + encoded_size, octet_7, encoded_size);

  // Paket filter list
  for (int i = 0; i < number_of_packet_filters_; i++) {
    if (rule_operation_code_ ==
        kQosRuleRuleOperationCodeModifyExistingQosRuleAndDeletePacketFilters) {
      if (pf_modify_and_delete_list_.has_value()) {
        for (auto p : pf_modify_and_delete_list_.value()) {
          ENCODE_U8(
              buf + encoded_size, (p.packet_filter_id & 0x0f), encoded_size);
        }
      }

    } else if (
        (rule_operation_code_ == kQosRuleRuleOperationCodeCreateNewQosRule) or
        (rule_operation_code_ ==
         kQosRuleRuleOperationCodeModifyExistingQosRuleAndAddPacketFilters) or
        (rule_operation_code_ ==
         kQosRuleRuleOperationCodeModifyExistingQosRuleAndReplaceAllPacketFilters)) {
      if (pf_create_and_modify_and_replace_list_.has_value()) {
        auto p = (pf_create_and_modify_and_replace_list_.value())[i];
        uint8_t octet_8 =
            ((p.packet_filter_direction & 0x03) << 4) |
            (p.packet_filter_id & 0x0f);  // octet 8- packet filter direction
                                          // + packet filter identifier
        ENCODE_U8(buf + encoded_size, octet_8, encoded_size);
        ENCODE_U8(
            buf + encoded_size, p.content.length,
            encoded_size);  // length of packet filter

        for (auto const& pc : p.content.packet_filter_components) {
          ENCODE_U8(buf + encoded_size, pc.type, encoded_size);
          int encoded_content_size = encode_bstring(
              pc.value, (buf + encoded_size),
              len - encoded_size);  // packet filter content
          encoded_size += encoded_content_size;
        }
      }
    }
  }

  // Precedence
  if (precedence_.has_value())
    ENCODE_U8(buf + encoded_size, precedence_.value(), encoded_size);
  // Segregation + QFI
  uint8_t octet_segregation_qfi = {};
  if (segregation_) octet_segregation_qfi = 0b01000000;
  if (qfi_.has_value())
    octet_segregation_qfi = octet_segregation_qfi | (qfi_.value() & 0x03f);
  if (segregation_ or qfi_.has_value())
    ENCODE_U8(buf + encoded_size, octet_segregation_qfi, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded QosRule, len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int QosRule::Decode(const uint8_t* const buf, int len) {
  oai::logger::logger_common::nas().debug("Decoding QosRule");
  if (len < kQosRuleMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kQosRuleMinimumLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;

  // QoS Rule Identifier
  DECODE_U8(buf + decoded_size, qos_rule_id_, decoded_size);

  // Length
  DECODE_U16(buf + decoded_size, length_, decoded_size);

  // Octet 7 - Rule operation code, DQR bit, Number of packet filters
  uint8_t octet_7 = {};
  DECODE_U8(buf + decoded_size, octet_7, decoded_size);
  rule_operation_code_      = octet_7 >> 5;
  dqr_bit_                  = (octet_7 >> 4) & 0x01;
  number_of_packet_filters_ = octet_7 & 0x0f;

  // Packet filter list

  if (rule_operation_code_ ==
      kQosRuleRuleOperationCodeModifyExistingQosRuleAndDeletePacketFilters) {
    std::vector<PacketFilterModifyAndDelete> pf_modify_and_delete_list;
    for (int i = 0; i < number_of_packet_filters_; i++) {
      PacketFilterModifyAndDelete pf = {};
      DECODE_U8(buf + decoded_size, pf.packet_filter_id, decoded_size);
      pf_modify_and_delete_list.push_back(pf);
    }
    pf_modify_and_delete_list_ =
        std::make_optional<std::vector<PacketFilterModifyAndDelete>>(
            pf_modify_and_delete_list);
  }
  if ((rule_operation_code_ == kQosRuleRuleOperationCodeCreateNewQosRule) or
      (rule_operation_code_ ==
       kQosRuleRuleOperationCodeModifyExistingQosRuleAndAddPacketFilters) or
      (rule_operation_code_ ==
       kQosRuleRuleOperationCodeModifyExistingQosRuleAndReplaceAllPacketFilters)) {
    std::vector<PacketFilterCreateAndModifyAndReplace>
        pf_create_and_modify_and_replace_list;
    for (int i = 0; i < number_of_packet_filters_; i++) {
      PacketFilterCreateAndModifyAndReplace pf = {};
      uint8_t octet_8 = {};  // octet 8- packet filter direction
                             // + packet filter identifier
      DECODE_U8(buf + decoded_size, octet_8, decoded_size);
      pf.packet_filter_direction = (octet_8 >> 4) & 0x03;
      pf.packet_filter_id        = octet_8 & 0x0f;

      DECODE_U8(
          buf + decoded_size, pf.content.length,
          decoded_size);  // length of packet filter
      uint8_t packet_filter_length = pf.content.length;
      while (packet_filter_length > 0) {
        PacketFilterComponent pc = {};
        DECODE_U8(buf + decoded_size, pc.type, decoded_size);
        packet_filter_length -= 1;

        uint8_t decoded_ie_size = 0;
        switch (pc.type) {
          case kQosRulePfctiMatchAllType: {
            // not include the packet filter component value field
          } break;

          case kQosRulePfctiIpv4RemoteAddressType:
          case kQosRulePfctiIpv4LocalAddressType: {
            decoded_ie_size = decode_bstring(
                &pc.value, 8, (buf + decoded_size), len - decoded_size);
            // sequence of a four octet IPv4 address field and a four octet IPv4
            // address mask field
          } break;

          case kQosRulePfctiIpv6RemoveAddressOrPrefixLengthType:
          case kQosRulePfctiIpv6LocalAddressOrPrefixLengthType: {
            decoded_ie_size = decode_bstring(
                &pc.value, 17, (buf + decoded_size), len - decoded_size);
            // sequence of a sixteen octet IPv6 address field and one octet
            // prefix length field
          } break;

          case kQosRulePfctiProtocolIdentifierOrNextHeaderType: {
            decoded_ie_size = decode_bstring(
                &pc.value, 1, (buf + decoded_size), len - decoded_size);
            // IPv4 protocol identifier or Ipv6 next header

          } break;
          case kQosRulePfctiSingleLocalPortType:
          case kQosRulePfctiSingleRemotePortType: {
            // two octets which specify a port number
            decoded_ie_size = decode_bstring(
                &pc.value, 2, (buf + decoded_size), len - decoded_size);
          } break;
          case kQosRulePfctiLocalPortRangeType:
          case kQosRulePfctiRemotePortRangeType: {
            // sequence of a two octet port range low limit field and a two
            // octet port range high limit field
            decoded_ie_size = decode_bstring(
                &pc.value, 4, (buf + decoded_size), len - decoded_size);
          } break;
          case kQosRulePfctiSecurityParameterIndexType: {
            // four octets which specify the IPSec security parameter index
            decoded_ie_size = decode_bstring(
                &pc.value, 4, (buf + decoded_size), len - decoded_size);
          } break;
          case kQosRulePfctiTypeOfServiceOrTrafficClassType: {
            // sequence of a one octet type-of-service/traffic class field and a
            // one  octet type-of-service/traffic class mask field
            decoded_ie_size = decode_bstring(
                &pc.value, 2, (buf + decoded_size), len - decoded_size);
          } break;
          case kQosRulePfctiFlowLabelType: {
            // three octets which specify the IPv6 flow label
            decoded_ie_size = decode_bstring(
                &pc.value, 3, (buf + decoded_size), len - decoded_size);
          } break;

          case kQosRulePfctiDestinationMacAddressType:
          case kQosRulePfctiSourceMacAddressType: {
            // 6 octets which specify a MAC address
            decoded_ie_size = decode_bstring(
                &pc.value, 6, (buf + decoded_size), len - decoded_size);
          } break;
          case kQosRulePfcti8021qCtagVidType: {
            // two octets which specify the VID of the customer-VLAN tag (C-TAG)
            decoded_ie_size = decode_bstring(
                &pc.value, 2, (buf + decoded_size), len - decoded_size);
          } break;
          case kQosRulePfcti8021qStagVidType: {
            // two octets which specify the VID of the service-VLAN tag (S-TAG)
            decoded_ie_size = decode_bstring(
                &pc.value, 2, (buf + decoded_size), len - decoded_size);
          } break;
          case kQosRulePfcti8021qCtagPcpOrDeiType: {
            // one octet which specifies the 802.1Q C-TAG PCP and DEI
            decoded_ie_size = decode_bstring(
                &pc.value, 1, (buf + decoded_size), len - decoded_size);
          } break;
          case kQosRulePfcti8021qStagPcpOrDeiType: {
            // one octet which specifies the 802.1Q S-TAG PCP
            decoded_ie_size = decode_bstring(
                &pc.value, 1, (buf + decoded_size), len - decoded_size);
          } break;
          case kQosRulePfctiEthertypeType: {
            // two octets which specify an ethertype
            decoded_ie_size = decode_bstring(
                &pc.value, 2, (buf + decoded_size), len - decoded_size);
          } break;
          default: {
          } break;
        }

        if (decoded_ie_size > 0) {
          decoded_size += decoded_ie_size;
          packet_filter_length -= decoded_ie_size;
        }
      }

      pf_create_and_modify_and_replace_list.push_back(pf);
    }
    pf_create_and_modify_and_replace_list_ =
        std::make_optional<std::vector<PacketFilterCreateAndModifyAndReplace>>(
            pf_create_and_modify_and_replace_list);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded QosRule (len %d)", decoded_size);
  return decoded_size;
}
