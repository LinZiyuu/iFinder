/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_RULE_H_
#define _QOS_RULE_H_

#include <cstdint>
#include <vector>
#include <optional>

#include "Struct.hpp"

namespace oai::nas {
constexpr uint8_t kQosRuleMinimumLength = 4;

// Segregation
constexpr uint8_t kQosRuleSegregationNotRequested = 0;
constexpr uint8_t kQosRuleSegregationRequested    = 1;
// DRQ bit
constexpr uint8_t kQosRuleTheQosRuleIsNotTheDefaultQosRule = 0;
constexpr uint8_t kQosRuleTheQosRuleIsTheDefaultQosRule    = 1;

constexpr uint8_t kQosRuleRuleOperationCodeReserved000           = 0;  // 0b000
constexpr uint8_t kQosRuleRuleOperationCodeCreateNewQosRule      = 1;  // 0b001
constexpr uint8_t kQosRuleRuleOperationCodeDeleteExistingQosRule = 2;  // 0b010
constexpr uint8_t
    kQosRuleRuleOperationCodeModifyExistingQosRuleAndAddPacketFilters =
        3;  // 0b011
constexpr uint8_t
    kQosRuleRuleOperationCodeModifyExistingQosRuleAndReplaceAllPacketFilters =
        4;  // 0b100
constexpr uint8_t
    kQosRuleRuleOperationCodeModifyExistingQosRuleAndDeletePacketFilters =
        5;  // 0b101
constexpr uint8_t
    kQosRuleRuleOperationCodeModifyExistingQosRuleWithoutModifyingPacketFilters =
        6;                                                   // 110
constexpr uint8_t kQosRuleRuleOperationCodeReserved111 = 7;  // 111

// Packet filter component type identifier
constexpr uint8_t kQosRulePfctiMatchAllType                        = 0b00000001;
constexpr uint8_t kQosRulePfctiIpv4RemoteAddressType               = 0b00010000;
constexpr uint8_t kQosRulePfctiIpv4LocalAddressType                = 0b00010001;
constexpr uint8_t kQosRulePfctiIpv6RemoveAddressOrPrefixLengthType = 0b00100001;
constexpr uint8_t kQosRulePfctiIpv6LocalAddressOrPrefixLengthType  = 0b00100011;
constexpr uint8_t kQosRulePfctiProtocolIdentifierOrNextHeaderType  = 0b00110000;
constexpr uint8_t kQosRulePfctiSingleLocalPortType                 = 0b01000000;
constexpr uint8_t kQosRulePfctiLocalPortRangeType                  = 0b01000001;
constexpr uint8_t kQosRulePfctiSingleRemotePortType                = 0b01010000;
constexpr uint8_t kQosRulePfctiRemotePortRangeType                 = 0b01010001;
constexpr uint8_t kQosRulePfctiSecurityParameterIndexType          = 0b01100000;
constexpr uint8_t kQosRulePfctiTypeOfServiceOrTrafficClassType     = 0b01110000;
constexpr uint8_t kQosRulePfctiFlowLabelType                       = 0b10000000;
constexpr uint8_t kQosRulePfctiDestinationMacAddressType           = 0b10000001;
constexpr uint8_t kQosRulePfctiSourceMacAddressType                = 0b10000010;
constexpr uint8_t kQosRulePfcti8021qCtagVidType                    = 0b10000011;
constexpr uint8_t kQosRulePfcti8021qStagVidType                    = 0b10000100;
constexpr uint8_t kQosRulePfcti8021qCtagPcpOrDeiType               = 0b10000101;
constexpr uint8_t kQosRulePfcti8021qStagPcpOrDeiType               = 0b10000110;
constexpr uint8_t kQosRulePfctiEthertypeType                       = 0b10000111;

class QosRule {
 public:
  QosRule();
  virtual ~QosRule();

  int Encode(uint8_t* buf, int len) const;
  int Decode(const uint8_t* const buf, int len);

  uint16_t GetLengthIndicator() const;
  void SetLengthIndicator();

  uint16_t GetIeLength() const;

  void SetQosRuleId(uint8_t rule_id);
  void GetQosRuleId(uint8_t& rule_id) const;
  uint8_t GetQosRuleId() const;

  void SetRuleOperationCode(uint8_t code);
  void GetRuleOperationCode(uint8_t& code) const;
  uint8_t GetRuleOperationCode() const;

  void SetDqrBit(bool dqr);
  void GetDqrBit(bool& dqr) const;
  bool GetDqrBit() const;

  void SetNumberOfPacketFilters(uint8_t no_pf);
  void GetNumberOfPacketFilters(uint8_t& no_pf) const;
  uint8_t GetNumberOfPacketFilters() const;

  void SetPacketFilterModifyAndDeleteList(
      const std::vector<PacketFilterModifyAndDelete>& list);
  void GetPacketFilterModifyAndDeleteList(
      std::optional<std::vector<PacketFilterModifyAndDelete>>& list) const;
  std::optional<std::vector<PacketFilterModifyAndDelete>>
  GetPacketFilterModifyAndDeleteList() const;

  void SetPacketFilterCreateAndModifyAndReplaceList(
      const std::vector<PacketFilterCreateAndModifyAndReplace>& list);
  void GetPacketFilterCreateAndModifyAndReplaceList(
      std::optional<std::vector<PacketFilterCreateAndModifyAndReplace>>& list)
      const;
  std::optional<std::vector<PacketFilterCreateAndModifyAndReplace>>
  GetPacketFilterCreateAndModifyAndReplaceList() const;
  void AddPacketFilterCreateAndModifyAndReplace(
      const PacketFilterCreateAndModifyAndReplace& packet_filter);

  void SetPrecedence(uint8_t precedence);
  void GetPrecedence(std::optional<uint8_t>& precedence) const;
  std::optional<uint8_t> GetPrecedence() const;

  void SetSegregation(bool segregation);
  void GetSegregation(bool& segregation) const;
  bool GetSegregation() const;

  void SetQfi(uint8_t qfi);
  void GetQfi(std::optional<uint8_t>& qfi) const;
  std::optional<uint8_t> GetQfi() const;

 private:
  uint8_t qos_rule_id_;
  uint16_t length_;
  uint8_t rule_operation_code_;
  bool dqr_bit_;
  uint8_t number_of_packet_filters_;
  std::optional<std::vector<PacketFilterModifyAndDelete>>
      pf_modify_and_delete_list_;
  std::optional<std::vector<PacketFilterCreateAndModifyAndReplace>>
      pf_create_and_modify_and_replace_list_;
  std::optional<uint8_t> precedence_;
  bool segregation_;
  std::optional<uint8_t> qfi_;
};

}  // namespace oai::nas

#endif
