/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_DESCRIPTION_H_
#define _QOS_FLOW_DESCRIPTION_H_

#include <cstdint>
#include <vector>
#include <optional>
#include "Struct.hpp"
#include "QosFlowDescriptionParameter.hpp"

namespace oai::nas {
constexpr uint8_t kQosFlowDescriptionMinimumLength = 3;

constexpr uint8_t kQosFlowDescriptionRuleOperationCodeReserved000 = 0;  // 0b000
constexpr uint8_t
    kQosFlowDescriptionRuleOperationCodeCreateNewQosFlowDescription =
        1;  // 0b001
constexpr uint8_t
    kQosFlowDescriptionRuleOperationCodeDeleteExistingQosFlowDescription =
        2;  // 0b010
constexpr uint8_t
    kQosFlowDescriptionRuleOperationCodeModifyExistingQosFlowDescriptionAndAddPacketFilters =
        3;  // 0b011
constexpr uint8_t
    kQosFlowDescriptionRuleOperationCodeModifyExistingQosFlowDescriptionAndReplaceAllPacketFilters =
        4;  // 0b100
constexpr uint8_t
    kQosFlowDescriptionRuleOperationCodeModifyExistingQosFlowDescriptionAndDeletePacketFilters =
        5;  // 0b101
constexpr uint8_t
    kQosFlowDescriptionRuleOperationCodeModifyExistingQosFlowDescriptionWithoutModifyingPacketFilters =
        6;                                                              // 110
constexpr uint8_t kQosFlowDescriptionRuleOperationCodeReserved111 = 7;  // 111

// Ebit
constexpr uint8_t kQosFlowDescriptionEBitReserved                 = 0;
constexpr uint8_t kQosFlowDescriptionEBitParametersListIsIncluded = 1;

class QosFlowDescription {
 public:
  QosFlowDescription();
  virtual ~QosFlowDescription();

  int Encode(uint8_t* buf, int len) const;
  int Decode(const uint8_t* const buf, int len);

  uint16_t GetLength() const;
  void SetLength();

  void SetQfi(uint8_t qfi);
  void GetQfi(uint8_t& qfi) const;
  uint8_t GetQfi() const;

  void SetOperationCode(uint8_t code);
  void GetOperationCode(uint8_t& code) const;
  uint8_t GetOperationCode() const;

  void SetEBit(bool e_bit);
  void GetEBit(bool& e_bit) const;
  bool GetEBit() const;

  // void SetNumberOfParameters(uint8_t no_parameters);
  void GetNumberOfParameters(uint8_t& no_parameters) const;
  uint8_t GetNumberOfParameters() const;

  void SetParametersList(const std::vector<QosFlowDescriptionParameter>& list);
  void GetParametersList(std::vector<QosFlowDescriptionParameter>& list) const;
  std::vector<QosFlowDescriptionParameter> GetParametersList() const;

 private:
  uint16_t length_;
  uint8_t qfi_;
  uint8_t operation_code_;
  bool e_bit_;
  std::vector<QosFlowDescriptionParameter> parameters_list_;
};

}  // namespace oai::nas

#endif
