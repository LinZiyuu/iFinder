/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowDescription.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
QosFlowDescription::QosFlowDescription() : e_bit_(false) {
  SetLength();
}

//------------------------------------------------------------------------------
QosFlowDescription::~QosFlowDescription() {}

//------------------------------------------------------------------------------
uint16_t QosFlowDescription::GetLength() const {
  return length_;
}

//------------------------------------------------------------------------------
void QosFlowDescription::SetLength() {
  // Calculate the actual length
  length_ = kQosFlowDescriptionMinimumLength;  // Including  Octet 4,5,6
                                               // (Figure 9.11.4.12.2@3GPP
                                               // TS 24.501, Rel 16.14.0)
  if (parameters_list_.size() > 0) {
    for (auto p : parameters_list_) {
      length_ += p.GetLength();
    }
  }
}

//------------------------------------------------------------------------------
void QosFlowDescription::SetQfi(uint8_t qfi) {
  qfi_ = qfi & 0x3f;  // 6 bits
  SetLength();
}

//------------------------------------------------------------------------------
void QosFlowDescription::GetQfi(uint8_t& qfi) const {
  qfi = qfi_;
}

//------------------------------------------------------------------------------
uint8_t QosFlowDescription::GetQfi() const {
  return qfi_;
}

//------------------------------------------------------------------------------
void QosFlowDescription::SetOperationCode(uint8_t code) {
  operation_code_ = code & 0x07;  // 3 bits
}

//------------------------------------------------------------------------------
void QosFlowDescription::GetOperationCode(uint8_t& code) const {
  code = operation_code_;
}

//------------------------------------------------------------------------------
uint8_t QosFlowDescription::GetOperationCode() const {
  return operation_code_;
}

//------------------------------------------------------------------------------
void QosFlowDescription::SetEBit(bool e_bit) {
  e_bit_ = e_bit;
}
//------------------------------------------------------------------------------
void QosFlowDescription::GetEBit(bool& e_bit) const {
  e_bit = e_bit_;
}

//------------------------------------------------------------------------------
bool QosFlowDescription::GetEBit() const {
  return e_bit_;
}

//------------------------------------------------------------------------------
void QosFlowDescription::GetNumberOfParameters(uint8_t& no_parameters) const {
  no_parameters = parameters_list_.size();
}
//------------------------------------------------------------------------------
uint8_t QosFlowDescription::GetNumberOfParameters() const {
  return parameters_list_.size();
}

//------------------------------------------------------------------------------
void QosFlowDescription::SetParametersList(
    const std::vector<QosFlowDescriptionParameter>& list) {
  parameters_list_ = list;
  SetLength();
}

//------------------------------------------------------------------------------
void QosFlowDescription::GetParametersList(
    std::vector<QosFlowDescriptionParameter>& list) const {
  list = parameters_list_;
}
//------------------------------------------------------------------------------
std::vector<QosFlowDescriptionParameter> QosFlowDescription::GetParametersList()
    const {
  return parameters_list_;
}

//------------------------------------------------------------------------------
int QosFlowDescription::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding QosFlowDescription");

  int encoded_size = 0;

  // Validate the buffer's length and Encode IEI/Length (later)
  if (len < length_) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the length of this IE (%d "
        "octet)",
        length_);
    return KEncodeDecodeError;
  }

  // Octet 4: spare (2 bits) + QFI (6 bits)
  uint8_t octet4 = qfi_ & 0x3f;
  ENCODE_U8(buf + encoded_size, octet4, encoded_size);

  // Octet 5: Operation code (2 bits) + spare (4 bits)
  uint8_t octet5 = (operation_code_ & 0x07) << 5;
  ENCODE_U8(buf + encoded_size, octet5, encoded_size);

  uint8_t number_of_parameters = parameters_list_.size();

  // Octet 6: spare + e (1 bit) + number of parameters (6 bits)
  uint8_t octet6 = (e_bit_ << 6) | (number_of_parameters & 0x3f);
  ENCODE_U8(buf + encoded_size, octet6, encoded_size);

  if (parameters_list_.size() == 0) return encoded_size;

  // Parameter lists
  for (auto p : parameters_list_) {
    int encoded_size_ie = p.Encode(buf + encoded_size, len - encoded_size);
    if (encoded_size_ie > 0) encoded_size += encoded_size_ie;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded QosFlowDescription, len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int QosFlowDescription::Decode(const uint8_t* const buf, int len) {
  oai::logger::logger_common::nas().debug("Decoding QosFlowDescription");
  if (len < kQosFlowDescriptionMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kQosFlowDescriptionMinimumLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;

  // Octet 4: spare (2 bits) + QFI (6 bits)
  uint8_t octet4 = {};
  DECODE_U8(buf + decoded_size, octet4, decoded_size);
  qfi_ = octet4 & 0x3f;

  // Octet 5: Operation code (3 bits) + spare (4 bits)
  uint8_t octet5 = {};
  DECODE_U8(buf + decoded_size, octet5, decoded_size);
  operation_code_ = (octet5 & 0x80) >> 5;

  // Octet 6: spare + e (1 bit) + number of parameters (6 bits)
  uint8_t octet6 = {};
  DECODE_U8(buf + decoded_size, octet6, decoded_size);
  e_bit_                       = (octet6 >> 6) & 0x01;
  uint8_t number_of_parameters = octet6 & 0x3f;  // 6 bits

  // Parameters list
  parameters_list_.clear();
  for (int i = 0; i < number_of_parameters; i++) {
    QosFlowDescriptionParameter parameter = {};
    int decoded_parameter_size =
        parameter.Decode(buf + decoded_size, len - decoded_size);

    if (decoded_parameter_size > 0) {
      decoded_size += decoded_parameter_size;
      parameters_list_.push_back(parameter);
    }
  }

  oai::logger::logger_common::nas().debug(
      "Decoded QosFlowDescription (len %d)", decoded_size);
  return decoded_size;
}
