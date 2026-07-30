/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include "ServiceAreaList.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"
#include "nas_utils.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ServiceAreaList::ServiceAreaList()
    : Type4NasIe(kIei5gsTrackingAreaIdentityList), ie_list_() {
  SetLengthIndicator(kServiceAreaListContentMinimumLength);
}

//------------------------------------------------------------------------------
ServiceAreaList::ServiceAreaList(bool iei) : Type4NasIe(), ie_list_() {
  if (iei) {
    SetIei(kIeiServiceAreaList);
  }
  SetLengthIndicator(kServiceAreaListContentMinimumLength);
}

//------------------------------------------------------------------------------
ServiceAreaList::ServiceAreaList(
    const std::vector<service_area_list_ie_t>& list)
    : Type4NasIe(kIeiServiceAreaList) {
  // "Allowed type" should be the same in all the partial service area lists
  for (int i = 0; i < list.size(); i++) {
    if (list[i].type != list[0].type) return;
  }
  // only store the first 16 TAIs
  uint8_t size = (list.size() > kServiceAreaListMaximumSupportedTAIs) ?
                     kServiceAreaListMaximumSupportedTAIs :
                     list.size();

  uint8_t ie_len = 0;
  for (int i = 0; i < size; i++) {
    ie_list_.push_back(list[i]);

    switch (list[i].type) {
      case 0x00: {
        ie_len += 4 + list[i].tac_list.size() * 3;
      } break;
      case 0x01: {
        ie_len += 7;
      } break;
      case 0x10: {
        ie_len += 1 + list[i].tac_list.size() * 6;
      }
    }
  }

  SetLengthIndicator(ie_len);
}

//------------------------------------------------------------------------------
int ServiceAreaList::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int len_pos = 0;
  int encoded_header_size =
      Type4NasIe::Encode(buf + encoded_size, len, len_pos);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  for (int i = 0; i < ie_list_.size(); i++) {
    int item_len = 0;
    switch (ie_list_[i].type) {
      case 0x00: {
        int encode_00_type_size =
            EncodeType00(ie_list_[i], buf + encoded_size, len - encoded_size);
        if (encode_00_type_size == KEncodeDecodeError) break;
        item_len += encode_00_type_size;
      } break;
      case 0x01: {
        int encode_01_type_size =
            EncodeType01(ie_list_[i], buf + encoded_size, len - encoded_size);

        if (encode_01_type_size == KEncodeDecodeError) break;
        item_len += encode_01_type_size;
      } break;
      case 0x10: {
        int encode_10_type_size =
            EncodeType10(ie_list_[i], buf + encoded_size, len - encoded_size);
        if (encode_10_type_size == KEncodeDecodeError) break;
        item_len += encode_10_type_size;
      } break;
      case 0x11: {
        int encode_11_type_size =
            EncodeType11(ie_list_[i], buf + encoded_size, len - encoded_size);
        if (encode_11_type_size == KEncodeDecodeError) break;
        item_len += encode_11_type_size;
      } break;
    }
    encoded_size += item_len;
  }

  // Encode length
  int encoded_len_ie = 0;
  ENCODE_U8(buf + len_pos, encoded_size - GetHeaderLength(), encoded_len_ie);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int ServiceAreaList::EncodeType00(
    service_area_list_ie_t item, uint8_t* buf, int len) const {
  int encoded_size = 0;
  // Allowed type/Type of list/Number of elements
  uint8_t octet = (item.allowed_type & 0x80) | (item.type & 0x60) |
                  ((item.tac_list.size() - 1) &
                   0x1f);  // see Table 9.11.3.49.2@3GPP TS 24.501 V16.14.0
  ENCODE_U8(buf + encoded_size, octet, encoded_size);

  // Encode PLMN
  encoded_size += nas_utils::encodeMccMnc2Buffer(
      item.plmn_list[0].mcc, item.plmn_list[0].mnc, buf + encoded_size,
      len - encoded_size);

  // Encode TAC list
  for (int i = 0; i < item.tac_list.size(); i++) {
    ENCODE_U24(buf + encoded_size, item.tac_list[i], encoded_size);
  }
  return encoded_size;
}

//------------------------------------------------------------------------------
int ServiceAreaList::EncodeType01(
    service_area_list_ie_t item, uint8_t* buf, int len) const {
  int encoded_size = 0;
  // Allowed type/Type of list/Number of elements
  uint8_t octet = (item.allowed_type & 0x80) | (item.type & 0x60) |
                  ((item.tac_list.size() - 1) &
                   0x1f);  // see Table 9.11.3.49.3@3GPP TS 24.501 V16.14.0
  ENCODE_U8(buf + encoded_size, octet, encoded_size);

  // Encode PLMN
  encoded_size += nas_utils::encodeMccMnc2Buffer(
      item.plmn_list[0].mcc, item.plmn_list[0].mnc, buf + encoded_size,
      len - encoded_size);

  // Encode TAC
  ENCODE_U24(buf + encoded_size, item.tac_list[0], encoded_size);

  return encoded_size;
}

//------------------------------------------------------------------------------
int ServiceAreaList::EncodeType10(
    service_area_list_ie_t item, uint8_t* buf, int len) const {
  int encoded_size = 0;
  // Allowed type/Type of list/Number of elements
  uint8_t octet = (item.allowed_type & 0x80) | (item.type & 0x60) |
                  ((item.tac_list.size() - 1) &
                   0x1f);  // see Table 9.11.3.49.4@3GPP TS 24.501 V16.14.0
  ENCODE_U8(buf + encoded_size, octet, encoded_size);

  int list_size = (item.plmn_list.size() > item.tac_list.size()) ?
                      item.plmn_list.size() :
                      item.tac_list.size();

  for (int i = 0; i < list_size; i++) {
    // Encode PLMN
    encoded_size += nas_utils::encodeMccMnc2Buffer(
        item.plmn_list[i].mcc, item.plmn_list[i].mnc, buf + encoded_size,
        len - encoded_size);
    // Encode TAC
    ENCODE_U24(buf + encoded_size, item.tac_list[i], encoded_size);
  }

  return encoded_size;
}

//------------------------------------------------------------------------------
int ServiceAreaList::EncodeType11(
    service_area_list_ie_t item, uint8_t* buf, int len) const {
  int encoded_size = 0;
  // Allowed type/Type of list/Number of elements
  uint8_t octet = 0x00 | (item.type & 0x60) |
                  0x00;  // see Table 9.11.3.49.5@3GPP TS 24.501 V16.14.0
  ENCODE_U8(buf + encoded_size, octet, encoded_size);

  // Encode PLMN
  encoded_size += nas_utils::encodeMccMnc2Buffer(
      item.plmn_list[0].mcc, item.plmn_list[0].mnc, buf + encoded_size,
      len - encoded_size);

  // Encode TAC list
  for (int i = 0; i < item.tac_list.size(); i++) {
    ENCODE_U24(buf + encoded_size, item.tac_list[i], encoded_size);
  }
  return encoded_size;
}
