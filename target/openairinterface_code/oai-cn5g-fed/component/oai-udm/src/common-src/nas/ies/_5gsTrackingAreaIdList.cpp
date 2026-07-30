/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include "_5gsTrackingAreaIdList.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"
#include "nas_utils.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
_5gsTrackingAreaIdList::_5gsTrackingAreaIdList()
    : Type4NasIe(kIei5gsTrackingAreaIdentityList), tai_list_() {
  SetLengthIndicator(k5gsTrackingAreaIdListContentMinimumLength);
}

//------------------------------------------------------------------------------
_5gsTrackingAreaIdList::_5gsTrackingAreaIdList(bool iei)
    : Type4NasIe(), tai_list_() {
  if (iei) {
    SetIei(kIei5gsTrackingAreaIdentityList);
  }
  SetLengthIndicator(k5gsTrackingAreaIdListContentMinimumLength);
}

//------------------------------------------------------------------------------
_5gsTrackingAreaIdList::_5gsTrackingAreaIdList(
    const std::vector<p_tai_t>& tai_list)
    : Type4NasIe(kIei5gsTrackingAreaIdentityList) {
  // only store the first 16 TAIs
  uint8_t size =
      (tai_list.size() > k5gsTrackingAreaIdListMaximumSupportedTAIs) ?
          k5gsTrackingAreaIdListMaximumSupportedTAIs :
          tai_list.size();
  uint8_t ie_len = 0;
  for (int i = 0; i < size; i++) {
    tai_list_.push_back(tai_list[i]);
    switch (tai_list_[i].type) {
      case 0x00: {
        ie_len += 4 + tai_list_[i].tac_list.size() * 3;
      } break;
      case 0x01: {
        ie_len += 7;
      } break;
      case 0x10: {
        ie_len += 1 + tai_list_[i].tac_list.size() * 6;
      }
    }
  }

  tai_list_ = tai_list;
  SetLengthIndicator(ie_len);
}

//------------------------------------------------------------------------------
int _5gsTrackingAreaIdList::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // IEI and Length
  int len_pos = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size =
      Type4NasIe::Encode(buf + encoded_size, len, len_pos);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  for (int i = 0; i < tai_list_.size(); i++) {
    int item_len = 0;
    switch (tai_list_[i].type) {
      case 0x00: {
        int encode_00_type_size =
            EncodeType00(tai_list_[i], buf + encoded_size, len - encoded_size);
        if (encode_00_type_size == KEncodeDecodeError) break;
        item_len += encode_00_type_size;
      } break;
      case 0x01: {
        int encode_01_type_size =
            EncodeType01(tai_list_[i], buf + encoded_size, len - encoded_size);

        if (encode_01_type_size == KEncodeDecodeError) break;
        item_len += encode_01_type_size;
      } break;
      case 0x10: {
        int encode_10_type_size =
            EncodeType10(tai_list_[i], buf + encoded_size, len - encoded_size);
        if (encode_10_type_size == KEncodeDecodeError) break;
        item_len += encode_10_type_size;
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
int _5gsTrackingAreaIdList::EncodeType00(
    p_tai_t item, uint8_t* buf, int len) const {
  int encoded_size = 0;
  // Type of list/Number of elements
  uint8_t octet = 0x00 | (item.type & 0x60) |
                  ((item.tac_list.size() - 1) &
                   0x1f);  // see Table 9.11.3.9.2@3GPP TS 24.501 V16.1.0
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
int _5gsTrackingAreaIdList::EncodeType01(
    p_tai_t item, uint8_t* buf, int len) const {
  // TODO:
  return KEncodeDecodeError;
}

//------------------------------------------------------------------------------
int _5gsTrackingAreaIdList::EncodeType10(
    p_tai_t item, uint8_t* buf, int len) const {
  // TODO:
  return KEncodeDecodeError;
}
