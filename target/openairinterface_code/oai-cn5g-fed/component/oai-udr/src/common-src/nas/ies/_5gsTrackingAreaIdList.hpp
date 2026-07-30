/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _5GS_TRACKING_AREA_ID_LIST_H_
#define _5GS_TRACKING_AREA_ID_LIST_H_

#include <vector>

#include "Struct.hpp"
#include "Type4NasIe.hpp"

constexpr uint8_t k5gsTrackingAreaIdListMinimumLength = 9;
constexpr uint8_t k5gsTrackingAreaIdListContentMinimumLength =
    k5gsTrackingAreaIdListMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t k5gsTrackingAreaIdListMaximumLength        = 114;
constexpr uint8_t k5gsTrackingAreaIdListMaximumSupportedTAIs = 16;
constexpr auto k5gsTrackingAreaIdListIeName = "5GS Tracking Area Identity List";

namespace oai::nas {

class _5gsTrackingAreaIdList : public Type4NasIe {
 public:
  _5gsTrackingAreaIdList();
  _5gsTrackingAreaIdList(bool iei);
  _5gsTrackingAreaIdList(const std::vector<p_tai_t>& tai_list);
  int Encode(uint8_t* buf, int len) const override;

  static std::string GetIeName() { return k5gsTrackingAreaIdListIeName; }

 private:
  std::vector<p_tai_t> tai_list_;

 private:
  int EncodeType00(p_tai_t item, uint8_t* buf, int len) const;
  int EncodeType01(p_tai_t item, uint8_t* buf, int len) const;
  int EncodeType10(p_tai_t item, uint8_t* buf, int len) const;
};

}  // namespace oai::nas

#endif
