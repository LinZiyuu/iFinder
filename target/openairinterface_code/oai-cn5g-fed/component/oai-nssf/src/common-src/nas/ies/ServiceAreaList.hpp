/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SERVICE_AREA_LIST_H_
#define _SERVICE_AREA_LIST_H_

#include <vector>

#include "Struct.hpp"
#include "Type4NasIe.hpp"

constexpr uint8_t kServiceAreaListMinimumLength = 6;
constexpr uint8_t kServiceAreaListContentMinimumLength =
    kServiceAreaListMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kServiceAreaListMaximumLength        = 114;
constexpr uint8_t kServiceAreaListMaximumSupportedTAIs = 16;
constexpr auto kServiceAreaListIeName                  = "Service Area List";

namespace oai::nas {

class ServiceAreaList : public Type4NasIe {
 public:
  ServiceAreaList();
  ServiceAreaList(bool iei);
  ServiceAreaList(const std::vector<service_area_list_ie_t>& list);

  int Encode(uint8_t* buf, int len) const override;
  // TODO: int Decode(uint8_t* buf, int len);

  static std::string GetIeName() { return kServiceAreaListIeName; }

 private:
  std::vector<service_area_list_ie_t> ie_list_;

 private:
  int EncodeType00(service_area_list_ie_t item, uint8_t* buf, int len) const;
  int EncodeType01(service_area_list_ie_t item, uint8_t* buf, int len) const;
  int EncodeType10(service_area_list_ie_t item, uint8_t* buf, int len) const;
  int EncodeType11(service_area_list_ie_t item, uint8_t* buf, int len) const;
};

}  // namespace oai::nas

#endif
