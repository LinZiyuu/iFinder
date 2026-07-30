/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SERVICE_TYPE_H_
#define _SERVICE_TYPE_H_

#include "Type1NasIe.hpp"

constexpr auto kServiceTypeIeName = "Service Type";

namespace oai::nas {

class ServiceType : public Type1NasIe {
 public:
  ServiceType();
  ServiceType(uint8_t value);
  virtual ~ServiceType();

  static std::string GetIeName() { return kServiceTypeIeName; }

  void SetValue(uint8_t value);
  void GetValue(uint8_t& value) const;

 private:
  void SetValue() override;
  void GetValue() override;
  uint8_t service_type_value_;
};

}  // namespace oai::nas

#endif
