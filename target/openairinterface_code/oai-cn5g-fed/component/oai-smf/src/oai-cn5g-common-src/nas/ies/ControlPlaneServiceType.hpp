/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _CONTROL_PLANE_SERVICE_TYPE_H_
#define _CONTROL_PLANE_SERVICE_TYPE_H_

#include "Type1NasIe.hpp"

constexpr auto kControlPlaneServiceTypeIeName = "Control Plane Service Type";

namespace oai::nas {

class ControlPlaneServiceType : public Type1NasIe {
 public:
  ControlPlaneServiceType();
  ControlPlaneServiceType(uint8_t value);
  virtual ~ControlPlaneServiceType();

  static std::string GetIeName() { return kControlPlaneServiceTypeIeName; }

  void SetValue(uint8_t value);
  void GetValue(uint8_t& value) const;

 private:
  void SetValue() override;
  void GetValue() override;
  uint8_t service_type_value_;
};

}  // namespace oai::nas

#endif
