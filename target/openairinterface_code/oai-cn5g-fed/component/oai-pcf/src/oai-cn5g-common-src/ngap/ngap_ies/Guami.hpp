/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _GUAMI_H_
#define _GUAMI_H_

#include "AmfPointer.hpp"
#include "AmfRegionId.hpp"
#include "AmfSetId.hpp"
#include "PlmnId.hpp"

extern "C" {
#include "Ngap_GUAMI.h"
}

namespace oai::ngap {

class Guami {
 public:
  Guami();
  virtual ~Guami();

  void set(
      const PlmnId& plmnId, const AmfRegionId& amfRegionId,
      const AmfSetId& amfSetId, const AmfPointer& amfPointer);
  void get(
      PlmnId& plmnId, AmfRegionId& amfRegionId, AmfSetId& amfSetId,
      AmfPointer& amfPointer) const;

  bool set(
      const std::string& mcc, const std::string& mnc, uint8_t regionId,
      uint16_t setId, uint8_t pointer);
  void get(
      std::string& mcc, std::string& mnc, uint8_t& regionId, uint16_t& setId,
      uint8_t& pointer) const;

  bool set(
      const std::string& mcc, const std::string& mnc,
      const std::string& regionId, const std::string& setId,
      const std::string& pointer);
  void get(
      std::string& mcc, std::string& mnc, std::string& regionId,
      std::string& setId, std::string& pointer) const;

  bool encode(Ngap_GUAMI_t& guami) const;
  bool decode(const Ngap_GUAMI_t& pdu);

 private:
  PlmnId m_PlmnId;            // Mandatory
  AmfRegionId m_AmfRegionId;  // Mandatory
  AmfSetId m_AmfSetId;        // Mandatory
  AmfPointer m_AmfPointer;    // Mandatory
};

}  // namespace oai::ngap

#endif
