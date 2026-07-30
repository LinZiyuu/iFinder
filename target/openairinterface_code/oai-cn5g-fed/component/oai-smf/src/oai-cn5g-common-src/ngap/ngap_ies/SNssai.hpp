/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _S_NSSAI_H_
#define _S_NSSAI_H_

#include <optional>
#include <string>

extern "C" {
#include "Ngap_S-NSSAI.h"
#include "Ngap_SD.h"
#include "Ngap_SST.h"
}

namespace oai::ngap {

class SNssai {
 public:
  SNssai();
  virtual ~SNssai();

  void setSst(const std::string& sst);
  void getSst(std::string& sst) const;

  void setSst(const uint8_t& sst);
  void getSst(uint8_t& sst) const;
  uint8_t getSst() const;

  std::string getSstStr() const;

  void setSd(const std::string& sd_str);
  bool getSd(std::string& sd) const;
  std::string getSd() const;

  void setSd(const uint32_t& sd);
  bool getSd(uint32_t& sd) const;
  uint32_t getSdInt() const;

  bool encodeSd(Ngap_SD_t&) const;
  bool decodeSd(const Ngap_SD_t&);

  bool encode(Ngap_S_NSSAI_t&) const;
  bool decode(const Ngap_S_NSSAI_t&);

 private:
  uint8_t m_Sst;  // mandatory  OCTET_STRING(SIZE(1))
  std::optional<uint32_t> m_Sd;
};

}  // namespace oai::ngap

#endif
