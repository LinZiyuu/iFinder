/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UDR_SBI_HELPER_HPP
#define _UDR_SBI_HELPER_HPP

#include <nlohmann/json.hpp>

#include "udr_config.hpp"
#include "sbi_helper.hpp"

using namespace oai::common::sbi;

extern oai::udr::config::udr_config udr_cfg;

namespace oai::udr::api {

class udr_sbi_helper : public sbi_helper {
 public:
  static inline const std::string UdrDataRepositoryServiceBase =
      sbi_helper::UdrDataRepositoryBase +
      udr_cfg.nudr.api_version.value_or(kDefaultSbiApiVersion);

  static inline const std::string UdrConfigurationServiceBase =
      sbi_helper::UdrConfBase +
      udr_cfg.nudr.api_version.value_or(kDefaultSbiApiVersion);
};

}  // namespace oai::udr::api

#endif
