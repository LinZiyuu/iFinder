/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NRF_SBI_HELPER_HPP
#define _NRF_SBI_HELPER_HPP

#include <nlohmann/json.hpp>

#include "nrf_config.hpp"
#include "sbi_helper.hpp"

using namespace oai::config::nrf;
using namespace oai::common::sbi;

extern std::unique_ptr<nrf_config> nrf_cfg;

namespace oai::nrf::api {

class nrf_sbi_helper : public sbi_helper {
 public:
};

}  // namespace oai::nrf::api

#endif
