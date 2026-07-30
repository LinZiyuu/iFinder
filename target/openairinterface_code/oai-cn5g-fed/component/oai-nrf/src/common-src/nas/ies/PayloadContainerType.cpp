/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PayloadContainerType.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PayloadContainerType::PayloadContainerType() : Type1NasIeFormatTv() {}

//------------------------------------------------------------------------------
PayloadContainerType::PayloadContainerType(uint8_t value)
    : Type1NasIeFormatTv() {
  SetValue(value & 0x0f);
}

//------------------------------------------------------------------------------
PayloadContainerType::PayloadContainerType(uint8_t iei, uint8_t value)
    : Type1NasIeFormatTv(iei) {
  SetValue(value & 0x0f);
}

//------------------------------------------------------------------------------
PayloadContainerType::~PayloadContainerType(){};
