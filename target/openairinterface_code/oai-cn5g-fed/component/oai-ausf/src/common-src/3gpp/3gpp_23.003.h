/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_3GPP_23_003_SEEN
#define FILE_3GPP_23_003_SEEN

#include <stdint.h>

#include <nlohmann/json.hpp>
#include <string>
#include <Snssai.h>
#include <boost/algorithm/string.hpp>

#include "logger_base.hpp"
using namespace oai::logger;

const uint32_t SD_NO_VALUE               = 0xFFFFFF;
const uint8_t SST_MAX_STANDARDIZED_VALUE = 127;

const uint8_t SST_LENGTH = 1;
const uint8_t SD_LENGTH  = 3;

typedef struct s_nssai  // section 28.4, TS23.003
{
  uint8_t sst;
  std::string sd = oai::model::common::SD_DEFAULT_VALUE;
  // s_nssai(const uint8_t& m_sst, const uint32_t m_sd) : sst(m_sst), sd(m_sd)
  // {}
  s_nssai(const uint8_t& m_sst, const std::string& m_sd)
      : sst(m_sst), sd(m_sd) {}
  s_nssai() : sst(), sd() {}
  s_nssai(const s_nssai& p) : sst(p.sst), sd(p.sd) {}
  bool operator==(const struct s_nssai& s) const {
    if ((s.sst == this->sst) && (s.sd == this->sd)) {
      return true;
    } else {
      return false;
    }
  }

  s_nssai& operator=(const struct s_nssai& s) {
    sst = s.sst;
    sd  = s.sd;
    return *this;
  }

  std::string toString() const {
    std::string s = {};
    s.append("sst, sd: ").append(std::to_string(sst));
    s.append(", ").append(sd);
    return s;
  }

  nlohmann::json to_json() const {
    nlohmann::json json_data = {};
    json_data["sst"]         = sst;
    json_data["sd"]          = sd;
    return json_data;
  }
  // TODO remove, only temporary, in the future only use model SNSSAI
  oai::model::common::Snssai to_model_snssai() const {
    oai::model::common::Snssai snssai;
    snssai.setSst(sst);
    // TODO this puts a decimal string but SD should be a hex string
    snssai.setSd(sd);
    return snssai;
  }

  void from_json(nlohmann::json& json_data) {
    this->sst = json_data["sst"].get<int>();
    this->sd  = json_data["sd"].get<std::string>();
  }

  [[nodiscard]] uint32_t get_sd_int() const {
    try {
      return std::stoul(sd, nullptr, 16);
    } catch (const std::exception& e) {
      logger_common::common().error(
          "Error when converting from string to int for S-NSSAI SD, error: "
          "%s",
          e.what());
      return SD_NO_VALUE;
    }
  }

} snssai_t;

typedef struct plmn_s {
  std::string mcc;
  std::string mnc;
} plmn_t;

#define INVALID_TAC_0000 (uint16_t) 0x0000
#define INVALID_TAC_FFFE (uint16_t) 0xFFFE
#define INVALID_TAC (uint32_t) 0x00000000

typedef uint16_t tac_t;
typedef struct tai_s {
  plmn_t plmn; /*!< \brief  <MCC> + <MNC>        */
  tac_t tac;   /*!< \brief  Tracking Area Code   */
} tai_t;

typedef struct eci_s {
  uint32_t gnb_id : 20;
  uint32_t cell_id : 8;
  uint32_t empty : 4;
} ci_t;

typedef struct cgi_s {
  plmn_t plmn;
  ci_t cell_identity;  // 28 bits
} cgi_t;

typedef struct nr_cell_identity_s {
  uint32_t gnb_id;
  uint8_t cell_id : 4;
} nr_cell_identity_t;

typedef struct guami_s {
  plmn_t plmn;
  std::string amf_id;
} guami_t;

// TODO: remove redefinition of guami_t
typedef struct guami_5g_s {
  plmn_t plmn;
  uint32_t amf_id;
} guami_5g_t;

typedef struct guami_full_format_s {
  std::string mcc;
  std::string mnc;
  uint8_t region_id;
  uint16_t amf_set_id;
  uint8_t amf_pointer;

  nlohmann::json to_json() const {
    nlohmann::json json_data = {};
    json_data["mcc"]         = this->mcc;
    json_data["mnc"]         = this->mnc;
    json_data["region_id"]   = this->region_id;
    json_data["amf_set_id"]  = this->amf_set_id;
    json_data["amf_pointer"] = this->amf_pointer;
    return json_data;
  }

  void from_json(nlohmann::json& json_data) {
    try {
      if (json_data.find("mcc") != json_data.end()) {
        this->mcc = json_data["mcc"].get<std::string>();
      }
      if (json_data.find("mnc") != json_data.end()) {
        this->mnc = json_data["mnc"].get<std::string>();
      }
      if (json_data.find("region_id") != json_data.end()) {
        this->region_id = json_data["region_id"].get<int>();
      }
      if (json_data.find("amf_set_id") != json_data.end()) {
        this->amf_set_id = json_data["amf_set_id"].get<int>();
      }
      if (json_data.find("amf_pointer") != json_data.end()) {
        this->amf_pointer = json_data["amf_pointer"].get<int>();
      }
    } catch (std::exception& e) {
      logger_common::common().error("%s", e.what());
    }
  }
} guami_full_format_t;

#endif
