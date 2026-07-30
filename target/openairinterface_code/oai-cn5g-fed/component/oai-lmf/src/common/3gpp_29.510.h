/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* TODO: check if actually needed in lmf */
#ifndef FILE_3GPP_29_510_nssf_SEEN
#define FILE_3GPP_29_510_nssf_SEEN

#include <vector>
#include <nlohmann/json.hpp>

// Section 28.4, TS23.003
typedef struct s_nssai {
  uint8_t sST;
  std::string sD;
  s_nssai(const uint8_t& sst, const std::string sd) : sST(sst), sD(sd) {}
  s_nssai() : sST(), sD() {}
  s_nssai(const s_nssai& p) : sST(p.sST), sD(p.sD) {}
  bool operator==(const struct s_nssai& s) const {
    if ((s.sST == this->sST) && (s.sD.compare(this->sD) == 0)) {
      return true;
    } else {
      return false;
    }
  }
  s_nssai& operator=(const s_nssai& s) {
    sST = s.sST;
    sD  = s.sD;
    return *this;
  }

} snssai_t;

typedef struct dnai_s {
} dnai_t;

typedef struct patch_item_s {
  std::string op;
  std::string path;
  // std::string from;
  std::string value;

  nlohmann::json to_json() const {
    nlohmann::json json_data = {};
    json_data["op"]          = op;
    json_data["path"]        = path;
    json_data["value"]       = value;
    return json_data;
  }
} patch_item_t;

#define LMF_CURL_TIMEOUT_MS 100L
#define NNRF_NFM_BASE "/nnrf-nfm/"
#define LMF_NF_REGISTER_URL "/nf-instances/"

#endif
