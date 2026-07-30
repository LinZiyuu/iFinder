/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_SNSSAI_HASHER_SEEN
#define FILE_SNSSAI_HASHER_SEEN

#include "Snssai.h"

/**
 * @brief Hash function to use Snssai objects as keys in (unordered) maps
 *
 */
namespace oai::pcf::app::sm_policy {
class snssai_hasher {
  const int HASH_SEED   = 17;
  const int HASH_FACTOR = 31;

 public:
  /**
   * @brief Calculates the hash for a snssai
   *
   * @param snssai calculate hash based on this value
   * @return size_t hash value
   */
  size_t operator()(const oai::model::common::Snssai& snssai) const {
    size_t res = HASH_SEED;
    res        = res * HASH_FACTOR + std::hash<std::string>()(snssai.getSd());
    res        = res * HASH_FACTOR + std::hash<int>()(snssai.getSst());
    return res;
  }
};
}  // namespace oai::pcf::app::sm_policy
#endif