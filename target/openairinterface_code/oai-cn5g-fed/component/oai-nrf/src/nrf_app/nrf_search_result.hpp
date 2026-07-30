/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NRF_SEARCH_RESULT_HPP_SEEN
#define FILE_NRF_SEARCH_RESULT_HPP_SEEN

#include "3gpp_29.510.h"
#include "logger.hpp"
#include "nrf_profile.hpp"

namespace oai {
namespace nrf {
namespace app {
using namespace std;

class nrf_search_result {
 public:
  nrf_search_result() {
    limit_nf_instances   = 10;  // default value, TODO: to be removed
    validity_period      = 0;
    num_nf_inst_complete = 0;
  };
  nrf_search_result(nrf_search_result const&) = delete;

  virtual ~nrf_search_result() {
    Logger::nrf_app().debug("Delete NRF Subscription instance...");
  }

  void operator=(nrf_search_result const&) = delete;

  /*
   * Set the search id
   * @param [const std::string &]: id: Search id
   * @return void
   */
  void set_search_id(const std::string& id);

  /*
   * Get the search id
   * @param [std::string &]: id: search id
   * @return void
   */
  void get_search_id(std::string& id) const;

  /*
   * Get the search id
   * @param [void]
   * @return search id
   */
  std::string get_search_id() const;

  /*
   * Set the nf instances
   * @param [std::vector<std::shared_ptr<nrf_profile>> &]: instances: Array of
   * nrf profile instances
   * @return void
   */
  void set_nf_instances(
      const std::vector<std::shared_ptr<nrf_profile>>& instances);

  /*
   * Add an nf instance to the list of nrf profile instances
   * @param [const std::shared_ptr<nrf_profile> &]: instance: A nrf profile
   * instance
   * @return void
   */
  void add_nf_instance(const std::shared_ptr<nrf_profile>& instance);

  /*
   * Get the nf instances
   * @param [std::vector<std::shared_ptr<nrf_profile>> &]: instances: Store
   * array of nrf profile instances
   * @return void
   */
  void get_nf_instances(
      std::vector<std::shared_ptr<nrf_profile>>& instances) const;

  /*
   * Get the nf instances
   * @param [void]
   * @return std::vector<std::shared_ptr<nrf_profile>>: array of nrf profile
   * instances
   */
  std::vector<std::shared_ptr<nrf_profile>> get_nf_instances() const;

  /*
   * Set the validity period
   * @param [const uint64_t &] p: validity period
   * @return
   */
  void set_validity_period(const uint64_t& v);

  /*
   * Get the validity period
   * @param [uint64_t &]p:  validity period
   * @return
   */
  void get_validity_period(uint64_t& p) const;

  /*
   * Get the validity period
   * @param [void]
   * @return [uint64_t &] validity period
   */
  uint64_t get_validity_period() const;

  /*
   * Set the the total number of NF Instances found by NRF
   * @param [const uint32_t &] n: the total number of NF Instances found by NRF
   * @return void
   */
  void set_num_nf_inst_complete(const uint32_t& n);

  /*
   * Get the the total number of NF Instances found by NRF
   * @param [uint32_t &] n: the total number of NF Instances found by NRF
   * @return void
   */
  void get_num_nf_inst_complete(uint32_t& n) const;

  /*
   * Set the maximum number of NFProfiles to be returned in the response
   * @param [const uint32_t &] l: the maximum number of NFProfiles to be
   * returned in the response
   * @return void
   */
  void set_limit_nf_instances(const uint32_t& l);

  /*
   * Get the maximum number of NFProfiles to be returned in the response
   * @param [uint32_t &] l: the maximum number of NFProfiles to be returned in
   * the response
   * @return void
   */
  void get_limit_nf_instances(uint32_t& l) const;

  /*
   * Get the maximum number of NFProfiles to be returned in the response
   * @param [void]
   * @return the maximum number of NFProfiles to be returned in the response
   */
  uint32_t get_limit_nf_instances() const;

  /*
   * Display all the members of a subscription
   * @param [void]
   * @return void
   */
  void display();

  /*
   * Represent NF profile as json object
   * @param [nlohmann::json &] data: Json data
   * @param [uint32_t &] limit_nfs: maximum number of NF profiles stored in the
   * json data 0, means without any restriction
   * @return void
   */
  void to_json(nlohmann::json& data, const uint32_t& limit_nfs) const;

 private:
  std::vector<std::shared_ptr<nrf_profile>> nf_instances;
  std::string search_id;
  uint64_t validity_period;
  uint32_t num_nf_inst_complete;
  uint32_t limit_nf_instances;
  std::string nrf_supported_features;
};
}  // namespace app
}  // namespace nrf
}  // namespace oai

#endif /* FILE_NRF_SEARCH_RESULT_HPP_SEEN */
