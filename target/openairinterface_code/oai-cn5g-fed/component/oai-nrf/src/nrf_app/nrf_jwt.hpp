/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NRF_JWT_HPP_SEEN
#define FILE_NRF_JWT_HPP_SEEN

#include <string>

namespace oai {
namespace nrf {
namespace app {

class nrf_jwt {
 private:
 public:
  void test_jwt();

  /*
   * Generate signature for the requested consumer
   * @param [const std::string &] nf_consumer_id: Consumer ID
   * @param [const std::string &] scope: names of the NF Services that the NF
   * Service Consumer is trying to access
   * @param [const std::string &] nf_type: NF type of the NF service consumer
   * @param [const std::string &] target_nf_type: NF type of the NF service
   * producer
   * @param [const std::string &] nrf_instance_id: NRF instance ID
   * @param [std::string &] signature: generated signature
   * @return void
   */
  bool generate_signature(
      const std::string& nf_consumer_id, const std::string& scope,
      const std::string& nf_type, const std::string& target_nf_type,
      const std::string& nrf_instance_id, std::string& signature) const;

  /*
   * Generate signature for the requested consumer
   * @param [const std::string &] nf_consumer_id: Consumer ID
   * @param [const std::string &] scope: names of the NF Services that the NF
   * Service Consumer is trying to access
   * @param [const std::string &] target_nf_instance_Id: Instance ID the NF
   * service producer
   * @param [const std::string &] nrf_instance_id: NRF instance ID
   * @param [std::string &] signature: generated signature
   * @return void
   */
  bool generate_signature(
      const std::string& nf_consumer_id, const std::string& scope,
      const std::string& target_nf_instance_Id,
      const std::string& nrf_instance_id, std::string& signature) const;

  /*
   * Get the secret key
   * @param [const std::string &] scope: names of the NF Services that the NF
   * Service Consumer is trying to access
   * @param [const std::string &] nf_type: NF type of the NF service consumer
   * @param [const std::string &] target_nf_type: NF type of the NF service
   * @param [std::string &] key: secret key
   * @return void
   */
  bool get_secret_key(
      const std::string& scope, const std::string& nf_type,
      const std::string& target_nf_type, std::string& key) const;

  /*
   * Get the secret key
   * @param [const std::string &] scope: names of the NF Services that the NF
   * Service Consumer is trying to access
   * @param [const std::string &] target_nf_instance_Id: Instance ID the NF
   * service producer
   * @param [std::string &] key: secret key
   * @return void
   */
  bool get_secret_key(
      const std::string& scope, const std::string& target_nf_instance_Id,
      std::string& key) const;
};

}  // namespace app
}  // namespace nrf
}  // namespace oai

#endif /* FILE_NRF_JWT_HPP_SEEN */
