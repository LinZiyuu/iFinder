/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "nrf_jwt.hpp"

#include <iostream>

#include "jwt/jwt.hpp"

using namespace oai::nrf::app;

//------------------------------------------------------------------------------
bool nrf_jwt::generate_signature(
    const std::string& nf_consumer_id, const std::string& scope,
    const std::string& nf_type, const std::string& target_nf_type,
    const std::string& nrf_instance_id, std::string& signature) const {
  std::string key;
  get_secret_key(scope, nf_type, target_nf_type, key);
  // Create JWT object
  // TODO
  jwt::jwt_object obj{
      jwt::params::algorithm("HS256"),
      jwt::params::payload(
          {{"iss", nrf_instance_id},
           {"sub", nf_consumer_id},
           {"aud", target_nf_type},
           {"scope", scope},
           {"exp", "1000"}}),  // in second
      jwt::params::secret(key)};

  // Get the encoded string/assertion
  signature = obj.signature();
  return true;
}

//------------------------------------------------------------------------------
bool nrf_jwt::generate_signature(
    const std::string& nf_consumer_id, const std::string& scope,
    const std::string& target_nf_instance_Id,
    const std::string& nrf_instance_id, std::string& signature) const {
  std::string key;
  get_secret_key(scope, target_nf_instance_Id, key);
  // Create JWT object
  // TODO
  jwt::jwt_object obj{
      jwt::params::algorithm("HS256"),
      jwt::params::payload(
          {{"iss", nrf_instance_id},
           {"sub", nf_consumer_id},
           {"aud", target_nf_instance_Id},
           {"scope", scope},
           {"exp", "1000"}}),  // in second
      jwt::params::secret(key)};

  // Get the encoded string/assertion
  signature = obj.signature();
  return true;
}

//------------------------------------------------------------------------------
bool nrf_jwt::get_secret_key(
    const std::string& scope, const std::string& nf_type,
    const std::string& target_nf_type, std::string& key) const {
  // TODO:
  key = "secret";
  return true;
}

//------------------------------------------------------------------------------
bool nrf_jwt::get_secret_key(
    const std::string& scope, const std::string& target_nf_instance_Id,
    std::string& key) const {
  // TODO:
  key = "secret";
  return true;
}

//------------------------------------------------------------------------------
void nrf_jwt::test_jwt() {
  using namespace jwt::params;

  auto key = "secret";  // Secret to use for the algorithm
  // Create JWT object
  jwt::jwt_object obj{
      algorithm("HS256"), payload({{"some", "payload"}}), secret(key)};

  // Get the encoded string/assertion
  auto enc_str = obj.signature();
  std::cout << enc_str << std::endl;

  // Decode
  auto dec_obj = jwt::decode(enc_str, algorithms({"HS256"}), secret(key));
  std::cout << dec_obj.header() << std::endl;
  std::cout << dec_obj.payload() << std::endl;
}
