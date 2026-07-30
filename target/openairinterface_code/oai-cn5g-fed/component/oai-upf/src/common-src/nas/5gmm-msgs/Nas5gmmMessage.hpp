/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NAS_5GMM_MESSAGE_H_
#define _NAS_5GMM_MESSAGE_H_

#include "3gpp_24.501.hpp"

namespace oai::nas {

class Nas5gmmMessage {
 public:
  Nas5gmmMessage(){};
  virtual ~Nas5gmmMessage() = default;

  // May not be the actual length of the message (by rounding 1/2 octet to 1
  // octet in some IEs) but always greater than the actual length of the message
  virtual uint32_t GetLength() const = 0;
  virtual bool Validate(uint32_t len) const;

  virtual int Encode(uint8_t* buf, int len) = 0;
  virtual int Decode(uint8_t* buf, int len) = 0;

  void SetMessageName(const std::string& name);
  std::string GetMessageName() const;
  void GetMessageName(std::string& name) const;

 private:
  std::string msg_name_;  // non 3GPP IE
};

}  // namespace oai::nas

#endif
