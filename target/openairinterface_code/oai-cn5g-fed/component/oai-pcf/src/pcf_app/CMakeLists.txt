################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/msg)
include_directories(${SRC_TOP_DIR}/common/utils)
include_directories(${SRC_TOP_DIR}/itti)
include_directories(${SRC_TOP_DIR}/pcf)
include_directories(${SRC_TOP_DIR}/api-server/api)
include_directories(${SRC_TOP_DIR}/api-server/impl)
include_directories(${SRC_TOP_DIR}/api-server/)
include_directories(${SRC_TOP_DIR}/pcf_app/sm_policy/)
include_directories(${SRC_TOP_DIR}/pcf_app/policy_auth/)
include_directories(${SRC_TOP_DIR}/api-server/provisioning_api/api)
include_directories(${SRC_TOP_DIR}/api-server/provisioning_api/impl)
include_directories(${SRC_TOP_DIR}/api-server/provisioning_api/handler)
include_directories(${SRC_TOP_DIR}/api-server/provisioning_api/model)

## Common modules
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/http/http.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common/common.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/utils.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger/logger.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config/config.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/pcf/pcf_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model/common_model.cmake)
include(${SRC_TOP_DIR}/common/utils/utils.cmake)


include(${BUILD_TOP_DIR}/pcf/used_common_files.cmake)

add_library (PCF STATIC
  pcf_config_types.cpp
  pcf_config.cpp
  pcf_app.cpp
  pcf_nrf.cpp
  pcf_profile.cpp
  pcf_event.cpp
  pcf_sm_policy_control.cpp
  task_manager.cpp
  sm_policy/individual_sm_association.cpp
  sm_policy/policy_decision.cpp
  sm_policy/slice_policy_decision.cpp
  sm_policy/supi_policy_decision.cpp
  sm_policy/dnn_policy_decision.cpp
  sm_policy/policy_storage_yaml.cpp
  sm_policy/policy_storage_db.cpp
  sm_policy/policy_provisioning_file.cpp
  policy_auth/app_session.cpp
  pcf_policy_authorization.cpp
  sm_policy/database/mysql_db.cpp
  )
