# SPDX-License-Identifier: LicenseRef-CSSL-1.0

include_directories(${SRC_TOP_DIR}/../build/ext/cpp-jwt)
include_directories(${SRC_TOP_DIR}/api-server/api)
include_directories(${SRC_TOP_DIR}/api-server/impl)
include_directories(${SRC_TOP_DIR}/api-server/)
include_directories(${SRC_TOP_DIR}/common/)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)

include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config/config.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf/nrf_model.cmake)

add_library (NRF STATIC
  nrf_app.cpp
  nrf_config_types.cpp
  nrf_profile.cpp
  nrf_subscription.cpp 
  nrf_client.cpp 
  nrf_search_result.cpp 
  nrf_jwt.cpp 
  task_manager.cpp
  nrf_event.cpp
)


