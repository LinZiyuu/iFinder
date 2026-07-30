# SPDX-License-Identifier: LicenseRef-CSSL-1.0

include_directories(${SRC_TOP_DIR}/api_server/api)
include_directories(${SRC_TOP_DIR}/api_server/impl)
include_directories(${SRC_TOP_DIR}/api_server/)
include_directories(${SRC_TOP_DIR}/common/)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/http)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)


include(${BUILD_TOP_DIR}/ausf/used_models.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/http/http.cmake)

add_library (AUSF STATIC
  ausf_app.cpp
  ausf_config.cpp
  ausf_config_yaml.cpp  
  task_manager.cpp
  ausf_event.cpp
  ausf_profile.cpp
  ausf_nrf.cpp 
)
