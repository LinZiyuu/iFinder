################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################

include_directories(${SRC_TOP_DIR}/api_server/api)
include_directories(${SRC_TOP_DIR}/api_server/impl)
include_directories(${SRC_TOP_DIR}/api_server/)
include_directories(${SRC_TOP_DIR}/common/)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/http)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model/common_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf/nrf_model.cmake)


add_library (UDR STATIC
  udr_app.cpp
  udr_config.cpp 
  udr_config_yaml.cpp 
  sbi/udr_profile.cpp
  sbi/udr_nrf.cpp 
  event_handling/udr_event.cpp
  event_handling/task_manager.cpp
  database/mysql_db.cpp
  database/cassandra_db.cpp
  database/mongo_db.cpp
)

target_link_libraries (UDR mongo::mongocxx_shared mongo::bsoncxx_shared)


