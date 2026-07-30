################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################

set(PCF_API_SERVER_DIR "${SRC_TOP_DIR}/api-server")

include_directories(${PCF_API_SERVER_DIR}/api)
include_directories(${PCF_API_SERVER_DIR}/impl)
include_directories(${PCF_API_SERVER_DIR}/handler)
include_directories(${PCF_API_SERVER_DIR}/provisioning_api/api)
include_directories(${PCF_API_SERVER_DIR}/provisioning_api/impl)
include_directories(${PCF_API_SERVER_DIR}/provisioning_api/handler)
include_directories(${PCF_API_SERVER_DIR}/provisioning_api/model)
include_directories(${PCF_API_SERVER_DIR}/)
include_directories(${SRC_TOP_DIR}/pcf_app)
include_directories(${SRC_TOP_DIR}/pcf_app/sm_policy/database)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model/common_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/pcf/pcf_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/smf/smf_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/utils.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common/common.cmake)

file(GLOB PCF_API_SERVER_src_files
    ${PCF_API_SERVER_DIR}/pcf-api-server.cpp
    ${PCF_API_SERVER_DIR}/pcf-http2-server.cpp
    ${PCF_API_SERVER_DIR}/api_defs.cpp
    ${PCF_API_SERVER_DIR}/api/*.cpp
    ${PCF_API_SERVER_DIR}/impl/*.cpp
    ${PCF_API_SERVER_DIR}/handler/*.cpp
    ${PCF_API_SERVER_DIR}/provisioning_api/model/*.cpp
    ${PCF_API_SERVER_DIR}/provisioning_api/model/*.cxx
    ${PCF_API_SERVER_DIR}/provisioning_api/handler/*.cpp
    ${PCF_API_SERVER_DIR}/provisioning_api/api/*.cpp
    ${PCF_API_SERVER_DIR}/provisioning_api/impl/*.cpp
)
 
add_library(PCF_API STATIC
           ${PCF_API_SERVER_src_files})
