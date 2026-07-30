# SPDX-License-Identifier: LicenseRef-CSSL-1.0

set(UDM_API_SERVER_DIR "${SRC_TOP_DIR}/api_server")

include_directories(${UDM_API_SERVER_DIR}/api)
include_directories(${UDM_API_SERVER_DIR}/impl)
include_directories(${UDM_API_SERVER_DIR}/)
include_directories(${SRC_TOP_DIR}/udm_app)
include_directories(${SRC_TOP_DIR}/udm_app/event_handling)
include_directories(${SRC_TOP_DIR}/udm_app/sbi)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/http)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/bstr)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/udm/udm.cmake)

file(GLOB UDM_API_SERVER_src_files
    ${UDM_API_SERVER_DIR}/udm-api-server.cpp
    ${UDM_API_SERVER_DIR}/udm-http2-server.cpp
    ${UDM_API_SERVER_DIR}/api/*.cpp
    ${UDM_API_SERVER_DIR}/impl/*.cpp
)
 
add_library(UDM_API STATIC
           ${UDM_API_SERVER_src_files})
