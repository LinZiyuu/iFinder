################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################

set(UDR_API_SERVER_DIR "${SRC_TOP_DIR}/api_server")

include_directories(${UDR_API_SERVER_DIR}/api)
include_directories(${UDR_API_SERVER_DIR}/impl)
include_directories(${UDR_API_SERVER_DIR}/)
include_directories(${SRC_TOP_DIR}/udr_app)
include_directories(${SRC_TOP_DIR}/udr_app/database)
include_directories(${SRC_TOP_DIR}/udr_app/event_handling)
include_directories(${SRC_TOP_DIR}/udr_app/sbi)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/http)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/udr)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/bstr)

include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/udr/udr.cmake)

file(GLOB UDR_API_SERVER_src_files
    ${UDR_API_SERVER_DIR}/udr-api-server.cpp
    ${UDR_API_SERVER_DIR}/udr-http2-server.cpp
    ${UDR_API_SERVER_DIR}/api/*.cpp
    ${UDR_API_SERVER_DIR}/impl/*.cpp
)
 
add_library(UDR_API STATIC
           ${UDR_API_SERVER_src_files})

target_link_libraries (UDR_API mongo::mongocxx_shared mongo::bsoncxx_shared)
