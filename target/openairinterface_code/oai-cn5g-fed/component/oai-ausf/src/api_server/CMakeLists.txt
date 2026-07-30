# SPDX-License-Identifier: LicenseRef-CSSL-1.0

set(AUSF_API_SERVER_DIR "${SRC_TOP_DIR}/api_server")

include_directories(${AUSF_API_SERVER_DIR}/api)
include_directories(${AUSF_API_SERVER_DIR}/impl)
include_directories(${AUSF_API_SERVER_DIR}/model)
include_directories(${AUSF_API_SERVER_DIR}/)
include_directories(${SRC_TOP_DIR}/ausf_app)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/5gaka)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/http)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/bstr)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)

include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/ausf/ausf.cmake)

file(GLOB AUSF_API_SERVER_src_files
    ${AUSF_API_SERVER_DIR}/ausf-api-server.cpp
    ${AUSF_API_SERVER_DIR}/ausf_http2-server.cpp
    ${AUSF_API_SERVER_DIR}/api/*.cpp
    ${AUSF_API_SERVER_DIR}/impl/*.cpp
)
 
add_library(AUSF_API STATIC
           ${AUSF_API_SERVER_src_files})
