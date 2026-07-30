# SPDX-License-Identifier: LicenseRef-CSSL-1.0

set(NSSF_API_SERVER_DIR "${SRC_TOP_DIR}/api-server")

include_directories(${NSSF_API_SERVER_DIR}/api)
include_directories(${NSSF_API_SERVER_DIR}/impl)
include_directories(${NSSF_API_SERVER_DIR}/)
include_directories(${SRC_TOP_DIR}/nssf_app)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nssf)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/bstr)

include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nssf/nssf_model.cmake)

file(GLOB NSSF_API_SERVER_src_files
    ${NSSF_API_SERVER_DIR}/nssf-api-server.cpp
    ${NSSF_API_SERVER_DIR}/nssf-http2-server.cpp
    ${NSSF_API_SERVER_DIR}/api/*.cpp
    ${NSSF_API_SERVER_DIR}/impl/*.cpp
)

add_library(NSSF_API STATIC
           ${NSSF_API_SERVER_src_files})
