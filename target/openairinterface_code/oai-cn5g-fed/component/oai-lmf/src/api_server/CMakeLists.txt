# SPDX-License-Identifier: LicenseRef-CSSL-1.0

set(LMF_API_SERVER_DIR "${SRC_TOP_DIR}/api_server")

include_directories(${LMF_API_SERVER_DIR}/api)
include_directories(${LMF_API_SERVER_DIR}/impl)
include_directories(${LMF_API_SERVER_DIR}/)
include_directories(${SRC_TOP_DIR}/lmf_app)
include_directories(${SRC_TOP_DIR}/common)
#include_directories(${SRC_TOP_DIR}/lpp)
include_directories(${SRC_TOP_DIR}/nrppa)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/http)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/lmf)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/bstr)

include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/lmf/lmf.cmake)

file(GLOB LMF_API_SERVER_src_files
    ${LMF_API_SERVER_DIR}/lmf-api-server.cpp
    ${LMF_API_SERVER_DIR}/lmf-http2-server.cpp
    ${LMF_API_SERVER_DIR}/api/*.cpp
    ${LMF_API_SERVER_DIR}/impl/*.cpp
)
 
add_library(LMF_API STATIC
           ${LMF_API_SERVER_src_files})

#target_link_libraries(LMF_API LPP NRPPA)
