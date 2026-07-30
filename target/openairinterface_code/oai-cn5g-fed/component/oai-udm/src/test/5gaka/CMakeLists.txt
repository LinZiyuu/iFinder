# SPDX-License-Identifier: LicenseRef-CSSL-1.0

cmake_minimum_required(VERSION 3.14)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/../../common ${CMAKE_CURRENT_BINARY_DIR}/common)
ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/../../common/utils ${CMAKE_CURRENT_BINARY_DIR}/utils)
ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/../../5gaka ${CMAKE_CURRENT_BINARY_DIR}/5gaka)



message(CONFIGURE_LOG
    "NF_TARGET: ${NF_TARGET}\n"
  )

include_directories(${SRC_TOP_DIR}/5gaka)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)

add_executable(unit_test 
  test_5gaka.cpp 
  test_sha256.cpp 
  test_ecies_format.cpp 
  test_ecies_profilea.cpp)

## Common modules
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common/common.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger/logger.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/utils.cmake)


IF(STATIC_LINKING)
    SET(CMAKE_EXE_LINKER_FLAGS "-static")
    SET_TARGET_PROPERTIES(unit_test PROPERTIES LINK_SEARCH_END_STATIC 1)
    # asan do not support static linking
    SET(ASAN)
ENDIF(STATIC_LINKING)   

target_link_libraries(unit_test ${CONFIG} 
 -Wl,--start-group 5GAKA 3GPP_COMMON_TYPES CN_UTILS -lnettle 
 ${NETTLE_LIBRARIES} ${CRYPTO_LIBRARIES} -lboost_system 
 -lboost_thread -lboost_date_time -lfmt -lspdlog -lssl -lcrypto -lcryptopp
  -lgmp -Wl,--end-group
   gtest pthread m rt boost_system curl)

add_test(udm_unit_test  unit_test)
