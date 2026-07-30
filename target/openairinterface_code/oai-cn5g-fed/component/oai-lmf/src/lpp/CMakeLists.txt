set(LPP_DIR "${SRC_TOP_DIR}/lpp")
include_directories(${LPP_DIR})
file(GLOB LPP_src_files
    ${LPP_DIR}/*.c
    ${LPP_DIR}/*.cpp
)   

add_library(LPP STATIC ${LPP_src_files})
add_definitions(-DASN_DISABLE_OER_SUPPORT)
#add_definitions("-DASN_EMIT_DEBUG=1")
#add_definitions("-DASN_THREAD_SAFE")
