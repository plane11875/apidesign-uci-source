cmake_minimum_required(VERSION 3.10)
project(UCI VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)

# 查找系统 OpenSSL
find_package(OpenSSL REQUIRED)

# 包含头文件
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# UCI 库源文件
set(UCI_SOURCES
    src/uci_wrapper.c
    src/uci_evp_autogen.c
    src/uci_hybrid.c
    src/uci_unified.c
    src/sdf/sdf_unified.c
    src/sdf/sdf_store.c
    src/sdf/sdf_key_mgmt_ecc.c
    src/sdf/sdf_legacy_asym_keymgmt.c
    src/sdf/sdf_sym_ops.c
    src/sdf/sdf_hash_ops.c
    src/sdf/sdf_evp_router.c
)

# 创建 UCI 共享库
add_library(uci SHARED ${UCI_SOURCES})

# 链接系统 OpenSSL
target_link_libraries(uci OpenSSL::Crypto)

# 安装规则
install(TARGETS uci DESTINATION lib)
install(DIRECTORY include/uci DESTINATION include)
