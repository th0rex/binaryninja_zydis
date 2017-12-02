cmake_minimum_required(VERSION 3.10)
project(binaryninja_zydis)

set(CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)

if(WIN32)
    set(BINARYNINJA_CORE_PATH "C:\\Program Files\\Vector35\\BinaryNinja\\binaryninjacore.lib")
endif()

add_subdirectory(third_party)

set(SOURCE_FILES include/binaryninja_zydis/il.hpp src/library.cpp)
add_library(binaryninja_zydis SHARED ${SOURCE_FILES})
target_link_libraries(binaryninja_zydis binaryninjaapi Zydis)
target_include_directories(binaryninja_zydis PRIVATE third_party/binaryninja-api)
target_include_directories(binaryninja_zydis PUBLIC include/)

if(WIN32)
    target_link_libraries(binaryninja_zydis ${BINARYNINJA_CORE_PATH})
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(binaryninja_zydis PRIVATE -Wno-c++17-extensions)
endif()