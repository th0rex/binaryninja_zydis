cmake_minimum_required(VERSION 3.10)
project(binaryninja_zydis)

set(CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)

if(WIN32)
  set(BINARYNINJA_CORE_PATH "C:\\Program Files\\Vector35\\BinaryNinja\\binaryninjacore.lib")
else()
  # Must be specified on the command line
endif()

# Needed
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_subdirectory(third_party)

# Utils library
add_library(binaryninja_zydis_utils INTERFACE)
target_include_directories(binaryninja_zydis_utils INTERFACE include/utils)

# x86_sema
set(SOURCE_FILES src/x86_sema/main.cpp)
add_executable(x86_sema ${SOURCE_FILES})
target_link_libraries(x86_sema binaryninja_zydis_utils gsl)

# binaryninja_zydis Plugin
set(SOURCE_FILES src/library.cpp)
add_library(binaryninja_zydis SHARED ${SOURCE_FILES})
target_link_libraries(binaryninja_zydis binaryninjaapi Zydis)
target_include_directories(binaryninja_zydis PRIVATE third_party/binaryninja-api)

target_link_libraries(binaryninja_zydis ${BINARYNINJA_CORE_PATH})

