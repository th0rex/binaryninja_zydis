add_subdirectory(binaryninja-api)
add_subdirectory(zydis)

add_library(gsl INTERFACE)
target_include_directories(gsl INTERFACE gsl-lite/include/)
