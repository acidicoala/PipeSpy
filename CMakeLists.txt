cmake_minimum_required(VERSION 4.0)
project(PipeSpy VERSION 1.0.0)

include(KoalaBox/cmake/KoalaBox.cmake)
add_subdirectory(KoalaBox)

configure_build_config()

set_32_and_64(OUTPUT_NAME PipeSpy32 PipeSpy64)
set(PROJECT_SOURCES
    src/dllmain.cpp
    src/pipe_spy/pipe_spy.cpp
    src/pipe_spy/pipe_spy.hpp
)

add_library(${PROJECT_NAME} SHARED ${PROJECT_SOURCES})

target_link_libraries(${PROJECT_NAME} PRIVATE KoalaBox)

set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_NAME ${OUTPUT_NAME})

configure_version_resource(
    TARGET ${PROJECT_NAME}
    FILE_DESC "Unnamed pipe traffic inspector"
    ORIG_NAME ${PROJECT_NAME}
)

target_include_directories(${PROJECT_NAME} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_BINARY_DIR}"
)

configure_linker_exports(
    TARGET ${PROJECT_NAME}
    HEADER_NAME "linker_exports_for_iphlpapi"
    FORWARDED_DLL "C:/Windows/System32/iphlpapi.dll"
    INPUT_SOURCES_DIR ""
    DLL_FILES_GLOB "C:/Windows/System32/iphlpapi.dll"
)
