cmake_minimum_required(VERSION 3.21)

project(Bulwark LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(BULWARK_ENABLE_SPECTRE
       "Add /Qspectre (requires the VS 'Spectre-mitigated libs' component)" OFF)

# Test-only; must never be enabled for a release package. It only permits a fixed,
# validated canary root under %TEMP% for isolated VM regression.
option(BULWARK_ENABLE_SELFTEST
       "Compile test-only isolated canary support into bulwark_service" OFF)

if(MSVC)
    add_compile_options(/W4 /permissive- /guard:cf /utf-8)
    add_link_options(/guard:cf /CETCOMPAT /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA)
    if(BULWARK_ENABLE_SPECTRE)
        add_compile_options(/Qspectre)
    endif()
endif()

find_package(Qt6 REQUIRED COMPONENTS Core)

add_subdirectory(shared)
add_subdirectory(service)
add_subdirectory(ui)

add_subdirectory(amsi)

enable_testing()
add_subdirectory(tests)
