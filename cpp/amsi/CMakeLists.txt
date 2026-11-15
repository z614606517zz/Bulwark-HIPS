# 完整工程里由 cpp/CMakeLists.txt 引入。32 位版本单独配置(主工程依赖 64 位 Qt):
#   cmake -S cpp/amsi -B cpp/build_amsi_x86 -A Win32
#   cmake --build cpp/build_amsi_x86 --config Release
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    cmake_minimum_required(VERSION 3.21)
    project(BulwarkAmsi LANGUAGES CXX)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    if(MSVC)
        add_compile_options(/W4 /permissive- /guard:cf /utf-8)
        add_link_options(/guard:cf /DYNAMICBASE /NXCOMPAT)
    endif()
endif()

if(NOT WIN32)
    return()
endif()

add_library(BulwarkAmsi SHARED
    Provider.cpp
    PipeClient.cpp
    PipeClient.h
    AmsiProtocol.h
    BulwarkAmsi.def
)

# 32 位脚本宿主(SysWOW64 下的 PowerShell / wscript、32 位 Office 的宏)只加载 32 位提供程序。
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(_blw_amsi_name BulwarkAmsi32)
else()
    set(_blw_amsi_name BulwarkAmsi)
endif()

set_target_properties(BulwarkAmsi PROPERTIES
    OUTPUT_NAME "${_blw_amsi_name}"
    PREFIX ""
)

# 静态 CRT 由本属性控制(CMP0091),不要再往 flags 里手写 /MT。
set_property(TARGET BulwarkAmsi PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

target_include_directories(BulwarkAmsi PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(BulwarkAmsi PRIVATE kernel32 advapi32 ole32)

target_compile_definitions(BulwarkAmsi PRIVATE UNICODE _UNICODE)

if(MSVC)
    target_compile_options(BulwarkAmsi PRIVATE /EHsc /GS)
endif()

add_custom_command(TARGET BulwarkAmsi POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo
        "${_blw_amsi_name}.dll -> $<TARGET_FILE:BulwarkAmsi>"
    COMMENT "AMSI provider built (register with cpp/scripts/register-amsi-provider.ps1)")
