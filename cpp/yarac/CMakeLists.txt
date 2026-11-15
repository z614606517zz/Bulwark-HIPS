# 规则包处理(解压 / 切块 / 包头统计)不依赖 YARA-X,单元测试总能构建。
set(BULWARK_PUFF_DIR "${CMAKE_SOURCE_DIR}/third_party/puff")
add_library(bulwark_yarapkg STATIC
    YaraForgePackage.h
    YaraForgePackage.cpp
    "${BULWARK_PUFF_DIR}/puff.c")
# puff.c 没有用到任何 C++ 关键字,按 C++ 编译,工程不必另开 C 语言。
set_source_files_properties("${BULWARK_PUFF_DIR}/puff.c" PROPERTIES LANGUAGE CXX)
if(MSVC)
    # 第三方原样代码:窄化转换、setjmp 与对齐填充告警不改源码,只在这一个文件上关掉。
    set_source_files_properties("${BULWARK_PUFF_DIR}/puff.c" PROPERTIES
        COMPILE_OPTIONS "/wd4244;/wd4324;/wd4611")
endif()
target_include_directories(bulwark_yarapkg
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${BULWARK_PUFF_DIR})
target_compile_features(bulwark_yarapkg PUBLIC cxx_std_20)
set_target_properties(bulwark_yarapkg PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

# YARA-X 的 C 接口包由 cpp/scripts/fetch-yara-x.ps1 下载到这里(不进版本库)。
# 链接其中的静态库 yara_x_capi.lib:辅助程序是单个 exe,安装目录里没有可被替换的 YARA-X DLL。
set(BULWARK_YARAX_DIR "${CMAKE_SOURCE_DIR}/third_party/yara-x" CACHE PATH
    "YARA-X C API package directory (yara_x.h, yara_x_capi.lib)")

if(EXISTS "${BULWARK_YARAX_DIR}/yara_x.h" AND EXISTS "${BULWARK_YARAX_DIR}/yara_x_capi.lib")
    add_executable(bulwark_yarac main.cpp)
    target_include_directories(bulwark_yarac PRIVATE "${BULWARK_YARAX_DIR}")
    # Rust 静态库不带 /DEFAULTLIB,它用到的系统导入库要在这里列全。
    target_link_libraries(bulwark_yarac PRIVATE
        bulwark_yarapkg "${BULWARK_YARAX_DIR}/yara_x_capi.lib"
        advapi32 bcrypt ntdll userenv ws2_32 synchronization ole32 oleaut32 shell32)
    set_target_properties(bulwark_yarac PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
    if(MSVC)
        target_compile_definitions(bulwark_yarac PRIVATE UNICODE _UNICODE)
    endif()
    # 服务按「自己所在目录\bulwark_yarac.exe」找辅助程序;构建树里也放一份,开发期可直接运行。
    if(TARGET bulwark_service)
        add_dependencies(bulwark_service bulwark_yarac)
        add_custom_command(TARGET bulwark_yarac POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:bulwark_service>"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:bulwark_yarac>"
                "$<TARGET_FILE_DIR:bulwark_service>"
            COMMENT "Deploying bulwark_yarac next to bulwark_service.exe")
    endif()
    set(BULWARK_HAVE_YARAX ON PARENT_SCOPE)
else()
    message(STATUS "YARA-X C API not found in ${BULWARK_YARAX_DIR}; bulwark_yarac is skipped "
                   "(run cpp/scripts/fetch-yara-x.ps1).")
    set(BULWARK_HAVE_YARAX OFF PARENT_SCOPE)
endif()
