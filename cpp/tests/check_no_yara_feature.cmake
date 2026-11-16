# YARA 功能已经整体移除:程序里不能再有扫描器、规则更新器、规则库页面或辅助程序的痕迹。
# 服务启动时清理旧版留下的 yara 数据目录是有意保留的,不在下面的特征里。
if(NOT EXE OR NOT EXISTS "${EXE}")
    message(FATAL_ERROR "EXE not found: ${EXE}")
endif()
foreach(encoding UTF-8 UTF-16LE)
    file(STRINGS "${EXE}" hits ENCODING ${encoding}
         REGEX "bulwark_yarac|yara-forge/releases|YaraRules|YaraScanner|yara_x")
    if(hits)
        message(FATAL_ERROR "${EXE} still contains YARA feature strings (${encoding}): ${hits}")
    endif()
endforeach()
message(STATUS "OK: ${EXE} contains no YARA feature strings")
