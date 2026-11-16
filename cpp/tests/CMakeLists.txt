find_package(Qt6 REQUIRED COMPONENTS Core Network)

add_executable(bulwark_snapshot SnapshotTool.cpp)
target_link_libraries(bulwark_snapshot PRIVATE bulwark_shared Qt6::Core)
target_compile_features(bulwark_snapshot PRIVATE cxx_std_20)

add_executable(bulwark_snapshot_probe SnapshotTool.cpp)
target_link_libraries(bulwark_snapshot_probe PRIVATE bulwark_shared Qt6::Core)
target_compile_features(bulwark_snapshot_probe PRIVATE cxx_std_20)
set_target_properties(bulwark_snapshot_probe PROPERTIES
    OUTPUT_NAME "bulwark_snapshot"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/deploy/$<CONFIG>")

if(MSVC)
    target_compile_options(bulwark_snapshot PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(bulwark_snapshot PRIVATE UNICODE _UNICODE)
    target_compile_options(bulwark_snapshot_probe PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(bulwark_snapshot_probe PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(bulwark_snapshot PRIVATE -Wall -Wextra)
    target_compile_options(bulwark_snapshot_probe PRIVATE -Wall -Wextra)
endif()

set(BLW_CORPUS "${CMAKE_CURRENT_SOURCE_DIR}/data/corpus.json")
set(BLW_GOLDEN "${CMAKE_CURRENT_SOURCE_DIR}/data/golden.json")

add_test(NAME verdict_snapshot
         COMMAND bulwark_snapshot --verify "${BLW_CORPUS}" "${BLW_GOLDEN}")

add_test(NAME builtin_ruleset_ids
         COMMAND bulwark_snapshot --check-ruleset)

add_test(NAME service_regression
         COMMAND bulwark_service --regression-selftest)

add_test(NAME ipc_routing_selftest
         COMMAND bulwark_service --ipc-selftest)

add_test(NAME service_has_no_ai_verdict_client
         COMMAND ${CMAKE_COMMAND} "-DEXE=$<TARGET_FILE:bulwark_service>"
                 -P "${CMAKE_CURRENT_SOURCE_DIR}/check_no_ai_verdict_client.cmake")
set_tests_properties(service_has_no_ai_verdict_client PROPERTIES LABELS "service;regression")

add_test(NAME service_has_no_yara_feature
         COMMAND ${CMAKE_COMMAND} "-DEXE=$<TARGET_FILE:bulwark_service>"
                 -P "${CMAKE_CURRENT_SOURCE_DIR}/check_no_yara_feature.cmake")
add_test(NAME ui_has_no_yara_feature
         COMMAND ${CMAKE_COMMAND} "-DEXE=$<TARGET_FILE:bulwark_ui>"
                 -P "${CMAKE_CURRENT_SOURCE_DIR}/check_no_yara_feature.cmake")
set_tests_properties(service_has_no_yara_feature PROPERTIES LABELS "service;regression")
set_tests_properties(ui_has_no_yara_feature PROPERTIES LABELS "ui;regression")

get_target_property(_blw_qtcore_loc Qt6::Core LOCATION)
get_filename_component(_blw_qt_bin "${_blw_qtcore_loc}" DIRECTORY)

set_tests_properties(verdict_snapshot builtin_ruleset_ids PROPERTIES
    ENVIRONMENT "QT_HASH_SEED=0"
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "engine;snapshot")

set_tests_properties(service_regression PROPERTIES
    ENVIRONMENT "QT_HASH_SEED=0"
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "service;regression")

set_tests_properties(ipc_routing_selftest PROPERTIES
    ENVIRONMENT "QT_HASH_SEED=0"
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    TIMEOUT 60
    LABELS "service;ipc")

add_executable(defense_policy_unit
    DefensePolicyTest.cpp
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/src/DurableExecBlockPolicy.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/src/WorkerDurableExecBlockSeam.cpp")
target_include_directories(defense_policy_unit PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../ui/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include")
target_link_libraries(defense_policy_unit PRIVATE bulwark_shared Qt6::Core)
target_compile_features(defense_policy_unit PRIVATE cxx_std_20)
set_target_properties(defense_policy_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(defense_policy_unit PRIVATE /W4 /WX /permissive- /utf-8)
else()
    target_compile_options(defense_policy_unit PRIVATE -Wall -Wextra -Werror)
endif()
add_test(NAME defense_policy_unit COMMAND defense_policy_unit)
set_tests_properties(defense_policy_unit PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "ui;service;policy")

add_executable(ransomware_response_policy_unit RansomwareResponsePolicyTest.cpp)
target_link_libraries(ransomware_response_policy_unit PRIVATE bulwark_shared Qt6::Core)
target_compile_features(ransomware_response_policy_unit PRIVATE cxx_std_20)
set_target_properties(ransomware_response_policy_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(ransomware_response_policy_unit PRIVATE /W4 /WX /permissive- /utf-8)
    target_compile_definitions(ransomware_response_policy_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(ransomware_response_policy_unit PRIVATE -Wall -Wextra -Werror)
endif()
add_test(NAME ransomware_response_policy_unit COMMAND ransomware_response_policy_unit)
set_tests_properties(ransomware_response_policy_unit PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "engine;ransomware;policy")

# 服务读文件开头的探针(勒索判断用):真实文件、被独占、删除中、不存在、网络路径。
add_executable(file_content_probe_unit
    FileContentProbeTest.cpp
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/src/FileContentProbe.cpp")
target_include_directories(file_content_probe_unit PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include")
target_link_libraries(file_content_probe_unit PRIVATE bulwark_shared Qt6::Core)
target_compile_features(file_content_probe_unit PRIVATE cxx_std_20)
set_target_properties(file_content_probe_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(file_content_probe_unit PRIVATE /W4 /WX /permissive- /utf-8)
    target_compile_definitions(file_content_probe_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(file_content_probe_unit PRIVATE -Wall -Wextra -Werror)
endif()
add_test(NAME file_content_probe_unit COMMAND file_content_probe_unit)
set_tests_properties(file_content_probe_unit PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "service;ransomware;policy")

# 内存承载方发现 vs 已归因注入(规则层):按发起方归因的规则不得命中承载方,
# 专为承载方写的规则必须仍然命中。
add_executable(memory_carrier_attribution_unit MemoryCarrierAttributionTest.cpp)
target_link_libraries(memory_carrier_attribution_unit PRIVATE bulwark_shared Qt6::Core)
target_compile_features(memory_carrier_attribution_unit PRIVATE cxx_std_20)
set_target_properties(memory_carrier_attribution_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(memory_carrier_attribution_unit PRIVATE /W4 /WX /permissive- /utf-8)
    target_compile_definitions(memory_carrier_attribution_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(memory_carrier_attribution_unit PRIVATE -Wall -Wextra -Werror)
endif()
add_test(NAME memory_carrier_attribution_unit COMMAND memory_carrier_attribution_unit)
set_tests_properties(memory_carrier_attribution_unit PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "engine;injection;policy")

# 命令行还原:误报哨兵(正常命令行必须逐字不变)、放行规则不得被还原文本放宽、
# 混淆写法与干净写法必须拿到同一个裁决。
add_executable(command_deobfuscation_unit CommandDeobfuscationTest.cpp)
target_link_libraries(command_deobfuscation_unit PRIVATE bulwark_shared Qt6::Core)
target_compile_features(command_deobfuscation_unit PRIVATE cxx_std_20)
set_target_properties(command_deobfuscation_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(command_deobfuscation_unit PRIVATE /W4 /WX /permissive- /utf-8)
    target_compile_definitions(command_deobfuscation_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(command_deobfuscation_unit PRIVATE -Wall -Wextra -Werror)
endif()
add_test(NAME command_deobfuscation_unit COMMAND command_deobfuscation_unit)
set_tests_properties(command_deobfuscation_unit PROPERTIES
    ENVIRONMENT "QT_HASH_SEED=0"
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "engine;obfuscation;policy")

# 检测判据的边界:编码命令 / 隐藏窗口 / 直连 IP 的精确判定、AMSI 拦截判据(正规一行安装不拦)、
# DGA 评分,以及勒索 / 下载器 / 信标监视器的阈值与豁免。
add_executable(detection_policy_unit DetectionPolicyTest.cpp)
target_link_libraries(detection_policy_unit PRIVATE bulwark_shared Qt6::Core)
target_compile_features(detection_policy_unit PRIVATE cxx_std_20)
set_target_properties(detection_policy_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(detection_policy_unit PRIVATE /W4 /WX /permissive- /utf-8)
    target_compile_definitions(detection_policy_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(detection_policy_unit PRIVATE -Wall -Wextra -Werror)
endif()
add_test(NAME detection_policy_unit COMMAND detection_policy_unit)
set_tests_properties(detection_policy_unit PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "engine;amsi;policy")

# 离线告警解释:契约(文案永不为空)、不重复 riskReasons、各手法必须互相区分、
# 身份问题优先级高于手法。
add_executable(threat_explainer_unit ThreatExplainerTest.cpp)
target_link_libraries(threat_explainer_unit PRIVATE bulwark_shared Qt6::Core)
target_compile_features(threat_explainer_unit PRIVATE cxx_std_20)
set_target_properties(threat_explainer_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(threat_explainer_unit PRIVATE /W4 /WX /permissive- /utf-8)
    target_compile_definitions(threat_explainer_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(threat_explainer_unit PRIVATE -Wall -Wextra -Werror)
endif()
add_test(NAME threat_explainer_unit COMMAND threat_explainer_unit)
set_tests_properties(threat_explainer_unit PROPERTIES
    ENVIRONMENT "QT_HASH_SEED=0"
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "engine;explain;ui")

add_executable(service_pure_policy_unit ServicePurePolicyTest.cpp)
target_include_directories(service_pure_policy_unit PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/include")
target_link_libraries(service_pure_policy_unit PRIVATE bulwark_shared Qt6::Core)
target_compile_features(service_pure_policy_unit PRIVATE cxx_std_20)
set_target_properties(service_pure_policy_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(service_pure_policy_unit PRIVATE /W4 /WX /permissive- /utf-8)
    target_compile_definitions(service_pure_policy_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(service_pure_policy_unit PRIVATE -Wall -Wextra -Werror)
endif()
add_test(NAME service_pure_policy_unit COMMAND service_pure_policy_unit)
set_tests_properties(service_pure_policy_unit PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "service;amsi;fileless;policy")

# 「系统目录 / Program Files 即可信」只认系统盘;经控制管道写入的放行规则受服务端闸门约束。
add_executable(trust_path_policy_unit TrustPathPolicyTest.cpp)
target_link_libraries(trust_path_policy_unit PRIVATE bulwark_shared Qt6::Core)
target_compile_features(trust_path_policy_unit PRIVATE cxx_std_20)
set_target_properties(trust_path_policy_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(trust_path_policy_unit PRIVATE /W4 /WX /permissive- /utf-8)
    target_compile_definitions(trust_path_policy_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(trust_path_policy_unit PRIVATE -Wall -Wextra -Werror)
endif()
add_test(NAME trust_path_policy_unit COMMAND trust_path_policy_unit)
set_tests_properties(trust_path_policy_unit PROPERTIES
    ENVIRONMENT "QT_HASH_SEED=0"
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "engine;trust;policy")

add_library(amsi_bridge_compile_unit OBJECT
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/src/AmsiBridge.cpp")
target_include_directories(amsi_bridge_compile_unit PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../amsi")
target_link_libraries(amsi_bridge_compile_unit PRIVATE bulwark_shared Qt6::Core)
target_compile_features(amsi_bridge_compile_unit PRIVATE cxx_std_20)
set_target_properties(amsi_bridge_compile_unit PROPERTIES AUTOMOC ON AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(amsi_bridge_compile_unit PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(amsi_bridge_compile_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(amsi_bridge_compile_unit PRIVATE -Wall -Wextra)
endif()

add_library(fileless_guard_compile_unit OBJECT
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/src/FilelessGuard.cpp")
target_include_directories(fileless_guard_compile_unit PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include")
target_link_libraries(fileless_guard_compile_unit PRIVATE bulwark_shared Qt6::Core)
target_compile_features(fileless_guard_compile_unit PRIVATE cxx_std_20)
set_target_properties(fileless_guard_compile_unit PROPERTIES AUTOMOC ON AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(fileless_guard_compile_unit PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(fileless_guard_compile_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(fileless_guard_compile_unit PRIVATE -Wall -Wextra)
endif()

add_library(selftest_canary_compile_unit OBJECT
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/src/UserModeBehaviorSource.cpp")
target_include_directories(selftest_canary_compile_unit PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include")
target_link_libraries(selftest_canary_compile_unit PRIVATE bulwark_shared Qt6::Core)
target_compile_features(selftest_canary_compile_unit PRIVATE cxx_std_20)
target_compile_definitions(selftest_canary_compile_unit PRIVATE BULWARK_ENABLE_SELFTEST=1)
set_target_properties(selftest_canary_compile_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(selftest_canary_compile_unit PRIVATE /W4 /WX /permissive- /utf-8)
    target_compile_definitions(selftest_canary_compile_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(selftest_canary_compile_unit PRIVATE -Wall -Wextra -Werror)
endif()

add_library(worker_audit_compile_unit OBJECT
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/src/Worker.cpp")
target_include_directories(worker_audit_compile_unit PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include"
    "${CMAKE_SOURCE_DIR}/third_party/krabsetw/krabs"
    "${CMAKE_SOURCE_DIR}/../Bulwark.Driver")
target_link_libraries(worker_audit_compile_unit PRIVATE bulwark_shared Qt6::Core Qt6::Network)
target_compile_features(worker_audit_compile_unit PRIVATE cxx_std_20)
set_target_properties(worker_audit_compile_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(worker_audit_compile_unit PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(worker_audit_compile_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(worker_audit_compile_unit PRIVATE -Wall -Wextra)
endif()

add_library(etw_attribution_compile_unit OBJECT
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/src/EtwProcessEventSource.cpp")
target_include_directories(etw_attribution_compile_unit PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include"
    "${CMAKE_SOURCE_DIR}/third_party/krabsetw/krabs"
    "${CMAKE_SOURCE_DIR}/../Bulwark.Driver")
target_link_libraries(etw_attribution_compile_unit PRIVATE bulwark_shared Qt6::Core)
target_compile_features(etw_attribution_compile_unit PRIVATE cxx_std_20)
set_target_properties(etw_attribution_compile_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(etw_attribution_compile_unit PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(etw_attribution_compile_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(etw_attribution_compile_unit PRIVATE -Wall -Wextra)
endif()

add_executable(snapshot_repair_unit
    SnapshotRepairTest.cpp
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/src/RepairDriverSession.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/src/SnapshotRepairJournal.cpp")
target_include_directories(snapshot_repair_unit PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../service/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../shared/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../Bulwark.Driver")
target_link_libraries(snapshot_repair_unit PRIVATE Qt6::Core advapi32 fltlib)
target_compile_features(snapshot_repair_unit PRIVATE cxx_std_20)
set_target_properties(snapshot_repair_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(snapshot_repair_unit PRIVATE /W4 /WX /permissive- /utf-8)
    target_compile_definitions(snapshot_repair_unit PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(snapshot_repair_unit PRIVATE -Wall -Wextra -Werror)
endif()
add_test(NAME snapshot_repair_unit COMMAND snapshot_repair_unit)
set_tests_properties(snapshot_repair_unit PROPERTIES
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "service;repair;policy")

find_program(BLW_POWERSHELL_EXECUTABLE powershell.exe REQUIRED)
set(BLW_PWSH_POLICY_ARGS -NoProfile -ExecutionPolicy RemoteSigned)
set(BLW_RECONCILIATION_CONTROLLER
    "${CMAKE_SOURCE_DIR}/../scripts/Invoke-SnapshotReconciliationTransaction.ps1")
set(BLW_ROLLBACK_REPORT_DIR "${CMAKE_CURRENT_BINARY_DIR}/rollback-failure-injection")
add_test(NAME snapshot_transaction_rollback_aggregate
    COMMAND "${BLW_POWERSHELL_EXECUTABLE}" ${BLW_PWSH_POLICY_ARGS}
            -File "${BLW_RECONCILIATION_CONTROLLER}"
            -OfflineRollbackAggregate
            -OfflineRollbackReportPath "${BLW_ROLLBACK_REPORT_DIR}/aggregate.json")
set_tests_properties(snapshot_transaction_rollback_aggregate PROPERTIES
    LABELS "service;repair;rollback;offline")

function(add_snapshot_transaction_rollback_case case_name injection)
    add_test(NAME "snapshot_transaction_rollback_${case_name}"
        COMMAND "${BLW_POWERSHELL_EXECUTABLE}" ${BLW_PWSH_POLICY_ARGS}
                -File "${BLW_RECONCILIATION_CONTROLLER}"
                -OfflineRollbackFailureInjection "${injection}"
                -OfflineRollbackReportPath "${BLW_ROLLBACK_REPORT_DIR}/${case_name}.json")
    set_tests_properties("snapshot_transaction_rollback_${case_name}" PROPERTIES
        LABELS "service;repair;rollback;offline")
endfunction()

add_snapshot_transaction_rollback_case(file_execblock file-execblock)
add_snapshot_transaction_rollback_case(user_manifest user-manifest)
add_snapshot_transaction_rollback_case(service_binary service-binary)
add_snapshot_transaction_rollback_case(service_registration service-registration)
add_snapshot_transaction_rollback_case(snapshot_preimage snapshot-preimage)
add_snapshot_transaction_rollback_case(driver driver)
add_snapshot_transaction_rollback_case(minifilter minifilter)
add_snapshot_transaction_rollback_case(ui ui)
add_snapshot_transaction_rollback_case(appsettings appsettings)
add_snapshot_transaction_rollback_case(selfguard selfguard)
add_snapshot_transaction_rollback_case(missing_evidence missing-evidence)
add_snapshot_transaction_rollback_case(duplicate_evidence duplicate-evidence)

function(add_snapshot_transaction_interruption_case case_name injection)
    add_test(NAME "snapshot_transaction_interruption_${case_name}"
        COMMAND "${BLW_POWERSHELL_EXECUTABLE}" ${BLW_PWSH_POLICY_ARGS}
                -File "${BLW_RECONCILIATION_CONTROLLER}"
                -OfflineInterruptionFailureInjection "${injection}"
                -OfflineRollbackReportPath "${BLW_ROLLBACK_REPORT_DIR}/interruption-${case_name}.json")
    set_tests_properties("snapshot_transaction_interruption_${case_name}" PROPERTIES
        LABELS "service;repair;rollback;offline")
endfunction()

add_snapshot_transaction_interruption_case(stage_created stage-created)
add_snapshot_transaction_interruption_case(service_stop_intent service-stop-intent)
add_snapshot_transaction_interruption_case(service_stopped service-stopped)
add_snapshot_transaction_interruption_case(snapshot_installed snapshot-installed)
add_snapshot_transaction_interruption_case(service_restarted service-restarted)

function(add_snapshot_transaction_driver_path_case case_name injection)
    add_test(NAME "snapshot_transaction_driver_path_${case_name}"
        COMMAND "${BLW_POWERSHELL_EXECUTABLE}" ${BLW_PWSH_POLICY_ARGS}
                -File "${BLW_RECONCILIATION_CONTROLLER}"
                -OfflineDriverPathFailureInjection "${injection}"
                -OfflineRollbackReportPath "${BLW_ROLLBACK_REPORT_DIR}/driver-path-${case_name}.json")
    set_tests_properties("snapshot_transaction_driver_path_${case_name}" PROPERTIES
        LABELS "service;driver;repair;offline")
endfunction()

add_snapshot_transaction_driver_path_case(x86_on_x64_sysnative x86-on-x64-sysnative)
add_snapshot_transaction_driver_path_case(x64_on_x64_system32 x64-on-x64-system32)
add_snapshot_transaction_driver_path_case(x86_on_x86_system32 x86-on-x86-system32)
add_snapshot_transaction_driver_path_case(missing_file missing-file)
add_snapshot_transaction_driver_path_case(redirected_path redirected-path)
add_snapshot_transaction_driver_path_case(wrong_service_image wrong-service-image)
add_snapshot_transaction_driver_path_case(hash_mismatch hash-mismatch)
add_snapshot_transaction_driver_path_case(signature_mismatch signature-mismatch)
add_snapshot_transaction_driver_path_case(thumbprint_mismatch thumbprint-mismatch)
add_snapshot_transaction_driver_path_case(signtool_failure signtool-failure)
add_snapshot_transaction_driver_path_case(service_stopped service-stopped)

function(add_snapshot_transaction_preflight_case case_name injection)
    add_test(NAME "snapshot_transaction_preflight_${case_name}"
        COMMAND "${BLW_POWERSHELL_EXECUTABLE}" ${BLW_PWSH_POLICY_ARGS}
                -File "${BLW_RECONCILIATION_CONTROLLER}"
                -OfflinePreflightFailureInjection "${injection}"
                -OfflineRollbackReportPath "${BLW_ROLLBACK_REPORT_DIR}/preflight-${case_name}.json")
    set_tests_properties("snapshot_transaction_preflight_${case_name}" PROPERTIES
        LABELS "service;preflight;repair;offline")
endfunction()

add_snapshot_transaction_preflight_case(all_pass all-pass)
add_snapshot_transaction_preflight_case(external_timeout external-timeout)
add_snapshot_transaction_preflight_case(incomplete incomplete-preflight)
add_snapshot_transaction_preflight_case(canceled canceled-preflight)

add_executable(remote_thread_telemetry_probe RemoteThreadTelemetryProbe.cpp)
target_compile_features(remote_thread_telemetry_probe PRIVATE cxx_std_20)
set_target_properties(remote_thread_telemetry_probe PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(remote_thread_telemetry_probe PRIVATE /W4 /WX /permissive- /utf-8)
else()
    target_compile_options(remote_thread_telemetry_probe PRIVATE -Wall -Wextra -Werror)
endif()

# 驱动冒烟:需要管理员权限与真实加载的驱动,不进 CTest,由 scripts/driver-smoke.ps1 编排。
add_executable(driver_smoke_probe driver_smoke/DriverSmokeProbe.cpp)
target_compile_features(driver_smoke_probe PRIVATE cxx_std_20)
target_compile_definitions(driver_smoke_probe PRIVATE UNICODE _UNICODE)
target_link_libraries(driver_smoke_probe PRIVATE advapi32)
set_target_properties(driver_smoke_probe PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
if(MSVC)
    target_compile_options(driver_smoke_probe PRIVATE /W4 /WX /permissive- /utf-8)
endif()

# 「结束进程」事件源(ETW Kernel-Audit-API-Calls)的实机核对,同样不进 CTest。
add_executable(etw_audit_probe driver_smoke/EtwAuditProbe.cpp)
target_compile_features(etw_audit_probe PRIVATE cxx_std_20)
target_compile_definitions(etw_audit_probe PRIVATE UNICODE _UNICODE)
target_include_directories(etw_audit_probe PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/krabsetw/krabs")
target_link_libraries(etw_audit_probe PRIVATE tdh advapi32 ole32)
set_target_properties(etw_audit_probe PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

set(BLW_DRIVER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../Bulwark.Driver")

add_executable(driver_match_unit
    DriverMatchTest.c
    "${BLW_DRIVER_DIR}/MatchCore.c")
set_source_files_properties(
    DriverMatchTest.c "${BLW_DRIVER_DIR}/MatchCore.c"
    PROPERTIES LANGUAGE CXX)
target_include_directories(driver_match_unit PRIVATE "${BLW_DRIVER_DIR}")
target_compile_definitions(driver_match_unit PRIVATE BLW_MATCHCORE_HOST)
set_target_properties(driver_match_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

if(MSVC)
    target_compile_options(driver_match_unit PRIVATE /W4 /WX /utf-8)
else()
    target_compile_options(driver_match_unit PRIVATE -Wall -Wextra -Werror)
endif()

add_test(NAME driver_match_unit COMMAND driver_match_unit)
set_tests_properties(driver_match_unit PROPERTIES LABELS "driver;match")
