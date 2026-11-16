find_package(Qt6 REQUIRED COMPONENTS Core Network)

qt_add_executable(bulwark_service
    app.rc
    src/main.cpp
    src/Logger.cpp
    src/BulwarkOptions.cpp
    src/SettingsStore.cpp
    src/RuleStore.cpp
    src/FirstSeenStore.cpp
    src/BaselineStore.cpp
    src/AuditLog.cpp
    src/AlertExporter.cpp

    src/EventHistoryStore.cpp
    src/QuarantineManager.cpp
    src/RegSurgery.cpp
    src/reputation/HttpTransport.cpp
    include/bulwark/service/reputation/HttpTransport.h

    src/reputation/ThreatFoxFeed.cpp

    src/monitoring/ProcessInspector.cpp
    src/monitoring/ProcessOriginResolver.cpp
    src/monitoring/ProcessEnumerator.cpp
    include/bulwark/service/SystemBoost.h
    src/SystemBoost.cpp
    src/ForensicsService.cpp
    src/ThreatRemediator.cpp
    src/PersistenceScanner.cpp

    include/bulwark/service/EventSource.h
    include/bulwark/service/EtwProcessEventSource.h
    include/bulwark/service/DriverEventSource.h
    include/bulwark/service/UserModeBehaviorSource.h
    include/bulwark/service/UserModeExecBlock.h
    include/bulwark/service/UserModeNetworkBlock.h
    include/bulwark/service/UserModeProcessContainment.h
    include/bulwark/service/SystemHardening.h
    include/bulwark/service/BootSectorGuard.h
    include/bulwark/service/FilelessGuard.h
    include/bulwark/service/FilelessPolicy.h
    include/bulwark/service/RemoteThreadDeduplicator.h
    include/bulwark/service/EventSourceRoutingPolicy.h
    include/bulwark/service/ResourceAbuseMonitor.h
    include/bulwark/service/EventSourceCoordinator.h
    include/bulwark/service/IpcServer.h
    include/bulwark/service/Worker.h
    include/bulwark/service/AmsiBridge.h
    src/AmsiBridge.cpp
    src/IpcServer.cpp
    src/IpcClientAuth.cpp
    src/InstallDirAclCheck.cpp
    src/EtwProcessEventSource.cpp
    src/DriverEventSource.cpp
    src/DriverControl.cpp
    src/UserModeBehaviorSource.cpp
    src/UserModeExecBlock.cpp
    src/UserModeNetworkBlock.cpp
    src/OccupiedFileAccess.cpp
    src/UserModeProcessContainment.cpp
    src/SystemHardening.cpp
    include/bulwark/service/HijackGuard.h
    include/bulwark/service/HijackPolicy.h
    include/bulwark/service/HardeningCatalog.h
    include/bulwark/service/RegistryUtil.h
    src/RegistryUtil.cpp
    src/HijackPolicy.cpp
    src/HijackGuard.cpp
    src/HardeningCatalog.cpp
    include/bulwark/service/NetTrafficMonitor.h
    src/NetTrafficMonitor.cpp
    src/SelfHardening.cpp
    src/BootSectorGuard.cpp
    src/FilelessGuard.cpp
    src/ResourceAbuseMonitor.cpp
    src/EventSourceCoordinator.cpp
    src/ServiceControlTracer.cpp
    src/DurableExecBlockPolicy.cpp
    include/bulwark/service/DurableExecBlockPolicy.h
    src/WorkerDurableExecBlockSeam.cpp
    include/bulwark/service/WorkerDurableExecBlockSeam.h
    src/RepairDriverSession.cpp
    include/bulwark/service/RepairDriverSession.h
    src/SnapshotRepairJournal.cpp
    include/bulwark/service/SnapshotRepairJournal.h
    include/bulwark/service/InstallerDetect.h
    src/InstallerDetect.cpp
    include/bulwark/service/FileContentProbe.h
    src/FileContentProbe.cpp
    src/Worker.cpp
)

target_include_directories(bulwark_service
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_SOURCE_DIR}/third_party/krabsetw/krabs
    # Protocol.h is the single declaration of the kernel<->service message layout; never re-declare the structs.
    PRIVATE ${CMAKE_SOURCE_DIR}/../Bulwark.Driver
    # AmsiProtocol.h:提供程序 DLL 与服务端共用的唯一线格式声明,两侧不得各写一份。
    PRIVATE ${CMAKE_SOURCE_DIR}/amsi)

target_link_libraries(bulwark_service PRIVATE bulwark_shared Qt6::Core Qt6::Network)

if(WIN32)
    target_link_libraries(bulwark_service PRIVATE advapi32 kernel32 wintrust crypt32 tdh fltlib ole32 uuid fwpuclnt ws2_32 rstrtmgr psapi iphlpapi)
endif()

target_compile_features(bulwark_service PRIVATE cxx_std_20)

# Isolated-VM self-test entry points only; release binaries must not contain them.
if(BULWARK_ENABLE_SELFTEST)
    target_compile_definitions(bulwark_service PRIVATE BULWARK_ENABLE_SELFTEST=1)
endif()

if(MSVC)
    target_compile_options(bulwark_service PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(bulwark_service PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(bulwark_service PRIVATE -Wall -Wextra)
endif()

add_custom_command(TARGET bulwark_service POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/appsettings.json"
        "$<TARGET_FILE_DIR:bulwark_service>/appsettings.json"
    COMMENT "Deploying appsettings.json next to bulwark_service.exe")
