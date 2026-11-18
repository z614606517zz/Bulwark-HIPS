add_library(bulwark_shared STATIC
    src/models/Evidence.cpp
    src/models/ChainEventInfo.cpp
    src/models/ThreatSnippet.cpp
    src/models/SecurityEvent.cpp
    src/models/Verdict.cpp
    src/models/DefenseRule.cpp
    src/models/RuntimeSettings.cpp
    src/models/PersistenceEntry.cpp
    src/models/AttackGraph.cpp
    src/models/ProcessEntry.cpp

    src/ipc/IpcMessage.cpp
    src/ipc/Payloads.cpp

    src/engine/SystemPaths.cpp
    src/engine/AttackCatalog.cpp
    src/engine/AttackAnnotator.cpp
    src/engine/CommandDeobfuscator.cpp
    src/engine/CommandLineAnalyzer.cpp
    src/engine/ScriptAnalyzer.cpp
    src/engine/DgaDomainAnalyzer.cpp
    src/engine/NetworkBehaviorMonitor.cpp
    src/engine/CrossEventMonitor.cpp
    src/engine/DownloaderBehaviorMonitor.cpp
    src/engine/FileContentClassifier.cpp
    src/engine/ZipIntegrity.cpp
    src/engine/RansomwareBehaviorMonitor.cpp
    src/engine/BaselineAnalyzer.cpp
    src/engine/CommandBurstMonitor.cpp
    src/engine/PersistenceAnalyzer.cpp
    src/engine/SelfProtection.cpp
    src/engine/ProcessChainTracker.cpp
    src/engine/AttackGraphBuilder.cpp
    src/engine/TrustPolicy.cpp
    src/engine/TrustedSoftwareCatalog.cpp
    src/engine/ThreatDetector.cpp
    src/engine/ThreatExplainer.cpp
    src/engine/DefaultRules.cpp
    src/engine/RuleEngine.cpp
    src/engine/EcsAlertFormatter.cpp

    src/engine/rules/RulesCommon.cpp
    src/engine/rules/Rules01_Execution.cpp
    src/engine/rules/Rules02_Persistence.cpp
    src/engine/rules/Rules03_PrivilegeEscalation.cpp
    src/engine/rules/Rules04_DefenseEvasion.cpp
    src/engine/rules/Rules05_CredentialAccess.cpp
    src/engine/rules/Rules06_LateralMovement.cpp
    src/engine/rules/Rules07_CommandAndControl.cpp
    src/engine/rules/Rules08_Impact.cpp
    src/engine/rules/Rules09_InjectionAndDrivers.cpp
    src/engine/rules/Rules10_SystemIntegrity.cpp
)

target_include_directories(bulwark_shared
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(bulwark_shared PUBLIC Qt6::Core Qt6::Network)

target_compile_features(bulwark_shared PUBLIC cxx_std_20)

add_library(bulwark_inflate STATIC ../third_party/miniz/miniz_tinfl.c)
set_source_files_properties(../third_party/miniz/miniz_tinfl.c PROPERTIES LANGUAGE CXX)
set_target_properties(bulwark_inflate PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
target_include_directories(bulwark_inflate PUBLIC ../third_party/miniz)
target_compile_definitions(bulwark_inflate PRIVATE MINIZ_NO_ARCHIVE_APIS MINIZ_NO_DEFLATE_APIS MINIZ_NO_ZLIB_APIS MINIZ_NO_TIME MINIZ_NO_STDIO)
if(MSVC)
    target_compile_options(bulwark_inflate PRIVATE /W0)
endif()
target_link_libraries(bulwark_shared PRIVATE bulwark_inflate)

if(MSVC)
    target_compile_options(bulwark_shared PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(bulwark_shared PRIVATE -Wall -Wextra)
endif()
