find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network Concurrent)

set(BULWARK_UI_SOURCES
    src/Bootstrap.h
    src/Bootstrap.cpp
    src/MainWindow.h
    src/MainWindow.cpp
    src/UiHost.h               # 主窗口宿主:建窗、挂 WindowGuard、换皮肤时整窗重建
    src/UiHost.cpp
    src/WindowGuard.h
    src/WindowGuardPolicy.h
    src/WindowGuard.cpp
    src/Nav.h
    src/Nav.cpp

    src/design/Skin.h          # 三套机器人皮肤(机甲 / 卡哇伊 / 金刚)的调色板与轮廓
    src/design/Skin.cpp
    src/design/Theme.h
    src/design/Theme.cpp
    src/design/SvgPath.h
    src/design/SvgPath.cpp
    src/design/Robot.h         # 小垒:机器人形象(表情 = 防护状态)
    src/design/Robot.cpp
    src/design/Sticker.h       # 贴纸 / 器件语汇:面板、斑马条、钢印、数码管、贴纸字、贴纸图标
    src/design/Sticker.cpp
    src/design/Shell.h         # 主窗口机身外壳
    src/design/Shell.cpp
    src/design/Cockpit.h       # 驾驶舱顶栏:键帽导航、品牌面板、六角窗口按钮
    src/design/Cockpit.cpp
    src/design/Identity.h      # page identity hues + record kind hues (never a status colour)
    src/design/Tone.h
    src/design/Format.h
    src/design/Motion.h
    src/design/Motion.cpp
    src/design/Icons.h
    src/design/Icons.cpp
    src/design/IconTile.h
    src/design/GlowCard.h
    src/design/GlowCard.cpp
    src/design/Backdrop.h
    src/design/Backdrop.cpp
    src/design/NavButton.h
    src/design/NavButton.cpp
    src/design/PageTransition.h
    src/design/PageTransition.cpp
    src/design/Ripple.h
    src/design/Ripple.cpp
    src/design/ToggleSwitch.h
    src/design/ToggleSwitch.cpp
    src/design/Components.h
    src/design/TitanKit.h      # 金刚专属版式的面板头、代号标签、读数
    src/design/TitanKit.cpp
    src/design/TableKit.h
    src/design/FlowLayout.h
    src/design/FlowLayout.cpp
    src/design/Segmented.h
    src/design/Segmented.cpp
    src/design/FilterChip.h
    src/design/FilterChip.cpp
    src/design/EmptyState.h
    src/design/EmptyState.cpp
    src/design/Banner.h
    src/design/Banner.cpp
    src/design/Inspector.h
    src/design/Inspector.cpp
    src/design/RecordModel.h
    src/design/RecordModel.cpp
    src/design/RecordDelegate.h
    src/design/RecordDelegate.cpp
    src/design/ListShell.h
    src/design/ListShell.cpp
    src/design/Sheet.h
    src/design/Sheet.cpp
    src/design/Confirm.h
    src/design/Confirm.cpp
    src/design/CountdownBar.h
    src/design/CountdownBar.cpp
    src/design/DropZone.h
    src/design/DropZone.cpp
    src/design/FilePicker.h
    src/design/FilePicker.cpp
    src/design/FitScroll.h
    src/design/CountTile.h
    src/design/StatusStrip.h

    src/widgets/ElidingLabel.h
    src/widgets/WrapLabel.h
    src/widgets/CodeBlock.h
    src/widgets/CodeBlock.cpp
    src/widgets/FileIconSafe.h
    src/widgets/FileIconSafe.cpp
    src/widgets/TrafficOverlay.h
    src/widgets/TrafficOverlay.cpp
    src/widgets/ResidentBot.h  # 常驻机器人小垒
    src/widgets/ResidentBot.cpp
    src/pages/HardeningPage.cpp
    src/widgets/TrafficDetailWindow.h
    src/widgets/TrafficDetailWindow.cpp
    src/widgets/TableColumns.h
    src/widgets/TableColumns.cpp
    src/pages/DashboardPage.h
    src/pages/DashboardPage.cpp
    src/pages/TablePages.h
    src/pages/PageKit.h
    src/pages/EventsPage.cpp
    src/pages/TimelinePage.cpp
    src/pages/ProcessesPage.cpp
    src/pages/RulesPage.cpp
    src/pages/TrustPage.cpp
    src/pages/SoftwareCatalogPage.cpp
    src/pages/QuarantinePage.cpp
    src/pages/PersistencePage.cpp
    src/pages/CardPages.h
    src/pages/SettingsPage.cpp
    src/pages/BoostPage.cpp

    src/dialogs/EventFormat.h
    src/dialogs/ExplainCard.h
    src/dialogs/ExplainCard.cpp
    src/dialogs/ThreatCodeView.h
    src/dialogs/ThreatCodeView.cpp
    src/dialogs/EventViews.h
    src/dialogs/EventViews.cpp
    src/dialogs/ProcessViews.h
    src/dialogs/ProcessViews.cpp
    src/dialogs/PromptDialog.h
    src/dialogs/PromptDialog.cpp
    src/dialogs/AiInsightPanel.h
    src/dialogs/AiInsightPanel.cpp
    src/dialogs/AiActivityWindow.h
    src/dialogs/AiActivityWindow.cpp
    src/dialogs/RemediationReportDialog.h
    src/dialogs/RemediationReportDialog.cpp
    src/dialogs/AttackTimelineWindow.h
    src/dialogs/AttackTimelineWindow.cpp
    src/dialogs/AttackGraphWindow.h
    src/dialogs/AttackGraphWindow.cpp
    src/dialogs/ProcessDetailDialog.h
    src/dialogs/ProcessDetailDialog.cpp
    src/dialogs/ToastWindow.h
    src/dialogs/ToastWindow.cpp
    src/dialogs/ToastNotifier.h
    src/dialogs/ToastNotifier.cpp

    src/ipc/IpcClient.h
    src/ipc/IpcClient.cpp
    src/ai/AiScanner.h
    src/ai/AiScanner.cpp
    src/ai/McpConfig.h
    src/ai/McpConfig.cpp
    src/ai/McpClient.h
    src/ai/McpClient.cpp
    src/ai/McpManager.h
    src/ai/McpManager.cpp
    src/dialogs/McpServerDialog.h
    src/dialogs/McpServerDialog.cpp
    src/voice/VoiceAnnouncer.h
    src/voice/VoiceAnnouncer.cpp
)

qt_add_executable(bulwark_ui WIN32
    app.rc
    src/main.cpp
    ${BULWARK_UI_SOURCES}
)

target_include_directories(bulwark_ui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(bulwark_ui PRIVATE
    bulwark_shared
    Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network Qt6::Concurrent)

if(WIN32)
    target_link_libraries(bulwark_ui PRIVATE shell32 dwmapi ole32 crypt32)
endif()

target_compile_features(bulwark_ui PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(bulwark_ui PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(bulwark_ui PRIVATE UNICODE _UNICODE)
    # 控制台可修改全局防护并调用 SYSTEM 服务，当前止血模型要求每次启动经 UAC 提升。
    target_link_options(bulwark_ui PRIVATE
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
else()
    target_compile_options(bulwark_ui PRIVATE -Wall -Wextra)
endif()

# 询问弹窗的离屏预览工具。默认不构建,正式构建与发布包都不受影响。
# 复用上面同一份 BULWARK_UI_SOURCES;刻意不加 WIN32:要走控制台子系统才能看到它打印的尺寸与裁决。
#   cmake -S cpp -B cpp\build -DBULWARK_BUILD_UI_PREVIEW=ON
#   cmake --build cpp\build --config Release --target bulwark_prompt_preview
option(BULWARK_BUILD_UI_PREVIEW "构建询问弹窗离屏预览工具(仅开发期排版验证)" OFF)
if(BULWARK_BUILD_UI_PREVIEW)
    qt_add_executable(bulwark_prompt_preview
        src/PromptPreviewMain.cpp
        ${BULWARK_UI_SOURCES}
    )
    target_include_directories(bulwark_prompt_preview PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(bulwark_prompt_preview PRIVATE
        bulwark_shared
        Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network Qt6::Concurrent)
    if(WIN32)
        target_link_libraries(bulwark_prompt_preview PRIVATE shell32 dwmapi ole32 crypt32)
    endif()
    target_compile_features(bulwark_prompt_preview PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(bulwark_prompt_preview PRIVATE /W4 /permissive- /utf-8)
        target_compile_definitions(bulwark_prompt_preview PRIVATE UNICODE _UNICODE)
    else()
        target_compile_options(bulwark_prompt_preview PRIVATE -Wall -Wextra)
    endif()
endif()
