#pragma once
#include <QDialog>
#include <QList>

#include "ai/AiScanner.h"
#include "design/RecordModel.h"

#include <memory>

class BannerHost;
class ElidingLabel;
class Inspector;
class QLabel;
class QMenu;
class QTimer;
class RecordBrowser;

struct AiActivityRow {
    bool fromLibrary = false;
    AiCallRecord call;
    AiScanner::ExplainEntry entry;
};

class AiActivityWindow : public QDialog
{
    Q_OBJECT
public:
    explicit AiActivityWindow(AiScanner* ai, QWidget* parent = nullptr);
    ~AiActivityWindow() override;

    static void open(QWidget* context, AiScanner* ai);

private:
    void rebuild();
    void refreshSummary();
    void scheduleRefresh();  // 合并刷新:询问风暴下流水会一秒来好几条,不能每条都重建一次
    void buildInspector(Inspector* ins, int sourceRow);
    void fillMenu(QMenu* menu, const QList<int>& sourceRows);
    void copyRow(int sourceRow);
    bool isLibrarySegment() const;

    AiScanner* m_ai = nullptr;
    BannerHost* m_banners = nullptr;
    RecordBrowser* m_list = nullptr;
    std::shared_ptr<RecordStore<AiActivityRow>> m_store;
    QTimer* m_refresh = nullptr;

    QList<AiScanner::ExplainEntry> m_library;
    bool m_libraryDirty = true;

    QLabel* m_creditValue = nullptr;
    ElidingLabel* m_creditNote = nullptr;
    QLabel* m_callValue = nullptr;
    ElidingLabel* m_callNote = nullptr;
    QLabel* m_libValue = nullptr;
    ElidingLabel* m_libNote = nullptr;
    QLabel* m_apiValue = nullptr;
    ElidingLabel* m_apiNote = nullptr;
};
