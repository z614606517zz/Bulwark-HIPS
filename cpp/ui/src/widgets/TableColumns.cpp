#include "widgets/TableColumns.h"

#include <QAction>
#include <QCoreApplication>
#include <QEvent>
#include <QFont>
#include <QFontMetrics>
#include <QHeaderView>
#include <QHelpEvent>
#include <QMenu>
#include <QModelIndex>
#include <QSettings>
#include <QStyledItemDelegate>
#include <QTableWidget>
#include <QTimer>
#include <QToolTip>
#include <QVariant>

#include <algorithm>
#include <utility>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr int kCellPadding = 22;
constexpr int kMinSection  = 56;
constexpr int kSaveDelayMs = 500;

class ElideDelegate : public QStyledItemDelegate
{
public:
    ElideDelegate(QObject* parent, QList<bool> middle)
        : QStyledItemDelegate(parent), middle_(std::move(middle))
    {}

protected:
    void initStyleOption(QStyleOptionViewItem* option, const QModelIndex& index) const override
    {
        QStyledItemDelegate::initStyleOption(option, index);
        const int c = index.column();
        if (c >= 0 && c < middle_.size() && middle_[c])
            option->textElideMode = Qt::ElideMiddle;
    }

private:
    QList<bool> middle_;
};

class ColumnLayout : public QObject
{
public:
    ColumnLayout(QTableWidget* t, QString key, QList<ui::ColSpec> spec)
        : QObject(t), table_(t), key_(std::move(key)), spec_(std::move(spec))
    {
        auto* hh = table_->horizontalHeader();
        hh->setSectionResizeMode(QHeaderView::Interactive); // 全列可拖(Stretch 是不能拖的)
        hh->setStretchLastSection(false);
        hh->setCascadingSectionResizes(false);
        hh->setMinimumSectionSize(kMinSection);
        hh->setToolTip(u("拖动列边界可调整列宽 · 双击边界按内容自适应 · 右键可恢复默认"));
        table_->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);

        QList<bool> middle;
        middle.reserve(spec_.size());
        for (const ui::ColSpec& c : spec_)
            middle.append(c.pathLike);
        table_->setItemDelegate(new ElideDelegate(table_, std::move(middle)));

        saveTimer_ = new QTimer(this);
        saveTimer_->setSingleShot(true);
        saveTimer_->setInterval(kSaveDelayMs);
        connect(saveTimer_, &QTimer::timeout, this, [this] { save(); });
        connect(qApp, &QCoreApplication::aboutToQuit, this, [this] {
            if (saveTimer_->isActive()) {
                saveTimer_->stop();
                save();
            }
        });

        restore();
        apply();
        table_->viewport()->installEventFilter(this);

        connect(hh, &QHeaderView::sectionResized, this, [this](int, int, int) {
            if (applying_)
                return;
            custom_ = true;
            saveTimer_->start();
        });

        hh->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(hh, &QWidget::customContextMenuRequested, this,
                [this, hh](const QPoint& p) { showMenu(hh->mapToGlobal(p)); });

        QTimer::singleShot(0, this, [this] { apply(); });
    }

protected:
    bool eventFilter(QObject* watched, QEvent* ev) override
    {
        if (watched == table_->viewport()) {
            if (ev->type() == QEvent::Resize) {
                apply();
            } else if (ev->type() == QEvent::ToolTip) {
                if (showElidedTip(static_cast<QHelpEvent*>(ev)))
                    return true;
            }
        }
        return QObject::eventFilter(watched, ev);
    }

private:
    QString settingsKey() const { return QStringLiteral("columnWidths/") + key_; }

    void save() const
    {
        QStringList widths;
        for (int i = 0; i < table_->columnCount(); ++i)
            widths << QString::number(table_->columnWidth(i));
        QSettings().setValue(settingsKey(), widths.join(QLatin1Char(',')));
    }

    void restore()
    {
        const QStringList widths =
            QSettings().value(settingsKey()).toString().split(QLatin1Char(','), Qt::SkipEmptyParts);
        if (widths.size() != table_->columnCount())
            return;
        applying_ = true;
        for (int i = 0; i < widths.size(); ++i) {
            const int w = widths[i].toInt();
            if (w >= kMinSection)
                table_->setColumnWidth(i, w);
        }
        applying_ = false;
        custom_ = true;
    }

    void apply()
    {
        if (applying_ || custom_)
            return;
        const int n = std::min<int>(table_->columnCount(), spec_.size());
        if (n <= 0)
            return;

        int base = 0;
        int weight = 0;
        for (int i = 0; i < n; ++i) {
            base += spec_[i].width;
            weight += spec_[i].grow;
        }

        QList<int> widths;
        widths.reserve(n);
        for (int i = 0; i < n; ++i)
            widths.append(spec_[i].width);

        const int extra = table_->viewport()->width() - base;
        if (extra > 0 && weight > 0) {
            int handed = 0;
            int last = -1;
            for (int i = 0; i < n; ++i) {
                if (spec_[i].grow <= 0)
                    continue;
                const int add = extra * spec_[i].grow / weight;
                widths[i] += add;
                handed += add;
                last = i;
            }
            if (last >= 0)
                widths[last] += extra - handed;
        }

        applying_ = true;
        for (int i = 0; i < n; ++i)
            table_->setColumnWidth(i, widths[i]);
        applying_ = false;
    }

    bool showElidedTip(QHelpEvent* he) const
    {
        const QModelIndex idx = table_->indexAt(he->pos());
        if (!idx.isValid() || !idx.data(Qt::ToolTipRole).toString().isEmpty())
            return false;
        const QString text = idx.data(Qt::DisplayRole).toString();
        if (text.isEmpty())
            return false;

        QFont f = table_->font();
        const QVariant fv = idx.data(Qt::FontRole);
        if (fv.canConvert<QFont>())
            f = qvariant_cast<QFont>(fv);
        if (QFontMetrics(f).horizontalAdvance(text) <= table_->columnWidth(idx.column()) - kCellPadding)
            return false;

        QToolTip::showText(he->globalPos(), text, table_->viewport());
        return true;
    }

    void showMenu(const QPoint& global)
    {
        QMenu m(table_);
        QAction* fit = m.addAction(u("按内容自适应列宽"));
        QAction* def = m.addAction(u("恢复默认列宽"));
        const QAction* chosen = m.exec(global);
        if (chosen == fit) {
            applying_ = true;
            table_->resizeColumnsToContents();
            applying_ = false;
            custom_ = true;
            saveTimer_->start();
        } else if (chosen == def) {
            custom_ = false;
            QSettings().remove(settingsKey());
            apply();
        }
    }

    QTableWidget* table_ = nullptr;
    QString key_;
    QList<ui::ColSpec> spec_;
    QTimer* saveTimer_ = nullptr;
    bool applying_ = false; // 正在由代码改列宽:别把它当成用户拖动
    bool custom_ = false;
};

}

void ui::columns(QTableWidget* table, const QString& key, const QList<ColSpec>& spec)
{
    if (!table)
        return;
    new ColumnLayout(table, key, spec);
}
