#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "design/Banner.h"
#include "design/Confirm.h"
#include "design/Format.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Skin.h"
#include "design/Tone.h"
#include "dialogs/EventFormat.h"
#include "bulwark/engine/TrustedSoftwareCatalog.h"

#include <QComboBox>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPushButton>
#include <QTextEdit>
#include <QTimer>
#include <QUrl>

#include <algorithm>
#include <memory>

using evtfmt::u;
using bulwark::engine::TrustedApp;
using bulwark::engine::TrustedSoftwareCatalog;

namespace {

RecordView appView(const TrustedApp& a)
{
    RecordView v;
    v.icon = a.scope == TrustedApp::Scope::Vendor ? QStringLiteral("package")
                                                  : QStringLiteral("trust");
    v.iconColor = a.enabled ? theme::olive() : theme::textSecondary();
    v.title = a.name;
    // 匹配方式只用「厂商级」标签说一次。分类不放进行里:列表始终按分类分组,组标题就是分类
    // (搜索仍能按分类命中,见下面的 haystack;详情里也有「分类」一项)。
    if (a.scope == TrustedApp::Scope::Vendor) {
        v.subtitle = u("签名主体:") + a.publishers.join(QStringLiteral(" / "));
        v.chips << u("厂商级");
    } else {
        v.subtitle = a.vendor + QStringLiteral(" · ") + a.exes.join(QStringLiteral(", "));
    }
    v.subtitleMono = true;
    if (a.builtin)
        v.chips << u("内置");
    if (!a.enabled)
        v.chips << u("已停用");
    v.dim = !a.enabled;
    if (theme::titan()) {
        // 金刚:匹配方式用两种颜色的标签区分 —— 厂商级(按签名主体)蓝、映像级(按 exe 文件名)绿;
        // 来源和停用写在右侧小字里。
        const bool vendor = a.scope == TrustedApp::Scope::Vendor;
        v.chips.clear();
        v.pill = vendor ? u("厂商级") : u("映像级");
        v.pillColor = !a.enabled ? theme::textMuted() : vendor ? theme::pal().glow : theme::success();
        v.meta = (a.builtin ? u("内置") : u("手动添加")) + (a.enabled ? QString() : u(" · 已停用"));
    }
    v.haystack = a.name + QLatin1Char(' ') + a.vendor + QLatin1Char(' ') + a.category
        + QLatin1Char(' ') + a.exes.join(QLatin1Char(' ')) + QLatin1Char(' ')
        + a.publishers.join(QLatin1Char(' '));
    v.key = a.id;
    v.tooltip = a.scope == TrustedApp::Scope::Vendor
        ? a.publishers.join(QStringLiteral(" / "))
        : a.exes.join(QStringLiteral(", "));
    return v;
}

bool addAppDialog(QWidget* parent, TrustedApp* out)
{
    QDialog dlg(parent);
    dlg.setWindowTitle(u("添加到软件信任库"));
    // 太窄时两个多行输入框里的示例文字会折行,最后一行就被框的下边切掉。
    dlg.setMinimumWidth(460);
    auto* form = new QFormLayout(&dlg);
    auto* scope = new QComboBox(&dlg);
    scope->addItem(u("映像级:按 exe 文件名匹配"), 0);
    scope->addItem(u("厂商级:按签名主体匹配全家桶"), 1);
    auto* name = new QLineEdit(&dlg);
    auto* vendor = new QLineEdit(&dlg);
    auto* cat = new QComboBox(&dlg);
    cat->setEditable(true);
    cat->addItems({u("厂商"), u("办公"), u("浏览器"), u("即时通讯"), u("开发"), u("压缩"),
                   u("媒体"), u("安全"), u("传输"), u("远程"), u("游戏"), u("金融"), u("硬件"),
                   u("工程"), u("其他")});
    auto* exes = new QTextEdit(&dlg);
    exes->setPlaceholderText(u("每行一个映像名,如:\nmyapp.exe\nmyapp64.exe"));
    exes->setFixedHeight(88);
    auto* pubs = new QTextEdit(&dlg);
    pubs->setPlaceholderText(u("证书主体关键词,每行一个。\n厂商级必填(如:Tencent Technology)。"));
    pubs->setFixedHeight(88);
    form->addRow(u("匹配方式"), scope);
    form->addRow(u("显示名 *"), name);
    form->addRow(u("发行商"), vendor);
    form->addRow(u("分类"), cat);
    form->addRow(u("映像名"), exes);
    form->addRow(u("签名主体 *"), pubs);
    auto* tip = new QLabel(
        u("映像级=指定 exe;厂商级=该厂全家桶(证书主体词边界命中)。"
          "两者都要求【签名健康】;行为规则与硬指标仍然生效。"),
        &dlg);
    tip->setWordWrap(true);
    form->addRow(tip);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    form->addRow(buttons);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    QObject::connect(scope, &QComboBox::currentIndexChanged, &dlg, [exes](int idx) {
        exes->setEnabled(idx == 0);
        exes->setPlaceholderText(idx == 0
            ? u("每行一个映像名,如:\nmyapp.exe\nmyapp64.exe")
            : u("厂商级不需要列 exe,按签名主体覆盖全家桶"));
    });

    if (dlg.exec() != QDialog::Accepted)
        return false;
    if (name->text().trimmed().isEmpty()) {
        ui::notify(parent, ui::Tone::Danger, u("请填写显示名。"));
        return false;
    }
    const bool vendorScope = scope->currentData().toInt() == 1;
    QStringList pubList;
    for (const QString& line : pubs->toPlainText().split(QLatin1Char('\n'), Qt::SkipEmptyParts))
        pubList << line.trimmed();
    if (vendorScope && pubList.isEmpty()) {
        ui::notify(parent, ui::Tone::Danger, u("厂商级必须填写签名主体关键词。"));
        return false;
    }
    QStringList exeList;
    if (!vendorScope) {
        for (const QString& line : exes->toPlainText().split(QLatin1Char('\n'), Qt::SkipEmptyParts))
            exeList << line.trimmed().toLower();
        if (exeList.isEmpty()) {
            ui::notify(parent, ui::Tone::Danger, u("请至少填写一个映像名。"));
            return false;
        }
    }
    TrustedApp a;
    a.name = name->text().trimmed();
    a.vendor = vendor->text().trimmed();
    a.category = cat->currentText().trimmed().isEmpty() ? u("其他") : cat->currentText().trimmed();
    a.exes = exeList;
    a.publishers = pubList;
    a.scope = vendorScope ? TrustedApp::Scope::Vendor : TrustedApp::Scope::Exe;
    a.enabled = true;
    a.builtin = false;
    *out = a;
    return true;
}

}

QWidget* pages::softwareCatalog()
{
    auto* page = new RecordBrowser;
    page->setIdentity(theme::olive());
    page->setGrouped(true, true);
    page->setNeedsConnection(false);
    page->searchBox()->setPlaceholderText(u("搜索名称 / 发行商 / 映像名…"));
    auto store = std::make_shared<RecordStore<TrustedApp>>(page->model(), &appView);
    auto reloadFn = std::make_shared<std::function<void()>>();

    const auto reload = [page, store, reloadFn] {
        page->setLoading(true);
        TrustedSoftwareCatalog::instance().load();
        QList<TrustedApp> list = TrustedSoftwareCatalog::instance().apps();
        std::stable_sort(list.begin(), list.end(),
                         [](const TrustedApp& a, const TrustedApp& b) {
                             if (a.category != b.category)
                                 return a.category < b.category;
                             return a.name.localeAwareCompare(b.name) < 0;
                         });
        store->resetGrouped(
            list, [](const TrustedApp& a) { return a.category; },
            [](const QString& g, const QList<const TrustedApp*>& members) {
                RecordView h;
                h.title = g;
                h.groupNote = u("%1 项").arg(members.size());
                h.groupColor = theme::olive();
                return h;
            },
            {u("厂商"), u("浏览器"), u("办公"), u("即时通讯"), u("开发"), u("压缩"),
             u("传输"), u("媒体"), u("安全"), u("远程"), u("游戏"), u("金融"), u("硬件"),
             u("工程"), u("其他")});
        page->setLoading(false);
    };
    *reloadFn = reload;

    const auto addOne = [page, reload] {
        TrustedApp a;
        if (!addAppDialog(page, &a))
            return;
        QString err;
        if (!TrustedSoftwareCatalog::instance().upsert(a, &err)) {
            ui::notify(page, ui::Tone::Danger, err);
            return;
        }
        ui::notify(page, ui::Tone::Success, u("已添加:%1").arg(a.name));
        reload();
    };

    page->setNoDataContent(QStringLiteral("trust"), u("软件信任库是空的"),
                           u("这里收录市面常用软件画像,用于降低信标/外联等误报。可手动添加本机常用软件。"),
                           u("添加软件…"), addOne);

    page->setInspectorBuilder([store, page, reloadFn](Inspector* in, int row) {
        const TrustedApp* a = store->itemAt(row);
        if (!a)
            return;
        in->setHeader(QStringLiteral("trust"),
                      a->enabled ? theme::olive() : theme::textSecondary(), a->name,
                      a->scope == TrustedApp::Scope::Vendor ? u("厂商级画像(全家桶)")
                                                           : (a->builtin ? u("内置软件画像")
                                                                         : u("手动添加的软件画像")));
        in->addLead(a->scope == TrustedApp::Scope::Vendor
                        ? u("同一发行商签发的程序(全家桶)在签名健康时,信标/外联等时序检测前放行。"
                            "行为规则与硬指标仍然生效。")
                        : u("命中该映像且签名健康时,信标/外联等时序检测前放行,降低正常软件误报。"
                            "行为规则与硬指标仍然生效。"));
        QVBoxLayout* s = in->addSection(u("画像"));
        in->addField(s, u("显示名"), a->name);
        in->addField(s, u("发行商"), a->vendor);
        in->addField(s, u("分类"), a->category);
        in->addField(s, u("匹配方式"),
                     a->scope == TrustedApp::Scope::Vendor ? u("厂商级(签名主体)")
                                                           : u("映像级(exe 文件名)"));
        if (!a->exes.isEmpty())
            in->addField(s, u("映像名"), a->exes.join(QStringLiteral(", ")), Inspector::Mono);
        if (!a->publishers.isEmpty())
            in->addField(s, u("签名主体"), a->publishers.join(QStringLiteral(" / ")));
        if (!a->note.isEmpty())
            in->addField(s, u("备注"), a->note);
        in->addField(s, u("来源"), a->builtin ? u("内置") : u("手动添加"));
        in->addField(s, u("状态"), a->enabled ? u("启用") : u("已停用"));

        const TrustedApp copy = *a;
        in->addAction(QStringLiteral("power"), a->enabled ? u("停用") : u("启用"),
                      a->enabled ? "ghost" : "primary", [page, copy, reloadFn] {
                          QString err;
                          if (!TrustedSoftwareCatalog::instance().setEnabled(copy.id, !copy.enabled, &err)) {
                              ui::notify(page, ui::Tone::Danger, err);
                              return;
                          }
                          ui::notify(page, ui::Tone::Success,
                                     copy.enabled ? u("已停用:%1").arg(copy.name)
                                                  : u("已启用:%1").arg(copy.name));
                          if (reloadFn && *reloadFn)
                              (*reloadFn)();
                      });
        if (!a->builtin) {
            in->addAction(QStringLiteral("trash"), u("删除"), "danger", [page, copy, reloadFn] {
                ui::ConfirmSpec c;
                c.title = u("删除软件画像");
                c.summary = u("删除后该软件不再自动降误报,可随时再添加。");
                c.subjectLabel = u("软件");
                c.subject = copy.name;
                c.confirmText = u("删除");
                if (!ui::confirm(page, c))
                    return;
                QString err;
                if (!TrustedSoftwareCatalog::instance().remove(copy.id, &err)) {
                    ui::notify(page, ui::Tone::Danger, err);
                    return;
                }
                ui::notify(page, ui::Tone::Success, u("已删除:%1").arg(copy.name));
                if (reloadFn && *reloadFn)
                    (*reloadFn)();
            });
        }
    });

    QHBoxLayout* actions = pagekit::headerActions(page);
    QObject::connect(pagekit::headerButton(actions, QStringLiteral("plus"), u("添加软件…"), "primary"),
                     &QPushButton::clicked, page, addOne);
    QMenu* more = pagekit::headerMenu(actions);
    pagekit::menuAction(more, QStringLiteral("refresh"), u("刷新"), page, reload);
    pagekit::menuAction(more, QStringLiteral("file"), u("打开配置文件"), page, [] {
        QDesktopServices::openUrl(
            QUrl::fromLocalFile(TrustedSoftwareCatalog::instance().filePath()));
    });
    pagekit::menuAction(more, QStringLiteral("undo"), u("恢复内置库"), page, [page, reload] {
        ui::ConfirmSpec c;
        c.title = u("恢复内置软件库");
        c.summary = u("将重建内置条目,并保留你手动添加的软件。");
        c.confirmText = u("恢复");
        if (!ui::confirm(page, c))
            return;
        TrustedSoftwareCatalog::instance().resetToBuiltin();
        ui::notify(page, ui::Tone::Success, u("已恢复内置软件库"));
        reload();
    });

    QTimer::singleShot(0, page, reload);
    return page;
}
