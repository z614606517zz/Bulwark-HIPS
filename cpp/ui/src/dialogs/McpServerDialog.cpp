#include "dialogs/McpServerDialog.h"

#include "ai/McpManager.h"
#include "design/Components.h"
#include "design/Segmented.h"
#include "design/Sheet.h"
#include "design/Theme.h"
#include "design/ToggleSwitch.h"
#include "dialogs/EventFormat.h"

#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QUuid>
#include <QVBoxLayout>

using evtfmt::u;

namespace {

QStringList lines(const QPlainTextEdit* e)
{
    QStringList out;
    for (const QString& l : e->toPlainText().split(QLatin1Char('\n'))) {
        const QString t = l.trimmed();
        if (!t.isEmpty())
            out << t;
    }
    return out;
}

QPlainTextEdit* multiLine(const QString& placeholder, const QString& accessible, int height = 66)
{
    auto* e = new QPlainTextEdit;
    e->setPlaceholderText(placeholder);
    e->setAccessibleName(accessible);
    e->setFixedHeight(height);
    e->setTabChangesFocus(true);
    return e;
}

QLineEdit* singleLine(const QString& placeholder, const QString& accessible)
{
    auto* e = new QLineEdit;
    e->setPlaceholderText(placeholder);
    e->setAccessibleName(accessible);
    return e;
}

void addField(QGridLayout* g, int row, const QString& label, QWidget* field, const QString& hint = QString())
{
    auto* l = ui::label(label, "caption");
    g->addWidget(l, row, 0, Qt::AlignTop);
    if (hint.isEmpty()) {
        g->addWidget(field, row, 1);
        return;
    }
    auto* col = new QVBoxLayout;
    col->setSpacing(2);
    col->addWidget(field);
    auto* h = ui::label(hint, "muted");
    h->setWordWrap(true);
    col->addWidget(h);
    g->addLayout(col, row, 1);
}

QGridLayout* grid()
{
    auto* g = new QGridLayout;
    g->setContentsMargins(0, 0, 0, 0);
    g->setHorizontalSpacing(12);
    g->setVerticalSpacing(8);
    g->setColumnStretch(1, 1);
    return g;
}

}

std::optional<McpServerConfig> mcpui::editServer(QWidget* parent, McpManager* mcp, const McpServerConfig& initial,
                                                 bool isNew)
{
    Sheet s(parent);
    s.setSheetWidth(620);
    s.setHeader(QStringLiteral("server"), theme::purple(), isNew ? u("添加 MCP 服务器") : u("编辑 MCP 服务器"),
                u("生成 AI 规则建议时,大模型可以调用这台服务器提供的工具。"));

    auto* top = grid();
    auto* name = singleLine(u("例如:文件系统、威胁情报"), u("名称"));
    name->setText(initial.name);
    addField(top, 0, u("名称"), name);
    auto* transport = new Segmented;
    transport->setIdentity(theme::purple());
    transport->addSegment(u("本地命令(stdio)"));
    transport->addSegment(u("远程地址(HTTP)"));
    transport->setAccessibleName(u("传输方式"));
    addField(top, 1, u("传输方式"), transport);
    s.body()->addLayout(top);

    auto* stdioBox = new QWidget;
    auto* sg = grid();
    stdioBox->setLayout(sg);
    auto* command = singleLine(u("npx / uvx / node / C:\\path\\server.exe"), u("命令"));
    command->setText(initial.command);
    addField(sg, 0, u("命令"), command, u("以当前 Windows 用户的身份运行。只填你信任的程序。"));
    auto* args = multiLine(u("-y\n@modelcontextprotocol/server-filesystem\nC:\\Users\\me\\Documents"), u("参数"), 78);
    args->setPlainText(initial.args.join(QLatin1Char('\n')));
    addField(sg, 1, u("参数"), args, u("一行一个,原样传给程序(不需要加引号)。"));
    auto* env = multiLine(u("API_KEY=…"), u("环境变量"), 52);
    env->setPlainText(initial.env.join(QLatin1Char('\n')));
    addField(sg, 2, u("环境变量"), env, u("KEY=VALUE,一行一个;叠加在当前环境之上。"));
    auto* cwd = singleLine(u("留空 = 不指定"), u("工作目录"));
    cwd->setText(initial.cwd);
    addField(sg, 3, u("工作目录"), cwd);
    s.body()->addWidget(stdioBox);

    auto* httpBox = new QWidget;
    auto* hg = grid();
    httpBox->setLayout(hg);
    auto* url = singleLine(u("https://example.com/mcp"), u("端点 URL"));
    url->setText(initial.url);
    addField(hg, 0, u("端点 URL"), url, u("Streamable HTTP 端点。旧式 HTTP+SSE 端点不支持。"));
    auto* headers = multiLine(u("Authorization: Bearer …"), u("请求头"), 52);
    headers->setPlainText(initial.headers.join(QLatin1Char('\n')));
    addField(hg, 1, u("请求头"), headers, u("名称: 值,一行一个。令牌这类凭据填在这里。"));
    s.body()->addWidget(httpBox);

    s.body()->addWidget(ui::hDivider());
    auto* approveRow = new QHBoxLayout;
    approveRow->setSpacing(16);
    auto* approveText = new QVBoxLayout;
    approveText->setSpacing(2);
    approveText->addWidget(ui::label(u("自动批准工具调用"), "title"));
    auto* approveDesc = ui::label(u("开启后,大模型调用这台服务器的任何工具都不再逐次询问。"
                                    "只对只读、无副作用且由你信任的服务器开启。"),
                                  "muted");
    approveDesc->setWordWrap(true);
    approveText->addWidget(approveDesc);
    approveRow->addLayout(approveText, 1);
    auto* autoApprove = new ToggleSwitch(initial.autoApprove);
    autoApprove->setAccessibleName(u("自动批准工具调用"));
    approveRow->addWidget(autoApprove, 0, Qt::AlignVCenter);
    s.body()->addLayout(approveRow);

    auto* result = ui::label(QString(), "secondary");
    result->setWordWrap(true);
    result->hide();
    s.body()->addWidget(result);

    const auto syncTransport = [&s, stdioBox, httpBox, transport] {
        const bool stdio = transport->currentIndex() == 0;
        stdioBox->setVisible(stdio);
        httpBox->setVisible(!stdio);
        s.refit();
    };
    transport->setCurrentIndex(initial.isStdio() ? 0 : 1);
    stdioBox->setVisible(initial.isStdio());
    httpBox->setVisible(!initial.isStdio());
    QObject::connect(transport, &Segmented::currentChanged, &s, [syncTransport](int) { syncTransport(); });

    const auto collect = [&] {
        McpServerConfig c = initial;
        if (c.id.isEmpty())
            c.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
        c.name = name->text().trimmed();
        c.transport = transport->currentIndex() == 0 ? McpServerConfig::Transport::Stdio
                                                     : McpServerConfig::Transport::Http;
        c.command = command->text().trimmed();
        c.args = lines(args);
        c.env = lines(env);
        c.cwd = cwd->text().trimmed();
        c.url = url->text().trimmed();
        c.headers = lines(headers);
        c.autoApprove = autoApprove->isChecked();
        return c;
    };
    const auto showResult = [&s, result](const QString& text, const QColor& color) {
        result->setStyleSheet(QStringLiteral("color:%1;").arg(color.name()));
        result->setText(text);
        result->show();
        s.refit();
    };

    QPointer<QPushButton> test = ui::button(u("测试连接"), "ghost", QString(), true);
    s.addFooterLeft(test);
    QObject::connect(test, &QPushButton::clicked, &s, [&, test] {
        const McpServerConfig c = collect();
        if (const QString why = c.validationError(); !why.isEmpty()) {
            showResult(why, theme::danger());
            return;
        }
        test->setEnabled(false);
        showResult(c.isStdio() ? u("正在启动并连接…(首次运行 npx / uvx 可能要先下载,稍等)") : u("正在连接…"),
                   theme::textMuted());
        QPointer<QLabel> out = result;
        QPointer<Sheet> sheet = &s;
        mcp->test(c, [out, sheet, test](bool ok, const QString& msg) {
            if (test)
                test->setEnabled(true);
            if (!out || !sheet)
                return;
            out->setStyleSheet(QStringLiteral("color:%1;").arg((ok ? theme::success() : theme::danger()).name()));
            out->setText(msg);
            sheet->refit();
        });
    });

    s.addButton(u("取消"), "ghost", [&s] { s.reject(); });
    s.addButton(u("保存"), "primary", [&] {
        const QString why = collect().validationError();
        if (!why.isEmpty()) {
            showResult(why, theme::danger());
            return;
        }
        s.accept();
    });
    name->setFocus();
    if (s.exec() != QDialog::Accepted)
        return std::nullopt;
    return collect();
}

QList<McpServerConfig> mcpui::importServers(QWidget* parent, QString* note)
{
    Sheet s(parent);
    s.setSheetWidth(620);
    s.setHeader(QStringLiteral("server"), theme::purple(), u("从 JSON 导入 MCP 服务器"),
                u("粘贴服务器说明里给的配置片段,支持 Claude Desktop / Cursor / VS Code 的写法。"));
    auto* edit = new QPlainTextEdit;
    edit->setAccessibleName(u("MCP 配置 JSON"));
    edit->setPlaceholderText(QStringLiteral("{\n  \"mcpServers\": {\n    \"filesystem\": {\n      \"command\": \"npx\",\n"
                                            "      \"args\": [\"-y\", \"@modelcontextprotocol/server-filesystem\", "
                                            "\"C:\\\\Users\\\\me\\\\Documents\"]\n    }\n  }\n}"));
    edit->setFixedHeight(220);
    edit->setTabChangesFocus(true);
    s.body()->addWidget(edit);
    auto* hint = ui::label(u("导入的服务器默认需要逐次批准工具调用。导入后请逐台核对命令与参数。"), "muted");
    hint->setWordWrap(true);
    s.body()->addWidget(hint);
    auto* error = ui::label(QString(), "secondary");
    error->setWordWrap(true);
    error->setStyleSheet(QStringLiteral("color:%1;").arg(theme::danger().name()));
    error->hide();
    s.body()->addWidget(error);

    QList<McpServerConfig> parsed;
    s.addButton(u("取消"), "ghost", [&s] { s.reject(); });
    QPushButton* go = s.addButton(u("导入"), "primary", [&] {
        QString why;
        parsed = mcpcfg::parseImport(edit->toPlainText(), &why);
        if (parsed.isEmpty()) {
            error->setText(why);
            error->show();
            s.refit();
            return;
        }
        if (note)
            *note = why;
        s.accept();
    });
    go->setEnabled(false);
    QObject::connect(edit, &QPlainTextEdit::textChanged, &s,
                     [edit, go] { go->setEnabled(!edit->toPlainText().trimmed().isEmpty()); });
    edit->setFocus();
    if (s.exec() != QDialog::Accepted)
        return {};
    return parsed;
}
