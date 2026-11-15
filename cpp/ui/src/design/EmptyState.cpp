#include "design/EmptyState.h"
#include "design/Components.h"
#include "design/Reflow.h"
#include "design/Robot.h"
#include "design/Theme.h"

#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

class CenteredText : public QLabel
{
public:
    CenteredText(const char* role, int maxWidth)
    {
        setProperty("role", role);
        setAlignment(Qt::AlignHCenter);
        setWordWrap(true);
        setMaximumWidth(maxWidth);
    }
    int heightForWidth(int w) const override { return QLabel::heightForWidth(qMin(w, maximumWidth())); }
    QSize sizeHint() const override
    {
        const int oneLine = fontMetrics().horizontalAdvance(text()) + 4;
        const int w = qMin(oneLine, maximumWidth());
        return {w, heightForWidth(w)};
    }
    QSize minimumSizeHint() const override { return {qMin(160, maximumWidth()), fontMetrics().height()}; }
};

}

EmptyState::EmptyState(QWidget* parent) : QWidget(parent)
{
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 24, 24, 24);
    v->setSpacing(0);
    v->addStretch(3);

    robot::Look look;
    look.mood = robot::Mood::Think;
    look.pose = robot::Pose::Sit;
    look.shadow = false;
    m_bot = new RobotWidget(88, look);
    m_bot->setAutoBlink(true);
    m_bot->setAnimated(true);
    v->addWidget(m_bot, 0, Qt::AlignHCenter);
    v->addSpacing(12);

    m_title = new CenteredText("h2", 480);
    v->addWidget(m_title, 0, Qt::AlignHCenter);
    v->addSpacing(6);

    m_body = new CenteredText("secondary", 440);
    v->addWidget(m_body, 0, Qt::AlignHCenter);
    v->addSpacing(16);

    m_action = ui::button(QString(), "ghost");
    m_action->hide();
    connect(m_action, &QPushButton::clicked, this, [this] {
        if (m_fn)
            m_fn();
    });
    v->addWidget(m_action, 0, Qt::AlignHCenter);
    v->addStretch(4);

    // 列表区矮到放不下整套内容时,先收起小垒(它只是装饰,硬挤会被切掉头顶),标题和说明保持完整。
    ui::onResize(this, [this, v] { ui::showIfFits(m_bot, v, size()); });
}

void EmptyState::setContent(const QString& icon, const QColor& color, const QString& title,
                            const QString& body)
{
    // 小垒的表情跟着这条提示的语气走;图标名只决定「是不是还在加载」。
    robot::Mood mood = robot::Mood::Think;
    if (color == theme::danger())
        mood = robot::Mood::Alert;
    else if (color == theme::warning())
        mood = robot::Mood::Ask;
    else if (color == theme::success())
        mood = robot::Mood::Happy;
    else if (icon == QLatin1String("search") || icon == QLatin1String("filter"))
        mood = robot::Mood::Info;
    else if (icon == QLatin1String("server") || icon == QLatin1String("plug"))
        mood = robot::Mood::Sleep;
    m_bot->setMood(mood);
    m_title->setText(title);
    m_body->setText(body);
    m_body->setVisible(!body.isEmpty());
    setAccessibleName(title);
    setAccessibleDescription(body);
}

void EmptyState::setAction(const QString& text, std::function<void()> fn, const char* variant)
{
    m_fn = std::move(fn);
    m_action->setText(text);
    ui::setVariant(m_action, variant);
    m_action->setVisible(!text.isEmpty());
}
