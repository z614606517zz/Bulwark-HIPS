#include "Nav.h"

#include <QCoreApplication>

NavHub* NavHub::instance()
{
    static NavHub* hub = new NavHub(QCoreApplication::instance());
    return hub;
}
