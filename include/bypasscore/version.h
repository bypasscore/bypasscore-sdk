#pragma once

#define BYPASSCORE_VERSION_MAJOR 4
#define BYPASSCORE_VERSION_MINOR 0
#define BYPASSCORE_VERSION_PATCH 0

#define BYPASSCORE_VERSION_STRING "4.0.0"

#define BYPASSCORE_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))

#define BYPASSCORE_VERSION \
    BYPASSCORE_MAKE_VERSION(BYPASSCORE_VERSION_MAJOR, \
                            BYPASSCORE_VERSION_MINOR, \
                            BYPASSCORE_VERSION_PATCH)
