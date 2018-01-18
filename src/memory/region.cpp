#include "bypasscore/memory/region.h"
#include "bypasscore/util/logger.h"

namespace bypasscore {
namespace memory {

// Most functionality is in the header as inline functions.
// This translation unit ensures the library has a region.o for linking
// and provides any non-inline helpers needed in the future.

} // namespace memory
} // namespace bypasscore
