#include <Common/SilkTLSCheck.h>

#include "config.h"

#if defined(SILK_TLS_CHECK) && USE_SILK
#    include <cstdint>
#    include <mutex>
#    include <string_view>
#    include <unordered_map>

#    include <Common/Exception.h>
#    include <Common/MemoryTrackerBlockerInThread.h>

#    include <silk/fibers/fiber.h>
#endif

namespace Silk
{

thread_local bool inside_silk_fiber = false;

}

/// Remembers, per fiber, the address at which it first observed each thread-local. Seeing the same
/// variable at a second address means the fiber ran it on two OS threads: it is thread-affine and
/// must be wrapped in FiberLocal (or marked SILK_TLS_BENIGN). Asserts on the spot, naming the variable.
extern "C" void check_silk_tls_access([[maybe_unused]] void * address, [[maybe_unused]] const char * name) noexcept
{
#if defined(SILK_TLS_CHECK) && USE_SILK
    const uint64_t fiber = silk::FiberScheduler::getCurrentFiberId().raw;
    if (fiber == 0)
        return;

    /// The map below locks and allocates, which touch instrumented thread-locals; guard against recursion.
    static thread_local bool inside = false;
    if (inside)
        return;
    inside = true;

    /// This runs on the allocation path; keep its own allocations off the query's memory tracker.
    MemoryTrackerBlockerInThread untracked(VariableContext::Global);

    static std::mutex mutex;
    static std::unordered_map<uint64_t, std::unordered_map<std::string_view, const void *>> first_seen_at;

    {
        std::lock_guard lock(mutex);
        const void * first = first_seen_at[fiber].try_emplace(name, address).first->second;
        chassert(first == address, name);
    }

    inside = false;
#endif
}
