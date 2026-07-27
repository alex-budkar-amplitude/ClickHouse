#include <Common/SilkTLSCheck.h>

#include "config.h"

#if defined(SILK_TLS_CHECK) && USE_SILK
#    include <array>
#    include <cstdint>
#    include <string_view>
#    include <utility>

#    include <Common/Exception.h>
#    include <Common/FiberLocal.h>

#    include <silk/fibers/fiber.h>
#endif

namespace Silk
{

thread_local bool inside_silk_fiber = false;

}

#if defined(SILK_TLS_CHECK) && USE_SILK
namespace
{

struct ThreadLocalStorageFirstSeen
{
    static constexpr size_t capacity = 1000;

    size_t size = 0;
    std::array<std::pair<std::string_view, const void *>, capacity> entries;

    const void * find(std::string_view name) const noexcept
    {
        for (size_t i = 0; i < size; ++i)
            if (entries[i].first == name)
                return entries[i].second;
        return nullptr;
    }

    void insert(std::string_view name, const void * address) noexcept
    {
        chassert(size < capacity);
        entries[size] = {name, address};
        ++size;
    }
};

constinit FiberLocal<ThreadLocalStorageFirstSeen, FiberLocalSlot::ThreadLocalStorageCheckFirstSeen> first_seen;

}

/// The pass injects a call at the entry of SILK_FIBER_ENTRYPOINT function: the per-fiber
/// state is created at fiber start, a safe allocation point, so the hook itself never allocates.
extern "C" void silk_tls_check_prime() noexcept
{
    first_seen.get();
}
#endif

/// Remembers, per fiber, the address at which it first observed each thread-local. Seeing the same
/// variable at a second address means the fiber ran it on two OS threads: it is thread-affine and
/// must be wrapped in FiberLocal (or marked SILK_TLS_BENIGN). Asserts on the spot, naming the variable.
extern "C" void check_silk_tls_access([[maybe_unused]] void * address, [[maybe_unused]] const char * name) noexcept
{
#if defined(SILK_TLS_CHECK) && USE_SILK
    const uint64_t fiber = silk::FiberScheduler::getCurrentFiberId().raw;
    if (fiber == 0)
        return;

    /// The failure path below logs and aborts, which touches instrumented thread-locals; guard against recursion.
    static thread_local bool inside = false;
    if (inside)
        return;
    inside = true;

    if (const void * first = first_seen->find(name))
        chassert(first == address, name);
    else
        first_seen->insert(name, address);

    inside = false;
#endif
}
