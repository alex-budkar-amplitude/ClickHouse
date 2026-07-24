#include <Common/SilkFiberScheduler.h>

#if USE_SILK

#include <Common/Exception.h>
#include <Common/FiberLocal.h>
#include <Common/SilkTLSCheck.h>

#include <silk/fibers/fiber.h>
#include <silk/fibers/future.h>
#include <silk/util/init.h>
#include <silk/util/perf.h>

#include <cerrno>
#include <functional>
#include <memory>
#include <utility>

namespace Silk
{

namespace
{

/// We need to formally guarantee that any Silk-initialization-related writes to memory
/// happen-before any reads that follow a isFiberSchedulerInitialized call that returns true.
/// Therefore, release-acquire is required.
std::atomic<bool> fiber_scheduler_initialized = false;

struct FiberContext
{
    FiberLocalStorage::Holder fiber_local_storage;
    std::function<int()> task;

    static int main(FiberContext * self) noexcept
    {
        try
        {
            return self->task();
        }
        catch (...)
        {
            DB::tryLogCurrentException(__PRETTY_FUNCTION__);
            return EIO;
        }
    }
};

void onFiberResume(silk::Fiber * fiber) noexcept
{
    auto * context = static_cast<FiberContext *>(silk::FiberScheduler::getFiberParameters(fiber));
    FiberLocalStorage::swap(*context->fiber_local_storage);
    inside_silk_fiber = true;
}

void onFiberSuspend(silk::Fiber * fiber) noexcept
{
    inside_silk_fiber = false;
    auto * context = static_cast<FiberContext *>(silk::FiberScheduler::getFiberParameters(fiber));
    FiberLocalStorage::swap(*context->fiber_local_storage);
}

}

void initializeFiberScheduler(uint32_t fiber_stack_size)
{
    silk::initialize();

    const silk::FiberScheduler::Options options =
    {
        .fiberStackSize = fiber_stack_size,
        .fiberSuspend = &onFiberSuspend,
        .fiberResume = &onFiberResume,
    };
    silk::FiberScheduler::initialize(&options);

    fiber_scheduler_initialized.store(true, std::memory_order_release);
}

void destroyFiberScheduler()
{
    fiber_scheduler_initialized.store(false, std::memory_order_release);

    silk::FiberScheduler::destroy();
    silk::destroy();
}

/// TOCTOU is only possible if the function is run outside the global thread pool
/// because global thread pool shutdown explicitly preceeds Silk runtime destruction.
bool isFiberSchedulerInitialized()
{
    return fiber_scheduler_initialized.load(std::memory_order_acquire);
}

RuntimeCounters getRuntimeCounters()
{
    RuntimeCounters result;

    if (!isFiberSchedulerInitialized())
        return result;

    const uint32_t count = silk::Perf::getSimpleCounterCount();
    if (count == 0)
        return result;

    /// No TOCTOU is possible:
    /// 1. Registration is append-only and confined to initializeFiberScheduler.
    /// 2. Destruction presupposes quiesced readers as Silk runtime is explicitly destroyed after shutting down the global thread pool.
    /// 3. In between, the counter set is immutable.
    /// 4. In theory, if the current thread reads a stale counter count, getSimpleCounters respects the counterArraySize argument.
    auto accumulated = std::make_unique<silk::Perf::SimpleCounter[]>(count);
    const uint32_t written = silk::Perf::getSimpleCounters(0, accumulated.get(), count);

    result.reserve(written);
    for (uint32_t i = 0; i < written; ++i)
        result.emplace_back(silk::Perf::getSimpleCounterInfo(i).name, accumulated[i].value.load(std::memory_order_relaxed));

    return result;
}

/// 0 = success; ENOMEM = fiber allocation failed.
int spawn(std::function<int()> task, silk::FiberFuture & future)
{
    return silk::FiberScheduler::run(
        &FiberContext::main,
        FiberContext{ .fiber_local_storage = FiberLocalStorage::create(), .task = std::move(task) },
        &future);
}

int runBlocking(std::function<int()> task)
{
    silk::FiberFuture future;
    int r = spawn(std::move(task), future);
    return r ? r : future.wait();
}

}

#endif
