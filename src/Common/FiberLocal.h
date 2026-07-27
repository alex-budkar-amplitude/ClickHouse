#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <memory>
#include <type_traits>

#include <base/defines.h>

enum class FiberLocalSlot : size_t
{
    CurrentThread,
    TraceContext,
#if defined(SILK_TLS_CHECK)
    ThreadLocalStorageCheckFirstSeen,
#endif
    Count,
};

template <typename T>
concept FiberLocalStoredInline
    = std::is_scalar_v<T>
    && sizeof(T) <= sizeof(void *)
    && alignof(T) <= alignof(void *);

/// Storage for FiberLocal slots.
///
/// (1) One instance per execution context (thread, silk fiber, or stackful coroutine).
///
/// (2) FiberLocalStoredInline variables (e.g. integers, pointers) are stored inline.
///     Accessing those is zero overhead instructions vs plain TLS.
///     Non-FiberLocalStoredInline variables are allocated on the heap and destroyed
///     on execution context exit.
///
/// (3) Trivially constructible and destructible, which avoids static initialization/destruction
///     order related complexity and provides identical semantics with plain TLS variables
///     for threads. So static objects' constructors and destructors may use FiberLocal
///     just like they would use normal thread_local variables.
///
/// (4) A context switch should swap the arenas' (i.e. slots) contents. This is where we pay for
///     zero overhead on access.
///
/// (5) One type = one slot. Slots numbers are constant (see FiberLocalSlot enum).
///     So destructors are stored in a static array.
///     Example: type A is stored in slot 0, so we store ~A in slot_destructors[0]
///     once and won't ever overwrite it.
///
/// To achieve both (2) and (3):
/// 1. For threads, the class holds its instance in TLS
///    along with ThreadStorageCleaner which runs destroySlots.
/// 2. Other usages (i.e. fibers and coroutines) hold
///    std::unique_ptr<FiberLocalStorage, SlotsDestroyer> (FiberLocalStorage::Holder).
///
class FiberLocalStorage
{
public:
    struct SlotsDestroyer
    {
        void operator()(FiberLocalStorage * storage) const noexcept;
    };

    using Holder = std::unique_ptr<FiberLocalStorage, SlotsDestroyer>;

    static Holder create();

    template <typename T, FiberLocalSlot slot>
    static T load() noexcept
    {
        void * word = load<static_cast<size_t>(slot)>();
        T value;
        std::memcpy(&value, &word, sizeof(T));
        return value;
    }

    template <typename T, FiberLocalSlot slot>
    static void store(T value) noexcept
    {
        void * word = nullptr;
        std::memcpy(&word, &value, sizeof(T));
        store<static_cast<size_t>(slot)>(word);
    }

    template <typename T, FiberLocalSlot slot>
    static T & heapObject()
    {
        auto * object = static_cast<T *>(load<static_cast<size_t>(slot)>());
        if (!object)
        {
            object = new T();
            store<static_cast<size_t>(slot)>(object);
            registerDestructor(slot, [](void * raw) { delete static_cast<T *>(raw); });
            armThreadStorageCleaner();
        }
        return *object;
    }

    static void swap(FiberLocalStorage & saved) noexcept
    {
        thread_storage.slots.swap(saved.slots);
    }

    void destroySlots() noexcept;

private:

    /// A fiber may resume on another OS thread, but the compiler may hoist &slots[slot].

    static constexpr size_t slot_count = static_cast<size_t>(FiberLocalSlot::Count);

    __attribute__((noinline)) static std::array<void *, slot_count> & currentSlots() noexcept
    {
        __asm__ __volatile__("" ::: "memory");
        return thread_storage.slots;
    }

    template <size_t slot>
    static void * load() noexcept
    {
        void * value = nullptr;
#if defined(__x86_64__) && defined(__ELF__)
        __asm__ __volatile__(
            "movq %%fs:FiberLocalStorageThreadStorage@tpoff+%c1, %0"
            : "=r"(value)
            : "i"(slot * sizeof(void *))
            : "memory");
#elif defined(__aarch64__) && defined(__ELF__)
        __asm__ __volatile__(
            "mrs %0, tpidr_el0\n\t"
            "add %0, %0, :tprel_hi12:FiberLocalStorageThreadStorage\n\t"
            "add %0, %0, :tprel_lo12_nc:FiberLocalStorageThreadStorage\n\t"
            "ldr %0, [%0, %c1]"
            : "=&r"(value)
            : "i"(slot * sizeof(void *))
            : "memory");
#else
        value = currentSlots()[slot];
#endif
        return value;
    }

    template <size_t slot>
    static void store(void * value) noexcept
    {
#if defined(__x86_64__) && defined(__ELF__)
        __asm__ __volatile__(
            "movq %1, %%fs:FiberLocalStorageThreadStorage@tpoff+%c0"
            :
            : "i"(slot * sizeof(void *)), "r"(value)
            : "memory");
#elif defined(__aarch64__) && defined(__ELF__)
        void * address;
        __asm__ __volatile__(
            "mrs %0, tpidr_el0\n\t"
            "add %0, %0, :tprel_hi12:FiberLocalStorageThreadStorage\n\t"
            "add %0, %0, :tprel_lo12_nc:FiberLocalStorageThreadStorage\n\t"
            "str %2, [%0, %c1]"
            : "=&r"(address)
            : "i"(slot * sizeof(void *)), "r"(value)
            : "memory");
#else
        currentSlots()[slot] = value;
#endif
    }

    static void registerDestructor(FiberLocalSlot slot, void (* destroy)(void *)) noexcept;
    static void armThreadStorageCleaner() noexcept;

    struct ThreadStorageCleaner;

    static inline constinit std::array<std::atomic<void (*)(void *)>, slot_count> slot_destructors{};
    static thread_local constinit FiberLocalStorage thread_storage asm("FiberLocalStorageThreadStorage");

    std::array<void *, slot_count> slots{};
};

/// Fiber-aware thread_local variable.
/// Works in plain threads, silk fibers, and stackful coroutines.
template <typename T, FiberLocalSlot slot>
class FiberLocal
{
public:
    T get() const requires FiberLocalStoredInline<T> { return FiberLocalStorage::load<T, slot>(); }
    operator T() const requires FiberLocalStoredInline<T> { return get(); }
    T operator->() const requires (FiberLocalStoredInline<T> && std::is_pointer_v<T>) { return get(); }

    FiberLocal & operator=(T value) requires FiberLocalStoredInline<T>
    {
        FiberLocalStorage::store<T, slot>(value);
        return *this;
    }

    T & get() const requires (!FiberLocalStoredInline<T>) { return FiberLocalStorage::heapObject<T, slot>(); }
    operator T &() const requires (!FiberLocalStoredInline<T>) { return get(); }
    T & operator*() const requires (!FiberLocalStoredInline<T>) { return get(); }
    T * operator->() const requires (!FiberLocalStoredInline<T>) { return &get(); }
};
