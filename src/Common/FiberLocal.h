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
        T value;
        std::memcpy(&value, &thread_storage.slots[static_cast<size_t>(slot)], sizeof(T));
        return value;
    }

    template <typename T, FiberLocalSlot slot>
    static void store(T value) noexcept
    {
        std::memcpy(&thread_storage.slots[static_cast<size_t>(slot)], &value, sizeof(T));
    }

    template <typename T, FiberLocalSlot slot>
    static T & heapObject()
    {
        void * & word = thread_storage.slots[static_cast<size_t>(slot)];
        auto * object = static_cast<T *>(word);
        if (!object)
        {
            object = new T();
            word = static_cast<void *>(object);
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
    static constexpr size_t slot_count = static_cast<size_t>(FiberLocalSlot::Count);

    static void registerDestructor(FiberLocalSlot slot, void (* destroy)(void *)) noexcept;
    static void armThreadStorageCleaner() noexcept;

    struct ThreadStorageCleaner;

    static inline constinit std::array<std::atomic<void (*)(void *)>, slot_count> slot_destructors{};
    static thread_local constinit FiberLocalStorage thread_storage;

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
