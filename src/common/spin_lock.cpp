#include "common/spin_lock.h"

#if _MSC_VER
#include <intrin.h>
#if _M_AMD64
#define __x86_64__ 1
#endif
#if _M_ARM64
#define __aarch64__ 1
#endif
#else
#if __x86_64__
#include <xmmintrin.h>
#endif
#endif

namespace Common {

void PauseThread() {
#if __x86_64__
    _mm_pause();
#elif __aarch64__ && _MSC_VER
    __yield();
#elif __aarch64__
    asm("yield");
#endif
}

void SpinLock::lock() {
    while (flag.test_and_set(std::memory_order_acquire))
        PauseThread();
}

void SpinLock::unlock() {
    flag.clear(std::memory_order_release);
}

IndexSpinLock::IndexSpinLock(std::size_t num_locks) : locks(num_locks) {}
IndexSpinLock::~IndexSpinLock() = default;

void IndexSpinLock::lock(std::size_t index) {
    while (locks[index]->test_and_set(std::memory_order_acquire)) {
        PauseThread();
    }
}

void IndexSpinLock::unlock(std::size_t index) {
    locks[index]->clear(std::memory_order_release);
}

void IndexSpinLock::reserve(std::size_t size) {
    const std::size_t num_locks = locks.size();
    if (size <= num_locks) {
        return;
    }

    locks.reserve(size);
    for (std::size_t index = num_locks; index < size; index++) {
        locks.push_back(std::make_unique<std::atomic_flag>());
        locks.back()->clear();
    }
}

} // namespace Common
