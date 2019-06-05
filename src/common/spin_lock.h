#pragma once

#include <atomic>
#include <memory>
#include <thread>
#include <vector>
#include "common/common_types.h"

namespace Common {
/////////////////////////////////////////////////////////////
// Code snippet from: http://anki3d.org/spinlock/
// Posted on 20 Jan 2014 by Panagiotis Christopoulos Charitos
// modified to use pause intrinsics.
/////////////////////////////////////////////////////////////
class SpinLock {
public:
    void lock();
    void unlock();

private:
    std::atomic_flag flag = ATOMIC_FLAG_INIT;
};

class IndexSpinLock {
public:
    explicit IndexSpinLock(std::size_t num_locks);
    ~IndexSpinLock();

    void lock(std::size_t index);
    void unlock(std::size_t index);
    void reserve(std::size_t size);

private:
    std::vector<std::unique_ptr<std::atomic_flag>> locks;
};

} // namespace Common
