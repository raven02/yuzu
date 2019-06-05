// Copyright 2018 yuzu emulator team
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <cstdlib>
#include <cstring>

#include "common/assert.h"
#include "common/logging/log.h"
#include "core/hle/ipc_helpers.h"
#include "core/hle/kernel/kernel.h"
#include "core/hle/kernel/readable_event.h"
#include "core/hle/kernel/writable_event.h"
#include "core/hle/service/nvdrv/devices/nvhost_ctrl.h"

namespace Service::Nvidia::Devices {

nvhost_ctrl::nvhost_ctrl() = default;
nvhost_ctrl::~nvhost_ctrl() = default;

u32 nvhost_ctrl::ioctl(Ioctl command, const std::vector<u8>& input, std::vector<u8>& output) {
    LOG_DEBUG(Service_NVDRV, "called, command=0x{:08X}, input_size=0x{:X}, output_size=0x{:X}",
              command.raw, input.size(), output.size());

    switch (static_cast<IoctlCommand>(command.raw)) {
    case IoctlCommand::IocGetConfigCommand:
        return NvOsGetConfigU32(input, output);
    case IoctlCommand::IocCtrlEventRegisterCommand:
        return IocCtrlEventRegister(input, output);
    }
    UNIMPLEMENTED_MSG("Unimplemented ioctl");
    return 0;
}

u32 nvhost_ctrl::ioctlHLE(Kernel::HLERequestContext& ctx, Ioctl command,
                          const std::vector<u8>& input, std::vector<u8>& output) {
    switch (static_cast<IoctlCommand>(command.raw)) {
    case IoctlCommand::IocCtrlEventWaitCommand:
        return IocCtrlEventWait(ctx, input, output, false);
    case IoctlCommand::IocCtrlEventWaitAsyncCommand:
        return IocCtrlEventWait(ctx, input, output, true);
    }
    UNIMPLEMENTED_MSG("Unimplemented ioctl");
    return 0;
}

u32 nvhost_ctrl::NvOsGetConfigU32(const std::vector<u8>& input, std::vector<u8>& output) {
    IocGetConfigParams params{};
    std::memcpy(&params, input.data(), sizeof(params));
    LOG_TRACE(Service_NVDRV, "called, setting={}!{}", params.domain_str.data(),
              params.param_str.data());
    return 0x30006; // Returns error on production mode
}

enum class NvResult : s32 {
    Success = 0,
    TryAgain = -11,
};

u32 nvhost_ctrl::IocCtrlEventWait(Kernel::HLERequestContext& ctx, const std::vector<u8>& input,
                                  std::vector<u8>& output, bool is_async) {
    IocCtrlEventWaitParams params{};
    std::memcpy(&params, input.data(), sizeof(params));
    LOG_WARNING(Service_NVDRV,
                "(STUBBED) called, syncpt_id={}, threshold={}, timeout={}, is_async={}",
                params.syncpt_id, params.threshold, params.timeout, is_async);

    // TODO(Subv): Implement actual syncpt waiting.
    params.value = 0;
    std::memcpy(output.data(), &params, sizeof(params));
    IPC::ResponseBuilder rb{ctx, 3};
    rb.Push(RESULT_SUCCESS);
    rb.Push(static_cast<u32>(NvResult::Success));

    ctx.WriteBuffer(output);
    return 0;
}

u32 nvhost_ctrl::IocCtrlEventRegister(const std::vector<u8>& input, std::vector<u8>& output) {
    LOG_WARNING(Service_NVDRV, "(STUBBED) called");
    // TODO(bunnei): Implement this.
    return 0;
}

} // namespace Service::Nvidia::Devices
