// Copyright 2019 yuzu emulator team
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "common/logging/log.h"
#include "core/core.h"
#include "core/core_timing.h"
#include "core/core_timing_util.h"
#include "core/hardware_properties.h"
#include "core/hle/ipc_helpers.h"
#include "core/hle/kernel/client_port.h"
#include "core/hle/kernel/client_session.h"
#include "core/hle/kernel/scheduler.h"
#include "core/hle/service/time/interface.h"
#include "core/hle/service/time/time.h"
#include "core/hle/service/time/time_sharedmemory.h"
#include "core/hle/service/time/time_zone_service.h"

namespace Service::Time {

class ISystemClock final : public ServiceFramework<ISystemClock> {
public:
    ISystemClock(Clock::SystemClockCore& clock_core)
        : ServiceFramework("ISystemClock"), clock_core{clock_core} {
        // clang-format off
        static const FunctionInfo functions[] = {
            {0, &ISystemClock::GetCurrentTime, "GetCurrentTime"},
            {1, nullptr, "SetCurrentTime"},
            {2,  &ISystemClock::GetSystemClockContext, "GetSystemClockContext"},
            {3, nullptr, "SetSystemClockContext"},
            {4, nullptr, "GetOperationEventReadableHandle"},
        };
        // clang-format on

        RegisterHandlers(functions);
    }

private:
    void GetCurrentTime(Kernel::HLERequestContext& ctx) {
        LOG_DEBUG(Service_Time, "called");

        if (!clock_core.IsInitialized()) {
            IPC::ResponseBuilder rb{ctx, 2};
            rb.Push(ERROR_UNINITIALIZED_CLOCK);
            return;
        }

        s64 posix_time{};
        if (const ResultCode result{
                clock_core.GetCurrentTime(Core::System::GetInstance(), posix_time)};
            result != RESULT_SUCCESS) {
            IPC::ResponseBuilder rb{ctx, 2};
            rb.Push(result);
            return;
        }

        IPC::ResponseBuilder rb{ctx, 4};
        rb.Push(RESULT_SUCCESS);
        rb.Push<s64>(posix_time);
    }

    void GetSystemClockContext(Kernel::HLERequestContext& ctx) {
        LOG_DEBUG(Service_Time, "called");

        if (!clock_core.IsInitialized()) {
            IPC::ResponseBuilder rb{ctx, 2};
            rb.Push(ERROR_UNINITIALIZED_CLOCK);
            return;
        }

        Clock::SystemClockContext system_clock_context{};
        if (const ResultCode result{
                clock_core.GetClockContext(Core::System::GetInstance(), system_clock_context)};
            result != RESULT_SUCCESS) {
            IPC::ResponseBuilder rb{ctx, 2};
            rb.Push(result);
            return;
        }

        IPC::ResponseBuilder rb{ctx, sizeof(Clock::SystemClockContext) / 4 + 2};
        rb.Push(RESULT_SUCCESS);
        rb.PushRaw(system_clock_context);
    }

    Clock::SystemClockCore& clock_core;
};

class ISteadyClock final : public ServiceFramework<ISteadyClock> {
public:
    ISteadyClock(Clock::SteadyClockCore& clock_core)
        : ServiceFramework("ISteadyClock"), clock_core{clock_core} {
        static const FunctionInfo functions[] = {
            {0, &ISteadyClock::GetCurrentTimePoint, "GetCurrentTimePoint"},
        };
        RegisterHandlers(functions);
    }

private:
    void GetCurrentTimePoint(Kernel::HLERequestContext& ctx) {
        LOG_DEBUG(Service_Time, "called");

        if (!clock_core.IsInitialized()) {
            IPC::ResponseBuilder rb{ctx, 2};
            rb.Push(ERROR_UNINITIALIZED_CLOCK);
            return;
        }

        const Clock::SteadyClockTimePoint time_point{
            clock_core.GetCurrentTimePoint(Core::System::GetInstance())};
        IPC::ResponseBuilder rb{ctx, (sizeof(Clock::SteadyClockTimePoint) / 4) + 2};
        rb.Push(RESULT_SUCCESS);
        rb.PushRaw(time_point);
    }

    Clock::SteadyClockCore& clock_core;
};

ResultCode Module::Interface::GetClockSnapshotFromSystemClockContextInternal(
    Kernel::Thread* thread, Clock::SystemClockContext user_context,
    Clock::SystemClockContext network_context, u8 type, Clock::ClockSnapshot& clock_snapshot) {

    auto& time_manager{module->GetTimeManager()};

    clock_snapshot.is_automatic_correction_enabled =
        time_manager.GetStandardUserSystemClockCore().IsAutomaticCorrectionEnabled();
    clock_snapshot.user_context = user_context;
    clock_snapshot.network_context = network_context;

    if (const ResultCode result{
            time_manager.GetTimeZoneContentManager().GetTimeZoneManager().GetDeviceLocationName(
                clock_snapshot.location_name)};
        result != RESULT_SUCCESS) {
        return result;
    }

    const auto current_time_point{
        time_manager.GetStandardSteadyClockCore().GetCurrentTimePoint(Core::System::GetInstance())};
    if (const ResultCode result{Clock::ClockSnapshot::GetCurrentTime(
            clock_snapshot.user_time, current_time_point, clock_snapshot.user_context)};
        result != RESULT_SUCCESS) {
        return result;
    }

    TimeZone::CalendarInfo userCalendarInfo{};
    if (const ResultCode result{
            time_manager.GetTimeZoneContentManager().GetTimeZoneManager().ToCalendarTimeWithMyRules(
                clock_snapshot.user_time, userCalendarInfo)};
        result != RESULT_SUCCESS) {
        return result;
    }

    clock_snapshot.user_calendar_time = userCalendarInfo.time;
    clock_snapshot.user_calendar_additional_time = userCalendarInfo.additiona_info;

    if (Clock::ClockSnapshot::GetCurrentTime(clock_snapshot.network_time, current_time_point,
                                             clock_snapshot.network_context) != RESULT_SUCCESS) {
        clock_snapshot.network_time = 0;
    }

    TimeZone::CalendarInfo networkCalendarInfo{};
    if (const ResultCode result{
            time_manager.GetTimeZoneContentManager().GetTimeZoneManager().ToCalendarTimeWithMyRules(
                clock_snapshot.network_time, networkCalendarInfo)};
        result != RESULT_SUCCESS) {
        return result;
    }

    clock_snapshot.network_calendar_time = networkCalendarInfo.time;
    clock_snapshot.network_calendar_additional_time = networkCalendarInfo.additiona_info;
    clock_snapshot.type = type;

    return RESULT_SUCCESS;
}

void Module::Interface::GetStandardUserSystemClock(Kernel::HLERequestContext& ctx) {
    LOG_DEBUG(Service_Time, "called");
    IPC::ResponseBuilder rb{ctx, 2, 0, 1};
    rb.Push(RESULT_SUCCESS);
    rb.PushIpcInterface<ISystemClock>(module->GetTimeManager().GetStandardUserSystemClockCore());
}

void Module::Interface::GetStandardNetworkSystemClock(Kernel::HLERequestContext& ctx) {
    LOG_DEBUG(Service_Time, "called");
    IPC::ResponseBuilder rb{ctx, 2, 0, 1};
    rb.Push(RESULT_SUCCESS);
    rb.PushIpcInterface<ISystemClock>(module->GetTimeManager().GetStandardNetworkSystemClockCore());
}

void Module::Interface::GetStandardSteadyClock(Kernel::HLERequestContext& ctx) {
    LOG_DEBUG(Service_Time, "called");
    IPC::ResponseBuilder rb{ctx, 2, 0, 1};
    rb.Push(RESULT_SUCCESS);
    rb.PushIpcInterface<ISteadyClock>(module->GetTimeManager().GetStandardSteadyClockCore());
}

void Module::Interface::GetTimeZoneService(Kernel::HLERequestContext& ctx) {
    LOG_DEBUG(Service_Time, "called");
    IPC::ResponseBuilder rb{ctx, 2, 0, 1};
    rb.Push(RESULT_SUCCESS);
    rb.PushIpcInterface<ITimeZoneService>(module->GetTimeManager().GetTimeZoneContentManager());
}

void Module::Interface::GetStandardLocalSystemClock(Kernel::HLERequestContext& ctx) {
    LOG_DEBUG(Service_Time, "called");
    IPC::ResponseBuilder rb{ctx, 2, 0, 1};
    rb.Push(RESULT_SUCCESS);
    rb.PushIpcInterface<ISystemClock>(module->GetTimeManager().GetStandardLocalSystemClockCore());
}

void Module::Interface::IsStandardNetworkSystemClockAccuracySufficient(
    Kernel::HLERequestContext& ctx) {
    LOG_DEBUG(Service_Time, "called");
    auto& clock_core{module->GetTimeManager().GetStandardNetworkSystemClockCore()};
    IPC::ResponseBuilder rb{ctx, 3};
    rb.Push(RESULT_SUCCESS);
    rb.Push<u32>(clock_core.IsStandardNetworkSystemClockAccuracySufficient(system));
}

void Module::Interface::CalculateMonotonicSystemClockBaseTimePoint(Kernel::HLERequestContext& ctx) {
    LOG_DEBUG(Service_Time, "called");

    auto& steady_clock_core{module->GetTimeManager().GetStandardSteadyClockCore()};
    if (!steady_clock_core.IsInitialized()) {
        IPC::ResponseBuilder rb{ctx, 2};
        rb.Push(ERROR_UNINITIALIZED_CLOCK);
        return;
    }

    IPC::RequestParser rp{ctx};
    const auto context{rp.PopRaw<Clock::SystemClockContext>()};
    const auto current_time_point{
        steady_clock_core.GetCurrentTimePoint(Core::System::GetInstance())};

    if (current_time_point.clock_source_id == context.steady_time_point.clock_source_id) {
        const auto ticks{Clock::TimeSpanType::FromTicks(system.CoreTiming().GetClockTicks(),
                                                        Core::Hardware::CNTFREQ)};
        const s64 base_time_point{context.offset + current_time_point.time_point -
                                  ticks.ToSeconds()};
        IPC::ResponseBuilder rb{ctx, (sizeof(s64) / 4) + 2};
        rb.Push(RESULT_SUCCESS);
        rb.PushRaw(base_time_point);
        return;
    }

    IPC::ResponseBuilder rb{ctx, 2};
    rb.Push(ERROR_TIME_MISMATCH);
}

void Module::Interface::GetClockSnapshot(Kernel::HLERequestContext& ctx) {
    LOG_DEBUG(Service_Time, "called");
    IPC::RequestParser rp{ctx};
    const auto type{rp.PopRaw<u8>()};

    Clock::SystemClockContext user_context{};
    if (const ResultCode result{
            module->GetTimeManager().GetStandardUserSystemClockCore().GetClockContext(
                Core::System::GetInstance(), user_context)};
        result != RESULT_SUCCESS) {
        IPC::ResponseBuilder rb{ctx, 2};
        rb.Push(result);
        return;
    }
    Clock::SystemClockContext network_context{};
    if (const ResultCode result{
            module->GetTimeManager().GetStandardNetworkSystemClockCore().GetClockContext(
                Core::System::GetInstance(), network_context)};
        result != RESULT_SUCCESS) {
        IPC::ResponseBuilder rb{ctx, 2};
        rb.Push(result);
        return;
    }

    Clock::ClockSnapshot clock_snapshot{};
    if (const ResultCode result{GetClockSnapshotFromSystemClockContextInternal(
            &ctx.GetThread(), user_context, network_context, type, clock_snapshot)};
        result != RESULT_SUCCESS) {
        IPC::ResponseBuilder rb{ctx, 2};
        rb.Push(result);
        return;
    }

    IPC::ResponseBuilder rb{ctx, 2};
    rb.Push(RESULT_SUCCESS);
    ctx.WriteBuffer(&clock_snapshot, sizeof(Clock::ClockSnapshot));
}

void Module::Interface::GetClockSnapshotFromSystemClockContext(Kernel::HLERequestContext& ctx) {
    LOG_DEBUG(Service_Time, "called");
    IPC::RequestParser rp{ctx};
    const auto type{rp.PopRaw<u8>()};
    rp.AlignWithPadding();

    const Clock::SystemClockContext user_context{rp.PopRaw<Clock::SystemClockContext>()};
    const Clock::SystemClockContext network_context{rp.PopRaw<Clock::SystemClockContext>()};

    Clock::ClockSnapshot clock_snapshot{};
    if (const ResultCode result{GetClockSnapshotFromSystemClockContextInternal(
            &ctx.GetThread(), user_context, network_context, type, clock_snapshot)};
        result != RESULT_SUCCESS) {
        IPC::ResponseBuilder rb{ctx, 2};
        rb.Push(result);
        return;
    }

    IPC::ResponseBuilder rb{ctx, 2};
    rb.Push(RESULT_SUCCESS);
    ctx.WriteBuffer(&clock_snapshot, sizeof(Clock::ClockSnapshot));
}

void Module::Interface::GetSharedMemoryNativeHandle(Kernel::HLERequestContext& ctx) {
    LOG_DEBUG(Service_Time, "called");
    IPC::ResponseBuilder rb{ctx, 2, 1};
    rb.Push(RESULT_SUCCESS);
    rb.PushCopyObjects(module->GetTimeManager().GetSharedMemory().GetSharedMemoryHolder());
}

Module::Interface::Interface(std::shared_ptr<Module> module, Core::System& system, const char* name)
    : ServiceFramework(name), module{std::move(module)}, system{system} {}

Module::Interface::~Interface() = default;

void InstallInterfaces(Core::System& system) {
    auto module{std::make_shared<Module>(system)};
    std::make_shared<Time>(module, system, "time:a")->InstallAsService(system.ServiceManager());
    std::make_shared<Time>(module, system, "time:s")->InstallAsService(system.ServiceManager());
    std::make_shared<Time>(module, system, "time:u")->InstallAsService(system.ServiceManager());
}

} // namespace Service::Time
