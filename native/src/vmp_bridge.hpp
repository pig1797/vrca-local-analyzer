#pragma once

// This project deliberately compiles with no-op markers until a VMProtect
// Company license is installed.  Enabling VRC_ENABLE_VMPROTECT switches these
// macros to the official SDK without changing protected function bodies.
#if defined(VRC_ENABLE_VMPROTECT)
#include <VMProtectSDK.h>
#define VRC_VMP_BEGIN_ULTRA(name) VMProtectBeginUltra(name)
#define VRC_VMP_BEGIN_VIRTUAL(name) VMProtectBeginVirtualization(name)
#define VRC_VMP_BEGIN_MUTATION(name) VMProtectBeginMutation(name)
#define VRC_VMP_BEGIN_LOCKED(name) VMProtectBeginUltraLockByKey(name)
#define VRC_VMP_SET_SERIAL(serial) VMProtectSetSerialNumber(serial)
#define VRC_VMP_GET_SERIAL_DATA(data, size) VMProtectGetSerialNumberData(data, size)
#define VRC_VMP_GET_CURRENT_HWID(data, size) VMProtectGetCurrentHWID(data, size)
#define VRC_VMP_END() VMProtectEnd()
#else
#define VRC_VMP_BEGIN_ULTRA(name) do { (void)sizeof(name); } while (0)
#define VRC_VMP_BEGIN_VIRTUAL(name) do { (void)sizeof(name); } while (0)
#define VRC_VMP_BEGIN_MUTATION(name) do { (void)sizeof(name); } while (0)
#define VRC_VMP_BEGIN_LOCKED(name) do { (void)sizeof(name); } while (0)
#define VRC_VMP_SET_SERIAL(serial) (static_cast<void>(serial), 0)
#define VRC_VMP_GET_SERIAL_DATA(data, size) (static_cast<void>(data), static_cast<void>(size), false)
#define VRC_VMP_GET_CURRENT_HWID(data, size) (static_cast<void>(data), static_cast<void>(size), 0)
#define VRC_VMP_END() do {} while (0)
#endif
