#pragma once
/*
 * host_umdf2.h — WDF v2 host-side binding, stub function table, and internal types
 *
 * Provides everything needed to host a UMDF v2 driver DLL (one that exports
 * FxDriverEntryUm) without needing WUDFx02000.dll or the real WDF framework.
 *
 * Protocol (from Ghidra decompile of Goodix Wbdi.dll):
 *  1. Host builds WUDF_LOADER_INTERFACE (size >= 0x38).
 *  2. Host calls: FxDriverEntryUm(loaderIface, hostVersionBind, NULL, NULL)
 *  3. Driver stub calls: hostVersionBind(&WDF_BIND_INFO, &WdfDriverGlobals_ptr)
 *     → We fill *FuncTable = g_wdf2Table and *ComponentGlobals = &g_wdf2Globals
 *  4. Driver's DriverEntry() calls WdfDriverCreate → stored in g_wdf2Driver
 *  5. Host calls: g_wdf2Driver->evtDeviceAdd(driver, new Wdf2DeviceInit)
 *  6. Driver calls WdfDeviceCreate, WdfIoQueueCreate, etc. → stubs store state
 *  7. Host exercises device via g_wdf2Queue->evtIoDeviceControl (Wdf2Request wrapper)
 *
 * Struct layouts derived from:
 *  - ReactOS fxldr.h (WDF_BIND_INFO, WDF_LOADER_INTERFACE)
 *  - Ghidra decompile of Wbdi.dll FxDriverEntryUm  (WUDF_LOADER_INTERFACE extension)
 *  - WDK include wdk-include/wdf/umdf/2.15/ headers (callback structs and indices)
 *
 * NOT included: wdf.h or any WDF v2 public header (would conflict with v1 headers).
 */

#include <cstdlib>
#include <cstring>

// ---------------------------------------------------------------------------
// WDF2 trace log — level controlled from hello.cc via g_umdf2_loglevel:
//   0 = silent (default), 1 = all named stub calls, 2 = detailed parameters
// ---------------------------------------------------------------------------
static int g_umdf2_loglevel = 0;
#define WDF2_LOG(lvl, ...) \
    do { if (g_umdf2_loglevel >= (lvl)) { fprintf(stderr, __VA_ARGS__); fflush(stderr); } } while(0)

// -----------------------------------------------------------------------
// WDFFUNC type (void function pointer, cast at call sites)
// -----------------------------------------------------------------------
typedef void (*WDFFUNC)(void);

// -----------------------------------------------------------------------
// Minimal WDF v2 types (avoids including conflicting wdf.h v2 headers)
// -----------------------------------------------------------------------

// WDF_VERSION (from fxldr.h: {Major, Minor, Build})
typedef struct _WDF2_VERSION {
    ULONG Major;
    ULONG Minor;
    ULONG Build;
} WDF2_VERSION;

// WDF_BIND_INFO embedded in driver DLL .data — layout on 64-bit:
//   +0x00: Size (ULONG = sizeof WDF_BIND_INFO = 0x30)
//   +0x04: _pad04
//   +0x08: Component (PWCHAR, e.g. L"UMDF")
//   +0x10: Version.Major (ULONG), +0x14: Minor, +0x18: Build
//   +0x1C: FuncCount (ULONG, e.g. 257)
//   +0x20: FuncTable (WDFFUNC* = &WdfFunctions_02015 in driver; versionBind sets *FuncTable = our table)
//   +0x28: Module (void* = NULL, management only)
typedef struct _WDF2_BIND_INFO {
    ULONG        Size;        // +0x00
    ULONG        _pad04;      // +0x04
    PWCHAR       Component;   // +0x08
    WDF2_VERSION Version;     // +0x10
    ULONG        FuncCount;   // +0x1C
    WDFFUNC     *FuncTable;   // +0x20: &WdfFunctions_02015 in driver DLL
    void        *Module;      // +0x28: NULL
} WDF2_BIND_INFO;             // Total: 0x30

// VersionBind function pointer type (2-arg UMDF variant; KMDF uses 4 args)
typedef NTSTATUS (*PWDF2_VERSION_BIND)(WDF2_BIND_INFO *bindInfo,
                                       void          **ppComponentGlobals);

// WUDF_LOADER_INTERFACE (param_1 to FxDriverEntryUm) — extends WDF_LOADER_INTERFACE:
//   WDF_INTERFACE_HEADER:
//     +0x00: Size/InterfaceSize (ULONG; must be >= 0x38)
//     +0x04: _pad04
//     +0x08: BindClient (function ptr — NOT a GUID! Disassembly of Wbdi.dll
//            FxDriverEntryUm shows: mov [rbx+0x08],%rax; call [thunk=jmp *rax]
//            called as: BindClient(param_2, &WDF_BIND_INFO, &WdfDriverGlobals))
//   WDF_LOADER_INTERFACE body:
//     +0x10: RegisterLibrary (function ptr, NULL = unused)
//     +0x18: VersionBind (function ptr, stored in loaderIface but also passed as param_2)
//     +0x20: VersionUnbind (function ptr, NULL = unused)
//     +0x28: Diagnostics (function ptr; driver stores as internal global, can be NULL)
//   UMDF extension:
//     +0x30: Flags (ULONG; bit 0 = verbose debug logging in driver)
//     +0x34: _pad34
typedef struct _WUDF_LOADER_INTERFACE {
    ULONG   Size;            // +0x00: must be >= 0x38
    ULONG   _pad04;          // +0x04
    void   *BindClient;      // +0x08: called as BindClient(versionBind, bindInfo, ppGlobals)
    void   *RegisterLibrary; // +0x10: NULL
    void   *VersionBind;     // +0x18: PWDF2_VERSION_BIND (also passed as param_2)
    void   *VersionUnbind;   // +0x20: NULL
    void   *Diagnostics;     // +0x28: NULL (stored by driver; can be NULL)
    ULONG   Flags;           // +0x30: 0
    ULONG   _pad34;          // +0x34
} WUDF_LOADER_INTERFACE;     // Total: 0x38

// FxDriverEntryUm signature (exported by UMDF v2 driver DLL)
typedef NTSTATUS (*PFN_FxDriverEntryUm)(
    WUDF_LOADER_INTERFACE *loaderIface,  // param_1
    void                  *versionBind,  // param_2: called as versionBind(bindInfo, &globals)
    void                  *driverObject, // param_3: NULL for user-mode context
    void                  *registryPath  // param_4: NULL
);

// WDF_DRIVER_GLOBALS (from wdfglobals.h) — minimal
typedef struct _WDF2_DRIVER_GLOBALS {
    void  *Driver;                // WDFDRIVER handle
    ULONG  DriverFlags;
    ULONG  DriverTag;
    char   DriverName[32];
    BOOL   DisplaceDriverUnload;
} WDF2_DRIVER_GLOBALS;

// -----------------------------------------------------------------------
// WDF callback typedefs (no wdf.h needed — use void* for handles)
// -----------------------------------------------------------------------
typedef NTSTATUS (*Wdf2_EvtDriverDeviceAdd)(void *driver, void *deviceInit);
typedef NTSTATUS (*Wdf2_EvtDevicePrepareHw)(void *device, void *rawRes, void *translatedRes);
typedef NTSTATUS (*Wdf2_EvtDeviceReleaseHw)(void *device, void *translatedRes);
typedef NTSTATUS (*Wdf2_EvtDeviceD0Entry)(void *device, int prevState);
typedef NTSTATUS (*Wdf2_EvtDeviceD0Exit)(void *device, int targetState);
typedef void     (*Wdf2_EvtIoDeviceControl)(void *queue, void *request,
                                             size_t outLen, size_t inLen, ULONG ioctl);
typedef void     (*Wdf2_EvtDriverUnload)(void *driver);

// -----------------------------------------------------------------------
// Internal Wdf2* types — host-side representations of WDF objects
// -----------------------------------------------------------------------

struct Wdf2Obj {
    void   *context;   // allocated context block (from WDF_OBJECT_ATTRIBUTES)
    size_t  ctxSize;
    Wdf2Obj() : context(nullptr), ctxSize(0) {}
    ~Wdf2Obj() { free(context); context = nullptr; }

    // Allocate context from WDF_OBJECT_ATTRIBUTES (layout from wdfobject.h):
    //   +0x00 Size, +0x08 EvtCleanup, +0x10 EvtDestroy,
    //   +0x18 ExecutionLevel, +0x1C SynchronizationScope,
    //   +0x20 ParentObject, +0x28 ContextSizeOverride, +0x30 ContextTypeInfo
    // WDF_OBJECT_CONTEXT_TYPE_INFO:
    //   +0x00 Size, +0x08 ContextName (LPCSTR), +0x10 ContextSize (size_t)
    void allocContext(void *attrs) {
        if (!attrs || context) return;
        void    *typeInfo = *(void**)((char*)attrs + 0x30);
        size_t   ctxSz    = typeInfo ? *(size_t*)((char*)typeInfo + 0x10) : 0;
        size_t   override = *(size_t*)((char*)attrs + 0x28);
        if (override) ctxSz = override;
        if (ctxSz) {
            context = calloc(1, ctxSz);
            ctxSize = ctxSz;
        }
    }
};

struct Wdf2Queue;

struct Wdf2Driver : Wdf2Obj {
    Wdf2_EvtDriverDeviceAdd evtDeviceAdd;
    Wdf2_EvtDriverUnload    evtUnload;
    Wdf2Driver() : evtDeviceAdd(nullptr), evtUnload(nullptr) {}
};

// WDF_PNPPOWER_EVENT_CALLBACKS field offsets (from wdfdevice.h, 64-bit):
//   +0x00: Size, +0x08: EvtDeviceD0Entry, +0x18: EvtDeviceD0Exit,
//   +0x28: EvtDevicePrepareHardware, +0x30: EvtDeviceReleaseHardware
struct Wdf2DeviceInit : Wdf2Obj {
    char pnpPowerCbs[0x100];  // WDF_PNPPOWER_EVENT_CALLBACKS (max ~0x90 bytes)
    char powerPolicyCbs[0x80]; // WDF_POWER_POLICY_EVENT_CALLBACKS
    BOOL powerPolicyOwner;

    Wdf2DeviceInit() : powerPolicyOwner(FALSE) {
        memset(pnpPowerCbs, 0, sizeof(pnpPowerCbs));
        memset(powerPolicyCbs, 0, sizeof(powerPolicyCbs));
    }

    Wdf2_EvtDevicePrepareHw EvtPrepareHw() const {
        return *(Wdf2_EvtDevicePrepareHw*)(pnpPowerCbs + 0x28);
    }
    Wdf2_EvtDeviceReleaseHw EvtReleaseHw() const {
        return *(Wdf2_EvtDeviceReleaseHw*)(pnpPowerCbs + 0x30);
    }
    Wdf2_EvtDeviceD0Entry EvtD0Entry() const {
        return *(Wdf2_EvtDeviceD0Entry*)(pnpPowerCbs + 0x08);
    }
    Wdf2_EvtDeviceD0Exit EvtD0Exit() const {
        return *(Wdf2_EvtDeviceD0Exit*)(pnpPowerCbs + 0x18);
    }
};

struct Wdf2Device : Wdf2Obj {
    Wdf2Driver     *driver;
    Wdf2DeviceInit *init;
    Wdf2Queue      *queue;  // first queue created (typically the default IO queue)

    Wdf2Device() : driver(nullptr), init(nullptr), queue(nullptr) {}

    Wdf2_EvtDevicePrepareHw EvtPrepareHw() const { return init ? init->EvtPrepareHw() : nullptr; }
    Wdf2_EvtDeviceReleaseHw EvtReleaseHw() const { return init ? init->EvtReleaseHw() : nullptr; }
    Wdf2_EvtDeviceD0Entry   EvtD0Entry()   const { return init ? init->EvtD0Entry()   : nullptr; }
    Wdf2_EvtDeviceD0Exit    EvtD0Exit()    const { return init ? init->EvtD0Exit()    : nullptr; }
};

struct Wdf2Memory : Wdf2Obj {
    void   *buf;
    size_t  size;
    bool    owner;   // if true, free buf on destruction

    Wdf2Memory() : buf(nullptr), size(0), owner(false) {}
    ~Wdf2Memory() { if (owner && buf) { free(buf); buf = nullptr; } }
};

struct Wdf2Request : Wdf2Obj {
    ULONG       ioctlCode;
    Wdf2Memory *inMem;
    Wdf2Memory *outMem;
    NTSTATUS    status;
    ULONG_PTR   information;
    bool        completed;
    Wdf2Queue  *queue;

    Wdf2Request()
        : ioctlCode(0), inMem(nullptr), outMem(nullptr),
          status(0), information(0), completed(false), queue(nullptr) {}
    ~Wdf2Request() { delete inMem; delete outMem; }
};

struct Wdf2Queue : Wdf2Obj {
    Wdf2Device             *device;
    Wdf2_EvtIoDeviceControl evtIoDeviceControl;

    Wdf2Queue() : device(nullptr), evtIoDeviceControl(nullptr) {}
};

// -----------------------------------------------------------------------
// Globals
// -----------------------------------------------------------------------

static WDF2_DRIVER_GLOBALS g_wdf2Globals;
static Wdf2Driver         *g_wdf2Driver  = nullptr;
static Wdf2Device         *g_wdf2Device  = nullptr;
static Wdf2Queue          *g_wdf2Queue   = nullptr;
static WDFFUNC             g_wdf2Table[257];

// -----------------------------------------------------------------------
// WDF stub implementations
// ALL stubs: first arg = WDF_DRIVER_GLOBALS* (always ignored in our host).
// Struct offsets verified against wdk-include/wdf/umdf/2.15/ headers.
// HLOG_USER is redirected to WDF2_LOG(1,...) for the duration of this file
// so all existing HLOG_USER calls become level-1 trace output.
// -----------------------------------------------------------------------
#pragma push_macro("HLOG_USER")
#undef HLOG_USER
#define HLOG_USER(...) WDF2_LOG(1, __VA_ARGS__)

// --- WdfDriverCreate (index 57) ---
// WDF_DRIVER_CONFIG layout (64-bit):
//   +0x00: Size, +0x08: EvtDriverDeviceAdd, +0x10: EvtDriverUnload,
//   +0x18: DriverInitFlags, +0x1C: DriverPoolTag
static NTSTATUS WINAPI
stub_WdfDriverCreate(void *globals, void *drvObj, void *regPath,
                     void *drvAttrs, void *drvConfig, void **pDriver)
{
    HLOG_USER("[WDF2] WdfDriverCreate: config=%p attrs=%p\n", drvConfig, drvAttrs);
    if (drvConfig)
        HLOG_USER("[WDF2]   config.Size=0x%lx\n", (unsigned long)*(ULONG*)drvConfig);

    g_wdf2Driver = new Wdf2Driver();
    g_wdf2Driver->allocContext(drvAttrs);
    if (drvConfig) {
        g_wdf2Driver->evtDeviceAdd = *(Wdf2_EvtDriverDeviceAdd*)((char*)drvConfig + 0x08);
        g_wdf2Driver->evtUnload    = *(Wdf2_EvtDriverUnload*)    ((char*)drvConfig + 0x10);
    }
    g_wdf2Globals.Driver = g_wdf2Driver;
    if (pDriver) *pDriver = g_wdf2Driver;
    HLOG_USER("[WDF2]   EvtDriverDeviceAdd=%p\n", (void*)g_wdf2Driver->evtDeviceAdd);
    return 0;
}

// --- WdfDeviceInitSetPnpPowerEventCallbacks (index 19) ---
static void WINAPI
stub_WdfDeviceInitSetPnpPowerEventCallbacks(void *globals, void *devInit, void *cbs)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetPnpPowerEventCallbacks\n");
    auto *di = (Wdf2DeviceInit*)devInit;
    if (di && cbs) {
        ULONG sz = *(ULONG*)cbs;
        if (sz > (ULONG)sizeof(di->pnpPowerCbs)) sz = (ULONG)sizeof(di->pnpPowerCbs);
        memcpy(di->pnpPowerCbs, cbs, sz);
    }
}

// --- WdfDeviceInitSetPowerPolicyEventCallbacks (index 20) ---
static void WINAPI
stub_WdfDeviceInitSetPowerPolicyEventCallbacks(void *globals, void *devInit, void *cbs)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetPowerPolicyEventCallbacks\n");
    auto *di = (Wdf2DeviceInit*)devInit;
    if (di && cbs) {
        ULONG sz = *(ULONG*)cbs;
        if (sz > (ULONG)sizeof(di->powerPolicyCbs)) sz = (ULONG)sizeof(di->powerPolicyCbs);
        memcpy(di->powerPolicyCbs, cbs, sz);
    }
}

// --- WdfDeviceInitSetPowerPolicyOwnership (index 21) ---
static void WINAPI
stub_WdfDeviceInitSetPowerPolicyOwnership(void *globals, void *devInit, BOOL owner)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetPowerPolicyOwnership(%d)\n", owner);
    auto *di = (Wdf2DeviceInit*)devInit;
    if (di) di->powerPolicyOwner = owner;
}

// --- WdfDeviceInitSetIoType (index 22) --- no-op
static void WINAPI
stub_WdfDeviceInitSetIoType(void *globals, void *devInit, int ioType)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetIoType(%d) no-op\n", ioType);
}

// --- WdfDeviceInitSetFileObjectConfig (index 23) --- no-op
static void WINAPI
stub_WdfDeviceInitSetFileObjectConfig(void *globals, void *devInit, void *cfg, void *attrs)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetFileObjectConfig no-op\n");
}

// --- WdfDeviceInitSetRequestAttributes (index 24) --- no-op
static void WINAPI
stub_WdfDeviceInitSetRequestAttributes(void *globals, void *devInit, void *attrs)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetRequestAttributes no-op\n");
}

// --- WdfDeviceInitSetIoTypeEx (index 43) --- no-op
static void WINAPI
stub_WdfDeviceInitSetIoTypeEx(void *globals, void *devInit, void *cfg)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetIoTypeEx no-op\n");
}

// --- WdfDeviceCreate (index 25) ---
// WDF_OBJECT_ATTRIBUTES layout (64-bit):
//   +0x00 Size, +0x08 EvtCleanup, +0x10 EvtDestroy,
//   +0x18 ExecutionLevel, +0x1C SynchronizationScope,
//   +0x20 ParentObject, +0x28 ContextSizeOverride, +0x30 ContextTypeInfo
static NTSTATUS WINAPI
stub_WdfDeviceCreate(void *globals, void **ppDevInit, void *devAttrs, void **pDevice)
{
    HLOG_USER("[WDF2] WdfDeviceCreate\n");
    auto *di = ppDevInit ? (Wdf2DeviceInit*)*ppDevInit : nullptr;

    g_wdf2Device = new Wdf2Device();
    g_wdf2Device->driver = g_wdf2Driver;
    g_wdf2Device->init   = di;
    g_wdf2Device->allocContext(devAttrs);

    if (ppDevInit) *ppDevInit = nullptr; // "consumed" by the framework
    if (pDevice)   *pDevice   = g_wdf2Device;
    return 0;
}

// --- WdfDeviceSetStaticStopRemove (index 26) --- no-op
static void WINAPI
stub_WdfDeviceSetStaticStopRemove(void *globals, void *device, BOOL value)
{
    HLOG_USER("[WDF2] WdfDeviceSetStaticStopRemove no-op\n");
}

// --- WdfDeviceCreateDeviceInterface (index 27) --- no-op
static NTSTATUS WINAPI
stub_WdfDeviceCreateDeviceInterface(void *globals, void *device, void *guid, void *refStr)
{
    HLOG_USER("[WDF2] WdfDeviceCreateDeviceInterface no-op\n");
    return 0;
}

// --- WdfDeviceSetDeviceInterfaceState (index 28) --- no-op
static void WINAPI
stub_WdfDeviceSetDeviceInterfaceState(void *globals, void *device, void *guid,
                                      void *refStr, BOOL enable)
{
    HLOG_USER("[WDF2] WdfDeviceSetDeviceInterfaceState(%d) no-op\n", enable);
}

// --- WdfDeviceQueryProperty (index 31) --- return STATUS_NOT_FOUND
static NTSTATUS WINAPI
stub_WdfDeviceQueryProperty(void *globals, void *device, int prop, ULONG bufSz,
                             void *buf, ULONG *pLen)
{
    HLOG_USER("[WDF2] WdfDeviceQueryProperty no-op\n");
    return 0xC0000225L; // STATUS_NOT_FOUND
}

// --- WdfDeviceSetPnpCapabilities (index 33) --- no-op
static void WINAPI
stub_WdfDeviceSetPnpCapabilities(void *globals, void *device, void *caps)
{
    HLOG_USER("[WDF2] WdfDeviceSetPnpCapabilities no-op\n");
}

// --- WdfDeviceSetPowerCapabilities (index 34) --- no-op
static void WINAPI
stub_WdfDeviceSetPowerCapabilities(void *globals, void *device, void *caps)
{
    HLOG_USER("[WDF2] WdfDeviceSetPowerCapabilities no-op\n");
}

// --- WdfDeviceSetFailed (index 35) --- no-op
static void WINAPI
stub_WdfDeviceSetFailed(void *globals, void *device, int reason)
{
    HLOG_USER("[WDF2] WdfDeviceSetFailed(%d) no-op\n", reason);
}

// --- WdfDeviceStopIdleNoTrack (index 36) --- return success
static NTSTATUS WINAPI
stub_WdfDeviceStopIdleNoTrack(void *globals, void *device, BOOL waitForD0,
                               void *file, int line, const char *func)
{
    WDF2_LOG(2, "[WDF2] WdfDeviceStopIdleNoTrack\n");
    return 0;
}

// --- WdfDeviceResumeIdleNoTrack (index 37) --- no-op
static void WINAPI
stub_WdfDeviceResumeIdleNoTrack(void *globals, void *device,
                                 void *file, int line, const char *func)
{
    WDF2_LOG(2, "[WDF2] WdfDeviceResumeIdleNoTrack\n");
}

// --- WdfDeviceGetDefaultQueue (index 39) ---
static void* WINAPI
stub_WdfDeviceGetDefaultQueue(void *globals, void *device)
{
    auto *dev = (Wdf2Device*)device;
    void *q = dev ? dev->queue : nullptr;
    WDF2_LOG(2, "[WDF2] WdfDeviceGetDefaultQueue -> %p\n", q);
    return q;
}

// --- WdfDeviceGetSystemPowerAction (index 41) --- return PowerActionNone = 0
static int WINAPI
stub_WdfDeviceGetSystemPowerAction(void *globals, void *device)
{
    WDF2_LOG(2, "[WDF2] WdfDeviceGetSystemPowerAction -> 0 (PowerActionNone)\n");
    return 0;
}

// --- WdfDeviceSetDeviceState (index 13) --- no-op
static void WINAPI
stub_WdfDeviceSetDeviceState(void *globals, void *device, void *state)
{
    HLOG_USER("[WDF2] WdfDeviceSetDeviceState no-op\n");
}

// --- WdfDeviceGetDriver (index 14) ---
static void* WINAPI
stub_WdfDeviceGetDriver(void *globals, void *device)
{
    WDF2_LOG(2, "[WDF2] WdfDeviceGetDriver -> %p\n", (void*)g_wdf2Driver);
    return g_wdf2Driver;
}

// --- WdfDeviceOpenRegistryKey (index 18) ---
static NTSTATUS WINAPI
stub_WdfDeviceOpenRegistryKey(void *globals, void *device, ULONG devInstKeyType,
                               ULONG access, void *attrs, void **pKey)
{
    HLOG_USER("[WDF2] WdfDeviceOpenRegistryKey -> STATUS_OBJECT_NAME_NOT_FOUND\n");
    return 0xC0000034L; // STATUS_OBJECT_NAME_NOT_FOUND
}

// --- WdfDeviceAssignS0IdleSettings (index 16) --- return success
static NTSTATUS WINAPI
stub_WdfDeviceAssignS0IdleSettings(void *globals, void *device, void *settings)
{
    HLOG_USER("[WDF2] WdfDeviceAssignS0IdleSettings no-op\n");
    return 0;
}

// --- WdfDeviceAssignSxWakeSettings (index 17) --- return success
static NTSTATUS WINAPI
stub_WdfDeviceAssignSxWakeSettings(void *globals, void *device, void *settings)
{
    HLOG_USER("[WDF2] WdfDeviceAssignSxWakeSettings no-op\n");
    return 0;
}

// --- WdfDriverCreate table index 57; WdfDriverGetRegistryPath index 58 ---
static NTSTATUS WINAPI
stub_WdfDriverGetRegistryPath(void *globals, void *driver, void *string)
{
    HLOG_USER("[WDF2] WdfDriverGetRegistryPath -> empty\n");
    return 0;
}

// --- WdfDriverOpenParametersRegistryKey (index 59) ---
static NTSTATUS WINAPI
stub_WdfDriverOpenParametersRegistryKey(void *globals, void *driver, ULONG access,
                                         void *attrs, void **pKey)
{
    HLOG_USER("[WDF2] WdfDriverOpenParametersRegistryKey -> STATUS_OBJECT_NAME_NOT_FOUND\n");
    return 0xC0000034L;
}

// --- WdfIoQueueCreate (index 85) ---
// WDF_IO_QUEUE_CONFIG layout (64-bit):
//   +0x00 Size, +0x04 DispatchType, +0x08 PowerManaged,
//   +0x0C AllowZeroLengthRequests, +0x0D DefaultQueue,
//   +0x10 EvtIoDefault, +0x18 EvtIoRead, +0x20 EvtIoWrite,
//   +0x28 EvtIoDeviceControl, +0x30 EvtIoInternalDeviceControl,
//   +0x38 EvtIoStop, +0x40 EvtIoResume
static NTSTATUS WINAPI
stub_WdfIoQueueCreate(void *globals, void *device, void *config,
                      void *queueAttrs, void **pQueue)
{
    HLOG_USER("[WDF2] WdfIoQueueCreate\n");
    auto *q = new Wdf2Queue();
    q->device = (Wdf2Device*)device;
    q->allocContext(queueAttrs);
    if (config)
        q->evtIoDeviceControl = *(Wdf2_EvtIoDeviceControl*)((char*)config + 0x28);

    HLOG_USER("[WDF2]   EvtIoDeviceControl=%p\n", (void*)q->evtIoDeviceControl);

    if (device && !((Wdf2Device*)device)->queue)
        ((Wdf2Device*)device)->queue = q;
    if (!g_wdf2Queue)
        g_wdf2Queue = q;
    if (pQueue) *pQueue = q;
    return 0;
}

// --- WdfIoQueueGetDevice (index 90) ---
static void* WINAPI
stub_WdfIoQueueGetDevice(void *globals, void *queue)
{
    auto *q = (Wdf2Queue*)queue;
    void *dev = q ? q->device : nullptr;
    WDF2_LOG(2, "[WDF2] WdfIoQueueGetDevice -> %p\n", dev);
    return dev;
}

// --- WdfIoQueueStart (index 87) --- no-op
static NTSTATUS WINAPI
stub_WdfIoQueueStart(void *globals, void *queue)
{
    WDF2_LOG(2, "[WDF2] WdfIoQueueStart\n");
    return 0;
}

// --- WdfIoQueueStop (index 88) --- no-op
static void WINAPI
stub_WdfIoQueueStop(void *globals, void *queue, void *stopCb, void *ctx)
{
    WDF2_LOG(2, "[WDF2] WdfIoQueueStop\n");
}

// --- WdfIoTargetCreate (index 102) ---
static NTSTATUS WINAPI
stub_WdfIoTargetCreate(void *globals, void *device, void *attrs, void **pTarget)
{
    HLOG_USER("[WDF2] WdfIoTargetCreate\n");
    // Return a tagged non-NULL pointer as dummy handle
    static char dummy_target[8];
    if (pTarget) *pTarget = dummy_target;
    return 0;
}

// --- WdfIoTargetOpen (index 103) --- stub; succeeds without actual USB
static NTSTATUS WINAPI
stub_WdfIoTargetOpen(void *globals, void *target, void *params)
{
    HLOG_USER("[WDF2] WdfIoTargetOpen (stub -> success)\n");
    return 0;
}

// --- WdfIoTargetCloseForQueryRemove (index 104) --- no-op
static void WINAPI
stub_WdfIoTargetCloseForQueryRemove(void *globals, void *target)
{
    WDF2_LOG(2, "[WDF2] WdfIoTargetCloseForQueryRemove\n");
}

// --- WdfIoTargetClose (index 105) --- no-op
static void WINAPI
stub_WdfIoTargetClose(void *globals, void *target)
{
    WDF2_LOG(2, "[WDF2] WdfIoTargetClose\n");
}

// --- WdfIoTargetStart (index 106) ---
static NTSTATUS WINAPI
stub_WdfIoTargetStart(void *globals, void *target)
{
    HLOG_USER("[WDF2] WdfIoTargetStart (stub -> success)\n");
    return 0;
}

// --- WdfIoTargetStop (index 107) --- no-op
static void WINAPI
stub_WdfIoTargetStop(void *globals, void *target, int action)
{
    HLOG_USER("[WDF2] WdfIoTargetStop no-op\n");
}

// --- WdfIoTargetGetDevice (index 110) ---
static void* WINAPI
stub_WdfIoTargetGetDevice(void *globals, void *target)
{
    WDF2_LOG(2, "[WDF2] WdfIoTargetGetDevice -> %p\n", (void*)g_wdf2Device);
    return g_wdf2Device;
}

// --- WdfMemoryCreate (index 117) ---
static NTSTATUS WINAPI
stub_WdfMemoryCreate(void *globals, void *attrs, int poolType, ULONG tag,
                     size_t bufSize, void **pMem)
{
    HLOG_USER("[WDF2] WdfMemoryCreate(size=%zu)\n", bufSize);
    auto *m = new Wdf2Memory();
    m->buf   = calloc(1, bufSize ? bufSize : 1);
    m->size  = bufSize;
    m->owner = true;
    m->allocContext(attrs);
    if (pMem) *pMem = m;
    return 0;
}

// --- WdfMemoryCreatePreallocated (index 118) ---
static NTSTATUS WINAPI
stub_WdfMemoryCreatePreallocated(void *globals, void *attrs, void *buf, size_t size,
                                  void **pMem)
{
    HLOG_USER("[WDF2] WdfMemoryCreatePreallocated(buf=%p, size=%zu)\n", buf, size);
    auto *m = new Wdf2Memory();
    m->buf   = buf;
    m->size  = size;
    m->owner = false;
    m->allocContext(attrs);
    if (pMem) *pMem = m;
    return 0;
}

// --- WdfMemoryGetBuffer (index 119) ---
static void* WINAPI
stub_WdfMemoryGetBuffer(void *globals, void *mem, size_t *pSize)
{
    auto *m = (Wdf2Memory*)mem;
    if (!m) { if (pSize) *pSize = 0; return nullptr; }
    if (pSize) *pSize = m->size;
    WDF2_LOG(2, "[WDF2] WdfMemoryGetBuffer -> %p (size=%zu)\n", m->buf, m->size);
    return m->buf;
}

// --- WdfObjectGetTypedContextWorker (index 123) ---
static void* WINAPI
stub_WdfObjectGetTypedContextWorker(void *globals, void *handle, void *typeInfo)
{
    auto *obj = (Wdf2Obj*)handle;
    void *ctx = obj ? obj->context : nullptr;
    WDF2_LOG(2, "[WDF2] WdfObjectGetTypedContextWorker(handle=%p) -> %p\n", handle, ctx);
    return ctx;
}

// --- WdfObjectAllocateContext (index 124) ---
static NTSTATUS WINAPI
stub_WdfObjectAllocateContext(void *globals, void *handle, void *attrs, void **pCtx)
{
    auto *obj = (Wdf2Obj*)handle;
    if (!obj) return 0xC000000DL; // STATUS_INVALID_PARAMETER
    obj->allocContext(attrs);
    if (pCtx) *pCtx = obj->context;
    WDF2_LOG(1, "[WDF2] WdfObjectAllocateContext(handle=%p) -> ctx=%p\n", handle, obj->context);
    return 0;
}

// --- WdfObjectContextGetObject (index 125) ---
static void* WINAPI
stub_WdfObjectContextGetObject(void *globals, void *ctx)
{
    // We don't track reverse mapping; return NULL
    WDF2_LOG(2, "[WDF2] WdfObjectContextGetObject(ctx=%p) -> NULL (no reverse map)\n", ctx);
    return nullptr;
}

// --- WdfObjectDelete (index 129) --- no-op (no ref-counting in stub)
static void WINAPI
stub_WdfObjectDelete(void *globals, void *handle)
{
    HLOG_USER("[WDF2] WdfObjectDelete(%p) no-op\n", handle);
}

// --- WdfRegistryOpenKey (index 131) ---
static NTSTATUS WINAPI
stub_WdfRegistryOpenKey(void *globals, void *key, void *keyName, ULONG access,
                         void *attrs, void **pKey)
{
    HLOG_USER("[WDF2] WdfRegistryOpenKey -> STATUS_OBJECT_NAME_NOT_FOUND\n");
    return 0xC0000034L;
}

// --- WdfRegistryCreateKey (index 132) --- fail
static NTSTATUS WINAPI
stub_WdfRegistryCreateKey(void *globals, void *parentKey, void *keyName, ULONG access,
                           ULONG createOpts, ULONG *disposition, void *attrs, void **pKey)
{
    HLOG_USER("[WDF2] WdfRegistryCreateKey -> STATUS_OBJECT_NAME_NOT_FOUND\n");
    return 0xC0000034L;
}

// --- WdfRegistryClose (index 133) --- no-op
static void WINAPI
stub_WdfRegistryClose(void *globals, void *key)
{
    HLOG_USER("[WDF2] WdfRegistryClose no-op\n");
}

// --- WdfRegistryQueryULong (index 141) --- not found
static NTSTATUS WINAPI
stub_WdfRegistryQueryULong(void *globals, void *key, void *valueName, ULONG *pValue)
{
    HLOG_USER("[WDF2] WdfRegistryQueryULong -> STATUS_OBJECT_NAME_NOT_FOUND\n");
    return 0xC0000034L;
}

// --- WdfRegistryQueryUnicodeString (index 139) --- not found
static NTSTATUS WINAPI
stub_WdfRegistryQueryUnicodeString(void *globals, void *key, void *valueName,
                                    void *requiredSize, void *value)
{
    HLOG_USER("[WDF2] WdfRegistryQueryUnicodeString -> STATUS_OBJECT_NAME_NOT_FOUND\n");
    return 0xC0000034L;
}

// --- WdfRegistryAssignULong (index 147) --- no-op
static NTSTATUS WINAPI
stub_WdfRegistryAssignULong(void *globals, void *key, void *valueName, ULONG value)
{
    WDF2_LOG(2, "[WDF2] WdfRegistryAssignULong(value=%lu)\n", (unsigned long)value);
    return 0;
}

// --- WdfRequestGetStatus (index 153) ---
static NTSTATUS WINAPI
stub_WdfRequestGetStatus(void *globals, void *request)
{
    auto *r = (Wdf2Request*)request;
    NTSTATUS s = r ? r->status : 0;
    WDF2_LOG(2, "[WDF2] WdfRequestGetStatus -> 0x%lx\n", (long)s);
    return s;
}

// --- WdfRequestComplete (index 163) ---
static void WINAPI
stub_WdfRequestComplete(void *globals, void *request, NTSTATUS status)
{
    HLOG_USER("[WDF2] WdfRequestComplete(%p, 0x%lx)\n", request, (long)status);
    auto *r = (Wdf2Request*)request;
    if (r) { r->status = status; r->completed = true; }
}

// --- WdfRequestCompleteWithInformation (index 164) ---
static void WINAPI
stub_WdfRequestCompleteWithInformation(void *globals, void *request,
                                        NTSTATUS status, ULONG_PTR info)
{
    HLOG_USER("[WDF2] WdfRequestCompleteWithInformation(%p, 0x%lx, %lu)\n",
              request, (long)status, (unsigned long)info);
    auto *r = (Wdf2Request*)request;
    if (r) { r->status = status; r->information = info; r->completed = true; }
}

// --- WdfRequestGetParameters (index 165) ---
// WDF_REQUEST_PARAMETERS for DeviceIoControl (simplified):
//   +0x00 Size (ULONG), +0x04 MinorFunction (UCHAR), +0x05 Type (UCHAR)
//   +0x08 OutputBufferLength (size_t), +0x10 InputBufferLength (size_t)
//   +0x18 IoControlCode (ULONG), +0x20 Type3InputBuffer (void*)
static void WINAPI
stub_WdfRequestGetParameters(void *globals, void *request, void *params)
{
    auto *r = (Wdf2Request*)request;
    WDF2_LOG(1, "[WDF2] WdfRequestGetParameters(ioctl=0x%lx)\n", r ? (long)r->ioctlCode : 0L);
    if (!r || !params) return;
    ULONG sz = *(ULONG*)params;
    if (sz < 4) return;
    memset(params, 0, sz);
    *(ULONG*)((char*)params + 0x00) = sz;
    // Type = WdfRequestTypeDeviceControl = 0x0E
    *((UCHAR*)params + 0x05) = 0x0E;
    if (sz >= 0x1C) {
        *(size_t*)((char*)params + 0x08) = r->outMem ? r->outMem->size : 0;
        *(size_t*)((char*)params + 0x10) = r->inMem  ? r->inMem->size  : 0;
        *(ULONG*) ((char*)params + 0x18) = r->ioctlCode;
    }
}

// --- WdfRequestRetrieveInputMemory (index 166) ---
static NTSTATUS WINAPI
stub_WdfRequestRetrieveInputMemory(void *globals, void *request, void **pMem)
{
    auto *r = (Wdf2Request*)request;
    if (!r || !r->inMem) { WDF2_LOG(2, "[WDF2] WdfRequestRetrieveInputMemory -> UNSUCCESSFUL\n"); return 0xC0000001L; }
    WDF2_LOG(2, "[WDF2] WdfRequestRetrieveInputMemory -> %p (size=%zu)\n", r->inMem->buf, r->inMem->size);
    if (pMem) *pMem = r->inMem;
    return 0;
}

// --- WdfRequestRetrieveOutputMemory (index 167) ---
static NTSTATUS WINAPI
stub_WdfRequestRetrieveOutputMemory(void *globals, void *request, void **pMem)
{
    auto *r = (Wdf2Request*)request;
    if (!r || !r->outMem) { WDF2_LOG(2, "[WDF2] WdfRequestRetrieveOutputMemory -> UNSUCCESSFUL\n"); return 0xC0000001L; }
    WDF2_LOG(2, "[WDF2] WdfRequestRetrieveOutputMemory -> %p (size=%zu)\n", r->outMem->buf, r->outMem->size);
    if (pMem) *pMem = r->outMem;
    return 0;
}

// --- WdfRequestRetrieveInputBuffer (index 168) ---
static NTSTATUS WINAPI
stub_WdfRequestRetrieveInputBuffer(void *globals, void *request, size_t minRequired,
                                    void **pBuf, size_t *pLen)
{
    auto *r = (Wdf2Request*)request;
    if (!r || !r->inMem) { WDF2_LOG(2, "[WDF2] WdfRequestRetrieveInputBuffer -> UNSUCCESSFUL\n"); return 0xC0000001L; }
    WDF2_LOG(2, "[WDF2] WdfRequestRetrieveInputBuffer -> %p (size=%zu)\n", r->inMem->buf, r->inMem->size);
    if (pBuf) *pBuf = r->inMem->buf;
    if (pLen) *pLen = r->inMem->size;
    return 0;
}

// --- WdfRequestRetrieveOutputBuffer (index 169) ---
static NTSTATUS WINAPI
stub_WdfRequestRetrieveOutputBuffer(void *globals, void *request, size_t minRequired,
                                     void **pBuf, size_t *pLen)
{
    auto *r = (Wdf2Request*)request;
    if (!r || !r->outMem) { WDF2_LOG(2, "[WDF2] WdfRequestRetrieveOutputBuffer -> UNSUCCESSFUL\n"); return 0xC0000001L; }
    WDF2_LOG(2, "[WDF2] WdfRequestRetrieveOutputBuffer -> %p (size=%zu)\n", r->outMem->buf, r->outMem->size);
    if (pBuf) *pBuf = r->outMem->buf;
    if (pLen) *pLen = r->outMem->size;
    return 0;
}

// --- WdfRequestSetInformation (index 170) ---
static void WINAPI
stub_WdfRequestSetInformation(void *globals, void *request, ULONG_PTR info)
{
    WDF2_LOG(2, "[WDF2] WdfRequestSetInformation(info=%lu)\n", (unsigned long)info);
    auto *r = (Wdf2Request*)request;
    if (r) r->information = info;
}

// --- WdfRequestGetInformation (index 171) ---
static ULONG_PTR WINAPI
stub_WdfRequestGetInformation(void *globals, void *request)
{
    auto *r = (Wdf2Request*)request;
    ULONG_PTR info = r ? r->information : 0;
    WDF2_LOG(2, "[WDF2] WdfRequestGetInformation -> %lu\n", (unsigned long)info);
    return info;
}

// --- WdfRequestForwardToIoQueue (index 174) ---
static NTSTATUS WINAPI
stub_WdfRequestForwardToIoQueue(void *globals, void *request, void *queue)
{
    HLOG_USER("[WDF2] WdfRequestForwardToIoQueue no-op\n");
    return 0;
}

// --- WdfRequestGetIoQueue (index 175) ---
static void* WINAPI
stub_WdfRequestGetIoQueue(void *globals, void *request)
{
    auto *r = (Wdf2Request*)request;
    void *q = r ? r->queue : nullptr;
    WDF2_LOG(2, "[WDF2] WdfRequestGetIoQueue -> %p\n", q);
    return q;
}

// --- WdfCmResourceListGetCount (index 186) ---
static ULONG WINAPI
stub_WdfCmResourceListGetCount(void *globals, void *list)
{
    WDF2_LOG(1, "[WDF2] WdfCmResourceListGetCount -> 0 (empty)\n");
    return 0; // empty resource list
}

// --- WdfCmResourceListGetDescriptor (index 187) ---
static void* WINAPI
stub_WdfCmResourceListGetDescriptor(void *globals, void *list, ULONG index)
{
    WDF2_LOG(1, "[WDF2] WdfCmResourceListGetDescriptor(idx=%lu) -> NULL\n", (unsigned long)index);
    return nullptr;
}

// -----------------------------------------------------------------------
// USB WDF stubs  (indices 202-239)
// -----------------------------------------------------------------------

// Fake USB objects — populated by stub_WdfUsbTargetDeviceCreate
struct Wdf2UsbPipe {
    UCHAR endpointAddr;
    ULONG maxPacketSize;
    ULONG pipeType;   // WdfUsbPipeTypeBulk=3, WdfUsbPipeTypeInterrupt=4
};
struct Wdf2UsbInterface {
    UCHAR        numPipes;
    Wdf2UsbPipe  pipes[4];
};
struct Wdf2UsbDevice {
    USHORT           idVendor;
    USHORT           idProduct;
    Wdf2UsbInterface iface;
};
static Wdf2UsbDevice g_wdf2UsbDev;

// --- WdfUsbTargetDeviceCreate (index 202) ---
static NTSTATUS WINAPI
stub_WdfUsbTargetDeviceCreate(void *globals, void *device, void *attrs, void **pUsbDevice)
{
    // Parse USB_ID env var (format "vid:pid") for VID/PID, default = Goodix 27c6:6594
    USHORT vid = 0x27c6, pid = 0x6594;
    const char *usb_id = getenv("USB_ID");
    if (usb_id) sscanf(usb_id, "%hx:%hx", &vid, &pid);

    g_wdf2UsbDev.idVendor  = vid;
    g_wdf2UsbDev.idProduct = pid;
    // Two bulk endpoints: 0x81 bulk-in, 0x01 bulk-out
    g_wdf2UsbDev.iface.numPipes   = 2;
    g_wdf2UsbDev.iface.pipes[0]   = { 0x81, 512, 3 }; // bulk-in
    g_wdf2UsbDev.iface.pipes[1]   = { 0x01, 512, 3 }; // bulk-out

    HLOG_USER("[WDF2] WdfUsbTargetDeviceCreate -> %04x:%04x (2 bulk pipes)\n", vid, pid);
    if (pUsbDevice) *pUsbDevice = &g_wdf2UsbDev;
    return 0;
}

// --- WdfUsbTargetDeviceRetrieveInformation (index 204) ---
// Fills WDF_USB_DEVICE_INFORMATION: Size, USBD_Version, Supported_USB_Version,
// HcdPortCapabilities, Traits
static NTSTATUS WINAPI
stub_WdfUsbTargetDeviceRetrieveInformation(void *globals, void *usbDevice, void *info)
{
    WDF2_LOG(1, "[WDF2] WdfUsbTargetDeviceRetrieveInformation\n");
    if (info) {
        ULONG sz = *(ULONG*)info;
        if (sz >= 20) {
            memset(info, 0, sz);
            *(ULONG*)((char*)info + 0)  = sz;          // Size
            *(ULONG*)((char*)info + 4)  = 0x00050000;  // USBD_Version (5.0 = WinXP+)
            *(ULONG*)((char*)info + 8)  = 0x00000200;  // Supported_USB_Version (USB 2.0)
            *(ULONG*)((char*)info + 12) = 0;           // HcdPortCapabilities
            *(ULONG*)((char*)info + 16) = 2;           // Traits: WDF_USB_DEVICE_TRAIT_AT_HIGH_SPEED
        }
    }
    return 0;
}

// --- WdfUsbTargetDeviceGetDeviceDescriptor (index 205) --- void return
static void WINAPI
stub_WdfUsbTargetDeviceGetDeviceDescriptor(void *globals, void *usbDevice, void *desc)
{
    auto *ud = (Wdf2UsbDevice*)usbDevice;
    HLOG_USER("[WDF2] WdfUsbTargetDeviceGetDeviceDescriptor -> %04x:%04x\n",
              ud ? ud->idVendor : 0, ud ? ud->idProduct : 0);
    if (!desc) return;
    // USB_DEVICE_DESCRIPTOR layout (18 bytes)
    UCHAR *d = (UCHAR*)desc;
    memset(d, 0, 18);
    d[0]  = 18;    d[1] = 0x01;               // bLength, bDescriptorType
    d[2]  = 0x00;  d[3] = 0x02;               // bcdUSB = 0x0200
    d[4]  = 0x00;  d[5] = 0x00; d[6] = 0x00; // bDeviceClass/Sub/Protocol
    d[7]  = 0x40;                              // bMaxPacketSize0 = 64
    *(USHORT*)(d+8)  = ud ? ud->idVendor  : 0x27c6;
    *(USHORT*)(d+10) = ud ? ud->idProduct : 0x6594;
    *(USHORT*)(d+12) = 0x0100;                // bcdDevice
    d[14] = 1; d[15] = 2; d[16] = 3;         // iManufacturer, iProduct, iSerial
    d[17] = 1;                                 // bNumConfigurations
}

// --- WdfUsbTargetDeviceGetNumInterfaces (index 210) --- returns UCHAR
static UCHAR WINAPI
stub_WdfUsbTargetDeviceGetNumInterfaces(void *globals, void *usbDevice)
{
    HLOG_USER("[WDF2] WdfUsbTargetDeviceGetNumInterfaces -> 1\n");
    return 1;
}

// --- WdfUsbTargetDeviceSelectConfig (index 211) ---
// Output (for SingleInterface): Types.SingleInterface.NumberConfiguredPipes (at +8)
//                               Types.SingleInterface.ConfiguredUsbInterface (at +16)
static NTSTATUS WINAPI
stub_WdfUsbTargetDeviceSelectConfig(void *globals, void *usbDevice,
                                    void *pipeAttrs, void *params)
{
    auto *ud = (Wdf2UsbDevice*)usbDevice;
    HLOG_USER("[WDF2] WdfUsbTargetDeviceSelectConfig\n");
    if (params && ud) {
        // Types union starts at offset 8; SingleInterface layout:
        //   +0 (=+8):  NumberConfiguredPipes (UCHAR)
        //   +8 (=+16): ConfiguredUsbInterface (ptr, 8-byte aligned)
        *((UCHAR*)params + 8)         = ud->iface.numPipes;
        *(void**)((char*)params + 16) = &ud->iface;
    }
    return 0;
}

// --- WdfUsbTargetPipeGetInformation (index 216) --- void return
// WDF_USB_PIPE_INFORMATION: Size(+0), MaxPacketSize(+4), EndpointAddr(+8),
//   Interval(+9), SettingIndex(+10), PipeType(+12), MaxTransferSize(+16)
static void WINAPI
stub_WdfUsbTargetPipeGetInformation(void *globals, void *pipe, void *info)
{
    auto *p = (Wdf2UsbPipe*)pipe;
    WDF2_LOG(1, "[WDF2] WdfUsbTargetPipeGetInformation(pipe=%p ep=0x%02x)\n",
             pipe, p ? p->endpointAddr : 0);
    if (!info || !p) return;
    ULONG sz = *(ULONG*)info;
    if (sz < 20) return;
    memset(info, 0, sz);
    *(ULONG*)((char*)info + 0)  = sz;
    *(ULONG*)((char*)info + 4)  = p->maxPacketSize;
    *((UCHAR*)info + 8)         = p->endpointAddr;
    *((UCHAR*)info + 9)         = 0;   // Interval
    *((UCHAR*)info + 10)        = 0;   // SettingIndex
    *(ULONG*)((char*)info + 12) = p->pipeType;
    *(ULONG*)((char*)info + 16) = 4096; // MaximumTransferSize
}

// --- WdfUsbTargetPipeIsInEndpoint (index 217) --- returns BOOLEAN
static UCHAR WINAPI
stub_WdfUsbTargetPipeIsInEndpoint(void *globals, void *pipe)
{
    auto *p = (Wdf2UsbPipe*)pipe;
    UCHAR r = (p && (p->endpointAddr & 0x80)) ? 1 : 0;
    WDF2_LOG(2, "[WDF2] WdfUsbTargetPipeIsInEndpoint(ep=0x%02x) -> %u\n",
             p ? p->endpointAddr : 0, r);
    return r;
}

// --- WdfUsbTargetPipeIsOutEndpoint (index 218) --- returns BOOLEAN
static UCHAR WINAPI
stub_WdfUsbTargetPipeIsOutEndpoint(void *globals, void *pipe)
{
    auto *p = (Wdf2UsbPipe*)pipe;
    UCHAR r = (p && !(p->endpointAddr & 0x80)) ? 1 : 0;
    WDF2_LOG(2, "[WDF2] WdfUsbTargetPipeIsOutEndpoint(ep=0x%02x) -> %u\n",
             p ? p->endpointAddr : 0, r);
    return r;
}

// --- WdfUsbTargetPipeSetNoMaximumPacketSizeCheck (index 220) --- void, no-op
static void WINAPI
stub_WdfUsbTargetPipeSetNoMaximumPacketSizeCheck(void *globals, void *pipe)
{
    WDF2_LOG(2, "[WDF2] WdfUsbTargetPipeSetNoMaximumPacketSizeCheck no-op\n");
}

// --- WdfUsbTargetPipeConfigContinuousReader (index 225) --- no-op
// Sets up a continuous reader on bulk/interrupt-in pipe; we have no real USB,
// so just succeed and let the driver proceed.
static NTSTATUS WINAPI
stub_WdfUsbTargetPipeConfigContinuousReader(void *globals, void *pipe, void *config)
{
    HLOG_USER("[WDF2] WdfUsbTargetPipeConfigContinuousReader no-op\n");
    return 0;
}

// --- WdfUsbTargetDeviceGetInterface (index 236) ---
static void* WINAPI
stub_WdfUsbTargetDeviceGetInterface(void *globals, void *usbDevice, UCHAR ifaceIdx)
{
    auto *ud = (Wdf2UsbDevice*)usbDevice;
    HLOG_USER("[WDF2] WdfUsbTargetDeviceGetInterface(idx=%u)\n", (unsigned)ifaceIdx);
    return (ud && ifaceIdx == 0) ? &ud->iface : nullptr;
}

// --- WdfUsbInterfaceGetNumConfiguredPipes (index 238) --- returns UCHAR
static UCHAR WINAPI
stub_WdfUsbInterfaceGetNumConfiguredPipes(void *globals, void *iface)
{
    auto *i = (Wdf2UsbInterface*)iface;
    UCHAR n = i ? i->numPipes : 0;
    HLOG_USER("[WDF2] WdfUsbInterfaceGetNumConfiguredPipes -> %u\n", (unsigned)n);
    return n;
}

// --- WdfUsbInterfaceGetConfiguredPipe (index 239) ---
static void* WINAPI
stub_WdfUsbInterfaceGetConfiguredPipe(void *globals, void *iface, UCHAR pipeIdx, void *pipeInfo)
{
    auto *i = (Wdf2UsbInterface*)iface;
    if (!i || pipeIdx >= i->numPipes) {
        HLOG_USER("[WDF2] WdfUsbInterfaceGetConfiguredPipe(idx=%u) -> NULL\n", (unsigned)pipeIdx);
        return nullptr;
    }
    auto *p = &i->pipes[pipeIdx];
    HLOG_USER("[WDF2] WdfUsbInterfaceGetConfiguredPipe(idx=%u) -> ep=0x%02x\n",
              (unsigned)pipeIdx, p->endpointAddr);
    if (pipeInfo) stub_WdfUsbTargetPipeGetInformation(globals, p, pipeInfo);
    return p;
}

// Generic catch-all stubs (used for unimplemented slots).
// Each index gets its own instantiation so the log shows the exact slot.
template<int N>
struct WdfStubSlot {
    static NTSTATUS WINAPI stub(void *g, ...) {
        WDF2_LOG(1, "[WDF2] STUB: unimplemented WDF table entry [%d] called\n", N);
        return 0;
    }
    static void fill() {
        g_wdf2Table[N] = (WDFFUNC)stub;
        WdfStubSlot<N-1>::fill();
    }
};
template<> struct WdfStubSlot<-1> { static void fill() {} };

// -----------------------------------------------------------------------
// Fill g_wdf2Table with stub function pointers
// -----------------------------------------------------------------------
static void fill_wdf2_table(void)
{
    // Default all slots to per-index stubs (so log shows which slot was hit)
    WdfStubSlot<256>::fill();

#define SET(idx, fn) g_wdf2Table[idx] = (WDFFUNC)(fn)
    SET(13,  stub_WdfDeviceSetDeviceState);
    SET(14,  stub_WdfDeviceGetDriver);
    SET(16,  stub_WdfDeviceAssignS0IdleSettings);
    SET(17,  stub_WdfDeviceAssignSxWakeSettings);
    SET(18,  stub_WdfDeviceOpenRegistryKey);
    SET(19,  stub_WdfDeviceInitSetPnpPowerEventCallbacks);
    SET(20,  stub_WdfDeviceInitSetPowerPolicyEventCallbacks);
    SET(21,  stub_WdfDeviceInitSetPowerPolicyOwnership);
    SET(22,  stub_WdfDeviceInitSetIoType);
    SET(23,  stub_WdfDeviceInitSetFileObjectConfig);
    SET(24,  stub_WdfDeviceInitSetRequestAttributes);
    SET(25,  stub_WdfDeviceCreate);
    SET(26,  stub_WdfDeviceSetStaticStopRemove);
    SET(27,  stub_WdfDeviceCreateDeviceInterface);
    SET(28,  stub_WdfDeviceSetDeviceInterfaceState);
    SET(31,  stub_WdfDeviceQueryProperty);
    SET(33,  stub_WdfDeviceSetPnpCapabilities);
    SET(34,  stub_WdfDeviceSetPowerCapabilities);
    SET(35,  stub_WdfDeviceSetFailed);
    SET(36,  stub_WdfDeviceStopIdleNoTrack);
    SET(37,  stub_WdfDeviceResumeIdleNoTrack);
    SET(39,  stub_WdfDeviceGetDefaultQueue);
    SET(41,  stub_WdfDeviceGetSystemPowerAction);
    SET(43,  stub_WdfDeviceInitSetIoTypeEx);
    SET(57,  stub_WdfDriverCreate);
    SET(58,  stub_WdfDriverGetRegistryPath);
    SET(59,  stub_WdfDriverOpenParametersRegistryKey);
    SET(85,  stub_WdfIoQueueCreate);
    SET(87,  stub_WdfIoQueueStart);
    SET(88,  stub_WdfIoQueueStop);
    SET(90,  stub_WdfIoQueueGetDevice);
    SET(102, stub_WdfIoTargetCreate);
    SET(103, stub_WdfIoTargetOpen);
    SET(104, stub_WdfIoTargetCloseForQueryRemove);
    SET(105, stub_WdfIoTargetClose);
    SET(106, stub_WdfIoTargetStart);
    SET(107, stub_WdfIoTargetStop);
    SET(110, stub_WdfIoTargetGetDevice);
    SET(117, stub_WdfMemoryCreate);
    SET(118, stub_WdfMemoryCreatePreallocated);
    SET(119, stub_WdfMemoryGetBuffer);
    SET(123, stub_WdfObjectGetTypedContextWorker);
    SET(124, stub_WdfObjectAllocateContext);
    SET(125, stub_WdfObjectContextGetObject);
    SET(129, stub_WdfObjectDelete);
    SET(131, stub_WdfRegistryOpenKey);
    SET(132, stub_WdfRegistryCreateKey);
    SET(133, stub_WdfRegistryClose);
    SET(139, stub_WdfRegistryQueryUnicodeString);
    SET(141, stub_WdfRegistryQueryULong);
    SET(147, stub_WdfRegistryAssignULong);
    SET(153, stub_WdfRequestGetStatus);
    SET(163, stub_WdfRequestComplete);
    SET(164, stub_WdfRequestCompleteWithInformation);
    SET(165, stub_WdfRequestGetParameters);
    SET(166, stub_WdfRequestRetrieveInputMemory);
    SET(167, stub_WdfRequestRetrieveOutputMemory);
    SET(168, stub_WdfRequestRetrieveInputBuffer);
    SET(169, stub_WdfRequestRetrieveOutputBuffer);
    SET(170, stub_WdfRequestSetInformation);
    SET(171, stub_WdfRequestGetInformation);
    SET(174, stub_WdfRequestForwardToIoQueue);
    SET(175, stub_WdfRequestGetIoQueue);
    SET(186, stub_WdfCmResourceListGetCount);
    SET(187, stub_WdfCmResourceListGetDescriptor);
    SET(202, stub_WdfUsbTargetDeviceCreate);
    SET(204, stub_WdfUsbTargetDeviceRetrieveInformation);
    SET(205, stub_WdfUsbTargetDeviceGetDeviceDescriptor);
    SET(210, stub_WdfUsbTargetDeviceGetNumInterfaces);
    SET(211, stub_WdfUsbTargetDeviceSelectConfig);
    SET(216, stub_WdfUsbTargetPipeGetInformation);
    SET(217, stub_WdfUsbTargetPipeIsInEndpoint);
    SET(218, stub_WdfUsbTargetPipeIsOutEndpoint);
    SET(220, stub_WdfUsbTargetPipeSetNoMaximumPacketSizeCheck);
    SET(225, stub_WdfUsbTargetPipeConfigContinuousReader);
    SET(236, stub_WdfUsbTargetDeviceGetInterface);
    SET(238, stub_WdfUsbInterfaceGetNumConfiguredPipes);
    SET(239, stub_WdfUsbInterfaceGetConfiguredPipe);
#undef SET
}

// -----------------------------------------------------------------------
// host_VersionBind — called by driver's WDF stub with:
//   (WDF2_BIND_INFO *bindInfo, void **ppComponentGlobals)
//
// bindInfo->FuncTable  = &WdfFunctions_02015 in driver's .data
// *FuncTable is set to point to our g_wdf2Table
// *ppComponentGlobals is set to &g_wdf2Globals
// -----------------------------------------------------------------------
static NTSTATUS WINAPI
host_VersionBind(WDF2_BIND_INFO *bindInfo, void **ppComponentGlobals)
{
    if (bindInfo) {
        HLOG_USER("[WDF2] VersionBind: version=%lu.%lu, FuncCount=%lu, FuncTable=%p\n",
                  (unsigned long)bindInfo->Version.Major,
                  (unsigned long)bindInfo->Version.Minor,
                  (unsigned long)bindInfo->FuncCount,
                  (void*)bindInfo->FuncTable);
    }

    fill_wdf2_table();

    if (bindInfo && bindInfo->FuncTable) {
        // FuncTable = &WdfFunctions_02015 (pointer to the extern WDFFUNC* in driver)
        // Set: *FuncTable = g_wdf2Table  (WdfFunctions_02015 now points to our array)
        *(WDFFUNC **)bindInfo->FuncTable = g_wdf2Table;
    }

    memset(&g_wdf2Globals, 0, sizeof(g_wdf2Globals));
    strncpy(g_wdf2Globals.DriverName, "wbdi", sizeof(g_wdf2Globals.DriverName) - 1);

    if (ppComponentGlobals)
        *ppComponentGlobals = &g_wdf2Globals;

    return 0; // STATUS_SUCCESS
}

// -----------------------------------------------------------------------
// wdf2_dispatch_ioctl — send an IOCTL through the WDF v2 queue.
// Returns STATUS and copies at most outBufLen bytes to outBuf.
// -----------------------------------------------------------------------
#pragma pop_macro("HLOG_USER")

// -----------------------------------------------------------------------
// host_BindClient — stored at loaderIface.BindClient (+0x08).
// Called by FxDriverEntryUm as: BindClient(versionBind, bindInfo, ppGlobals)
//   versionBind = param_2 from FxDriverEntryUm call (= host_VersionBind)
//   bindInfo    = &WdfFunctions_02015_bindInfo embedded in driver .data
//   ppGlobals   = &WdfDriverGlobals global ptr in driver .data
// We simply delegate to host_VersionBind.
// -----------------------------------------------------------------------
static NTSTATUS WINAPI
host_BindClient(void *versionBind, WDF2_BIND_INFO *bindInfo, void **ppGlobals)
{
    WDF2_LOG(2, "[WDF2] host_BindClient: versionBind=%p bindInfo=%p ppGlobals=%p\n",
             versionBind, (void*)bindInfo, (void*)ppGlobals);
    if (bindInfo)
        WDF2_LOG(2, "[WDF2]   bindInfo: ver=%lu.%lu.%lu FuncCount=%lu FuncTable=%p\n",
                 (unsigned long)bindInfo->Version.Major,
                 (unsigned long)bindInfo->Version.Minor,
                 (unsigned long)bindInfo->Version.Build,
                 (unsigned long)bindInfo->FuncCount,
                 (void*)bindInfo->FuncTable);
    // Delegate to host_VersionBind (or call the passed-in versionBind if different)
    auto *fn = (PWDF2_VERSION_BIND)versionBind;
    return fn ? fn(bindInfo, ppGlobals) : host_VersionBind(bindInfo, ppGlobals);
}

static NTSTATUS
wdf2_dispatch_ioctl(ULONG ioctlCode,
                    const void *inBuf,  size_t inBufLen,
                    void       *outBuf, size_t outBufLen,
                    ULONG_PTR  *pInfo)
{
    WDF2_LOG(1, "[WDF2] wdf2_dispatch_ioctl: ioctl=0x%lx inLen=%zu outLen=%zu\n",
             (long)ioctlCode, inBufLen, outBufLen);
    if (!g_wdf2Queue || !g_wdf2Queue->evtIoDeviceControl) {
        WDF2_LOG(1, "[WDF2] wdf2_dispatch_ioctl: no queue/callback\n");
        return 0xC0000001L; // STATUS_UNSUCCESSFUL
    }

    Wdf2Request req;
    req.ioctlCode = ioctlCode;
    req.queue     = g_wdf2Queue;

    Wdf2Memory inMem, outMem;
    inMem.buf  = const_cast<void*>(inBuf);
    inMem.size = inBufLen;
    inMem.owner = false;
    outMem.buf  = outBuf;
    outMem.size = outBufLen;
    outMem.owner = false;

    req.inMem  = inBufLen  ? &inMem  : nullptr;
    req.outMem = outBufLen ? &outMem : nullptr;

    g_wdf2Queue->evtIoDeviceControl(
        g_wdf2Queue,
        &req,
        outBufLen,
        inBufLen,
        ioctlCode);

    if (pInfo) *pInfo = req.information;
    return req.status;
}
