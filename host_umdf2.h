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
    do { if (g_umdf2_loglevel >= (lvl)) { printf(__VA_ARGS__); fflush(stdout); } } while(0)

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
// WDF handle types — opaque pointer typedefs matching kmdf/1.15/wdftypes.h.
// Defined as typedef void* (not DECLARE_HANDLE) to avoid conflicts with
// UMDF v1 COM headers and to keep stub bodies unchanged (casts still compile).
// Guard: WDFDRIVER_DEFINED mirrors the pattern used by wdftypes.h.
// -----------------------------------------------------------------------
#ifndef WDFDRIVER_DEFINED
#define WDFDRIVER_DEFINED
typedef void *WDFDRIVER;
typedef void *WDFDEVICE;
typedef void *WDFQUEUE;
typedef void *WDFREQUEST;
typedef void *WDFMEMORY;
typedef void *WDFIOTARGET;
typedef void *WDFUSBDEVICE;
typedef void *WDFUSBINTERFACE;
typedef void *WDFUSBPIPE;
typedef void *WDFKEY;
typedef void *WDFCMRESLIST;
typedef void *WDFOBJECT;
typedef struct WDFDEVICE_INIT *PWDFDEVICE_INIT;
#endif  // WDFDRIVER_DEFINED

// WDF_DRIVER_GLOBALS — first argument to every WDF stub (DriverGlobals parameter).
// We alias our internal WDF2_DRIVER_GLOBALS to this name.
typedef WDF2_DRIVER_GLOBALS  WDF_DRIVER_GLOBALS;
typedef WDF2_DRIVER_GLOBALS *PWDF_DRIVER_GLOBALS;

// Forward-declared struct pointer types for WDF API parameters.
// These match the struct names used in kmdf/1.15/ headers.
typedef struct _DRIVER_OBJECT                           *PDRIVER_OBJECT;
typedef struct _WDF_DRIVER_CONFIG                       *PWDF_DRIVER_CONFIG;
typedef struct _WDF_OBJECT_ATTRIBUTES                   *PWDF_OBJECT_ATTRIBUTES;
typedef struct _WDF_PNPPOWER_EVENT_CALLBACKS            *PWDF_PNPPOWER_EVENT_CALLBACKS;
typedef struct _WDF_POWER_POLICY_EVENT_CALLBACKS        *PWDF_POWER_POLICY_EVENT_CALLBACKS;
typedef struct _WDF_FILEOBJECT_CONFIG                   *PWDF_FILEOBJECT_CONFIG;
typedef struct _WDF_IO_TYPE_CONFIG                      *PWDF_IO_TYPE_CONFIG;
typedef struct _WDF_DEVICE_STATE                        *PWDF_DEVICE_STATE;
typedef struct _WDF_DEVICE_PNP_CAPABILITIES             *PWDF_DEVICE_PNP_CAPABILITIES;
typedef struct _WDF_DEVICE_POWER_CAPABILITIES           *PWDF_DEVICE_POWER_CAPABILITIES;
typedef struct _WDF_DEVICE_POWER_POLICY_IDLE_SETTINGS   *PWDF_DEVICE_POWER_POLICY_IDLE_SETTINGS;
typedef struct _WDF_DEVICE_POWER_POLICY_WAKE_SETTINGS   *PWDF_DEVICE_POWER_POLICY_WAKE_SETTINGS;
typedef struct _WDF_IO_QUEUE_CONFIG                     *PWDF_IO_QUEUE_CONFIG;
typedef struct _WDF_IO_TARGET_OPEN_PARAMS               *PWDF_IO_TARGET_OPEN_PARAMS;
typedef struct _WDF_OBJECT_CONTEXT_TYPE_INFO             WDF_OBJECT_CONTEXT_TYPE_INFO;
typedef const   WDF_OBJECT_CONTEXT_TYPE_INFO            *PCWDF_OBJECT_CONTEXT_TYPE_INFO;
typedef struct _WDF_REQUEST_PARAMETERS                  *PWDF_REQUEST_PARAMETERS;
typedef struct _WDF_USB_DEVICE_INFORMATION              *PWDF_USB_DEVICE_INFORMATION;
typedef struct _WDF_USB_DEVICE_SELECT_CONFIG_PARAMS     *PWDF_USB_DEVICE_SELECT_CONFIG_PARAMS;
typedef struct _WDF_USB_PIPE_INFORMATION                *PWDF_USB_PIPE_INFORMATION;
typedef struct _WDF_USB_CONTINUOUS_READER_CONFIG        *PWDF_USB_CONTINUOUS_READER_CONFIG;
typedef void   *WDFCONTEXT;
// WDF_DEVICE_IO_TYPE and WDF_IO_TARGET_SENT_IO_ACTION are already defined as enums
// in wdk-10/Include/wdf/umdf/1.11/wudfddi_types.h (included transitively via wudfddi.h).
// Do NOT redefine them here — it causes a conflicting-declaration error.
typedef ULONG   WDF_DEVICE_FAILED_ACTION;     // enum WDF_DEVICE_FAILED_ACTION in wdfdevice.h
typedef ULONG   POOL_TYPE;                    // enum POOL_TYPE in wudfwdm.h
typedef ULONG   DEVICE_REGISTRY_PROPERTY;     // enum DEVICE_REGISTRY_PROPERTY in wudfwdm.h
typedef void  (*PFN_WDF_IO_QUEUE_STATE)(WDFQUEUE Queue, WDFCONTEXT Context);

// UNICODE_STRING — not in mingw headers; defined in WDK ntdef.h but that
// header conflicts with mingw windows.h. Define the three types directly.
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING;
typedef UNICODE_STRING  *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;


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
// g_wdf2Table declared below, after all stub function definitions.

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
stub_WdfDriverCreate(PWDF_DRIVER_GLOBALS DriverGlobals, PDRIVER_OBJECT DriverObject,
                     PCUNICODE_STRING RegistryPath,
                     PWDF_OBJECT_ATTRIBUTES DriverAttributes,
                     PWDF_DRIVER_CONFIG DriverConfig, WDFDRIVER *Driver)
{
    HLOG_USER("[WDF2] WdfDriverCreate: config=%p attrs=%p\n", DriverConfig, DriverAttributes);
    if (DriverConfig)
        HLOG_USER("[WDF2]   config.Size=0x%lx\n", (unsigned long)*(ULONG*)DriverConfig);

    g_wdf2Driver = new Wdf2Driver();
    g_wdf2Driver->allocContext(DriverAttributes);
    if (DriverConfig) {
        g_wdf2Driver->evtDeviceAdd = *(Wdf2_EvtDriverDeviceAdd*)((char*)DriverConfig + 0x08);
        g_wdf2Driver->evtUnload    = *(Wdf2_EvtDriverUnload*)    ((char*)DriverConfig + 0x10);
    }
    g_wdf2Globals.Driver = g_wdf2Driver;
    if (Driver) *Driver = g_wdf2Driver;
    HLOG_USER("[WDF2]   EvtDriverDeviceAdd=%p\n", (void*)g_wdf2Driver->evtDeviceAdd);
    return 0;
}

// --- WdfDeviceInitSetPnpPowerEventCallbacks (index 19) ---
static void WINAPI
stub_WdfDeviceInitSetPnpPowerEventCallbacks(PWDF_DRIVER_GLOBALS DriverGlobals,
                                             PWDFDEVICE_INIT DeviceInit,
                                             PWDF_PNPPOWER_EVENT_CALLBACKS PnpPowerEventCallbacks)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetPnpPowerEventCallbacks\n");
    auto *di = (Wdf2DeviceInit*)DeviceInit;
    if (di && PnpPowerEventCallbacks) {
        ULONG sz = *(ULONG*)PnpPowerEventCallbacks;
        if (sz > (ULONG)sizeof(di->pnpPowerCbs)) sz = (ULONG)sizeof(di->pnpPowerCbs);
        memcpy(di->pnpPowerCbs, PnpPowerEventCallbacks, sz);
    }
}

// --- WdfDeviceInitSetPowerPolicyEventCallbacks (index 20) ---
static void WINAPI
stub_WdfDeviceInitSetPowerPolicyEventCallbacks(PWDF_DRIVER_GLOBALS DriverGlobals,
                                                PWDFDEVICE_INIT DeviceInit,
                                                PWDF_POWER_POLICY_EVENT_CALLBACKS PowerPolicyEventCallbacks)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetPowerPolicyEventCallbacks\n");
    auto *di = (Wdf2DeviceInit*)DeviceInit;
    if (di && PowerPolicyEventCallbacks) {
        ULONG sz = *(ULONG*)PowerPolicyEventCallbacks;
        if (sz > (ULONG)sizeof(di->powerPolicyCbs)) sz = (ULONG)sizeof(di->powerPolicyCbs);
        memcpy(di->powerPolicyCbs, PowerPolicyEventCallbacks, sz);
    }
}

// --- WdfDeviceInitSetPowerPolicyOwnership (index 21) ---
static void WINAPI
stub_WdfDeviceInitSetPowerPolicyOwnership(PWDF_DRIVER_GLOBALS DriverGlobals,
                                           PWDFDEVICE_INIT DeviceInit, BOOLEAN IsPowerPolicyOwner)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetPowerPolicyOwnership(%d)\n", IsPowerPolicyOwner);
    auto *di = (Wdf2DeviceInit*)DeviceInit;
    if (di) di->powerPolicyOwner = IsPowerPolicyOwner;
}

// --- WdfDeviceInitSetIoType (index 22) --- no-op
static void WINAPI
stub_WdfDeviceInitSetIoType(PWDF_DRIVER_GLOBALS DriverGlobals,
                             PWDFDEVICE_INIT DeviceInit, WDF_DEVICE_IO_TYPE IoType)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetIoType(%lu) no-op\n", (unsigned long)IoType);
}

// --- WdfDeviceInitSetFileObjectConfig (index 23) --- no-op
static void WINAPI
stub_WdfDeviceInitSetFileObjectConfig(PWDF_DRIVER_GLOBALS DriverGlobals,
                                       PWDFDEVICE_INIT DeviceInit,
                                       PWDF_FILEOBJECT_CONFIG FileObjectConfig,
                                       PWDF_OBJECT_ATTRIBUTES FileObjectAttributes)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetFileObjectConfig no-op\n");
}

// --- WdfDeviceInitSetRequestAttributes (index 24) --- no-op
static void WINAPI
stub_WdfDeviceInitSetRequestAttributes(PWDF_DRIVER_GLOBALS DriverGlobals,
                                        PWDFDEVICE_INIT DeviceInit,
                                        PWDF_OBJECT_ATTRIBUTES RequestAttributes)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetRequestAttributes no-op\n");
}

// --- WdfDeviceInitSetIoTypeEx (index 43) --- no-op
static void WINAPI
stub_WdfDeviceInitSetIoTypeEx(PWDF_DRIVER_GLOBALS DriverGlobals,
                               PWDFDEVICE_INIT DeviceInit, PWDF_IO_TYPE_CONFIG IoTypeConfig)
{
    HLOG_USER("[WDF2] WdfDeviceInitSetIoTypeEx no-op\n");
}

// --- WdfDeviceCreate (index 25) ---
// WDF_OBJECT_ATTRIBUTES layout (64-bit):
//   +0x00 Size, +0x08 EvtCleanup, +0x10 EvtDestroy,
//   +0x18 ExecutionLevel, +0x1C SynchronizationScope,
//   +0x20 ParentObject, +0x28 ContextSizeOverride, +0x30 ContextTypeInfo
static NTSTATUS WINAPI
stub_WdfDeviceCreate(PWDF_DRIVER_GLOBALS DriverGlobals, PWDFDEVICE_INIT *DeviceInit,
                     PWDF_OBJECT_ATTRIBUTES DeviceAttributes, WDFDEVICE *Device)
{
    HLOG_USER("[WDF2] WdfDeviceCreate\n");
    auto *di = DeviceInit ? (Wdf2DeviceInit*)*DeviceInit : nullptr;

    g_wdf2Device = new Wdf2Device();
    g_wdf2Device->driver = g_wdf2Driver;
    g_wdf2Device->init   = di;
    g_wdf2Device->allocContext(DeviceAttributes);

    if (DeviceInit) *DeviceInit = nullptr; // "consumed" by the framework
    if (Device)     *Device     = g_wdf2Device;
    return 0;
}

// --- WdfDeviceSetStaticStopRemove (index 26) --- no-op
static void WINAPI
stub_WdfDeviceSetStaticStopRemove(PWDF_DRIVER_GLOBALS DriverGlobals,
                                   WDFDEVICE Device, BOOLEAN Stoppable)
{
    HLOG_USER("[WDF2] WdfDeviceSetStaticStopRemove no-op\n");
}

// --- WdfDeviceCreateDeviceInterface (index 27) --- no-op
static NTSTATUS WINAPI
stub_WdfDeviceCreateDeviceInterface(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                                     CONST GUID *InterfaceClassGUID,
                                     PCUNICODE_STRING ReferenceString)
{
    HLOG_USER("[WDF2] WdfDeviceCreateDeviceInterface no-op\n");
    return 0;
}

// --- WdfDeviceSetDeviceInterfaceState (index 28) --- no-op
static void WINAPI
stub_WdfDeviceSetDeviceInterfaceState(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                                      CONST GUID *InterfaceClassGUID,
                                      PCUNICODE_STRING ReferenceString,
                                      BOOLEAN IsInterfaceEnabled)
{
    HLOG_USER("[WDF2] WdfDeviceSetDeviceInterfaceState(%d) no-op\n", IsInterfaceEnabled);
}

// --- WdfDeviceQueryProperty (index 31) --- return STATUS_NOT_FOUND
static NTSTATUS WINAPI
stub_WdfDeviceQueryProperty(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                             DEVICE_REGISTRY_PROPERTY DeviceProperty, ULONG BufferLength,
                             PVOID PropertyBuffer, PULONG ResultLength)
{
    HLOG_USER("[WDF2] WdfDeviceQueryProperty no-op\n");
    return 0xC0000225L; // STATUS_NOT_FOUND
}

// --- WdfDeviceSetPnpCapabilities (index 33) --- no-op
static void WINAPI
stub_WdfDeviceSetPnpCapabilities(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                                  PWDF_DEVICE_PNP_CAPABILITIES PnpCapabilities)
{
    HLOG_USER("[WDF2] WdfDeviceSetPnpCapabilities no-op\n");
}

// --- WdfDeviceSetPowerCapabilities (index 34) --- no-op
static void WINAPI
stub_WdfDeviceSetPowerCapabilities(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                                    PWDF_DEVICE_POWER_CAPABILITIES PowerCapabilities)
{
    HLOG_USER("[WDF2] WdfDeviceSetPowerCapabilities no-op\n");
}

// --- WdfDeviceSetFailed (index 35) --- no-op
static void WINAPI
stub_WdfDeviceSetFailed(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                         WDF_DEVICE_FAILED_ACTION FailedAction)
{
    HLOG_USER("[WDF2] WdfDeviceSetFailed(%lu) no-op\n", (unsigned long)FailedAction);
}

// --- WdfDeviceStopIdleNoTrack (index 36) --- return success
static NTSTATUS WINAPI
stub_WdfDeviceStopIdleNoTrack(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                               BOOLEAN WaitForD0)
{
    WDF2_LOG(2, "[WDF2] WdfDeviceStopIdleNoTrack\n");
    return 0;
}

// --- WdfDeviceResumeIdleNoTrack (index 37) --- no-op
static void WINAPI
stub_WdfDeviceResumeIdleNoTrack(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device)
{
    WDF2_LOG(2, "[WDF2] WdfDeviceResumeIdleNoTrack\n");
}

// --- WdfDeviceGetDefaultQueue (index 39) ---
static WDFQUEUE WINAPI
stub_WdfDeviceGetDefaultQueue(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device)
{
    auto *dev = (Wdf2Device*)Device;
    WDFQUEUE q = dev ? dev->queue : nullptr;
    WDF2_LOG(2, "[WDF2] WdfDeviceGetDefaultQueue -> %p\n", q);
    return q;
}

// --- WdfDeviceGetSystemPowerAction (index 41) --- return PowerActionNone = 0
static POWER_ACTION WINAPI
stub_WdfDeviceGetSystemPowerAction(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device)
{
    WDF2_LOG(2, "[WDF2] WdfDeviceGetSystemPowerAction -> 0 (PowerActionNone)\n");
    return (POWER_ACTION)0;
}

// --- WdfDeviceSetDeviceState (index 13) --- no-op
static void WINAPI
stub_WdfDeviceSetDeviceState(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                              PWDF_DEVICE_STATE DeviceState)
{
    HLOG_USER("[WDF2] WdfDeviceSetDeviceState no-op\n");
}

// --- WdfDeviceGetDriver (index 14) ---
static WDFDRIVER WINAPI
stub_WdfDeviceGetDriver(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device)
{
    WDF2_LOG(2, "[WDF2] WdfDeviceGetDriver -> %p\n", (void*)g_wdf2Driver);
    return (WDFDRIVER)g_wdf2Driver;
}

// --- WdfDeviceOpenRegistryKey (index 18) ---
static NTSTATUS WINAPI
stub_WdfDeviceOpenRegistryKey(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                               ULONG DeviceInstanceKeyType, ACCESS_MASK DesiredAccess,
                               PWDF_OBJECT_ATTRIBUTES KeyAttributes, WDFKEY *Key)
{
    HLOG_USER("[WDF2] WdfDeviceOpenRegistryKey -> STATUS_OBJECT_NAME_NOT_FOUND\n");
    return 0xC0000034L; // STATUS_OBJECT_NAME_NOT_FOUND
}

// --- WdfDeviceAssignS0IdleSettings (index 16) --- return success
static NTSTATUS WINAPI
stub_WdfDeviceAssignS0IdleSettings(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                                    PWDF_DEVICE_POWER_POLICY_IDLE_SETTINGS Settings)
{
    HLOG_USER("[WDF2] WdfDeviceAssignS0IdleSettings no-op\n");
    return 0;
}

// --- WdfDeviceAssignSxWakeSettings (index 17) --- return success
static NTSTATUS WINAPI
stub_WdfDeviceAssignSxWakeSettings(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                                    PWDF_DEVICE_POWER_POLICY_WAKE_SETTINGS Settings)
{
    HLOG_USER("[WDF2] WdfDeviceAssignSxWakeSettings no-op\n");
    return 0;
}

// --- WdfDriverCreate table index 57; WdfDriverGetRegistryPath index 58 ---
static PWSTR WINAPI
stub_WdfDriverGetRegistryPath(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDRIVER Driver)
{
    HLOG_USER("[WDF2] WdfDriverGetRegistryPath -> NULL\n");
    return nullptr;
}

// --- WdfDriverOpenParametersRegistryKey (index 59) ---
static NTSTATUS WINAPI
stub_WdfDriverOpenParametersRegistryKey(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDRIVER Driver,
                                         ACCESS_MASK DesiredAccess,
                                         PWDF_OBJECT_ATTRIBUTES KeyAttributes, WDFKEY *Key)
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
stub_WdfIoQueueCreate(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                      PWDF_IO_QUEUE_CONFIG Config,
                      PWDF_OBJECT_ATTRIBUTES QueueAttributes, WDFQUEUE *Queue)
{
    HLOG_USER("[WDF2] WdfIoQueueCreate\n");
    auto *q = new Wdf2Queue();
    q->device = (Wdf2Device*)Device;
    q->allocContext(QueueAttributes);
    if (Config)
        q->evtIoDeviceControl = *(Wdf2_EvtIoDeviceControl*)((char*)Config + 0x28);

    HLOG_USER("[WDF2]   EvtIoDeviceControl=%p\n", (void*)q->evtIoDeviceControl);

    if (Device && !((Wdf2Device*)Device)->queue)
        ((Wdf2Device*)Device)->queue = q;
    if (!g_wdf2Queue)
        g_wdf2Queue = q;
    if (Queue) *Queue = q;
    return 0;
}

// --- WdfIoQueueGetDevice (index 90) ---
static WDFDEVICE WINAPI
stub_WdfIoQueueGetDevice(PWDF_DRIVER_GLOBALS DriverGlobals, WDFQUEUE Queue)
{
    auto *q = (Wdf2Queue*)Queue;
    WDFDEVICE dev = q ? q->device : nullptr;
    WDF2_LOG(2, "[WDF2] WdfIoQueueGetDevice -> %p\n", dev);
    return dev;
}

// --- WdfIoQueueStart (index 87) --- no-op
static VOID WINAPI
stub_WdfIoQueueStart(PWDF_DRIVER_GLOBALS DriverGlobals, WDFQUEUE Queue)
{
    WDF2_LOG(2, "[WDF2] WdfIoQueueStart\n");
}

// --- WdfIoQueueStop (index 88) --- no-op
static void WINAPI
stub_WdfIoQueueStop(PWDF_DRIVER_GLOBALS DriverGlobals, WDFQUEUE Queue,
                     PFN_WDF_IO_QUEUE_STATE StopComplete, WDFCONTEXT Context)
{
    WDF2_LOG(2, "[WDF2] WdfIoQueueStop\n");
}

// --- WdfIoTargetCreate (index 102) ---
static NTSTATUS WINAPI
stub_WdfIoTargetCreate(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                        PWDF_OBJECT_ATTRIBUTES IoTargetAttributes, WDFIOTARGET *IoTarget)
{
    HLOG_USER("[WDF2] WdfIoTargetCreate\n");
    // Return a tagged non-NULL pointer as dummy handle
    static char dummy_target[8];
    if (IoTarget) *IoTarget = dummy_target;
    return 0;
}

// --- WdfIoTargetOpen (index 103) --- stub; succeeds without actual USB
static NTSTATUS WINAPI
stub_WdfIoTargetOpen(PWDF_DRIVER_GLOBALS DriverGlobals, WDFIOTARGET IoTarget,
                      PWDF_IO_TARGET_OPEN_PARAMS OpenParams)
{
    HLOG_USER("[WDF2] WdfIoTargetOpen (stub -> success)\n");
    return 0;
}

// --- WdfIoTargetCloseForQueryRemove (index 104) --- no-op
static void WINAPI
stub_WdfIoTargetCloseForQueryRemove(PWDF_DRIVER_GLOBALS DriverGlobals, WDFIOTARGET IoTarget)
{
    WDF2_LOG(2, "[WDF2] WdfIoTargetCloseForQueryRemove\n");
}

// Forward declaration: body defined after Wdf2UsbPipe
static void wdf2_maybe_start_cont_reader(WDFIOTARGET IoTarget);

// --- WdfIoTargetClose (index 105) --- no-op
static void WINAPI
stub_WdfIoTargetClose(PWDF_DRIVER_GLOBALS DriverGlobals, WDFIOTARGET IoTarget)
{
    WDF2_LOG(2, "[WDF2] WdfIoTargetClose\n");
}

// --- WdfIoTargetStart (index 106) ---
static NTSTATUS WINAPI
stub_WdfIoTargetStart(PWDF_DRIVER_GLOBALS DriverGlobals, WDFIOTARGET IoTarget)
{
    HLOG_USER("[WDF2] WdfIoTargetStart target=%p\n", (void*)IoTarget);
    wdf2_maybe_start_cont_reader(IoTarget);
    return 0;
}

// --- WdfIoTargetStop (index 107) --- no-op
static void WINAPI
stub_WdfIoTargetStop(PWDF_DRIVER_GLOBALS DriverGlobals, WDFIOTARGET IoTarget,
                      WDF_IO_TARGET_SENT_IO_ACTION Action)
{
    HLOG_USER("[WDF2] WdfIoTargetStop no-op\n");
}

// --- WdfIoTargetGetDevice (index 110) ---
static WDFDEVICE WINAPI
stub_WdfIoTargetGetDevice(PWDF_DRIVER_GLOBALS DriverGlobals, WDFIOTARGET IoTarget)
{
    WDF2_LOG(2, "[WDF2] WdfIoTargetGetDevice -> %p\n", (void*)g_wdf2Device);
    return (WDFDEVICE)g_wdf2Device;
}

// --- WdfMemoryCreate (index 117) ---
static NTSTATUS WINAPI
stub_WdfMemoryCreate(PWDF_DRIVER_GLOBALS DriverGlobals,
                     PWDF_OBJECT_ATTRIBUTES Attributes, POOL_TYPE PoolType,
                     ULONG PoolTag, size_t BufferSize, WDFMEMORY *Memory,
                     PVOID *Buffer)
{
    HLOG_USER("[WDF2] WdfMemoryCreate(size=%zu)\n", BufferSize);
    auto *m = new Wdf2Memory();
    m->buf   = calloc(1, BufferSize ? BufferSize : 1);
    m->size  = BufferSize;
    m->owner = true;
    m->allocContext(Attributes);
    if (Memory) *Memory = m;
    if (Buffer) *Buffer = m->buf;
    return 0;
}

// --- WdfMemoryCreatePreallocated (index 118) ---
static NTSTATUS WINAPI
stub_WdfMemoryCreatePreallocated(PWDF_DRIVER_GLOBALS DriverGlobals,
                                  PWDF_OBJECT_ATTRIBUTES Attributes,
                                  PVOID Buffer, size_t BufferSize, WDFMEMORY *Memory)
{
    HLOG_USER("[WDF2] WdfMemoryCreatePreallocated(buf=%p, size=%zu)\n", Buffer, BufferSize);
    auto *m = new Wdf2Memory();
    m->buf   = Buffer;
    m->size  = BufferSize;
    m->owner = false;
    m->allocContext(Attributes);
    if (Memory) *Memory = m;
    return 0;
}

// --- WdfMemoryGetBuffer (index 119) ---
static PVOID WINAPI
stub_WdfMemoryGetBuffer(PWDF_DRIVER_GLOBALS DriverGlobals, WDFMEMORY Memory, size_t *BufferSize)
{
    auto *m = (Wdf2Memory*)Memory;
    if (!m) { if (BufferSize) *BufferSize = 0; return nullptr; }
    if (BufferSize) *BufferSize = m->size;
    WDF2_LOG(2, "[WDF2] WdfMemoryGetBuffer -> %p (size=%zu)\n", m->buf, m->size);
    return m->buf;
}

// --- WdfObjectGetTypedContextWorker (index 123) ---
static PVOID WINAPI
stub_WdfObjectGetTypedContextWorker(PWDF_DRIVER_GLOBALS DriverGlobals,
                                     WDFOBJECT Handle, PCWDF_OBJECT_CONTEXT_TYPE_INFO TypeInfo)
{
    auto *obj = (Wdf2Obj*)Handle;
    PVOID ctx = obj ? obj->context : nullptr;
    WDF2_LOG(2, "[WDF2] WdfObjectGetTypedContextWorker(handle=%p) -> %p\n", Handle, ctx);
    return ctx;
}

// --- WdfObjectAllocateContext (index 124) ---
static NTSTATUS WINAPI
stub_WdfObjectAllocateContext(PWDF_DRIVER_GLOBALS DriverGlobals, WDFOBJECT Handle,
                               PWDF_OBJECT_ATTRIBUTES ContextAttributes, PVOID *Context)
{
    auto *obj = (Wdf2Obj*)Handle;
    if (!obj) return 0xC000000DL; // STATUS_INVALID_PARAMETER
    obj->allocContext(ContextAttributes);
    if (Context) *Context = obj->context;
    WDF2_LOG(1, "[WDF2] WdfObjectAllocateContext(handle=%p) -> ctx=%p\n", Handle, obj->context);
    return 0;
}

// --- WdfObjectContextGetObject (index 125) ---
static WDFOBJECT WINAPI
stub_WdfObjectContextGetObject(PWDF_DRIVER_GLOBALS DriverGlobals, PVOID ContextPointer)
{
    // We don't track reverse mapping; return NULL
    WDF2_LOG(2, "[WDF2] WdfObjectContextGetObject(ctx=%p) -> NULL (no reverse map)\n", ContextPointer);
    return nullptr;
}

// --- WdfObjectDelete (index 129) --- no-op (no ref-counting in stub)
static void WINAPI
stub_WdfObjectDelete(PWDF_DRIVER_GLOBALS DriverGlobals, WDFOBJECT Object)
{
    HLOG_USER("[WDF2] WdfObjectDelete(%p) no-op\n", Object);
}

// --- WdfRegistryOpenKey (index 131) ---
static NTSTATUS WINAPI
stub_WdfRegistryOpenKey(PWDF_DRIVER_GLOBALS DriverGlobals, WDFKEY ParentKey,
                         PCUNICODE_STRING KeyName, ACCESS_MASK DesiredAccess,
                         PWDF_OBJECT_ATTRIBUTES KeyAttributes, WDFKEY *Key)
{
    HLOG_USER("[WDF2] WdfRegistryOpenKey -> STATUS_OBJECT_NAME_NOT_FOUND\n");
    return 0xC0000034L;
}

// --- WdfRegistryCreateKey (index 132) --- fail
static NTSTATUS WINAPI
stub_WdfRegistryCreateKey(PWDF_DRIVER_GLOBALS DriverGlobals, WDFKEY ParentKey,
                           PCUNICODE_STRING KeyName, ACCESS_MASK DesiredAccess,
                           ULONG CreateOptions, PULONG CreateDisposition,
                           PWDF_OBJECT_ATTRIBUTES KeyAttributes, WDFKEY *Key)
{
    HLOG_USER("[WDF2] WdfRegistryCreateKey -> STATUS_OBJECT_NAME_NOT_FOUND\n");
    return 0xC0000034L;
}

// --- WdfRegistryClose (index 133) --- no-op
static void WINAPI
stub_WdfRegistryClose(PWDF_DRIVER_GLOBALS DriverGlobals, WDFKEY Key)
{
    HLOG_USER("[WDF2] WdfRegistryClose no-op\n");
}

// --- WdfRegistryQueryULong (index 141) --- not found
static NTSTATUS WINAPI
stub_WdfRegistryQueryULong(PWDF_DRIVER_GLOBALS DriverGlobals, WDFKEY Key,
                            PCUNICODE_STRING ValueName, PULONG Value)
{
    HLOG_USER("[WDF2] WdfRegistryQueryULong -> STATUS_OBJECT_NAME_NOT_FOUND\n");
    return 0xC0000034L;
}

// --- WdfRegistryQueryUnicodeString (index 139) --- not found
static NTSTATUS WINAPI
stub_WdfRegistryQueryUnicodeString(PWDF_DRIVER_GLOBALS DriverGlobals, WDFKEY Key,
                                    PCUNICODE_STRING ValueName,
                                    PUSHORT ValueByteLength, PUNICODE_STRING Value)
{
    HLOG_USER("[WDF2] WdfRegistryQueryUnicodeString -> STATUS_OBJECT_NAME_NOT_FOUND\n");
    return 0xC0000034L;
}

// --- WdfRegistryAssignULong (index 147) --- no-op
static NTSTATUS WINAPI
stub_WdfRegistryAssignULong(PWDF_DRIVER_GLOBALS DriverGlobals, WDFKEY Key,
                             PCUNICODE_STRING ValueName, ULONG Value)
{
    WDF2_LOG(2, "[WDF2] WdfRegistryAssignULong(value=%lu)\n", (unsigned long)Value);
    return 0;
}

// --- WdfRequestGetStatus (index 153) ---
static NTSTATUS WINAPI
stub_WdfRequestGetStatus(PWDF_DRIVER_GLOBALS DriverGlobals, WDFREQUEST Request)
{
    auto *r = (Wdf2Request*)Request;
    NTSTATUS s = r ? r->status : 0;
    WDF2_LOG(2, "[WDF2] WdfRequestGetStatus -> 0x%lx\n", (long)s);
    return s;
}

// --- WdfRequestComplete (index 163) ---
static void WINAPI
stub_WdfRequestComplete(PWDF_DRIVER_GLOBALS DriverGlobals, WDFREQUEST Request,
                         NTSTATUS Status)
{
    HLOG_USER("[WDF2] WdfRequestComplete(%p, 0x%lx)\n", Request, (long)Status);
    auto *r = (Wdf2Request*)Request;
    if (r) { r->status = Status; r->completed = true; }
}

// --- WdfRequestCompleteWithInformation (index 164) ---
static void WINAPI
stub_WdfRequestCompleteWithInformation(PWDF_DRIVER_GLOBALS DriverGlobals,
                                        WDFREQUEST Request, NTSTATUS Status,
                                        ULONG_PTR Information)
{
    HLOG_USER("[WDF2] WdfRequestCompleteWithInformation(%p, 0x%lx, %lu)\n",
              Request, (long)Status, (unsigned long)Information);
    auto *r = (Wdf2Request*)Request;
    if (r) { r->status = Status; r->information = Information; r->completed = true; }
}

// --- WdfRequestGetParameters (index 165) ---
// WDF_REQUEST_PARAMETERS for DeviceIoControl (simplified):
//   +0x00 Size (ULONG), +0x04 MinorFunction (UCHAR), +0x05 Type (UCHAR)
//   +0x08 OutputBufferLength (size_t), +0x10 InputBufferLength (size_t)
//   +0x18 IoControlCode (ULONG), +0x20 Type3InputBuffer (void*)
static void WINAPI
stub_WdfRequestGetParameters(PWDF_DRIVER_GLOBALS DriverGlobals, WDFREQUEST Request,
                              PWDF_REQUEST_PARAMETERS Parameters)
{
    auto *r = (Wdf2Request*)Request;
    WDF2_LOG(1, "[WDF2] WdfRequestGetParameters(ioctl=0x%lx)\n", r ? (long)r->ioctlCode : 0L);
    if (!r || !Parameters) return;
    ULONG sz = *(ULONG*)Parameters;
    if (sz < 4) return;
    memset(Parameters, 0, sz);
    *(ULONG*)((char*)Parameters + 0x00) = sz;
    // Type = WdfRequestTypeDeviceControl = 0x0E
    *((UCHAR*)Parameters + 0x05) = 0x0E;
    if (sz >= 0x1C) {
        *(size_t*)((char*)Parameters + 0x08) = r->outMem ? r->outMem->size : 0;
        *(size_t*)((char*)Parameters + 0x10) = r->inMem  ? r->inMem->size  : 0;
        *(ULONG*) ((char*)Parameters + 0x18) = r->ioctlCode;
    }
}

// --- WdfRequestRetrieveInputMemory (index 166) ---
static NTSTATUS WINAPI
stub_WdfRequestRetrieveInputMemory(PWDF_DRIVER_GLOBALS DriverGlobals,
                                    WDFREQUEST Request, WDFMEMORY *Memory)
{
    auto *r = (Wdf2Request*)Request;
    if (!r || !r->inMem) { WDF2_LOG(2, "[WDF2] WdfRequestRetrieveInputMemory -> UNSUCCESSFUL\n"); return 0xC0000001L; }
    WDF2_LOG(2, "[WDF2] WdfRequestRetrieveInputMemory -> %p (size=%zu)\n", r->inMem->buf, r->inMem->size);
    if (Memory) *Memory = r->inMem;
    return 0;
}

// --- WdfRequestRetrieveOutputMemory (index 167) ---
static NTSTATUS WINAPI
stub_WdfRequestRetrieveOutputMemory(PWDF_DRIVER_GLOBALS DriverGlobals,
                                     WDFREQUEST Request, WDFMEMORY *Memory)
{
    auto *r = (Wdf2Request*)Request;
    if (!r || !r->outMem) { WDF2_LOG(2, "[WDF2] WdfRequestRetrieveOutputMemory -> UNSUCCESSFUL\n"); return 0xC0000001L; }
    WDF2_LOG(2, "[WDF2] WdfRequestRetrieveOutputMemory -> %p (size=%zu)\n", r->outMem->buf, r->outMem->size);
    if (Memory) *Memory = r->outMem;
    return 0;
}

// --- WdfRequestRetrieveInputBuffer (index 168) ---
static NTSTATUS WINAPI
stub_WdfRequestRetrieveInputBuffer(PWDF_DRIVER_GLOBALS DriverGlobals, WDFREQUEST Request,
                                    size_t MinimumRequiredLength,
                                    PVOID *Buffer, size_t *Length)
{
    auto *r = (Wdf2Request*)Request;
    if (!r || !r->inMem) { WDF2_LOG(2, "[WDF2] WdfRequestRetrieveInputBuffer -> UNSUCCESSFUL\n"); return 0xC0000001L; }
    WDF2_LOG(2, "[WDF2] WdfRequestRetrieveInputBuffer -> %p (size=%zu)\n", r->inMem->buf, r->inMem->size);
    if (Buffer) *Buffer = r->inMem->buf;
    if (Length) *Length = r->inMem->size;
    return 0;
}

// --- WdfRequestRetrieveOutputBuffer (index 169) ---
static NTSTATUS WINAPI
stub_WdfRequestRetrieveOutputBuffer(PWDF_DRIVER_GLOBALS DriverGlobals, WDFREQUEST Request,
                                     size_t MinimumRequiredSize,
                                     PVOID *Buffer, size_t *Length)
{
    auto *r = (Wdf2Request*)Request;
    if (!r || !r->outMem) { WDF2_LOG(2, "[WDF2] WdfRequestRetrieveOutputBuffer -> UNSUCCESSFUL\n"); return 0xC0000001L; }
    WDF2_LOG(2, "[WDF2] WdfRequestRetrieveOutputBuffer -> %p (size=%zu)\n", r->outMem->buf, r->outMem->size);
    if (Buffer) *Buffer = r->outMem->buf;
    if (Length) *Length = r->outMem->size;
    return 0;
}

// --- WdfRequestSetInformation (index 170) ---
static void WINAPI
stub_WdfRequestSetInformation(PWDF_DRIVER_GLOBALS DriverGlobals, WDFREQUEST Request,
                               ULONG_PTR Information)
{
    WDF2_LOG(2, "[WDF2] WdfRequestSetInformation(info=%lu)\n", (unsigned long)Information);
    auto *r = (Wdf2Request*)Request;
    if (r) r->information = Information;
}

// --- WdfRequestGetInformation (index 171) ---
static ULONG_PTR WINAPI
stub_WdfRequestGetInformation(PWDF_DRIVER_GLOBALS DriverGlobals, WDFREQUEST Request)
{
    auto *r = (Wdf2Request*)Request;
    ULONG_PTR info = r ? r->information : 0;
    WDF2_LOG(2, "[WDF2] WdfRequestGetInformation -> %lu\n", (unsigned long)info);
    return info;
}

// --- WdfRequestForwardToIoQueue (index 174) ---
static NTSTATUS WINAPI
stub_WdfRequestForwardToIoQueue(PWDF_DRIVER_GLOBALS DriverGlobals, WDFREQUEST Request,
                                 WDFQUEUE DestinationQueue)
{
    HLOG_USER("[WDF2] WdfRequestForwardToIoQueue no-op\n");
    return 0;
}

// --- WdfRequestGetIoQueue (index 175) ---
static WDFQUEUE WINAPI
stub_WdfRequestGetIoQueue(PWDF_DRIVER_GLOBALS DriverGlobals, WDFREQUEST Request)
{
    auto *r = (Wdf2Request*)Request;
    WDFQUEUE q = r ? r->queue : nullptr;
    WDF2_LOG(2, "[WDF2] WdfRequestGetIoQueue -> %p\n", q);
    return q;
}

// --- WdfCmResourceListGetCount (index 186) ---
static ULONG WINAPI
stub_WdfCmResourceListGetCount(PWDF_DRIVER_GLOBALS DriverGlobals, WDFCMRESLIST List)
{
    WDF2_LOG(1, "[WDF2] WdfCmResourceListGetCount -> 0 (empty)\n");
    return 0; // empty resource list
}

// --- WdfCmResourceListGetDescriptor (index 187) ---
static PVOID WINAPI
stub_WdfCmResourceListGetDescriptor(PWDF_DRIVER_GLOBALS DriverGlobals,
                                     WDFCMRESLIST List, ULONG Index)
{
    WDF2_LOG(1, "[WDF2] WdfCmResourceListGetDescriptor(idx=%lu) -> NULL\n", (unsigned long)Index);
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

// ---------------------------------------------------------------------------
// WinUSB / real-device globals and helpers
// ---------------------------------------------------------------------------
static HANDLE                  g_wdf2DevFile      = INVALID_HANDLE_VALUE;
static WINUSB_INTERFACE_HANDLE g_wdf2WinusbHandle = NULL;
typedef void (WINAPI *wdf2_usb_read_cb_t)(WDFUSBPIPE, WDFMEMORY, size_t, WDFCONTEXT);
static wdf2_usb_read_cb_t g_wdf2ContReadCb     = NULL;
static WDFCONTEXT         g_wdf2ContReadCtx    = NULL;
static size_t             g_wdf2ContReadBufLen = 0;
static WDFUSBPIPE         g_wdf2ContReadPipe   = NULL;

// Opens the real USB device via WinUsb_Initialize, stores handle in globals.
// Writes the "VID:PID\r\n" text to a temp file so the Wine unix-lib can find it.
static void wdf2_open_winusb_device(USHORT vid, USHORT pid)
{
    if (g_wdf2WinusbHandle != NULL) return;  // already open

    // Write VID:PID to a temp file that the Wine WinUSB unix-lib reads via
    // ReadFile(DeviceHandle, buf, ...) — the file acts as the device path.
    char vidpid[32];
    snprintf(vidpid, sizeof(vidpid), "%04x:%04x\r\n", vid, pid);
    char tmpPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tmpPath);
    strncat(tmpPath, "wdf2_usb_dev.txt", sizeof(tmpPath) - strlen(tmpPath) - 1);
    {
        FILE *fp = fopen(tmpPath, "wt");
        if (fp) { fputs(vidpid, fp); fclose(fp); }
    }
    WCHAR wPath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, tmpPath, -1, wPath, MAX_PATH);
    g_wdf2DevFile = CreateFileW(wPath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED, NULL);
    if (g_wdf2DevFile == INVALID_HANDLE_VALUE) {
        HLOG_USER("[WDF2] wdf2_open_winusb_device: CreateFileW failed err=%lu\n", GetLastError());
        return;
    }
    WINUSB_INTERFACE_HANDLE h = NULL;
    if (!WinUsb_Initialize(g_wdf2DevFile, &h)) {
        HLOG_USER("[WDF2] wdf2_open_winusb_device: WinUsb_Initialize failed err=%lu\n", GetLastError());
        CloseHandle(g_wdf2DevFile);
        g_wdf2DevFile = INVALID_HANDLE_VALUE;
        return;
    }
    g_wdf2WinusbHandle = h;
    HLOG_USER("[WDF2] WinUSB opened %04x:%04x handle=%p\n", vid, pid, (void*)h);
}

// Reads buffer pointer+length from a WDF_MEMORY_DESCRIPTOR (raw offsets, 64-bit).
// Type field at +0x00 (ULONG):
//   1 = buffer (ptr at +0x08, len at +0x10)
//   3 = WDFMEMORY handle (at +0x08; use WdfMemoryGetBuffer)
static BOOL wdf2_get_memdesc_buffer(const void *mdesc, void **buf, ULONG *len)
{
    if (!mdesc) return FALSE;
    ULONG type;
    memcpy(&type, (const char*)mdesc + 0x00, 4);
    if (type == 1) {
        memcpy(buf, (const char*)mdesc + 0x08, 8);
        memcpy(len, (const char*)mdesc + 0x10, 4);
        return TRUE;
    }
    if (type == 3) {
        void *hmem = NULL;
        memcpy(&hmem, (const char*)mdesc + 0x08, 8);
        if (!hmem) return FALSE;
        auto *m = (Wdf2Memory*)hmem;
        *buf = m->buf;
        *len = (ULONG)m->size;
        return TRUE;
    }
    return FALSE;
}

// --- WdfUsbTargetPipeWriteSynchronously (UMDF v2 index 221) ---
// Writes to the USB pipe identified by Pipe->endpointAddr (should be EP 0x01 OUT).
static NTSTATUS WINAPI
stub_WdfUsbTargetPipeWriteSynchronously(PWDF_DRIVER_GLOBALS DriverGlobals,
    WDFUSBPIPE Pipe, WDFREQUEST Request,
    void *RequestOptions,
    void *MemoryDescriptor,
    PULONG_PTR BytesWritten)
{
    Wdf2UsbPipe *p = (Wdf2UsbPipe*)Pipe;
    UCHAR ep = p ? p->endpointAddr : 0;
    void *buf = NULL; ULONG len = 0;
    if (!wdf2_get_memdesc_buffer(MemoryDescriptor, &buf, &len)) {
        HLOG_USER("[WDF2] WdfUsbTargetPipeWriteSynchronously ep=0x%02x: bad MemoryDescriptor\n", ep);
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_wdf2WinusbHandle) {
        HLOG_USER("[WDF2] WdfUsbTargetPipeWriteSynchronously ep=0x%02x: no WinUSB handle\n", ep);
        return (NTSTATUS)0xC000009DL;
    }
    ULONG transferred = 0;
    { ULONG _i; HLOG_USER("[WDF2] WdfUsbTargetPipeWriteSynchronously ep=0x%02x len=%lu data:", ep, (unsigned long)len);
      for(_i=0;_i<len&&_i<64;_i++) HLOG_USER(" %02x", ((unsigned char*)buf)[_i]);
      HLOG_USER("\n"); }
    BOOL ok = WinUsb_WritePipe(g_wdf2WinusbHandle, ep, (PUCHAR)buf, len, &transferred, NULL);
    HLOG_USER("[WDF2] WdfUsbTargetPipeWriteSynchronously ep=0x%02x len=%lu -> ok=%d transferred=%lu err=%lu\n",
              ep, (unsigned long)len, ok, (unsigned long)transferred, ok ? 0UL : (unsigned long)GetLastError());
    if (BytesWritten) *BytesWritten = transferred;
    return ok ? 0 : (NTSTATUS)0xC0000185L;
}

// --- WdfUsbTargetPipeReadSynchronously (UMDF v2 index 223) ---
// Reads from the USB pipe identified by Pipe->endpointAddr (should be EP 0x83 IN).
static NTSTATUS WINAPI
stub_WdfUsbTargetPipeReadSynchronously(PWDF_DRIVER_GLOBALS DriverGlobals,
    WDFUSBPIPE Pipe, WDFREQUEST Request,
    void *RequestOptions,
    void *MemoryDescriptor,
    PULONG_PTR BytesRead)
{
    Wdf2UsbPipe *p = (Wdf2UsbPipe*)Pipe;
    UCHAR ep = p ? p->endpointAddr : 0;
    void *buf = NULL; ULONG len = 0;
    if (!wdf2_get_memdesc_buffer(MemoryDescriptor, &buf, &len)) {
        HLOG_USER("[WDF2] WdfUsbTargetPipeReadSynchronously ep=0x%02x: bad MemoryDescriptor\n", ep);
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_wdf2WinusbHandle) {
        HLOG_USER("[WDF2] WdfUsbTargetPipeReadSynchronously ep=0x%02x: no WinUSB handle\n", ep);
        return (NTSTATUS)0xC000009DL;
    }
    ULONG transferred = 0;
    BOOL ok = WinUsb_ReadPipe(g_wdf2WinusbHandle, ep, (PUCHAR)buf, len, &transferred, NULL);
    HLOG_USER("[WDF2] WdfUsbTargetPipeReadSynchronously ep=0x%02x len=%lu -> ok=%d transferred=%lu err=%lu\n",
              ep, (unsigned long)len, ok, (unsigned long)transferred, ok ? 0UL : (unsigned long)GetLastError());
    if (BytesRead) *BytesRead = transferred;
    return ok ? 0 : (NTSTATUS)0xC0000185L;
}

// --- WdfIoTargetSendReadSynchronously (index 182) ---
// Calls WinUsb_ReadPipe on the bulk-in endpoint (EP 0x83).
static NTSTATUS WINAPI
stub_WdfIoTargetSendReadSynchronously(PWDF_DRIVER_GLOBALS DriverGlobals,
    WDFIOTARGET IoTarget, WDFREQUEST Request,
    PLONGLONG RequestOptions,
    void *MemoryDescriptor,
    PLONGLONG StartingOffset, PULONG_PTR BytesRead)
{
    void *buf = NULL; ULONG len = 0;
    if (!wdf2_get_memdesc_buffer(MemoryDescriptor, &buf, &len)) {
        HLOG_USER("[WDF2] WdfIoTargetSendReadSynchronously: bad MemoryDescriptor\n");
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_wdf2WinusbHandle) {
        HLOG_USER("[WDF2] WdfIoTargetSendReadSynchronously: no WinUSB handle\n");
        return (NTSTATUS)0xC000009DL; // STATUS_DEVICE_NOT_CONNECTED
    }
    ULONG transferred = 0;
    BOOL ok = WinUsb_ReadPipe(g_wdf2WinusbHandle, 0x83, (PUCHAR)buf, len, &transferred, NULL);
    HLOG_USER("[WDF2] WdfIoTargetSendReadSynchronously ep=0x83 len=%lu -> ok=%d transferred=%lu err=%lu\n",
              (unsigned long)len, ok, (unsigned long)transferred, ok ? 0UL : (unsigned long)GetLastError());
    if (BytesRead) *BytesRead = transferred;
    return ok ? 0 : (NTSTATUS)0xC0000185L; // STATUS_IO_DEVICE_ERROR
}

// --- WdfIoTargetSendWriteSynchronously (index 184) ---
// Calls WinUsb_WritePipe on the bulk-out endpoint (EP 0x01).
static NTSTATUS WINAPI
stub_WdfIoTargetSendWriteSynchronously(PWDF_DRIVER_GLOBALS DriverGlobals,
    WDFIOTARGET IoTarget, WDFREQUEST Request,
    PLONGLONG RequestOptions,
    void *MemoryDescriptor,
    PLONGLONG StartingOffset, PULONG_PTR BytesWritten)
{
    void *buf = NULL; ULONG len = 0;
    if (!wdf2_get_memdesc_buffer(MemoryDescriptor, &buf, &len)) {
        HLOG_USER("[WDF2] WdfIoTargetSendWriteSynchronously: bad MemoryDescriptor\n");
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_wdf2WinusbHandle) {
        HLOG_USER("[WDF2] WdfIoTargetSendWriteSynchronously: no WinUSB handle\n");
        return (NTSTATUS)0xC000009DL; // STATUS_DEVICE_NOT_CONNECTED
    }
    ULONG transferred = 0;
    BOOL ok = WinUsb_WritePipe(g_wdf2WinusbHandle, 0x01, (PUCHAR)buf, len, &transferred, NULL);
    HLOG_USER("[WDF2] WdfIoTargetSendWriteSynchronously ep=0x01 len=%lu -> ok=%d transferred=%lu err=%lu\n",
              (unsigned long)len, ok, (unsigned long)transferred, ok ? 0UL : (unsigned long)GetLastError());
    if (BytesWritten) *BytesWritten = transferred;
    return ok ? 0 : (NTSTATUS)0xC0000185L; // STATUS_IO_DEVICE_ERROR
}

// Forward declaration for cont-reader helper defined after Wdf2UsbPipe
static void wdf2_maybe_start_cont_reader(WDFIOTARGET IoTarget);

// --- WdfUsbTargetDeviceCreate (index 202) ---
static NTSTATUS WINAPI
stub_WdfUsbTargetDeviceCreate(PWDF_DRIVER_GLOBALS DriverGlobals, WDFDEVICE Device,
                               PWDF_OBJECT_ATTRIBUTES Attributes, WDFUSBDEVICE *UsbDevice)
{
    // Parse USB_ID env var (format "vid:pid") for VID/PID, default = Goodix 27c6:6594
    USHORT vid = 0x27c6, pid = 0x6594;
    const char *usb_id = getenv("USB_ID");
    if (usb_id) sscanf(usb_id, "%hx:%hx", &vid, &pid);

    g_wdf2UsbDev.idVendor  = vid;
    g_wdf2UsbDev.idProduct = pid;
    // Two bulk endpoints: 0x81 bulk-in, 0x01 bulk-out
    g_wdf2UsbDev.iface.numPipes   = 2;
    g_wdf2UsbDev.iface.pipes[0]   = { 0x83, 64, 3 };  // bulk-in EP 3
    g_wdf2UsbDev.iface.pipes[1]   = { 0x01, 64, 3 };  // bulk-out EP 1

    // Open the real device via WinUSB (idempotent)
    wdf2_open_winusb_device(vid, pid);

    HLOG_USER("[WDF2] WdfUsbTargetDeviceCreate -> %04x:%04x (2 bulk pipes)\n", vid, pid);
    if (UsbDevice) *UsbDevice = &g_wdf2UsbDev;
    return 0;
}

// --- WdfUsbTargetDeviceRetrieveInformation (index 204) ---
// Fills WDF_USB_DEVICE_INFORMATION: Size, USBD_Version, Supported_USB_Version,
// HcdPortCapabilities, Traits
static NTSTATUS WINAPI
stub_WdfUsbTargetDeviceRetrieveInformation(PWDF_DRIVER_GLOBALS DriverGlobals,
                                            WDFUSBDEVICE UsbDevice,
                                            PWDF_USB_DEVICE_INFORMATION Information)
{
    WDF2_LOG(1, "[WDF2] WdfUsbTargetDeviceRetrieveInformation\n");
    if (Information) {
        ULONG sz = *(ULONG*)Information;
        if (sz >= 20) {
            memset(Information, 0, sz);
            *(ULONG*)((char*)Information + 0)  = sz;          // Size
            *(ULONG*)((char*)Information + 4)  = 0x00050000;  // USBD_Version (5.0 = WinXP+)
            *(ULONG*)((char*)Information + 8)  = 0x00000200;  // Supported_USB_Version (USB 2.0)
            *(ULONG*)((char*)Information + 12) = 0;           // HcdPortCapabilities
            *(ULONG*)((char*)Information + 16) = 2;           // Traits: WDF_USB_DEVICE_TRAIT_AT_HIGH_SPEED
        }
    }
    return 0;
}

// --- WdfUsbTargetDeviceGetDeviceDescriptor (index 205) --- void return
static void WINAPI
stub_WdfUsbTargetDeviceGetDeviceDescriptor(PWDF_DRIVER_GLOBALS DriverGlobals,
                                            WDFUSBDEVICE UsbDevice,
                                            PUSB_DEVICE_DESCRIPTOR UsbDeviceDescriptor)
{
    auto *ud = (Wdf2UsbDevice*)UsbDevice;
    HLOG_USER("[WDF2] WdfUsbTargetDeviceGetDeviceDescriptor -> %04x:%04x\n",
              ud ? ud->idVendor : 0, ud ? ud->idProduct : 0);
    if (!UsbDeviceDescriptor) return;
    // USB_DEVICE_DESCRIPTOR layout (18 bytes)
    UCHAR *d = (UCHAR*)UsbDeviceDescriptor;
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
stub_WdfUsbTargetDeviceGetNumInterfaces(PWDF_DRIVER_GLOBALS DriverGlobals,
                                         WDFUSBDEVICE UsbDevice)
{
    HLOG_USER("[WDF2] WdfUsbTargetDeviceGetNumInterfaces -> 1\n");
    return 1;
}

// --- WdfUsbTargetDeviceSelectConfig (index 211) ---
// Output (for SingleInterface): Types.SingleInterface.NumberConfiguredPipes (at +8)
//                               Types.SingleInterface.ConfiguredUsbInterface (at +16)
static NTSTATUS WINAPI
stub_WdfUsbTargetDeviceSelectConfig(PWDF_DRIVER_GLOBALS DriverGlobals,
                                    WDFUSBDEVICE UsbDevice,
                                    PWDF_OBJECT_ATTRIBUTES PipeAttributes,
                                    PWDF_USB_DEVICE_SELECT_CONFIG_PARAMS Params)
{
    auto *ud = (Wdf2UsbDevice*)UsbDevice;
    HLOG_USER("[WDF2] WdfUsbTargetDeviceSelectConfig\n");
    if (Params && ud) {
        // Types union starts at offset 8; SingleInterface layout:
        //   +0 (=+8):  NumberConfiguredPipes (UCHAR)
        //   +8 (=+16): ConfiguredUsbInterface (ptr, 8-byte aligned)
        *((UCHAR*)Params + 8)         = ud->iface.numPipes;
        *(void**)((char*)Params + 16) = &ud->iface;
    }
    return 0;
}

// --- WdfUsbTargetPipeGetInformation (index 216) --- void return
// WDF_USB_PIPE_INFORMATION: Size(+0), MaxPacketSize(+4), EndpointAddr(+8),
//   Interval(+9), SettingIndex(+10), PipeType(+12), MaxTransferSize(+16)
static void WINAPI
stub_WdfUsbTargetPipeGetInformation(PWDF_DRIVER_GLOBALS DriverGlobals, WDFUSBPIPE Pipe,
                                     PWDF_USB_PIPE_INFORMATION PipeInformation)
{
    auto *p = (Wdf2UsbPipe*)Pipe;
    WDF2_LOG(1, "[WDF2] WdfUsbTargetPipeGetInformation(pipe=%p ep=0x%02x)\n",
             Pipe, p ? p->endpointAddr : 0);
    if (!PipeInformation || !p) return;
    ULONG sz = *(ULONG*)PipeInformation;
    if (sz < 20) return;
    memset(PipeInformation, 0, sz);
    *(ULONG*)((char*)PipeInformation + 0)  = sz;
    *(ULONG*)((char*)PipeInformation + 4)  = p->maxPacketSize;
    *((UCHAR*)PipeInformation + 8)         = p->endpointAddr;
    *((UCHAR*)PipeInformation + 9)         = 0;   // Interval
    *((UCHAR*)PipeInformation + 10)        = 0;   // SettingIndex
    *(ULONG*)((char*)PipeInformation + 12) = p->pipeType;
    *(ULONG*)((char*)PipeInformation + 16) = 4096; // MaximumTransferSize
}

// --- WdfUsbTargetPipeIsInEndpoint (index 217) --- returns BOOLEAN
static UCHAR WINAPI
stub_WdfUsbTargetPipeIsInEndpoint(PWDF_DRIVER_GLOBALS DriverGlobals, WDFUSBPIPE Pipe)
{
    auto *p = (Wdf2UsbPipe*)Pipe;
    UCHAR r = (p && (p->endpointAddr & 0x80)) ? 1 : 0;
    WDF2_LOG(2, "[WDF2] WdfUsbTargetPipeIsInEndpoint(ep=0x%02x) -> %u\n",
             p ? p->endpointAddr : 0, r);
    return r;
}

// --- WdfUsbTargetPipeIsOutEndpoint (index 218) --- returns BOOLEAN
static UCHAR WINAPI
stub_WdfUsbTargetPipeIsOutEndpoint(PWDF_DRIVER_GLOBALS DriverGlobals, WDFUSBPIPE Pipe)
{
    auto *p = (Wdf2UsbPipe*)Pipe;
    UCHAR r = (p && !(p->endpointAddr & 0x80)) ? 1 : 0;
    WDF2_LOG(2, "[WDF2] WdfUsbTargetPipeIsOutEndpoint(ep=0x%02x) -> %u\n",
             p ? p->endpointAddr : 0, r);
    return r;
}

// --- WdfUsbTargetPipeSetNoMaximumPacketSizeCheck (index 220) --- void, no-op
static void WINAPI
stub_WdfUsbTargetPipeSetNoMaximumPacketSizeCheck(PWDF_DRIVER_GLOBALS DriverGlobals,
                                                   WDFUSBPIPE Pipe)
{
    WDF2_LOG(2, "[WDF2] WdfUsbTargetPipeSetNoMaximumPacketSizeCheck no-op\n");
}

// Continuous reader thread: loops reading from EP 0x83, calling g_wdf2ContReadCb
static DWORD WINAPI wdf2_cont_reader_thread(LPVOID)
{
    size_t bufLen = g_wdf2ContReadBufLen > 0 ? g_wdf2ContReadBufLen : 512;
    HLOG_USER("[WDF2] cont_reader_thread started ep=0x83 bufLen=%zu\n", bufLen);
    void *buf = malloc(bufLen);
    if (!buf) { HLOG_USER("[WDF2] cont_reader_thread: malloc failed\n"); return 1; }
    while (g_wdf2ContReadCb) {
        ULONG transferred = 0;
        BOOL ok = WinUsb_ReadPipe(g_wdf2WinusbHandle, 0x83, (PUCHAR)buf, (ULONG)bufLen, &transferred, NULL);
        HLOG_USER("[WDF2] cont_reader_thread: ok=%d transferred=%lu err=%lu\n",
                  ok, (unsigned long)transferred, ok ? 0UL : (unsigned long)GetLastError());
        if (ok && transferred > 0 && g_wdf2ContReadCb) {
            { ULONG _i; HLOG_USER("[WDF2] cont_reader ep=0x83 got %lu bytes:", transferred);
              for(_i=0;_i<transferred&&_i<32;_i++) HLOG_USER(" %02x", ((unsigned char*)buf)[_i]);
              if(transferred>32) HLOG_USER("..."); HLOG_USER("\n"); }
            auto *m = new Wdf2Memory();
            m->buf = malloc(transferred); m->size = transferred; m->owner = true;
            if (m->buf) memcpy(m->buf, buf, transferred);
            g_wdf2ContReadCb(g_wdf2ContReadPipe, (WDFMEMORY)m, transferred, g_wdf2ContReadCtx);
        } else if (!ok) {
            HLOG_USER("[WDF2] cont_reader_thread: read failed, retrying in 200ms\n");
            Sleep(200);
        }
    }
    free(buf);
    HLOG_USER("[WDF2] cont_reader_thread exiting\n");
    return 0;
}

static void wdf2_start_cont_reader(WDFUSBPIPE pipe)
{
    g_wdf2ContReadPipe = pipe;
    HLOG_USER("[WDF2] wdf2_start_cont_reader: spawning thread\n");
    CreateThread(NULL, 0, wdf2_cont_reader_thread, NULL, 0, NULL);
}

// --- WdfUsbTargetPipeConfigContinuousReader (index 225) ---
static NTSTATUS WINAPI
stub_WdfUsbTargetPipeConfigContinuousReader(PWDF_DRIVER_GLOBALS DriverGlobals,
                                             WDFUSBPIPE Pipe,
                                             PWDF_USB_CONTINUOUS_READER_CONFIG Config)
{
    if (Config) {
        const char *c = (const char*)Config;
        size_t transferLen = 0;
        void *cb = NULL, *ctx = NULL;
        memcpy(&transferLen, c + 0x08, sizeof(size_t));
        memcpy(&cb,          c + 0x30, sizeof(void*));
        memcpy(&ctx,         c + 0x38, sizeof(void*));
        g_wdf2ContReadCb     = (wdf2_usb_read_cb_t)cb;
        g_wdf2ContReadCtx    = (WDFCONTEXT)ctx;
        g_wdf2ContReadBufLen = transferLen ? transferLen : 512;
    }
    HLOG_USER("[WDF2] WdfUsbTargetPipeConfigContinuousReader pipe=%p cb=%p bufLen=%zu\n",
              (void*)Pipe, (void*)(void*)g_wdf2ContReadCb, g_wdf2ContReadBufLen);
    return 0;
}

// --- WdfUsbTargetDeviceGetInterface (index 236) ---
static WDFUSBINTERFACE WINAPI
stub_WdfUsbTargetDeviceGetInterface(PWDF_DRIVER_GLOBALS DriverGlobals,
                                     WDFUSBDEVICE UsbDevice, UCHAR InterfaceIndex)
{
    auto *ud = (Wdf2UsbDevice*)UsbDevice;
    HLOG_USER("[WDF2] WdfUsbTargetDeviceGetInterface(idx=%u)\n", (unsigned)InterfaceIndex);
    return (ud && InterfaceIndex == 0) ? (WDFUSBINTERFACE)&ud->iface : nullptr;
}

// --- WdfUsbInterfaceGetNumConfiguredPipes (index 238) --- returns UCHAR
static UCHAR WINAPI
stub_WdfUsbInterfaceGetNumConfiguredPipes(PWDF_DRIVER_GLOBALS DriverGlobals,
                                           WDFUSBINTERFACE UsbInterface)
{
    auto *i = (Wdf2UsbInterface*)UsbInterface;
    UCHAR n = i ? i->numPipes : 0;
    HLOG_USER("[WDF2] WdfUsbInterfaceGetNumConfiguredPipes -> %u\n", (unsigned)n);
    return n;
}

// --- WdfUsbInterfaceGetConfiguredPipe (index 239) ---
static WDFUSBPIPE WINAPI
stub_WdfUsbInterfaceGetConfiguredPipe(PWDF_DRIVER_GLOBALS DriverGlobals,
                                       WDFUSBINTERFACE UsbInterface, UCHAR PipeIndex,
                                       PWDF_USB_PIPE_INFORMATION PipeInfo)
{
    auto *i = (Wdf2UsbInterface*)UsbInterface;
    if (!i || PipeIndex >= i->numPipes) {
        HLOG_USER("[WDF2] WdfUsbInterfaceGetConfiguredPipe(idx=%u) -> NULL\n", (unsigned)PipeIndex);
        return nullptr;
    }
    auto *p = &i->pipes[PipeIndex];
    HLOG_USER("[WDF2] WdfUsbInterfaceGetConfiguredPipe(idx=%u) -> ep=0x%02x\n",
              (unsigned)PipeIndex, p->endpointAddr);
    if (PipeInfo) stub_WdfUsbTargetPipeGetInformation(DriverGlobals, (WDFUSBPIPE)p, PipeInfo);
    return (WDFUSBPIPE)p;
}

// Post-Wdf2UsbPipe: continuous reader start helper
static void wdf2_maybe_start_cont_reader(WDFIOTARGET IoTarget)
{
    if (!IoTarget || !g_wdf2ContReadCb || !g_wdf2WinusbHandle) return;
    // Check if this is the bulk-in pipe (EP 0x83, pipes[0])
    auto *p = (Wdf2UsbPipe*)IoTarget;
    bool isBulkIn = (p == &g_wdf2UsbDev.iface.pipes[0] && p->endpointAddr == 0x83);
    HLOG_USER("[WDF2] wdf2_maybe_start_cont_reader: target=%p isBulkIn=%d\n",
              (void*)IoTarget, (int)isBulkIn);
    if (isBulkIn) wdf2_start_cont_reader((WDFUSBPIPE)p);
}

// Catch-all for unimplemented WDF table slots.
// Per-slot unimplemented stub: each index N gets its own instantiation so
// the log shows the exact slot number.
template<int N>
struct WdfUnimplSlot {
    static NTSTATUS WINAPI stub(PWDF_DRIVER_GLOBALS, ...) {
        HLOG_USER("[WDF2] UNIMPL slot [%d] called\n", N);
        return 0;
    }
};

// WDF function table: struct with constructor so slots are filled at static-init
// time without an explicit fill_wdf2_table() call.  Slots not listed explicitly
// default to the per-index WdfUnimplSlot<N>::stub via fill_defaults<N>().
struct Wdf2FunctionTable {
    WDFFUNC fn[257];
    template<int N> void fill_defaults() {
        fn[N] = (WDFFUNC)WdfUnimplSlot<N>::stub;
        fill_defaults<N-1>();
    }
    Wdf2FunctionTable() {
        fill_defaults<256>();
        fn[13]  = (WDFFUNC)stub_WdfDeviceSetDeviceState;
        fn[14]  = (WDFFUNC)stub_WdfDeviceGetDriver;
        fn[16]  = (WDFFUNC)stub_WdfDeviceAssignS0IdleSettings;
        fn[17]  = (WDFFUNC)stub_WdfDeviceAssignSxWakeSettings;
        fn[18]  = (WDFFUNC)stub_WdfDeviceOpenRegistryKey;
        fn[19]  = (WDFFUNC)stub_WdfDeviceInitSetPnpPowerEventCallbacks;
        fn[20]  = (WDFFUNC)stub_WdfDeviceInitSetPowerPolicyEventCallbacks;
        fn[21]  = (WDFFUNC)stub_WdfDeviceInitSetPowerPolicyOwnership;
        fn[22]  = (WDFFUNC)stub_WdfDeviceInitSetIoType;
        fn[23]  = (WDFFUNC)stub_WdfDeviceInitSetFileObjectConfig;
        fn[24]  = (WDFFUNC)stub_WdfDeviceInitSetRequestAttributes;
        fn[25]  = (WDFFUNC)stub_WdfDeviceCreate;
        fn[26]  = (WDFFUNC)stub_WdfDeviceSetStaticStopRemove;
        fn[27]  = (WDFFUNC)stub_WdfDeviceCreateDeviceInterface;
        fn[28]  = (WDFFUNC)stub_WdfDeviceSetDeviceInterfaceState;
        fn[31]  = (WDFFUNC)stub_WdfDeviceQueryProperty;
        fn[33]  = (WDFFUNC)stub_WdfDeviceSetPnpCapabilities;
        fn[34]  = (WDFFUNC)stub_WdfDeviceSetPowerCapabilities;
        fn[35]  = (WDFFUNC)stub_WdfDeviceSetFailed;
        fn[36]  = (WDFFUNC)stub_WdfDeviceStopIdleNoTrack;
        fn[37]  = (WDFFUNC)stub_WdfDeviceResumeIdleNoTrack;
        fn[39]  = (WDFFUNC)stub_WdfDeviceGetDefaultQueue;
        fn[41]  = (WDFFUNC)stub_WdfDeviceGetSystemPowerAction;
        fn[43]  = (WDFFUNC)stub_WdfDeviceInitSetIoTypeEx;
        fn[57]  = (WDFFUNC)stub_WdfDriverCreate;
        fn[58]  = (WDFFUNC)stub_WdfDriverGetRegistryPath;
        fn[59]  = (WDFFUNC)stub_WdfDriverOpenParametersRegistryKey;
        fn[85]  = (WDFFUNC)stub_WdfIoQueueCreate;
        fn[87]  = (WDFFUNC)stub_WdfIoQueueStart;
        fn[88]  = (WDFFUNC)stub_WdfIoQueueStop;
        fn[90]  = (WDFFUNC)stub_WdfIoQueueGetDevice;
        fn[102] = (WDFFUNC)stub_WdfIoTargetCreate;
        fn[103] = (WDFFUNC)stub_WdfIoTargetOpen;
        fn[104] = (WDFFUNC)stub_WdfIoTargetCloseForQueryRemove;
        fn[105] = (WDFFUNC)stub_WdfIoTargetClose;
        fn[106] = (WDFFUNC)stub_WdfIoTargetStart;
        fn[107] = (WDFFUNC)stub_WdfIoTargetStop;
        fn[110] = (WDFFUNC)stub_WdfIoTargetGetDevice;
        fn[117] = (WDFFUNC)stub_WdfMemoryCreate;
        fn[118] = (WDFFUNC)stub_WdfMemoryCreatePreallocated;
        fn[119] = (WDFFUNC)stub_WdfMemoryGetBuffer;
        fn[123] = (WDFFUNC)stub_WdfObjectGetTypedContextWorker;
        fn[124] = (WDFFUNC)stub_WdfObjectAllocateContext;
        fn[125] = (WDFFUNC)stub_WdfObjectContextGetObject;
        fn[129] = (WDFFUNC)stub_WdfObjectDelete;
        fn[131] = (WDFFUNC)stub_WdfRegistryOpenKey;
        fn[132] = (WDFFUNC)stub_WdfRegistryCreateKey;
        fn[133] = (WDFFUNC)stub_WdfRegistryClose;
        fn[139] = (WDFFUNC)stub_WdfRegistryQueryUnicodeString;
        fn[141] = (WDFFUNC)stub_WdfRegistryQueryULong;
        fn[147] = (WDFFUNC)stub_WdfRegistryAssignULong;
        fn[153] = (WDFFUNC)stub_WdfRequestGetStatus;
        fn[163] = (WDFFUNC)stub_WdfRequestComplete;
        fn[164] = (WDFFUNC)stub_WdfRequestCompleteWithInformation;
        fn[165] = (WDFFUNC)stub_WdfRequestGetParameters;
        fn[166] = (WDFFUNC)stub_WdfRequestRetrieveInputMemory;
        fn[167] = (WDFFUNC)stub_WdfRequestRetrieveOutputMemory;
        fn[168] = (WDFFUNC)stub_WdfRequestRetrieveInputBuffer;
        fn[169] = (WDFFUNC)stub_WdfRequestRetrieveOutputBuffer;
        fn[170] = (WDFFUNC)stub_WdfRequestSetInformation;
        fn[171] = (WDFFUNC)stub_WdfRequestGetInformation;
        fn[174] = (WDFFUNC)stub_WdfRequestForwardToIoQueue;
        fn[175] = (WDFFUNC)stub_WdfRequestGetIoQueue;
        fn[111] = (WDFFUNC)stub_WdfIoTargetSendReadSynchronously;
        fn[113] = (WDFFUNC)stub_WdfIoTargetSendWriteSynchronously;
        fn[186] = (WDFFUNC)stub_WdfCmResourceListGetCount;
        fn[187] = (WDFFUNC)stub_WdfCmResourceListGetDescriptor;
        fn[221] = (WDFFUNC)stub_WdfUsbTargetPipeWriteSynchronously;
        fn[223] = (WDFFUNC)stub_WdfUsbTargetPipeReadSynchronously;
        fn[202] = (WDFFUNC)stub_WdfUsbTargetDeviceCreate;
        fn[204] = (WDFFUNC)stub_WdfUsbTargetDeviceRetrieveInformation;
        fn[205] = (WDFFUNC)stub_WdfUsbTargetDeviceGetDeviceDescriptor;
        fn[210] = (WDFFUNC)stub_WdfUsbTargetDeviceGetNumInterfaces;
        fn[211] = (WDFFUNC)stub_WdfUsbTargetDeviceSelectConfig;
        fn[216] = (WDFFUNC)stub_WdfUsbTargetPipeGetInformation;
        fn[217] = (WDFFUNC)stub_WdfUsbTargetPipeIsInEndpoint;
        fn[218] = (WDFFUNC)stub_WdfUsbTargetPipeIsOutEndpoint;
        fn[220] = (WDFFUNC)stub_WdfUsbTargetPipeSetNoMaximumPacketSizeCheck;
        fn[225] = (WDFFUNC)stub_WdfUsbTargetPipeConfigContinuousReader;
        fn[236] = (WDFFUNC)stub_WdfUsbTargetDeviceGetInterface;
        fn[238] = (WDFFUNC)stub_WdfUsbInterfaceGetNumConfiguredPipes;
        fn[239] = (WDFFUNC)stub_WdfUsbInterfaceGetConfiguredPipe;
    }
} g_wdf2Table;
template<> void Wdf2FunctionTable::fill_defaults<-1>() {}

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

    if (bindInfo && bindInfo->FuncTable) {
        // FuncTable = &WdfFunctions_02015 (pointer to the extern WDFFUNC* in driver)
        // Set: *FuncTable = g_wdf2Table  (WdfFunctions_02015 now points to our array)
        *(WDFFUNC **)bindInfo->FuncTable = g_wdf2Table.fn;
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
