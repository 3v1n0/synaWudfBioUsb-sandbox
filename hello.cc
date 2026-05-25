
#define NTDDI_VERSION NTDDI_WIN7
#include <windows.h>
#include <ksguid.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cassert>
#include <map>

// #define _Analysis_mode_(...)
// #define _Notliteral_
// #define __user_driver
// #define _Out_writes_bytes_opt_
// #define _In_reads_bytes_opt_(...)
// #define _Out_writes_bytes_opt_(...)

#include <wudfddi.h>
#include <winusb.h>
#include <wudfusb.h>
#include <setupapi.h>

#include <cfgmgr32.h>

#include "winbio_ioctl.h"

/* Logging levels controlled by HELLO_DEBUG env var:
 *   0 or unset = USER messages only (progress, results, high-level steps)
 *   1          = + INFO (IOCTL results, completion statuses)
 *   2          = + DEBUG (object lifecycle, USB transfers, hex dumps)
 *   3          = + TRACE (hash computation, BIR dumps, raw breakpoint data)
 */
static int hello_log_level = -1;
static int hello_get_log_level() {
    if (hello_log_level < 0) {
        const char *env = getenv("HELLO_DEBUG");
        hello_log_level = env ? atoi(env) : 0;
    }
    return hello_log_level;
}
#define HLOG_USER(...)   do { printf(__VA_ARGS__); } while(0)
#define HLOG_INFO(...)   do { if (hello_get_log_level() >= 1) { printf(__VA_ARGS__); } } while(0)
#define HLOG_DEBUG(...)  do { if (hello_get_log_level() >= 2) { printf(__VA_ARGS__); } } while(0)
#define HLOG_TRACE(...)  do { if (hello_get_log_level() >= 3) { printf(__VA_ARGS__); } } while(0)
#define IFLOG(level)     if (hello_get_log_level() >= (level))


#ifndef WINBIO_I_MORE_DATA
#define WINBIO_I_MORE_DATA                       ((HRESULT)0x00090001L)
#endif
#ifndef WINBIO_I_EXTENDED_STATUS_INFORMATION
#define WINBIO_I_EXTENDED_STATUS_INFORMATION    ((HRESULT)0x00090002L)
#endif
#ifndef WINBIO_E_UNSUPPORTED_FACTOR
#define WINBIO_E_UNSUPPORTED_FACTOR             ((HRESULT)0x80098001L)
#endif
#ifndef WINBIO_E_INVALID_UNIT
#define WINBIO_E_INVALID_UNIT                   ((HRESULT)0x80098002L)
#endif
#ifndef WINBIO_E_UNKNOWN_ID
#define WINBIO_E_UNKNOWN_ID                     ((HRESULT)0x80098003L)
#endif
#ifndef WINBIO_E_CANCELED
#define WINBIO_E_CANCELED                       ((HRESULT)0x80098004L)
#endif
#ifndef WINBIO_E_NO_MATCH
#define WINBIO_E_NO_MATCH                       ((HRESULT)0x80098005L)
#endif
#ifndef WINBIO_E_CAPTURE_ABORTED
#define WINBIO_E_CAPTURE_ABORTED                ((HRESULT)0x80098006L)
#endif
#ifndef WINBIO_E_ENROLLMENT_IN_PROGRESS
#define WINBIO_E_ENROLLMENT_IN_PROGRESS         ((HRESULT)0x80098007L)
#endif
#ifndef WINBIO_E_BAD_CAPTURE
#define WINBIO_E_BAD_CAPTURE                    ((HRESULT)0x80098008L)
#endif
#ifndef WINBIO_E_INVALID_CONTROL_CODE
#define WINBIO_E_INVALID_CONTROL_CODE           ((HRESULT)0x80098009L)
#endif
#ifndef WINBIO_E_DATA_COLLECTION_IN_PROGRESS
#define WINBIO_E_DATA_COLLECTION_IN_PROGRESS    ((HRESULT)0x8009800BL)
#endif
#ifndef WINBIO_E_UNSUPPORTED_DATA_FORMAT
#define WINBIO_E_UNSUPPORTED_DATA_FORMAT        ((HRESULT)0x8009800CL)
#endif
#ifndef WINBIO_E_UNSUPPORTED_DATA_TYPE
#define WINBIO_E_UNSUPPORTED_DATA_TYPE          ((HRESULT)0x8009800DL)
#endif
#ifndef WINBIO_E_UNSUPPORTED_PURPOSE
#define WINBIO_E_UNSUPPORTED_PURPOSE            ((HRESULT)0x8009800EL)
#endif
#ifndef WINBIO_E_INVALID_DEVICE_STATE
#define WINBIO_E_INVALID_DEVICE_STATE           ((HRESULT)0x8009800FL)
#endif
#ifndef WINBIO_E_DEVICE_BUSY
#define WINBIO_E_DEVICE_BUSY                    ((HRESULT)0x80098010L)
#endif
#ifndef WINBIO_E_DATABASE_CANT_CREATE
#define WINBIO_E_DATABASE_CANT_CREATE           ((HRESULT)0x80098011L)
#endif
#ifndef WINBIO_E_DATABASE_CANT_OPEN
#define WINBIO_E_DATABASE_CANT_OPEN             ((HRESULT)0x80098012L)
#endif
#ifndef WINBIO_E_DATABASE_CANT_CLOSE
#define WINBIO_E_DATABASE_CANT_CLOSE            ((HRESULT)0x80098013L)
#endif
#ifndef WINBIO_E_DATABASE_CANT_ERASE
#define WINBIO_E_DATABASE_CANT_ERASE            ((HRESULT)0x80098014L)
#endif
#ifndef WINBIO_E_DATABASE_CANT_FIND
#define WINBIO_E_DATABASE_CANT_FIND             ((HRESULT)0x80098015L)
#endif
#ifndef WINBIO_E_DATABASE_ALREADY_EXISTS
#define WINBIO_E_DATABASE_ALREADY_EXISTS        ((HRESULT)0x80098016L)
#endif
#ifndef WINBIO_E_DATABASE_FULL
#define WINBIO_E_DATABASE_FULL                  ((HRESULT)0x80098018L)
#endif
#ifndef WINBIO_E_DATABASE_LOCKED
#define WINBIO_E_DATABASE_LOCKED                ((HRESULT)0x80098019L)
#endif
#ifndef WINBIO_E_DATABASE_CORRUPTED
#define WINBIO_E_DATABASE_CORRUPTED             ((HRESULT)0x8009801AL)
#endif
#ifndef WINBIO_E_DATABASE_NO_SUCH_RECORD
#define WINBIO_E_DATABASE_NO_SUCH_RECORD        ((HRESULT)0x8009801BL)
#endif
#ifndef WINBIO_E_DUPLICATE_ENROLLMENT
#define WINBIO_E_DUPLICATE_ENROLLMENT           ((HRESULT)0x8009801CL)
#endif
#ifndef WINBIO_E_DATABASE_READ_ERROR
#define WINBIO_E_DATABASE_READ_ERROR            ((HRESULT)0x8009801DL)
#endif
#ifndef WINBIO_E_DATABASE_WRITE_ERROR
#define WINBIO_E_DATABASE_WRITE_ERROR           ((HRESULT)0x8009801EL)
#endif
#ifndef WINBIO_E_DATABASE_NO_RESULTS
#define WINBIO_E_DATABASE_NO_RESULTS            ((HRESULT)0x8009801FL)
#endif
#ifndef WINBIO_E_DATABASE_NO_MORE_RECORDS
#define WINBIO_E_DATABASE_NO_MORE_RECORDS       ((HRESULT)0x80098020L)
#endif
#ifndef WINBIO_E_DATABASE_EOF
#define WINBIO_E_DATABASE_EOF                   ((HRESULT)0x80098021L)
#endif
#ifndef WINBIO_E_DATABASE_BAD_INDEX_VECTOR
#define WINBIO_E_DATABASE_BAD_INDEX_VECTOR      ((HRESULT)0x80098022L)
#endif
#ifndef WINBIO_E_INCORRECT_BSP
#define WINBIO_E_INCORRECT_BSP                  ((HRESULT)0x80098024L)
#endif
#ifndef WINBIO_E_INCORRECT_SENSOR_POOL
#define WINBIO_E_INCORRECT_SENSOR_POOL          ((HRESULT)0x80098025L)
#endif
#ifndef WINBIO_E_NO_CAPTURE_DATA
#define WINBIO_E_NO_CAPTURE_DATA               ((HRESULT)0x80098026L)
#endif
#ifndef WINBIO_E_INVALID_SENSOR_MODE
#define WINBIO_E_INVALID_SENSOR_MODE            ((HRESULT)0x80098027L)
#endif
#ifndef WINBIO_E_LOCK_VIOLATION
#define WINBIO_E_LOCK_VIOLATION                 ((HRESULT)0x8009802AL)
#endif
#ifndef WINBIO_E_DUPLICATE_TEMPLATE
#define WINBIO_E_DUPLICATE_TEMPLATE             ((HRESULT)0x8009802BL)
#endif
#ifndef WINBIO_E_INVALID_OPERATION
#define WINBIO_E_INVALID_OPERATION              ((HRESULT)0x8009802CL)
#endif
#ifndef WINBIO_E_SESSION_BUSY
#define WINBIO_E_SESSION_BUSY                   ((HRESULT)0x8009802DL)
#endif
#ifndef WINBIO_E_CRED_PROV_DISABLED
#define WINBIO_E_CRED_PROV_DISABLED             ((HRESULT)0x80098030L)
#endif
#ifndef WINBIO_E_CRED_PROV_NO_CREDENTIAL
#define WINBIO_E_CRED_PROV_NO_CREDENTIAL        ((HRESULT)0x80098031L)
#endif
#ifndef WINBIO_E_DISABLED
#define WINBIO_E_DISABLED                       ((HRESULT)0x80098032L)
#endif
#ifndef WINBIO_E_CONFIGURATION_FAILURE
#define WINBIO_E_CONFIGURATION_FAILURE          ((HRESULT)0x80098033L)
#endif
#ifndef WINBIO_E_SENSOR_UNAVAILABLE
#define WINBIO_E_SENSOR_UNAVAILABLE             ((HRESULT)0x80098034L)
#endif
#ifndef WINBIO_E_SAS_ENABLED
#define WINBIO_E_SAS_ENABLED                    ((HRESULT)0x80098035L)
#endif
#ifndef WINBIO_E_DEVICE_FAILURE
#define WINBIO_E_DEVICE_FAILURE                 ((HRESULT)0x80098036L)
#endif
#ifndef WINBIO_E_FAST_USER_SWITCH_DISABLED
#define WINBIO_E_FAST_USER_SWITCH_DISABLED      ((HRESULT)0x80098037L)
#endif
#ifndef WINBIO_E_NOT_ACTIVE_CONSOLE
#define WINBIO_E_NOT_ACTIVE_CONSOLE             ((HRESULT)0x80098038L)
#endif
#ifndef WINBIO_E_EVENT_MONITOR_ACTIVE
#define WINBIO_E_EVENT_MONITOR_ACTIVE           ((HRESULT)0x80098039L)
#endif
#ifndef WINBIO_E_INVALID_PROPERTY_TYPE
#define WINBIO_E_INVALID_PROPERTY_TYPE          ((HRESULT)0x8009803AL)
#endif
#ifndef WINBIO_E_INVALID_PROPERTY_ID
#define WINBIO_E_INVALID_PROPERTY_ID            ((HRESULT)0x8009803BL)
#endif
#ifndef WINBIO_E_UNSUPPORTED_PROPERTY
#define WINBIO_E_UNSUPPORTED_PROPERTY            ((HRESULT)0x8009803CL)
#endif
#ifndef WINBIO_E_ADAPTER_INTEGRITY_FAILURE
#define WINBIO_E_ADAPTER_INTEGRITY_FAILURE      ((HRESULT)0x8009803DL)
#endif
#ifndef WINBIO_E_INCORRECT_SESSION_TYPE
#define WINBIO_E_INCORRECT_SESSION_TYPE         ((HRESULT)0x8009803EL)
#endif
#ifndef WINBIO_E_SESSION_HANDLE_CLOSED
#define WINBIO_E_SESSION_HANDLE_CLOSED          ((HRESULT)0x8009803FL)
#endif
#ifndef WINBIO_E_DEADLOCK_DETECTED
#define WINBIO_E_DEADLOCK_DETECTED              ((HRESULT)0x80098040L)
#endif
#ifndef WINBIO_E_NO_PREBOOT_IDENTITY
#define WINBIO_E_NO_PREBOOT_IDENTITY            ((HRESULT)0x80098041L)
#endif
#ifndef WINBIO_E_MAX_ERROR_COUNT_EXCEEDED
#define WINBIO_E_MAX_ERROR_COUNT_EXCEEDED       ((HRESULT)0x80098042L)
#endif
#ifndef WINBIO_E_AUTO_LOGON_DISABLED
#define WINBIO_E_AUTO_LOGON_DISABLED             ((HRESULT)0x80098043L)
#endif
#ifndef WINBIO_E_INVALID_TICKET
#define WINBIO_E_INVALID_TICKET                 ((HRESULT)0x80098044L)
#endif
#ifndef WINBIO_E_TICKET_QUOTA_EXCEEDED
#define WINBIO_E_TICKET_QUOTA_EXCEEDED          ((HRESULT)0x80098045L)
#endif
#ifndef WINBIO_E_DATA_PROTECTION_FAILURE
#define WINBIO_E_DATA_PROTECTION_FAILURE        ((HRESULT)0x80098046L)
#endif
#ifndef WINBIO_E_CRED_PROV_SECURITY_LOCKOUT
#define WINBIO_E_CRED_PROV_SECURITY_LOCKOUT     ((HRESULT)0x80098047L)
#endif
#ifndef WINBIO_E_UNSUPPORTED_POOL_TYPE
#define WINBIO_E_UNSUPPORTED_POOL_TYPE          ((HRESULT)0x80098048L)
#endif
#ifndef WINBIO_E_SELECTION_REQUIRED
#define WINBIO_E_SELECTION_REQUIRED             ((HRESULT)0x80098049L)
#endif
#ifndef WINBIO_E_PRESENCE_MONITOR_ACTIVE
#define WINBIO_E_PRESENCE_MONITOR_ACTIVE        ((HRESULT)0x8009804AL)
#endif
#ifndef WINBIO_E_INVALID_SUBFACTOR
#define WINBIO_E_INVALID_SUBFACTOR              ((HRESULT)0x8009804BL)
#endif
#ifndef WINBIO_E_INVALID_CALIBRATION_FORMAT_ARRAY
#define WINBIO_E_INVALID_CALIBRATION_FORMAT_ARRAY ((HRESULT)0x8009804CL)
#endif
#ifndef WINBIO_E_NO_SUPPORTED_CALIBRATION_FORMAT
#define WINBIO_E_NO_SUPPORTED_CALIBRATION_FORMAT ((HRESULT)0x8009804DL)
#endif
#ifndef WINBIO_E_UNSUPPORTED_SENSOR_CALIBRATION_FORMAT
#define WINBIO_E_UNSUPPORTED_SENSOR_CALIBRATION_FORMAT ((HRESULT)0x8009804EL)
#endif
#ifndef WINBIO_E_CALIBRATION_BUFFER_TOO_SMALL
#define WINBIO_E_CALIBRATION_BUFFER_TOO_SMALL   ((HRESULT)0x8009804FL)
#endif
#ifndef WINBIO_E_CALIBRATION_BUFFER_TOO_LARGE
#define WINBIO_E_CALIBRATION_BUFFER_TOO_LARGE   ((HRESULT)0x80098050L)
#endif
#ifndef WINBIO_E_CALIBRATION_BUFFER_INVALID
#define WINBIO_E_CALIBRATION_BUFFER_INVALID     ((HRESULT)0x80098051L)
#endif

#ifndef WINBIO_FP_TOO_HIGH
#define WINBIO_FP_TOO_HIGH                      0x00000001L
#endif
#ifndef WINBIO_FP_TOO_LOW
#define WINBIO_FP_TOO_LOW                       0x00000002L
#endif
#ifndef WINBIO_FP_TOO_LEFT
#define WINBIO_FP_TOO_LEFT                      0x00000003L
#endif
#ifndef WINBIO_FP_TOO_RIGHT
#define WINBIO_FP_TOO_RIGHT                     0x00000004L
#endif
#ifndef WINBIO_FP_TOO_FAST
#define WINBIO_FP_TOO_FAST                      0x00000005L
#endif
#ifndef WINBIO_FP_TOO_SLOW
#define WINBIO_FP_TOO_SLOW                      0x00000006L
#endif
#ifndef WINBIO_FP_POOR_QUALITY
#define WINBIO_FP_POOR_QUALITY                  0x00000007L
#endif
#ifndef WINBIO_FP_TOO_SKEWED
#define WINBIO_FP_TOO_SKEWED                    0x00000008L
#endif
#ifndef WINBIO_FP_TOO_SHORT
#define WINBIO_FP_TOO_SHORT                     0x00000009L
#endif
#ifndef WINBIO_FP_MERGE_FAILURE
#define WINBIO_FP_MERGE_FAILURE                 0x0000000AL
#endif

#ifndef WINBIO_ID_TYPE_WILDCARD
#define WINBIO_ID_TYPE_WILDCARD ((WINBIO_IDENTITY_TYPE)1)
#endif
#ifndef WINBIO_ID_TYPE_GUID
#define WINBIO_ID_TYPE_GUID     ((WINBIO_IDENTITY_TYPE)2)
#endif
#ifndef WINBIO_ID_TYPE_SID
#define WINBIO_ID_TYPE_SID      ((WINBIO_IDENTITY_TYPE)3)
#endif
#ifndef WINBIO_IDENTITY_WILDCARD
#define WINBIO_IDENTITY_WILDCARD ((ULONG)0x25066282)
#endif

#define STORAGE_QUERY_TYPE_ALL      1
#define STORAGE_QUERY_TYPE_SUBJECT  2
#define STORAGE_QUERY_TYPE_CONTENT  3
#define STORAGE_QUERY_TYPE_GET_SINGLE 4

typedef struct _SYNA_STORAGE_QUERY_INPUT {
    DWORD QueryType;
    WINBIO_IDENTITY Identity;
    WINBIO_BIOMETRIC_SUBTYPE SubFactor;
    DWORD IndexElementCount;
    ULONG IndexVector[1];
} SYNA_STORAGE_QUERY_INPUT;

typedef struct _SYNA_STORAGE_RECORD {
    WINBIO_IDENTITY Identity;
    WINBIO_BIOMETRIC_SUBTYPE SubFactor;
    ULONGLONG TemplateBlobSize;
    UCHAR TemplateBlob[24];
} SYNA_STORAGE_RECORD;

typedef struct _SYNA_STORAGE_QUERY_RESULT {
    ULONGLONG RecordCount;
    SYNA_STORAGE_RECORD Records[1];
} SYNA_STORAGE_QUERY_RESULT;

typedef struct _WINBIO_IDENTIFY_ALL_OUTPUT_WIRE {
    WINBIO_IDENTITY Identity;
    WINBIO_BIOMETRIC_SUBTYPE SubFactor;
    HRESULT EngineHresult;
} WINBIO_IDENTIFY_ALL_OUTPUT_WIRE;

static_assert(sizeof(SYNA_STORAGE_RECORD) == 0x70, "SYNA_STORAGE_RECORD must be 0x70 bytes");
static_assert(offsetof(WINBIO_IDENTIFY_ALL_OUTPUT_WIRE, SubFactor) == 0x4c, "SubFactor offset must be 0x4c");
static_assert(offsetof(WINBIO_IDENTIFY_ALL_OUTPUT_WIRE, EngineHresult) == 0x50, "EngineHresult offset must be 0x50");
static_assert(sizeof(WINBIO_IDENTIFY_ALL_OUTPUT_WIRE) == 0x54, "WINBIO_IDENTIFY_ALL_OUTPUT_WIRE must be 0x54 bytes");
static_assert(sizeof(WINBIO_IDENTITY) == 0x4c, "WINBIO_IDENTITY must be 0x4c bytes");

static SIZE_T
clampInfoSize(LONG_PTR informationSize, SIZE_T bufferSize)
{
    if(informationSize <= 0)
        return 0;
    SIZE_T n = (SIZE_T)informationSize;
    return n < bufferSize ? n : bufferSize;
}

//
// Vendor-range IOCTLs (function code = 0x800 + n)
// These map to standard WinBio Engine/Storage adapter interface functions
// but are exposed as vendor-range IOCTLs by the Synaptics WDF driver.
//
#define VENDOR_IOCTL(n)                CTL_CODE(FILE_DEVICE_BIOMETRIC, (0x800 + n), METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_BIOMETRIC_ENGINE_CREATE_ENROLLMENT             VENDOR_IOCTL(3)   // 0x44200C
#define IOCTL_BIOMETRIC_ENGINE_UPDATE_ENROLLMENT             VENDOR_IOCTL(4)   // 0x442010
#define IOCTL_BIOMETRIC_ENGINE_CHECK_FOR_DUPLICATE           VENDOR_IOCTL(5)   // 0x442014
#define IOCTL_BIOMETRIC_ENGINE_COMMIT_ENROLLMENT             VENDOR_IOCTL(6)   // 0x442018
#define IOCTL_BIOMETRIC_ENGINE_DISCARD_ENROLLMENT            VENDOR_IOCTL(7)   // 0x44201C
#define IOCTL_BIOMETRIC_ENGINE_DISCARD_SMI_DATA              VENDOR_IOCTL(8)   // 0x442020
#define IOCTL_BIOMETRIC_ENGINE_ERASE_DATABASE                VENDOR_IOCTL(10)  // 0x442028
#define IOCTL_BIOMETRIC_STORAGE_GET_RECORD_COUNT             VENDOR_IOCTL(11)  // 0x44202C
#define IOCTL_BIOMETRIC_ENGINE_STORAGE_QUERY                 VENDOR_IOCTL(12)  // 0x442030
#define IOCTL_BIOMETRIC_STORAGE_DELETE_RECORD                VENDOR_IOCTL(13)  // 0x442034
#define IOCTL_BIOMETRIC_ENGINE_GET_COMMON_DATA               VENDOR_IOCTL(14)  // 0x442038
#define IOCTL_BIOMETRIC_ENGINE_SET_COMMON_DATA               VENDOR_IOCTL(15)  // 0x44203C
#define IOCTL_BIOMETRIC_ENGINE_RESET_OWNERSHIP               VENDOR_IOCTL(16)  // 0x442040
#define IOCTL_BIOMETRIC_ENGINE_SET_LED_STATE                 VENDOR_IOCTL(17)  // 0x442044
#define IOCTL_BIOMETRIC_ENGINE_SAP_REQUEST                   VENDOR_IOCTL(18)  // 0x442048
#define IOCTL_BIOMETRIC_ENGINE_GET_TEMPLATE                  VENDOR_IOCTL(20)  // 0x442050
#define IOCTL_BIOMETRIC_ENGINE_SET_TEMPLATE_LIST             VENDOR_IOCTL(21)  // 0x442054
#define IOCTL_BIOMETRIC_ENGINE_GET_IDENTIFY_ALL              VENDOR_IOCTL(22)  // 0x442058
#define IOCTL_BIOMETRIC_ENGINE_GET_IS_NON_ENROLL_COMMIT_PROC VENDOR_IOCTL(25)  // 0x442064
#define IOCTL_BIOMETRIC_ENGINE_SET_BIOTEST_RUNNING_STATE     VENDOR_IOCTL(32)  // 0x442080

// Undispatched vendor-range IOCTLs (fall through to OnControlUnit → E_NOTIMPL)
// 0x442004 - no handler
// 0x442024 - no handler
// 0x44204C - no handler (used as "setMode" placeholder in test code)

#include "breakpoints.h"

extern "C" {
HRESULT WINAPI PropVariantToInt32(REFPROPVARIANT propvarIn, LONG *ret);

int WINAPI PropVariantToStringAlloc(
  REFPROPVARIANT propvar,
  PWSTR          *ppszOut
);
}

typedef WINAPI DllGetClassObject_t(_In_ REFCLSID rclsid, _In_ REFIID riid, _Out_ LPVOID* ppv);

// INF file from which DriverCLSID and ServiceBinary are read at startup
#define INF_FILE "synaWudfBioUsb.inf"

// Filled at runtime from INF_FILE's [synaWudfBioUsb_Install] DriverCLSID entry
GUID DriverCLSID;

// 1BEC7499-8881-4F2B-B01C-A1A907304AFC
DEFINE_GUID(IID_IDriverEntry, 0x1BEC7499, 0x8881, 0x4F2B, 0xB0, 0x1C, 0xA1, 0xA9, 0x07, 0x30, 0x4A, 0xFC);

DEFINE_GUID(IID_IQueueCallbackDeviceIoControl, 0xC5411408, 0x0F1E, 0x4ed6, 0xA4, 0x12, 0x36, 0xDD, 0x15, 0xEE, 0xE7, 0x07);

DEFINE_GUID(IID_IPnpCallbackHardware, 0x51433BD3, 0xC7C1, 0x4bd8, 0xB4, 0xC1, 0xAB, 0x1E, 0x03, 0x46, 0x26, 0xCC);

DEFINE_GUID(IID_IPnpCallbackHardware2, 0x1493CD1B, 0xC546, 0x46bb, 0xBF, 0x47, 0xB2, 0x74, 0x65, 0x09, 0x33, 0x93);

// 5e8e7e85
DEFINE_GUID(IID_IPnpCallback, 0x27c32374, 0xcc45, 0x4840, 0x85, 0x7e, 0x8e, 0x5e, 0xf7, 0xc0, 0xeb, 0xff);

DEFINE_GUID(IID_IWDFPropertyStoreFactory, 0x45BE7E06, 0x9B65, 0x434d, 0xA7, 0xD6, 0x95, 0x72, 0xD7, 0xF7, 0x3D, 0x53);

DEFINE_GUID(IID_IWDFDevice3, 0x863D943A, 0xC9CD, 0x4655, 0xA8, 0xD6, 0xC8, 0x4E, 0xF4, 0x11, 0xCC, 0x0D);

DEFINE_GUID(IID_IWDFUsbTargetFactory, 0x3f7becf9, 0x3a65, 0x4348, 0xa4, 0xf3, 0x33, 0x9d, 0x57, 0x34, 0xa9, 0xc6);

DEFINE_GUID(IID_IWDFUsbTargetDevice, 0x4cd12e96,0x900a,0x44c3,0xa1,0xb7,0x05,0xb8,0x95,0x4d,0xab,0x76);

// {00000001-0000-0000-C000-000000000046} - defined in coguid.h
DEFINE_GUID(IID_IClassFactory, 0x00000001, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);

DEFINE_GUID(WINUSB_GUID, 0x88BAE032, 0x5A81, 0x49f0, 0xBC, 0x3D, 0xA4, 0xFF, 0x13, 0x82, 0x16, 0xD6);

// The driver defines it, not sure for what yet.
DEFINE_GUID(IID_IDeviceExtension, 0x5cd8d6f8, 0x3725, 0x4cfa, 0x98, 0xca, 0x39, 0xc5, 0x74, 0x1a, 0x66, 0x9c);

DEFINE_GUID(IID_UsbTargetAliasMaybe, 0xA44A3FEF, 0x88D9, 0x4C6E, 0xBC, 0xB1, 0xE5, 0xBF, 0xA3, 0x8B, 0xC4, 0xA6);

// Driver also defines IPowerPolicyCallbackWakeFromS0 - 7EE9F0FA-5A1A-48df-A35E-8DB42F519B66
// IPowerPolicyCallbackWakeFromSx - 3AB1426D-689C-4220-901E-03C6D909B5F5

/*
  if (((*param_2 == 0) && (param_2[1] == 0x46000000000000c0)) ||
     ((*param_2 == 0x4cfa37255cd8d6f8 && (param_2[1] == -0x6399e58b3ac63568)))) {
    plVar2 = param_1 + 0x9f;
  }
  else {
    // if !IID_IPnpCallbackHardware2
    if ((*param_2 != 0x46bbc5461493cd1b) || (param_2[1] != -0x6cccf69a8b4db841)) {
      uVar1 = FUN_18000cc9c(param_1,param_2,param_3);
      if (-1 < (int)uVar1) {
        return uVar1;
      }
      *param_3 = 0;
      return 0x80004002;
    }
    IID_IPnpCallbackHardware2
    plVar2 = param_1 + 1;
  }

  // IRequestCallbackCancel
  if ((*param_2 == 0x423545874e9f1a77) && (param_2[1] == 0x56a64545d2e6c481)) {
    *param_3 = -(ulonglong)(param_1 != (longlong *)0x0) & (ulonglong)(param_1 + 2);
    lVar1 = *param_1;
  }
  else {
    // IPnpCallback
    if ((*param_2 == 0x4840cc4527c32374) && (param_2[1] == L'\x5e8e7e85')) {
      plVar2 = param_1 + 3;
    }
    // IPowerPolicyCallbackWakeFromS0
    else if ((*param_2 == 0x48df5a1a7ee9f0fa) && (param_2[1] == 0x669b512fb48d5ea3)) {
      plVar2 = param_1 + 4;
    }
    //   IPowerPolicyCallbackWakeFromSx
    else if ((*param_2 == 0x4220689c3ab1426d) && (param_2[1] == -0xa4af62639fce170)) {
      plVar2 = param_1 + 5;
    }
    else if ((*param_2 == 0x4aaf9545a49a0bb4) && (param_2[1] == 0x3458bb0bef0d2e87)) {
      plVar2 = param_1 + 8;
    }
    else {
      //   IQueueCallbackDeviceIoControl
      if ((*param_2 != 0x4ed60f1ec5411408) || (param_2[1] != 0x7e7ee15dd3612a4)) {
        *param_3 = 0;
        return 0x80004002;
      }
      plVar2 = param_1 + 6;
    }
    *param_3 = -(ulonglong)(param_1 != (longlong *)0x0) & (ulonglong)plVar2;
    lVar1 = *param_1;
  }


  Simplified by Deepseek:
  // Define all GUIDs used in both functions
static const GUID GUID_IUnknown = { 0x00000000, 0x0000, 0x0000, {0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46} };
static const GUID GUID_DeviceExtension = { 0x5CD8D6F8, 0x3725, 0x4CFA, {0x98,0xCA,0x39,0xC5,0x74,0x1A,0x66,0x9C} };
static const GUID GUID_Interface = { 0x1493CD1B, 0xC546, 0x46BB, {0xBF,0x47,0xB2,0x74,0x65,0x09,0x33,0x93} };

static const GUID GUID_ServiceTable = { 0x4E9F1A77, 0x4235, 0x4587, {0x56,0xA6,0x45,0x45,0xD2,0xE6,0xC4,0x81} };
static const GUID GUID_PowerManagement = { 0x27C32374, 0x4840, 0xCC45, {0x5E,0x8E,0x7E,0x85,0x00,0x00,0x00,0x00} };
static const GUID GUID_DeviceControl = { 0x7EE9F0FA, 0x48DF, 0x5A1A, {0x66,0x9B,0x51,0x2F,0xB4,0x8D,0x5E,0xA3} };
static const GUID GUID_SystemControl = { 0x3AB1426D, 0x4220, 0x689C, {0xF5,0xB2,0x0E,0x5F,0x60,0x3C,0xE5,0xF0} };
static const GUID GUID_Wmi = { 0xA49A0BB4, 0x4AAF, 0x9545, {0x34,0x58,0xBB,0x0B,0xEF,0x0D,0x2E,0x87} };
static const GUID GUID_Pnp = { 0xC5411408, 0x4ED6, 0x0F1E, {0x07,0xE7,0xEE,0x15,0xDD,0x36,0x12,0xA4} };

// Main QueryInterface implementation
NTSTATUS QueryInterfaceHandler(longlong* pThis, GUID* pIid, ulonglong* ppvObject)
{
    longlong* pInterface;

    // Handle IUnknown and device-specific interfaces
    if (IsEqualGUID(pIid, &GUID_IUnknown) ||
        IsEqualGUID(pIid, &GUID_DeviceExtension)) {
        pInterface = pThis + 0x9F;
    }
    else if (IsEqualGUID(pIid, &GUID_Interface)) {
        pInterface = pThis + 1;
    }
    else {
        // Fallback to secondary interface handler
        return SecondaryInterfaceHandler(pThis, pIid, ppvObject);
    }

    *ppvObject = (pThis != NULL) ? (ulonglong)pInterface : 0;
    (**(code**)(*pThis + 0x18))(pThis);  // Call Release method
    return STATUS_SUCCESS;
}

// Handle secondary interfaces
NTSTATUS SecondaryInterfaceHandler(longlong* pThis, GUID* pIid, ulonglong* ppvObject)
{
    longlong* pInterface;
    longlong vtable;

    if (IsEqualGUID(pIid, &GUID_ServiceTable)) {
        pInterface = pThis + 2;
        vtable = *pThis;
    }
    else {
        // Handle other specialized interfaces
        if (IsEqualGUID(pIid, &GUID_PowerManagement)) {
            pInterface = pThis + 3;
        }
        else if (IsEqualGUID(pIid, &GUID_DeviceControl)) {
            pInterface = pThis + 4;
        }
        else if (IsEqualGUID(pIid, &GUID_SystemControl)) {
            pInterface = pThis + 5;
        }
        else if (IsEqualGUID(pIid, &GUID_Wmi)) {
            pInterface = pThis + 8;
        }
        else if (IsEqualGUID(pIid, &GUID_Pnp)) {
            pInterface = pThis + 6;
        }
        else {
            // Interface not supported
            *ppvObject = 0;
            return STATUS_NOINTERFACE;
        }

        *ppvObject = (pThis != NULL) ? (ulonglong)pInterface : 0;
        vtable = *pThis;
    }

    (**(code**)(vtable + 0x18))(pThis);  // Call Release method
    return STATUS_SUCCESS;
}
*/

int goIdle;

static const char *hresult_to_sting(HRESULT res)
{
    switch (res) {
#ifdef S_OK
    case S_OK:
        return "S_OK";
#endif
#ifdef E_CLASSNOTAVAILABLE
    case E_CLASSNOTAVAILABLE:
        return "E_CLASSNOTAVAILABLE";
#endif
#ifdef E_ABORT
    case E_ABORT:
        return "E_ABORT";
#endif
#ifdef E_ACCESSDENIED
    case E_ACCESSDENIED:
        return "E_ACCESSDENIED";
#endif
#ifdef E_APPLICATION_ACTIVATION_EXEC_FAILURE
    case E_APPLICATION_ACTIVATION_EXEC_FAILURE:
        return "E_APPLICATION_ACTIVATION_EXEC_FAILURE";
#endif
#ifdef E_APPLICATION_ACTIVATION_TIMED_OUT
    case E_APPLICATION_ACTIVATION_TIMED_OUT:
        return "E_APPLICATION_ACTIVATION_TIMED_OUT";
#endif
#ifdef E_APPLICATION_EXITING
    case E_APPLICATION_EXITING:
        return "E_APPLICATION_EXITING";
#endif
#ifdef E_APPLICATION_MANAGER_NOT_RUNNING
    case E_APPLICATION_MANAGER_NOT_RUNNING:
        return "E_APPLICATION_MANAGER_NOT_RUNNING";
#endif
#ifdef E_APPLICATION_NOT_REGISTERED
    case E_APPLICATION_NOT_REGISTERED:
        return "E_APPLICATION_NOT_REGISTERED";
#endif
#ifdef E_APPLICATION_TEMPORARY_LICENSE_ERROR
    case E_APPLICATION_TEMPORARY_LICENSE_ERROR:
        return "E_APPLICATION_TEMPORARY_LICENSE_ERROR";
#endif
#ifdef E_APPLICATION_TRIAL_LICENSE_EXPIRED
    case E_APPLICATION_TRIAL_LICENSE_EXPIRED:
        return "E_APPLICATION_TRIAL_LICENSE_EXPIRED";
#endif
#ifdef E_APPLICATION_VIEW_EXITING
    case E_APPLICATION_VIEW_EXITING:
        return "E_APPLICATION_VIEW_EXITING";
#endif
#ifdef E_ASYNC_OPERATION_NOT_STARTED
    case E_ASYNC_OPERATION_NOT_STARTED:
        return "E_ASYNC_OPERATION_NOT_STARTED";
#endif
#ifdef E_AUDIO_ENGINE_NODE_NOT_FOUND
    case E_AUDIO_ENGINE_NODE_NOT_FOUND:
        return "E_AUDIO_ENGINE_NODE_NOT_FOUND";
#endif
#ifdef E_BLUETOOTH_ATT_ATTRIBUTE_NOT_FOUND
    case E_BLUETOOTH_ATT_ATTRIBUTE_NOT_FOUND:
        return "E_BLUETOOTH_ATT_ATTRIBUTE_NOT_FOUND";
#endif
#ifdef E_BLUETOOTH_ATT_ATTRIBUTE_NOT_LONG
    case E_BLUETOOTH_ATT_ATTRIBUTE_NOT_LONG:
        return "E_BLUETOOTH_ATT_ATTRIBUTE_NOT_LONG";
#endif
#ifdef E_BLUETOOTH_ATT_INSUFFICIENT_AUTHENTICATION
    case E_BLUETOOTH_ATT_INSUFFICIENT_AUTHENTICATION:
        return "E_BLUETOOTH_ATT_INSUFFICIENT_AUTHENTICATION";
#endif
#ifdef E_BLUETOOTH_ATT_INSUFFICIENT_AUTHORIZATION
    case E_BLUETOOTH_ATT_INSUFFICIENT_AUTHORIZATION:
        return "E_BLUETOOTH_ATT_INSUFFICIENT_AUTHORIZATION";
#endif
#ifdef E_BLUETOOTH_ATT_INSUFFICIENT_ENCRYPTION
    case E_BLUETOOTH_ATT_INSUFFICIENT_ENCRYPTION:
        return "E_BLUETOOTH_ATT_INSUFFICIENT_ENCRYPTION";
#endif
#ifdef E_BLUETOOTH_ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE
    case E_BLUETOOTH_ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE:
        return "E_BLUETOOTH_ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE";
#endif
#ifdef E_BLUETOOTH_ATT_INSUFFICIENT_RESOURCES
    case E_BLUETOOTH_ATT_INSUFFICIENT_RESOURCES:
        return "E_BLUETOOTH_ATT_INSUFFICIENT_RESOURCES";
#endif
#ifdef E_BLUETOOTH_ATT_INVALID_ATTRIBUTE_VALUE_LENGTH
    case E_BLUETOOTH_ATT_INVALID_ATTRIBUTE_VALUE_LENGTH:
        return "E_BLUETOOTH_ATT_INVALID_ATTRIBUTE_VALUE_LENGTH";
#endif
#ifdef E_BLUETOOTH_ATT_INVALID_HANDLE
    case E_BLUETOOTH_ATT_INVALID_HANDLE:
        return "E_BLUETOOTH_ATT_INVALID_HANDLE";
#endif
#ifdef E_BLUETOOTH_ATT_INVALID_OFFSET
    case E_BLUETOOTH_ATT_INVALID_OFFSET:
        return "E_BLUETOOTH_ATT_INVALID_OFFSET";
#endif
#ifdef E_BLUETOOTH_ATT_INVALID_PDU
    case E_BLUETOOTH_ATT_INVALID_PDU:
        return "E_BLUETOOTH_ATT_INVALID_PDU";
#endif
#ifdef E_BLUETOOTH_ATT_PREPARE_QUEUE_FULL
    case E_BLUETOOTH_ATT_PREPARE_QUEUE_FULL:
        return "E_BLUETOOTH_ATT_PREPARE_QUEUE_FULL";
#endif
#ifdef E_BLUETOOTH_ATT_READ_NOT_PERMITTED
    case E_BLUETOOTH_ATT_READ_NOT_PERMITTED:
        return "E_BLUETOOTH_ATT_READ_NOT_PERMITTED";
#endif
#ifdef E_BLUETOOTH_ATT_REQUEST_NOT_SUPPORTED
    case E_BLUETOOTH_ATT_REQUEST_NOT_SUPPORTED:
        return "E_BLUETOOTH_ATT_REQUEST_NOT_SUPPORTED";
#endif
#ifdef E_BLUETOOTH_ATT_UNKNOWN_ERROR
    case E_BLUETOOTH_ATT_UNKNOWN_ERROR:
        return "E_BLUETOOTH_ATT_UNKNOWN_ERROR";
#endif
#ifdef E_BLUETOOTH_ATT_UNLIKELY
    case E_BLUETOOTH_ATT_UNLIKELY:
        return "E_BLUETOOTH_ATT_UNLIKELY";
#endif
#ifdef E_BLUETOOTH_ATT_UNSUPPORTED_GROUP_TYPE
    case E_BLUETOOTH_ATT_UNSUPPORTED_GROUP_TYPE:
        return "E_BLUETOOTH_ATT_UNSUPPORTED_GROUP_TYPE";
#endif
#ifdef E_BLUETOOTH_ATT_WRITE_NOT_PERMITTED
    case E_BLUETOOTH_ATT_WRITE_NOT_PERMITTED:
        return "E_BLUETOOTH_ATT_WRITE_NOT_PERMITTED";
#endif
#ifdef E_BOUNDS
    case E_BOUNDS:
        return "E_BOUNDS";
#endif
#ifdef E_CHANGED_STATE
    case E_CHANGED_STATE:
        return "E_CHANGED_STATE";
#endif
#ifdef E_ELEVATED_ACTIVATION_NOT_SUPPORTED
    case E_ELEVATED_ACTIVATION_NOT_SUPPORTED:
        return "E_ELEVATED_ACTIVATION_NOT_SUPPORTED";
#endif
#ifdef E_FAIL
    case E_FAIL:
        return "E_FAIL";
#endif
#ifdef E_FULL_ADMIN_NOT_SUPPORTED
    case E_FULL_ADMIN_NOT_SUPPORTED:
        return "E_FULL_ADMIN_NOT_SUPPORTED";
#endif
#ifdef E_HANDLE
    case E_HANDLE:
        return "E_HANDLE";
#endif
#ifdef E_HDAUDIO_CONNECTION_LIST_NOT_SUPPORTED
    case E_HDAUDIO_CONNECTION_LIST_NOT_SUPPORTED:
        return "E_HDAUDIO_CONNECTION_LIST_NOT_SUPPORTED";
#endif
#ifdef E_HDAUDIO_EMPTY_CONNECTION_LIST
    case E_HDAUDIO_EMPTY_CONNECTION_LIST:
        return "E_HDAUDIO_EMPTY_CONNECTION_LIST";
#endif
#ifdef E_HDAUDIO_NO_LOGICAL_DEVICES_CREATED
    case E_HDAUDIO_NO_LOGICAL_DEVICES_CREATED:
        return "E_HDAUDIO_NO_LOGICAL_DEVICES_CREATED";
#endif
#ifdef E_HDAUDIO_NULL_LINKED_LIST_ENTRY
    case E_HDAUDIO_NULL_LINKED_LIST_ENTRY:
        return "E_HDAUDIO_NULL_LINKED_LIST_ENTRY";
#endif
#ifdef E_ILLEGAL_DELEGATE_ASSIGNMENT
    case E_ILLEGAL_DELEGATE_ASSIGNMENT:
        return "E_ILLEGAL_DELEGATE_ASSIGNMENT";
#endif
#ifdef E_ILLEGAL_METHOD_CALL
    case E_ILLEGAL_METHOD_CALL:
        return "E_ILLEGAL_METHOD_CALL";
#endif
#ifdef E_ILLEGAL_STATE_CHANGE
    case E_ILLEGAL_STATE_CHANGE:
        return "E_ILLEGAL_STATE_CHANGE";
#endif
#ifdef E_INVALIDARG
    case E_INVALIDARG:
        return "E_INVALIDARG";
#endif
#ifdef E_INVALID_PROTOCOL_FORMAT
    case E_INVALID_PROTOCOL_FORMAT:
        return "E_INVALID_PROTOCOL_FORMAT";
#endif
#ifdef E_INVALID_PROTOCOL_OPERATION
    case E_INVALID_PROTOCOL_OPERATION:
        return "E_INVALID_PROTOCOL_OPERATION";
#endif
#ifdef E_MBN_BAD_SIM
    case E_MBN_BAD_SIM:
        return "E_MBN_BAD_SIM";
#endif
#ifdef E_MBN_CONTEXT_NOT_ACTIVATED
    case E_MBN_CONTEXT_NOT_ACTIVATED:
        return "E_MBN_CONTEXT_NOT_ACTIVATED";
#endif
#ifdef E_MBN_DATA_CLASS_NOT_AVAILABLE
    case E_MBN_DATA_CLASS_NOT_AVAILABLE:
        return "E_MBN_DATA_CLASS_NOT_AVAILABLE";
#endif
#ifdef E_MBN_DEFAULT_PROFILE_EXIST
    case E_MBN_DEFAULT_PROFILE_EXIST:
        return "E_MBN_DEFAULT_PROFILE_EXIST";
#endif
#ifdef E_MBN_FAILURE
    case E_MBN_FAILURE:
        return "E_MBN_FAILURE";
#endif
#ifdef E_MBN_INVALID_ACCESS_STRING
    case E_MBN_INVALID_ACCESS_STRING:
        return "E_MBN_INVALID_ACCESS_STRING";
#endif
#ifdef E_MBN_INVALID_CACHE
    case E_MBN_INVALID_CACHE:
        return "E_MBN_INVALID_CACHE";
#endif
#ifdef E_MBN_INVALID_PROFILE
    case E_MBN_INVALID_PROFILE:
        return "E_MBN_INVALID_PROFILE";
#endif
#ifdef E_MBN_MAX_ACTIVATED_CONTEXTS
    case E_MBN_MAX_ACTIVATED_CONTEXTS:
        return "E_MBN_MAX_ACTIVATED_CONTEXTS";
#endif
#ifdef E_MBN_NOT_REGISTERED
    case E_MBN_NOT_REGISTERED:
        return "E_MBN_NOT_REGISTERED";
#endif
#ifdef E_MBN_PACKET_SVC_DETACHED
    case E_MBN_PACKET_SVC_DETACHED:
        return "E_MBN_PACKET_SVC_DETACHED";
#endif
#ifdef E_MBN_PIN_DISABLED
    case E_MBN_PIN_DISABLED:
        return "E_MBN_PIN_DISABLED";
#endif
#ifdef E_MBN_PIN_NOT_SUPPORTED
    case E_MBN_PIN_NOT_SUPPORTED:
        return "E_MBN_PIN_NOT_SUPPORTED";
#endif
#ifdef E_MBN_PIN_REQUIRED
    case E_MBN_PIN_REQUIRED:
        return "E_MBN_PIN_REQUIRED";
#endif
#ifdef E_MBN_PROVIDERS_NOT_FOUND
    case E_MBN_PROVIDERS_NOT_FOUND:
        return "E_MBN_PROVIDERS_NOT_FOUND";
#endif
#ifdef E_MBN_PROVIDER_NOT_VISIBLE
    case E_MBN_PROVIDER_NOT_VISIBLE:
        return "E_MBN_PROVIDER_NOT_VISIBLE";
#endif
#ifdef E_MBN_RADIO_POWER_OFF
    case E_MBN_RADIO_POWER_OFF:
        return "E_MBN_RADIO_POWER_OFF";
#endif
#ifdef E_MBN_SERVICE_NOT_ACTIVATED
    case E_MBN_SERVICE_NOT_ACTIVATED:
        return "E_MBN_SERVICE_NOT_ACTIVATED";
#endif
#ifdef E_MBN_SIM_NOT_INSERTED
    case E_MBN_SIM_NOT_INSERTED:
        return "E_MBN_SIM_NOT_INSERTED";
#endif
#ifdef E_MBN_SMS_ENCODING_NOT_SUPPORTED
    case E_MBN_SMS_ENCODING_NOT_SUPPORTED:
        return "E_MBN_SMS_ENCODING_NOT_SUPPORTED";
#endif
#ifdef E_MBN_SMS_FILTER_NOT_SUPPORTED
    case E_MBN_SMS_FILTER_NOT_SUPPORTED:
        return "E_MBN_SMS_FILTER_NOT_SUPPORTED";
#endif
#ifdef E_MBN_SMS_FORMAT_NOT_SUPPORTED
    case E_MBN_SMS_FORMAT_NOT_SUPPORTED:
        return "E_MBN_SMS_FORMAT_NOT_SUPPORTED";
#endif
#ifdef E_MBN_SMS_INVALID_MEMORY_INDEX
    case E_MBN_SMS_INVALID_MEMORY_INDEX:
        return "E_MBN_SMS_INVALID_MEMORY_INDEX";
#endif
#ifdef E_MBN_SMS_LANG_NOT_SUPPORTED
    case E_MBN_SMS_LANG_NOT_SUPPORTED:
        return "E_MBN_SMS_LANG_NOT_SUPPORTED";
#endif
#ifdef E_MBN_SMS_MEMORY_FAILURE
    case E_MBN_SMS_MEMORY_FAILURE:
        return "E_MBN_SMS_MEMORY_FAILURE";
#endif
#ifdef E_MBN_SMS_MEMORY_FULL
    case E_MBN_SMS_MEMORY_FULL:
        return "E_MBN_SMS_MEMORY_FULL";
#endif
#ifdef E_MBN_SMS_NETWORK_TIMEOUT
    case E_MBN_SMS_NETWORK_TIMEOUT:
        return "E_MBN_SMS_NETWORK_TIMEOUT";
#endif
#ifdef E_MBN_SMS_OPERATION_NOT_ALLOWED
    case E_MBN_SMS_OPERATION_NOT_ALLOWED:
        return "E_MBN_SMS_OPERATION_NOT_ALLOWED";
#endif
#ifdef E_MBN_SMS_UNKNOWN_SMSC_ADDRESS
    case E_MBN_SMS_UNKNOWN_SMSC_ADDRESS:
        return "E_MBN_SMS_UNKNOWN_SMSC_ADDRESS";
#endif
#ifdef E_MBN_VOICE_CALL_IN_PROGRESS
    case E_MBN_VOICE_CALL_IN_PROGRESS:
        return "E_MBN_VOICE_CALL_IN_PROGRESS";
#endif
#ifdef E_MONITOR_RESOLUTION_TOO_LOW
    case E_MONITOR_RESOLUTION_TOO_LOW:
        return "E_MONITOR_RESOLUTION_TOO_LOW";
#endif
#ifdef E_MULTIPLE_EXTENSIONS_FOR_APPLICATION
    case E_MULTIPLE_EXTENSIONS_FOR_APPLICATION:
        return "E_MULTIPLE_EXTENSIONS_FOR_APPLICATION";
#endif
#ifdef E_MULTIPLE_PACKAGES_FOR_FAMILY
    case E_MULTIPLE_PACKAGES_FOR_FAMILY:
        return "E_MULTIPLE_PACKAGES_FOR_FAMILY";
#endif
#ifdef E_NOINTERFACE
    case E_NOINTERFACE:
        return "E_NOINTERFACE";
#endif
#ifdef E_NOTIMPL
    case E_NOTIMPL:
        return "E_NOTIMPL";
#endif
#ifdef E_NOT_SET
    case E_NOT_SET:
        return "E_NOT_SET";
#endif
#ifdef E_NOT_SUFFICIENT_BUFFER
    case E_NOT_SUFFICIENT_BUFFER:
        return "E_NOT_SUFFICIENT_BUFFER";
#endif
#ifdef E_NOT_VALID_STATE
    case E_NOT_VALID_STATE:
        return "E_NOT_VALID_STATE";
#endif
#ifdef E_OUTOFMEMORY
    case E_OUTOFMEMORY:
        return "E_OUTOFMEMORY";
#endif
#ifdef E_PENDING
    case E_PENDING:
        return "E_PENDING";
#endif
#ifdef E_POINTER
    case E_POINTER:
        return "E_POINTER";
#endif
#ifdef E_PROTOCOL_EXTENSIONS_NOT_SUPPORTED
    case E_PROTOCOL_EXTENSIONS_NOT_SUPPORTED:
        return "E_PROTOCOL_EXTENSIONS_NOT_SUPPORTED";
#endif
#ifdef E_PROTOCOL_VERSION_NOT_SUPPORTED
    case E_PROTOCOL_VERSION_NOT_SUPPORTED:
        return "E_PROTOCOL_VERSION_NOT_SUPPORTED";
#endif
#ifdef E_SKYDRIVE_FILE_NOT_UPLOADED
    case E_SKYDRIVE_FILE_NOT_UPLOADED:
        return "E_SKYDRIVE_FILE_NOT_UPLOADED";
#endif
#ifdef E_SKYDRIVE_ROOT_TARGET_CANNOT_INDEX
    case E_SKYDRIVE_ROOT_TARGET_CANNOT_INDEX:
        return "E_SKYDRIVE_ROOT_TARGET_CANNOT_INDEX";
#endif
#ifdef E_SKYDRIVE_ROOT_TARGET_FILE_SYSTEM_NOT_SUPPORTED
    case E_SKYDRIVE_ROOT_TARGET_FILE_SYSTEM_NOT_SUPPORTED:
        return "E_SKYDRIVE_ROOT_TARGET_FILE_SYSTEM_NOT_SUPPORTED";
#endif
#ifdef E_SKYDRIVE_ROOT_TARGET_OVERLAP
    case E_SKYDRIVE_ROOT_TARGET_OVERLAP:
        return "E_SKYDRIVE_ROOT_TARGET_OVERLAP";
#endif
#ifdef E_SKYDRIVE_ROOT_TARGET_VOLUME_ROOT_NOT_SUPPORTED
    case E_SKYDRIVE_ROOT_TARGET_VOLUME_ROOT_NOT_SUPPORTED:
        return "E_SKYDRIVE_ROOT_TARGET_VOLUME_ROOT_NOT_SUPPORTED";
#endif
#ifdef E_SKYDRIVE_UPDATE_AVAILABILITY_FAIL
    case E_SKYDRIVE_UPDATE_AVAILABILITY_FAIL:
        return "E_SKYDRIVE_UPDATE_AVAILABILITY_FAIL";
#endif
#ifdef E_STRING_NOT_NULL_TERMINATED
    case E_STRING_NOT_NULL_TERMINATED:
        return "E_STRING_NOT_NULL_TERMINATED";
#endif
#ifdef E_SUBPROTOCOL_NOT_SUPPORTED
    case E_SUBPROTOCOL_NOT_SUPPORTED:
        return "E_SUBPROTOCOL_NOT_SUPPORTED";
#endif
#ifdef E_SYNCENGINE_CLIENT_UPDATE_NEEDED
    case E_SYNCENGINE_CLIENT_UPDATE_NEEDED:
        return "E_SYNCENGINE_CLIENT_UPDATE_NEEDED";
#endif
#ifdef E_SYNCENGINE_FILE_IDENTIFIER_UNKNOWN
    case E_SYNCENGINE_FILE_IDENTIFIER_UNKNOWN:
        return "E_SYNCENGINE_FILE_IDENTIFIER_UNKNOWN";
#endif
#ifdef E_SYNCENGINE_FILE_SIZE_EXCEEDS_REMAINING_QUOTA
    case E_SYNCENGINE_FILE_SIZE_EXCEEDS_REMAINING_QUOTA:
        return "E_SYNCENGINE_FILE_SIZE_EXCEEDS_REMAINING_QUOTA";
#endif
#ifdef E_SYNCENGINE_FILE_SIZE_OVER_LIMIT
    case E_SYNCENGINE_FILE_SIZE_OVER_LIMIT:
        return "E_SYNCENGINE_FILE_SIZE_OVER_LIMIT";
#endif
#ifdef E_SYNCENGINE_FILE_SYNC_PARTNER_ERROR
    case E_SYNCENGINE_FILE_SYNC_PARTNER_ERROR:
        return "E_SYNCENGINE_FILE_SYNC_PARTNER_ERROR";
#endif
#ifdef E_SYNCENGINE_FOLDER_INACCESSIBLE
    case E_SYNCENGINE_FOLDER_INACCESSIBLE:
        return "E_SYNCENGINE_FOLDER_INACCESSIBLE";
#endif
#ifdef E_SYNCENGINE_FOLDER_IN_REDIRECTION
    case E_SYNCENGINE_FOLDER_IN_REDIRECTION:
        return "E_SYNCENGINE_FOLDER_IN_REDIRECTION";
#endif
#ifdef E_SYNCENGINE_FOLDER_ITEM_COUNT_LIMIT_EXCEEDED
    case E_SYNCENGINE_FOLDER_ITEM_COUNT_LIMIT_EXCEEDED:
        return "E_SYNCENGINE_FOLDER_ITEM_COUNT_LIMIT_EXCEEDED";
#endif
#ifdef E_SYNCENGINE_PATH_LENGTH_LIMIT_EXCEEDED
    case E_SYNCENGINE_PATH_LENGTH_LIMIT_EXCEEDED:
        return "E_SYNCENGINE_PATH_LENGTH_LIMIT_EXCEEDED";
#endif
#ifdef E_SYNCENGINE_PROXY_AUTHENTICATION_REQUIRED
    case E_SYNCENGINE_PROXY_AUTHENTICATION_REQUIRED:
        return "E_SYNCENGINE_PROXY_AUTHENTICATION_REQUIRED";
#endif
#ifdef E_SYNCENGINE_REMOTE_PATH_LENGTH_LIMIT_EXCEEDED
    case E_SYNCENGINE_REMOTE_PATH_LENGTH_LIMIT_EXCEEDED:
        return "E_SYNCENGINE_REMOTE_PATH_LENGTH_LIMIT_EXCEEDED";
#endif
#ifdef E_SYNCENGINE_REQUEST_BLOCKED_BY_SERVICE
    case E_SYNCENGINE_REQUEST_BLOCKED_BY_SERVICE:
        return "E_SYNCENGINE_REQUEST_BLOCKED_BY_SERVICE";
#endif
#ifdef E_SYNCENGINE_REQUEST_BLOCKED_DUE_TO_CLIENT_ERROR
    case E_SYNCENGINE_REQUEST_BLOCKED_DUE_TO_CLIENT_ERROR:
        return "E_SYNCENGINE_REQUEST_BLOCKED_DUE_TO_CLIENT_ERROR";
#endif
#ifdef E_SYNCENGINE_SERVICE_AUTHENTICATION_FAILED
    case E_SYNCENGINE_SERVICE_AUTHENTICATION_FAILED:
        return "E_SYNCENGINE_SERVICE_AUTHENTICATION_FAILED";
#endif
#ifdef E_SYNCENGINE_SERVICE_RETURNED_UNEXPECTED_SIZE
    case E_SYNCENGINE_SERVICE_RETURNED_UNEXPECTED_SIZE:
        return "E_SYNCENGINE_SERVICE_RETURNED_UNEXPECTED_SIZE";
#endif
#ifdef E_SYNCENGINE_STORAGE_SERVICE_BLOCKED
    case E_SYNCENGINE_STORAGE_SERVICE_BLOCKED:
        return "E_SYNCENGINE_STORAGE_SERVICE_BLOCKED";
#endif
#ifdef E_SYNCENGINE_STORAGE_SERVICE_PROVISIONING_FAILED
    case E_SYNCENGINE_STORAGE_SERVICE_PROVISIONING_FAILED:
        return "E_SYNCENGINE_STORAGE_SERVICE_PROVISIONING_FAILED";
#endif
#ifdef E_SYNCENGINE_SYNC_PAUSED_BY_SERVICE
    case E_SYNCENGINE_SYNC_PAUSED_BY_SERVICE:
        return "E_SYNCENGINE_SYNC_PAUSED_BY_SERVICE";
#endif
#ifdef E_SYNCENGINE_UNKNOWN_SERVICE_ERROR
    case E_SYNCENGINE_UNKNOWN_SERVICE_ERROR:
        return "E_SYNCENGINE_UNKNOWN_SERVICE_ERROR";
#endif
#ifdef E_SYNCENGINE_UNSUPPORTED_FILE_NAME
    case E_SYNCENGINE_UNSUPPORTED_FILE_NAME:
        return "E_SYNCENGINE_UNSUPPORTED_FILE_NAME";
#endif
#ifdef E_SYNCENGINE_UNSUPPORTED_FOLDER_NAME
    case E_SYNCENGINE_UNSUPPORTED_FOLDER_NAME:
        return "E_SYNCENGINE_UNSUPPORTED_FOLDER_NAME";
#endif
#ifdef E_SYNCENGINE_UNSUPPORTED_MARKET
    case E_SYNCENGINE_UNSUPPORTED_MARKET:
        return "E_SYNCENGINE_UNSUPPORTED_MARKET";
#endif
#ifdef E_SYNCENGINE_UNSUPPORTED_REPARSE_POINT
    case E_SYNCENGINE_UNSUPPORTED_REPARSE_POINT:
        return "E_SYNCENGINE_UNSUPPORTED_REPARSE_POINT";
#endif
#ifdef E_UAC_DISABLED
    case E_UAC_DISABLED:
        return "E_UAC_DISABLED";
#endif
#ifdef E_UNEXPECTED
    case E_UNEXPECTED:
        return "E_UNEXPECTED";
#endif
#ifdef WINBIO_I_MORE_DATA
    case WINBIO_I_MORE_DATA:
        return "WINBIO_I_MORE_DATA";
#endif
#ifdef WINBIO_I_EXTENDED_STATUS_INFORMATION
    case WINBIO_I_EXTENDED_STATUS_INFORMATION:
        return "WINBIO_I_EXTENDED_STATUS_INFORMATION";
#endif
#ifdef WINBIO_E_UNSUPPORTED_FACTOR
    case WINBIO_E_UNSUPPORTED_FACTOR:
        return "WINBIO_E_UNSUPPORTED_FACTOR";
#endif
#ifdef WINBIO_E_INVALID_UNIT
    case WINBIO_E_INVALID_UNIT:
        return "WINBIO_E_INVALID_UNIT";
#endif
#ifdef WINBIO_E_UNKNOWN_ID
    case WINBIO_E_UNKNOWN_ID:
        return "WINBIO_E_UNKNOWN_ID";
#endif
#ifdef WINBIO_E_CANCELED
    case WINBIO_E_CANCELED:
        return "WINBIO_E_CANCELED";
#endif
#ifdef WINBIO_E_NO_MATCH
    case WINBIO_E_NO_MATCH:
        return "WINBIO_E_NO_MATCH";
#endif
#ifdef WINBIO_E_CAPTURE_ABORTED
    case WINBIO_E_CAPTURE_ABORTED:
        return "WINBIO_E_CAPTURE_ABORTED";
#endif
#ifdef WINBIO_E_ENROLLMENT_IN_PROGRESS
    case WINBIO_E_ENROLLMENT_IN_PROGRESS:
        return "WINBIO_E_ENROLLMENT_IN_PROGRESS";
#endif
#ifdef WINBIO_E_BAD_CAPTURE
    case WINBIO_E_BAD_CAPTURE:
        return "WINBIO_E_BAD_CAPTURE";
#endif
#ifdef WINBIO_E_INVALID_CONTROL_CODE
    case WINBIO_E_INVALID_CONTROL_CODE:
        return "WINBIO_E_INVALID_CONTROL_CODE";
#endif
#ifdef WINBIO_E_DATA_COLLECTION_IN_PROGRESS
    case WINBIO_E_DATA_COLLECTION_IN_PROGRESS:
        return "WINBIO_E_DATA_COLLECTION_IN_PROGRESS";
#endif
#ifdef WINBIO_E_UNSUPPORTED_DATA_FORMAT
    case WINBIO_E_UNSUPPORTED_DATA_FORMAT:
        return "WINBIO_E_UNSUPPORTED_DATA_FORMAT";
#endif
#ifdef WINBIO_E_UNSUPPORTED_DATA_TYPE
    case WINBIO_E_UNSUPPORTED_DATA_TYPE:
        return "WINBIO_E_UNSUPPORTED_DATA_TYPE";
#endif
#ifdef WINBIO_E_UNSUPPORTED_PURPOSE
    case WINBIO_E_UNSUPPORTED_PURPOSE:
        return "WINBIO_E_UNSUPPORTED_PURPOSE";
#endif
#ifdef WINBIO_E_INVALID_DEVICE_STATE
    case WINBIO_E_INVALID_DEVICE_STATE:
        return "WINBIO_E_INVALID_DEVICE_STATE";
#endif
#ifdef WINBIO_E_DEVICE_BUSY
    case WINBIO_E_DEVICE_BUSY:
        return "WINBIO_E_DEVICE_BUSY";
#endif
#ifdef WINBIO_E_DATABASE_CANT_CREATE
    case WINBIO_E_DATABASE_CANT_CREATE:
        return "WINBIO_E_DATABASE_CANT_CREATE";
#endif
#ifdef WINBIO_E_DATABASE_CANT_OPEN
    case WINBIO_E_DATABASE_CANT_OPEN:
        return "WINBIO_E_DATABASE_CANT_OPEN";
#endif
#ifdef WINBIO_E_DATABASE_CANT_CLOSE
    case WINBIO_E_DATABASE_CANT_CLOSE:
        return "WINBIO_E_DATABASE_CANT_CLOSE";
#endif
#ifdef WINBIO_E_DATABASE_CANT_ERASE
    case WINBIO_E_DATABASE_CANT_ERASE:
        return "WINBIO_E_DATABASE_CANT_ERASE";
#endif
#ifdef WINBIO_E_DATABASE_CANT_FIND
    case WINBIO_E_DATABASE_CANT_FIND:
        return "WINBIO_E_DATABASE_CANT_FIND";
#endif
#ifdef WINBIO_E_DATABASE_ALREADY_EXISTS
    case WINBIO_E_DATABASE_ALREADY_EXISTS:
        return "WINBIO_E_DATABASE_ALREADY_EXISTS";
#endif
#ifdef WINBIO_E_DATABASE_FULL
    case WINBIO_E_DATABASE_FULL:
        return "WINBIO_E_DATABASE_FULL";
#endif
#ifdef WINBIO_E_DATABASE_LOCKED
    case WINBIO_E_DATABASE_LOCKED:
        return "WINBIO_E_DATABASE_LOCKED";
#endif
#ifdef WINBIO_E_DATABASE_CORRUPTED
    case WINBIO_E_DATABASE_CORRUPTED:
        return "WINBIO_E_DATABASE_CORRUPTED";
#endif
#ifdef WINBIO_E_DATABASE_NO_SUCH_RECORD
    case WINBIO_E_DATABASE_NO_SUCH_RECORD:
        return "WINBIO_E_DATABASE_NO_SUCH_RECORD";
#endif
#ifdef WINBIO_E_DUPLICATE_ENROLLMENT
    case WINBIO_E_DUPLICATE_ENROLLMENT:
        return "WINBIO_E_DUPLICATE_ENROLLMENT";
#endif
#ifdef WINBIO_E_DATABASE_READ_ERROR
    case WINBIO_E_DATABASE_READ_ERROR:
        return "WINBIO_E_DATABASE_READ_ERROR";
#endif
#ifdef WINBIO_E_DATABASE_WRITE_ERROR
    case WINBIO_E_DATABASE_WRITE_ERROR:
        return "WINBIO_E_DATABASE_WRITE_ERROR";
#endif
#ifdef WINBIO_E_DATABASE_NO_RESULTS
    case WINBIO_E_DATABASE_NO_RESULTS:
        return "WINBIO_E_DATABASE_NO_RESULTS";
#endif
#ifdef WINBIO_E_DATABASE_NO_MORE_RECORDS
    case WINBIO_E_DATABASE_NO_MORE_RECORDS:
        return "WINBIO_E_DATABASE_NO_MORE_RECORDS";
#endif
#ifdef WINBIO_E_DATABASE_EOF
    case WINBIO_E_DATABASE_EOF:
        return "WINBIO_E_DATABASE_EOF";
#endif
#ifdef WINBIO_E_DATABASE_BAD_INDEX_VECTOR
    case WINBIO_E_DATABASE_BAD_INDEX_VECTOR:
        return "WINBIO_E_DATABASE_BAD_INDEX_VECTOR";
#endif
#ifdef WINBIO_E_INCORRECT_BSP
    case WINBIO_E_INCORRECT_BSP:
        return "WINBIO_E_INCORRECT_BSP";
#endif
#ifdef WINBIO_E_INCORRECT_SENSOR_POOL
    case WINBIO_E_INCORRECT_SENSOR_POOL:
        return "WINBIO_E_INCORRECT_SENSOR_POOL";
#endif
#ifdef WINBIO_E_NO_CAPTURE_DATA
    case WINBIO_E_NO_CAPTURE_DATA:
        return "WINBIO_E_NO_CAPTURE_DATA";
#endif
#ifdef WINBIO_E_INVALID_SENSOR_MODE
    case WINBIO_E_INVALID_SENSOR_MODE:
        return "WINBIO_E_INVALID_SENSOR_MODE";
#endif
#ifdef WINBIO_E_LOCK_VIOLATION
    case WINBIO_E_LOCK_VIOLATION:
        return "WINBIO_E_LOCK_VIOLATION";
#endif
#ifdef WINBIO_E_DUPLICATE_TEMPLATE
    case WINBIO_E_DUPLICATE_TEMPLATE:
        return "WINBIO_E_DUPLICATE_TEMPLATE";
#endif
#ifdef WINBIO_E_INVALID_OPERATION
    case WINBIO_E_INVALID_OPERATION:
        return "WINBIO_E_INVALID_OPERATION";
#endif
#ifdef WINBIO_E_SESSION_BUSY
    case WINBIO_E_SESSION_BUSY:
        return "WINBIO_E_SESSION_BUSY";
#endif
#ifdef WINBIO_E_CRED_PROV_DISABLED
    case WINBIO_E_CRED_PROV_DISABLED:
        return "WINBIO_E_CRED_PROV_DISABLED";
#endif
#ifdef WINBIO_E_CRED_PROV_NO_CREDENTIAL
    case WINBIO_E_CRED_PROV_NO_CREDENTIAL:
        return "WINBIO_E_CRED_PROV_NO_CREDENTIAL";
#endif
#ifdef WINBIO_E_DISABLED
    case WINBIO_E_DISABLED:
        return "WINBIO_E_DISABLED";
#endif
#ifdef WINBIO_E_CONFIGURATION_FAILURE
    case WINBIO_E_CONFIGURATION_FAILURE:
        return "WINBIO_E_CONFIGURATION_FAILURE";
#endif
#ifdef WINBIO_E_SENSOR_UNAVAILABLE
    case WINBIO_E_SENSOR_UNAVAILABLE:
        return "WINBIO_E_SENSOR_UNAVAILABLE";
#endif
#ifdef WINBIO_E_SAS_ENABLED
    case WINBIO_E_SAS_ENABLED:
        return "WINBIO_E_SAS_ENABLED";
#endif
#ifdef WINBIO_E_DEVICE_FAILURE
    case WINBIO_E_DEVICE_FAILURE:
        return "WINBIO_E_DEVICE_FAILURE";
#endif
#ifdef WINBIO_E_FAST_USER_SWITCH_DISABLED
    case WINBIO_E_FAST_USER_SWITCH_DISABLED:
        return "WINBIO_E_FAST_USER_SWITCH_DISABLED";
#endif
#ifdef WINBIO_E_NOT_ACTIVE_CONSOLE
    case WINBIO_E_NOT_ACTIVE_CONSOLE:
        return "WINBIO_E_NOT_ACTIVE_CONSOLE";
#endif
#ifdef WINBIO_E_EVENT_MONITOR_ACTIVE
    case WINBIO_E_EVENT_MONITOR_ACTIVE:
        return "WINBIO_E_EVENT_MONITOR_ACTIVE";
#endif
#ifdef WINBIO_E_INVALID_PROPERTY_TYPE
    case WINBIO_E_INVALID_PROPERTY_TYPE:
        return "WINBIO_E_INVALID_PROPERTY_TYPE";
#endif
#ifdef WINBIO_E_INVALID_PROPERTY_ID
    case WINBIO_E_INVALID_PROPERTY_ID:
        return "WINBIO_E_INVALID_PROPERTY_ID";
#endif
#ifdef WINBIO_E_UNSUPPORTED_PROPERTY
    case WINBIO_E_UNSUPPORTED_PROPERTY:
        return "WINBIO_E_UNSUPPORTED_PROPERTY";
#endif
#ifdef WINBIO_E_ADAPTER_INTEGRITY_FAILURE
    case WINBIO_E_ADAPTER_INTEGRITY_FAILURE:
        return "WINBIO_E_ADAPTER_INTEGRITY_FAILURE";
#endif
#ifdef WINBIO_E_INCORRECT_SESSION_TYPE
    case WINBIO_E_INCORRECT_SESSION_TYPE:
        return "WINBIO_E_INCORRECT_SESSION_TYPE";
#endif
#ifdef WINBIO_E_SESSION_HANDLE_CLOSED
    case WINBIO_E_SESSION_HANDLE_CLOSED:
        return "WINBIO_E_SESSION_HANDLE_CLOSED";
#endif
#ifdef WINBIO_E_DEADLOCK_DETECTED
    case WINBIO_E_DEADLOCK_DETECTED:
        return "WINBIO_E_DEADLOCK_DETECTED";
#endif
#ifdef WINBIO_E_NO_PREBOOT_IDENTITY
    case WINBIO_E_NO_PREBOOT_IDENTITY:
        return "WINBIO_E_NO_PREBOOT_IDENTITY";
#endif
#ifdef WINBIO_E_MAX_ERROR_COUNT_EXCEEDED
    case WINBIO_E_MAX_ERROR_COUNT_EXCEEDED:
        return "WINBIO_E_MAX_ERROR_COUNT_EXCEEDED";
#endif
#ifdef WINBIO_E_AUTO_LOGON_DISABLED
    case WINBIO_E_AUTO_LOGON_DISABLED:
        return "WINBIO_E_AUTO_LOGON_DISABLED";
#endif
#ifdef WINBIO_E_INVALID_TICKET
    case WINBIO_E_INVALID_TICKET:
        return "WINBIO_E_INVALID_TICKET";
#endif
#ifdef WINBIO_E_TICKET_QUOTA_EXCEEDED
    case WINBIO_E_TICKET_QUOTA_EXCEEDED:
        return "WINBIO_E_TICKET_QUOTA_EXCEEDED";
#endif
#ifdef WINBIO_E_DATA_PROTECTION_FAILURE
    case WINBIO_E_DATA_PROTECTION_FAILURE:
        return "WINBIO_E_DATA_PROTECTION_FAILURE";
#endif
#ifdef WINBIO_E_CRED_PROV_SECURITY_LOCKOUT
    case WINBIO_E_CRED_PROV_SECURITY_LOCKOUT:
        return "WINBIO_E_CRED_PROV_SECURITY_LOCKOUT";
#endif
#ifdef WINBIO_E_UNSUPPORTED_POOL_TYPE
    case WINBIO_E_UNSUPPORTED_POOL_TYPE:
        return "WINBIO_E_UNSUPPORTED_POOL_TYPE";
#endif
#ifdef WINBIO_E_SELECTION_REQUIRED
    case WINBIO_E_SELECTION_REQUIRED:
        return "WINBIO_E_SELECTION_REQUIRED";
#endif
#ifdef WINBIO_E_PRESENCE_MONITOR_ACTIVE
    case WINBIO_E_PRESENCE_MONITOR_ACTIVE:
        return "WINBIO_E_PRESENCE_MONITOR_ACTIVE";
#endif
#ifdef WINBIO_E_INVALID_SUBFACTOR
    case WINBIO_E_INVALID_SUBFACTOR:
        return "WINBIO_E_INVALID_SUBFACTOR";
#endif
#ifdef WINBIO_E_INVALID_CALIBRATION_FORMAT_ARRAY
    case WINBIO_E_INVALID_CALIBRATION_FORMAT_ARRAY:
        return "WINBIO_E_INVALID_CALIBRATION_FORMAT_ARRAY";
#endif
#ifdef WINBIO_E_NO_SUPPORTED_CALIBRATION_FORMAT
    case WINBIO_E_NO_SUPPORTED_CALIBRATION_FORMAT:
        return "WINBIO_E_NO_SUPPORTED_CALIBRATION_FORMAT";
#endif
#ifdef WINBIO_E_UNSUPPORTED_SENSOR_CALIBRATION_FORMAT
    case WINBIO_E_UNSUPPORTED_SENSOR_CALIBRATION_FORMAT:
        return "WINBIO_E_UNSUPPORTED_SENSOR_CALIBRATION_FORMAT";
#endif
#ifdef WINBIO_E_CALIBRATION_BUFFER_TOO_SMALL
    case WINBIO_E_CALIBRATION_BUFFER_TOO_SMALL:
        return "WINBIO_E_CALIBRATION_BUFFER_TOO_SMALL";
#endif
#ifdef WINBIO_E_CALIBRATION_BUFFER_TOO_LARGE
    case WINBIO_E_CALIBRATION_BUFFER_TOO_LARGE:
        return "WINBIO_E_CALIBRATION_BUFFER_TOO_LARGE";
#endif
#ifdef WINBIO_E_CALIBRATION_BUFFER_INVALID
    case WINBIO_E_CALIBRATION_BUFFER_INVALID:
        return "WINBIO_E_CALIBRATION_BUFFER_INVALID";
#endif
    default:
        return "UNKNOWN";
    }
}

static const char *reject_detail_to_string(DWORD detail)
{
    switch (detail) {
    case WINBIO_FP_TOO_HIGH:    return "WINBIO_FP_TOO_HIGH";
    case WINBIO_FP_TOO_LOW:     return "WINBIO_FP_TOO_LOW";
    case WINBIO_FP_TOO_LEFT:    return "WINBIO_FP_TOO_LEFT";
    case WINBIO_FP_TOO_RIGHT:   return "WINBIO_FP_TOO_RIGHT";
    case WINBIO_FP_TOO_FAST:    return "WINBIO_FP_TOO_FAST";
    case WINBIO_FP_TOO_SLOW:    return "WINBIO_FP_TOO_SLOW";
    case WINBIO_FP_POOR_QUALITY:return "WINBIO_FP_POOR_QUALITY";
    case WINBIO_FP_TOO_SKEWED:  return "WINBIO_FP_TOO_SKEWED";
    case WINBIO_FP_TOO_SHORT:   return "WINBIO_FP_TOO_SHORT";
    case WINBIO_FP_MERGE_FAILURE:return "WINBIO_FP_MERGE_FAILURE";
    default:                    return "NONE";
    }
}

static const char *
identity_type_to_string(WINBIO_IDENTITY_TYPE type)
{
    switch(type) {
    case WINBIO_ID_TYPE_WILDCARD: return "WINBIO_ID_TYPE_WILDCARD";
    case WINBIO_ID_TYPE_GUID:     return "WINBIO_ID_TYPE_GUID";
    case WINBIO_ID_TYPE_SID:      return "WINBIO_ID_TYPE_SID";
    default:                      return "UNKNOWN";
    }
}

static const char *
subfactor_to_string(WINBIO_BIOMETRIC_SUBTYPE sub)
{
    switch(sub) {
    case WINBIO_SUBTYPE_NO_INFORMATION:    return "WINBIO_SUBTYPE_NO_INFORMATION(0)";
    case WINBIO_SUBTYPE_ANY:               return "WINBIO_SUBTYPE_ANY";
    case WINBIO_ANSI_381_POS_RH_THUMB:      return "RH_THUMB";
    case WINBIO_ANSI_381_POS_RH_INDEX_FINGER: return "RH_INDEX_FINGER";
    case WINBIO_ANSI_381_POS_RH_MIDDLE_FINGER: return "RH_MIDDLE_FINGER";
    case WINBIO_ANSI_381_POS_RH_RING_FINGER: return "RH_RING_FINGER";
    case WINBIO_ANSI_381_POS_RH_LITTLE_FINGER: return "RH_LITTLE_FINGER";
    case WINBIO_ANSI_381_POS_LH_THUMB:      return "LH_THUMB";
    case WINBIO_ANSI_381_POS_LH_INDEX_FINGER: return "LH_INDEX_FINGER";
    case WINBIO_ANSI_381_POS_LH_MIDDLE_FINGER: return "LH_MIDDLE_FINGER";
    case WINBIO_ANSI_381_POS_LH_RING_FINGER: return "LH_RING_FINGER";
    case WINBIO_ANSI_381_POS_LH_LITTLE_FINGER: return "LH_LITTLE_FINGER";
    case WINBIO_ANSI_381_POS_RH_FOUR_FINGERS: return "RH_FOUR_FINGERS";
    case WINBIO_ANSI_381_POS_LH_FOUR_FINGERS: return "LH_FOUR_FINGERS";
    case WINBIO_ANSI_381_POS_TWO_THUMBS:    return "TWO_THUMBS";
    default: {
        static char buf[32];
        snprintf(buf, sizeof(buf), "UNKNOWN(%u)", (unsigned)sub);
        return buf;
    }
    }
}

static const char *
biometric_type_to_string(WINBIO_BIOMETRIC_TYPE type)
{
    switch(type) {
    case WINBIO_NO_TYPE_AVAILABLE:      return "WINBIO_NO_TYPE_AVAILABLE(0)";
    case WINBIO_TYPE_MULTIPLE:           return "WINBIO_TYPE_MULTIPLE";
    case WINBIO_TYPE_FACIAL_FEATURES:    return "WINBIO_TYPE_FACIAL_FEATURES";
    case WINBIO_TYPE_VOICE:              return "WINBIO_TYPE_VOICE";
    case WINBIO_TYPE_FINGERPRINT:        return "WINBIO_TYPE_FINGERPRINT";
    case WINBIO_TYPE_IRIS:               return "WINBIO_TYPE_IRIS";
    case WINBIO_TYPE_RETINA:             return "WINBIO_TYPE_RETINA";
    case WINBIO_TYPE_HAND_GEOMETRY:      return "WINBIO_TYPE_HAND_GEOMETRY";
    case WINBIO_TYPE_SIGNATURE_DYNAMICS: return "WINBIO_TYPE_SIGNATURE_DYNAMICS";
    case WINBIO_TYPE_KEYSTROKE_DYNAMICS: return "WINBIO_TYPE_KEYSTROKE_DYNAMICS";
    case WINBIO_TYPE_LIP_MOVEMENT:       return "WINBIO_TYPE_LIP_MOVEMENT";
    case WINBIO_TYPE_THERMAL_FACE_IMAGE: return "WINBIO_TYPE_THERMAL_FACE_IMAGE";
    case WINBIO_TYPE_THERMAL_HAND_IMAGE: return "WINBIO_TYPE_THERMAL_HAND_IMAGE";
    case WINBIO_TYPE_GAIT:               return "WINBIO_TYPE_GAIT";
    case WINBIO_TYPE_SCENT:              return "WINBIO_TYPE_SCENT";
    case WINBIO_TYPE_DNA:                return "WINBIO_TYPE_DNA";
    case WINBIO_TYPE_EAR_SHAPE:          return "WINBIO_TYPE_EAR_SHAPE";
    case WINBIO_TYPE_FINGER_GEOMETRY:    return "WINBIO_TYPE_FINGER_GEOMETRY";
    case WINBIO_TYPE_PALM_PRINT:         return "WINBIO_TYPE_PALM_PRINT";
    case WINBIO_TYPE_VEIN_PATTERN:       return "WINBIO_TYPE_VEIN_PATTERN";
    case WINBIO_TYPE_FOOT_PRINT:         return "WINBIO_TYPE_FOOT_PRINT";
    case WINBIO_TYPE_OTHER:              return "WINBIO_TYPE_OTHER";
    case WINBIO_TYPE_PASSWORD:           return "WINBIO_TYPE_PASSWORD";
    default: {
        static char buf[48];
        snprintf(buf, sizeof(buf), "UNKNOWN(0x%08lx)", (unsigned long)type);
        return buf;
    }
    }
}

static const char *
sensor_subtype_to_string(WINBIO_BIOMETRIC_SENSOR_SUBTYPE sub)
{
    switch(sub) {
    case WINBIO_SENSOR_SUBTYPE_UNKNOWN: return "WINBIO_SENSOR_SUBTYPE_UNKNOWN(0)";
    case WINBIO_FP_SENSOR_SUBTYPE_SWIPE: return "WINBIO_FP_SENSOR_SUBTYPE_SWIPE";
    case WINBIO_FP_SENSOR_SUBTYPE_TOUCH: return "WINBIO_FP_SENSOR_SUBTYPE_TOUCH";
    default: {
        static char buf[48];
        snprintf(buf, sizeof(buf), "UNKNOWN(0x%08lx)", (unsigned long)sub);
        return buf;
    }
    }
}

static void
capabilities_to_string(WINBIO_CAPABILITIES caps, char *buf, size_t bufsize)
{
    buf[0] = '\0';
    if(caps == 0) {
        snprintf(buf, bufsize, "NONE(0x%08lx)", (unsigned long)caps);
        return;
    }
    size_t pos = 0;
    #define ADD_FLAG(flag, name) do { \
        if(caps & (flag)) { \
            if(pos > 0) { \
                if(pos < bufsize - 1) buf[pos++] = '|'; \
            } \
            size_t sl = strlen(name); \
            if(pos + sl < bufsize - 1) { \
                memcpy(buf + pos, name, sl); \
                pos += sl; \
            } \
        } \
    } while(0)
    ADD_FLAG(WINBIO_CAPABILITY_SENSOR, "SENSOR");
    ADD_FLAG(WINBIO_CAPABILITY_MATCHING, "MATCHING");
    ADD_FLAG(WINBIO_CAPABILITY_DATABASE, "DATABASE");
    ADD_FLAG(WINBIO_CAPABILITY_PROCESSING, "PROCESSING");
    ADD_FLAG(WINBIO_CAPABILITY_ENCRYPTION, "ENCRYPTION");
    ADD_FLAG(WINBIO_CAPABILITY_NAVIGATION, "NAVIGATION");
    ADD_FLAG(WINBIO_CAPABILITY_INDICATOR, "INDICATOR");
    #undef ADD_FLAG
    buf[pos] = '\0';
}

static void
display_identity(WINBIO_IDENTITY *identity, const char *prefix)
{
    HLOG_USER("%sIdentityType=%lu (%s)\n", prefix,
        (unsigned long)identity->Type,
        identity_type_to_string(identity->Type));
    if(identity->Type == WINBIO_ID_TYPE_SID) {
        HLOG_USER("%s  SID[%lu]=", prefix, (unsigned long)identity->Value.AccountSid.Size);
        for(ULONG j=0; j<identity->Value.AccountSid.Size && j<SECURITY_MAX_SID_SIZE; j++)
            HLOG_USER("%02x", identity->Value.AccountSid.Data[j]);
        HLOG_USER("\n");
    } else if(identity->Type == WINBIO_ID_TYPE_GUID) {
        HLOG_USER("%s  GUID=%08lx-%04x-%04x-",
            prefix,
            (unsigned long)identity->Value.TemplateGuid.Data1,
            identity->Value.TemplateGuid.Data2,
            identity->Value.TemplateGuid.Data3);
        for(int j=0;j<2;j++) HLOG_USER("%02x", identity->Value.TemplateGuid.Data4[j]);
        HLOG_USER("-");
        for(int j=2;j<8;j++) HLOG_USER("%02x", identity->Value.TemplateGuid.Data4[j]);
        HLOG_USER("\n");
    } else {
        HLOG_USER("%s  IdentityValue=%lu\n", prefix, (unsigned long)identity->Value.Wildcard);
    }
}

struct MyNamedPropertyStore : public IWDFNamedPropertyStore2 {
    std::map<std::wstring, PROPVARIANT*> m_store;
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyMem::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("New NamedPropertyStore: ppvObject=%p\r\n", *ppvObject);
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("MyNamedPropertyStore::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("MyNamedPropertyStore::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("MyNamedPropertyStore::DeleteWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) {
            HLOG_DEBUG("MyNamedPropertyStore::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) {
            HLOG_DEBUG("MyNamedPropertyStore::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            HLOG_DEBUG("MyNamedPropertyStore::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            HLOG_DEBUG("MyNamedPropertyStore::ReleaseLock\r\n");
        }
    public:
        virtual HRESULT STDMETHODCALLTYPE GetNamedValue(
            /* [annotation][string][in] */
            _In_  LPCWSTR pszName,
            /* [annotation][out] */
            _Out_  PROPVARIANT *pv){
            HLOG_DEBUG("MyNamedPropertyStore::GetNamedValue %ls %d\n", pszName, pv->vt);

            auto name = std::wstring(pszName);
            auto it = m_store.find(name);
            if (it != m_store.end()) {
                HLOG_INFO("Return cached value %d\n", it->second->vt);
                *pv = *it->second;
                return S_OK;
            }

            std::string fname;
            std::wstring wfname(pszName);
            fname.assign(wfname.begin(), wfname.end());
            if(fname == "CalibrationData") {
                std::ifstream input(fname + ".blob", std::ios::binary);
                std::vector<char> buf((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
                HLOG_INFO("Loaded %zu bytes of calibration data\n", buf.size());
                if(buf.size() == 0) {
                    DECIMAL_SETZERO(pv->decVal);
                } else {
                    pv->vt = VT_BLOB;
                    pv->blob.cbSize = buf.size();
                    pv->blob.pBlobData = (BYTE*)CoTaskMemAlloc(pv->blob.cbSize);
                    std::copy(buf.begin(), buf.end(), pv->blob.pBlobData);
                }
            }
            else if(fname == "LastUpdateSystemTimeStamp" || fname == "OldCalDataDeleted") {
                std::ifstream input(fname + ".uint");
                if(input) {
                    pv->vt = VT_UINT;
                    input >> pv->uintVal;
                    HLOG_DEBUG("UINT %s = %d\n", fname.c_str(), pv->uintVal);
                }
                else {
                    DECIMAL_SETZERO(pv->decVal);
                    std::cout << "UINT " << fname << " not found" << std::endl;
                }
            }
            else if (fname == "PairingInProcess" || fname == "UnairingInProcess" ||
                     fname == "DeviceUpdateInProcess") {
                    // InitPropVariantFromBoolean(FALSE, pv);
                    pv->vt = VT_BOOL;
                    pv->boolVal = VARIANT_FALSE;
            }
            else {
                DECIMAL_SETZERO(pv->decVal);
                return E_NOTIMPL;
            }
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE SetNamedValue(
            /* [annotation][string][in] */
            _In_  LPCWSTR pszName,
            /* [annotation][in] */
            _In_  const PROPVARIANT *pv){
            //wchar_t *buf = L"<error>";
            //LONG num = 118;
            //PropVariantToInt32(*pv, &num);
            //PropVariantToStringAlloc(*pv, &buf);

            HLOG_DEBUG("MyNamedPropertyStore::SetNamedValue %ls (%d)\n", pszName, pv->vt);
            switch(pv->vt) {
                case VT_I1:
                    HLOG_DEBUG("  VT_I1: %d\n", pv->cVal);
                    break;
                case VT_UI4:
                    HLOG_DEBUG("  VT_UI4: %lu\n", (unsigned long)pv->ulVal);
                    break;
                case VT_UINT: {
                        std::string fname;
                        std::wstring wfname(pszName);
                        fname.assign(wfname.begin(), wfname.end());
                        std::ofstream output(fname + ".uint");
                        output << pv->uintVal << std::endl;
                        HLOG_DEBUG("  VT_UINT: %d\n", pv->uintVal);
                    }
                    break;
                case VT_BLOB: {
                        std::string fname;
                        std::wstring wfname(pszName);
                        fname.assign(wfname.begin(), wfname.end());
                        std::ofstream output(fname + ".blob", std::ios::binary);
                        std::copy(pv->blob.pBlobData, pv->blob.pBlobData + pv->blob.cbSize,
                                std::ostreambuf_iterator<char>(output));

                        char hex[800020], *p = hex;
                        for(unsigned int i=0;i<(pv->blob.cbSize < 400? pv->blob.cbSize : 400);i++) {
                            p+=sprintf(p, "%02x", pv->blob.pBlobData[i]);
                        }
                        *p=0;
                        HLOG_DEBUG("  Blob value: %lu: %s\n", pv->blob.cbSize, hex);
                    }
                    break;
            }

            PROPVARIANT *copy = (PROPVARIANT*) malloc(sizeof(PROPVARIANT));
            PropVariantCopy(copy, pv);
            std::wstring wfname(pszName);
            m_store.insert({wfname, copy});

            //CoTaskMemFree(buf);
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE GetNameCount(
            /* [annotation][out] */
            _Out_  DWORD *pdwCount){
            HLOG_DEBUG("MyNamedPropertyStore::GetNameCount\n");
            *pdwCount = 0;
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE GetNameAt(
            /* [annotation][in] */
            _In_  DWORD iProp,
            /* [annotation][string][out] */
            _Out_  PWSTR *ppwszName){
            HLOG_DEBUG("MyNamedPropertyStore::GetNameAt %lu\n", (unsigned long)iProp);
            static WCHAR emptyStr[] = L""; *ppwszName = emptyStr;
            return 0;
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE DeleteNamedValue(
            /* [annotation][string][in] */
            _In_  LPCWSTR pwszName){
            std::wcout << L"MyNamedPropertyStore::DeleteNamedValue " << pwszName<< std::endl;
            return 0;
        }

};


struct MyPropertyStoreFactory : public IWDFPropertyStoreFactory {
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyPropertyStoreFactory::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("IWDFPropertyStoreFactory::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("MyPropertyStoreFactory::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("MyPropertyStoreFactory::DeleteWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) {
            HLOG_DEBUG("MyPropertyStoreFactory::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) {
            HLOG_DEBUG("MyPropertyStoreFactory::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            HLOG_DEBUG("MyPropertyStoreFactory::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            HLOG_DEBUG("MyPropertyStoreFactory::ReleaseLock\r\n");
        }
    public:
        virtual HRESULT STDMETHODCALLTYPE RetrieveDevicePropertyStore(
            /* [annotation][in] */
            _In_  PWDF_PROPERTY_STORE_ROOT RootSpecifier,
            /* [annotation][in] */
            _In_  WDF_PROPERTY_STORE_RETRIEVE_FLAGS Flags,
            /* [annotation][in] */
            _In_  REGSAM DesiredAccess,
            /* [annotation][unique][in] */
            _In_opt_  PCWSTR SubkeyPath,
            /* [annotation][out] */
            _Out_  IWDFNamedPropertyStore2 **PropertyStore,
            /* [annotation][unique][out] */
            _Out_opt_  WDF_PROPERTY_STORE_DISPOSITION *Disposition){
            HLOG_DEBUG("MyPropertyStoreFactory::RetrieveDevicePropertyStore\r\n");
            *PropertyStore = new MyNamedPropertyStore();
            return 0;
        }

};

struct MyMem : public IWDFMemory {
    public:
        MyMem(void *b, SIZE_T s) {
            buf = b;
            size = s;
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyMem::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("MyMem::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("MyMem::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("MyMem::DeleteWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) {
            HLOG_DEBUG("AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) {
            HLOG_DEBUG("RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            HLOG_DEBUG("AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            HLOG_DEBUG("ReleaseLock\r\n");
        }
    public:
        virtual HRESULT STDMETHODCALLTYPE CopyFromMemory(
            /* [annotation][in] */
            _In_  IWDFMemory *Source,
            /* [annotation][unique][in] */
            _In_opt_  PWDFMEMORY_OFFSET SourceOffset){
            HLOG_DEBUG("CopyFromMemory\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE CopyToBuffer(
            /* [annotation][in] */
            _In_  ULONG_PTR SourceOffset,
            /* [annotation][size_is][in] */
            _Out_writes_bytes_(NumOfBytesToCopyTo)  void *TargetBuffer,
            /* [annotation][in] */
            _In_  SIZE_T NumOfBytesToCopyTo){
            HLOG_DEBUG("CopyToBuffer\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE CopyFromBuffer(
            /* [annotation][in] */
            _In_  ULONG_PTR DestOffset,
            /* [annotation][size_is][in] */
            _In_reads_bytes_(NumOfBytesToCopyFrom)  void *SourceBuffer,
            /* [annotation][in] */
            _In_  SIZE_T NumOfBytesToCopyFrom){
            HLOG_DEBUG("CopyFromBuffer\r\n");
            return 0;
        }


        virtual SIZE_T STDMETHODCALLTYPE GetSize( void){
            HLOG_DEBUG("GetSize\r\n");
            return size;
        }


        virtual void *STDMETHODCALLTYPE GetDataBuffer(
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *BufferSize){
            if(BufferSize) {
                *BufferSize = size;
            }
            HLOG_DEBUG("MyMem::GetDataBuffer size=%llu\r\n", size);
            return buf;
        }


        virtual void STDMETHODCALLTYPE SetBuffer(
            /* [annotation][size_is][in] */
            _In_reads_bytes_(BufferSize)  void *Buffer,
            /* [annotation][in] */
            _In_  SIZE_T BufferSize){
            HLOG_DEBUG("SetBuffer\r\n");
            buf = Buffer;
            size = BufferSize;
        }

    void * buf;
    SIZE_T size;
};

class MyUsbRequestCompletionParams : public IWDFUsbRequestCompletionParams
    {
    public:
        MyUsbRequestCompletionParams(WDF_REQUEST_TYPE rt, ULONG sent) :
            m_request_type(rt),
            // FIXME: use actual type
            m_usb_request_type(WdfUsbRequestTypeDeviceControlTransfer),
            m_sent(sent) {}

        virtual ULONG STDMETHODCALLTYPE AddRef() override {
            HLOG_DEBUG("MyUsbRequestCompletionParams::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() override {
            HLOG_DEBUG("MyUsbRequestCompletionParams::Release\r\n");
            return 0;
        }
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyUsbRequestCompletionParams::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE GetCompletionStatus() override {
            HLOG_DEBUG("MyUsbRequestCompletionParams::GetCompletionStatus\r\n");
            return S_OK;
        }

        virtual ULONG_PTR STDMETHODCALLTYPE GetInformation() override {
            HLOG_DEBUG("MyUsbRequestCompletionParams::GetInformation\r\n");
            return m_sent;
        }

        virtual WDF_REQUEST_TYPE STDMETHODCALLTYPE GetCompletedRequestType() override {
            HLOG_DEBUG("MyUsbRequestCompletionParams::GetCompletedRequestType: %d\r\n", m_request_type);
            return m_request_type;
        }

        virtual WDF_USB_REQUEST_TYPE STDMETHODCALLTYPE GetCompletedUsbRequestType() override {
            HLOG_DEBUG("MyUsbRequestCompletionParams::GetCompletedRequestType2: %d\r\n",
                m_usb_request_type);
            return m_usb_request_type;
        };

        virtual void STDMETHODCALLTYPE GetDeviceControlTransferParameters(
            /* [annotation][unique][out] */
            _Out_opt_  IWDFMemory **ppMemory,
            /* [annotation][unique][out] */
            _Out_opt_  ULONG *pLengthTransferred,
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pOffset,
            /* [annotation][unique][out] */
            _Out_opt_  PWINUSB_SETUP_PACKET pSetupPacket) override {
            HLOG_DEBUG("MyUsbRequestCompletionParams::GetDeviceControlTransferParameters\r\n");
            assert(false && "NOT IMPLEMENTED");
        }

        virtual void STDMETHODCALLTYPE GetPipeWriteParameters(
            /* [annotation][unique][out] */
            _Out_opt_  IWDFMemory **ppWriteMemory,
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pBytesWritten,
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pWriteMemoryOffset) override {
            HLOG_DEBUG("MyUsbRequestCompletionParams::GetPipeWriteParameters\r\n");
            assert(false && "NOT IMPLEMENTED");
        }

        virtual void STDMETHODCALLTYPE GetPipeReadParameters(
            /* [annotation][unique][out] */
            _Out_opt_  IWDFMemory **ppReadMemory,
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pBytesRead,
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pReadMemoryOffset) override {
            HLOG_DEBUG("MyUsbRequestCompletionParams::GetPipeReadParameters\r\n");
            assert(false && "NOT IMPLEMENTED");
        }

    private:
        WDF_REQUEST_TYPE m_request_type;
        WDF_USB_REQUEST_TYPE m_usb_request_type;
        ULONG m_sent;
    };

struct MyRequest : public IWDFIoRequest {
    public:
        MyRequest(WDF_REQUEST_TYPE t, ULONG c, MyMem *out, MyMem *in) {
            reqType = t;
            ctl = c;
            outMem = out;
            inMem = in;
            complete = FALSE;
            informationSize = 0;
            completionStatus = S_OK;
        }

        IRequestCallbackCancel *cancelCallback;
        WDF_REQUEST_TYPE reqType;
        ULONG ctl;
        BOOL complete;
        LONG_PTR informationSize;
        HRESULT completionStatus;
        WINUSB_SETUP_PACKET m_setupPacket;
        ULONG m_sent = 0;

        enum UsbOp { UsbControl, UsbPipeRead, UsbPipeWrite } m_usbOp = UsbControl;
        WINUSB_INTERFACE_HANDLE m_pipeHandle = nullptr;
        UCHAR m_pipeId = 0;
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyRequest::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("MyRequest::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("MyRequest::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("MyRequest::DeleteWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) {
            HLOG_DEBUG("MyRequest::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) {
            HLOG_DEBUG("MyRequest::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            HLOG_DEBUG("MyRequest::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            HLOG_DEBUG("MyRequest::ReleaseLock\r\n");
        }
    public:
        virtual void STDMETHODCALLTYPE CompleteWithInformation(
            /* [annotation][in] */
            _In_  HRESULT CompletionStatus,
            /* [annotation][in] */
            _In_  SIZE_T Information){
            HLOG_INFO("MyRequest::CompleteWithInformation: %lx (%s)\r\n", (unsigned long)CompletionStatus,
                hresult_to_sting(CompletionStatus));
            completionStatus = CompletionStatus;
            informationSize = Information;
            complete = TRUE;
        }

        virtual void STDMETHODCALLTYPE SetInformation(
            /* [annotation][in] */
            _In_  ULONG_PTR Information){
            HLOG_INFO("MyRequest::SetInformation size=%lld\r\n", Information);
            informationSize = Information;
        }

        virtual void STDMETHODCALLTYPE Complete(
            /* [annotation][in] */
            _In_  HRESULT CompletionStatus){
            HLOG_INFO("MyRequest::Complete: %lx (%s)\r\n", (unsigned long)CompletionStatus,
                hresult_to_sting(CompletionStatus));
            completionStatus = CompletionStatus;
            complete = TRUE;
        }

        virtual void STDMETHODCALLTYPE SetCompletionCallback(
            /* [annotation][in] */
            _In_  IRequestCallbackRequestCompletion *pCompletionCallback,
            /* [annotation][unique][in] */
            _In_opt_  void *pContext){
            HLOG_DEBUG("MyRequest::SetCompletionCallback\r\n");
        }

        virtual WDF_REQUEST_TYPE STDMETHODCALLTYPE GetType( void){
            HLOG_DEBUG("MyRequest::GetType\r\n");
            return reqType;
        }

        virtual void STDMETHODCALLTYPE GetCreateParameters(
            /* [annotation][unique][out] */
            _Out_opt_  ULONG *pOptions,
            /* [annotation][unique][out] */
            _Out_opt_  USHORT *pFileAttributes,
            /* [annotation][unique][out] */
            _Out_opt_  USHORT *pShareAccess){
            HLOG_DEBUG("MyRequest::GetCreateParameters\r\n");
        }


        virtual void STDMETHODCALLTYPE GetReadParameters(
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pSizeInBytes,
            /* [annotation][unique][out] */
            _Out_opt_  LONGLONG *pullOffset,
            /* [annotation][unique][out] */
            _Out_opt_  ULONG *pulKey){
            HLOG_DEBUG("MyRequest::GetReadParameters\r\n");
        }


        virtual void STDMETHODCALLTYPE GetWriteParameters(
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pSizeInBytes,
            /* [annotation][unique][out] */
            _Out_opt_  LONGLONG *pullOffset,
            /* [annotation][unique][out] */
            _Out_opt_  ULONG *pulKey){
            HLOG_DEBUG("MyRequest::GetWriteParameters\r\n");
        }


        virtual void STDMETHODCALLTYPE GetDeviceIoControlParameters(
            /* [annotation][unique][out] */
            _Out_opt_  ULONG *pControlCode,
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pInBufferSize,
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pOutBufferSize){
            HLOG_DEBUG("MyRequest::GetDeviceIoControlParameters %p %p %p",
                pControlCode, pInBufferSize, pOutBufferSize);
            if (pControlCode)
                *pControlCode = ctl;
            if (pInBufferSize)
                *pInBufferSize = inMem->size;
            if (pOutBufferSize)
                *pOutBufferSize = outMem->size;

            HLOG_DEBUG("=> %zu %zu\r\n",
                    (size_t)(pInBufferSize ? *pInBufferSize : 0),
                    (size_t)(pOutBufferSize ? *pOutBufferSize : 0));
        }


        MyMem *outMem = nullptr;
        MyMem *inMem = nullptr;

        virtual void STDMETHODCALLTYPE GetOutputMemory(
            /* [annotation][out] */
            _Out_  IWDFMemory **ppWdfMemory){
            HLOG_DEBUG("MyRequest::GetOutputMemory => %p\r\n", outMem);
            *ppWdfMemory = outMem;
        }

        virtual void STDMETHODCALLTYPE GetInputMemory(
            /* [annotation][out] */
            _Out_  IWDFMemory **ppWdfMemory){
            HLOG_DEBUG("MyRequest::GetInputMemory => %p\r\n", inMem);
            *ppWdfMemory = inMem;
        }

        virtual void STDMETHODCALLTYPE MarkCancelable(
            /* [annotation][in] */
            _In_  IRequestCallbackCancel *pCancelCallback){
            HLOG_DEBUG("MyRequest::MarkCancelable\r\n");
            this->cancelCallback = pCancelCallback;
        }

        virtual HRESULT STDMETHODCALLTYPE UnmarkCancelable( void){
            HLOG_DEBUG("MyRequest::UnmarkCancelable\r\n");
            return 0;
        }


        virtual BOOL STDMETHODCALLTYPE CancelSentRequest( void){
            HLOG_DEBUG("MyRequest::CancelSentRequest\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE ForwardToIoQueue(
            /* [annotation][in] */
            _In_  IWDFIoQueue *pDestination){
            HLOG_DEBUG("MyRequest::ForwardToIoQueue\r\n");
            return 0;
        }

        void SetControlData(PWINUSB_SETUP_PACKET SetupPacket,
                            IWDFMemory *pMemory,
                            PWDFMEMORY_OFFSET Offset) {
            HLOG_DEBUG("MyRequest::SetControlData: %p %p %p\r\n",
                SetupPacket, pMemory, Offset);
            m_setupPacket = *SetupPacket;
            outMem = (MyMem *) pMemory;
            m_usbOp = UsbControl;
            m_pipeHandle = nullptr;
            m_pipeId = 0;
        }

        virtual HRESULT STDMETHODCALLTYPE Send(
            /* [annotation][in] */
            _In_  IWDFIoTarget *pIoTarget,
            /* [annotation][in] */
            _In_  ULONG Flags,
            /* [annotation][in] */
            _In_  LONGLONG Timeout){
            assert(reqType == WdfRequestUsb);
            HLOG_DEBUG("MyRequest::Send %p | %lu | %lld\r\n", pIoTarget,
                    (unsigned long)Flags, (long long)Timeout);

            if (Flags != WDF_REQUEST_SEND_OPTION_SYNCHRONOUS) {
                HLOG_INFO("Flags are not supported: %lu\r\n", (unsigned long)Flags);
                return E_NOTIMPL;
            }

            PUCHAR buffer = nullptr;
            SIZE_T bufLen = 0;
            m_sent = 0;

            if (outMem)
                buffer = (PUCHAR) outMem->GetDataBuffer(&bufLen);

            if (m_usbOp == UsbPipeRead) {
                if (!WinUsb_ReadPipe(m_pipeHandle, m_pipeId, buffer, bufLen, &m_sent, 0)) {
                    HLOG_DEBUG("Fail to read pipe: %lu (%s)\n", (unsigned long)GetLastError(),
                        hresult_to_sting(GetLastError()));
                    return GetLastError();
                }
                HLOG_DEBUG("Pipe read: %zu - Actual data transferred: %lu.\n",
                    (size_t)bufLen, (unsigned long)m_sent);
                HLOG_DEBUG("<- ");
                for (SIZE_T i = 0; i < m_sent; ++i)
                    HLOG_DEBUG("%02x", buffer[i]);
                HLOG_DEBUG("\r\n");
            } else if (m_usbOp == UsbPipeWrite) {
                if (!WinUsb_WritePipe(m_pipeHandle, m_pipeId, buffer, bufLen, &m_sent, 0)) {
                    HLOG_DEBUG("Fail to write pipe: %lu (%s)\n", (unsigned long)GetLastError(),
                        hresult_to_sting(GetLastError()));
                    return GetLastError();
                }
                HLOG_DEBUG("Pipe write: %zu - Actual data transferred: %lu.\n",
                    (size_t)bufLen, (unsigned long)m_sent);
            } else {
                auto usbDev = (IWDFUsbTargetDevice *) pIoTarget;

                if (m_setupPacket.Length && !(m_setupPacket.RequestType & 0b10000000)) {
                    HLOG_DEBUG("-> ");
                    for (SIZE_T i = 0; i < bufLen; ++i)
                        HLOG_DEBUG("%02x", buffer[i]);
                    HLOG_DEBUG("\r\n");
                }

                if (!WinUsb_ControlTransfer(usbDev->GetWinUsbHandle(), m_setupPacket,
                    buffer, bufLen, &m_sent, 0)) {
                    HLOG_DEBUG("Fail to send data: %lu (%s)\n", (unsigned long)GetLastError(),
                        hresult_to_sting(GetLastError()));
                    return GetLastError();
                }
                HLOG_DEBUG("Data sent: %zu - Actual data transferred: %lu.\n",
                    (size_t)bufLen, (unsigned long)m_sent);

                if (m_setupPacket.Length && (m_setupPacket.RequestType & 0b10000000)) {
                    HLOG_DEBUG("<- ");
                    for (SIZE_T i = 0; i < m_sent; ++i)
                        HLOG_DEBUG("%02x", buffer[i]);
                    HLOG_DEBUG("\r\n");
                }
            }

            m_usbOp = UsbControl;
            m_pipeHandle = nullptr;
            m_pipeId = 0;
            outMem = nullptr;
            inMem = outMem;

            // WDF_REQUEST_SEND_OPTION_TIMEOUT
            // WDF_REQUEST_SEND_OPTION_IGNORE_TARGET_STATE
            // WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET
            return 0;
        }

        virtual void STDMETHODCALLTYPE GetFileObject(
            /* [annotation][out] */
            _Out_  IWDFFile **ppFileObject){
            HLOG_DEBUG("MyRequest::GetFileObject\r\n");
        }

        virtual void STDMETHODCALLTYPE FormatUsingCurrentType( void){
            HLOG_DEBUG("MyRequest::FormatUsingCurrentType\r\n");
        }

        virtual ULONG STDMETHODCALLTYPE GetRequestorProcessId( void){
            HLOG_DEBUG("MyRequest::GetRequestorProcessId\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE GetIoQueue(
            /* [annotation][out] */
            _Out_  IWDFIoQueue **ppWdfIoQueue){
            HLOG_DEBUG("MyRequest::GetIoQueue\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE Impersonate(
            /* [annotation][in] */
            _In_  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            /* [annotation][in] */
            _In_  IImpersonateCallback *pCallback,
            /* [annotation][unique][in] */
            _In_opt_  void *pvCallbackContext){
            HLOG_DEBUG("MyRequest::Impersonate\r\n");
            return 0;
        }


        virtual BOOL STDMETHODCALLTYPE IsFrom32BitProcess( void){
            HLOG_DEBUG("MyRequest::IsFrom32BitProcess\r\n");
            return 1;
        }

        virtual void STDMETHODCALLTYPE GetCompletionParams(
            /* [annotation][out] */
            _Out_  IWDFRequestCompletionParams **ppCompletionParams){
            HLOG_DEBUG("MyRequest::GetCompletionParams\r\n");
            *ppCompletionParams = new MyUsbRequestCompletionParams(reqType, m_sent);
        }
};

struct MyQueue : public IWDFIoQueue {
    public:
        MyQueue(IUnknown *pCallbackInterface) {
            pCallbackInterface->AddRef();
            pCallbackInterface->QueryInterface(IID_IQueueCallbackDeviceIoControl, (LPVOID*)&ioctl);
            HLOG_DEBUG("ioctl=%p\r\n", ioctl);
        }

        IQueueCallbackDeviceIoControl *ioctl=0;

    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyQueue::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("MyQueue::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("MyQueue::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("MyQueue::DeleteWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) {
            HLOG_DEBUG("MyQueue::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) {
            HLOG_DEBUG("MyQueue::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            HLOG_DEBUG("MyQueue::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            HLOG_DEBUG("MyQueue::ReleaseLock\r\n");
        }
    public:
        virtual void STDMETHODCALLTYPE GetDevice(
            /* [annotation][out] */
            _Out_  IWDFDevice **ppWdfDevice){
            HLOG_DEBUG("MyQueue::GetDevice\r\n");
        }


        virtual HRESULT STDMETHODCALLTYPE ConfigureRequestDispatching(
            /* [annotation][in] */
            _In_  WDF_REQUEST_TYPE RequestType,
            /* [annotation][in] */
            _In_  BOOL Forward){
            HLOG_DEBUG("MyDevice::ConfigureRequestDispatching (%d, %d)\r\n",
                RequestType, Forward);
            return 0;
        }


        virtual WDF_IO_QUEUE_STATE STDMETHODCALLTYPE GetState(
            /* [annotation][out] */
            _Out_  ULONG *pulNumOfRequestsInQueue,
            /* [annotation][out] */
            _Out_  ULONG *pulNumOfRequestsInDriver){
            HLOG_DEBUG("MyQueue::GetState\r\n");
            return (WDF_IO_QUEUE_STATE)(WdfIoQueueAcceptRequests |
                    WdfIoQueueDispatchRequests |
                    WdfIoQueueNoRequests |
                    WdfIoQueueDriverNoRequests);
        }


        virtual HRESULT STDMETHODCALLTYPE RetrieveNextRequest(
            /* [annotation][out] */
            _Out_  IWDFIoRequest **ppRequest){
            HLOG_DEBUG("MyQueue::RetrieveNextRequest\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE RetrieveNextRequestByFileObject(
            /* [annotation][in] */
            _In_  IWDFFile *pFile,
            /* [annotation][out] */
            _Out_  IWDFIoRequest **ppRequest){
            HLOG_DEBUG("MyQueue::RetrieveNextRequestByFileObject\r\n");
            return 0;
        }


        virtual void STDMETHODCALLTYPE Start( void){
            HLOG_DEBUG("MyQueue::Start\r\n");
        }


        virtual void STDMETHODCALLTYPE Stop(
            /* [annotation][unique][in] */
            _In_opt_  IQueueCallbackStateChange *pStopComplete){
            HLOG_DEBUG("MyQueue::Stop\r\n");
        }


        virtual void STDMETHODCALLTYPE StopSynchronously( void){
            HLOG_DEBUG("MyQueue::StopSynchronously\r\n");
        }


        virtual void STDMETHODCALLTYPE Drain(
            /* [annotation][unique][in] */
            _In_opt_  IQueueCallbackStateChange *pDrainComplete){
            HLOG_DEBUG("MyQueue::Drain\r\n");
        }


        virtual void STDMETHODCALLTYPE DrainSynchronously( void){
            HLOG_DEBUG("MyQueue::Drain\r\n");
        }


        virtual void STDMETHODCALLTYPE Purge(
            /* [annotation][unique][in] */
            _In_opt_  IQueueCallbackStateChange *pPurgeComplete){
            HLOG_DEBUG("MyQueue::Purge\r\n");
        }


        virtual void STDMETHODCALLTYPE PurgeSynchronously( void){
            HLOG_DEBUG("MyQueue::Purge\r\n");
        }


};

/*

#include <usbiodef.h>

typedef struct _DEVICE_GUID_LIST {
    HDEVINFO   DeviceInfo;
    LIST_ENTRY ListHead;
} DEVICE_GUID_LIST, *PDEVICE_GUID_LIST;

typedef struct _DEVICE_INFO_NODE {
    HDEVINFO                         DeviceInfo;
    LIST_ENTRY                       ListEntry;
    SP_DEVINFO_DATA                  DeviceInfoData;
    SP_DEVICE_INTERFACE_DATA         DeviceInterfaceData;
    PSP_DEVICE_INTERFACE_DETAIL_DATA DeviceDetailData;
    PSTR                             DeviceDescName;
    ULONG                            DeviceDescNameLength;
    PSTR                             DeviceDriverName;
    ULONG                            DeviceDriverNameLength;
    DEVICE_POWER_STATE               LatestDevicePowerState;
} DEVICE_INFO_NODE, *PDEVICE_INFO_NODE;


#define OOPS() { HLOG_DEBUG("Failed at %d\r\n", __LINE__); }

BOOL
GetDeviceProperty(
    _In_    HDEVINFO         DeviceInfoSet,
    _In_    PSP_DEVINFO_DATA DeviceInfoData,
    _In_    DWORD            Property,
    _Outptr_  LPTSTR        *ppBuffer
    )
{
    BOOL bResult;
    DWORD requiredLength = 0;
    DWORD lastError;

    if (ppBuffer == NULL)
    {
        return FALSE;
    }

    *ppBuffer = NULL;

    bResult = SetupDiGetDeviceRegistryProperty(DeviceInfoSet,
                                               DeviceInfoData,
                                               Property ,
                                               NULL,
                                               NULL,
                                               0,
                                               &requiredLength);
    lastError = GetLastError();

    if ((requiredLength == 0) || (bResult != FALSE && lastError != ERROR_INSUFFICIENT_BUFFER))
    {
        return FALSE;
    }

    *ppBuffer = (PSTR) malloc(requiredLength);

    if (*ppBuffer == NULL)
    {
        return FALSE;
    }

    bResult = SetupDiGetDeviceRegistryProperty(DeviceInfoSet,
                                                DeviceInfoData,
                                                Property ,
                                                NULL,
                                                (PBYTE) *ppBuffer,
                                                requiredLength,
                                                &requiredLength);
    if(bResult == FALSE)
    {
        free(*ppBuffer);
        *ppBuffer = NULL;
        return FALSE;
    }

    return TRUE;
}

#define InsertTailList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Blink = _EX_ListHead->Blink;\
    (Entry)->Flink = _EX_ListHead;\
    (Entry)->Blink = _EX_Blink;\
    _EX_Blink->Flink = (Entry);\
    _EX_ListHead->Blink = (Entry);\
    }

void
EnumerateAllDevicesWithGuid(
    PDEVICE_GUID_LIST DeviceList,
    LPGUID Guid
    )
{
    if (DeviceList->DeviceInfo != INVALID_HANDLE_VALUE)
    {
        // ClearDeviceList(DeviceList);
    }

    DeviceList->DeviceInfo = SetupDiGetClassDevs(NULL, NULL, NULL, DIGCF_PRESENT|DIGCF_ALLCLASSES);
    // DeviceList->DeviceInfo = SetupDiGetClassDevs(Guid,
    //                                  NULL,
    //                                  NULL,
    //                                  (DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));

    std::cout << "Device info is " << DeviceList->DeviceInfo << std::endl;
    if (DeviceList->DeviceInfo != INVALID_HANDLE_VALUE)
    {
        ULONG                    index;
        DWORD error;

        error = 0;
        index = 0;

        while (error != ERROR_NO_MORE_ITEMS)
        {
            BOOL success;
            PDEVICE_INFO_NODE pNode;

            pNode = (PDEVICE_INFO_NODE) malloc(sizeof(DEVICE_INFO_NODE));
            if (pNode == NULL)
            {
                OOPS();
                continue;
            }
            pNode->DeviceInfo = DeviceList->DeviceInfo;
            pNode->DeviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
            pNode->DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

            success = SetupDiEnumDeviceInfo(DeviceList->DeviceInfo,
                                            index,
                                            &pNode->DeviceInfoData);
            LPOLESTR str;
            StringFromIID(pNode->DeviceInfoData.ClassGuid, &str);
            std::wcout << "Device info Date is " << success << " " << str << std::endl;

            index++;

            if (success == FALSE)
            {
                error = GetLastError();

                if (error != ERROR_NO_MORE_ITEMS)
                {
                    OOPS();
                    continue;
                }

                // FreeDeviceInfoNode(&pNode);
            }
            else
            {
                BOOL   bResult;
                ULONG  requiredLength;

                bResult = GetDeviceProperty(DeviceList->DeviceInfo,
                                            &pNode->DeviceInfoData,
                                            SPDRP_DEVICEDESC,
                                            &pNode->DeviceDescName);
                if (bResult == FALSE)
                {
                    // FreeDeviceInfoNode(&pNode);
                    OOPS();
                    continue;
                }

                std::cout << "  Device desc name is " << pNode->DeviceDescName << std::endl;

                bResult = GetDeviceProperty(DeviceList->DeviceInfo,
                                            &pNode->DeviceInfoData,
                                            SPDRP_DRIVER,
                                            &pNode->DeviceDriverName);
                if (bResult == FALSE)
                {
                    // FreeDeviceInfoNode(&pNode);
                    OOPS();
                    continue;
                }

                std::cout << "  Device driver name is " << pNode->DeviceDriverName << std::endl;

                pNode->DeviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

                success = SetupDiEnumDeviceInterfaces(DeviceList->DeviceInfo,
                                                      0,
                                                      Guid,
                                                      index-1,
                                                      &pNode->DeviceInterfaceData);
                if (!success)
                {
                    // FreeDeviceInfoNode(&pNode);
                    OOPS();
                    continue;
                }

                success = SetupDiGetDeviceInterfaceDetail(DeviceList->DeviceInfo,
                                                          &pNode->DeviceInterfaceData,
                                                          NULL,
                                                          0,
                                                          &requiredLength,
                                                          NULL);

                error = GetLastError();

                if (!success && error != ERROR_INSUFFICIENT_BUFFER)
                {
                    // FreeDeviceInfoNode(&pNode);
                    OOPS();
                    continue;
                }

                pNode->DeviceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA) malloc(requiredLength);

                if (pNode->DeviceDetailData == NULL)
                {
                    // FreeDeviceInfoNode(&pNode);
                    OOPS();
                    continue;
                }

                pNode->DeviceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

                success = SetupDiGetDeviceInterfaceDetail(DeviceList->DeviceInfo,
                                                          &pNode->DeviceInterfaceData,
                                                          pNode->DeviceDetailData,
                                                          requiredLength,
                                                          &requiredLength,
                                                          NULL);
                if (!success)
                {
                    // FreeDeviceInfoNode(&pNode);
                    OOPS();
                    continue;
                }

                std::cout << "  DevicePath is " << pNode->DeviceDetailData->DevicePath << std::endl;

                // InsertTailList(&DeviceList->ListHead, &pNode->ListEntry);
            }
        }
    }
}

static void
EnumerateAllDevices()
{
    DEVICE_GUID_LIST gHubList;
    DEVICE_GUID_LIST gDeviceList;

    EnumerateAllDevicesWithGuid(&gDeviceList,
                                (LPGUID)&GUID_DEVINTERFACE_USB_DEVICE);

    EnumerateAllDevicesWithGuid(&gHubList,
                                (LPGUID)&GUID_DEVINTERFACE_USB_HUB);

    // PLIST_ENTRY       pEntry = NULL;
    // PDEVICE_INFO_NODE pNode  = NULL;
    // PDEVICE_GUID_LIST pList = &gHubList;

    // std::wcout << L"Listing HUBS" << std::endl;
    // pEntry = pList->ListHead.Flink;
    // while (pEntry != &pList->ListHead)
    // {
    //     pNode = CONTAINING_RECORD(pEntry,
    //                               DEVICE_INFO_NODE,
    //                               ListEntry);
    //     std::cout << "Device " << (pNode ? pNode->DeviceDriverName : "<none>") << std::endl;
    //     pEntry = pEntry->Flink;
    // }

    // pList = &gDeviceList;
    // pEntry = pList->ListHead.Flink;
    // std::wcout << L"Listing DEVS" << std::endl;
    // while (pEntry != &pList->ListHead)
    // {
    //     pNode = CONTAINING_RECORD(pEntry,
    //                               DEVICE_INFO_NODE,
    //                               ListEntry);
    //     std::cout << "Device " << (pNode ? pNode->DeviceDriverName : "<none>") << std::endl;
    //     pEntry = pEntry->Flink;
    // }
}

HRESULT
RetrieveDevicePath(
    _Out_ LPTSTR DevicePath,
    _In_                  ULONG  BufLen,
    _Out_opt_             PBOOL  FailureDeviceNotFound
    )
{
    CONFIGRET cr = CR_SUCCESS;
    HRESULT   hr = S_OK;
    PTSTR     DeviceInterfaceList = NULL;
    ULONG     DeviceInterfaceListLength = 0;

    if (NULL != FailureDeviceNotFound) {
        *FailureDeviceNotFound = FALSE;
    }

    //
    // Enumerate all devices exposing the interface. Do this in a loop
    // in case a new interface is discovered while this code is executing,
    // causing CM_Get_Device_Interface_List to return CR_BUFFER_SMALL.
    //
    do {
        cr = CM_Get_Device_Interface_List_Size(&DeviceInterfaceListLength,
                                               (LPGUID)&GUID_DEVINTERFACE_USB_DEVICE,
                                               NULL,
                                               CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

        if (cr != CR_SUCCESS) {
            hr = E_ABORT;
            break;
        }

        DeviceInterfaceList = (PTSTR)HeapAlloc(GetProcessHeap(),
                                               HEAP_ZERO_MEMORY,
                                               DeviceInterfaceListLength * sizeof(TCHAR));

        if (DeviceInterfaceList == NULL) {
            hr = E_OUTOFMEMORY;
            break;
        }

        cr = CM_Get_Device_Interface_List((LPGUID)&GUID_DEVINTERFACE_USB_DEVICE,
                                          NULL,
                                          DeviceInterfaceList,
                                          DeviceInterfaceListLength,
                                          CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

        if (cr != CR_SUCCESS) {
            HeapFree(GetProcessHeap(), 0, DeviceInterfaceList);

            if (cr != CR_BUFFER_SMALL) {
                hr = E_ABORT;
            }
        }
    } while (cr == CR_BUFFER_SMALL);

    if (FAILED(hr)) {
        return hr;
    }

    //
    // If the interface list is empty, no devices were found.
    //
    if (*DeviceInterfaceList == TEXT('\0')) {
        if (NULL != FailureDeviceNotFound) {
            *FailureDeviceNotFound = TRUE;
        }

        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        HeapFree(GetProcessHeap(), 0, DeviceInterfaceList);
        return hr;
    }

    //
    // Give path of the first found device interface instance to the caller. CM_Get_Device_Interface_List ensured
    // the instance is NULL-terminated.
    //
    // hr = StringCbCopy(DevicePath,
    //                   BufLen,
    //                   DeviceInterfaceList);

    // HeapFree(GetProcessHeap(), 0, DeviceInterfaceList);

    return hr;
}
*/

MyQueue *myQueue = 0;

class MyUsbTargetPipe : public IWDFUsbTargetPipe2 {
    public:
        MyUsbTargetPipe(
            WINUSB_INTERFACE_HANDLE winUsbHandle,
            USBD_PIPE_TYPE PipeType,
            UCHAR PipeId,
            USHORT MaximumPacketSize,
            UCHAR Interval)
            : m_WinUsbHandle(winUsbHandle),
                m_PipeId(PipeId),
                m_PipeType(PipeType),
                m_MaxPacketSize(MaximumPacketSize),
                m_Interval(Interval) {
            HLOG_DEBUG("MyUsbTargetPipe::MyUsbTargetPipe %d 0x%x\r\n",
                m_PipeType, m_PipeId);
        }

        virtual ULONG STDMETHODCALLTYPE AddRef() override {
            HLOG_DEBUG("MyUsbTargetPipe::AddRef\r\n");
            return 0;
        }

        virtual ULONG STDMETHODCALLTYPE Release() override {
            HLOG_DEBUG("MyUsbTargetPipe::Release\r\n");
            return 0;
        }
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyUsbTargetPipe::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject() override {
            HLOG_DEBUG("MyUsbTargetPipe::DeleteWdfObject\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock() override {
            HLOG_DEBUG("MyUsbTargetPipe::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock() override {
            HLOG_DEBUG("MyUsbTargetPipe::ReleaseLock\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) override {
            HLOG_DEBUG("MyUsbTargetPipe::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) override {
            HLOG_DEBUG("MyUsbTargetPipe::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE GetTargetFile(
            /* [annotation][out] */
            _Out_  IWDFFile **ppWdfFile) override {
            HLOG_DEBUG("MyUsbTargetPipe::GetTargetFile\r\n");
            *ppWdfFile = NULL;
        }

        virtual void STDMETHODCALLTYPE CancelSentRequestsForFile(
            /* [annotation][in] */
            _In_  IWDFFile *pFile) override {
            HLOG_DEBUG("MyUsbTargetPipe::CancelSentRequestsForFile\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE FormatRequestForRead(
            /* [annotation][in] */
            _In_  IWDFIoRequest *pRequest,
            /* [annotation][unique][in] */
            _In_opt_  IWDFFile *pFile,
            /* [annotation][unique][in] */
            _In_opt_  IWDFMemory *pOutputMemory,
            /* [annotation][unique][in] */
            _In_opt_  PWDFMEMORY_OFFSET pOutputMemoryOffset,
            /* [annotation][unique][in] */
            _In_opt_  PLONGLONG DeviceOffset) override {
            HLOG_DEBUG("MyUsbTargetPipe::FormatRequestForRead\r\n");
            auto req = (MyRequest *)pRequest;
            req->m_usbOp = MyRequest::UsbPipeRead;
            req->m_pipeHandle = m_WinUsbHandle;
            req->m_pipeId = m_PipeId;
            req->outMem = (MyMem *)pOutputMemory;
            return S_OK;
        }

        virtual HRESULT STDMETHODCALLTYPE FormatRequestForWrite(
            /* [annotation][in] */
            _In_  IWDFIoRequest *pRequest,
            /* [annotation][unique][in] */
            _In_opt_  IWDFFile *pFile,
            /* [annotation][unique][in] */
            _In_opt_  IWDFMemory *pInputMemory,
            /* [annotation][unique][in] */
            _In_opt_  PWDFMEMORY_OFFSET pInputMemoryOffset,
            /* [annotation][unique][in] */
            _In_opt_  PLONGLONG DeviceOffset) override {
            HLOG_DEBUG("MyUsbTargetPipe::FormatRequestForWrite\r\n");
            auto req = (MyRequest *)pRequest;
            req->m_usbOp = MyRequest::UsbPipeWrite;
            req->m_pipeHandle = m_WinUsbHandle;
            req->m_pipeId = m_PipeId;
            req->inMem = (MyMem *)pInputMemory;
            return S_OK;
        }

        virtual HRESULT STDMETHODCALLTYPE FormatRequestForIoctl(
            /* [annotation][in] */
            _In_  IWDFIoRequest *pRequest,
            /* [annotation][in] */
            _In_  ULONG IoctlCode,
            /* [annotation][unique][in] */
            _In_opt_  IWDFFile *pFile,
            /* [annotation][unique][in] */
            _In_opt_  IWDFMemory *pInputMemory,
            /* [annotation][unique][in] */
            _In_opt_  PWDFMEMORY_OFFSET pInputMemoryOffset,
            /* [annotation][unique][in] */
            _In_opt_  IWDFMemory *pOutputMemory,
            /* [annotation][unique][in] */
            _In_opt_  PWDFMEMORY_OFFSET pOutputMemoryOffset) override {
            HLOG_DEBUG("MyUsbTargetPipe::FormatRequestForIoctl\r\n");
            return S_OK;
        }

        virtual HRESULT STDMETHODCALLTYPE Abort() override {
            HLOG_DEBUG("MyUsbTargetPipe::Abort\r\n");

            if (!WinUsb_AbortPipe(m_WinUsbHandle, m_PipeId)) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            return S_OK;
        }

        virtual HRESULT STDMETHODCALLTYPE Reset() override {
            HLOG_DEBUG("MyUsbTargetPipe::Reset\r\n");

            if (!WinUsb_ResetPipe(m_WinUsbHandle, m_PipeId)) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            return S_OK;
        }

        virtual HRESULT STDMETHODCALLTYPE Flush() override {
            HLOG_DEBUG("MyUsbTargetPipe::Flush\r\n");

            if (!WinUsb_FlushPipe(m_WinUsbHandle, m_PipeId)) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            return S_OK;
        }

        virtual void STDMETHODCALLTYPE GetInformation(_Out_ PWINUSB_PIPE_INFORMATION pInfo) override {
            HLOG_DEBUG("MyUsbTargetPipe::GetInformation %d 0x%x\r\n", m_PipeType, m_PipeId);
            pInfo->PipeType = m_PipeType;
            pInfo->PipeId = m_PipeId;
            pInfo->MaximumPacketSize = m_MaxPacketSize;
            pInfo->Interval = m_Interval;
        }

        virtual BOOL STDMETHODCALLTYPE IsInEndPoint() override {
            HLOG_DEBUG("MyUsbTargetPipe::IsInEndPoint\r\n");

            return (m_PipeId & 0x80) != 0;
        }

        virtual BOOL STDMETHODCALLTYPE IsOutEndPoint() override {
            HLOG_DEBUG("MyUsbTargetPipe::IsOutEndPoint\r\n");

            return (m_PipeId & 0x80) == 0;
        }

        virtual USBD_PIPE_TYPE STDMETHODCALLTYPE GetType() override {
            HLOG_DEBUG("MyUsbTargetPipe::GetType\r\n");

            return m_PipeType;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrievePipePolicy(
            _In_ ULONG PolicyType,
            _Inout_ ULONG* ValueLength,
            _Out_ PVOID Value) override {
            HLOG_DEBUG("MyUsbTargetPipe::RetrievePipePolicy\r\n");

            if (!WinUsb_GetPipePolicy(
                    m_WinUsbHandle,
                    m_PipeId,
                    PolicyType,
                    ValueLength,
                    Value)) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            return S_OK;
        }

        virtual HRESULT STDMETHODCALLTYPE SetPipePolicy(
            _In_ ULONG PolicyType,
            _In_ ULONG ValueLength,
            _In_ PVOID Value) override {
            HLOG_DEBUG("MyUsbTargetPipe::SetPipePolicy\r\n");

            if (!WinUsb_SetPipePolicy(
                m_WinUsbHandle,
                m_PipeId,
                PolicyType,
                ValueLength,
                Value
            )) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            return S_OK;
        }

        virtual HRESULT STDMETHODCALLTYPE ConfigureContinuousReader(
            /* [annotation][in] */
            _In_  SIZE_T TransferLength,
            /* [annotation][in] */
            _In_  SIZE_T HeaderLength,
            /* [annotation][in] */
            _In_  SIZE_T TrailerLength,
            /* [annotation][in] */
            _In_  UCHAR NumPendingReads,
            /* [annotation][unique][in] */
            _In_opt_  IUnknown *pMemoryCleanupCallbackInterface,
            /* [annotation][in] */
            _In_  IUsbTargetPipeContinuousReaderCallbackReadComplete *pOnCompletion,
            /* [annotation][unique][in] */
            _In_opt_  PVOID pCompletionContext,
            /* [annotation][unique][in] */
            _In_opt_  IUsbTargetPipeContinuousReaderCallbackReadersFailed *pOnFailure) override {
            HLOG_DEBUG("MyUsbTargetPipe::ConfigureContinuousReader\r\n");
            return S_OK;
        }

    private:
        WINUSB_INTERFACE_HANDLE m_WinUsbHandle;
        UCHAR m_PipeId;
        USBD_PIPE_TYPE m_PipeType;
        ULONG m_MaxPacketSize;
        ULONG m_Interval;
};

class MyUsbInterface : public IWDFUsbInterface {
    public:
        MyUsbInterface(UCHAR idx, WINUSB_INTERFACE_HANDLE handle)
            : m_idx(idx), m_handle(handle) {}

        virtual ULONG STDMETHODCALLTYPE AddRef() override {
            HLOG_DEBUG("MyUsbInterface::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() override {
            HLOG_DEBUG("MyUsbInterface::Release\r\n");
            return 0;
        }
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyUsbInterface::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject() override {
            HLOG_DEBUG("MyUsbInterface::DeleteWdfObject\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock() override {
            HLOG_DEBUG("MyUsbInterface::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock() override {
            HLOG_DEBUG("MyUsbInterface::ReleaseLock\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) override {
            HLOG_DEBUG("MyUsbInterface::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) override {
            HLOG_DEBUG("MyUsbInterface::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE GetInterfaceDescriptor(
            /* [annotation][out] */
            _Out_  PUSB_INTERFACE_DESCRIPTOR UsbAltInterfaceDescriptor) override {
            HLOG_DEBUG("MyUsbInterface::GetInterfaceDescriptor\r\n");
        }

        virtual UCHAR STDMETHODCALLTYPE GetInterfaceNumber() override {
            HLOG_DEBUG("MyUsbInterface::GetInterfaceNumber\r\n");
            return m_idx;
        }

        virtual UCHAR STDMETHODCALLTYPE GetNumEndPoints() override {
            HLOG_DEBUG("MyUsbInterface::GetNumEndPoints\r\n");
            return 3;
        }

        virtual UCHAR STDMETHODCALLTYPE GetConfiguredSettingIndex() override {
            HLOG_DEBUG("MyUsbInterface::GetConfiguredSettingIndex\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE SelectSetting(
            /* [annotation][in] */
            _In_  UCHAR SettingNumber) override {
            HLOG_DEBUG("MyUsbInterface::SelectSetting\r\n");
            return 0;
        }

        virtual WINUSB_INTERFACE_HANDLE STDMETHODCALLTYPE GetWinUsbHandle() override {
            HLOG_DEBUG("MyUsbInterface::GetWinUsbHandle\r\n");
            return m_handle;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveUsbPipeObject(
            /* [annotation][in] */
            _In_  UCHAR PipeIndex,
            /* [annotation][out] */
            _Out_  IWDFUsbTargetPipe **ppPipe) override {
            HLOG_DEBUG("MyUsbInterface::IWDFUsbTargetPipe 0x%x\r\n", PipeIndex);

            WINUSB_PIPE_INFORMATION pipeInfo;
            if (!WinUsb_QueryPipe(GetWinUsbHandle(), m_idx, PipeIndex, &pipeInfo)) {
                HLOG_INFO("Impossible to get pipe informatio!\r\n");
                return E_NOTIMPL;
            }

            *ppPipe = new MyUsbTargetPipe(m_handle, pipeInfo.PipeType,
                pipeInfo.PipeId, pipeInfo.MaximumPacketSize, pipeInfo.Interval);
            return 0;
        }

    private:
        UCHAR m_idx;
        WINUSB_INTERFACE_HANDLE m_handle;
    };

class MyUsbTargetDevice : public IWDFUsbTargetDevice {
public:
        MyUsbTargetDevice(WINUSB_INTERFACE_HANDLE handle) : m_handle(handle) {
            HLOG_DEBUG("MyUsbTargetDevice::MyUsbTargetDevice: %p\r\n", this);

            // Get device descriptor (non-fatal -- wine winusb stubs this)
            USB_DEVICE_DESCRIPTOR devDesc;
            ULONG len;
            if (!WinUsb_GetDescriptor(m_handle, USB_DEVICE_DESCRIPTOR_TYPE,
                                      0, 0, (PUCHAR)&devDesc, sizeof(devDesc), &len)) {
                HLOG_USER("WinUsb_GetDescriptor (device) failed: %lu (wine stub, continuing)\r\n", (unsigned long)GetLastError());
            } else {
                HLOG_USER("Found USB %u configurations\n", devDesc.bNumConfigurations);

                for (UCHAR i = 0; i < devDesc.bNumConfigurations; i++) {
                    USB_CONFIGURATION_DESCRIPTOR configHeader;

                    if (!WinUsb_GetDescriptor(m_handle, USB_CONFIGURATION_DESCRIPTOR_TYPE,
                                              i, 0, (PUCHAR)&configHeader,
                                              sizeof(configHeader), &len)) {
                        continue;
                    }

                    m_configDesc = &configHeader;
                    HLOG_USER("Found USB Configuration descriptor %p (real size %lu)\n", m_configDesc, len);
                    break;
                }

                if (!m_configDesc)
                    HLOG_USER("Active configuration not found\r\n");
            }

            IFLOG(2) {
                std::wcout
                    << L"  =======================" << std::endl
                    << L"  bLength: " << m_configDesc->bLength << std::endl
                    << L"  bDescriptorType: " << m_configDesc->bDescriptorType << std::endl
                    << L"  wTotalLength: " << m_configDesc->wTotalLength << std::endl
                    << L"  bNumInterfaces: " << m_configDesc->bNumInterfaces << std::endl
                    << L"  bConfigurationValue: " << m_configDesc->bConfigurationValue << std::endl
                    << L"  iConfiguration: " << m_configDesc->iConfiguration << std::endl
                    << L"  bmAttributes: " << m_configDesc->bmAttributes << std::endl
                    << L"  MaxPower: " << m_configDesc->MaxPower << std::endl
                    << L"  =======================" << std::endl;
            }

            // for (UCHAR i = 0; i < pConfigDesc->bNumInterfaces; i++) {
            //      USB_INTERFACE_DESCRIPTOR iface_desc;

            //     if (!WinUsb_GetDescriptor(m_handle, USB_INTERFACE_DESCRIPTOR_TYPE,
            //                               i, 0, (PUCHAR)&iface_desc,
            //                               sizeof(iface_desc), &len)) {
            //         continue;
            //     }

            //     HLOG_USER("Found USB Interface descriptor %u\n", i);
            //     break;
            // }

            // TODO: Let's not bother for now checking the oher interfaces, we
            // only care on the first one for now.

            // // Parse interfaces
            // PUCHAR p = (PUCHAR)(pConfigDesc) + pConfigDesc->bLength;
            // ULONG totalLength = pConfigDesc->wTotalLength - pConfigDesc->bLength;

            // while (totalLength > 0) {
            //     HLOG_DEBUG("Handling p at %p | totalLength %lu\n", p, totalLength);
            //     UCHAR descLen = p[0];
            //     UCHAR descType = p[1];

            //     if (descType == USB_INTERFACE_DESCRIPTOR_TYPE && descLen >= sizeof(USB_INTERFACE_DESCRIPTOR)) {
            //         PUSB_INTERFACE_DESCRIPTOR iface = (PUSB_INTERFACE_DESCRIPTOR)p;
            //         HLOG_DEBUG("Interface #%d, Alternate %d: Class=0x%02X, SubClass=0x%02X, Protocol=0x%02X, Endpoints=%d\n",
            //             iface->bInterfaceNumber, iface->bAlternateSetting,
            //             iface->bInterfaceClass, iface->bInterfaceSubClass, iface->bInterfaceProtocol,
            //             iface->bNumEndpoints);
            //     }

            //     descLen = std::max(sizeof(USB_INTERFACE_DESCRIPTOR), size_t(descLen));
            //     if (descLen > totalLength)
            //         break;

            //     totalLength -= descLen;
            //     p += descLen;
            // }
        }

        virtual ULONG STDMETHODCALLTYPE AddRef() override {
            HLOG_DEBUG("MyUsbTargetDevice::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() override {
            HLOG_DEBUG("MyUsbTargetDevice::Release\r\n");
            return 0;
        }
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyUsbTargetDevice::QueryInterface " << str << std::endl;
    if (IsEqualIID(riid, IID_IWDFUsbTargetDevice) ||
        IsEqualIID(riid, IID_UsbTargetAliasMaybe)) {
        *ppvObject = this;
        HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
        return S_OK;
    }

    std::wcout << L" NOT FOUND!" << std::endl;
    return E_NOINTERFACE;
        }

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject() override {
            HLOG_DEBUG("MyUsbTargetDevice::DeleteWdfObject\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock() override {
            HLOG_DEBUG("MyUsbTargetDevice::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock() override {
            HLOG_DEBUG("MyUsbTargetDevice::ReleaseLock\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) override {
            HLOG_DEBUG("MyUsbTargetDevice::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) override {
            HLOG_DEBUG("MyUsbTargetDevice::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE GetTargetFile(
            /* [annotation][out] */
            _Out_  IWDFFile **ppWdfFile) override {
            HLOG_DEBUG("MyUsbTargetDevice::GetTargetFile\r\n");
        };

        virtual void STDMETHODCALLTYPE CancelSentRequestsForFile(
            /* [annotation][in] */
            _In_  IWDFFile *pFile) override {
            HLOG_DEBUG("MyUsbTargetDevice::CancelSentRequestsForFile\r\n");
        };

        virtual HRESULT STDMETHODCALLTYPE FormatRequestForRead(
            /* [annotation][in] */
            _In_  IWDFIoRequest *pRequest,
            /* [annotation][unique][in] */
            _In_opt_  IWDFFile *pFile,
            /* [annotation][unique][in] */
            _In_opt_  IWDFMemory *pOutputMemory,
            /* [annotation][unique][in] */
            _In_opt_  PWDFMEMORY_OFFSET pOutputMemoryOffset,
            /* [annotation][unique][in] */
            _In_opt_  PLONGLONG DeviceOffset) override {
            HLOG_DEBUG("MyUsbTargetDevice::FormatRequestForRead\r\n");
            return 0;
        };

        virtual HRESULT STDMETHODCALLTYPE FormatRequestForWrite(
            /* [annotation][in] */
            _In_  IWDFIoRequest *pRequest,
            /* [annotation][unique][in] */
            _In_opt_  IWDFFile *pFile,
            /* [annotation][unique][in] */
            _In_opt_  IWDFMemory *pInputMemory,
            /* [annotation][unique][in] */
            _In_opt_  PWDFMEMORY_OFFSET pInputMemoryOffset,
            /* [annotation][unique][in] */
            _In_opt_  PLONGLONG DeviceOffset) override {
            HLOG_DEBUG("MyUsbTargetDevice::FormatRequestForWrite\r\n");
            return 0;
        };

        virtual HRESULT STDMETHODCALLTYPE FormatRequestForIoctl(
            /* [annotation][in] */
            _In_  IWDFIoRequest *pRequest,
            /* [annotation][in] */
            _In_  ULONG IoctlCode,
            /* [annotation][unique][in] */
            _In_opt_  IWDFFile *pFile,
            /* [annotation][unique][in] */
            _In_opt_  IWDFMemory *pInputMemory,
            /* [annotation][unique][in] */
            _In_opt_  PWDFMEMORY_OFFSET pInputMemoryOffset,
            /* [annotation][unique][in] */
            _In_opt_  IWDFMemory *pOutputMemory,
            /* [annotation][unique][in] */
            _In_opt_  PWDFMEMORY_OFFSET pOutputMemoryOffset) override {
            HLOG_DEBUG("MyUsbTargetDevice::FormatRequestForIoctl\r\n");
            return 0;
        };

        virtual WINUSB_INTERFACE_HANDLE STDMETHODCALLTYPE GetWinUsbHandle() override {
            HLOG_DEBUG("MyUsbTargetDevice::GetWinUsbHandle\r\n");
            return m_handle;
        }

        virtual UCHAR STDMETHODCALLTYPE GetNumInterfaces() override {
            HLOG_DEBUG("MyUsbTargetDevice::GetNumInterfaces\r\n");
            return m_configDesc ? m_configDesc->bNumInterfaces : 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveUsbInterface(
            /* [annotation][in] */
            _In_  UCHAR InterfaceIndex,
            /* [annotation][out] */
            _Out_  IWDFUsbInterface **ppUsbInterface) override {
                HLOG_DEBUG("MyUsbTargetDevice::RetrieveUsbInterface %x\r\n", InterfaceIndex);
                *ppUsbInterface = new MyUsbInterface(InterfaceIndex, m_handle);
                return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE FormatRequestForControlTransfer(
            /* [annotation][in] */
            _In_  IWDFIoRequest *pRequest,
            /* [annotation][in] */
            _In_  PWINUSB_SETUP_PACKET SetupPacket,
            /* [annotation][unique][in] */
            _In_opt_  IWDFMemory *pMemory,
            /* [annotation][unique][in] */
            _In_opt_  PWDFMEMORY_OFFSET TransferOffset) override {
                HLOG_DEBUG("MyUsbTargetDevice::FormatRequestForControlTransfer: %p %p\r\n",
                    pRequest, pMemory);

                IFLOG(2) {
                    char buf[10] = {0};
                    snprintf(buf, sizeof(buf), "0x%x", SetupPacket->RequestType);
                    std::wcout
                        << L"  =======================" << std::endl
                        << L"  RequestType: " << buf << std::endl
                        << L"  RequestType.Direction: " << (SetupPacket->Length ? (SetupPacket->RequestType & 0b10000000) >> 7 : -1) << std::endl
                        << L"  RequestType.Type: " << ((SetupPacket->RequestType & 0b01100000) >> 5) << std::endl
                        << L"  RequestType.Recipient: " << (SetupPacket->RequestType & 0b00011111) << std::endl
                        << L"  Request: " << SetupPacket->Request << std::endl
                        << L"  Value: " << SetupPacket->Value << std::endl
                        << L"  Index: " << SetupPacket->Index << std::endl
                        << L"  Length: " << SetupPacket->Length << std::endl
                        << L"  =======================" << std::endl;
                }

                if (pRequest == nullptr)
                    return E_ABORT;

                auto *myReq = (MyRequest *) pRequest;
                myReq->SetControlData(SetupPacket, pMemory, TransferOffset);

                return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceInformation(
            /* [annotation][in] */
            _In_  ULONG InformationType,
            /* [annotation][out][in] */
            _Inout_  ULONG *BufferLength,
            /* [annotation][out] */
            _Out_  PVOID Buffer) override {
                HLOG_DEBUG("MyUsbTargetDevice::RetrieveDeviceInformation %lx\r\n",
                    InformationType);
                // If InformationType is DEVICE_SPEED (0x01), on successful return,
                //  Buffer indicates the operating speed of the device.
                // 0x03 indicates high-speed or higher; 0x01 indicates full-speed or lower.
                assert(BufferLength && *BufferLength == 1);
                if (InformationType == DEVICE_SPEED)
                    memset(Buffer, 1, 1);
                return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveDescriptor(
            /* [annotation][in] */
            _In_  UCHAR DescriptorType,
            /* [annotation][in] */
            _In_  UCHAR Index,
            /* [annotation][in] */
            _In_  USHORT LanguageID,
            /* [annotation][out][in] */
            _Inout_  ULONG *BufferLength,
            /* [annotation][out] */
            _Out_  PVOID Buffer) override {
                HLOG_DEBUG("MyUsbTargetDevice::RetrieveDescriptor\r\n");
                return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrievePowerPolicy(
            /* [annotation][in] */
            _In_  ULONG PolicyType,
            /* [annotation][out][in] */
            _Inout_  ULONG *ValueLength,
            /* [annotation][out] */
            _Out_  PVOID Value) override {
                HLOG_DEBUG("MyUsbTargetDevice::RetrievePowerPolicy\r\n");
                return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE SetPowerPolicy(
            /* [annotation][in] */
            _In_  ULONG PolicyType,
            /* [annotation][in] */
            _In_  ULONG ValueLength,
            /* [annotation][in] */
            _In_  PVOID Value) override {
                HLOG_DEBUG("MyUsbTargetDevice::SetPowerPolicy %lu\r\n", (unsigned long)PolicyType);
                return 0;
        }

    private:
        WINUSB_INTERFACE_HANDLE m_handle;
        PUSB_CONFIGURATION_DESCRIPTOR m_configDesc = NULL;
};

class MyUsbTargetFactory : public IWDFUsbTargetFactory {
public:
        virtual ULONG STDMETHODCALLTYPE AddRef() override {
            HLOG_DEBUG("MyUsbTargetFactory::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() override {
            HLOG_DEBUG("MyUsbTargetFactory::Release\r\n");
            return 0;
        }
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyUsbTargetFactory::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE CreateUsbTargetDevice(
            _Out_  IWDFUsbTargetDevice **ppDevice) override {
            HLOG_DEBUG("MyUsbTargetFactory::CreateUsbTargetDevice\r\n");
#if 0
            // To be fair... Enumerate the devices and only get the ones we care about.
            static const char dPath[] =  "\\\\?\\usb#vid_047d&pid_00f2#de88bf659e72#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
#else
            static const char dPath[] =  "c:\\usb.txt";
#endif
            HANDLE deviceHandle = CreateFile(dPath, GENERIC_READ |
                                             GENERIC_WRITE, FILE_SHARE_READ |
                                             FILE_SHARE_WRITE,
                                             NULL, OPEN_EXISTING,
                                             FILE_ATTRIBUTE_NORMAL |
                                             FILE_FLAG_OVERLAPPED, NULL);

            if (deviceHandle == INVALID_HANDLE_VALUE) {
                HLOG_USER("CreateFile failed: %lu (%s)\n",
                    (unsigned long)GetLastError(), hresult_to_sting(GetLastError()));
                return E_FAIL;
            }

            WINUSB_INTERFACE_HANDLE winusbHandle = NULL;
            if (!WinUsb_Initialize(deviceHandle, &winusbHandle)) {
                HLOG_USER("WinUsb_Initialize failed: %lu (%s)\n", (unsigned long)GetLastError(),
                    hresult_to_sting(GetLastError()));
                CloseHandle(deviceHandle);
                return E_FAIL;
            }

            *ppDevice = new MyUsbTargetDevice(winusbHandle);
            return 0;
        }
};

struct MyDevice;

MyDevice *myDevice = 0;


struct MyDevice : public IWDFDevice3 {
    public:
        MyDevice(IWDFDriver *driver, IUnknown *pCallbackInterface) : m_driver(driver) {
            pCallbackInterface->AddRef();
            pCallbackInterface->QueryInterface(IID_IPnpCallbackHardware, (LPVOID*)&pnphwcb);
            pCallbackInterface->QueryInterface(IID_IPnpCallbackHardware2, (LPVOID*)&pnphwcb2);
            pCallbackInterface->QueryInterface(IID_IPnpCallback, (LPVOID*)&pnpcb);
            HLOG_USER("NewDevice: pnphwcb=%p, pnphwcb2=%p, pnpcb=%p\r\n", pnphwcb, pnphwcb2, pnpcb);
        }

        IPnpCallbackHardware *pnphwcb;
        IPnpCallbackHardware2 *pnphwcb2;
        IPnpCallback *pnpcb;
        IWDFDriver *m_driver;
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyDevice::QueryInterface " << str << std::endl;

            if(IsEqualIID(riid, IID_IWDFPropertyStoreFactory)) {
                HLOG_DEBUG("is IID_IWDFPropertyStoreFactory\r\n");
                *ppvObject = new MyPropertyStoreFactory();
            } else if (IsEqualIID(riid, IID_IWDFDevice3)) {
                HLOG_DEBUG("is IID_IWDFDevice3\r\n");
                *ppvObject = (IWDFDevice3*)this;
            } else if (IsEqualIID(riid, IID_IWDFUsbTargetFactory)) {
                HLOG_DEBUG("is IID_IWDFUsbTargetFactory\r\n");
                *ppvObject = new MyUsbTargetFactory();
            }
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("MyDevice::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("MyDevice::DeleteWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) {
            HLOG_DEBUG("MyDevice::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) {
            HLOG_DEBUG("MyDevice::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            HLOG_DEBUG("MyDevice::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            HLOG_DEBUG("MyDevice::ReleaseLock\r\n");
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE RetrieveDevicePropertyStore(
            /* [annotation][unique][in] */
            _In_opt_  PCWSTR pcwszServiceName,
            /* [annotation][in] */
            _In_  WDF_PROPERTY_STORE_RETRIEVE_FLAGS Flags,
            /* [annotation][out] */
            _Out_  IWDFNamedPropertyStore **ppPropStore,
            /* [annotation][unique][out] */
            _Out_opt_  WDF_PROPERTY_STORE_DISPOSITION *pDisposition){
            HLOG_DEBUG("MyDevice::RetrieveDevicePropertyStore\r\n");
            *ppPropStore = new MyNamedPropertyStore();
            return 0;
        }


        virtual void STDMETHODCALLTYPE GetDriver(
            /* [annotation][out] */
            _Out_  IWDFDriver **ppWdfDriver){
            HLOG_DEBUG("MyDevice::GetDriver\r\n");
            *ppWdfDriver = m_driver;
        }


        virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceInstanceId(
            /* [annotation][unique][out][string] */
            _Out_opt_  PWSTR Buffer,
            /* [annotation][out][in] */
            _Inout_  DWORD *pdwSizeInChars){
            HLOG_DEBUG("MyDevice::RetrieveDeviceInstanceId\r\n");
            return 0;
        }


        virtual void STDMETHODCALLTYPE GetDefaultIoTarget(
            /* [annotation][out] */
            _Out_  IWDFIoTarget **ppWdfIoTarget){
            HLOG_DEBUG("MyDevice::GetDefaultIoTarget\r\n");
        }


        virtual HRESULT STDMETHODCALLTYPE CreateWdfFile(
            /* [annotation][string][unique][in] */
            _In_opt_  LPCWSTR pcwszFileName,
            /* [annotation][out] */
            _Out_  IWDFDriverCreatedFile **ppFile){
            HLOG_DEBUG("MyDevice::CreateWdfFile\r\n");
            return 0;
        }


        virtual void STDMETHODCALLTYPE GetDefaultIoQueue(
            /* [annotation][out] */
            _Out_  IWDFIoQueue **ppWdfIoQueue){
            HLOG_DEBUG("MyDevice::GetDefaultIoQueue\r\n");
        }


        virtual HRESULT STDMETHODCALLTYPE CreateIoQueue(
            /* [annotation][in] */
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][in] */
            _In_  BOOL bDefaultQueue,
            /* [annotation][in] */
            _In_  WDF_IO_QUEUE_DISPATCH_TYPE DispatchType,
            /* [annotation][in] */
            _In_  BOOL bPowerManaged,
            /* [annotation][in] */
            _In_  BOOL bAllowZeroLengthRequests,
            /* [annotation][out] */
            _Out_  IWDFIoQueue **ppIoQueue){
            HLOG_DEBUG("MyDevice::CreateIoQueue (%p, %d, %d, %d, %d)\r\n",
                pCallbackInterface, (int)bDefaultQueue, (int)DispatchType, (int)bPowerManaged,
                (int)bAllowZeroLengthRequests);
            *ppIoQueue = myQueue = new MyQueue(pCallbackInterface);
            HLOG_USER("new queue=%p\r\n", *ppIoQueue);
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE CreateDeviceInterface(
            /* [annotation][in] */
            _In_  LPCGUID pDeviceInterfaceGuid,
            /* [annotation][unique][string][in] */
            _In_opt_  PCWSTR pReferenceString){
            // this ois of type GUID_DEVINTERFACE_BIOMETRIC_READER
            LPOLESTR str;
            StringFromIID(*pDeviceInterfaceGuid, &str);
            HLOG_DEBUG("MyDevice::CreateDeviceInterface %ls\n", str);
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE AssignDeviceInterfaceState(
            /* [annotation][in] */
            _In_  LPCGUID pDeviceInterfaceGuid,
            /* [annotation][unique][string][in] */
            _In_opt_  PCWSTR pReferenceString,
            /* [annotation][in] */
            _In_  BOOL Enable){
            //HLOG_DEBUG("AssignDeviceInterfaceState\r\n");
            LPOLESTR str;
            StringFromIID(*pDeviceInterfaceGuid, &str);
            HLOG_DEBUG("MyDevice::AssignDeviceInterfaceState %ls=%d\n", str, Enable);
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceName(
            /* [annotation][unique][out][string] */
            _Out_writes_to_opt_(*pdwDeviceNameLength, *pdwDeviceNameLength)  PWSTR pDeviceName,
            /* [annotation][out][in] */
            _Inout_  DWORD *pdwDeviceNameLength){
            HLOG_DEBUG("MyDevice::RetrieveDeviceName %p %lu\r\n", pDeviceName, *pdwDeviceNameLength);
            // FIXME: Get it enumerating the USB maybe?
            static const wchar_t name[] =  L"VeriMark DT Fingerprint Key";
            // static const wchar_t name[] =  L"c:\\usb.txt";
            //static const wchar_t name[] =  L"c:\\UMDF.txt";
            if(pDeviceName) {
                wcscpy(pDeviceName, name);
                //Sleep(5000);
            }
            // Always return the length, since the driver uses it to allocate the memory.
            *pdwDeviceNameLength = sizeof(name);
            //Sleep(5000);
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE PostEvent(
            /* [annotation][in] */
            _In_  REFGUID EventGuid,
            /* [annotation][in] */
            _In_  WDF_EVENT_TYPE EventType,
            /* [annotation][size_is][in] */
            _In_reads_bytes_(cbDataSize)  BYTE *pbData,
            /* [annotation][in] */
            _In_  DWORD cbDataSize){
            HLOG_DEBUG("MyDevice::PostEvent\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE ConfigureRequestDispatching(
            /* [annotation][in] */
            _In_  IWDFIoQueue *pQueue,
            /* [annotation][in] */
            _In_  WDF_REQUEST_TYPE RequestType,
            /* [annotation][in] */
            _In_  BOOL Forward){
            HLOG_DEBUG("MyDevice::ConfigureRequestDispatching (%d, %d)\r\n",
                RequestType, Forward);
            return 0;
        }


        virtual void STDMETHODCALLTYPE SetPnpState(
            /* [annotation][in] */
            _In_  WDF_PNP_STATE State,
            /* [annotation][in] */
            _In_  WDF_TRI_STATE Value){
            HLOG_DEBUG("MyDevice::SetPnpState\r\n");
        }


        virtual WDF_TRI_STATE STDMETHODCALLTYPE GetPnpState(
            /* [annotation][in] */
            _In_  WDF_PNP_STATE State){
            HLOG_DEBUG("MyDevice::GetPnpState\r\n");
            return WdfFalse;
        }


        virtual void STDMETHODCALLTYPE CommitPnpState( void){
            HLOG_DEBUG("MyDevice::CommitPnpState\r\n");
        }


        virtual HRESULT STDMETHODCALLTYPE CreateRequest(
            /* [annotation][unique][in] */
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */
            _Out_  IWDFIoRequest **ppRequest){
            HLOG_DEBUG("MyDevice::CreateRequest");
            *ppRequest = new MyRequest(WdfRequestUsb, 0, nullptr, nullptr);
            HLOG_DEBUG(" = %p\r\n", *ppRequest);
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE CreateSymbolicLink(
            /* [annotation][unique][string][in] */
            _In_  PCWSTR pSymbolicLink){
            HLOG_DEBUG("MyDevice::CreateSymbolicLink\r\n");
            return 0;
        }

    // Device2
        virtual HRESULT STDMETHODCALLTYPE AssignS0IdleSettings(
            /* [annotation][in] */
            _In_  WDF_POWER_POLICY_S0_IDLE_CAPABILITIES IdleCaps,
            /* [annotation][in] */
            _In_  DEVICE_POWER_STATE DxState,
            /* [annotation][in] */
            _In_  ULONG IdleTimeout,
            /* [annotation][in] */
            _In_  WDF_POWER_POLICY_S0_IDLE_USER_CONTROL UserControlOfIdleSettings,
            /* [annotation][in] */
            _In_  WDF_TRI_STATE Enabled){
            HLOG_DEBUG("MyDevice::AssignS0IdleSettings\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE StopIdle(
            /* [annotation][in] */
            _In_  BOOL WaitForD0){
            HLOG_DEBUG("MyDevice::StopIdle\r\n");
            return 0;
        }


        virtual void STDMETHODCALLTYPE ResumeIdle( void){
            goIdle = 1;
            HLOG_DEBUG("MyDevice::ResumeIdle\r\n");
        }


        virtual HRESULT STDMETHODCALLTYPE CreateSymbolicLinkWithReferenceString(
            /* [annotation][unique][string][in] */
            _In_  PCWSTR pSymbolicLink,
            /* [annotation][unique][string][in] */
            _In_opt_  PCWSTR pReferenceString){
            HLOG_DEBUG("MyDevice::CreateSymbolicLinkWithReferenceString\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE RegisterRemoteInterfaceNotification(
            /* [annotation][in] */
            _In_  LPCGUID pDeviceInterfaceGuid,
            /* [annotation][in] */
            _In_  BOOL IncludeExistingInterfaces){
            HLOG_DEBUG("MyDevice::RegisterRemoteInterfaceNotification\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE CreateRemoteInterface(
            /* [annotation][in] */
            _In_  IWDFRemoteInterfaceInitialize *pRemoteInterfaceInit,
            /* [annotation][unique][in] */
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][out] */
            _Out_  IWDFRemoteInterface **ppRemoteInterface){
            HLOG_DEBUG("MyDevice::CreateRemoteInterface\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE CreateRemoteTarget(
            /* [annotation][unique][in] */
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */
            _Out_  IWDFRemoteTarget **ppRemoteTarget){
            HLOG_DEBUG("MyDevice::CreateRemoteTarget\r\n");
            return 0;
        }


        virtual void STDMETHODCALLTYPE GetDeviceStackIoTypePreference(
            /* [annotation][out] */
            _Out_  WDF_DEVICE_IO_TYPE *ReadWritePreference,
            /* [annotation][out] */
            _Out_  WDF_DEVICE_IO_TYPE *IoControlPreference){
            HLOG_DEBUG("MyDevice::GetDeviceStackIoTypePreference\r\n");
        }


        virtual HRESULT STDMETHODCALLTYPE AssignSxWakeSettings(
            /* [annotation][in] */
            _In_  DEVICE_POWER_STATE DxState,
            /* [annotation][in] */
            _In_  WDF_POWER_POLICY_SX_WAKE_USER_CONTROL UserControlOfWakeSettings,
            /* [annotation][in] */
            _In_  WDF_TRI_STATE Enabled){
            HLOG_DEBUG("MyDevice::AssignSxWakeSettings\r\n");
            return 0;
        }


        virtual POWER_ACTION STDMETHODCALLTYPE GetSystemPowerAction( void){
            HLOG_DEBUG("MyDevice::GetSystemPowerAction\r\n");
            return PowerActionNone;
        }

    // Device3
    public:
        virtual HRESULT STDMETHODCALLTYPE MapIoSpace(
            /* [annotation][in] */
            _In_  PHYSICAL_ADDRESS PhysicalAddress,
            /* [annotation][in] */
            _In_  SIZE_T NumberOfBytes,
            /* [annotation][in] */
            _In_  MEMORY_CACHING_TYPE CacheType,
            /* [annotation][out] */
            _Out_  void **pPseudoBaseAddress){
            HLOG_DEBUG("MyDevice::MapIoSpace\r\n");
            return 0;
        }


        virtual void STDMETHODCALLTYPE UnmapIoSpace(
            /* [annotation][in] */
            _In_  void *PseudoBaseAddress,
            /* [annotation][in] */
            _In_  SIZE_T NumberOfBytes){
            HLOG_DEBUG("MyDevice::UnmapIoSpace\r\n");
        }


        virtual void *STDMETHODCALLTYPE GetHardwareRegisterMappedAddress(
            /* [annotation][in] */
            _In_  void *PseudoBaseAddress){
            HLOG_DEBUG("MyDevice::GetHardwareRegisterMappedAddress\r\n");
            return 0;
        }


        virtual SIZE_T STDMETHODCALLTYPE ReadFromHardware(
            /* [annotation][in] */
            _In_  WDF_DEVICE_HWACCESS_TARGET_TYPE Type,
            /* [annotation][in] */
            _In_  WDF_DEVICE_HWACCESS_TARGET_SIZE Size,
            /* [annotation][in] */
            _In_  void *Address,
            /* [annotation][out] */
            _Out_writes_all_opt_(Count)  void *Buffer,
            /* [annotation][in] */
            _In_opt_  ULONG Count){
            HLOG_DEBUG("MyDevice::ReadFromHardware\r\n");
            return 0;
        }


        virtual void STDMETHODCALLTYPE WriteToHardware(
            /* [annotation][in] */
            _In_  WDF_DEVICE_HWACCESS_TARGET_TYPE Type,
            /* [annotation][in] */
            _In_  WDF_DEVICE_HWACCESS_TARGET_SIZE Size,
            /* [annotation][in] */
            _In_  void *Address,
            /* [annotation][in] */
            _In_  SIZE_T Value,
            /* [annotation][in] */
            _In_reads_opt_(Count)  void *Buffer,
            /* [annotation][in] */
            _In_opt_  ULONG Count){
            HLOG_DEBUG("MyDevice::WriteToHardware\r\n");
        }


        virtual HRESULT STDMETHODCALLTYPE CreateInterrupt(
            /* [annotation][in] */
            _In_  PWUDF_INTERRUPT_CONFIG Configuration,
            /* [annotation][out] */
            _Out_  IWDFInterrupt **ppInterrupt){
            HLOG_DEBUG("MyDevice::CreateInterrupt\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE CreateWorkItem(
            /* [annotation][in] */
            _In_  PWUDF_WORKITEM_CONFIG pConfig,
            /* [annotation][in] */
            _In_  IWDFObject *pParentObject,
            /* [annotation][out] */
            _Out_  IWDFWorkItem **ppWorkItem){
            HLOG_DEBUG("MyDevice::CreateWorkItem\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE AssignS0IdleSettingsEx(
            /* [annotation][in] */
            _In_  PWUDF_DEVICE_POWER_POLICY_IDLE_SETTINGS IdleSettings){
            HLOG_DEBUG("MyDevice::AssignS0IdleSettingsEx\r\n");
            return 0;
        }
};

struct MyDriver : public IWDFDriver {
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyDriver::QueryInterface " << str << std::endl;
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("MyDriver::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("MyDriver::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("MyDriver::DeleteWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) {
            HLOG_DEBUG("MyDriver::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) {
            HLOG_DEBUG("MyDriver::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            HLOG_DEBUG("MyDriver::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            HLOG_DEBUG("MyDriver::ReleaseLock\r\n");
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE CreateDevice(
            /* [annotation][in] */
            _In_  IWDFDeviceInitialize *pDeviceInit,
            /* [annotation][unique][in] */
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][out] */
            _Out_  IWDFDevice **ppDevice) {
            HLOG_DEBUG("MyDriver::CreateDevice\r\n");
            *ppDevice = myDevice = new MyDevice(this, pCallbackInterface);
            HLOG_USER("new device=%p\r\n", *ppDevice);
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE CreateWdfObject(
            /* [annotation][unique][in] */
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */
            _Out_  IWDFObject **ppWdfObject) {
            HLOG_DEBUG("MyDriver::CreateWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE CreatePreallocatedWdfMemory(
            /* [annotation][size_is][in] */
            _In_reads_bytes_(BufferSize)  BYTE *pBuff,
            /* [annotation][in] */
            _In_  SIZE_T BufferSize,
            /* [annotation][unique][in] */
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */
            _Out_  IWDFMemory **ppWdfMemory) {
            HLOG_DEBUG("MyDriver::CreatePreallocatedWdfMemory %p (%zu) = ",
                pBuff, (size_t)BufferSize);
            *ppWdfMemory = new MyMem(pBuff, BufferSize);
            HLOG_DEBUG(" %p\r\n", *ppWdfMemory);
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE CreateWdfMemory(
            /* [annotation][in] */
            _In_  SIZE_T BufferSize,
            /* [annotation][unique][in] */
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */
            _Out_  IWDFMemory **ppWdfMemory) {
            HLOG_DEBUG("MyDriver::CreateWdfMemory %zu = ", (size_t)BufferSize);
            // FIXME: Free this
            void *mem = malloc(BufferSize);
            memset(mem, 0, BufferSize);
            *ppWdfMemory = new MyMem(mem, BufferSize);
            HLOG_DEBUG(" %p\r\n", *ppWdfMemory);
            return 0;
        }

        virtual BOOL STDMETHODCALLTYPE IsVersionAvailable(
            /* [annotation][in] */
            _In_  UMDF_VERSION_DATA *pMinimumVersion) {
            HLOG_DEBUG("MyDriver::IsVersionAvailable\r\n");
            return true;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveVersionString(
            /* [annotation][unique][out][string] */
            _Out_writes_to_opt_(*pdwVersionLength, *pdwVersionLength)  PWSTR pVersion,
            /* [annotation][out][in] */
            _Inout_  DWORD *pdwVersionLength) {
            HLOG_DEBUG("MyDriver::RetrieveVersionString\r\n");
            return 0;
        }
};

class MyDevInit : public IWDFDeviceInitialize {
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            HLOG_DEBUG("MyDevInit::QueryInterface\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("MyDevInit::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("MyDevInit::Release\r\n");
            return 0;
        }

    public:
        virtual void STDMETHODCALLTYPE SetFilter( void) {
            HLOG_DEBUG("MyDevInit::SetFilter\r\n");
        }

        virtual void STDMETHODCALLTYPE SetLockingConstraint(
            /* [annotation][in] */
            _In_  WDF_CALLBACK_CONSTRAINT LockType) {
            HLOG_DEBUG("MyDevInit::SetLockingConstraint\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveDevicePropertyStore(
            /* [annotation][unique][in] */
            _In_opt_  PCWSTR pcwszServiceName,
            /* [annotation][in] */
            _In_  WDF_PROPERTY_STORE_RETRIEVE_FLAGS Flags,
            /* [annotation][out] */
            _Out_  IWDFNamedPropertyStore **ppPropStore,
            /* [annotation][unique][out] */
            _Out_opt_  WDF_PROPERTY_STORE_DISPOSITION *pDisposition) {
            HLOG_DEBUG("MyDevInit::RetrieveDevicePropertyStore\r\n");
            *ppPropStore = new MyNamedPropertyStore();
            return 0;
        }

        virtual void STDMETHODCALLTYPE SetPowerPolicyOwnership(
            /* [annotation][in] */
            _In_  BOOL fTrue) {
            HLOG_DEBUG("MyDevInit::SetPowerPolicyOwnership %d\r\n", fTrue);
        }

        virtual void STDMETHODCALLTYPE AutoForwardCreateCleanupClose(
            /* [annotation][in] */
            _In_  WDF_TRI_STATE State) {
            HLOG_DEBUG("MyDevInit::AutoForwardCreateCleanupClose\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceInstanceId(
            /* [annotation][unique][out][string] */
            _Out_opt_  PWSTR Buffer,
            /* [annotation][out][in] */
            _Inout_  DWORD *pdwSizeInChars) {
            HLOG_DEBUG("MyDevInit::RetrieveDeviceInstanceId\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE SetPnpCapability(
            /* [annotation][in] */
            _In_  WDF_PNP_CAPABILITY Capability,
            /* [annotation][in] */
            _In_  WDF_TRI_STATE Value) {
            HLOG_DEBUG("MyDevInit::SetPnpCapability\r\n");
        }

        virtual WDF_TRI_STATE STDMETHODCALLTYPE GetPnpCapability(
            /* [annotation][in] */
            _In_  WDF_PNP_CAPABILITY Capability) {
            HLOG_DEBUG("MyDevInit::GetPnpCapability\r\n");
            return WdfFalse;
        }
};

class MyResourceList : public IWDFCmResourceList {
public:
        MyResourceList(const char *type) {
            HLOG_DEBUG("MyResourceList(%s)\r\n", type);
            m_type = type;
        }

        // IUnknown methods (simplified)
        virtual ULONG STDMETHODCALLTYPE AddRef() override {
            HLOG_DEBUG("MyResourceList::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() override {
            HLOG_DEBUG("MyResourceList::Release\r\n");
            return 0;
        }
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyResourceList::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }

        virtual ULONG STDMETHODCALLTYPE GetCount() override {
            HLOG_DEBUG("MyResourceList::GetCount %s\r\n", m_type);
            return m_count;
        }

        virtual PCM_PARTIAL_RESOURCE_DESCRIPTOR STDMETHODCALLTYPE GetDescriptor(ULONG index) override {
            HLOG_DEBUG("MyResourceList::GetDescriptor %s %lu\r\n", m_type, index);
            return (index < m_count) ? &m_descriptors[index] : nullptr;
        }

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject() override {
            HLOG_DEBUG("MyResourceList::DeleteWdfObject\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock() override {
            HLOG_DEBUG("MyResourceList::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock() override {
            HLOG_DEBUG("MyResourceList::ReleaseLock\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) override {
            HLOG_DEBUG("MyResourceList::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) override {
            HLOG_DEBUG("MyResourceList::RetrieveContext\r\n");
            return 0;
        }

    // // USB-specific initialization
    // HRESULT InitializeForUSB() {
    //     // USB devices typically have these descriptors
    //     m_descriptors[0].Type = CmResourceTypeDeviceSpecific;
    //     m_descriptors[0].u.DeviceSpecificData.DataSize = sizeof(USB_DEVICE_DESCRIPTOR);

    //     m_descriptors[1].Type = CmResourceTypeDeviceSpecific;
    //     m_descriptors[1].u.DeviceSpecificData.DataSize = sizeof(USB_CONFIGURATION_DESCRIPTOR);

    //     m_count = 2;
    //     return S_OK;
    // }

private:
    const char *m_type = nullptr;
    CM_PARTIAL_RESOURCE_DESCRIPTOR m_descriptors[4];
    ULONG m_count = 0;
};


std::basic_ostream<wchar_t> &
operator << (std::basic_ostream<wchar_t> &os, LARGE_INTEGER i)
{
    return os << i.QuadPart;
}


std::basic_ostream<wchar_t> &
operator << (std::basic_ostream<wchar_t> &os, WINBIO_REGISTERED_FORMAT r)
{
    return os << L"Owher=" << r.Owner << L", Type=" << r.Type;
}

void
identifyFeatureSet()
{
    ULONGLONG stl_zero = 0;
    WINBIO_BLANK_PAYLOAD stl_obuf = {0};
    MyMem stl_in((UCHAR *)&stl_zero, sizeof(stl_zero)), stl_out((UCHAR *)&stl_obuf, sizeof(stl_obuf));
    MyRequest stl_req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_SET_TEMPLATE_LIST, &stl_out, &stl_in);

    HLOG_USER("SET_TEMPLATE_LIST (zero-list)\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &stl_req, IOCTL_BIOMETRIC_ENGINE_SET_TEMPLATE_LIST, 0, 0);
    while(!stl_req.complete)
        Sleep(200);

    HLOG_USER("SET_TEMPLATE_LIST: hresult=0x%lx (%s), PayloadSize=%lu, infoSize=%lld\n",
        (unsigned long)stl_req.completionStatus, hresult_to_sting(stl_req.completionStatus),
        (unsigned long)stl_obuf.PayloadSize, (long long)stl_req.informationSize);

    const DWORD ia_obuf_size = 4096;
    UCHAR *ia_obuf = (UCHAR *)calloc(1, ia_obuf_size);
    if(!ia_obuf) {
        HLOG_USER("identifyFeatureSet: failed to allocate identify buffer\n");
        return;
    }
    MyMem ia_in(NULL, 0), ia_out(ia_obuf, ia_obuf_size);
    MyRequest ia_req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_GET_IDENTIFY_ALL, &ia_out, &ia_in);

    HLOG_USER("GET_IDENTIFY_ALL\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &ia_req, IOCTL_BIOMETRIC_ENGINE_GET_IDENTIFY_ALL, 0, 0);
    HLOG_DEBUG("returned from IOCTL_BIOMETRIC_ENGINE_GET_IDENTIFY_ALL dispatch, complete=%d\n", ia_req.complete ? 1 : 0);
    while(!ia_req.complete)
        Sleep(200);

    HLOG_USER("IDENTIFY_ALL: hresult=0x%lx (%s), infoSize=%lld\n",
        (unsigned long)ia_req.completionStatus, hresult_to_sting(ia_req.completionStatus),
        (long long)ia_req.informationSize);

    if(!FAILED(ia_req.completionStatus) && ia_req.informationSize >= (LONG_PTR)sizeof(WINBIO_IDENTIFY_ALL_OUTPUT_WIRE)) {
        WINBIO_IDENTIFY_ALL_OUTPUT_WIRE *identifyOut = (WINBIO_IDENTIFY_ALL_OUTPUT_WIRE *)ia_obuf;
        HLOG_USER("=== Match Result ===\n");
        HLOG_USER("EngineHresult=0x%lx (%s)\n",
            (unsigned long)identifyOut->EngineHresult,
            hresult_to_sting(identifyOut->EngineHresult));
        HLOG_USER("SubFactor=%u (%s)\n",
            (unsigned)identifyOut->SubFactor,
            subfactor_to_string((WINBIO_BIOMETRIC_SUBTYPE)identifyOut->SubFactor));
        display_identity(&identifyOut->Identity, "");
        LONG_PTR extra = ia_req.informationSize - sizeof(WINBIO_IDENTIFY_ALL_OUTPUT_WIRE);
        if(extra > 0)
            HLOG_USER("  TrailingData: %lld bytes\n", (long long)extra);
    }

    HLOG_DEBUG("IDENTIFY_ALL raw (%lld bytes): ", (long long)ia_req.informationSize);
    for(LONG_PTR i=0;i<ia_req.informationSize && i<96;i++)
        HLOG_DEBUG("%02x", ia_obuf[i]);
    HLOG_DEBUG("\n");

    free(ia_obuf);
}

void setIndicator(WINBIO_INDICATOR_STATUS status);

void
identify()
{
    {
        char calibrate_buf[1024];
        WINBIO_CALIBRATION_INFO *cal = (WINBIO_CALIBRATION_INFO *)calibrate_buf;
        MyMem cal_in(NULL, 0), cal_out(calibrate_buf, sizeof(calibrate_buf));
        MyRequest cal_req(WdfRequestOther, IOCTL_BIOMETRIC_CALIBRATE, &cal_out, &cal_in);

        HLOG_USER("about to IOCTL_BIOMETRIC_CALIBRATE\r\n");
        myQueue->ioctl->OnDeviceIoControl(myQueue, &cal_req, IOCTL_BIOMETRIC_CALIBRATE, 0, 0);
        int waitedMs = 0;
        while(!cal_req.complete && waitedMs < 5000) {
            Sleep(200);
            waitedMs += 200;
        }

        if(!cal_req.complete) {
            HLOG_USER("CALIBRATE still pending after %d ms; continuing to CAPTURE_DATA\n", waitedMs);
        }
        else {
            HLOG_INFO("CALIBRATE: hresult=0x%lx (%s)\n", (unsigned long)cal_req.completionStatus,
                hresult_to_sting(cal_req.completionStatus));
            if(FAILED(cal_req.completionStatus))
                HLOG_USER("CALIBRATE failed; continuing to CAPTURE_DATA anyway\n");
        }
    }

    char obuf[1024*100];
    WINBIO_CAPTURE_DATA *data = (WINBIO_CAPTURE_DATA *)obuf;
    WINBIO_CAPTURE_PARAMETERS params = {0};

    HLOG_USER("sizeof(params)=%lld\n", (long long)sizeof(params));

    params.PayloadSize = sizeof(params);
    params.Purpose = WINBIO_PURPOSE_IDENTIFY;
    ((uint64_t*)&params.VendorFormat)[0] = 0x46DCFA2072A4E245L;
    ((uint64_t*)&params.VendorFormat)[1] = 0xA927C0D0BA850395L;
    params.Format.Owner = 0;
    params.Format.Type = 0;
    params.Flags = WINBIO_DATA_FLAG_PROCESSED;

    setIndicator(WINBIO_INDICATOR_ON);

    MyMem in((UCHAR*)&params, sizeof(params)), out(obuf, sizeof(obuf));
    MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_CAPTURE_DATA, &out, &in);

    HLOG_USER("about to IOCTL_BIOMETRIC_CAPTURE_DATA\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_CAPTURE_DATA, 0, 0);
    int waitedMs = 0;
    HLOG_USER("Waiting for capture to complete (touch sensor)...\n");
    while(!req.complete && waitedMs < 60000) {
        Sleep(200);
        waitedMs += 200;
        if((waitedMs % 2000) == 0)
            HLOG_TRACE("  ...still waiting (%d ms)\n", waitedMs);
    }

    if(!req.complete) {
        HLOG_DEBUG("CAPTURE_DATA still pending after %d ms; cancelling request\n", waitedMs);
        if(req.cancelCallback) {
            req.cancelCallback->OnCancel(&req);
            for(int i=0;i<25 && !req.complete;i++)
                Sleep(200);
        }
    }

    if(!req.complete) {
        HLOG_USER("CAPTURE_DATA did not complete; capture thread is still waiting for sensor event\n");
        setIndicator(WINBIO_INDICATOR_OFF);
        return;
    }

    //HLOG_DEBUG("wakey wakey\r\n");
    //rc = myDevice->pnpcb->OnD0Entry(myDevice, WdfPowerDeviceInvalid);
    if(FAILED(req.completionStatus) || FAILED(data->WinBioHresult) || data->CaptureData.Size == 0) {
        HLOG_USER("Capture did not produce a usable sample; skipping identify stage\n");
        setIndicator(WINBIO_INDICATOR_OFF);
        return;
    }

    HLOG_USER("=== Capture Result ===\n");
    HLOG_USER("PayloadSize=%lu WinBioHresult=0x%lx (%s)\n",
        data->PayloadSize,
        (unsigned long)data->WinBioHresult,
        hresult_to_sting(data->WinBioHresult));
    HLOG_USER("SensorStatus=%lu RejectDetail=0x%lx (%s)\n",
        (unsigned long)data->SensorStatus,
        (unsigned long)data->RejectDetail,
        reject_detail_to_string(data->RejectDetail));
    HLOG_USER("CaptureData.Size=%lu\n", data->CaptureData.Size);

    if(data->CaptureData.Size > 0) {
        WINBIO_BIR *bir = (WINBIO_BIR *)data->CaptureData.Data;
        HLOG_USER("BIR: HeaderBlock={Size=%ld,Offset=%ld} "
            "StandardDataBlock={Size=%ld,Offset=%ld} "
            "VendorDataBlock={Size=%ld,Offset=%ld} "
            "SignatureBlock={Size=%ld,Offset=%ld}\n",
            bir->HeaderBlock.Size, bir->HeaderBlock.Offset,
            bir->StandardDataBlock.Size, bir->StandardDataBlock.Offset,
            bir->VendorDataBlock.Size, bir->VendorDataBlock.Offset,
            bir->SignatureBlock.Size, bir->SignatureBlock.Offset);

        if(bir->HeaderBlock.Size > 0) {
            WINBIO_BIR_HEADER *hdr = (WINBIO_BIR_HEADER *)(data->CaptureData.Data + bir->HeaderBlock.Offset);
            HLOG_USER("BIR Header:\n");
            HLOG_USER("  ValidFields=0x%04x HeaderVersion=%u PatronHeaderVersion=%u\n",
                hdr->ValidFields, hdr->HeaderVersion, hdr->PatronHeaderVersion);
            HLOG_USER("  DataFlags=0x%04x Type=0x%04x Subtype=0x%04x Purpose=%d\n",
                hdr->DataFlags, hdr->Type, hdr->Subtype, hdr->Purpose);
            HLOG_USER("  DataQuality=%d CreationDate=%lld\n",
                (int)hdr->DataQuality, (long long)hdr->CreationDate.QuadPart);
            HLOG_USER("  Format={Owner=0x%04x,Type=0x%04x} ProductId={Owner=0x%04x,Type=0x%04x}\n",
                hdr->BiometricDataFormat.Owner, hdr->BiometricDataFormat.Type,
                hdr->ProductId.Owner, hdr->ProductId.Type);
        }
        HLOG_DEBUG("Raw capture data (%lu bytes): ", data->CaptureData.Size);
        for(ULONG i=0;i<data->CaptureData.Size && i<64;i++)
            HLOG_DEBUG("%02x", ((UCHAR*)data->CaptureData.Data)[i]);
        if(data->CaptureData.Size > 64)
            HLOG_DEBUG("...");
        HLOG_DEBUG("\n");
    }

    setIndicator(WINBIO_INDICATOR_OFF);

    HLOG_USER("=== Identify Match ===\n");
    identifyFeatureSet();
}

void
commitEnrollment()
{
    // UCHAR arecord[] = {
    //     /* 4c, identity  */ 0x03, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0xc5, 0x69, 0x85, 0x17, 0xbc, 0xff, 0x12, 0xe7, 0x24, 0x96, 0xb7, 0x63, 0xed, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //     /* 04, subfactor */ 0xf6, 0x00, 0x00, 0x00,
    //     /* 08, payload sz*/ 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //     /* 08, payload   */ 'U', 'n', 'i', 'c', 'o', 'r', 'n', 0x00
    // };

    // UCHAR obuf[1];
    // MyMem in(arecord, sizeof(arecord)), out(obuf, sizeof(obuf));
    // MyRequest req(WdfRequestOther, 0x442018, &out, &in);

    // HLOG_DEBUG("about to Commit Enrollment\r\n");
    // myQueue->ioctl->OnDeviceIoControl(myQueue, &req, 0x442018, 0, 0);
    // while(!req.complete)
    //     Sleep(200);

    // HLOG_INFO("Got back 0x%llx bytes: ", req.informationSize);
    // for(LONG_PTR i=0;i<req.informationSize;i++)
    //     HLOG_DEBUG("%02x", obuf[i]);
    // HLOG_DEBUG("\n");
    // return;


    typedef struct _SYNA_COMMIT_ENROLLMENT_INPUT_WIRE {
        WINBIO_IDENTITY Identity;
        ULONG SubFactor;
        ULONGLONG PayloadBlobSize;
        UCHAR PayloadBlob[8];
    } SYNA_COMMIT_ENROLLMENT_INPUT_WIRE;
    static_assert(offsetof(SYNA_COMMIT_ENROLLMENT_INPUT_WIRE, SubFactor) == 0x4c, "Commit SubFactor offset must be 0x4c");
    static_assert(offsetof(SYNA_COMMIT_ENROLLMENT_INPUT_WIRE, PayloadBlobSize) == 0x50, "Commit PayloadBlobSize offset must be 0x50");
    static_assert(offsetof(SYNA_COMMIT_ENROLLMENT_INPUT_WIRE, PayloadBlob) == 0x58, "Commit PayloadBlob offset must be 0x58");
    static_assert(sizeof(SYNA_COMMIT_ENROLLMENT_INPUT_WIRE) == 0x60, "Commit input wire size must be 0x60");

    HRESULT commitStatus = E_FAIL;

    {
        SYNA_COMMIT_ENROLLMENT_INPUT_WIRE input = {0};
        WINBIO_BLANK_PAYLOAD obuf = {0};

        input.Identity.Type = WINBIO_ID_TYPE_GUID;
        if(FAILED(CoCreateGuid(&input.Identity.Value.TemplateGuid))) {
            input.Identity.Type = WINBIO_ID_TYPE_WILDCARD;
            input.Identity.Value.Wildcard = WINBIO_IDENTITY_WILDCARD;
        }
        input.SubFactor = (ULONG)WINBIO_ANSI_381_POS_RH_INDEX_FINGER;
        HLOG_USER("COMMIT_ENROLLMENT using new identity (Type=%lu, SubFactor=%u)\n",
            (unsigned long)input.Identity.Type,
            (unsigned)input.SubFactor);

        input.PayloadBlobSize = sizeof(input.PayloadBlob);
        memcpy(input.PayloadBlob, "Unicorn", sizeof(input.PayloadBlob));

        MyMem in((UCHAR *)&input, sizeof(input)), out((UCHAR *)&obuf, sizeof(obuf));
        MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_COMMIT_ENROLLMENT, &out, &in);

        HLOG_USER("about to IOCTL_BIOMETRIC_ENGINE_COMMIT_ENROLLMENT (typed input, inSize=%zu)\r\n", sizeof(input));
        myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_ENGINE_COMMIT_ENROLLMENT, 0, 0);
        while(!req.complete)
            Sleep(200);

        HLOG_INFO("COMMIT_ENROLLMENT structured: hresult=0x%lx (%s), infoSize=%lld\n",
            (unsigned long)req.completionStatus, hresult_to_sting(req.completionStatus),
            (long long)req.informationSize);
        HLOG_DEBUG("  PayloadSize=%lu WinBioHresult=0x%lx (%s)\n",
            obuf.PayloadSize, (unsigned long)obuf.WinBioHresult,
            hresult_to_sting(obuf.WinBioHresult));

        commitStatus = req.completionStatus;

    }

    if(FAILED(commitStatus)) {
        uint64_t ibuf = 0;
        WINBIO_BLANK_PAYLOAD obuf = {0};
        MyMem in((UCHAR *)&ibuf, sizeof(ibuf)), out((UCHAR *)&obuf, sizeof(obuf));
        MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_COMMIT_ENROLLMENT, &out, &in);

        HLOG_USER("about to IOCTL_BIOMETRIC_ENGINE_COMMIT_ENROLLMENT (fallback inSize=8)\r\n");
        myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_ENGINE_COMMIT_ENROLLMENT, 0, 0);
        while(!req.complete)
            Sleep(200);

        HLOG_INFO("COMMIT_ENROLLMENT fallback: hresult=0x%lx (%s), infoSize=%lld\n",
            (unsigned long)req.completionStatus, hresult_to_sting(req.completionStatus),
            (long long)req.informationSize);
        HLOG_DEBUG("  PayloadSize=%lu WinBioHresult=0x%lx (%s)\n",
            obuf.PayloadSize, (unsigned long)obuf.WinBioHresult,
            hresult_to_sting(obuf.WinBioHresult));

        commitStatus = req.completionStatus;
    }

    if(commitStatus == 1) {
        HLOG_USER("COMMIT_ENROLLMENT error: EnrollmentCommit returned 1 (VFM write failed), treating as failure\n");
        commitStatus = E_FAIL;
    }

    if(SUCCEEDED(commitStatus)) {
        HLOG_INFO("Enrollment commit successful\n");
    }

}

void
reset()
{
    WINBIO_BLANK_PAYLOAD payload = {0};
    MyMem in(NULL, 0), out((UCHAR*)&payload, sizeof(payload));
    MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_RESET, &out, &in);

    HLOG_USER("about to Reset\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_RESET, 0, 0);

    while(!req.complete)
        Sleep(200);

    Sleep(100);

    if(FAILED(req.completionStatus)) {
        HLOG_INFO("RESET failed: hresult=0x%lx (%s)\n",
            (unsigned long)req.completionStatus,
            hresult_to_sting(req.completionStatus));
        return;
    }

    if(req.informationSize >= (LONG_PTR)sizeof(payload)) {
        HLOG_INFO("RESET complete: WinBioHresult=0x%lx (%s)\r\n",
            (unsigned long)payload.WinBioHresult,
            hresult_to_sting(payload.WinBioHresult));
    }
    else {
        HLOG_INFO("RESET complete (short payload, infoSize=%lld): ", (long long)req.informationSize);
        SIZE_T dump = clampInfoSize(req.informationSize, sizeof(payload));
        for(SIZE_T i=0;i<dump;i++)
            HLOG_DEBUG("%02x", ((UCHAR*)&payload)[i]);
        HLOG_DEBUG("\r\n");
    }
}

void
enroll()
{
    Sleep(500);

    char calibrate_buf[1024];
    WINBIO_CALIBRATION_INFO *cal = (WINBIO_CALIBRATION_INFO *)calibrate_buf;
    MyMem cal_in(NULL, 0), cal_out(calibrate_buf, sizeof(calibrate_buf));
    MyRequest cal_req(WdfRequestOther, IOCTL_BIOMETRIC_CALIBRATE, &cal_out, &cal_in);

    HLOG_USER("about to IOCTL_BIOMETRIC_CALIBRATE\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &cal_req, IOCTL_BIOMETRIC_CALIBRATE, 0, 0);
    while(!cal_req.complete)
        Sleep(200);

    if(FAILED(cal_req.completionStatus)) {
        HLOG_USER("CALIBRATE failed in enroll: hresult=0x%lx (%s)\n",
            (unsigned long)cal_req.completionStatus,
            hresult_to_sting(cal_req.completionStatus));
        return;
    }

    Sleep(100);

    // CREATE_ENROLLMENT: driver expects WDF input=8, WDF output=0x28
    // EIS->vtable[1] EnrollmentCreate(interface, inputBuffer, outputBuffer):
    //   (communication with sensor VFM to start enrollment session)
    {
        typedef struct _SYNA_CREATE_ENROLLMENT_WIRE_INPUT {
            UCHAR Data[8];
        } SYNA_CREATE_ENROLLMENT_WIRE_INPUT;
        typedef struct _SYNA_CREATE_ENROLLMENT_WIRE_OUTPUT {
            UCHAR Data[0x28];
        } SYNA_CREATE_ENROLLMENT_WIRE_OUTPUT;

        SYNA_CREATE_ENROLLMENT_WIRE_INPUT ceInput = {0};
        SYNA_CREATE_ENROLLMENT_WIRE_OUTPUT ceOutput = {0};
        MyMem in((UCHAR*)&ceInput, sizeof(ceInput)), out((UCHAR*)&ceOutput, sizeof(ceOutput));
        MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_CREATE_ENROLLMENT, &out, &in);

        HLOG_USER("about to IOCTL_BIOMETRIC_ENGINE_CREATE_ENROLLMENT\r\n");
        myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_ENGINE_CREATE_ENROLLMENT, 0, 0);
        while(!req.complete)
            Sleep(200);

        HLOG_INFO("CREATE_ENROLLMENT: hresult=0x%lx (%s)\r\n", (unsigned long)req.completionStatus,
            hresult_to_sting(req.completionStatus));
        if(FAILED(req.completionStatus)) {
            HLOG_USER("CREATE_ENROLLMENT failed, aborting enroll\r\n");
            return;
        }
    }

    Sleep(100);

    // keep going until template is complete
    for(int t=0;t<70;t++) {
        char obuf[1024*100];
        WINBIO_CAPTURE_DATA *data = (WINBIO_CAPTURE_DATA *)obuf;
        WINBIO_CAPTURE_PARAMETERS params = {0};

        params.PayloadSize = sizeof(params);
        params.Purpose = WINBIO_PURPOSE_ENROLL_FOR_IDENTIFICATION;
        ((uint64_t*)&params.VendorFormat)[0] = 0x46DCFA2072A4E245L;
        ((uint64_t*)&params.VendorFormat)[1] = 0xA927C0D0BA850395L;
        params.Format.Owner = 0;
        params.Format.Type = 0;
        params.Flags = WINBIO_DATA_FLAG_PROCESSED;

        MyMem in((UCHAR*)&params, sizeof(params)), out(obuf, sizeof(obuf));
        MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_CAPTURE_DATA, &out, &in);

        HLOG_USER("about to IOCTL_BIOMETRIC_CAPTURE_DATA\r\n");
        myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_CAPTURE_DATA, 0, 0);
        while(!req.complete)
            Sleep(200);

        if(FAILED(req.completionStatus)) {
            HLOG_INFO("CAPTURE_DATA request failed: hresult=0x%lx (%s)\n",
                (unsigned long)req.completionStatus,
                hresult_to_sting(req.completionStatus));
            Sleep(100);
            continue;
        }

        IFLOG(1) {
            std::wcout
                << L"=======================" << std::endl
                << L"PayloadSize " << data->PayloadSize << std::endl
                << L"WinBioHresult 0x" << std::hex << data->WinBioHresult << L" (" << hresult_to_sting(data->WinBioHresult) << L")" << std::endl
                << L"SensorStatus " << std::dec << data->SensorStatus << std::endl
                << L"RejectDetail 0x" << std::hex << data->RejectDetail << L" (" << reject_detail_to_string(data->RejectDetail) << L")" << std::dec << std::endl
                << L"CaptureData.Size " << data->CaptureData.Size << std::endl
                << L"=======================" << std::endl;
        }

        // scan failed?
        if(data->SensorStatus == 2) {
            Sleep(100);
            continue;
        }

        Sleep(100);
        {
            // UPDATE_ENROLLMENT: driver expects WDF in/out both 0x48 bytes
            // EIS->vtable[2] (offset 0x10): accepts 0x48-byte buffer
            // Output layout:
            //   [0x00] HRESULT EnrollmentStatus
            //   [0x28] ULONG Progress
            //   [0x2c] ULONG RejectDetail
            typedef struct _SYNA_UPDATE_ENROLLMENT_WIRE_OUTPUT {
                HRESULT EnrollmentStatus;
                UCHAR Reserved1[0x24];
                ULONG Progress;
                ULONG RejectDetail;
                UCHAR Reserved2[0x18];
            } SYNA_UPDATE_ENROLLMENT_WIRE_OUTPUT;
            typedef struct _SYNA_UPDATE_ENROLLMENT_WIRE_INPUT {
                UCHAR Data[0x48];
            } SYNA_UPDATE_ENROLLMENT_WIRE_INPUT;

            SYNA_UPDATE_ENROLLMENT_WIRE_INPUT ueInput = {0};
            SYNA_UPDATE_ENROLLMENT_WIRE_OUTPUT ueOutput = {0};
            MyMem in((UCHAR*)&ueInput, sizeof(ueInput)), out((UCHAR*)&ueOutput, sizeof(ueOutput));
            MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_UPDATE_ENROLLMENT, &out, &in);

            HLOG_USER("about to IOCTL_BIOMETRIC_ENGINE_UPDATE_ENROLLMENT\r\n");
            myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_ENGINE_UPDATE_ENROLLMENT, 0, 0);
            while(!req.complete)
                Sleep(200);

            HLOG_INFO("UPDATE_ENROLLMENT hresult=0x%lx (%s), data: ", (unsigned long)req.completionStatus,
                hresult_to_sting(req.completionStatus));
            SIZE_T updateDumpSize = clampInfoSize(req.informationSize, sizeof(ueOutput));
            for(SIZE_T i=0;i<updateDumpSize;i++)
                HLOG_DEBUG("%02x", ((UCHAR*)&ueOutput)[i]);
            HLOG_DEBUG("\n");

            if(FAILED(req.completionStatus) || req.informationSize < 0x30) {
                HLOG_DEBUG("UPDATE_ENROLLMENT did not return expected payload (status=0x%lx, infoSize=%lld)\n",
                    (unsigned long)req.completionStatus,
                    (long long)req.informationSize);
                break;
            }

            // Enrollment status in output: WINBIO_I_MORE_DATA = need more samples, S_OK = complete
            DWORD enrollStatus = ueOutput.EnrollmentStatus;
            DWORD enrollProgress = ueOutput.Progress;
            DWORD enrollReject = ueOutput.RejectDetail;
            HLOG_USER("Enrollment status=0x%lx (%s) progress=%lu%% reject=%s\n",
                (unsigned long)enrollStatus, hresult_to_sting(enrollStatus),
                (unsigned long)enrollProgress, reject_detail_to_string(enrollReject));
            if(enrollStatus != WINBIO_I_MORE_DATA)
                break;
        }
        Sleep(100);
    }

    //------------------------------- check for dups --------------------------
    // EIS->vtable[9] EnrollmentCheckForDuplicate(interface, buffer):
    //   WDF in/out both 0x50 bytes. Buffer layout (all OUTPUT from EIS):
    //   [0x00] WINBIO_IDENTITY Identity  (0x4c bytes)
    //   [0x4c] UCHAR SubFactor
    //   [0x4d] UCHAR Duplicate (1 = duplicate found)
    //   [0x4e] UCHAR Reserved[2]
    {
        typedef struct _SYNA_CHECK_FOR_DUPLICATE_WIRE {
            WINBIO_IDENTITY Identity;
            UCHAR SubFactor;
            UCHAR Duplicate;
            UCHAR Reserved[2];
        } SYNA_CHECK_FOR_DUPLICATE_WIRE;
        static_assert(sizeof(SYNA_CHECK_FOR_DUPLICATE_WIRE) == 0x50, "CheckForDuplicate wire size must be 0x50");

        SYNA_CHECK_FOR_DUPLICATE_WIRE wireBuf = {0};
        MyMem in((UCHAR*)&wireBuf, sizeof(wireBuf)), out((UCHAR*)&wireBuf, sizeof(wireBuf));
        MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_CHECK_FOR_DUPLICATE, &out, &in);

        HLOG_USER("about to IOCTL_BIOMETRIC_ENGINE_CHECK_FOR_DUPLICATE\r\n");
        myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_ENGINE_CHECK_FOR_DUPLICATE, 0, 0);
        while(!req.complete)
            Sleep(200);

        HLOG_USER("CHECK_FOR_DUPLICATE hresult=0x%lx (%s)\n",
            (unsigned long)req.completionStatus, hresult_to_sting(req.completionStatus));

        if(SUCCEEDED(req.completionStatus)) {
            HLOG_USER("  Duplicate=%u\n", (unsigned)wireBuf.Duplicate);
            if(wireBuf.Duplicate) {
                HLOG_USER("  Duplicate template found! Skipping commit.\n");
                HLOG_USER("  Matched Identity Type=%lu\n", (unsigned long)wireBuf.Identity.Type);
                if(wireBuf.Identity.Type == WINBIO_ID_TYPE_GUID) {
                    RPC_CSTR guidStr = NULL;
                    if(SUCCEEDED(UuidToStringA((UUID*)&wireBuf.Identity.Value.TemplateGuid, &guidStr))) {
                        HLOG_USER("  Matched GUID: %s\n", guidStr);
                        RpcStringFreeA(&guidStr);
                    }
                }
                HLOG_USER("  Matched SubFactor=%u\n", (unsigned)wireBuf.SubFactor);
                return;
            }
        }

        HLOG_INFO("Got back 0x%llx bytes: ", req.informationSize);
        SIZE_T dupDumpSize = clampInfoSize(req.informationSize, sizeof(wireBuf));
        for(SIZE_T i=0;i<dupDumpSize;i++)
            HLOG_DEBUG("%02x", ((UCHAR*)&wireBuf)[i]);
        HLOG_DEBUG("\n");
    }

    Sleep(1000);

    commitEnrollment();
}

void
identifyAll()
{
    {
        char calibrate_buf[1024];
        WINBIO_CALIBRATION_INFO *cal = (WINBIO_CALIBRATION_INFO *)calibrate_buf;
        MyMem cal_in(NULL, 0), cal_out(calibrate_buf, sizeof(calibrate_buf));
        MyRequest cal_req(WdfRequestOther, IOCTL_BIOMETRIC_CALIBRATE, &cal_out, &cal_in);

        HLOG_USER("about to IOCTL_BIOMETRIC_CALIBRATE\r\n");
        myQueue->ioctl->OnDeviceIoControl(myQueue, &cal_req, IOCTL_BIOMETRIC_CALIBRATE, 0, 0);
        while(!cal_req.complete)
            Sleep(200);

        HLOG_INFO("CALIBRATE: hresult=0x%lx (%s)\n", (unsigned long)cal_req.completionStatus,
            hresult_to_sting(cal_req.completionStatus));
        if(FAILED(cal_req.completionStatus)) {
            HLOG_USER("CALIBRATE failed, aborting identify-all\n");
            return;
        }
    }

    {
        ULONGLONG stl_zero = 0;
        WINBIO_BLANK_PAYLOAD stl_obuf = {0};
        MyMem stl_in((UCHAR *)&stl_zero, sizeof(stl_zero)), stl_out((UCHAR *)&stl_obuf, sizeof(stl_obuf));
        MyRequest stl_req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_SET_TEMPLATE_LIST, &stl_out, &stl_in);

        HLOG_USER("SET_TEMPLATE_LIST (zero-list)\n");
        myQueue->ioctl->OnDeviceIoControl(myQueue, &stl_req, IOCTL_BIOMETRIC_ENGINE_SET_TEMPLATE_LIST, 0, 0);
        while(!stl_req.complete)
            Sleep(200);

        HLOG_USER("SET_TEMPLATE_LIST: hresult=0x%lx (%s), PayloadSize=%lu, infoSize=%lld\n",
            (unsigned long)stl_req.completionStatus, hresult_to_sting(stl_req.completionStatus),
            (unsigned long)stl_obuf.PayloadSize, (long long)stl_req.informationSize);

        if(FAILED(stl_req.completionStatus)) {
            HLOG_USER("SET_TEMPLATE_LIST failed, aborting identify-all\n");
            return;
        }
    }

    DWORD obufSize = 4096;
    UCHAR *obuf = (UCHAR *)calloc(1, obufSize);
    if(!obuf) {
        HLOG_USER("identifyAll: failed to allocate output buffer\n");
        return;
    }
    MyMem in(NULL, 0), out(obuf, obufSize);
    MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_GET_IDENTIFY_ALL, &out, &in);

    HLOG_USER("about to IOCTL_BIOMETRIC_ENGINE_GET_IDENTIFY_ALL (OnIdentifyAll)\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_ENGINE_GET_IDENTIFY_ALL, 0, 0);
    HLOG_INFO("returned from IOCTL_BIOMETRIC_ENGINE_GET_IDENTIFY_ALL dispatch, complete=%d\n", req.complete ? 1 : 0);
    while(!req.complete)
        Sleep(200);

    HLOG_USER("IDENTIFY_ALL: hresult=0x%lx (%s), infoSize=%lld\n",
        (unsigned long)req.completionStatus, hresult_to_sting(req.completionStatus),
        (long long)req.informationSize);

    if(!FAILED(req.completionStatus) && req.informationSize >= (LONG_PTR)sizeof(WINBIO_IDENTIFY_ALL_OUTPUT_WIRE)) {
        WINBIO_IDENTIFY_ALL_OUTPUT_WIRE *identifyOut = (WINBIO_IDENTIFY_ALL_OUTPUT_WIRE *)obuf;
        HRESULT engineHr = identifyOut->EngineHresult;

        HLOG_USER("=== Match Result ===\n");
        HLOG_USER("EngineHresult=0x%lx (%s)\n",
            (unsigned long)engineHr, hresult_to_sting(engineHr));
        HLOG_USER("SubFactor=%u (%s)\n",
            (unsigned)identifyOut->SubFactor,
            subfactor_to_string((WINBIO_BIOMETRIC_SUBTYPE)identifyOut->SubFactor));
        display_identity(&identifyOut->Identity, "");
    }

    HLOG_DEBUG("IDENTIFY_ALL raw (%lld bytes): ", (long long)req.informationSize);
    for(LONG_PTR i=0;i<req.informationSize && i<96;i++)
        HLOG_DEBUG("%02x", obuf[i]);
    HLOG_DEBUG("\n");

    free(obuf);
}

void
setLed(WINBIO_INDICATOR_STATUS state)
{
    DWORD ibuf = state;
    DWORD obuf = 0;
    MyMem in((UCHAR*)&ibuf, sizeof(ibuf)), out((UCHAR*)&obuf, sizeof(obuf));
    MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_SET_LED_STATE, &out, &in);

    HLOG_USER("about to IOCTL_BIOMETRIC_ENGINE_SET_LED_STATE (OnSetLedState, state=%s)\r\n",
        state == WINBIO_INDICATOR_ON ? "WINBIO_INDICATOR_ON" : "WINBIO_INDICATOR_OFF");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_ENGINE_SET_LED_STATE, 0, 0);
    while(!req.complete)
        Sleep(200);

    HLOG_INFO("SET_LED_STATE: hresult=0x%lx (%s)\r\n",
        (unsigned long)req.completionStatus, hresult_to_sting(req.completionStatus));
}

void
listDatabase()
{
    UCHAR ibuf_rc[8] = {0};
    SIZE_T recordCount = 0;
    MyMem in_rc(ibuf_rc, sizeof(ibuf_rc)), out_rc((UCHAR*)&recordCount, sizeof(recordCount));
    MyRequest req_rc(WdfRequestOther, IOCTL_BIOMETRIC_STORAGE_GET_RECORD_COUNT, &out_rc, &in_rc);

    HLOG_USER("about to IOCTL_BIOMETRIC_STORAGE_GET_RECORD_COUNT (WbioStorageGetRecordCount)\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req_rc, IOCTL_BIOMETRIC_STORAGE_GET_RECORD_COUNT, 0, 0);
    while(!req_rc.complete)
        Sleep(200);

    HLOG_INFO("GET_RECORD_COUNT: hresult=0x%lx (%s)\r\n",
        (unsigned long)req_rc.completionStatus, hresult_to_sting(req_rc.completionStatus));

    if(FAILED(req_rc.completionStatus)) {
        HLOG_USER("GET_RECORD_COUNT failed\r\n");
        return;
    }

    HLOG_USER("Record count: %zu\r\n", recordCount);

    if(recordCount == 0) {
        HLOG_USER("Database is empty\r\n");
        return;
    }

    {
        UCHAR gcd_ibuf[4] = {0};
        UCHAR gcd_obuf[256] = {0};
        MyMem gcd_in(gcd_ibuf, sizeof(gcd_ibuf)), gcd_out(gcd_obuf, sizeof(gcd_obuf));
        MyRequest gcd_req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_GET_COMMON_DATA, &gcd_out, &gcd_in);
        HLOG_USER("about to IOCTL_BIOMETRIC_ENGINE_GET_COMMON_DATA (OnGetCommonData)\r\n");
        myQueue->ioctl->OnDeviceIoControl(myQueue, &gcd_req, IOCTL_BIOMETRIC_ENGINE_GET_COMMON_DATA, 0, 0);
        while(!gcd_req.complete)
            Sleep(200);
        HLOG_INFO("GET_COMMON_DATA: hresult=0x%lx (%s), infoSize=%lld\r\n",
            (unsigned long)gcd_req.completionStatus, hresult_to_sting(gcd_req.completionStatus),
            (long long)gcd_req.informationSize);
    }

    {
        ULONGLONG stl_zero = 0;
        WINBIO_BLANK_PAYLOAD stl_obuf = {0};
        MyMem stl_in((UCHAR *)&stl_zero, sizeof(stl_zero)), stl_out((UCHAR *)&stl_obuf, sizeof(stl_obuf));
        MyRequest stl_req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_SET_TEMPLATE_LIST, &stl_out, &stl_in);
        HLOG_USER("SET_TEMPLATE_LIST (zero-list)\n");
        myQueue->ioctl->OnDeviceIoControl(myQueue, &stl_req, IOCTL_BIOMETRIC_ENGINE_SET_TEMPLATE_LIST, 0, 0);
        while(!stl_req.complete)
            Sleep(200);
        HLOG_USER("SET_TEMPLATE_LIST: hresult=0x%lx (%s), PayloadSize=%lu, infoSize=%lld\n",
            (unsigned long)stl_req.completionStatus, hresult_to_sting(stl_req.completionStatus),
            (unsigned long)stl_obuf.PayloadSize, (long long)stl_req.informationSize);
    }

    size_t maxRecords = recordCount > 128 ? 128 : recordCount;

    {
        UCHAR *eis_ptr = *(UCHAR **)(((UCHAR *)myDevice) + 0x428);
        HLOG_USER("EIS object at %p, flag 0xf8=%u, vec begin=%p, vec end=%p\n",
            eis_ptr,
            eis_ptr ? (unsigned)eis_ptr[0xf8] : 0,
            eis_ptr ? *(void **)(eis_ptr + 0x120) : NULL,
            eis_ptr ? *(void **)(eis_ptr + 0x128) : NULL);
    }

    DWORD queryBufSize = sizeof(SYNA_STORAGE_QUERY_INPUT) - sizeof(ULONG) + 0x78;
    UCHAR *sbuf = (UCHAR *)calloc(1, queryBufSize);
    SYNA_STORAGE_QUERY_INPUT *query = (SYNA_STORAGE_QUERY_INPUT *)sbuf;
    query->QueryType = STORAGE_QUERY_TYPE_ALL;

    DWORD resultBufSize = (DWORD)(sizeof(SYNA_STORAGE_QUERY_RESULT) + (maxRecords - 1) * sizeof(SYNA_STORAGE_RECORD));
    UCHAR *rbuf = (UCHAR *)calloc(1, resultBufSize);

    MyMem in_s(sbuf, queryBufSize), out_s(rbuf, resultBufSize);
    MyRequest req_s(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_STORAGE_QUERY, &out_s, &in_s);

    HLOG_USER("about to IOCTL_BIOMETRIC_ENGINE_STORAGE_QUERY (OnStorageQuery, STORAGE_QUERY_TYPE_ALL)\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req_s, IOCTL_BIOMETRIC_ENGINE_STORAGE_QUERY, 0, 0);
    while(!req_s.complete)
        Sleep(200);

    HLOG_INFO("STORAGE_QUERY: hresult=0x%lx (%s), infoSize=%lld\r\n",
        (unsigned long)req_s.completionStatus, hresult_to_sting(req_s.completionStatus),
        (long long)req_s.informationSize);

    HLOG_DEBUG("Output buffer raw (first 64 bytes): ");
    for(int i=0;i<64 && i<(int)resultBufSize;i++)
        HLOG_DEBUG("%02x", rbuf[i]);
    HLOG_DEBUG("\n");

    HLOG_DEBUG("Input buffer raw (first 64 bytes): ");
    for(int i=0;i<64 && i<(int)queryBufSize;i++)
        HLOG_DEBUG("%02x", sbuf[i]);
    HLOG_DEBUG("\n");

    SYNA_STORAGE_QUERY_RESULT *result = (SYNA_STORAGE_QUERY_RESULT *)rbuf;

    if(FAILED(req_s.completionStatus)) {
        HLOG_USER("STORAGE_QUERY failed\r\n");
        free(sbuf);
        free(rbuf);
        return;
    }

    HLOG_USER("Returned records: %llu\r\n", (unsigned long long)result->RecordCount);

    for(DWORD i=0; i<result->RecordCount && i<maxRecords; i++) {
        SYNA_STORAGE_RECORD *rec = &result->Records[i];
        HLOG_USER("[%lu] IdentityType=%lu Subfactor=%u\n",
            (unsigned long)i,
            (unsigned long)rec->Identity.Type,
            (unsigned)rec->SubFactor);
        if(rec->Identity.Type == WINBIO_ID_TYPE_SID) {
            HLOG_USER("    SID size=%lu Data=",
                (unsigned long)rec->Identity.Value.AccountSid.Size);
            for(ULONG j=0; j<rec->Identity.Value.AccountSid.Size && j<SECURITY_MAX_SID_SIZE; j++)
                HLOG_USER("%02x", rec->Identity.Value.AccountSid.Data[j]);
            HLOG_USER("\n");
        } else if(rec->Identity.Type == WINBIO_ID_TYPE_GUID) {
            HLOG_USER("    GUID=%08lx-%04x-%04x-",
                (unsigned long)rec->Identity.Value.TemplateGuid.Data1,
                rec->Identity.Value.TemplateGuid.Data2,
                rec->Identity.Value.TemplateGuid.Data3);
            for(int j=0;j<8;j++) HLOG_USER("%02x", rec->Identity.Value.TemplateGuid.Data4[j]);
            HLOG_USER("\n");
        } else {
            HLOG_USER("    IdentityValue=%lu\n", (unsigned long)rec->Identity.Value.Wildcard);
        }
        HLOG_USER("    TemplateBlobSize=%llu\n", (unsigned long long)rec->TemplateBlobSize);
        if(rec->TemplateBlobSize > 0) {
            SIZE_T showSize = rec->TemplateBlobSize < sizeof(rec->TemplateBlob) ? rec->TemplateBlobSize : sizeof(rec->TemplateBlob);
            HLOG_USER("    TemplateBlob[%zu]=", showSize);
            for(SIZE_T j=0;j<showSize;j++)
                HLOG_USER("%02x", rec->TemplateBlob[j]);
            HLOG_USER("\n");
        }
    }

    free(sbuf);
    free(rbuf);
}

void
clearDatabase()
{
    MyMem in(NULL, 0), out(NULL, 0);
    MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_ERASE_DATABASE, &out, &in);

    HLOG_USER("about to IOCTL_BIOMETRIC_ENGINE_ERASE_DATABASE (OnEraseDatabase)\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_ENGINE_ERASE_DATABASE, 0, 0);
    while(!req.complete)
        Sleep(200);

    HLOG_INFO("ERASE_DATABASE: hresult=0x%lx (%s)\r\n",
        (unsigned long)req.completionStatus, hresult_to_sting(req.completionStatus));
}

void
getSensorStatus()
{
    char buf[1024*10];
    WINBIO_DIAGNOSTICS *diag = (WINBIO_DIAGNOSTICS*)buf;

    MyMem in(NULL, 0), out(buf, sizeof(buf));
    MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_GET_SENSOR_STATUS, &out, &in);

    HLOG_USER("about to IOCTL_BIOMETRIC_GET_SENSOR_STATUS\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_GET_SENSOR_STATUS, 0, 0);
    while(!req.complete)
        Sleep(200);
    //Sleep(4000);
    //rc = myDevice->pnpcb->OnD0Entry(myDevice, WdfPowerDeviceInvalid);
    //Sleep(4000);
    IFLOG(1) {
        std::wcout
            << L"=======================" << std::endl
            << L"PayloadSize " << diag->PayloadSize << std::endl
            << L"WinBioHresult " << diag->WinBioHresult << std::endl
            << L"SensorStatus " << diag->SensorStatus << std::endl
            << L"VendorDiagnostics.Size " << diag->VendorDiagnostics.Size << std::endl
            << L"=======================" << std::endl;
    }

    if(FAILED(req.completionStatus) || req.informationSize < (LONG_PTR)sizeof(WINBIO_DIAGNOSTICS)) {
        HLOG_INFO("GET_SENSOR_STATUS returned unexpected payload: status=0x%lx (%s), infoSize=%lld\n",
            (unsigned long)req.completionStatus,
            hresult_to_sting(req.completionStatus),
            (long long)req.informationSize);
    }

}

void
resetIoctl()
{
    char buf[1024*10];
    WINBIO_BLANK_PAYLOAD *diag = (WINBIO_BLANK_PAYLOAD*)buf;

    MyMem in(NULL, 0), out(buf, sizeof(buf));
    MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_RESET, &out, &in);

    HLOG_USER("about to IOCTL_BIOMETRIC_RESET\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_RESET, 0, 0);
    while(!req.complete)
        Sleep(200);

    if(FAILED(req.completionStatus) || req.informationSize < (LONG_PTR)sizeof(WINBIO_BLANK_PAYLOAD)) {
        HLOG_DEBUG("RESET returned unexpected payload: status=0x%lx (%s), infoSize=%lld\n",
            (unsigned long)req.completionStatus,
            hresult_to_sting(req.completionStatus),
            (long long)req.informationSize);
        return;
    }

    IFLOG(1) {
        std::wcout
            << L"=======================" << std::endl
            << L"WinBioHresult " << diag->WinBioHresult << std::endl
            << L"=======================" << std::endl;
    }
}

void
getAttributes()
{
    char obuf[10*1024];
    WINBIO_SENSOR_ATTRIBUTES *attrs = (WINBIO_SENSOR_ATTRIBUTES*)obuf;
    MyMem in(NULL, 0), out(obuf, sizeof(obuf));
    MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_GET_ATTRIBUTES, &out, &in);

    HLOG_USER("about to IOCTL_BIOMETRIC_GET_ATTRIBUTES\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_GET_ATTRIBUTES, 0, 0);
    //Sleep(1000);
    //rc = myDevice->pnpcb->OnD0Entry(myDevice, WdfPowerDeviceInvalid);
    while(!req.complete)
        Sleep(200);

    if(FAILED(req.completionStatus) || req.informationSize < (LONG_PTR)offsetof(WINBIO_SENSOR_ATTRIBUTES, SupportedFormat)) {
        HLOG_INFO("GET_ATTRIBUTES returned unexpected payload: status=0x%lx (%s), infoSize=%lld\n",
            (unsigned long)req.completionStatus,
            hresult_to_sting(req.completionStatus),
            (long long)req.informationSize);
        return;
    }

    SIZE_T attrsFixedSize = offsetof(WINBIO_SENSOR_ATTRIBUTES, SupportedFormat);
    SIZE_T attrsPayloadSize = clampInfoSize(req.informationSize, sizeof(obuf));
    SIZE_T attrsFormatsCapacity = 0;
    if(attrsPayloadSize > attrsFixedSize)
        attrsFormatsCapacity = (attrsPayloadSize - attrsFixedSize) / sizeof(WINBIO_REGISTERED_FORMAT);
    ULONG attrsFormatsToPrint = attrs->SupportedFormatEntries;
    if(attrsFormatsToPrint > attrsFormatsCapacity)
        attrsFormatsToPrint = (ULONG)attrsFormatsCapacity;

    char capsStr[256];
    capabilities_to_string(attrs->Capabilities, capsStr, sizeof(capsStr));

    HLOG_USER("=======================\n");
    HLOG_USER("  WinBioHresult:  0x%08lx (%s)\n",
        (unsigned long)attrs->WinBioHresult,
        hresult_to_sting(attrs->WinBioHresult));
    HLOG_USER("  PayloadSize:    %lu\n", (unsigned long)attrs->PayloadSize);
    HLOG_USER("  Manufacturer:   %ls\n", (wchar_t*)attrs->ManufacturerName);
    HLOG_USER("  Model:          %ls\n", (wchar_t*)attrs->ModelName);
    HLOG_USER("  SensorType:     0x%08lx (%s)\n",
        (unsigned long)attrs->SensorType,
        biometric_type_to_string(attrs->SensorType));
    HLOG_USER("  SensorSubType:  0x%08lx (%s)\n",
        (unsigned long)attrs->SensorSubType,
        sensor_subtype_to_string(attrs->SensorSubType));
    HLOG_USER("  Capabilities:   0x%08lx (%s)\n",
        (unsigned long)attrs->Capabilities, capsStr);
    HLOG_USER("  SerialNumber:   %ls\n", (wchar_t*)attrs->SerialNumber);
    HLOG_USER("  Firmware:       %lu.%lu\n",
        (unsigned long)attrs->FirmwareVersion.MajorVersion,
        (unsigned long)attrs->FirmwareVersion.MinorVersion);
    HLOG_USER("  FormatEntries:  %lu\n", (unsigned long)attrs->SupportedFormatEntries);
    for(ULONG i=0;i<attrsFormatsToPrint;i++) {
        HLOG_USER("    [%lu] Owner=0x%04x Type=0x%04x\n",
            (unsigned long)i,
            attrs->SupportedFormat[i].Owner,
            attrs->SupportedFormat[i].Type);
    }
    if(attrsFormatsToPrint != attrs->SupportedFormatEntries) {
        HLOG_USER("  NOTE: truncated SupportedFormatEntries to %lu based on infoSize\n",
            (unsigned long)attrsFormatsToPrint);
    }
    HLOG_USER("=======================\n");
}

void
setMode(WINBIO_SENSOR_MODE mode)
{
    uint32_t ibuf[2] = { mode, 2 };

    MyMem in((unsigned char*)ibuf, sizeof(ibuf)), out(NULL, 0);
    // 0x44204C has no handler in driver dispatch - falls to OnControlUnit (E_NOTIMPL)
    MyRequest req(WdfRequestOther, 0x44204C, &out, &in);

    HLOG_USER("about to setMode (0x44204C - no handler)\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, 0x44204C, 0, 0);
    while(!req.complete)
        Sleep(200);
    HLOG_INFO("setMode complete: hresult=0x%lx (%s), infoSize=%lld\n",
        (unsigned long)req.completionStatus,
        hresult_to_sting(req.completionStatus),
        (long long)req.informationSize);
}

void
deleteRecord(DWORD subfactor)
{
    // DELETE_RECORD: driver expects WDF in/out. Buffer layout:
    //   [0x00] WINBIO_IDENTITY (0x4c bytes): Type=2/3 identity for matching
    //   [0x4c] UCHAR SubFactor
    //   [0x4d] UCHAR Reserved[3]
    //   wire total = 0x50 bytes
    // Type=3 with Wildcard=0 matches all records with given subfactor
    {
        typedef struct _SYNA_DELETE_RECORD_WIRE {
            WINBIO_IDENTITY Identity;
            UCHAR SubFactor;
            UCHAR Reserved[3];
        } SYNA_DELETE_RECORD_WIRE;
        static_assert(sizeof(SYNA_DELETE_RECORD_WIRE) == 0x50, "DeleteRecord wire must be 0x50");

        SYNA_DELETE_RECORD_WIRE wireBuf = {0};
        wireBuf.Identity.Type = WINBIO_ID_TYPE_WILDCARD;
        wireBuf.Identity.Value.Wildcard = WINBIO_IDENTITY_WILDCARD;
        wireBuf.SubFactor = (UCHAR)subfactor;

        WINBIO_BLANK_PAYLOAD obuf = {0};
        MyMem in((UCHAR*)&wireBuf, sizeof(wireBuf)), out((UCHAR*)&obuf, sizeof(obuf));
        MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_STORAGE_DELETE_RECORD, &out, &in);

        HLOG_USER("about to IOCTL_BIOMETRIC_STORAGE_DELETE_RECORD (Type=%lu, Wildcard=%lu, subfactor=%u)\r\n",
            (unsigned long)wireBuf.Identity.Type,
            (unsigned long)wireBuf.Identity.Value.Wildcard,
            (unsigned)wireBuf.SubFactor);
        myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_STORAGE_DELETE_RECORD, 0, 0);
        while(!req.complete)
            Sleep(200);

        HLOG_USER("DELETE_RECORD: hresult=0x%lx (%s)\r\n",
            (unsigned long)req.completionStatus, hresult_to_sting(req.completionStatus));
        HLOG_DEBUG("  PayloadSize=%lu WinBioHresult=0x%lx (%s)\n",
            obuf.PayloadSize, (unsigned long)obuf.WinBioHresult,
            hresult_to_sting(obuf.WinBioHresult));
    }
}

void
discardEnrollment()
{
    MyMem in(NULL, 0), out(NULL, 0);
    MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_ENGINE_DISCARD_ENROLLMENT, &out, &in);

    HLOG_USER("about to IOCTL_BIOMETRIC_ENGINE_DISCARD_ENROLLMENT\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_ENGINE_DISCARD_ENROLLMENT, 0, 0);
    while(!req.complete)
        Sleep(200);

    HLOG_INFO("DISCARD_ENROLLMENT: hresult=0x%lx (%s), infoSize=%lld\n",
        (unsigned long)req.completionStatus,
        hresult_to_sting(req.completionStatus),
        (long long)req.informationSize);
}

void
setIndicator(WINBIO_INDICATOR_STATUS status)
{
    WINBIO_SET_INDICATOR setInd;
    setInd.PayloadSize = sizeof(setInd);
    setInd.IndicatorStatus = status;
    WINBIO_GET_INDICATOR getInd = {0};
    MyMem in((UCHAR*)&setInd, sizeof(setInd)), out((UCHAR*)&getInd, sizeof(getInd));
    MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_SET_INDICATOR, &out, &in);

    HLOG_USER("about to IOCTL_BIOMETRIC_SET_INDICATOR (SensorAdapterSetIndicatorStatus, status=%s)\r\n",
        status == WINBIO_INDICATOR_ON ? "WINBIO_INDICATOR_ON" : "WINBIO_INDICATOR_OFF");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_SET_INDICATOR, 0, 0);
    while(!req.complete)
        Sleep(200);

    if(req.informationSize >= (LONG_PTR)sizeof(getInd)) {
        HLOG_INFO("SET_INDICATOR: hresult=0x%lx (%s), getInd.WinBioHresult=0x%lx, getInd.IndicatorStatus=%lu\r\n",
            (unsigned long)req.completionStatus, hresult_to_sting(req.completionStatus),
            (unsigned long)getInd.WinBioHresult, (unsigned long)getInd.IndicatorStatus);
    }
    else {
        HLOG_INFO("SET_INDICATOR: hresult=0x%lx (%s), short output infoSize=%lld\r\n",
            (unsigned long)req.completionStatus,
            hresult_to_sting(req.completionStatus),
            (long long)req.informationSize);
    }
}

void
getIndicator()
{
    WINBIO_GET_INDICATOR getInd = {0};
    MyMem in(NULL, 0), out((UCHAR*)&getInd, sizeof(getInd));
    MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_GET_INDICATOR, &out, &in);

    HLOG_USER("about to IOCTL_BIOMETRIC_GET_INDICATOR (SensorAdapterGetIndicatorStatus)\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_GET_INDICATOR, 0, 0);
    while(!req.complete)
        Sleep(200);

    if(req.informationSize >= (LONG_PTR)sizeof(getInd)) {
        HLOG_INFO("GET_INDICATOR: hresult=0x%lx (%s), WinBioHresult=0x%lx, IndicatorStatus=%lu\r\n",
            (unsigned long)req.completionStatus, hresult_to_sting(req.completionStatus),
            (unsigned long)getInd.WinBioHresult, (unsigned long)getInd.IndicatorStatus);
    }
    else {
        HLOG_INFO("GET_INDICATOR: hresult=0x%lx (%s), short output infoSize=%lld\r\n",
            (unsigned long)req.completionStatus,
            hresult_to_sting(req.completionStatus),
            (long long)req.informationSize);
    }
}

void
getDatabaseSize()
{
    UCHAR ibuf[8] = {0};
    SIZE_T recordCount = 0;
    MyMem in(ibuf, sizeof(ibuf)), out((UCHAR *)&recordCount, sizeof(recordCount));
    MyRequest req(WdfRequestOther, IOCTL_BIOMETRIC_STORAGE_GET_RECORD_COUNT, &out, &in);

    HLOG_USER("about to IOCTL_BIOMETRIC_STORAGE_GET_RECORD_COUNT\r\n");
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, IOCTL_BIOMETRIC_STORAGE_GET_RECORD_COUNT, 0, 0);
    while(!req.complete)
        Sleep(200);

    HLOG_INFO("GET_RECORD_COUNT: hresult=0x%lx (%s), infoSize=%lld, count=%zu\n",
        (unsigned long)req.completionStatus,
        hresult_to_sting(req.completionStatus),
        (long long)req.informationSize,
        recordCount);
}

void
blah()
{
    puts("blah");
}

void
handle_blah(_EXCEPTION_POINTERS *ExceptionInfo)
{
    HLOG_USER("Yay! Breakpoints work\n");
}

void
handle_trace(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;

    HLOG_TRACE("Trace: %llx:%llx\n", (unsigned long long)ctx->Rcx, (unsigned long long)ctx->Rdx);
}

void
handle_reset_calib_data_and_calibrate(_EXCEPTION_POINTERS *ExceptionInfo)
{
    HLOG_TRACE("reset_calib_data_and_calibrate:\n");
    print_regs(ExceptionInfo);
}

void
handle_calibrate_iteration(_EXCEPTION_POINTERS *ExceptionInfo)
{
    HLOG_DEBUG("==========================================================================================\n");
    HLOG_TRACE("                          PHASE %llu\n", (unsigned long long)ExceptionInfo->ContextRecord->Rdx);
    HLOG_DEBUG("==========================================================================================\n");
}

const uint8_t target[] = {
//0x4e, 0x00, 0x28, 0x00, 0xfb, 0xb2, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x30, 0x00, 0x00, 0x00, 0x87, 0x00, 0x02, 0x00, 0x67, 0x00, 0x0a, 0x00, 0x01, 0x80, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00, 0x0b, 0x19, 0x00, 0x00, 0x88, 0x13, 0xb8, 0x0b, 0x01, 0x09, 0x10, 0x00,
//0x17, 0x00, 0x00, 0x00,
'n', 0x23, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08, 0x00, 0x00, 0x20, 0x00, 0x80, 0x00, 0x00, 0x01, 0x00, 0x32, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x80, 0x20, 0x20, 0x04, 0x00, 0x24, 0x20, 0x00, 0x00, 0x50, 0x20, 0x77, 0x36, 0x28, 0x20, 0x01, 0x00, 0x30, 0x20, 0x01, 0x00, 0x3c, 0x20, 0x80, 0x00, 0x08, 0x21, 0x38, 0x00, 0x0c, 0x21, 0x00, 0x00, 0x48, 0x21, 0x07, 0x00, 0x4c, 0x21, 0x00, 0x00, 0x58, 0x20, 0x00, 0x00, 0x5c, 0x20, 0x00, 0x00, 0x60, 0x20,
};


void
handle_malloc(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    uint64_t *rsp = (uint64_t *)ctx->Rsp;
    uint8_t *rax = (uint8_t *)ctx->Rax;
    uint32_t len = (uint32_t)rsp[5+1];
    size_t i;

    HLOG_TRACE("malloc %u: %p\n", len, rax);
    if(len == 13440) {

        for(i=0;i<40;i++) {
            HLOG_DEBUG("    %016llx\n", rsp[i]);
        }
    }

    if(len == 728) {
        HLOG_USER("Allocating BiometricDevice!\n");
    }
}

void
handle_memmove(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    uint64_t *rsp = (uint64_t *)ctx->Rsp;
    uint8_t *dst = (uint8_t*)rsp[1+5];
    uint8_t *src = (uint8_t*)rsp[2+5];
    size_t len = (uint32_t)rsp[3+5];
    //uint8_t *src = (uint8_t*)ctx->Rdx;
    //uint8_t *dst = (uint8_t*)ctx->Rcx;
    //size_t len = ctx->R8;
    size_t i;

    HLOG_TRACE("memmove %p -> %p (%lld): ", src, dst, len);
    for(i=0;i<len;i++)
        HLOG_DEBUG("%02x", src[i]);
    puts("");

    if(len >= sizeof(target) && memcmp(src, target, sizeof(target)) == 0) {
        for(i=0;i<40;i++) {
            HLOG_DEBUG("    %016llx\n", rsp[i]);
        }
    }
}

void
handle_x(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    uint8_t *src = (uint8_t*)ctx->Rcx;
    int i;

    HLOG_TRACE("set sensor type before: ");
    for(i=0;i<0x40;i++)
        HLOG_DEBUG("%02x", src[i]);
    puts("");
}

void
handle_x_end(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    uint64_t *rsp = (uint64_t *)ctx->Rsp;
    uint8_t *src;
    int i;

    //print_regs(ExceptionInfo);
    rsp += 0x78/8;
    HLOG_TRACE("arg_0=%016llx\n", rsp[0x8/8]);
    HLOG_TRACE("arg_8=%016llx\n", rsp[0x10/8]);
    HLOG_TRACE("arg_10=%016llx\n", rsp[0x18/8]);
    HLOG_TRACE("arg_18=%016llxd\n", rsp[0x20/8]);

    src = (uint8_t *)rsp[0x8/8];
    HLOG_TRACE("set sensor type after: ");
    for(i=0;i<0x40;i++)
        HLOG_DEBUG("%02x", src[i]);
    puts("");
}

void
print_biometric_device(uint64_t *rcx)
{
    size_t i, j;

    HLOG_TRACE("Biometric device: %p\n", rcx);
    for(i=0;i<140;i++) {
        HLOG_TRACE("    %04llx: 0x%016llx\n", i*8, rcx[i]);
        if(i*8 == 0x28) { // device/fw info (as returned by cmd_01)
            uint64_t *f28 = (uint64_t *)rcx[i];
            for(j=0;j<10;j++) {
                HLOG_TRACE("        %04llx: 0x%016llx\n", j*8, f28[j]);
            }
        }

        if(i*8 == 0x288) { // calibration info
            uint64_t *f28 = (uint64_t *)rcx[i];
            for(j=0;j<40;j++) {
                HLOG_TRACE("        %04llx: 0x%016llx\n", j*8, f28[j]);
                if(j*8 == 0x80 && f28[j]) {
                    uint8_t *cal_blob = (uint8_t *)f28[j];
                    int k;
                    HLOG_TRACE("            Calibration blob: ");
                    for(k=0;k<0x80;k++) {
                        HLOG_DEBUG("%02x", cal_blob[k]);
                    }
                    HLOG_TRACE("...\n");
                }

                if(j*8 == 0x68 && f28[j]) {
                    uint8_t *cal_blob = (uint8_t *)f28[j];
                    int k;
                    HLOG_TRACE("            field_68: ");
                    for(k=0;k<0x80;k++) {
                        HLOG_DEBUG("%02x", cal_blob[k]);
                    }
                    HLOG_TRACE("...\n");
                }

                if(j*8 == 0x98 && f28[j]) {
                    uint8_t *cal_blob = (uint8_t *)f28[j];
                    int k;
                    HLOG_TRACE("            Calibration blob2: ");
                    for(k=0;k<0x80;k++) {
                        HLOG_DEBUG("%02x", cal_blob[k]);
                    }
                    HLOG_TRACE("...\n");
            }
        }
    }

}
}

void
handle_line_update(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    (void)ctx;
    uint64_t *rcx = (uint64_t *)ctx->Rcx;

    //print_regs(ExceptionInfo);
    print_biometric_device(rcx);
}

void
pp(uint64_t *tmp)
{
    HLOG_DEBUG(" %016llx %016llx\n", tmp[0], tmp[1]);
}

void
handle_create_line_transform_segment(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    uint64_t *rsp = (uint64_t *)ctx->Rsp;
    size_t i;

    pp((uint64_t *)ctx->Rcx);
    pp((uint64_t *)ctx->Rdx);
    pp((uint64_t *)ctx->R8);
    pp((uint64_t *)ctx->R9);
    pp((uint64_t *)rsp[6]);
    pp((uint64_t *)rsp[7]);

    print_regs(ExceptionInfo);
    for(i=0;i<40;i++) {
        HLOG_DEBUG("    %016llx\n", rsp[i]);
    }
}

void
handle_z(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    uint8_t *src = (uint8_t*)ctx->Rax;
    int i;

    print_regs(ExceptionInfo);
    HLOG_TRACE("z: ");
    for(i=0;i<0x20;i++)
        HLOG_DEBUG("%02x", src[i]);
    puts("");
}

void
handle_avg(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    // 58h
    uint64_t *rsp = (uint64_t *)ctx->Rsp;
    uint8_t *src = (uint8_t *)rsp[(0x58+0x10)/8];
    uint64_t *dst_struct = (uint64_t *)rsp[(0x58+0x30)/8];
    uint8_t *dst = (uint8_t *)dst_struct[0x10/8];
    int i;

    print_regs(ExceptionInfo);
    HLOG_TRACE("In: ");
    for(i=0;i<0x200;i++)
        HLOG_DEBUG("%02x", src[i]);
    puts("");
    HLOG_TRACE("Out: ");
    for(i=0;i<0x200;i++)
        HLOG_DEBUG("%02x", dst[i]);
    puts("");
}

void
handle_scale_calibration_buffer_start(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    uint64_t *biometricDevice = *(uint64_t **)ctx->Rcx;
    uint64_t *calib_results;
    uint8_t *src;
    int i;

    calib_results= biometricDevice + 0xd8/8;
    src = (uint8_t *)calib_results[0x10/8];
    if(src) {
        HLOG_TRACE("In: ");
        for(i=0;i<0x200;i++)
            HLOG_DEBUG("%02x", src[i]);
        puts("");
    }
}

void
handle_scale_calibration_buffer_end(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    uint64_t *biometricDevice;
    uint64_t *rsp = (uint64_t *)ctx->Rsp;
    uint64_t *calib_results, *calib_info;
    uint8_t *src, *dst;
    int i;

    rsp += 0xc8/8;
    HLOG_TRACE("arg_28=%d\n", (uint16_t)rsp[0x30/8]);
    HLOG_TRACE("arg_8=%d\n", (uint16_t)rsp[0x10/8]);
    HLOG_TRACE("arg_10=%d\n", (uint16_t)rsp[0x18/8]);

    biometricDevice = (uint64_t *)rsp[8/8];
    if(biometricDevice) {
        biometricDevice = (uint64_t *)*biometricDevice;
        calib_results= biometricDevice + 0xd8/8;
        src = (uint8_t *)calib_results[0x10/8];
        if(src) {
            HLOG_TRACE("In: ");
            for(i=0;i<0x200;i++)
                HLOG_DEBUG("%02x", src[i]);
            puts("");
        }

        calib_info = (uint64_t *)biometricDevice[0x288/8];
        dst = (uint8_t *)calib_info[0x80/8];
        HLOG_TRACE("Out: ");
        for(i=0;i<0x200;i++)
            HLOG_DEBUG("%02x", dst[i]);
        puts("");
    }
}

void
handle_sub_180067360(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    uint64_t *biometricDevice;
    uint64_t *rsp = (uint64_t *)ctx->Rsp;
    uint64_t *calib_results, *calib_info;
    uint8_t *src, *dst;
    int i;

    print_regs(ExceptionInfo);
    rsp += 0x58/8;
    HLOG_TRACE("arg_0=%016llx\n", rsp[0x8/8]);
    HLOG_TRACE("arg_8=%016llx\n", rsp[0x10/8]);
    HLOG_TRACE("arg_10=%016llx\n", rsp[0x18/8]);
    HLOG_TRACE("arg_18=%016llxd\n", rsp[0x20/8]);

    biometricDevice = (uint64_t *)rsp[8/8];
    if(biometricDevice) {
        biometricDevice = (uint64_t *)*biometricDevice;
        if(!biometricDevice)
            puts("biometricDevice is null");
        calib_results= biometricDevice + 0xd8/8;
        src = (uint8_t *)calib_results[0x10/8];
        if(src) {
            HLOG_TRACE("Avg: ");
            for(i=0;i<0x200;i++)
                HLOG_DEBUG("%02x", src[i]);
            puts("");
        }

        calib_info = (uint64_t *)biometricDevice[0x288/8];
        if(calib_info) {
            dst = (uint8_t *)calib_info[0x80/8];
            if(dst) {
                HLOG_DEBUG("Line Update Info > calibration blob: ");
                for(i=0;i<0x200;i++)
                    HLOG_DEBUG("%02x", dst[i]);
                puts("");
            }
        }
    }
}

void
handle_hack_timeslot_table_for_regwrite_8000203c(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    uint64_t **rcx = (uint64_t **)ctx->Rcx;

    print_biometric_device(*rcx);
}

void
print_axbuf(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    uint8_t *rax= (uint8_t *)ctx->Rax;
    int i;

    HLOG_TRACE("rax: ");
    for(i=0;i<0x20;i++)
        HLOG_DEBUG("%02x", rax[i]);
    puts("");
}

void
print_cxbuf(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    uint8_t *rcx= (uint8_t *)ctx->Rcx;
    int i;

    print_regs(ExceptionInfo);
    HLOG_TRACE("rcx: ");
    for(i=0;i<0x400;i++)
        HLOG_DEBUG("%02x", rcx[i]);
    puts("");
}


uint8_t *tout;
uint32_t *tsize;

void
handle_export_in(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    (void)ctx;
    tout = (uint8_t *)ctx->R8;
    tsize = (uint32_t *)ctx->R9;

    print_regs(ExceptionInfo);
}


void
handle_export_out(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    (void)ctx;
    uint32_t i;

    if(!tout || !tsize)
        return;

    print_regs(ExceptionInfo);
    HLOG_TRACE("tout: ");
    for(i=0;i<*tsize;i++)
        HLOG_DEBUG("%02x", tout[i]);
    puts("");
}


void
handle_new_biodev(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;

    print_regs(ExceptionInfo);
    ctx->Dr0 = ctx->Rax+0x128; // bytes per line
    ctx->Dr7 = (1 << 0) | (1 << 16) | (3 << 18);
    HLOG_TRACE("hw breakpoint set to %016llx\n", ctx->Dr0);
}

void
handle_lookup_capture_blob(_EXCEPTION_POINTERS *ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    uint64_t *rsp = (uint64_t *)ctx->Rsp;
    int i;

    print_regs(ExceptionInfo);
    rsp += 0x98/8;
    for(i=0;i<10;i++) {
        HLOG_TRACE("arg_%x=%016llx\n", i*8, rsp[i+1]);
    }
}


struct breakpoint breakpoints_0097[] = {
    { "blah", (unsigned char *)blah, handle_blah },
    { NULL, (unsigned char *)0x1800409B0, handle_trace },
    { "handle_reset_calib_data_and_calibrate", (unsigned char *)0x18005FD40, handle_reset_calib_data_and_calibrate },
    { "handle_calibrate_iteration", (unsigned char *)0x000000018006DF20, handle_calibrate_iteration },
    { NULL, (unsigned char *)0x000000018003E6F9, handle_memmove },
    { "handle_line_update", (unsigned char *)0x000000018008F950, handle_line_update},
    { "print_regs", (unsigned char *)0x000000018009D2D4, print_regs },
    { "z", (unsigned char *)0x000000018008E326, handle_z },
    { NULL,(unsigned char *)0x000000018003E623, handle_malloc },
    { "handle_avg", (unsigned char *)0x0000000180093FC8, handle_avg },
    { "handle_scale_calibration_buffer_start", (unsigned char *)0x0000000180071AC0, handle_scale_calibration_buffer_start }, // scale_calibration_buffer
    { "handle_scale_calibration_buffer_end", (unsigned char *)0x00000001800723F9, handle_scale_calibration_buffer_end }, // scale_calibration_buffer
    { "scale_calibration_buffer", (unsigned char *)0x00000001800746B0, print_regs }, // subfunction of scale_calibration_buffer
    { "handle_sub_180067360_start", (unsigned char *)0x0000000180067377, handle_sub_180067360 }, // called from scale_calibration_buffer 3 times
    { "handle_sub_180067360_end", (unsigned char *)0x0000000180067597, handle_sub_180067360 }, // called from scale_calibration_buffer 3 times
    { "hack_timeslot_table_for_regwrite_8000203c", (unsigned char *)0x0000000180087540, handle_hack_timeslot_table_for_regwrite_8000203c},
    { "maybe set sensor type", (unsigned char *)0x0000000180066AAE, print_regs },
    { "00000001800666B0 start", (unsigned char *)0x00000001800666B0, handle_x }, // sets the sensor type from arg0+0x10
    { "00000001800666B0 end", (unsigned char *)0x0000000180066AC2, handle_x_end }, // sets the sensor type from arg0+0x10
    { "bytes per line", (unsigned char *)0x000000018007F94F, print_regs },
    { "bytes per line 2", (unsigned char *)0x000000018007F93A, print_axbuf },
    { "new BiometricDevice, after memset", (unsigned char *)0x000000018007EE83, handle_new_biodev },
    { "lookup capture blob", (unsigned char *)0x0000000180094B8A, handle_lookup_capture_blob },
    //{ "avg, no overscan", (unsigned char *)0x0000000180093EB7, handle_avg_overscan },
    { 0 }
};

struct breakpoint breakpoints[] = {
    { "CeivMode::IdentifyUserStorageOnFlash", (unsigned char *)0x0000000180017531, print_regs },
    /*
    { "create_MVWT", (unsigned char *)0x00000001800D7886, print_cxbuf },
    { "00000001800E1330", (unsigned char *)0x00000001800E1330, print_cxbuf },
    { "00000001800F5B73", (unsigned char *)0x00000001800F5B73, print_regs },
    { "00000001800FA054", (unsigned char *)0x00000001800FA054, print_regs },
    { "00000001800F71A2", (unsigned char *)0x00000001800F71A2, print_regs },
    */
    { "00000001800D8C24", (unsigned char *)0x00000001800D8C24, handle_export_in },
    { "00000001800D8C34", (unsigned char *)0x00000001800D8C34, handle_export_out },
};

void
nop()
{
}

static bool
parseInfFile(const char *infPath, GUID *clsid, char *dllName, size_t dllNameSize)
{
    FILE *f = fopen(infPath, "r");
    if(!f) {
        HLOG_USER("Failed to open INF: %s\n", infPath);
        return false;
    }
    char line[512];
    char installSection[64] = "";
    bool inWdfSection = false;

    // First pass: find the first [*.Wdf] section with an UmdfService= line
    // and extract the install section name after the comma.
    while(fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while(len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
        if(len == 0 || line[0] == ';')
            continue;
        if(line[0] == '[') {
            inWdfSection = (strstr(line, ".Wdf]") != NULL);
            continue;
        }
        if(!inWdfSection)
            continue;
        if(strncmp(line, "UmdfService=", 12) != 0)
            continue;
        // Extract the install section name (after the comma)
        char *comma = strchr(line + 12, ',');
        if(!comma)
            continue;
        char *sec = comma + 1;
        while(*sec == ' ' || *sec == '\t') sec++;
        char *s = sec;
        while(*s && *s != ' ' && *s != '\t') s++;
        *s = '\0';
        strncpy(installSection, sec, sizeof(installSection) - 1);
        installSection[sizeof(installSection) - 1] = '\0';
        break;
    }
    if(installSection[0] == '\0') {
        HLOG_USER("INF has no [*.Wdf]/UmdfService entry\n");
        fclose(f);
        return false;
    }
    HLOG_USER("Found install section: %s\n", installSection);

    // Second pass: find the install section and extract DriverCLSID / ServiceBinary
    char targetSection[72];
    snprintf(targetSection, sizeof(targetSection), "[%s]", installSection);
    bool inTarget = false;
    bool foundClsid = false;
    bool foundDll = false;
    rewind(f);
    while(fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while(len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' || line[len-1] == ' ' || line[len-1] == '\t'))
            line[--len] = '\0';
        if(len == 0 || line[0] == ';')
            continue;
        if(line[0] == '[') {
            inTarget = (strcmp(line, targetSection) == 0);
            continue;
        }
        if(!inTarget)
            continue;
        char *eq = strchr(line, '=');
        if(!eq)
            continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        while(*key == ' ' || *key == '\t') key++;
        char *kend = key + strlen(key) - 1;
        while(kend > key && (*kend == ' ' || *kend == '\t')) *kend-- = '\0';
        while(*val == ' ' || *val == '\t') val++;
        char *vend = val + strlen(val) - 1;
        while(vend > val && (*vend == ' ' || *vend == '\t' || *vend == '"')) *vend-- = '\0';
        if(val[0] == '"') val++;
        if(strcmp(key, "DriverCLSID") == 0) {
            unsigned d[11];
            if(sscanf(val, "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
                &d[0], &d[1], &d[2], &d[3], &d[4], &d[5], &d[6], &d[7], &d[8], &d[9], &d[10]) == 11) {
                clsid->Data1 = d[0];
                clsid->Data2 = (unsigned short)d[1];
                clsid->Data3 = (unsigned short)d[2];
                for(int i=0;i<8;i++) clsid->Data4[i] = (unsigned char)d[3+i];
                foundClsid = true;
            }
            if(!foundClsid) {
                HLOG_USER("Failed to parse DriverCLSID in [%s] (val='%s')\n", installSection, val);
                fclose(f);
                return false;
            }
        }
        if(strcmp(key, "ServiceBinary") == 0) {
            char *bs = strrchr(val, '\\');
            const char *fn = bs ? bs + 1 : val;
            strncpy(dllName, fn, dllNameSize - 1);
            dllName[dllNameSize - 1] = '\0';
            foundDll = true;
        }
        if(foundClsid && foundDll)
            break;
    }
    fclose(f);
    if(!foundClsid)
        HLOG_USER("INF missing DriverCLSID in [%s]\n", installSection);
    if(!foundDll)
        HLOG_USER("INF missing ServiceBinary in [%s]\n", installSection);
    return foundClsid && foundDll;
}

void
usage(const char *prog)
{
    printf("Usage: %s <nop|identify|enroll|set-led [on|off]|list-db|clear-db|delete-record|identify>\n", prog);
}


int
main(int argc, char *argv[])
{
    char *br = getenv("SANDBOX_BREAKPOINTS");
    void (*what)() = NULL;
    WINBIO_INDICATOR_STATUS ledState = WINBIO_INDICATOR_OFF;
    IClassFactory *fact = 0;

    if(argc < 2) {
        usage(argv[0]);
        return 3;
    }

    if(strcasecmp(argv[1], "identify") == 0) {
        what = identify;
    }
    else if(strcasecmp(argv[1], "enroll") == 0) {
        what = enroll;
    }
    else if(strcasecmp(argv[1], "set-led") == 0) {
        if(argc < 3 || (strcasecmp(argv[2], "on") != 0 && strcasecmp(argv[2], "off") != 0)) {
            printf("Usage: %s set-led <on|off>\n", argv[0]);
            return 3;
        }
        ledState = (strcasecmp(argv[2], "on") == 0) ? WINBIO_INDICATOR_ON : WINBIO_INDICATOR_OFF;
    }
    else if(strcasecmp(argv[1], "list-db") == 0) {
        what = listDatabase;
    }
    else if(strcasecmp(argv[1], "identify-all") == 0) {
        what = identifyAll;
    }
    else if(strcasecmp(argv[1], "identify") == 0) {
        what = identify;
    }
    else if(strcasecmp(argv[1], "clear-db") == 0) {
        what = clearDatabase;
    }
    else if(strcasecmp(argv[1], "delete-record") == 0) {
        if(argc < 3) {
            printf("Usage: %s delete-record <subfactor>\n", argv[0]);
            return 3;
        }
    }
    else if(strcasecmp(argv[1], "nop") == 0) {
        what = nop;
    }
    else if(strcasecmp(argv[1], "refresh-cache") == 0) {;
    }
    else {
        usage(argv[0]);
        return 3;
    }

    // EnumerateAllDevices();

    // HRESULT hr = S_OK;
    // BOOL    bResult;

    // typedef struct _DEVICE_DATA {
    //     BOOL                    HandlesOpen;
    //     WINUSB_INTERFACE_HANDLE WinusbHandle;
    //     HANDLE                  DeviceHandle;
    //     TCHAR                   DevicePath[MAX_PATH];

    // } DEVICE_DATA, *PDEVICE_DATA;

    // DEVICE_DATA dd;
    // PDEVICE_DATA DeviceData = &dd;
    // DeviceData->HandlesOpen = FALSE;

    // BOOL FailureDeviceNotFound;
    // hr = RetrieveDevicePath(DeviceData->DevicePath,
    //                         sizeof(DeviceData->DevicePath),
    //                         &FailureDeviceNotFound);
    // std::wcout << L"Checking for PATH " << hr << ", '"<<DeviceData->DevicePath<<"' not  found " << FailureDeviceNotFound << std::endl;

    // Load INF to get DriverCLSID and ServiceBinary DLL name
    char dllName[64];
    if(!parseInfFile(INF_FILE, &DriverCLSID, dllName, sizeof(dllName)))
        return 3;
    HLOG_USER("DriverCLSID loaded from %s, DLL=%s\n", INF_FILE, dllName);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/understanding-the-umdf-template-code-for-usb
    HMODULE pDll = LoadLibrary(dllName);
    if(!pDll) {
        HLOG_USER("Failed to LoadLibrary: %s\n", dllName);
        return 3;
    }
    DllGetClassObject_t *proc = (DllGetClassObject_t*)GetProcAddress(pDll, "DllGetClassObject");
    if(!proc) {
        printf("DllGetClassObject was not exported from %s\n", dllName);
        return 3;
    }
    HLOG_USER("creating factory\r\n");
    if(FAILED(proc(DriverCLSID, IID_IClassFactory, (LPVOID *)&fact))) {
        puts("DllGetClassObject failed");
        return 3;
    }
    HLOG_USER("factory=%p\r\n", fact);
    IDriverEntry *inst;
    fact->CreateInstance(NULL, IID_IDriverEntry, (LPVOID *)&inst);

    HRESULT rc;

    MyDriver *aDriver = new MyDriver();
    HLOG_USER(">>>>>>>>>>>>>>>>>>>>>>> about to init %p\r\n", aDriver);
    rc = inst->OnInitialize(aDriver);
    HLOG_USER("<<<<<<<<<<<<<<<<<<<<<<< OnInitialize rc = %lx (%s)\r\n",
        rc, hresult_to_sting(rc));
    if(rc < 0) {
        return 0;
    }
    Sleep(100);

    // Driver loaded, instument the code
    if(br && strcmp(br, "1") == 0) {
        set_bps(breakpoints);

        // Test breakpoints
        blah();
        blah();
    }

    MyDevInit *devinit = new MyDevInit();
    HLOG_USER(">>>>>>>>>>>>>>>>>>>>>>> about to add device %p\r\n", devinit);
    rc = inst->OnDeviceAdd(aDriver, devinit);
    HLOG_USER("<<<<<<<<<<<<<<<<<<<<<<< OnDeviceAdd rc = %lx (%s)\r\n",
        rc, hresult_to_sting(rc));
    if(rc < 0) {
        return 0;
    }

    goIdle = 0;

    Sleep(100);
    HLOG_USER(">>>>>>>>>>>>>>>>>>>>>>> about to prepare hw\r\n");
    if (myDevice->pnphwcb)
        rc = myDevice->pnphwcb->OnPrepareHardware(myDevice);
    else if (myDevice->pnphwcb2) {
        auto raw_resources = new MyResourceList("raw");
        auto translated_resources = new MyResourceList("translated");
        rc = myDevice->pnphwcb2->OnPrepareHardware(myDevice, raw_resources, translated_resources);
    }
    else
        assert(false);

    HLOG_USER("<<<<<<<<<<<<<<<<<<<<<<< OnPrepareHardware rc = %lx (%s)\r\n",
        rc, hresult_to_sting(rc));

    if(rc < 0) {
        return 1;
    }

    Sleep(100);
    HLOG_USER(">>>>>>>>>>>>>>>>>>>>>>> about to enter D0 state\r\n");
    rc = myDevice->pnpcb->OnD0Entry(myDevice, WdfPowerDeviceInvalid);
    HLOG_USER("<<<<<<<<<<<<<<<<<<<<<<< OnD0Entry rc = %lx (%s)\r\n", rc,
        hresult_to_sting(rc));

    if(rc < 0) {
        return 1;
    }

    puts("All done, sleeping a bit");
    while(!goIdle) {
      Sleep(200);
    }

    Sleep(1000);

    getAttributes();

    if(strcasecmp(argv[1], "set-led") == 0) {
        setLed(ledState);
    }
    else if(strcasecmp(argv[1], "delete-record") == 0) {
        deleteRecord((DWORD)atoi(argv[2]));
        listDatabase();
    }
    else if(what) {
        what();
    }

    HLOG_USER(">>>>>>>>>>>>>>>>>>>>>>> about to release hw\r\n");
    if (myDevice->pnphwcb)
        rc = myDevice->pnphwcb->OnReleaseHardware(myDevice);
    else if (myDevice->pnphwcb2) {
        auto translated_resources = new MyResourceList("translated");
        rc = myDevice->pnphwcb2->OnReleaseHardware(myDevice, translated_resources);
    } else
        assert(false);
    HLOG_USER("<<<<<<<<<<<<<<<<<<<<<<< OnReleaseHardware rc = %lx (%s)\r\n",
        rc, hresult_to_sting(rc));

    if(rc < 0) {
        return 1;
    }

    return 0;
}
