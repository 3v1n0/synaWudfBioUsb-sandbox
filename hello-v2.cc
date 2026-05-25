/*
 * hello-v2.cc — UMDF v2 driver hosting logic.
 *
 * Included directly from hello.cc (unity build) so it shares all types,
 * globals and helper functions without additional headers.
 * Called when umdfMajorVersion == 2.
 */

static int
hello_v2_main(int argc, char *argv[], HMODULE pDll,
              WINBIO_INDICATOR_STATUS ledState, const char *dllPath)
{
    PFN_FxDriverEntryUm fxEntry =
        (PFN_FxDriverEntryUm)GetProcAddress(pDll, "FxDriverEntryUm");
    if (!fxEntry) {
        HLOG_USER("FxDriverEntryUm not exported from %s\n", dllPath);
        return 3;
    }

    WUDF_LOADER_INTERFACE loaderIface = {};
    loaderIface.Size        = sizeof(WUDF_LOADER_INTERFACE); // 0x38
    loaderIface.BindClient  = (void*)host_BindClient;   // +0x08: called as BindClient(versionBind,bindInfo,ppGlobals)
    loaderIface.VersionBind = (void*)host_VersionBind;  // +0x18

    { const char *lv = getenv("WDF2_LOGLEVEL"); if (lv) g_umdf2_loglevel = atoi(lv); }
    HLOG_USER(">>> calling FxDriverEntryUm (WDF2_LOGLEVEL=%d)\n", g_umdf2_loglevel);
    NTSTATUS hr = fxEntry(&loaderIface, (void*)host_VersionBind, nullptr, nullptr);
    HLOG_USER("<<< FxDriverEntryUm -> 0x%lx\n", (long)hr);
    if (hr < 0) {
        HLOG_USER("FxDriverEntryUm failed: 0x%lx\n", (long)hr);
        return 3;
    }

    if (!g_wdf2Driver || !g_wdf2Driver->evtDeviceAdd) {
        HLOG_USER("no EvtDriverDeviceAdd after FxDriverEntryUm\n");
        return 3;
    }

    // Call EvtDriverDeviceAdd — driver calls WdfDeviceCreate / WdfIoQueueCreate
    auto *devInit = new Wdf2DeviceInit();
    HLOG_USER(">>> calling EvtDriverDeviceAdd\n");
    hr = g_wdf2Driver->evtDeviceAdd(g_wdf2Driver, devInit);
    HLOG_USER("<<< EvtDriverDeviceAdd -> 0x%lx\n", (long)hr);
    if (hr < 0) {
        HLOG_USER("EvtDriverDeviceAdd failed: 0x%lx\n", (long)hr);
        return 3;
    }

    if (!g_wdf2Device) {
        HLOG_USER("no Wdf2Device after EvtDriverDeviceAdd\n");
        return 3;
    }

    // Call EvtDevicePrepareHardware (with empty/NULL resource lists)
    auto *prepHw = g_wdf2Device->EvtPrepareHw();
    if (prepHw) {
        HLOG_USER(">>> calling EvtDevicePrepareHardware\n");
        hr = prepHw(g_wdf2Device, nullptr, nullptr);
        HLOG_USER("<<< EvtDevicePrepareHardware -> 0x%lx\n", (long)hr);
    }

    // Call EvtDeviceD0Entry
    auto *d0entry = g_wdf2Device->EvtD0Entry();
    if (d0entry && hr >= 0) {
        HLOG_USER(">>> calling EvtDeviceD0Entry\n");
        hr = d0entry(g_wdf2Device, 0 /* WdfPowerDeviceD3Final */);
        HLOG_USER("<<< EvtDeviceD0Entry -> 0x%lx\n", (long)hr);
    }

    if (strcasecmp(argv[1], "nop") == 0) {
        HLOG_USER("nop done (WDF v2)\n");
        return 0;
    }

    // v2 IOCTL helper — synchronous dispatch through EvtIoDeviceControl
    auto v2ioctl = [](ULONG code,
                      const void *in,  size_t inLen,
                      void       *out, size_t outLen,
                      ULONG_PTR  *pInfo = nullptr) -> NTSTATUS {
        ULONG_PTR info = 0;
        NTSTATUS s = wdf2_dispatch_ioctl(code, in, inLen, out, outLen, &info);
        if (pInfo) *pInfo = info;
        HLOG_USER("[v2] ioctl 0x%08lx -> 0x%lx (info=%zu)\n",
                  (unsigned long)code, (unsigned long)s, (size_t)info);
        return s;
    };

    if (strcasecmp(argv[1], "list-db") == 0) {
        uint64_t ibuf_rc = 0;
        SIZE_T recordCount = 0;
        NTSTATUS s = v2ioctl(IOCTL_BIOMETRIC_STORAGE_GET_RECORD_COUNT,
                             &ibuf_rc, sizeof(ibuf_rc),
                             &recordCount, sizeof(recordCount));
        HLOG_USER("GET_RECORD_COUNT: count=%zu\n", recordCount);
        if (s < 0) return 1;
        if (recordCount == 0) { HLOG_USER("Database is empty\n"); return 0; }

        size_t maxRec = recordCount > 128 ? 128 : recordCount;
        DWORD qInSz = sizeof(WINBIO_HOST_STORAGE_QUERY_INPUT_WIRE)
                    - sizeof(ULONG) + 0x78;
        UCHAR *qin  = (UCHAR*)calloc(1, qInSz);
        ((WINBIO_HOST_STORAGE_QUERY_INPUT_WIRE*)qin)->QueryType =
            STORAGE_QUERY_TYPE_ALL;
        DWORD qOutSz = sizeof(WINBIO_HOST_STORAGE_QUERY_RESULT_WIRE)
                     + (maxRec - 1) * sizeof(WINBIO_HOST_STORAGE_RECORD_WIRE);
        UCHAR *qout  = (UCHAR*)calloc(1, qOutSz);

        s = v2ioctl(IOCTL_BIOMETRIC_ENGINE_STORAGE_QUERY,
                    qin, qInSz, qout, qOutSz);
        if (s >= 0) {
            auto *res = (WINBIO_HOST_STORAGE_QUERY_RESULT_WIRE*)qout;
            HLOG_USER("Records: %llu\n", (unsigned long long)res->RecordCount);
            for (DWORD i = 0; i < res->RecordCount && i < (DWORD)maxRec; i++) {
                auto *rec = &res->Records[i];
                HLOG_USER("[%lu] IdentityType=%lu SubFactor=%u TemplateBlobSize=%llu\n",
                          (unsigned long)i,
                          (unsigned long)rec->Identity.Type,
                          (unsigned)rec->SubFactor,
                          (unsigned long long)rec->TemplateBlobSize);
                if (rec->Identity.Type == WINBIO_ID_TYPE_SID) {
                    HLOG_USER("    SID=");
                    for (ULONG j = 0;
                         j < rec->Identity.Value.AccountSid.Size
                         && j < SECURITY_MAX_SID_SIZE; j++)
                        HLOG_USER("%02x", rec->Identity.Value.AccountSid.Data[j]);
                    HLOG_USER("\n");
                } else if (rec->Identity.Type == WINBIO_ID_TYPE_GUID) {
                    HLOG_USER("    GUID=%08lx-%04x-%04x-",
                              (unsigned long)rec->Identity.Value.TemplateGuid.Data1,
                              rec->Identity.Value.TemplateGuid.Data2,
                              rec->Identity.Value.TemplateGuid.Data3);
                    for (int j = 0; j < 8; j++)
                        HLOG_USER("%02x", rec->Identity.Value.TemplateGuid.Data4[j]);
                    HLOG_USER("\n");
                }
            }
        }
        free(qin); free(qout);
        return (s >= 0) ? 0 : 1;
    }
    else if (strcasecmp(argv[1], "clear-db") == 0) {
        NTSTATUS s = v2ioctl(IOCTL_BIOMETRIC_ENGINE_ERASE_DATABASE,
                             nullptr, 0, nullptr, 0);
        return (s >= 0) ? 0 : 1;
    }
    else if (strcasecmp(argv[1], "delete-record") == 0) {
        typedef struct {
            WINBIO_IDENTITY Identity;
            WINBIO_BIOMETRIC_SUBTYPE SubFactor;
            UCHAR Reserved[3];
        } DeleteWire;
        DeleteWire wire = {};
        wire.Identity.Type = WINBIO_ID_TYPE_WILDCARD;
        wire.Identity.Value.Wildcard = WINBIO_IDENTITY_WILDCARD;
        wire.SubFactor = (WINBIO_BIOMETRIC_SUBTYPE)atoi(argv[2]);
        WINBIO_BLANK_PAYLOAD obuf = {};
        NTSTATUS s = v2ioctl(IOCTL_BIOMETRIC_STORAGE_DELETE_RECORD,
                             &wire, sizeof(wire), &obuf, sizeof(obuf));
        HLOG_USER("DELETE_RECORD: WinBioHresult=0x%lx\n",
                  (unsigned long)obuf.WinBioHresult);
        return (s >= 0) ? 0 : 1;
    }
    else if (strcasecmp(argv[1], "reset-ownership") == 0) {
        NTSTATUS s = v2ioctl(IOCTL_BIOMETRIC_ENGINE_RESET_OWNERSHIP,
                             nullptr, 0, nullptr, 0);
        return (s >= 0) ? 0 : 1;
    }
    else if (strcasecmp(argv[1], "reset") == 0) {
        WINBIO_BLANK_PAYLOAD payload = {};
        NTSTATUS s = v2ioctl(IOCTL_BIOMETRIC_RESET,
                             nullptr, 0, &payload, sizeof(payload));
        HLOG_USER("RESET: WinBioHresult=0x%lx\n",
                  (unsigned long)payload.WinBioHresult);
        return (s >= 0) ? 0 : 1;
    }
    else if (strcasecmp(argv[1], "set-led") == 0) {
        DWORD ibuf = ledState, obuf = 0;
        NTSTATUS s = v2ioctl(IOCTL_BIOMETRIC_ENGINE_SET_LED_STATE,
                             &ibuf, sizeof(ibuf), &obuf, sizeof(obuf));
        return (s >= 0) ? 0 : 1;
    }
    else if (strcasecmp(argv[1], "get-template") == 0) {
        typedef struct {
            WINBIO_IDENTITY Identity;
            WINBIO_BIOMETRIC_SUBTYPE SubFactor;
            UCHAR Reserved[3];
            ULONG TemplateId;
        } GetTemplateWire;
        static_assert(sizeof(GetTemplateWire) == 0x54,
                      "GetTemplate wire must be 0x54 bytes");
        GetTemplateWire ibuf = {};
        ibuf.Identity.Type = WINBIO_ID_TYPE_WILDCARD;
        ibuf.Identity.Value.Wildcard = WINBIO_IDENTITY_WILDCARD;
        ibuf.SubFactor = WINBIO_SUBTYPE_ANY;
        ibuf.TemplateId = (DWORD)atoi(argv[2]);
        UCHAR obuf[0x54] = {};
        ULONG_PTR info = 0;
        NTSTATUS s = v2ioctl(IOCTL_BIOMETRIC_ENGINE_GET_TEMPLATE,
                             &ibuf, sizeof(ibuf), obuf, sizeof(obuf), &info);
        HLOG_USER("GET_TEMPLATE: %zu bytes: ", (size_t)info);
        for (size_t i = 0; i < (size_t)info && i < sizeof(obuf); i++)
            HLOG_USER("%02x", obuf[i]);
        HLOG_USER("\n");
        return (s >= 0) ? 0 : 1;
    }
    else if (strcasecmp(argv[1], "identify") == 0 ||
             strcasecmp(argv[1], "enroll") == 0 ||
             strcasecmp(argv[1], "identify-all") == 0) {
        HLOG_USER("v2: %s requires real USB scan -- not yet implemented\n",
                  argv[1]);
        return 1;
    }

    return 0;
}
