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
    else if (strcasecmp(argv[1], "enroll") == 0) {
        // Step 1: CREATE_ENROLLMENT
        UCHAR ceInput[8] = {0};
        UCHAR ceOutput[0x28] = {0};
        NTSTATUS s = v2ioctl(IOCTL_BIOMETRIC_ENGINE_CREATE_ENROLLMENT,
                             ceInput, sizeof(ceInput), ceOutput, sizeof(ceOutput));
        if (s < 0) {
            HLOG_USER("CREATE_ENROLLMENT failed, aborting\n");
            return 1;
        }

        // Step 2: CAPTURE_DATA + UPDATE_ENROLLMENT loop
        typedef struct _V2_UE_WIRE {
            HRESULT TemplateStatus;
            UCHAR   Reserved1[0x24];
            ULONG   PercentComplete;
            WINBIO_REJECT_DETAIL RejectDetail;
            struct { ULONG GeneralSamples, Center, TopEdge, BottomEdge, LeftEdge, RightEdge; } Fingerprint;
        } V2_UE_WIRE;
        static_assert(sizeof(V2_UE_WIRE) == 0x48, "UE wire must be 0x48");

        bool enrollComplete = false;
        for (int t = 0; t < 70 && !enrollComplete; t++) {
            WINBIO_CAPTURE_PARAMETERS params = {0};
            params.PayloadSize = sizeof(params);
            params.Purpose    = WINBIO_PURPOSE_ENROLL_FOR_IDENTIFICATION;
            ((uint64_t*)&params.VendorFormat)[0] = 0x46DCFA2072A4E245ULL;
            ((uint64_t*)&params.VendorFormat)[1] = 0xA927C0D0BA850395ULL;
            params.Flags      = WINBIO_DATA_FLAG_PROCESSED;

            UCHAR capBuf[1024 * 100] = {0};
            ULONG_PTR capInfo = 0;
            HLOG_USER("Place finger on sensor (attempt %d)...\n", t + 1);
            s = v2ioctl(IOCTL_BIOMETRIC_CAPTURE_DATA,
                        &params, sizeof(params), capBuf, sizeof(capBuf), &capInfo);
            if (s < 0) {
                HLOG_USER("CAPTURE_DATA failed: 0x%lx (%s)\n",
                          (unsigned long)s, hresult_to_sting(s));
                Sleep(200);
                continue;
            }
            auto *capData = (WINBIO_CAPTURE_DATA *)capBuf;
            HLOG_USER("Capture: SensorStatus=%lu RejectDetail=0x%lx (%s)\n",
                      (unsigned long)capData->SensorStatus,
                      (unsigned long)capData->RejectDetail,
                      reject_detail_to_string(capData->RejectDetail));
            if (capData->SensorStatus == WINBIO_SENSOR_REJECT) {
                Sleep(200);
                continue;
            }

            V2_UE_WIRE ueWire = {0};
            ULONG_PTR ueInfo = 0;
            s = v2ioctl(IOCTL_BIOMETRIC_ENGINE_UPDATE_ENROLLMENT,
                        &ueWire, sizeof(ueWire), &ueWire, sizeof(ueWire), &ueInfo);
            if (s < 0 || ueInfo < 0x30) {
                HLOG_USER("UPDATE_ENROLLMENT failed: 0x%lx (info=%zu)\n",
                          (unsigned long)s, (size_t)ueInfo);
                break;
            }
            HLOG_USER("UPDATE: TemplateStatus=0x%lx (%s) PercentComplete=%lu RejectDetail=0x%lx (%s)\n",
                      (unsigned long)ueWire.TemplateStatus,
                      hresult_to_sting(ueWire.TemplateStatus),
                      (unsigned long)ueWire.PercentComplete,
                      (unsigned long)ueWire.RejectDetail,
                      reject_detail_to_string(ueWire.RejectDetail));
            if (ueWire.TemplateStatus != WINBIO_I_MORE_DATA)
                enrollComplete = true;
        }

        // Step 3: COMMIT_ENROLLMENT
        typedef struct _V2_COMMIT_WIRE {
            WINBIO_IDENTITY Identity;
            WINBIO_BIOMETRIC_SUBTYPE SubFactor;
            UCHAR Reserved[3];
            ULONGLONG PayloadBlobSize;
            UCHAR PayloadBlob[8];
        } V2_COMMIT_WIRE;
        static_assert(sizeof(V2_COMMIT_WIRE) == 0x60, "Commit wire must be 0x60");

        V2_COMMIT_WIRE commitIn = {0};
        commitIn.Identity.Type = WINBIO_ID_TYPE_GUID;
        if (FAILED(CoCreateGuid(&commitIn.Identity.Value.TemplateGuid))) {
            commitIn.Identity.Type = WINBIO_ID_TYPE_WILDCARD;
            commitIn.Identity.Value.Wildcard = WINBIO_IDENTITY_WILDCARD;
        }
        commitIn.SubFactor       = WINBIO_ANSI_381_POS_RH_INDEX_FINGER;
        commitIn.PayloadBlobSize = sizeof(commitIn.PayloadBlob);
        memcpy(commitIn.PayloadBlob, "Unicorn\0", sizeof(commitIn.PayloadBlob));

        WINBIO_BLANK_PAYLOAD commitOut = {0};
        s = v2ioctl(IOCTL_BIOMETRIC_ENGINE_COMMIT_ENROLLMENT,
                    &commitIn, sizeof(commitIn), &commitOut, sizeof(commitOut));
        HLOG_USER("COMMIT_ENROLLMENT: 0x%lx (%s)\n",
                  (unsigned long)s, hresult_to_sting(s));
        return (s >= 0) ? 0 : 1;
    }
    else if (strcasecmp(argv[1], "identify") == 0 ||
             strcasecmp(argv[1], "identify-all") == 0) {
        // Step 1: CAPTURE_DATA
        WINBIO_CAPTURE_PARAMETERS params = {0};
        params.PayloadSize = sizeof(params);
        params.Purpose     = WINBIO_PURPOSE_IDENTIFY;
        ((uint64_t*)&params.VendorFormat)[0] = 0x46DCFA2072A4E245ULL;
        ((uint64_t*)&params.VendorFormat)[1] = 0xA927C0D0BA850395ULL;
        params.Flags       = WINBIO_DATA_FLAG_PROCESSED;

        UCHAR capBuf[1024 * 100] = {0};
        ULONG_PTR capInfo = 0;
        HLOG_USER("Place finger on sensor...\n");
        NTSTATUS s = v2ioctl(IOCTL_BIOMETRIC_CAPTURE_DATA,
                             &params, sizeof(params), capBuf, sizeof(capBuf), &capInfo);
        if (s < 0) {
            HLOG_USER("CAPTURE_DATA failed: 0x%lx (%s)\n",
                      (unsigned long)s, hresult_to_sting(s));
            return 1;
        }
        auto *capData = (WINBIO_CAPTURE_DATA *)capBuf;
        HLOG_USER("Capture: SensorStatus=%lu RejectDetail=0x%lx (%s)\n",
                  (unsigned long)capData->SensorStatus,
                  (unsigned long)capData->RejectDetail,
                  reject_detail_to_string(capData->RejectDetail));

        // Step 2: SET_TEMPLATE_LIST (zero = match against all enrolled templates)
        uint64_t stlIn = 0;
        WINBIO_BLANK_PAYLOAD stlOut = {0};
        s = v2ioctl(IOCTL_BIOMETRIC_ENGINE_SET_TEMPLATE_LIST,
                    &stlIn, sizeof(stlIn), &stlOut, sizeof(stlOut));
        HLOG_USER("SET_TEMPLATE_LIST: 0x%lx (%s)\n",
                  (unsigned long)s, hresult_to_sting(s));
        if (s < 0) return 1;

        // Step 3: IDENTIFY_FEATURE_SET
        // Output may be larger than the base struct — heap-allocate to be safe
        const DWORD ifs_obuf_size = 4096;
        UCHAR *ifs_obuf_raw = (UCHAR *)calloc(1, ifs_obuf_size);
        if (!ifs_obuf_raw) { HLOG_USER("OOM\n"); return 1; }

        ULONG_PTR idInfo = 0;
        s = v2ioctl(IOCTL_BIOMETRIC_ENGINE_IDENTIFY_FEATURE_SET,
                    nullptr, 0, ifs_obuf_raw, ifs_obuf_size, &idInfo);
        HLOG_USER("IDENTIFY_FEATURE_SET: 0x%lx (%s)\n",
                  (unsigned long)s, hresult_to_sting(s));

        if (s >= 0 && idInfo >= sizeof(WINBIO_IDENTIFY_FEATURE_SET_OUTPUT_WIRE)) {
            auto *obuf = (WINBIO_IDENTIFY_FEATURE_SET_OUTPUT_WIRE *)ifs_obuf_raw;
            HLOG_USER("EngineHresult=0x%lx (%s) SubFactor=%u (%s)\n",
                      (unsigned long)obuf->EngineHresult,
                      hresult_to_sting(obuf->EngineHresult),
                      (unsigned)obuf->SubFactor,
                      subfactor_to_string((WINBIO_BIOMETRIC_SUBTYPE)obuf->SubFactor));
            if (obuf->Identity.Type == WINBIO_ID_TYPE_GUID) {
                RPC_CSTR guidStr = NULL;
                if (SUCCEEDED(UuidToStringA((UUID*)&obuf->Identity.Value.TemplateGuid, &guidStr))) {
                    HLOG_USER("Matched GUID: %s\n", guidStr);
                    RpcStringFreeA(&guidStr);
                }
            }
        }
        int ret = (s >= 0) ? 0 : 1;
        free(ifs_obuf_raw);
        return ret;
    }

    return 0;
}
