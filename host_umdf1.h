#pragma once
// Host-side stub implementations of UMDF v1 COM interfaces

struct HostNamedPropertyStore : public IWDFNamedPropertyStore2 {
    std::map<std::wstring, PROPVARIANT*> m_store;
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"HostMem::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("New NamedPropertyStore: ppvObject=%p\r\n", *ppvObject);
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("HostNamedPropertyStore::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("HostNamedPropertyStore::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("HostNamedPropertyStore::DeleteWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) {
            HLOG_DEBUG("HostNamedPropertyStore::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) {
            HLOG_DEBUG("HostNamedPropertyStore::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            HLOG_DEBUG("HostNamedPropertyStore::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            HLOG_DEBUG("HostNamedPropertyStore::ReleaseLock\r\n");
        }
    public:
        virtual HRESULT STDMETHODCALLTYPE GetNamedValue(
            /* [annotation][string][in] */
            _In_  LPCWSTR pszName,
            /* [annotation][out] */
            _Out_  PROPVARIANT *pv){
            HLOG_DEBUG("HostNamedPropertyStore::GetNamedValue %ls %d\n", pszName, pv->vt);

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

            HLOG_DEBUG("HostNamedPropertyStore::SetNamedValue %ls (%d)\n", pszName, pv->vt);
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
            HLOG_DEBUG("HostNamedPropertyStore::GetNameCount\n");
            *pdwCount = 0;
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE GetNameAt(
            /* [annotation][in] */
            _In_  DWORD iProp,
            /* [annotation][string][out] */
            _Out_  PWSTR *ppwszName){
            HLOG_DEBUG("HostNamedPropertyStore::GetNameAt %lu\n", (unsigned long)iProp);
            static WCHAR emptyStr[] = L""; *ppwszName = emptyStr;
            return 0;
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE DeleteNamedValue(
            /* [annotation][string][in] */
            _In_  LPCWSTR pwszName){
            std::wcout << L"HostNamedPropertyStore::DeleteNamedValue " << pwszName<< std::endl;
            return 0;
        }

};


struct HostPropertyStoreFactory : public IWDFPropertyStoreFactory {
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"HostPropertyStoreFactory::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("IWDFPropertyStoreFactory::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("HostPropertyStoreFactory::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("HostPropertyStoreFactory::DeleteWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) {
            HLOG_DEBUG("HostPropertyStoreFactory::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) {
            HLOG_DEBUG("HostPropertyStoreFactory::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            HLOG_DEBUG("HostPropertyStoreFactory::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            HLOG_DEBUG("HostPropertyStoreFactory::ReleaseLock\r\n");
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
            HLOG_DEBUG("HostPropertyStoreFactory::RetrieveDevicePropertyStore\r\n");
            *PropertyStore = new HostNamedPropertyStore();
            return 0;
        }

};

struct HostMem : public IWDFMemory {
    public:
        HostMem(void *b, SIZE_T s) {
            buf = b;
            size = s;
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"HostMem::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("HostMem::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("HostMem::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("HostMem::DeleteWdfObject\r\n");
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
            HLOG_DEBUG("HostMem::GetDataBuffer size=%llu\r\n", size);
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

class HostUsbRequestCompletionParams : public IWDFUsbRequestCompletionParams
    {
    public:
        HostUsbRequestCompletionParams(WDF_REQUEST_TYPE rt, ULONG sent) :
            m_request_type(rt),
            // FIXME: use actual type
            m_usb_request_type(WdfUsbRequestTypeDeviceControlTransfer),
            m_sent(sent) {}

        virtual ULONG STDMETHODCALLTYPE AddRef() override {
            HLOG_DEBUG("HostUsbRequestCompletionParams::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() override {
            HLOG_DEBUG("HostUsbRequestCompletionParams::Release\r\n");
            return 0;
        }
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"HostUsbRequestCompletionParams::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE GetCompletionStatus() override {
            HLOG_DEBUG("HostUsbRequestCompletionParams::GetCompletionStatus\r\n");
            return S_OK;
        }

        virtual ULONG_PTR STDMETHODCALLTYPE GetInformation() override {
            HLOG_DEBUG("HostUsbRequestCompletionParams::GetInformation\r\n");
            return m_sent;
        }

        virtual WDF_REQUEST_TYPE STDMETHODCALLTYPE GetCompletedRequestType() override {
            HLOG_DEBUG("HostUsbRequestCompletionParams::GetCompletedRequestType: %d\r\n", m_request_type);
            return m_request_type;
        }

        virtual WDF_USB_REQUEST_TYPE STDMETHODCALLTYPE GetCompletedUsbRequestType() override {
            HLOG_DEBUG("HostUsbRequestCompletionParams::GetCompletedRequestType2: %d\r\n",
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
            HLOG_DEBUG("HostUsbRequestCompletionParams::GetDeviceControlTransferParameters\r\n");
            assert(false && "NOT IMPLEMENTED");
        }

        virtual void STDMETHODCALLTYPE GetPipeWriteParameters(
            /* [annotation][unique][out] */
            _Out_opt_  IWDFMemory **ppWriteMemory,
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pBytesWritten,
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pWriteMemoryOffset) override {
            HLOG_DEBUG("HostUsbRequestCompletionParams::GetPipeWriteParameters\r\n");
            assert(false && "NOT IMPLEMENTED");
        }

        virtual void STDMETHODCALLTYPE GetPipeReadParameters(
            /* [annotation][unique][out] */
            _Out_opt_  IWDFMemory **ppReadMemory,
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pBytesRead,
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pReadMemoryOffset) override {
            HLOG_DEBUG("HostUsbRequestCompletionParams::GetPipeReadParameters\r\n");
            assert(false && "NOT IMPLEMENTED");
        }

    private:
        WDF_REQUEST_TYPE m_request_type;
        WDF_USB_REQUEST_TYPE m_usb_request_type;
        ULONG m_sent;
    };

struct HostRequest : public IWDFIoRequest {
    public:
        HostRequest(WDF_REQUEST_TYPE t, ULONG c, HostMem *out, HostMem *in) {
            reqType = t;
            ctl = c;
            outMem = out;
            inMem = in;
            cancelCallback = nullptr;
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
            std::wcout << L"HostRequest::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("HostRequest::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("HostRequest::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("HostRequest::DeleteWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) {
            HLOG_DEBUG("HostRequest::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) {
            HLOG_DEBUG("HostRequest::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            HLOG_DEBUG("HostRequest::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            HLOG_DEBUG("HostRequest::ReleaseLock\r\n");
        }
    public:
        virtual void STDMETHODCALLTYPE CompleteWithInformation(
            /* [annotation][in] */
            _In_  HRESULT CompletionStatus,
            /* [annotation][in] */
            _In_  SIZE_T Information){
            HLOG_INFO("HostRequest::CompleteWithInformation(req=%p ctl=0x%08lx): %lx (%s), info=%zu\r\n",
                this, (unsigned long)ctl, (unsigned long)CompletionStatus,
                hresult_to_sting(CompletionStatus), (size_t)Information);
            completionStatus = CompletionStatus;
            informationSize = Information;
            complete = TRUE;
        }

        virtual void STDMETHODCALLTYPE SetInformation(
            /* [annotation][in] */
            _In_  ULONG_PTR Information){
            HLOG_INFO("HostRequest::SetInformation(req=%p ctl=0x%08lx) size=%lld\r\n",
                this, (unsigned long)ctl, Information);
            informationSize = Information;
        }

        virtual void STDMETHODCALLTYPE Complete(
            /* [annotation][in] */
            _In_  HRESULT CompletionStatus){
            HLOG_INFO("HostRequest::Complete(req=%p ctl=0x%08lx): %lx (%s)\r\n",
                this, (unsigned long)ctl, (unsigned long)CompletionStatus,
                hresult_to_sting(CompletionStatus));
            completionStatus = CompletionStatus;
            complete = TRUE;
        }

        virtual void STDMETHODCALLTYPE SetCompletionCallback(
            /* [annotation][in] */
            _In_  IRequestCallbackRequestCompletion *pCompletionCallback,
            /* [annotation][unique][in] */
            _In_opt_  void *pContext){
            HLOG_DEBUG("HostRequest::SetCompletionCallback\r\n");
        }

        virtual WDF_REQUEST_TYPE STDMETHODCALLTYPE GetType( void){
            HLOG_DEBUG("HostRequest::GetType\r\n");
            return reqType;
        }

        virtual void STDMETHODCALLTYPE GetCreateParameters(
            /* [annotation][unique][out] */
            _Out_opt_  ULONG *pOptions,
            /* [annotation][unique][out] */
            _Out_opt_  USHORT *pFileAttributes,
            /* [annotation][unique][out] */
            _Out_opt_  USHORT *pShareAccess){
            HLOG_DEBUG("HostRequest::GetCreateParameters\r\n");
        }


        virtual void STDMETHODCALLTYPE GetReadParameters(
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pSizeInBytes,
            /* [annotation][unique][out] */
            _Out_opt_  LONGLONG *pullOffset,
            /* [annotation][unique][out] */
            _Out_opt_  ULONG *pulKey){
            HLOG_DEBUG("HostRequest::GetReadParameters\r\n");
        }


        virtual void STDMETHODCALLTYPE GetWriteParameters(
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pSizeInBytes,
            /* [annotation][unique][out] */
            _Out_opt_  LONGLONG *pullOffset,
            /* [annotation][unique][out] */
            _Out_opt_  ULONG *pulKey){
            HLOG_DEBUG("HostRequest::GetWriteParameters\r\n");
        }


        virtual void STDMETHODCALLTYPE GetDeviceIoControlParameters(
            /* [annotation][unique][out] */
            _Out_opt_  ULONG *pControlCode,
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pInBufferSize,
            /* [annotation][unique][out] */
            _Out_opt_  SIZE_T *pOutBufferSize){
            HLOG_DEBUG("HostRequest::GetDeviceIoControlParameters req=%p ctl=0x%08lx inMem=%p outMem=%p %p %p %p",
                this, (unsigned long)ctl, inMem, outMem, pControlCode, pInBufferSize, pOutBufferSize);
            if (pControlCode)
                *pControlCode = ctl;
            if (pInBufferSize)
                *pInBufferSize = inMem ? inMem->size : 0;
            if (pOutBufferSize)
                *pOutBufferSize = outMem ? outMem->size : 0;

            HLOG_DEBUG("=> %zu %zu\r\n",
                    (size_t)(pInBufferSize ? *pInBufferSize : 0),
                    (size_t)(pOutBufferSize ? *pOutBufferSize : 0));
        }


        HostMem *outMem = nullptr;
        HostMem *inMem = nullptr;

        virtual void STDMETHODCALLTYPE GetOutputMemory(
            /* [annotation][out] */
            _Out_  IWDFMemory **ppWdfMemory){
            HLOG_DEBUG("HostRequest::GetOutputMemory req=%p ctl=0x%08lx => %p\r\n",
                this, (unsigned long)ctl, outMem);
            *ppWdfMemory = outMem;
            if (outMem) {
                SIZE_T outSize = 0;
                void *outBuf = outMem->GetDataBuffer(&outSize);
                HLOG_DEBUG("HostRequest::GetOutputMemory buffer=%p size=%zu\r\n", outBuf, (size_t)outSize);
            } else {
                HLOG_USER("HostRequest::GetOutputMemory missing output memory for ctl=0x%08lx\n",
                    (unsigned long)ctl);
            }
        }

        virtual void STDMETHODCALLTYPE GetInputMemory(
            /* [annotation][out] */
            _Out_  IWDFMemory **ppWdfMemory){
            HLOG_DEBUG("HostRequest::GetInputMemory req=%p ctl=0x%08lx => %p\r\n",
                this, (unsigned long)ctl, inMem);
            *ppWdfMemory = inMem;
            if (inMem) {
                SIZE_T inSize = 0;
                void *inBuf = inMem->GetDataBuffer(&inSize);
                HLOG_DEBUG("HostRequest::GetInputMemory buffer=%p size=%zu\r\n", inBuf, (size_t)inSize);
            } else {
                HLOG_USER("HostRequest::GetInputMemory missing input memory for ctl=0x%08lx\n",
                    (unsigned long)ctl);
            }
        }

        virtual void STDMETHODCALLTYPE MarkCancelable(
            /* [annotation][in] */
            _In_  IRequestCallbackCancel *pCancelCallback){
            HLOG_DEBUG("HostRequest::MarkCancelable req=%p ctl=0x%08lx cb=%p\r\n",
                this, (unsigned long)ctl, pCancelCallback);
            this->cancelCallback = pCancelCallback;
        }

        virtual HRESULT STDMETHODCALLTYPE UnmarkCancelable( void){
            HLOG_DEBUG("HostRequest::UnmarkCancelable\r\n");
            return 0;
        }


        virtual BOOL STDMETHODCALLTYPE CancelSentRequest( void){
            HLOG_DEBUG("HostRequest::CancelSentRequest\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE ForwardToIoQueue(
            /* [annotation][in] */
            _In_  IWDFIoQueue *pDestination){
            HLOG_DEBUG("HostRequest::ForwardToIoQueue\r\n");
            return 0;
        }

        void SetControlData(PWINUSB_SETUP_PACKET SetupPacket,
                            IWDFMemory *pMemory,
                            PWDFMEMORY_OFFSET Offset) {
            HLOG_DEBUG("HostRequest::SetControlData: %p %p %p\r\n",
                SetupPacket, pMemory, Offset);
            m_setupPacket = *SetupPacket;
            outMem = (HostMem *) pMemory;
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
            HLOG_DEBUG("HostRequest::Send %p | %lu | %lld\r\n", pIoTarget,
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
            HLOG_DEBUG("HostRequest::GetFileObject\r\n");
        }

        virtual void STDMETHODCALLTYPE FormatUsingCurrentType( void){
            HLOG_DEBUG("HostRequest::FormatUsingCurrentType\r\n");
        }

        virtual ULONG STDMETHODCALLTYPE GetRequestorProcessId( void){
            HLOG_DEBUG("HostRequest::GetRequestorProcessId\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE GetIoQueue(
            /* [annotation][out] */
            _Out_  IWDFIoQueue **ppWdfIoQueue){
            HLOG_DEBUG("HostRequest::GetIoQueue\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE Impersonate(
            /* [annotation][in] */
            _In_  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            /* [annotation][in] */
            _In_  IImpersonateCallback *pCallback,
            /* [annotation][unique][in] */
            _In_opt_  void *pvCallbackContext){
            HLOG_DEBUG("HostRequest::Impersonate\r\n");
            return 0;
        }


        virtual BOOL STDMETHODCALLTYPE IsFrom32BitProcess( void){
            HLOG_DEBUG("HostRequest::IsFrom32BitProcess\r\n");
            return 1;
        }

        virtual void STDMETHODCALLTYPE GetCompletionParams(
            /* [annotation][out] */
            _Out_  IWDFRequestCompletionParams **ppCompletionParams){
            HLOG_DEBUG("HostRequest::GetCompletionParams\r\n");
            *ppCompletionParams = new HostUsbRequestCompletionParams(reqType, m_sent);
        }
};

struct HostQueue : public IWDFIoQueue {
    public:
        HostQueue(IUnknown *pCallbackInterface) {
            pCallbackInterface->AddRef();
            pCallbackInterface->QueryInterface(IID_IQueueCallbackDeviceIoControl, (LPVOID*)&ioctl);
            HLOG_DEBUG("ioctl=%p\r\n", ioctl);
        }

        IQueueCallbackDeviceIoControl *ioctl=0;

    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"HostQueue::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("HostQueue::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("HostQueue::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("HostQueue::DeleteWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) {
            HLOG_DEBUG("HostQueue::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) {
            HLOG_DEBUG("HostQueue::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            HLOG_DEBUG("HostQueue::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            HLOG_DEBUG("HostQueue::ReleaseLock\r\n");
        }
    public:
        virtual void STDMETHODCALLTYPE GetDevice(
            /* [annotation][out] */
            _Out_  IWDFDevice **ppWdfDevice){
            HLOG_DEBUG("HostQueue::GetDevice\r\n");
        }


        virtual HRESULT STDMETHODCALLTYPE ConfigureRequestDispatching(
            /* [annotation][in] */
            _In_  WDF_REQUEST_TYPE RequestType,
            /* [annotation][in] */
            _In_  BOOL Forward){
            HLOG_DEBUG("HostDevice::ConfigureRequestDispatching (%d, %d)\r\n",
                RequestType, Forward);
            return 0;
        }


        virtual WDF_IO_QUEUE_STATE STDMETHODCALLTYPE GetState(
            /* [annotation][out] */
            _Out_  ULONG *pulNumOfRequestsInQueue,
            /* [annotation][out] */
            _Out_  ULONG *pulNumOfRequestsInDriver){
            HLOG_DEBUG("HostQueue::GetState\r\n");
            return (WDF_IO_QUEUE_STATE)(WdfIoQueueAcceptRequests |
                    WdfIoQueueDispatchRequests |
                    WdfIoQueueNoRequests |
                    WdfIoQueueDriverNoRequests);
        }


        virtual HRESULT STDMETHODCALLTYPE RetrieveNextRequest(
            /* [annotation][out] */
            _Out_  IWDFIoRequest **ppRequest){
            HLOG_DEBUG("HostQueue::RetrieveNextRequest\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE RetrieveNextRequestByFileObject(
            /* [annotation][in] */
            _In_  IWDFFile *pFile,
            /* [annotation][out] */
            _Out_  IWDFIoRequest **ppRequest){
            HLOG_DEBUG("HostQueue::RetrieveNextRequestByFileObject\r\n");
            return 0;
        }


        virtual void STDMETHODCALLTYPE Start( void){
            HLOG_DEBUG("HostQueue::Start\r\n");
        }


        virtual void STDMETHODCALLTYPE Stop(
            /* [annotation][unique][in] */
            _In_opt_  IQueueCallbackStateChange *pStopComplete){
            HLOG_DEBUG("HostQueue::Stop\r\n");
        }


        virtual void STDMETHODCALLTYPE StopSynchronously( void){
            HLOG_DEBUG("HostQueue::StopSynchronously\r\n");
        }


        virtual void STDMETHODCALLTYPE Drain(
            /* [annotation][unique][in] */
            _In_opt_  IQueueCallbackStateChange *pDrainComplete){
            HLOG_DEBUG("HostQueue::Drain\r\n");
        }


        virtual void STDMETHODCALLTYPE DrainSynchronously( void){
            HLOG_DEBUG("HostQueue::Drain\r\n");
        }


        virtual void STDMETHODCALLTYPE Purge(
            /* [annotation][unique][in] */
            _In_opt_  IQueueCallbackStateChange *pPurgeComplete){
            HLOG_DEBUG("HostQueue::Purge\r\n");
        }


        virtual void STDMETHODCALLTYPE PurgeSynchronously( void){
            HLOG_DEBUG("HostQueue::Purge\r\n");
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

HostQueue *hostQueue = 0;

class HostUsbTargetPipe : public IWDFUsbTargetPipe2 {
    public:
        HostUsbTargetPipe(
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
            HLOG_DEBUG("HostUsbTargetPipe::HostUsbTargetPipe %d 0x%x\r\n",
                m_PipeType, m_PipeId);
        }

        virtual ULONG STDMETHODCALLTYPE AddRef() override {
            HLOG_DEBUG("HostUsbTargetPipe::AddRef\r\n");
            return 0;
        }

        virtual ULONG STDMETHODCALLTYPE Release() override {
            HLOG_DEBUG("HostUsbTargetPipe::Release\r\n");
            return 0;
        }
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"HostUsbTargetPipe::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject() override {
            HLOG_DEBUG("HostUsbTargetPipe::DeleteWdfObject\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock() override {
            HLOG_DEBUG("HostUsbTargetPipe::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock() override {
            HLOG_DEBUG("HostUsbTargetPipe::ReleaseLock\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) override {
            HLOG_DEBUG("HostUsbTargetPipe::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) override {
            HLOG_DEBUG("HostUsbTargetPipe::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE GetTargetFile(
            /* [annotation][out] */
            _Out_  IWDFFile **ppWdfFile) override {
            HLOG_DEBUG("HostUsbTargetPipe::GetTargetFile\r\n");
            *ppWdfFile = NULL;
        }

        virtual void STDMETHODCALLTYPE CancelSentRequestsForFile(
            /* [annotation][in] */
            _In_  IWDFFile *pFile) override {
            HLOG_DEBUG("HostUsbTargetPipe::CancelSentRequestsForFile\r\n");
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
            HLOG_DEBUG("HostUsbTargetPipe::FormatRequestForRead\r\n");
            auto req = (HostRequest *)pRequest;
            req->m_usbOp = HostRequest::UsbPipeRead;
            req->m_pipeHandle = m_WinUsbHandle;
            req->m_pipeId = m_PipeId;
            req->outMem = (HostMem *)pOutputMemory;
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
            HLOG_DEBUG("HostUsbTargetPipe::FormatRequestForWrite\r\n");
            auto req = (HostRequest *)pRequest;
            req->m_usbOp = HostRequest::UsbPipeWrite;
            req->m_pipeHandle = m_WinUsbHandle;
            req->m_pipeId = m_PipeId;
            req->inMem = (HostMem *)pInputMemory;
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
            HLOG_DEBUG("HostUsbTargetPipe::FormatRequestForIoctl\r\n");
            return S_OK;
        }

        virtual HRESULT STDMETHODCALLTYPE Abort() override {
            HLOG_DEBUG("HostUsbTargetPipe::Abort\r\n");

            if (!WinUsb_AbortPipe(m_WinUsbHandle, m_PipeId)) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            return S_OK;
        }

        virtual HRESULT STDMETHODCALLTYPE Reset() override {
            HLOG_DEBUG("HostUsbTargetPipe::Reset\r\n");

            if (!WinUsb_ResetPipe(m_WinUsbHandle, m_PipeId)) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            return S_OK;
        }

        virtual HRESULT STDMETHODCALLTYPE Flush() override {
            HLOG_DEBUG("HostUsbTargetPipe::Flush\r\n");

            if (!WinUsb_FlushPipe(m_WinUsbHandle, m_PipeId)) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            return S_OK;
        }

        virtual void STDMETHODCALLTYPE GetInformation(_Out_ PWINUSB_PIPE_INFORMATION pInfo) override {
            HLOG_DEBUG("HostUsbTargetPipe::GetInformation %d 0x%x\r\n", m_PipeType, m_PipeId);
            pInfo->PipeType = m_PipeType;
            pInfo->PipeId = m_PipeId;
            pInfo->MaximumPacketSize = m_MaxPacketSize;
            pInfo->Interval = m_Interval;
        }

        virtual BOOL STDMETHODCALLTYPE IsInEndPoint() override {
            HLOG_DEBUG("HostUsbTargetPipe::IsInEndPoint\r\n");

            return (m_PipeId & 0x80) != 0;
        }

        virtual BOOL STDMETHODCALLTYPE IsOutEndPoint() override {
            HLOG_DEBUG("HostUsbTargetPipe::IsOutEndPoint\r\n");

            return (m_PipeId & 0x80) == 0;
        }

        virtual USBD_PIPE_TYPE STDMETHODCALLTYPE GetType() override {
            HLOG_DEBUG("HostUsbTargetPipe::GetType\r\n");

            return m_PipeType;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrievePipePolicy(
            _In_ ULONG PolicyType,
            _Inout_ ULONG* ValueLength,
            _Out_ PVOID Value) override {
            HLOG_DEBUG("HostUsbTargetPipe::RetrievePipePolicy\r\n");

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
            HLOG_DEBUG("HostUsbTargetPipe::SetPipePolicy\r\n");

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
            HLOG_DEBUG("HostUsbTargetPipe::ConfigureContinuousReader\r\n");
            return S_OK;
        }

    private:
        WINUSB_INTERFACE_HANDLE m_WinUsbHandle;
        UCHAR m_PipeId;
        USBD_PIPE_TYPE m_PipeType;
        ULONG m_MaxPacketSize;
        ULONG m_Interval;
};

class HostUsbInterface : public IWDFUsbInterface {
    public:
        HostUsbInterface(UCHAR idx, WINUSB_INTERFACE_HANDLE handle)
            : m_idx(idx), m_handle(handle) {}

        virtual ULONG STDMETHODCALLTYPE AddRef() override {
            HLOG_DEBUG("HostUsbInterface::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() override {
            HLOG_DEBUG("HostUsbInterface::Release\r\n");
            return 0;
        }
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"HostUsbInterface::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject() override {
            HLOG_DEBUG("HostUsbInterface::DeleteWdfObject\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock() override {
            HLOG_DEBUG("HostUsbInterface::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock() override {
            HLOG_DEBUG("HostUsbInterface::ReleaseLock\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) override {
            HLOG_DEBUG("HostUsbInterface::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) override {
            HLOG_DEBUG("HostUsbInterface::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE GetInterfaceDescriptor(
            /* [annotation][out] */
            _Out_  PUSB_INTERFACE_DESCRIPTOR UsbAltInterfaceDescriptor) override {
            HLOG_DEBUG("HostUsbInterface::GetInterfaceDescriptor\r\n");
        }

        virtual UCHAR STDMETHODCALLTYPE GetInterfaceNumber() override {
            HLOG_DEBUG("HostUsbInterface::GetInterfaceNumber\r\n");
            return m_idx;
        }

        virtual UCHAR STDMETHODCALLTYPE GetNumEndPoints() override {
            HLOG_DEBUG("HostUsbInterface::GetNumEndPoints\r\n");
            return 3;
        }

        virtual UCHAR STDMETHODCALLTYPE GetConfiguredSettingIndex() override {
            HLOG_DEBUG("HostUsbInterface::GetConfiguredSettingIndex\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE SelectSetting(
            /* [annotation][in] */
            _In_  UCHAR SettingNumber) override {
            HLOG_DEBUG("HostUsbInterface::SelectSetting\r\n");
            return 0;
        }

        virtual WINUSB_INTERFACE_HANDLE STDMETHODCALLTYPE GetWinUsbHandle() override {
            HLOG_DEBUG("HostUsbInterface::GetWinUsbHandle\r\n");
            return m_handle;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveUsbPipeObject(
            /* [annotation][in] */
            _In_  UCHAR PipeIndex,
            /* [annotation][out] */
            _Out_  IWDFUsbTargetPipe **ppPipe) override {
            HLOG_DEBUG("HostUsbInterface::IWDFUsbTargetPipe 0x%x\r\n", PipeIndex);

            WINUSB_PIPE_INFORMATION pipeInfo;
            if (!WinUsb_QueryPipe(GetWinUsbHandle(), m_idx, PipeIndex, &pipeInfo)) {
                HLOG_INFO("Impossible to get pipe informatio!\r\n");
                return E_NOTIMPL;
            }

            *ppPipe = new HostUsbTargetPipe(m_handle, pipeInfo.PipeType,
                pipeInfo.PipeId, pipeInfo.MaximumPacketSize, pipeInfo.Interval);
            return 0;
        }

    private:
        UCHAR m_idx;
        WINUSB_INTERFACE_HANDLE m_handle;
    };

class HostUsbTargetDevice : public IWDFUsbTargetDevice {
public:
        HostUsbTargetDevice(WINUSB_INTERFACE_HANDLE handle) : m_handle(handle) {
            HLOG_DEBUG("HostUsbTargetDevice::HostUsbTargetDevice: %p\r\n", this);

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
                if (m_configDesc) {
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
                } else {
                    HLOG_DEBUG("No active USB configuration descriptor to dump\n");
                }
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
            HLOG_DEBUG("HostUsbTargetDevice::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() override {
            HLOG_DEBUG("HostUsbTargetDevice::Release\r\n");
            return 0;
        }
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"HostUsbTargetDevice::QueryInterface " << str << std::endl;
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
            HLOG_DEBUG("HostUsbTargetDevice::DeleteWdfObject\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock() override {
            HLOG_DEBUG("HostUsbTargetDevice::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock() override {
            HLOG_DEBUG("HostUsbTargetDevice::ReleaseLock\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) override {
            HLOG_DEBUG("HostUsbTargetDevice::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) override {
            HLOG_DEBUG("HostUsbTargetDevice::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE GetTargetFile(
            /* [annotation][out] */
            _Out_  IWDFFile **ppWdfFile) override {
            HLOG_DEBUG("HostUsbTargetDevice::GetTargetFile\r\n");
        };

        virtual void STDMETHODCALLTYPE CancelSentRequestsForFile(
            /* [annotation][in] */
            _In_  IWDFFile *pFile) override {
            HLOG_DEBUG("HostUsbTargetDevice::CancelSentRequestsForFile\r\n");
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
            HLOG_DEBUG("HostUsbTargetDevice::FormatRequestForRead\r\n");
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
            HLOG_DEBUG("HostUsbTargetDevice::FormatRequestForWrite\r\n");
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
            HLOG_DEBUG("HostUsbTargetDevice::FormatRequestForIoctl\r\n");
            return 0;
        };

        virtual WINUSB_INTERFACE_HANDLE STDMETHODCALLTYPE GetWinUsbHandle() override {
            HLOG_DEBUG("HostUsbTargetDevice::GetWinUsbHandle\r\n");
            return m_handle;
        }

        virtual UCHAR STDMETHODCALLTYPE GetNumInterfaces() override {
            HLOG_DEBUG("HostUsbTargetDevice::GetNumInterfaces\r\n");
            return m_configDesc ? m_configDesc->bNumInterfaces : 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveUsbInterface(
            /* [annotation][in] */
            _In_  UCHAR InterfaceIndex,
            /* [annotation][out] */
            _Out_  IWDFUsbInterface **ppUsbInterface) override {
                HLOG_DEBUG("HostUsbTargetDevice::RetrieveUsbInterface %x\r\n", InterfaceIndex);
                *ppUsbInterface = new HostUsbInterface(InterfaceIndex, m_handle);
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
                HLOG_DEBUG("HostUsbTargetDevice::FormatRequestForControlTransfer: %p %p\r\n",
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

                auto *myReq = (HostRequest *) pRequest;
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
                HLOG_DEBUG("HostUsbTargetDevice::RetrieveDeviceInformation %lx\r\n",
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
                HLOG_DEBUG("HostUsbTargetDevice::RetrieveDescriptor\r\n");
                return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrievePowerPolicy(
            /* [annotation][in] */
            _In_  ULONG PolicyType,
            /* [annotation][out][in] */
            _Inout_  ULONG *ValueLength,
            /* [annotation][out] */
            _Out_  PVOID Value) override {
                HLOG_DEBUG("HostUsbTargetDevice::RetrievePowerPolicy\r\n");
                return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE SetPowerPolicy(
            /* [annotation][in] */
            _In_  ULONG PolicyType,
            /* [annotation][in] */
            _In_  ULONG ValueLength,
            /* [annotation][in] */
            _In_  PVOID Value) override {
                HLOG_DEBUG("HostUsbTargetDevice::SetPowerPolicy %lu\r\n", (unsigned long)PolicyType);
                return 0;
        }

    private:
        WINUSB_INTERFACE_HANDLE m_handle;
        PUSB_CONFIGURATION_DESCRIPTOR m_configDesc = NULL;
};

class HostUsbTargetFactory : public IWDFUsbTargetFactory {
public:
        virtual ULONG STDMETHODCALLTYPE AddRef() override {
            HLOG_DEBUG("HostUsbTargetFactory::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() override {
            HLOG_DEBUG("HostUsbTargetFactory::Release\r\n");
            return 0;
        }
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"HostUsbTargetFactory::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE CreateUsbTargetDevice(
            _Out_  IWDFUsbTargetDevice **ppDevice) override {
            HLOG_DEBUG("HostUsbTargetFactory::CreateUsbTargetDevice\r\n");
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

            *ppDevice = new HostUsbTargetDevice(winusbHandle);
            return 0;
        }
};

struct HostDevice;

HostDevice *hostDevice = 0;


struct HostDevice : public IWDFDevice3 {
    public:
        HostDevice(IWDFDriver *driver, IUnknown *pCallbackInterface) : m_driver(driver) {
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
            std::wcout << L"HostDevice::QueryInterface " << str << std::endl;

            if(IsEqualIID(riid, IID_IWDFPropertyStoreFactory)) {
                HLOG_DEBUG("is IID_IWDFPropertyStoreFactory\r\n");
                *ppvObject = new HostPropertyStoreFactory();
            } else if (IsEqualIID(riid, IID_IWDFDevice3)) {
                HLOG_DEBUG("is IID_IWDFDevice3\r\n");
                *ppvObject = (IWDFDevice3*)this;
            } else if (IsEqualIID(riid, IID_IWDFUsbTargetFactory)) {
                HLOG_DEBUG("is IID_IWDFUsbTargetFactory\r\n");
                *ppvObject = new HostUsbTargetFactory();
            }
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("HostDevice::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("HostDevice::DeleteWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) {
            HLOG_DEBUG("HostDevice::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) {
            HLOG_DEBUG("HostDevice::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            HLOG_DEBUG("HostDevice::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            HLOG_DEBUG("HostDevice::ReleaseLock\r\n");
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
            HLOG_DEBUG("HostDevice::RetrieveDevicePropertyStore\r\n");
            *ppPropStore = new HostNamedPropertyStore();
            return 0;
        }


        virtual void STDMETHODCALLTYPE GetDriver(
            /* [annotation][out] */
            _Out_  IWDFDriver **ppWdfDriver){
            HLOG_DEBUG("HostDevice::GetDriver\r\n");
            *ppWdfDriver = m_driver;
        }


        virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceInstanceId(
            /* [annotation][unique][out][string] */
            _Out_opt_  PWSTR Buffer,
            /* [annotation][out][in] */
            _Inout_  DWORD *pdwSizeInChars){
            HLOG_DEBUG("HostDevice::RetrieveDeviceInstanceId\r\n");
            return 0;
        }


        virtual void STDMETHODCALLTYPE GetDefaultIoTarget(
            /* [annotation][out] */
            _Out_  IWDFIoTarget **ppWdfIoTarget){
            HLOG_DEBUG("HostDevice::GetDefaultIoTarget\r\n");
        }


        virtual HRESULT STDMETHODCALLTYPE CreateWdfFile(
            /* [annotation][string][unique][in] */
            _In_opt_  LPCWSTR pcwszFileName,
            /* [annotation][out] */
            _Out_  IWDFDriverCreatedFile **ppFile){
            HLOG_DEBUG("HostDevice::CreateWdfFile\r\n");
            return 0;
        }


        virtual void STDMETHODCALLTYPE GetDefaultIoQueue(
            /* [annotation][out] */
            _Out_  IWDFIoQueue **ppWdfIoQueue){
            HLOG_DEBUG("HostDevice::GetDefaultIoQueue\r\n");
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
            HLOG_DEBUG("HostDevice::CreateIoQueue (%p, %d, %d, %d, %d)\r\n",
                pCallbackInterface, (int)bDefaultQueue, (int)DispatchType, (int)bPowerManaged,
                (int)bAllowZeroLengthRequests);
            *ppIoQueue = hostQueue = new HostQueue(pCallbackInterface);
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
            HLOG_DEBUG("HostDevice::CreateDeviceInterface %ls\n", str);
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
            HLOG_DEBUG("HostDevice::AssignDeviceInterfaceState %ls=%d\n", str, Enable);
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceName(
            /* [annotation][unique][out][string] */
            _Out_writes_to_opt_(*pdwDeviceNameLength, *pdwDeviceNameLength)  PWSTR pDeviceName,
            /* [annotation][out][in] */
            _Inout_  DWORD *pdwDeviceNameLength){
            HLOG_DEBUG("HostDevice::RetrieveDeviceName %p %lu\r\n", pDeviceName, *pdwDeviceNameLength);
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
            HLOG_DEBUG("HostDevice::PostEvent\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE ConfigureRequestDispatching(
            /* [annotation][in] */
            _In_  IWDFIoQueue *pQueue,
            /* [annotation][in] */
            _In_  WDF_REQUEST_TYPE RequestType,
            /* [annotation][in] */
            _In_  BOOL Forward){
            HLOG_DEBUG("HostDevice::ConfigureRequestDispatching (%d, %d)\r\n",
                RequestType, Forward);
            return 0;
        }


        virtual void STDMETHODCALLTYPE SetPnpState(
            /* [annotation][in] */
            _In_  WDF_PNP_STATE State,
            /* [annotation][in] */
            _In_  WDF_TRI_STATE Value){
            HLOG_DEBUG("HostDevice::SetPnpState\r\n");
        }


        virtual WDF_TRI_STATE STDMETHODCALLTYPE GetPnpState(
            /* [annotation][in] */
            _In_  WDF_PNP_STATE State){
            HLOG_DEBUG("HostDevice::GetPnpState\r\n");
            return WdfFalse;
        }


        virtual void STDMETHODCALLTYPE CommitPnpState( void){
            HLOG_DEBUG("HostDevice::CommitPnpState\r\n");
        }


        virtual HRESULT STDMETHODCALLTYPE CreateRequest(
            /* [annotation][unique][in] */
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */
            _Out_  IWDFIoRequest **ppRequest){
            HLOG_DEBUG("HostDevice::CreateRequest");
            *ppRequest = new HostRequest(WdfRequestUsb, 0, nullptr, nullptr);
            HLOG_DEBUG(" = %p\r\n", *ppRequest);
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE CreateSymbolicLink(
            /* [annotation][unique][string][in] */
            _In_  PCWSTR pSymbolicLink){
            HLOG_DEBUG("HostDevice::CreateSymbolicLink\r\n");
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
            HLOG_DEBUG("HostDevice::AssignS0IdleSettings\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE StopIdle(
            /* [annotation][in] */
            _In_  BOOL WaitForD0){
            HLOG_DEBUG("HostDevice::StopIdle\r\n");
            return 0;
        }


        virtual void STDMETHODCALLTYPE ResumeIdle( void){
            goIdle = 1;
            HLOG_DEBUG("HostDevice::ResumeIdle\r\n");
        }


        virtual HRESULT STDMETHODCALLTYPE CreateSymbolicLinkWithReferenceString(
            /* [annotation][unique][string][in] */
            _In_  PCWSTR pSymbolicLink,
            /* [annotation][unique][string][in] */
            _In_opt_  PCWSTR pReferenceString){
            HLOG_DEBUG("HostDevice::CreateSymbolicLinkWithReferenceString\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE RegisterRemoteInterfaceNotification(
            /* [annotation][in] */
            _In_  LPCGUID pDeviceInterfaceGuid,
            /* [annotation][in] */
            _In_  BOOL IncludeExistingInterfaces){
            HLOG_DEBUG("HostDevice::RegisterRemoteInterfaceNotification\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE CreateRemoteInterface(
            /* [annotation][in] */
            _In_  IWDFRemoteInterfaceInitialize *pRemoteInterfaceInit,
            /* [annotation][unique][in] */
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][out] */
            _Out_  IWDFRemoteInterface **ppRemoteInterface){
            HLOG_DEBUG("HostDevice::CreateRemoteInterface\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE CreateRemoteTarget(
            /* [annotation][unique][in] */
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */
            _Out_  IWDFRemoteTarget **ppRemoteTarget){
            HLOG_DEBUG("HostDevice::CreateRemoteTarget\r\n");
            return 0;
        }


        virtual void STDMETHODCALLTYPE GetDeviceStackIoTypePreference(
            /* [annotation][out] */
            _Out_  WDF_DEVICE_IO_TYPE *ReadWritePreference,
            /* [annotation][out] */
            _Out_  WDF_DEVICE_IO_TYPE *IoControlPreference){
            HLOG_DEBUG("HostDevice::GetDeviceStackIoTypePreference\r\n");
        }


        virtual HRESULT STDMETHODCALLTYPE AssignSxWakeSettings(
            /* [annotation][in] */
            _In_  DEVICE_POWER_STATE DxState,
            /* [annotation][in] */
            _In_  WDF_POWER_POLICY_SX_WAKE_USER_CONTROL UserControlOfWakeSettings,
            /* [annotation][in] */
            _In_  WDF_TRI_STATE Enabled){
            HLOG_DEBUG("HostDevice::AssignSxWakeSettings\r\n");
            return 0;
        }


        virtual POWER_ACTION STDMETHODCALLTYPE GetSystemPowerAction( void){
            HLOG_DEBUG("HostDevice::GetSystemPowerAction\r\n");
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
            HLOG_DEBUG("HostDevice::MapIoSpace\r\n");
            return 0;
        }


        virtual void STDMETHODCALLTYPE UnmapIoSpace(
            /* [annotation][in] */
            _In_  void *PseudoBaseAddress,
            /* [annotation][in] */
            _In_  SIZE_T NumberOfBytes){
            HLOG_DEBUG("HostDevice::UnmapIoSpace\r\n");
        }


        virtual void *STDMETHODCALLTYPE GetHardwareRegisterMappedAddress(
            /* [annotation][in] */
            _In_  void *PseudoBaseAddress){
            HLOG_DEBUG("HostDevice::GetHardwareRegisterMappedAddress\r\n");
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
            HLOG_DEBUG("HostDevice::ReadFromHardware\r\n");
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
            HLOG_DEBUG("HostDevice::WriteToHardware\r\n");
        }


        virtual HRESULT STDMETHODCALLTYPE CreateInterrupt(
            /* [annotation][in] */
            _In_  PWUDF_INTERRUPT_CONFIG Configuration,
            /* [annotation][out] */
            _Out_  IWDFInterrupt **ppInterrupt){
            HLOG_DEBUG("HostDevice::CreateInterrupt\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE CreateWorkItem(
            /* [annotation][in] */
            _In_  PWUDF_WORKITEM_CONFIG pConfig,
            /* [annotation][in] */
            _In_  IWDFObject *pParentObject,
            /* [annotation][out] */
            _Out_  IWDFWorkItem **ppWorkItem){
            HLOG_DEBUG("HostDevice::CreateWorkItem\r\n");
            return 0;
        }


        virtual HRESULT STDMETHODCALLTYPE AssignS0IdleSettingsEx(
            /* [annotation][in] */
            _In_  PWUDF_DEVICE_POWER_POLICY_IDLE_SETTINGS IdleSettings){
            HLOG_DEBUG("HostDevice::AssignS0IdleSettingsEx\r\n");
            return 0;
        }
};

struct HostDriver : public IWDFDriver {
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"HostDriver::QueryInterface " << str << std::endl;
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("HostDriver::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("HostDriver::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            HLOG_DEBUG("HostDriver::DeleteWdfObject\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) {
            HLOG_DEBUG("HostDriver::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) {
            HLOG_DEBUG("HostDriver::RetrieveContext\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            HLOG_DEBUG("HostDriver::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            HLOG_DEBUG("HostDriver::ReleaseLock\r\n");
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE CreateDevice(
            /* [annotation][in] */
            _In_  IWDFDeviceInitialize *pDeviceInit,
            /* [annotation][unique][in] */
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][out] */
            _Out_  IWDFDevice **ppDevice) {
            HLOG_DEBUG("HostDriver::CreateDevice\r\n");
            *ppDevice = hostDevice = new HostDevice(this, pCallbackInterface);
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
            HLOG_DEBUG("HostDriver::CreateWdfObject\r\n");
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
            HLOG_DEBUG("HostDriver::CreatePreallocatedWdfMemory %p (%zu) = ",
                pBuff, (size_t)BufferSize);
            *ppWdfMemory = new HostMem(pBuff, BufferSize);
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
            HLOG_DEBUG("HostDriver::CreateWdfMemory %zu = ", (size_t)BufferSize);
            // FIXME: Free this
            void *mem = malloc(BufferSize);
            memset(mem, 0, BufferSize);
            *ppWdfMemory = new HostMem(mem, BufferSize);
            HLOG_DEBUG(" %p\r\n", *ppWdfMemory);
            return 0;
        }

        virtual BOOL STDMETHODCALLTYPE IsVersionAvailable(
            /* [annotation][in] */
            _In_  UMDF_VERSION_DATA *pMinimumVersion) {
            HLOG_DEBUG("HostDriver::IsVersionAvailable\r\n");
            return true;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveVersionString(
            /* [annotation][unique][out][string] */
            _Out_writes_to_opt_(*pdwVersionLength, *pdwVersionLength)  PWSTR pVersion,
            /* [annotation][out][in] */
            _Inout_  DWORD *pdwVersionLength) {
            HLOG_DEBUG("HostDriver::RetrieveVersionString\r\n");
            return 0;
        }
};

class HostDevInit : public IWDFDeviceInitialize {
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) {
            HLOG_DEBUG("HostDevInit::QueryInterface\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE AddRef() {
            HLOG_DEBUG("HostDevInit::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() {
            HLOG_DEBUG("HostDevInit::Release\r\n");
            return 0;
        }

    public:
        virtual void STDMETHODCALLTYPE SetFilter( void) {
            HLOG_DEBUG("HostDevInit::SetFilter\r\n");
        }

        virtual void STDMETHODCALLTYPE SetLockingConstraint(
            /* [annotation][in] */
            _In_  WDF_CALLBACK_CONSTRAINT LockType) {
            HLOG_DEBUG("HostDevInit::SetLockingConstraint\r\n");
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
            HLOG_DEBUG("HostDevInit::RetrieveDevicePropertyStore\r\n");
            *ppPropStore = new HostNamedPropertyStore();
            return 0;
        }

        virtual void STDMETHODCALLTYPE SetPowerPolicyOwnership(
            /* [annotation][in] */
            _In_  BOOL fTrue) {
            HLOG_DEBUG("HostDevInit::SetPowerPolicyOwnership %d\r\n", fTrue);
        }

        virtual void STDMETHODCALLTYPE AutoForwardCreateCleanupClose(
            /* [annotation][in] */
            _In_  WDF_TRI_STATE State) {
            HLOG_DEBUG("HostDevInit::AutoForwardCreateCleanupClose\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceInstanceId(
            /* [annotation][unique][out][string] */
            _Out_opt_  PWSTR Buffer,
            /* [annotation][out][in] */
            _Inout_  DWORD *pdwSizeInChars) {
            HLOG_DEBUG("HostDevInit::RetrieveDeviceInstanceId\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE SetPnpCapability(
            /* [annotation][in] */
            _In_  WDF_PNP_CAPABILITY Capability,
            /* [annotation][in] */
            _In_  WDF_TRI_STATE Value) {
            HLOG_DEBUG("HostDevInit::SetPnpCapability\r\n");
        }

        virtual WDF_TRI_STATE STDMETHODCALLTYPE GetPnpCapability(
            /* [annotation][in] */
            _In_  WDF_PNP_CAPABILITY Capability) {
            HLOG_DEBUG("HostDevInit::GetPnpCapability\r\n");
            return WdfFalse;
        }
};

class HostResourceList : public IWDFCmResourceList {
public:
        HostResourceList(const char *type) {
            HLOG_DEBUG("HostResourceList(%s)\r\n", type);
            m_type = type;
        }

        // IUnknown methods (simplified)
        virtual ULONG STDMETHODCALLTYPE AddRef() override {
            HLOG_DEBUG("HostResourceList::AddRef\r\n");
            return 0;
        }
        virtual ULONG STDMETHODCALLTYPE Release() override {
            HLOG_DEBUG("HostResourceList::Release\r\n");
            return 0;
        }
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override {
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"HostResourceList::QueryInterface " << str << std::endl;
            *ppvObject = this;
            HLOG_DEBUG("ppvObject=%p\r\n", *ppvObject);
            return 0;
        }

        virtual ULONG STDMETHODCALLTYPE GetCount() override {
            HLOG_DEBUG("HostResourceList::GetCount %s\r\n", m_type);
            return m_count;
        }

        virtual PCM_PARTIAL_RESOURCE_DESCRIPTOR STDMETHODCALLTYPE GetDescriptor(ULONG index) override {
            HLOG_DEBUG("HostResourceList::GetDescriptor %s %lu\r\n", m_type, index);
            return (index < m_count) ? &m_descriptors[index] : nullptr;
        }

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject() override {
            HLOG_DEBUG("HostResourceList::DeleteWdfObject\r\n");
            return 0;
        }

        virtual void STDMETHODCALLTYPE AcquireLock() override {
            HLOG_DEBUG("HostResourceList::AcquireLock\r\n");
        }

        virtual void STDMETHODCALLTYPE ReleaseLock() override {
            HLOG_DEBUG("HostResourceList::ReleaseLock\r\n");
        }

        virtual HRESULT STDMETHODCALLTYPE AssignContext(
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */
            _In_opt_ __drv_aliasesMem  void *pContext) override {
            HLOG_DEBUG("HostResourceList::AssignContext\r\n");
            return 0;
        }

        virtual HRESULT STDMETHODCALLTYPE RetrieveContext(
            /* [annotation][out] */
            _Out_  void **ppvContext) override {
            HLOG_DEBUG("HostResourceList::RetrieveContext\r\n");
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
