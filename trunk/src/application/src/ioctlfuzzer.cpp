#include "stdafx.h"

#define SERVICE_NAME "IOCTLfuzzer"
#define DRIVER_FILE_NAME "IOCTLfuzzer.sys"

#define RESOURCE_NAME_DRIVER "DRIVER"

#define DBG_LOG_FILE "ioctlfuzzer.log"

USER_MODE_DATA m_UserModeData;
DWORD m_dwFuzzThreadId = 0;
HANDLE hDevice = NULL;

// offset of nt!KiDispatchException()
DWORD m_KiDispatchException_Offset = 0;

// don't show any ioctls (usefull for exceptions only monitoring)
BOOL m_bSkipIoctls = FALSE;

// start fuzzing/monitoring at the boot time after the next reboot
BOOL m_bBootFuzzing = FALSE;

// defined in debug.cpp
extern HANDLE hDbgLogfile;
//--------------------------------------------------------------------------------------
BOOL GetNormalizedSymbolName(char *lpszName, char *lpszNormalizedName, int NameLen)
{
    int StrLen;
    char *lpszStr = lpszName;

    if (!strncmp(lpszName, "??", min(lstrlen(lpszName), 2)) ||
        !strncmp(lpszName, "__imp__", min(lstrlen(lpszName), 7)))
    {
        if (NameLen > lstrlen(lpszName))
        {
            strcpy(lpszNormalizedName, lpszName);
            return TRUE;
        }

        return FALSE;
    }

    if (*lpszStr == '_' || *lpszStr == '@')
    {
        lpszStr++;
    }

    for (StrLen = 0; StrLen < lstrlen(lpszStr); StrLen++)
    {
        if (lpszStr[StrLen] == '@')
        {
            break;
        }
    }

    if (NameLen > StrLen)
    {
        strncpy(lpszNormalizedName, lpszStr, StrLen);
        lpszNormalizedName[StrLen] = 0;
        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
typedef struct _ENUM_SYM_PARAM
{
    ULONGLONG Address;
    char    *lpszName;

} ENUM_SYM_PARAM,
*PENUM_SYM_PARAM;

BOOL CALLBACK EnumSymbolsProc(
    PSYMBOL_INFO pSymInfo,
    ULONG SymbolSize,
    PVOID UserContext)
{
    PENUM_SYM_PARAM Param = (PENUM_SYM_PARAM)UserContext;
    char szName[0x100];

    if (GetNormalizedSymbolName(pSymInfo->Name, szName, sizeof(szName)))
    {
        if (!lstrcmp(szName, Param->lpszName))
        {
            Param->Address = (ULONGLONG)pSymInfo->Address;
            return FALSE;
        }        
    }
    
    return TRUE;
}
//--------------------------------------------------------------------------------------
ULONGLONG GetSymbolByName(char *lpszModuleName, HMODULE hModule, char *lpszName)
{
    ULONGLONG Ret = 0;

    // try to load debug symbols for module
    if (SymLoadModuleEx(GetCurrentProcess(), NULL, lpszModuleName, NULL, (DWORD64)hModule, 0, NULL, 0))
    {
        ENUM_SYM_PARAM Param;

        Param.Address = NULL;
        Param.lpszName = lpszName;

        // get specified symbol address by name
        if (!SymEnumSymbols(
            GetCurrentProcess(),
            (DWORD64)hModule,
            NULL,
            EnumSymbolsProc,
            &Param))
        {                    
            DbgMsg(__FILE__, __LINE__, "SymEnumSymbols() ERROR %d\n", GetLastError());
        }

        if (Param.Address == NULL)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Can't locate symbol\n");
        }
        else
        {
            Ret = Param.Address;
        }

        // unload symbols
        SymUnloadModule64(GetCurrentProcess(), (DWORD64)hModule);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "SymLoadModuleEx() ERROR %d\n", GetLastError());
    }

    return Ret;
}
//--------------------------------------------------------------------------------------
PVOID GetSysInf(SYSTEM_INFORMATION_CLASS InfoClass)
{
    NTSTATUS ns = 0;
    ULONG RetSize = 0, Size = 0x100;
    PVOID Info = NULL;

    GET_NATIVE(NtQuerySystemInformation);

    while (true) 
    {    
        // allocate memory for system information
        if ((Info = M_ALLOC(Size)) == NULL) 
        {
            printf("M_ALLOC() fails\n");
            return NULL;
        }

        // query information
        RetSize = 0;
        ns = f_NtQuerySystemInformation(InfoClass, Info, Size, &RetSize);
        if (ns == STATUS_INFO_LENGTH_MISMATCH)
        {       
            // buffer is too small
            M_FREE(Info);
            Info = NULL;

            if (RetSize > 0)
            {
                // allocate more memory and try again
                Size = RetSize + 0x100;
            }            
            else
            {
                break;
            }
        }
        else
        {
            break;
        }
    }

    if (!NT_SUCCESS(ns))
    {
        printf("NtQuerySystemInformation() fails; status: 0x%.8x\n", ns);

        if (Info)
        {
            M_FREE(Info);
        }

        return NULL;
    }

    return Info;
}

//--------------------------------------------------------------------------------------
DWORD GetKernelSymbolOffset(char *lpszSymbolName)
{
    DWORD Ret = 0;

    // get system modules information
    PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)GetSysInf(SystemModuleInformation);
    if (Info)
    {
        char *lpszKernelName = (char *)Info->Modules[0].FullPathName + Info->Modules[0].OffsetToFileName;
        char szKernelPath[MAX_PATH];

        // get full kernel image path
        GetSystemDirectory(szKernelPath, MAX_PATH);
        lstrcat(szKernelPath, "\\");
        lstrcat(szKernelPath, lpszKernelName);

        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Using kernel binary '%s'\r\n", szKernelPath);

        // load kernel module
        HMODULE hModule = LoadLibraryEx(szKernelPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (hModule)
        {
            // get symbol offset
            LARGE_INTEGER Addr;
            Addr.QuadPart = GetSymbolByName(szKernelPath, hModule, lpszSymbolName);
            if (Addr.QuadPart > 0)
            {
                Addr.QuadPart -= (ULONGLONG)hModule;
                Ret = Addr.LowPart;
            }                       

            FreeLibrary(hModule);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "LoadLibraryEx() ERROR %d\r\n", GetLastError());
        }

        M_FREE(Info);
    }

    return Ret;
}
//--------------------------------------------------------------------------------------
IXMLDOMDocument *pXMLDoc = NULL;

IXMLDOMNode *LoadXml(PWSTR lpwcData)
{
    BOOL bOk = FALSE;
    VARIANT_BOOL status;    
    IXMLDOMNode *pIDOMRootNode = NULL;

    typedef HRESULT (WINAPI * func_CoCreateInstance)(
        REFCLSID rclsid, 
        LPUNKNOWN pUnkOuter,
        DWORD dwClsContext, 
        REFIID riid, 
        LPVOID FAR* ppv
    );

    func_CoCreateInstance f_CoCreateInstance = (func_CoCreateInstance)
        GetProcAddress(
        LoadLibrary("ole32.dll"),
        "CoCreateInstance"
    );
    if (f_CoCreateInstance == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "GetProcAddress() ERROR %d\r\n", GetLastError());
        return FALSE;
    } 

    // create new msxml document instance
    HRESULT hr = f_CoCreateInstance(CLSID_DOMDocument, NULL, CLSCTX_INPROC_SERVER, 
        IID_IXMLDOMDocument, (PVOID *)&pXMLDoc);
    if (FAILED(hr)) 
    {
        DbgMsg(__FILE__, __LINE__, "CoCreateInstance() ERROR 0x%.8x\r\n", hr);
        return NULL;
    }    

    hr = pXMLDoc->loadXML(lpwcData, &status);
    if (status != VARIANT_TRUE)
    {
        DbgMsg(__FILE__, __LINE__, "pXMLDoc->load() ERROR 0x%.8x\r\n", hr);
        goto end;
    }

    // если xml загружен, получаем список корневых узлов
    IXMLDOMNodeList *pIDOMRootNodeList;    
    hr = pXMLDoc->get_childNodes(&pIDOMRootNodeList);
    if (SUCCEEDED(hr))
    {        
        if (pIDOMRootNode = ConfGetListNodeByName(L"cfg", pIDOMRootNodeList))
        {
            bOk = TRUE;
        }            

        pIDOMRootNodeList->Release();        
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "pXMLDoc->get_childNodes() ERROR 0x%.8x\r\n", hr);
    }    

end:

    if (!bOk)
    {
        // произошла ошибка
        // освобождаем дескриптор докуммента
        pXMLDoc->Release();
    }

    return pIDOMRootNode;
}
//--------------------------------------------------------------------------------------
BOOL GetOption(IXMLDOMNode *pIDOMNode, PWSTR lpwcName, PBOOL pbVal)
{
    BOOL bRet = FALSE;
    char *lpszVal = NULL;

    if (ConfAllocGetTextByNameA(pIDOMNode, lpwcName, &lpszVal))
    {
        bRet = TRUE;

        if (!strcmp(strlwr(lpszVal), "true"))
        {
            *pbVal = TRUE;
        }
        else if (!strcmp(strlwr(lpszVal), "false"))
        {
            *pbVal = FALSE;
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "WARNING: invalid value for option '%ws'\r\n", lpwcName);
            bRet = FALSE;
        }

        M_FREE(lpszVal);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
void ParseAllowDenySection(IXMLDOMNode *pIDOMNode, BOOL bAllow)
{
    // get drivers node
    IXMLDOMNode *pIDOMAllowNode = ConfGetNodeByName(L"drivers", pIDOMNode);
    if (pIDOMAllowNode)                
    {
        IXMLDOMNodeList *pIDOMNodeList;
        // enumerate drivers
        HRESULT hr = pIDOMAllowNode->get_childNodes(&pIDOMNodeList);
        if (SUCCEEDED(hr))
        {
            LONG len = 0;
            pIDOMNodeList->get_length(&len);

            DbgMsg(__FILE__, __LINE__, "DRIVERS:\r\n");

            for (int i = 0; i < len; i++)
            { 
                IXMLDOMNode *pIDOMChildNode;
                // get driver name
                hr = pIDOMNodeList->get_item(i, &pIDOMChildNode);
                if (SUCCEEDED(hr))
                {
                    char *lpszName;
                    if (ConfGetNodeTextA(pIDOMChildNode, &lpszName))
                    {
                        DbgMsg(__FILE__, __LINE__, "- '%s'\r\n", lpszName);

                        DWORD dwBuffSize = sizeof(REQUEST_BUFFER) + lstrlen(lpszName) + 1;
                        PREQUEST_BUFFER Buff = (PREQUEST_BUFFER)M_ALLOC(dwBuffSize);
                        if (Buff)
                        {
                            Buff->Code = C_ADD_DRIVER;
                            Buff->bAllow = bAllow;
                            lstrcpy(Buff->Buff, lpszName);

                            DrvDeviceRequest(Buff, dwBuffSize);                                        

                            M_FREE(Buff);
                        }
                        else
                        {
                            DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\r\n", GetLastError());
                        }

                        M_FREE(lpszName);
                    }

                    pIDOMChildNode->Release();                                
                }
            }                        

            pIDOMNodeList->Release();
        }

        pIDOMAllowNode->Release();
    }

    // get devices node
    pIDOMAllowNode = ConfGetNodeByName(L"devices", pIDOMNode);
    if (pIDOMAllowNode)                
    {
        IXMLDOMNodeList *pIDOMNodeList;
        // enumerate devices
        HRESULT hr = pIDOMAllowNode->get_childNodes(&pIDOMNodeList);
        if (SUCCEEDED(hr))
        {
            LONG len = 0;
            pIDOMNodeList->get_length(&len);

            DbgMsg(__FILE__, __LINE__, "DEVICES:\r\n");

            for (int i = 0; i < len; i++)
            { 
                IXMLDOMNode *pIDOMChildNode;
                // get device name
                hr = pIDOMNodeList->get_item(i, &pIDOMChildNode);
                if (SUCCEEDED(hr))
                {
                    char *lpszName;
                    if (ConfGetNodeTextA(pIDOMChildNode, &lpszName))
                    {
                        DbgMsg(__FILE__, __LINE__, "- '%s'\r\n", lpszName);

                        DWORD dwBuffSize = sizeof(REQUEST_BUFFER) + lstrlen(lpszName) + 1;
                        PREQUEST_BUFFER Buff = (PREQUEST_BUFFER)M_ALLOC(dwBuffSize);
                        if (Buff)
                        {
                            Buff->Code = C_ADD_DEVICE;
                            Buff->bAllow = bAllow;
                            lstrcpy(Buff->Buff, lpszName);

                            DrvDeviceRequest(Buff, dwBuffSize);                                        

                            M_FREE(Buff);
                        }
                        else
                        {
                            DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\r\n", GetLastError());
                        }

                        M_FREE(lpszName);
                    }

                    pIDOMChildNode->Release();                                
                }
            }                        

            pIDOMNodeList->Release();
        }

        pIDOMAllowNode->Release();
    }

    // get IOCTLs node
    pIDOMAllowNode = ConfGetNodeByName(L"ioctls", pIDOMNode);
    if (pIDOMAllowNode)                
    {
        IXMLDOMNodeList *pIDOMNodeList;
        // enumerate IOCTLs
        HRESULT hr = pIDOMAllowNode->get_childNodes(&pIDOMNodeList);
        if (SUCCEEDED(hr))
        {
            LONG len = 0;
            pIDOMNodeList->get_length(&len);

            DbgMsg(__FILE__, __LINE__, "IOCTL CODES:\r\n");

            for (int i = 0; i < len; i++)
            { 
                IXMLDOMNode *pIDOMChildNode;
                // get IOCTL code value
                hr = pIDOMNodeList->get_item(i, &pIDOMChildNode);
                if (SUCCEEDED(hr))
                {
                    char *lpszName;
                    if (ConfGetNodeTextA(pIDOMChildNode, &lpszName))
                    {
                        DWORD dwIoctlCode = 0;
                        if (StrToIntEx(lpszName, STIF_SUPPORT_HEX, (int *)&dwIoctlCode))
                        {
                            DbgMsg(__FILE__, __LINE__, "- 0x%.8x\r\n", dwIoctlCode);

                            REQUEST_BUFFER Buff;
                            ZeroMemory(&Buff, sizeof(Buff));

                            Buff.Code = C_ADD_IOCTL;
                            Buff.bAllow = bAllow;
                            Buff.IoctlCode = dwIoctlCode;

                            DrvDeviceRequest(&Buff, sizeof(REQUEST_BUFFER));                                        
                        }                                    

                        M_FREE(lpszName);
                    }

                    pIDOMChildNode->Release();                                
                }
            }                        

            pIDOMNodeList->Release();
        }

        pIDOMAllowNode->Release();
    }

    // get processes node
    pIDOMAllowNode = ConfGetNodeByName(L"processes", pIDOMNode);
    if (pIDOMAllowNode)                
    {
        IXMLDOMNodeList *pIDOMNodeList;
        // enumerate processes
        HRESULT hr = pIDOMAllowNode->get_childNodes(&pIDOMNodeList);
        if (SUCCEEDED(hr))
        {
            LONG len = 0;
            pIDOMNodeList->get_length(&len);

            DbgMsg(__FILE__, __LINE__, "PROCESSES:\r\n");

            for (int i = 0; i < len; i++)
            { 
                IXMLDOMNode *pIDOMChildNode;
                // get process name
                hr = pIDOMNodeList->get_item(i, &pIDOMChildNode);
                if (SUCCEEDED(hr))
                {
                    char *lpszName;
                    if (ConfGetNodeTextA(pIDOMChildNode, &lpszName))
                    {
                        printf("- '%s'\r\n", lpszName);

                        DWORD dwBuffSize = sizeof(REQUEST_BUFFER) + lstrlen(lpszName) + 1;
                        PREQUEST_BUFFER Buff = (PREQUEST_BUFFER)M_ALLOC(dwBuffSize);
                        if (Buff)
                        {
                            Buff->Code = C_ADD_PROCESS;
                            Buff->bAllow = bAllow;
                            lstrcpy(Buff->Buff, lpszName);

                            DrvDeviceRequest(Buff, dwBuffSize);                                        

                            M_FREE(Buff);
                        }
                        else
                        {
                            DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\r\n", GetLastError());
                        }

                        M_FREE(lpszName);
                    }

                    pIDOMChildNode->Release();                                
                }
            }                        

            pIDOMNodeList->Release();
        }

        pIDOMAllowNode->Release();
    }
}
//--------------------------------------------------------------------------------------
void ParseConfig(char *lpszCfgFileName)
{
    PVOID Data = NULL;
    DWORD dwDataSize = 0;
    // read config file
    if (ReadFromFile(lpszCfgFileName, &Data, &dwDataSize))
    {
        PWSTR lpwcData = (PWSTR)M_ALLOC((dwDataSize + 1) * sizeof(WCHAR));
        if (lpwcData)
        {
            MultiByteToWideChar(CP_ACP, 0, (char *)Data, dwDataSize, lpwcData, dwDataSize);

            IXMLDOMNode *pIDOMNode;
            // load xml
            if (pIDOMNode = LoadXml(lpwcData))
            {
                REQUEST_BUFFER Buff;
                ZeroMemory(&Buff, sizeof(Buff));

                // create logfile, if option is set
                char *lpszLogFilePath = NULL;
                if (ConfAllocGetTextByNameA(pIDOMNode, L"log_file", &lpszLogFilePath))
                {
                    HANDLE hNewLogfile = CreateFile(
                        lpszLogFilePath, 
                        GENERIC_READ | GENERIC_WRITE, 
                        FILE_SHARE_READ | FILE_SHARE_WRITE, 
                        NULL, 
                        OPEN_ALWAYS, 
                        FILE_ATTRIBUTE_NORMAL, 
                        NULL
                    );
                    if (hNewLogfile != INVALID_HANDLE_VALUE)
                    {
                        SetFilePointer(hNewLogfile, 0, NULL, FILE_END);

                        if (hDbgLogfile != INVALID_HANDLE_VALUE)
                        {   
                            // close old debug log
                            CloseHandle(hDbgLogfile);
                            hDbgLogfile = hNewLogfile;
                        }
                    }
                    else
                    {
                        DbgMsg(__FILE__, __LINE__, "CreateFile() ERROR %d\r\n", GetLastError());
                        DbgMsg(__FILE__, __LINE__, "Error while creating/opening logfile at '%s'.\r\n", lpszLogFilePath);
                    }

                    M_FREE(lpszLogFilePath);
                }

                // parse allow node
                IXMLDOMNode *pIDOMAllowNode = ConfGetNodeByName(L"allow", pIDOMNode);
                if (pIDOMAllowNode)                
                {
                    ParseAllowDenySection(pIDOMAllowNode, TRUE);
                    pIDOMAllowNode->Release();
                }

                // parse deny node
                IXMLDOMNode *pIDOMDenyNode = ConfGetNodeByName(L"deny", pIDOMNode);
                if (pIDOMDenyNode)                
                {
                    ParseAllowDenySection(pIDOMDenyNode, FALSE);
                    pIDOMDenyNode->Release();
                }

                // parse options
                BOOL bLogRequests = TRUE, bDebugLogRequests = TRUE;                
                BOOL bFuzeRequests = FALSE, bFuzeSize = FALSE;
                BOOL bHexDump = FALSE; 
                BOOL bFairFuzzing = FALSE;

                GetOption(pIDOMNode, L"hex_dump", &bHexDump);
                GetOption(pIDOMNode, L"log_requests", &bLogRequests);
                GetOption(pIDOMNode, L"debug_log_requests", &bDebugLogRequests);
                GetOption(pIDOMNode, L"fuze_requests", &bFuzeRequests);
                GetOption(pIDOMNode, L"fuze_size", &bFuzeSize);
                GetOption(pIDOMNode, L"fair_fuzzing", &bFairFuzzing);

                DbgMsg(__FILE__, __LINE__, "PROGRAM OPTIONS:\r\n");

                #define STROPT(_x_) ((_x_)?"Yes":"No")
                DbgMsg(__FILE__, __LINE__, "           'hex_dump': %s\r\n", STROPT(bHexDump));
                DbgMsg(__FILE__, __LINE__, "       'log_requests': %s\r\n", STROPT(bLogRequests));
                DbgMsg(__FILE__, __LINE__, " 'debug_log_requests': %s\r\n", STROPT(bDebugLogRequests));
                DbgMsg(__FILE__, __LINE__, "      'fuze_requests': %s\r\n", STROPT(bFuzeRequests));
                DbgMsg(__FILE__, __LINE__, "          'fuze_size': %s\r\n", STROPT(bFuzeSize));
                DbgMsg(__FILE__, __LINE__, "       'fair_fuzzing': %s\r\n", STROPT(bFairFuzzing));

                // create logfile, if option is set
                char *lpszFuzzingType = NULL;
                if (ConfAllocGetTextByNameA(pIDOMNode, L"fuzzing_type", &lpszFuzzingType))
                {
                    if (!strcmp(lpszFuzzingType, "random"))
                    {
                        Buff.Options.FuzzingType = FuzzingType_Random;
                        DbgMsg(__FILE__, __LINE__, "'fuzzing_type' has been set to 'random'\r\n");
                    }
                    else if (!strcmp(lpszFuzzingType, "dwords"))
                    {
                        Buff.Options.FuzzingType = FuzzingType_Dword;
                        DbgMsg(__FILE__, __LINE__, "'fuzzing_type' has been set to 'dwords'\r\n");
                    }
                    else
                    {
                        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() WARNING: Invalid value for 'fuzzing_type' option\r\n");
                        Buff.Options.FuzzingType = FuzzingType_Random;
                    }

                    M_FREE(lpszFuzzingType);
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, __FUNCTION__"() WARNING: 'fuzzing_type' option is not set (using default)\r\n");
                    Buff.Options.FuzzingType = FuzzingType_Random;
                }

                Buff.Code = C_SET_OPTIONS;
                Buff.Options.UserModeData = &m_UserModeData;
                Buff.Options.FuzzThreadId = m_dwFuzzThreadId;
                Buff.Options.KiDispatchException_Offset = m_KiDispatchException_Offset;
                Buff.Options.Options = FUZZ_OPT_LOG_IOCTLS;

                if (bHexDump)
                {
                    Buff.Options.Options |= FUZZ_OPT_HEXDUMP;
                }

                if (bLogRequests)
                {
                    Buff.Options.Options |= FUZZ_OPT_LOG;
                }

                if (bDebugLogRequests)
                {
                    Buff.Options.Options |= FUZZ_OPT_DEBUGLOG;
                }

                if (bFuzeRequests)
                {
                    Buff.Options.Options |= FUZZ_OPT_FUZZ;
                }

                if (bFuzeSize)
                {
                    Buff.Options.Options |= FUZZ_OPT_FUZZSIZE;
                }

                if (bFairFuzzing)
                {
                    Buff.Options.Options |= FUZZ_OPT_FAIRFUZZ;
                }

                if (m_bBootFuzzing)
                {
                    Buff.Options.Options |= FUZZ_OPT_BOOTFUZZ;
                }

                // send options to driver
                DrvDeviceRequest(&Buff, sizeof(REQUEST_BUFFER));                

                pIDOMNode->Release();
                pXMLDoc->Release();
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\r\n", GetLastError());
        }

        M_FREE(Data);
    }
}
//--------------------------------------------------------------------------------------
void SetDefaultOptions(void)
{
    REQUEST_BUFFER Buff;
    ZeroMemory(&Buff, sizeof(Buff));

    Buff.Code = C_SET_OPTIONS;
    Buff.Options.Options = FUZZ_OPT_LOG | FUZZ_OPT_DEBUGLOG;

    if (!m_bSkipIoctls)
    {
        Buff.Options.Options |= FUZZ_OPT_LOG_IOCTLS;
    }
    
    if (m_bBootFuzzing)
    {
        Buff.Options.Options |= FUZZ_OPT_BOOTFUZZ;
    }

    Buff.Options.FuzzingType = FuzzingType_Random;
    Buff.Options.KiDispatchException_Offset = m_KiDispatchException_Offset;

    // send options to driver
    DrvDeviceRequest(&Buff, sizeof(REQUEST_BUFFER));
}
//--------------------------------------------------------------------------------------
DWORD WINAPI ApcThread(LPVOID lpParam)
{
    while (true)
    {
        SleepEx(INFINITE, TRUE);
    }

    return 0;
}
//--------------------------------------------------------------------------------------
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) 
{ 
    if (fdwCtrlType == CTRL_C_EVENT || 
        fdwCtrlType == CTRL_CLOSE_EVENT) 
    { 
        // Handle the CTRL-C signal. 
        DbgMsg(__FILE__, __LINE__, "Stopping application, please wait...\r\n");

        CloseHandle(hDevice);

        if (MessageBox(0,
            "Warning!\r\n"
            "Unloading of a kernel driver may be unsafe.\r\n"
            "Press <YES> to unload it, or <NO> for just a program termination.",
            "Exit from program", MB_YESNO | MB_ICONWARNING) == IDYES)
        {
            DrvServiceStop(SERVICE_NAME);
        }

        ExitProcess(0);
    } 

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOL GetResPayload(HMODULE hModule, char *lpszResourceName, PVOID *Data, DWORD *dwDataSize)
{
    HRSRC hRc = FindResource(hModule, lpszResourceName, "BINRES");
    if (hRc)
    {
        HGLOBAL hResData = LoadResource(hModule, hRc);
        if (hResData)
        {
            PVOID ResData = LockResource(hResData);
            if (ResData)
            {
                *dwDataSize = SizeofResource(hModule, hRc);
                if (*Data = M_ALLOC(*dwDataSize))
                {
                    memcpy(*Data, ResData, *dwDataSize);
                    return TRUE;
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\r\n", GetLastError());
                }                
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "LockResource() fails\r\n");
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "LoadResource() fails\r\n");
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "FindResource() fails\r\n");
    }

    return FALSE;
} 
//--------------------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{
    char szDriverFileName[MAX_PATH], szServiceFileName[MAX_PATH], *lpszConfigPath = NULL;
    BOOL bUninstall = FALSE, bShowExceptions = FALSE;

    GetSystemDirectory(szDriverFileName, sizeof(szDriverFileName));
    lstrcat(szDriverFileName, "\\drivers\\" DRIVER_FILE_NAME);
    lstrcpy(szServiceFileName, "system32\\drivers\\" DRIVER_FILE_NAME);

    DbgInit(DBG_PIPE_NAME_A, DBG_LOG_FILE);

    char szProductVersion[0x100] = "<unknown>";  
    char szProcessFileName[MAX_PATH];
    GetModuleFileName(GetModuleHandle(NULL), szProcessFileName, sizeof(szProcessFileName));
    
    if (argc > 1)
    {
        for (int i = 1; i < argc; i++)
        {
            if (!lstrcmp(argv[i], "--boot"))
            {
                // bootfuzzing mode has been enabled
                m_bBootFuzzing = TRUE;
            }
            else if (!lstrcmp(argv[i], "--uninstall"))
            {
                // uninstall service/driver and exit
                bUninstall = TRUE;
            }
            else if (!lstrcmp(argv[i], "--exceptions"))
            {
                // log exceptions
                bShowExceptions = TRUE;
            }
            else if (!lstrcmp(argv[i], "--noioctls"))
            {
                // log exceptions
                m_bSkipIoctls = TRUE;
            }
            else if (!lstrcmp(argv[i], "--config") && i < argc - 1)
            {
                // config file path specified
                lpszConfigPath = argv[i + 1];
            }
        }
    }

    if (m_bSkipIoctls && !bShowExceptions)
    {
        MessageBox(
            0, 
            "'--noioctls' option is valid only with '--exceptions'.",
            "Invalid params",
            MB_ICONERROR
        );

        ExitProcess(0);
    }

    if (m_bSkipIoctls && lpszConfigPath)
    {
        MessageBox(
            0, 
            "'--config' option is not valid with '--noioctls'.",
            "Invalid params",
            MB_ICONERROR
        );

        ExitProcess(0);
    }

    // get version information
    DWORD dwHandle = 0;
    DWORD dwSize = GetFileVersionInfoSize(szProcessFileName, &dwHandle);
    if (dwSize > 0)
    {
        PVOID pInfo = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, dwSize);
        if (pInfo)
        {
            ZeroMemory(pInfo, dwSize);
            if (GetFileVersionInfo(szProcessFileName, dwHandle, dwSize, pInfo))
            {
                UINT uValueSize = 0;
                VS_FIXEDFILEINFO *VersionInfo = NULL;                               

                if (VerQueryValue(pInfo, TEXT("\\"), (PVOID *)&VersionInfo, &uValueSize))
                {
                    // get product version from version information
                    wsprintf(szProductVersion, "%d.%d.%d.%d", 
                        HIWORD(VersionInfo->dwProductVersionMS), 
                        LOWORD(VersionInfo->dwProductVersionMS),
                        HIWORD(VersionInfo->dwProductVersionLS), 
                        LOWORD(VersionInfo->dwProductVersionLS)
                    );
                }                                                
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): GetFileVersionInfo() ERROR %d\r\n", GetLastError());
            }

            LocalFree(pInfo);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): LocalAlloc() ERROR %d\r\n", GetLastError());
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): GetFileVersionInfo() ERROR %d\r\n", GetLastError());
    }

    DbgMsg(__FILE__, __LINE__, "IOCTL Fuzzer\r\n");
    DbgMsg(__FILE__, __LINE__, "(c) 2010 eSage Lab\r\n");
    DbgMsg(__FILE__, __LINE__, "www.esagelab.com\r\n");
    DbgMsg(__FILE__, __LINE__, "Program version: %s\r\n", szProductVersion);

    if (bShowExceptions)
    {
        char szSymbolsPath[MAX_PATH], szSymbolsDir[MAX_PATH];
        GetCurrentDirectory(MAX_PATH - 1, szSymbolsDir);
        strcat(szSymbolsDir, "\\Symbols");

        // create directory for debug symbols
        CreateDirectory(szSymbolsDir, NULL);

        wsprintf(
            szSymbolsPath, 
            "%s;SRV*%s*http://msdl.microsoft.com/download/symbols", 
            szSymbolsDir, szSymbolsDir
        );

        // set symbol path and initialize symbol server client
        if (!SymInitialize(GetCurrentProcess(), szSymbolsPath, FALSE))
        {
            DbgMsg(__FILE__, __LINE__, "SymInitialize() ERROR %d\n", GetLastError());
            goto end;
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "Symbols path: '%s'\n", szSymbolsPath);
        } 

        printf("Obtaining address of nt!KiDispatchException() from debug symbols, this my take some time...\n");

        // lookup for nt!KiDispatchException() address in debug symbols
        m_KiDispatchException_Offset = GetKernelSymbolOffset("KiDispatchException");
        if (m_KiDispatchException_Offset > 0)
        {
            DbgMsg(__FILE__, __LINE__, "nt!KiDispatchException() is at nt+0x%x\r\n", m_KiDispatchException_Offset);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "WARNING: nt!KiDispatchException() is not found\r\n");

            MessageBox(
                0, 
                "Exception monitoring is not available, 'cause I can't obtain nt!KiDispatchException() from debug symbols."
                "Check console or program log for details.\n",
                "WARNING",
                MB_ICONWARNING
            );

            if (m_bSkipIoctls)
            {
                // IOCTL monitorig disabled, nothing to do anymore, exit
                ExitProcess(0);
            }
        }
    }    

    if (!LoadPrivileges(SE_LOAD_DRIVER_NAME))
    {
        DbgMsg(__FILE__, __LINE__, "Error while loading 'SeLoadDriverPrivilege'\r\n");
        goto end;
    }

    typedef HRESULT (WINAPI * func_CoInitializeEx)(LPVOID pvReserved, DWORD dwCoInit);

    func_CoInitializeEx f_CoInitializeEx = (func_CoInitializeEx)
        GetProcAddress(
        LoadLibrary("ole32.dll"),
        "CoInitializeEx"
    );
    if (f_CoInitializeEx == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "GetProcAddress() ERROR %d\r\n", GetLastError());
        goto end;
    }

    // initialize COM
    HRESULT hr = f_CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        DbgMsg(__FILE__, __LINE__, "CoInitializeEx() ERROR 0x%.8x\r\n", hr);
        goto end;
    }

    PVOID DriverData = NULL;
    DWORD dwDriverDataSize = 0;

    // extract kernel driver from resources
    if (GetResPayload(GetModuleHandle(NULL), RESOURCE_NAME_DRIVER, &DriverData, &dwDriverDataSize))
    {
        // ... and dump it to the disk
        if (!DumpToFile(szDriverFileName, DriverData, dwDriverDataSize))
        {
            DbgMsg(__FILE__, __LINE__, "Error while creating kernel driver file.\r\n");
            goto end;
        }

        M_FREE(DriverData);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "Error while extracting kernel driver from resources.\r\n");
        goto end;
    }

    if (!DrvServiceStart(SERVICE_NAME, szDriverFileName, NULL))
    {
        DbgMsg(__FILE__, __LINE__, "Error while creating/starting system service for kernel driver.\r\n");
        DeleteFile(szDriverFileName);
        goto end;
    }

    if (m_bBootFuzzing)
    {
        if (!DrvServiceSetStartType(SERVICE_NAME, SERVICE_BOOT_START))
        {
            DbgMsg(__FILE__, __LINE__, "Error while changing service startup type.\r\n");
            DeleteFile(szDriverFileName);
            goto end;
        }

        DbgMsg(__FILE__, __LINE__, "Service startup type has been set to the SERVICE_BOOT_START.\r\n");
    }
    else
    {
        if (!DrvServiceSetStartType(SERVICE_NAME, SERVICE_DEMAND_START))
        {
            DbgMsg(__FILE__, __LINE__, "Error while changing service startup type.\r\n");
            DeleteFile(szDriverFileName);
            goto end;
        }
    }

    // create thread for kernel mode APC's
    HANDLE hThread = CreateThread(NULL, 0, ApcThread, NULL, 0, &m_dwFuzzThreadId);
    if (hThread)
    {
        DbgMsg(__FILE__, __LINE__, "Thread for kernel mode APC's created (ID: %x)\r\n", m_dwFuzzThreadId);
        CloseHandle(hThread);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "CreateThread() ERROR %d\r\n", GetLastError());
    }

    if (DrvOpenDevice(DEVICE_NAME, &hDevice))
    {
        if (lpszConfigPath && !m_bSkipIoctls)
        {
            ParseConfig(lpszConfigPath);            
        }
        else
        {
            SetDefaultOptions();
        }        

        if (m_bBootFuzzing)
        {
            MessageBox(0,
                "Boot mode has been activated.\r\n"
                "Fuzzing/monitoring will be started at the next reboot.\r\n",
                "Press <OK> to exit from program.", MB_ICONINFORMATION
            );

            ExitProcess(0);
        }

        SetConsoleCtrlHandler(CtrlHandler, TRUE);
        Sleep(INFINITE);                      
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "Error while opening kernel driver communication device\r\n");
    }   

    DrvServiceStop(SERVICE_NAME);
    DeleteFile(szDriverFileName);

end:
    printf("Press any key to quit...\r\n");
    getch();

    return 0;
}
//--------------------------------------------------------------------------------------
// EoF
