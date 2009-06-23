/*

	(c) eSage lab
	http://www.esagelab.ru

*/
#include "stdafx.h"

#ifdef DBG
#include "../driver_debug.h"
#else
#include "../driver.h"
#endif

#define SERVICE_NAME        "IOCTL_fuzzer"
#define DRIVER_FILE_NAME    "IOCTL_fuzzer.sys"
#define PIPE_NAME           "IOCTL_fuzzer"

HANDLE hDevice = NULL, hPipe = NULL;
//--------------------------------------------------------------------------------------
BOOL DrvServiceStart(char *lpszServiceName, char *lpszPath)
{
    BOOL bRet = FALSE;
    SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hScm)
    {
        printf("Creating service... ");

        SC_HANDLE hService = CreateService(
            hScm, 
            lpszServiceName, 
            lpszServiceName, 
            SERVICE_START | DELETE | SERVICE_STOP, 
            SERVICE_KERNEL_DRIVER, 
            SERVICE_SYSTEM_START, 
            SERVICE_ERROR_IGNORE, 
            lpszPath, 
            NULL, NULL, NULL, NULL, NULL
        );
        if (hService == NULL)
        {
            if (GetLastError() == ERROR_SERVICE_EXISTS)
            {
                if (hService = OpenService(hScm, lpszServiceName, SERVICE_START | DELETE | SERVICE_STOP))
                {
                    printf("Allready exists\n");
                }
                else
                {
                    printf("OpenService() ERROR %d\n", GetLastError());
                }
            }
            else
            {
                printf("CreateService() ERROR %d\n", GetLastError());
            }
        }
        else
        {
            printf("OK\n");
        }

        if (hService)
        {                
            printf("Starting service... ");

            if (StartService(hService, 0, NULL))
            {
                printf("OK\n");                
                bRet = TRUE;
            }
            else
            {
                if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
                {
                    printf("Allready running\n");
                    bRet = TRUE;
                }
                else
                {
                    printf("StartService() ERROR %d\n", GetLastError());
                }                    
            }            

            CloseServiceHandle(hService);
        }

        CloseServiceHandle(hScm);
    }
    else
    {
        printf("OpenSCManager() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL DrvServiceStop(char *lpszServiceName)
{
    BOOL bRet = FALSE;
    SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hScm)
    {
        printf("Opening service... ");

        SC_HANDLE hService = OpenService(hScm, lpszServiceName, SERVICE_ALL_ACCESS);
        if (hService)
        {
            printf("OK\n");
            printf("Stopping service... ");

            SERVICE_STATUS ssStatus;
            if (!ControlService(hService, SERVICE_CONTROL_STOP, &ssStatus))
            {
                printf("ControlService() ERROR %d\n", GetLastError());
            }
            else
            {
                printf("OK\n");                
            }            

            CloseServiceHandle(hService);
        }
        else
        {
            printf("OpenService() ERROR %d\n", GetLastError());
        }

        CloseServiceHandle(hScm);
    }
    else
    {
        printf("OpenSCManager() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL LoadPrivileges(char *lpszName)
{
    HANDLE hToken = NULL;
    LUID Val;
    TOKEN_PRIVILEGES tp;
    BOOL bRet = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) 
    {
        printf("OpenProcessToken() fails: error %d\n", GetLastError());
        goto end;
    }

    if (!LookupPrivilegeValueA(NULL, lpszName, &Val))
    {
        printf("LookupPrivilegeValue() fails: error %d\n", GetLastError());
        goto end;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = Val;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof (tp), NULL, NULL))
    {
        printf("AdjustTokenPrivileges() fails: error %d\n", GetLastError());
        goto end;
    }

    bRet = TRUE;

end:
    if (hToken)
        CloseHandle(hToken);

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL DrvOpenDevice(PWSTR DriverName, HANDLE *lphDevice)
{
    WCHAR DeviceName[MAX_PATH];
    HANDLE hDevice;

    if ((GetVersion() & 0xFF) >= 5) 
    {
        wcscpy(DeviceName, L"\\\\.\\Global\\");
    } 
    else 
    {
        wcscpy(DeviceName, L"\\\\.\\");
    }

    wcscat(DeviceName, DriverName);

    hDevice = CreateFileW(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("CreateFile() ERROR %d\n", GetLastError());
        return FALSE;
    }

    *lphDevice = hDevice;

    return TRUE;
}
//--------------------------------------------------------------------------------------
BOOL DrvDeviceRequest(PREQUEST_BUFFER InBuff, DWORD dwBuffSize)
{
    BOOL bRet = FALSE;
    PREQUEST_BUFFER OutBuff = (PREQUEST_BUFFER)M_ALLOC(dwBuffSize);
    if (OutBuff)
    {
        DWORD dwBytes = 0;

        // send request to driver
        if (DeviceIoControl(
            hDevice, 
            IOCTL_DRV_CONTROL, 
            InBuff, 
            dwBuffSize, 
            OutBuff, 
            dwBuffSize, 
            &dwBytes, NULL))
        {
#ifdef DBG
            DbgMsg(__FILE__, __LINE__, "RkDeviceRequest() %d bytes returned; status 0x%.8x\n", dwBytes, OutBuff->Status);
#endif
            if (OutBuff->Status == S_SUCCESS)
            {
                bRet = TRUE;
            }
        }	
        else
        {
            printf("DeviceIoControl() ERROR %d\n", GetLastError());
        }

        M_FREE(OutBuff);
    }
    else
    {
        printf("M_ALLOC() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL ReadFromFile(char *lpszFileName, PVOID *pData, PDWORD lpdwDataSize)
{
    BOOL bRet = FALSE;
    HANDLE hFile = CreateFile(lpszFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        *lpdwDataSize = GetFileSize(hFile, NULL) + 1;
        if (*pData = M_ALLOC(*lpdwDataSize))
        {
            DWORD dwReaded = 0;
            ReadFile(hFile, *pData, *lpdwDataSize, &dwReaded, NULL);

            bRet = TRUE;
        }
        else
        {
            printf("LocalAlloc() ERROR %d\n", GetLastError());
            *lpdwDataSize = 0;
        }

        CloseHandle(hFile);
    }
    else
    {
        printf("CreateFile() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
IXMLDOMDocument *pXMLDoc = NULL;

IXMLDOMNode *LoadXml(PWSTR lpwcData)
{
    BOOL bOk = FALSE;
    VARIANT_BOOL status;    
    IXMLDOMNode *pIDOMRootNode = NULL;

    // create new msxml document instance
    HRESULT hr = CoCreateInstance(CLSID_DOMDocument, NULL, CLSCTX_INPROC_SERVER, 
        IID_IXMLDOMDocument, (PVOID *)&pXMLDoc);
    if (FAILED(hr)) 
    {
        DbgMsg(__FILE__, __LINE__, "CoCreateInstance() ERROR 0x%.8x\n", hr);
        return NULL;
    }    

    hr = pXMLDoc->loadXML(lpwcData, &status);
    if (status != VARIANT_TRUE)
    {
        DbgMsg(__FILE__, __LINE__, "pXMLDoc->load() ERROR 0x%.8x\n", hr);
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
        DbgMsg(__FILE__, __LINE__, "pXMLDoc->get_childNodes() ERROR 0x%.8x\n", hr);
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
            printf("WARNING: invalid value for option '%ws'\n", lpwcName);
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

            printf("Drivers:\n");

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
                        printf("  %s\n", lpszName);

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
                            printf("M_ALLOC() ERROR %d\n", GetLastError());
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

            printf("Devices:\n");

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
                        printf("  %s\n", lpszName);

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
                            printf("M_ALLOC() ERROR %d\n", GetLastError());
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

            printf("IOCTL codes:\n");

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
                            printf("  0x%.8x\n", dwIoctlCode);

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

            printf("Processes:\n");

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
                        printf("  %s\n", lpszName);

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
                            printf("M_ALLOC() ERROR %d\n", GetLastError());
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
// converts 'C:\somepath\somefile' to '\Device\HarrdiskVolume1\somepath\somefile'
BOOL FileNameToDeviceName(char *lpszFileName, char *lpszDeviceName)
{
    char szLetter[3], szVolume[128];

    szLetter[0] = lpszFileName[0];
    szLetter[1] = ':';
    szLetter[2] = '\0';

    if (QueryDosDeviceA(szLetter, szVolume, sizeof(szVolume)))
    {
        wsprintf(lpszDeviceName, "%s%s", szVolume, &lpszFileName[2]);
#ifdef DBG
        DbgMsg(__FILE__, __LINE__, "FileNameToDeviceName() %s\n", lpszDeviceName);
#endif
        return TRUE;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "QueryDosDeviceA() ERROR\n");
    }

    return FALSE;
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
                BOOL bHexDump = FALSE, bLogRequests = TRUE, bFuzeRequests = FALSE, bFuzeSize = FALSE, bDebugLogRequests = TRUE;

                GetOption(pIDOMNode, L"hex_dump", &bHexDump);
                GetOption(pIDOMNode, L"log_requests", &bLogRequests);
                GetOption(pIDOMNode, L"debug_log_requests", &bDebugLogRequests);
                GetOption(pIDOMNode, L"fuze_requests", &bFuzeRequests);
                GetOption(pIDOMNode, L"fuze_size", &bFuzeSize);

                REQUEST_BUFFER Buff;
                ZeroMemory(&Buff, sizeof(Buff));

                Buff.Code = C_SET_OPTIONS;
                Buff.Options.bHexDump = bHexDump;
                Buff.Options.bLogRequests = bLogRequests;
                Buff.Options.bDebugLogRequests = bDebugLogRequests;
                Buff.Options.bFuzeRequests = bFuzeRequests;
                Buff.Options.bFuzeSize = bFuzeSize;
                
                // send options to driver
                DrvDeviceRequest(&Buff, sizeof(REQUEST_BUFFER));

                // create logfile, if option is set
                char *lpszLogFilePath = NULL;
                if (ConfAllocGetTextByNameA(pIDOMNode, L"log_file", &lpszLogFilePath))
                {
                    char szLogFileNtPath[MAX_PATH];
                    if (FileNameToDeviceName(lpszLogFilePath, szLogFileNtPath))
                    {                        
                        DWORD dwRequestSize = sizeof(REQUEST_BUFFER) + lstrlen(szLogFileNtPath) + 1;
                        PREQUEST_BUFFER pBuff = (PREQUEST_BUFFER)M_ALLOC(dwRequestSize);
                        if (pBuff)
                        {
                            ZeroMemory(pBuff, dwRequestSize);
                            lstrcpy(pBuff->Buff, szLogFileNtPath);

                            pBuff->Code = C_SET_LOG_FILE;

                            // send options to driver
                            if (DrvDeviceRequest(pBuff, dwRequestSize))
                            {
                                DbgMsg(__FILE__, __LINE__, "Writing log data into '%s'\n", lpszLogFilePath);
                            }
                            else
                            {
                                DbgMsg(__FILE__, __LINE__, "Error while creating log file '%s'\n", lpszLogFilePath);
                            }

                            M_FREE(pBuff);
                        }
                        else
                        {
                            DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
                        }
                    }

                    M_FREE(lpszLogFilePath);
                }

                pIDOMNode->Release();
                pXMLDoc->Release();
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
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
    Buff.Options.bHexDump = FALSE;
    Buff.Options.bLogRequests = TRUE;
    Buff.Options.bDebugLogRequests = TRUE;
    Buff.Options.bFuzeRequests = FALSE;
    Buff.Options.bFuzeSize = FALSE;

    // send options to driver
    DrvDeviceRequest(&Buff, sizeof(REQUEST_BUFFER));
}
//--------------------------------------------------------------------------------------
BOOL __stdcall CtrlHandler(DWORD fdwCtrlType) 
{ 
    if (fdwCtrlType == CTRL_C_EVENT || 
        fdwCtrlType == CTRL_CLOSE_EVENT) 
    { 
        // Handle the CTRL-C signal. 
        printf("Stopping application, please wait...\n");
        
        CloseHandle(hDevice);
        
        if (MessageBox(0,
            "Warning!\n"
            "Unloading of a kernel driver may be unsafe.\n"
            "Press <YES> to unload it, or <NO> for just a program termination.",
            "Exit from program", MB_YESNO | MB_ICONWARNING) == IDYES)
        {
            DrvServiceStop(SERVICE_NAME);
        }               
        
        CloseHandle(hPipe);

        ExitProcess(0);
    } 

    return FALSE;
}
//--------------------------------------------------------------------------------------
DWORD __stdcall PipeReadThread(LPVOID lpParam)
{
    HANDLE hPipe = (HANDLE)lpParam;
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

    if (ConnectNamedPipe(hPipe, NULL))
    {
        DWORD dwReaded;
        char Buff[0x100];

        // read data from pipe
        while (ReadFile(hPipe, &Buff, sizeof(Buff), &dwReaded, NULL))
        {
            DWORD dwWritten;

            // and write it into stdout
            WriteFile(hStdout, Buff, dwReaded, &dwWritten, NULL);
        }
    }

    return 0;
}
//--------------------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{
    char szFileName[MAX_PATH];
    GetSystemDirectory(szFileName, sizeof(szFileName));
    lstrcat(szFileName, "\\drivers\\" DRIVER_FILE_NAME);

    if (!LoadPrivileges(SE_LOAD_DRIVER_NAME))
    {
        printf("Error while loading 'SeLoadDriverPrivilege'.\n");
        return -1;
    }

    // initialize COM
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        printf("CoInitializeEx() ERROR 0x%.8x\n", hr);
        return -1;
    }

    HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten;

        WriteFile(hFile, data, sizeof(data), &dwWritten, NULL);
        CloseHandle(hFile);
    }
    else
    {
        printf("CreateFile() ERROR %d\n", GetLastError());
        printf("Error while writing kernel driver image to disk.\n");
        return -1;
    }

    if (!DrvServiceStart(SERVICE_NAME, szFileName))
    {
        printf("Error while creating/starting system service for kernel driver.\n");
        DeleteFile(szFileName);
        return -1;
    }

    DeleteFile(szFileName);

    hPipe = CreateNamedPipe(
        "\\\\.\\pipe\\" PIPE_NAME, 
        PIPE_ACCESS_DUPLEX, 
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 
        PIPE_UNLIMITED_INSTANCES,  
        1024, 1024, 
        INFINITE, 
        NULL
    ); 
    if (hPipe != INVALID_HANDLE_VALUE)
    {
        HANDLE hThread = CreateThread(NULL, 0, PipeReadThread, hPipe, 0, NULL);
        if (hThread)
        {
            Sleep(100);
            CloseHandle(hThread);

            if (DrvOpenDevice(DEVICE_NAME, &hDevice))
            {
                if (argc > 1)
                {
                    ParseConfig(argv[1]);
                }
                else
                {
                    SetDefaultOptions();
                }

                char *lpszDriverPipeName = "\\Device\\NamedPipe\\" PIPE_NAME;
                DWORD dwBuffSize = sizeof(REQUEST_BUFFER) + lstrlen(lpszDriverPipeName) + 1;
                PREQUEST_BUFFER Buff = (PREQUEST_BUFFER)M_ALLOC(dwBuffSize);
                if (Buff)
                {
                    Buff->Code = C_SET_LOG_PIPE;
                    lstrcpy(Buff->Buff, lpszDriverPipeName);

                    if (DrvDeviceRequest(Buff, dwBuffSize))
                    {                    
                        SetConsoleCtrlHandler(CtrlHandler, TRUE);
                        Sleep(INFINITE);
                    }

                    M_FREE(Buff);
                }
                else
                {
                    printf("M_ALLOC() ERROR %d\n", GetLastError());
                }                       
            }
            else
            {
                printf("Error while opening kernel driver communication device\n");
            }
        }
        else
        {
            printf("CreateThread() ERROR %d\n", GetLastError());
        }        

        CloseHandle(hPipe);
    }
    else
    {
        printf("CreatePipe() ERROR %d\n", GetLastError());
    }        
   
    DrvServiceStop(SERVICE_NAME);

	return 0;
}
//--------------------------------------------------------------------------------------
// EoF
