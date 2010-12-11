#include "stdafx.h"
//--------------------------------------------------------------------------------------
BOOL LoadPrivileges(char *lpszName)
{
    HANDLE hToken = NULL;
    LUID Val;
    TOKEN_PRIVILEGES tp;
    BOOL bRet = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) 
    {
        DbgMsg(__FILE__, __LINE__, "OpenProcessToken() fails: error %d\n", GetLastError());
        goto end;
    }

    if (!LookupPrivilegeValueA(NULL, lpszName, &Val))
    {
        DbgMsg(__FILE__, __LINE__, "LookupPrivilegeValue() fails: error %d\n", GetLastError());
        goto end;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = Val;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof (tp), NULL, NULL))
    {
        DbgMsg(__FILE__, __LINE__, "AdjustTokenPrivileges() fails: error %d\n", GetLastError());
        goto end;
    }

    bRet = TRUE;

end:
    if (hToken)
        CloseHandle(hToken);

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL DumpToFile(char *lpszFileName, PVOID pData, ULONG DataSize)
{
    HANDLE hFile = CreateFile(lpszFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten;
        WriteFile(hFile, pData, DataSize, &dwWritten, NULL);

        CloseHandle(hFile);

        return TRUE;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "Error %d while creating '%s'\n", GetLastError(), lpszFileName);
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOL ReadFromFile(LPCTSTR lpszFileName, PVOID *pData, PDWORD lpdwDataSize)
{
    BOOL bRet = FALSE;
    HANDLE hFile = CreateFile(
        lpszFileName, 
        GENERIC_READ, 
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
        NULL,
        OPEN_EXISTING, 
        0, 
        NULL
    );
    if (hFile != INVALID_HANDLE_VALUE)
    {
        if (pData == NULL || lpdwDataSize == NULL)
        {
            // just check for existing file
            bRet = TRUE;
            goto close;
        }

        *lpdwDataSize = GetFileSize(hFile, NULL);
        if (*pData = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, *lpdwDataSize))
        {
            DWORD dwReaded = 0;
            ReadFile(hFile, *pData, *lpdwDataSize, &dwReaded, NULL);

            bRet = TRUE;
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "LocalAlloc() ERROR %d\n", GetLastError());
            *lpdwDataSize = 0;
        }

close:
        CloseHandle(hFile);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "Error %d while reading '%s'\n", GetLastError(), lpszFileName);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
// EoF
