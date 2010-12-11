#include "stdafx.h"

HANDLE hDbgPipe = NULL, hDbgLogFile = NULL;
KMUTEX DbgMutex;
//--------------------------------------------------------------------------------------
#ifdef DBGMSG_FULL
//--------------------------------------------------------------------------------------
void DbgMsg(char *lpszFile, int Line, char *lpszMsg, ...)
{
    char szBuff[0x100], szOutBuff[0x100];
    va_list mylist;

    va_start(mylist, lpszMsg);
    vsprintf(szBuff, lpszMsg, mylist);	
    va_end(mylist);

    sprintf(szOutBuff, "%s(%d) : %s", lpszFile, Line, szBuff);	

#ifdef DBGMSG

    DbgPrint(szOutBuff);

#endif

#if defined(DBGPIPE) || defined(DBGLOGFILE)

    if (KeGetCurrentIrql() == PASSIVE_LEVEL)
    {
        KeWaitForMutexObject(&DbgMutex, Executive, KernelMode, FALSE, NULL);

        if (hDbgPipe)
        {
            // write debug message into pipe
            IO_STATUS_BLOCK IoStatusBlock;
            ULONG Len = (ULONG)strlen(szOutBuff) + 1;

            ZwWriteFile(hDbgPipe, 0, NULL, NULL, &IoStatusBlock, (PVOID)&Len, sizeof(Len), NULL, NULL);
            ZwWriteFile(hDbgPipe, 0, NULL, NULL, &IoStatusBlock, szOutBuff, Len, NULL, NULL);
        }

        if (hDbgLogFile)
        {
            // write debug message into logfile
            IO_STATUS_BLOCK IoStatusBlock;
            ULONG Len = (ULONG)strlen(szOutBuff);

            ZwWriteFile(hDbgLogFile, 0, NULL, NULL, &IoStatusBlock, szOutBuff, Len, NULL, NULL);
        }

        KeReleaseMutex(&DbgMutex, FALSE);
    } 

#endif // DBGPIPE/DBGLOGFILE
}
//--------------------------------------------------------------------------------------
#ifdef DBGPIPE
//--------------------------------------------------------------------------------------
void DbgOpenPipe(void)
{
    OBJECT_ATTRIBUTES ObjAttr; 
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING usPipeName;

    RtlInitUnicodeString(&usPipeName, L"\\Device\\NamedPipe\\" DBG_PIPE_NAME);

    InitializeObjectAttributes(&ObjAttr, &usPipeName, 
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    KeWaitForMutexObject(&DbgMutex, Executive, KernelMode, FALSE, NULL);

    // open data pipe by name
    NTSTATUS status = ZwCreateFile(
        &hDbgPipe, 
        FILE_WRITE_DATA | SYNCHRONIZE, 
        &ObjAttr, 
        &IoStatusBlock,
        0, 
        FILE_ATTRIBUTE_NORMAL, 
        0, 
        FILE_OPEN, 
        FILE_SYNCHRONOUS_IO_NONALERT, 
        NULL, 
        0
    );
    if (!NT_SUCCESS(status))
    {
        DbgMsg(__FILE__, __LINE__, "ZwCreateFile() fails; status: 0x%.8x\n", status);
    }

    KeReleaseMutex(&DbgMutex, FALSE);
}
//--------------------------------------------------------------------------------------
void DbgClosePipe(void)
{
    KeWaitForMutexObject(&DbgMutex, Executive, KernelMode, FALSE, NULL);

	if (hDbgPipe)
    {
        ZwClose(hDbgPipe);
        hDbgPipe = NULL;
    }

    KeReleaseMutex(&DbgMutex, FALSE);
}
//--------------------------------------------------------------------------------------
#endif // DBGPIPE
//--------------------------------------------------------------------------------------
#ifdef DBGLOGFILE
//--------------------------------------------------------------------------------------
void DbgOpenLogFile(void)
{
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK StatusBlock;
    UNICODE_STRING usFileName;

    RtlInitUnicodeString(&usFileName, DBG_LOGFILE_NAME);

    InitializeObjectAttributes(&ObjAttr, &usFileName, 
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE , NULL, NULL);

    KeWaitForMutexObject(&DbgMutex, Executive, KernelMode, FALSE, NULL);

    NTSTATUS status = ZwCreateFile(
        &hDbgLogFile,
        FILE_ALL_ACCESS | SYNCHRONIZE,
        &ObjAttr,
        &StatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if (!NT_SUCCESS(status))
    {
        DbgMsg(__FILE__, __LINE__, "ZwCreateFile() fails; status: 0x%.8x\n", status);
    }

    KeReleaseMutex(&DbgMutex, FALSE);
}
//--------------------------------------------------------------------------------------
#endif // DBGLOGFILE
//--------------------------------------------------------------------------------------
void DbgClose(void)
{
    KeWaitForMutexObject(&DbgMutex, Executive, KernelMode, FALSE, NULL);

    if (hDbgPipe)
    {
        ZwClose(hDbgPipe);
        hDbgPipe = NULL;
    }

    if (hDbgLogFile)
    {
        ZwClose(hDbgLogFile);
        hDbgLogFile = NULL;
    }

    KeReleaseMutex(&DbgMutex, FALSE);
}
//--------------------------------------------------------------------------------------
void DbgInit(void)
{

#if defined(DBGPIPE) || defined(DBGLOGFILE)

    KeInitializeMutex(&DbgMutex, NULL);

#endif // DBGPIPE/DBGLOGFILE

}
//--------------------------------------------------------------------------------------
#endif // DBGMSG_FULL
//--------------------------------------------------------------------------------------
// EoF
