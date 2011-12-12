#include <stdio.h>
#include <conio.h>
#include <Windows.h>

#include "../../common/dbgcb_api.h"
//--------------------------------------------------------------------------------------
void DbgPrint(char *lpszMsg, ...)
{
    va_list mylist;
    va_start(mylist, lpszMsg);

    size_t len = _vscprintf(lpszMsg, mylist) + 0x100;

    char *lpszBuff = (char *)LocalAlloc(LMEM_FIXED, len);
    if (lpszBuff == NULL)
    {
        va_end(mylist);
        return;
    }

    vsprintf_s(lpszBuff, len, lpszMsg, mylist);	
    va_end(mylist);

    OutputDebugString(lpszBuff);

    HANDLE hStd = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStd != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
        WriteFile(hStd, lpszBuff, strlen(lpszBuff), &dwWritten, NULL);    
    }

    LocalFree(lpszBuff);
}
//--------------------------------------------------------------------------------------
int
__cdecl
main(
    __in ULONG argc,
    __in_ecount(argc) PCHAR argv[])
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    printf("*******************************************************\n\n");
    printf("  KERNEL DEBUGGER COMMUNICATION ENGINE\n");
    printf("  Test application\n\n");
    printf("  Developed by: Oleksiuk Dmytro (aka Cr4sh), Esage Lab\n\n");
    printf("  mailto:dmitry@esagelab.com\n\n");
    printf("*******************************************************\n\n");

    // Test debugger command execution.
    if (dbg_exec(".printf /D \"<b>Hello from " __FUNCTION__ "(), PID=%d</b>\\n\"", GetCurrentProcessId()))
    {
        DbgPrint("Reloading debug symbols and executing 'kb' in debugger...\n");
        dbg_exec(".reload;kb");

        // Test symbol querying.
        PVOID Addr = dbg_eval("ntdll!KiUserCallbackDispatcher");
        if (Addr)
        {
            DbgPrint("<?dml?><b>ntdll!KiUserCallbackDispatcher() is at "IFMT"</b>\n", Addr);
        }        
        else
        {
            DbgPrint(__FUNCTION__"() ERROR: dbg_eval() fails\n");
        }

        // Test structure field offset querying.
        LONG Offset = dbg_field_offset("ntdll!_PEB::KernelCallbackTable");
        if (Offset >= 0)
        {
            DbgPrint("<?dml?><b>_PEB::KernelCallbackTable offset is 0x%x</b>\n", Offset);
        }
        else
        {
            DbgPrint(__FUNCTION__"() ERROR: dbg_field_offset() fails\n");
        }
    }    
    else
    {
        DbgPrint(__FUNCTION__"() WARNING: dbgcb extension is not loaded or no connection to remote kernel debugger\n");
    }

    printf("\nPress any key to quit...\n");
    _getch();

    return 0;
}
//--------------------------------------------------------------------------------------
// EoF
