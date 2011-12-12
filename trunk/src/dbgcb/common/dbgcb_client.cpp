
/*******************************************************

    KERNEL DEBUGGER COMMUNICATION ENGINE

    Developed by: Oleksiuk Dmytro (aka Cr4sh), Esage Lab

    mailto:dmitry@esagelab.com

    http://esagelab.com/
    http://d-olex.blogspot.com/

 *******************************************************/

#include <stdio.h>
#include <stdarg.h>

#ifdef DBGCB_DRIVER

// Compile for kernel driver.
#include <ntddk.h>

#else

// Compile for user-mode application.
#include <Windows.h>

#endif

#include "dbgcb_api.h"

#define DBGCB_MAX_STRING_LENGTH 0x100

#ifdef DBGCB_DRIVER

extern "C" PBOOLEAN KdDebuggerNotPresent;
extern "C" PBOOLEAN KdDebuggerEnabled;

#define dbg_malloc(_len_) ExAllocatePool(NonPagedPool, (_len_))
#define dbg_free(_addr_) ExFreePool((_addr_))

#else

#define dbg_malloc(_len_) VirtualAlloc(NULL, (_len_), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)
#define dbg_free(_addr_) VirtualFree((_addr_), 0, MEM_RELEASE)

#endif

PVOID dbg_command(PCHAR lpParams, ULONG Command)
{
    PVOID ret = NULL;

    typedef PVOID (__fastcall * func_dbg_command)(
        PCHAR lpParams, 
        ULONG Command
    );

#ifdef DBGCB_DRIVER

    // Check for active kernel debugger.
    if (*KdDebuggerNotPresent == FALSE &&
        *KdDebuggerEnabled == TRUE)

#else

    __try

#endif

    {
        func_dbg_command f_dbg_command = (func_dbg_command)dbg_malloc(sizeof(ULONG));
        if (f_dbg_command)
        {
            // xor rax, rax \ int 3 \ ret
            *(PULONG)f_dbg_command = '\x33\xC0\xCC\xC3';

            ret = f_dbg_command(lpParams, Command);

            dbg_free(f_dbg_command);
        }
    }

#ifndef DBGCB_DRIVER

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // dbgcb extension is not loaded, or no connection to
        // remote kernel debugger
    }

#endif

    return ret;
}

#define DBGCB_FORMAT_ARGS()                 \
                                            \
    char Buffer[DBGCB_MAX_STRING_LENGTH];   \
    va_list mylist;                         \
                                            \
    va_start(mylist, lpFormat);             \
    vsprintf(Buffer, lpFormat, mylist);	    \
    va_end(mylist);

/**
 * Execute debuuger command (IDebugControl::Execute()).
 */
BOOLEAN dbg_exec(PCHAR lpFormat, ...)
{
    DBGCB_FORMAT_ARGS();

    return (BOOLEAN)dbg_command(Buffer, DBGCB_EXECUTE);    
}

/**
 * Evaluate debuuger expression (IDebugControl::Evaluate()).
 */
PVOID dbg_eval(PCHAR lpFormat, ...)
{
    DBGCB_FORMAT_ARGS();

    return dbg_command(Buffer, DBGCB_GET_SYMBOL);
}

/**
 * Get offset of the some structure field
 */
LONG dbg_field_offset(PCHAR lpFormat, ...)
{
    DBGCB_FORMAT_ARGS();

    return (LONG)dbg_command(Buffer, DBGCB_FIELD_OFFSET);
}
