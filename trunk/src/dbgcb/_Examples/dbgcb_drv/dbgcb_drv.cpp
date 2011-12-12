#include <ntddk.h>
#include <stdio.h>
#include <stdarg.h>

#include "../../common/dbgcb_api.h"

extern "C"
{
NTSTATUS NTAPI 
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
);
}
//--------------------------------------------------------------------------------------
VOID NTAPI DriverUnload(PDRIVER_OBJECT DriverObject)
{    
    DbgPrint(__FUNCTION__"()\n");
}
//--------------------------------------------------------------------------------------
NTSTATUS NTAPI DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{    
    DriverObject->DriverUnload = DriverUnload;
    
    DbgPrint(__FUNCTION__"()\n");    

    // Test debugger command execution.
    if (dbg_exec(".printf /D \"<b>Hello from " __FUNCTION__ "()</b>\\n\""))
    {
        // another DML example
        dbg_exec(
            ".printf /D \"<exec cmd=\\\"!drvobj "IFMT"\\\">Show _DRIVER_OBJECT information.</exec>\\n\"", 
            DriverObject
        );

        DbgPrint("Breaking into the kernel debugger (check the DML link above)...\n");
        DbgBreakPoint();

        // Test symbol querying.
        PVOID Addr = dbg_eval("nt!KiDispatchException");
        if (Addr)
        {
            DbgPrint("<?dml?><b>nt!KiDispatchException() is at "IFMT"</b>\n", Addr);
        }        
        else
        {
            DbgPrint(__FUNCTION__"() ERROR: dbg_eval() fails\n");
        }

        // Test structure field offset querying.
        LONG Offset = dbg_field_offset("nt!_EPROCESS::ImageFileName");
        if (Offset >= 0)
        {
            DbgPrint("<?dml?><b>_EPROCESS::ImageFileName offset is 0x%x</b>\n", Offset);
        }
        else
        {
            DbgPrint(__FUNCTION__"() ERROR: dbg_field_offset() fails\n");
        }
    }    
    else
    {
        DbgPrint(__FUNCTION__"() WARNING: dbgcb extension is not loaded\n");
    }
    
    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
// EoF
