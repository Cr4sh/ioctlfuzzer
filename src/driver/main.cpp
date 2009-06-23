/*

	(c) eSage lab
	http://www.esagelab.ru

*/
#define _X86_

extern "C"
{
#include <stdio.h>
#include <stdarg.h>
#include <ntddk.h>
#include "undocnt.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
extern PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
extern PUSHORT NtBuildNumber;
}

#include "rng.h"
#include "pe.h"
#include "main.h"
#include "drvcomm.h"

#ifdef DBGMSG
#define DbgMsg DbgPrint
#else
#define DbgMsg
#endif

ULONG KTHREAD_PrevMode = 0;
ULONG EPROCESS_name = 0;
ULONG SDT_NtDeviceIoControlFile = 0;
NT_DEVICE_IO_CONTROL_FILE OldNtDeviceIoControlFile = NULL;

PDEVICE_OBJECT DeviceObject = NULL;
UNICODE_STRING usDosDeviceName, usDeviceName;
KMUTEX ListMutex;

BOOLEAN bHexDump = FALSE;
BOOLEAN bLogRequests = FALSE;
BOOLEAN bDebugLogRequests = FALSE;
BOOLEAN bFuzeRequests = FALSE;
BOOLEAN bFuzeSize = FALSE;
HANDLE hLogPipe = NULL, hLogFile = NULL;

#define FUZE_ITERATIONS 20

#define FLT_DEVICE_NAME     1
#define FLT_DRIVER_NAME     2
#define FLT_IOCTL_CODE      3
#define FLT_PROCESS_PATH    4

typedef struct _IOCTL_FILTER
{
    ULONG Type;

    UNICODE_STRING usName;
    ULONG IoctlCode;

    struct _IOCTL_FILTER *next, *prev;

} IOCTL_FILTER,
*PIOCTL_FILTER;

PIOCTL_FILTER f_allow_head = NULL, f_allow_end = NULL;
PIOCTL_FILTER f_deny_head = NULL, f_deny_end = NULL;

#define FltAllowAdd(_entry_) FltAdd((_entry_), &f_allow_head, &f_allow_end)
#define FltAllowFlushList() FltFlushList(&f_allow_head, &f_allow_end)
#define FltAllowMatch(_drv_, _dev_, _c_, _p_) FltMatch(&f_allow_head, (_drv_), (_dev_), (_c_), (_p_))

#define FltDenyAdd(_entry_) FltAdd((_entry_), &f_deny_head, &f_deny_end)
#define FltDenyFlushList() FltFlushList(&f_deny_head, &f_deny_end)
#define FltDenyMatch(_drv_, _dev_, _c_, _p_) FltMatch(&f_deny_head, (_drv_), (_dev_), (_c_), (_p_))
//--------------------------------------------------------------------------------------
BOOLEAN FltAdd(PIOCTL_FILTER f, PIOCTL_FILTER *f_head, PIOCTL_FILTER *f_end)
{
    BOOLEAN bRet = FALSE;

    KeWaitForMutexObject(&ListMutex, Executive, KernelMode, FALSE, NULL); 

    PIOCTL_FILTER f_entry = (PIOCTL_FILTER)ExAllocatePool(NonPagedPool, sizeof(IOCTL_FILTER));
    if (f_entry)
    {
        RtlCopyMemory(f_entry, f, sizeof(IOCTL_FILTER));

        if (*f_end)
        {
            (*f_end)->next = f_entry;
            f_entry->prev = *f_end;
            (*f_end) = f_entry;
        } 
        else 
        {
            *f_end = *f_head = f_entry;    
        }

        bRet = TRUE;        
    }
    else
    {
        DbgMsg("ExAllocatePool() fails\n");
    }

    KeReleaseMutex(&ListMutex, FALSE);

    return bRet;
}
//--------------------------------------------------------------------------------------
void FltFlushList(PIOCTL_FILTER *f_head, PIOCTL_FILTER *f_end)
{
    KeWaitForMutexObject(&ListMutex, Executive, KernelMode, FALSE, NULL);   

    PIOCTL_FILTER f_entry = *f_head;
    while (f_entry)
    {
        PIOCTL_FILTER f_tmp = f_entry->next;

        if (f_entry->Type == FLT_DEVICE_NAME ||
            f_entry->Type == FLT_DRIVER_NAME)
        {
            RtlFreeUnicodeString(&f_entry->usName);
        }

        ExFreePool(f_entry);

        f_entry = f_tmp;
    }

    *f_head = *f_end = NULL;

    KeReleaseMutex(&ListMutex, FALSE);
}
//--------------------------------------------------------------------------------------
wchar_t xchrlower_w(wchar_t chr)
{
    if ((chr >= 'A') && (chr <= 'Z')) 
    {
        return chr + ('a'-'A');
    }

    return chr;
}
//--------------------------------------------------------------------------------------
BOOLEAN EqualUnicodeString_r(PUNICODE_STRING Str1, PUNICODE_STRING Str2, BOOLEAN CaseInSensitive)
{
    USHORT CmpLen = min(Str1->Length, Str2->Length) / sizeof(WCHAR);

    for (USHORT i = 1; i < CmpLen; i++)
    {
        WCHAR Chr1 = Str1->Buffer[Str1->Length / sizeof(WCHAR) - i], 
              Chr2 = Str2->Buffer[Str2->Length / sizeof(WCHAR) - i];

        if (CaseInSensitive)
        {
            Chr1 = xchrlower_w(Chr1);
            Chr2 = xchrlower_w(Chr2);
        }

        if (Chr1 != Chr2)
        {
            return FALSE;
        }
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
PIOCTL_FILTER FltMatch(
    PIOCTL_FILTER   *f_head,
    PUNICODE_STRING fDeviceName, 
    PUNICODE_STRING fDriverName,
    ULONG           IoControlCode,
    PUNICODE_STRING fProcessName)
{
    PIOCTL_FILTER ret = NULL;

    // match parameters by filter list
    PIOCTL_FILTER f_entry = *f_head;

    while (f_entry)
    {
        if (f_entry->Type == FLT_DEVICE_NAME)
        {
            if (EqualUnicodeString_r(&f_entry->usName, fDeviceName, TRUE))
            {
                ret = f_entry;
                break;
            }
        }
        else if (f_entry->Type == FLT_DRIVER_NAME)
        {
            if (EqualUnicodeString_r(&f_entry->usName, fDriverName, TRUE))
            {
                ret = f_entry;
                break;
            }
        }
        else if (f_entry->Type == FLT_IOCTL_CODE)
        {
            if (f_entry->IoctlCode == IoControlCode)
            {
                ret = f_entry;
                break;
            }
        }
        else if (f_entry->Type == FLT_PROCESS_PATH)
        {
            if (EqualUnicodeString_r(&f_entry->usName, fProcessName, TRUE))
            {
                ret = f_entry;
                break;
            }
        }

        f_entry = f_entry->next;
    }

    return ret;
}
//--------------------------------------------------------------------------------------
BOOLEAN FltIsMatchedRequest(
    PUNICODE_STRING fDeviceName, 
    PUNICODE_STRING fDriverName,
    ULONG           IoControlCode,
    PUNICODE_STRING fProcessName)
{
    // match process by allow/deny list
    if ((f_allow_head == NULL || 
        FltAllowMatch(fDeviceName, fDriverName, IoControlCode, fProcessName)) &&
        FltDenyMatch(fDeviceName, fDriverName, IoControlCode, fProcessName) == NULL)
    {
        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
void __stdcall ClearWp(PVOID Param)
{
    // clear wp-bit in cr0 register
    CLEAR_WP();
}
//--------------------------------------------------------------------------------------
void __stdcall SetWp(PVOID Param)
{
    // set wp-bit in cr0 register
    SET_WP();
}
//--------------------------------------------------------------------------------------
typedef struct _PROCESSOR_THREAD_PARAM
{
    KAFFINITY Mask;
    PKSTART_ROUTINE Routine;
    PVOID Param;

} PROCESSOR_THREAD_PARAM,
*PPROCESSOR_THREAD_PARAM;

void __stdcall ProcessorThread(PVOID Param)
{
    PPROCESSOR_THREAD_PARAM ThreadParam = (PPROCESSOR_THREAD_PARAM)Param;
    
    // bind thread to specific processor
    KeSetSystemAffinityThread(ThreadParam->Mask);
    
    // execute payload on this processor
    ThreadParam->Routine(ThreadParam->Param);
}

void ForEachProcessor(PKSTART_ROUTINE Routine, PVOID Param)
{
    // get bitmask of active processors
    KAFFINITY ActiveProcessors = KeQueryActiveProcessors();    

    for (KAFFINITY i = 0; i < sizeof(KAFFINITY) * 8; i++)
    {
        KAFFINITY Mask = 1 << i;
        // check if this processor bit present in mask
        if (ActiveProcessors & Mask)
        {
            HANDLE hThread;
            PROCESSOR_THREAD_PARAM ThreadParam;
            
            ThreadParam.Mask    = Mask;
            ThreadParam.Param   = Param;
            ThreadParam.Routine = Routine;
            
            // create thread for this processor
            NTSTATUS ns = PsCreateSystemThread(
                &hThread, 
                THREAD_ALL_ACCESS, 
                NULL, NULL, NULL, 
                ProcessorThread, 
                &ThreadParam
            );
            if (NT_SUCCESS(ns))
            {
                PVOID Thread;                
                // get pointer to thread object
                ns = ObReferenceObjectByHandle(
                    hThread,
                    THREAD_ALL_ACCESS,
                    NULL,
                    KernelMode,
                    &Thread,
                    NULL
                );
                if (NT_SUCCESS(ns))
                {
                    // waiting for thread termination
                    KeWaitForSingleObject(Thread, Executive, KernelMode, FALSE, NULL);
                    ObDereferenceObject(Thread);
                }
                else
                {
                    DbgMsg("ObReferenceObjectByHandle() fails; status: 0x%.8x\n", ns);
                }                

                ZwClose(hThread);
            }
            else
            {
                DbgMsg("PsCreateSystemThread() fails; status: 0x%.8x\n", ns);
            }
        }
    }
}
//--------------------------------------------------------------------------------------
PVOID GetSysInf(SYSTEM_INFORMATION_CLASS InfoClass)
{    
    NTSTATUS ns;
    ULONG RetSize, Size = 0x100;
    PVOID Info;

    while (true) 
    {    
        if ((Info = ExAllocatePool(NonPagedPool, Size)) == NULL) 
        {
            DbgMsg("ExAllocatePool() fails\n");
            return NULL;
        }

        ns = ZwQuerySystemInformation(InfoClass, Info, Size, &RetSize);
        if (ns == STATUS_INFO_LENGTH_MISMATCH)
        {       
            ExFreePool(Info);
            Size += 0x100;
        }
        else
            break;    
    }

    if (!NT_SUCCESS(ns))
    {
        DbgMsg("ZwQuerySystemInformation() fails; status: 0x%.8x\n", ns);

        if (Info)
            ExFreePool(Info);

        return NULL;
    }

    return Info;
}
//--------------------------------------------------------------------------------------
ULONG KernelGetExportAddress(PVOID Image, char *lpszFunctionName)
{
    __try
    {
        PIMAGE_EXPORT_DIRECTORY pExport = NULL;

        PIMAGE_NT_HEADERS32 pHeaders32 = (PIMAGE_NT_HEADERS32)
            ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

        if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        {
            // 32-bit image
            if (pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
            {
                pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(
                    Image,
                    pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
                );
            }                        
        }        
        else if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            // 64-bit image
            PIMAGE_NT_HEADERS64 pHeaders64 = (PIMAGE_NT_HEADERS64)
                ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

            if (pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
            {
                pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(
                    Image,
                    pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
                );
            }
        }
        else
        {
            DbgMsg(__FUNCTION__"() ERROR: Unkown machine type\n");
            return 0;
        }

        if (pExport)
        {
            PULONG AddressOfFunctions = (PULONG)RVATOVA(Image, pExport->AddressOfFunctions);
            PSHORT AddrOfOrdinals = (PSHORT)RVATOVA(Image, pExport->AddressOfNameOrdinals);
            PULONG AddressOfNames = (PULONG)RVATOVA(Image, pExport->AddressOfNames);

            for (ULONG i = 0; i < pExport->NumberOfFunctions; i++)
            {
                if (!strcmp((char *)RVATOVA(Image, AddressOfNames[i]), lpszFunctionName))
                {
                    return AddressOfFunctions[AddrOfOrdinals[i]];
                }
            }
        }
        else
        {
            DbgMsg("WARNING: Export directory not found\n");
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DbgMsg(__FUNCTION__"() EXCEPTION\n");
    }

    return NULL;
}
//--------------------------------------------------------------------------------------
PVOID KernelGetModuleBase(char *ModuleName)
{
    PVOID pModuleBase = NULL;

    PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)GetSysInf(SystemModuleInformation);
    if (Info)
    {
        ANSI_STRING asModuleName;
        UNICODE_STRING usModuleName;

        RtlInitAnsiString(&asModuleName, ModuleName);

        NTSTATUS ns = RtlAnsiStringToUnicodeString(&usModuleName, &asModuleName, TRUE);
        if (NT_SUCCESS(ns))
        {
            if (strcmp(ModuleName, "ntoskrnl.exe"))
            {
                for (ULONG i = 0; i < Info->NumberOfModules; i++)
                {
                    ANSI_STRING asModule;
                    UNICODE_STRING usModule;

                    RtlInitAnsiString(
                        &asModule, 
                        (char *)Info->Modules[i].FullPathName + Info->Modules[i].OffsetToFileName
                    );

                    NTSTATUS ns = RtlAnsiStringToUnicodeString(&usModule, &asModule, TRUE);
                    if (NT_SUCCESS(ns))
                    {
                        if (RtlEqualUnicodeString(&usModule, &usModuleName, TRUE))
                        {
                            pModuleBase = (PVOID)Info->Modules[i].ImageBase;
                            break;
                        }

                        RtlFreeUnicodeString(&usModule);
                    }                    
                }            
            } 
            else 
            {
                pModuleBase = (PVOID)Info->Modules[0].ImageBase;
            }

            RtlFreeUnicodeString(&usModuleName);
        }        

        ExFreePool(Info);
    }

    return pModuleBase;
}
//--------------------------------------------------------------------------------------
ULONG GetSyscallNumber(PVOID NtdllBase, char *lpszName)
{
    // get function addres by name hash
    ULONG FuncRva = KernelGetExportAddress(NtdllBase, lpszName);
    if (FuncRva)
    {
        PVOID Func = (PUCHAR)NtdllBase + FuncRva;

        // check for mov eax,imm32
        if (*(PUCHAR)Func == 0xB8)
        {
            // return imm32 argument (syscall numbr)
            return *(PULONG)((PUCHAR)Func + 1);
        }
    }

    return 0;
}
//--------------------------------------------------------------------------------------
void InitSdtNumbers(void)
{
    // get base address of ntdll.dll, that mapped into the system process
    PVOID NtdllBase = KernelGetModuleBase("ntdll.dll");
    if (NtdllBase)
    {
        SDT_NtDeviceIoControlFile = GetSyscallNumber(NtdllBase, "NtDeviceIoControlFile");
        DbgMsg("SDT number of NtDeviceIoControlFile: 0x%.8x\n", SDT_NtDeviceIoControlFile);
    }
}
//--------------------------------------------------------------------------------------
ULONG GetProcessNameOffset(void)
{
    PEPROCESS Process = PsGetCurrentProcess();

    __try
    {
        for (ULONG i = 0; i < PAGE_SIZE * 3; i++)
        {
            if (!strncmp("System", (char *)Process + i, strlen("System")))
            {
                return i;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgMsg("GetProcessNameOffset() EXCEPTION\n");
    }

    return 0;
}
//--------------------------------------------------------------------------------------
POBJECT_NAME_INFORMATION GetObjectName(PVOID pObject)
{
    ULONG BuffSize = 0x100;
    POBJECT_NAME_INFORMATION ObjNameInfo;
    NTSTATUS ns;

    while (true)
    {
        if ((ObjNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPool, BuffSize)) == NULL)
            return FALSE;

        ns = ObQueryNameString(pObject, ObjNameInfo, BuffSize, &BuffSize);

        if (ns == STATUS_INFO_LENGTH_MISMATCH)
        {               
            ExFreePool(ObjNameInfo);
            BuffSize += 0x100;
        }
        else
            break;
    }

    if (NT_SUCCESS(ns))
    {
        return ObjNameInfo;
    } 
    else
    {
        //DbgMsg("ObQueryNameString() FAILS; status: 0x%.8x\n", ns);
    }

    if (ObjNameInfo)
        ExFreePool(ObjNameInfo);

    return NULL;    
}
//--------------------------------------------------------------------------------------
// get object name by its handle
POBJECT_NAME_INFORMATION GetObjectNameByHandle(HANDLE hObject)
{
    PVOID pObject;
    NTSTATUS ns;
    POBJECT_NAME_INFORMATION ObjNameInfo = NULL;

    ns = ObReferenceObjectByHandle(hObject, 0, 0, KernelMode, &pObject, NULL);
    if (NT_SUCCESS(ns))
    {
        ObjNameInfo = GetObjectName(pObject);
        ObDereferenceObject(pObject);
    } 
    else
        DbgMsg("ObReferenceObjectByHandle() FAILS; status: 0x%.8x\n", ns);

    return ObjNameInfo;
}
//--------------------------------------------------------------------------------------
BOOLEAN AllocUnicodeString(PUNICODE_STRING us, USHORT MaximumLength)
{
    ULONG ulMaximumLength = MaximumLength;

    if (MaximumLength > 0)
    {
        if ((us->Buffer = (PWSTR)ExAllocatePool(NonPagedPool, ulMaximumLength)) == NULL)
            return FALSE;

        RtlZeroMemory(us->Buffer, ulMaximumLength);

        us->Length = 0;
        us->MaximumLength = MaximumLength;

        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOLEAN AppendUnicodeToString(PUNICODE_STRING Dest, PCWSTR Source, USHORT Len)
{
    ULONG ulLen = Len;

    if (Dest->MaximumLength >= Dest->Length + Len)
    {
        RtlCopyMemory((PUCHAR)Dest->Buffer + Dest->Length, Source, ulLen);
        Dest->Length += Len;

        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
#define PEB_PROCESS_PARAMS_OFFSET           0x10
#define PROCESS_PARAMS_FLAGS_OFFSET         0x08
#define PROCESS_PARAMS_IMAGE_NAME_OFFSET    0x38

#define	PROCESS_PARAMETERS_NORMALIZED	1	// pointers in are absolute (not self-relative)

BOOLEAN GetProcessFullImagePath(PEPROCESS Process, PUNICODE_STRING ImagePath)
{
    BOOLEAN bRet = FALSE;
    HANDLE hProcess;
    // get handle to target process
    NTSTATUS ns = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        0,
        NULL,
        KernelMode,
        &hProcess
    );
    if (NT_SUCCESS(ns))
    {
        PROCESS_BASIC_INFORMATION ProcessInfo;    
        // get address of PEB
        ns = ZwQueryInformationProcess(
            hProcess,
            ProcessBasicInformation,
            &ProcessInfo,
            sizeof(ProcessInfo),
            NULL
        );
        if (NT_SUCCESS(ns))
        {
            KAPC_STATE ApcState;
            // change context to target process
            KeStackAttachProcess(Process, &ApcState);

            PUCHAR Peb = (PUCHAR)ProcessInfo.PebBaseAddress;
            if (Peb)
            {
                // get pointer to RTL_USER_PROCESS_PARAMETERS
                PUCHAR ProcessParams = *(PUCHAR *)(Peb + PEB_PROCESS_PARAMS_OFFSET);
                if (ProcessParams)
                {
                    // get image path
                    PUNICODE_STRING ImagePathName = (PUNICODE_STRING)(ProcessParams + PROCESS_PARAMS_IMAGE_NAME_OFFSET);
                    if (ImagePathName->Buffer && ImagePathName->Length > 0)
                    {
                        // allocate string
                        if (AllocUnicodeString(ImagePath, ImagePathName->Length))
                        {
                            PWSTR lpwcName = NULL;
                            ULONG Flags = *(PULONG)(ProcessParams + PROCESS_PARAMS_FLAGS_OFFSET);

                            if (Flags & PROCESS_PARAMETERS_NORMALIZED)
                            {
                                // pointer to buffer is absolute address
                                lpwcName = ImagePathName->Buffer;
                            }
                            else
                            {
                                // pointer to buffer is relative address
                                lpwcName = (PWSTR)(ProcessParams + (ULONG)ImagePathName->Buffer);
                            }

                            if (AppendUnicodeToString(ImagePath, lpwcName, ImagePathName->Length))
                            {
                                bRet = TRUE;
                            }
                            else
                            {
                                DbgMsg("AppendUnicodeToString() ERROR\n");
                            }
                        }
                        else
                        {
                            DbgMsg("AllocUnicodeString() ERROR\n");
                        }
                    }
                }
            }

            KeUnstackDetachProcess(&ApcState);
        }
        else
        {
            DbgMsg("ZwQueryInformationProcess() fails; status: 0x%.8x\n", ns);
        }        

        ZwClose(hProcess);
    }
    else
    {
        DbgMsg("ObOpenObjectByPointer() fails; status: 0x%.8x\n", ns);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
void PipeWrite(char *lpszFormat, ...)
{
    IO_STATUS_BLOCK IoStatusBlock;
    char szBuff[0x200];
    va_list mylist;

    va_start(mylist, lpszFormat);
    vsprintf(szBuff, lpszFormat, mylist);	
    va_end(mylist);

    if (bDebugLogRequests)
    {
        // post message into debug output
        DbgPrint(szBuff);
    }

    // write data to pipe
    if (hLogPipe && bLogRequests)
    {
        ZwWriteFile(hLogPipe, 0, NULL, NULL, &IoStatusBlock, szBuff, strlen(szBuff), NULL, NULL);
    }

    // write data to logfile
    if (hLogFile)
    {
        ZwWriteFile(hLogFile, 0, NULL, NULL, &IoStatusBlock, szBuff, strlen(szBuff), NULL, NULL);        
    }
}
//--------------------------------------------------------------------------------------
void Hexdump(unsigned char *data, unsigned int amount) 
{
    unsigned int dp, p;
    const char trans[] =
        "................................ !\"#$%&'()*+,-./0123456789"
        ":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
        "nopqrstuvwxyz{|}~...................................."
        "....................................................."
        "........................................";

    char buff[0x100], cb[10];
    RtlZeroMemory(buff, sizeof(buff));

    for (dp = 1; dp <= amount; dp++)  
    {
        sprintf(cb, "%02x ", data[dp-1]);
        strcat(buff, cb);

        if ((dp % 8) == 0)
        {
            strcat(buff, " ");
        }

        if ((dp % 16) == 0) 
        {
            strcat(buff, "| ");
            p = dp;

            for (dp -= 16; dp < p; dp++)
            {
                sprintf(cb, "%c", trans[data[dp]]);
                strcat(buff, cb);
            }

            PipeWrite("%s\r\n", buff);
            RtlZeroMemory(buff, sizeof(buff));
        }
    }

    if ((amount % 16) != 0) 
    {
        p = dp = 16 - (amount % 16);

        for (dp = p; dp > 0; dp--) 
        {
            strcat(buff, "   ");

            if (((dp % 8) == 0) && (p != 8))
            {
                strcat(buff, " ");
            }
        }

        strcat(buff, " | ");
        for (dp = (amount - (16 - p)); dp < amount; dp++)
        {
            sprintf(cb, "%c", trans[data[dp]]);
            strcat(buff, cb);
        }

        PipeWrite("%s\r\n", buff);
    }

    PipeWrite("\r\n");
}
//--------------------------------------------------------------------------------------
void SetPreviousMode(KPROCESSOR_MODE Mode)
{
    PRKTHREAD CurrentThread = KeGetCurrentThread();
    *((PUCHAR)CurrentThread + KTHREAD_PrevMode) = (UCHAR)Mode;
}
//--------------------------------------------------------------------------------------
BOOLEAN ValidateUnicodeString(PUNICODE_STRING usStr)
{
    if (!MmIsAddressValid(usStr))
    {
        return FALSE;
    }

    if (usStr->Buffer == NULL || usStr->Length == 0)
    {
        return FALSE;
    }

    for (ULONG i = 0; i < usStr->Length; i++)
    {
        if (!MmIsAddressValid((PUCHAR)usStr->Buffer + i))
        {
            return FALSE;
        }
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
NTSTATUS __stdcall NewNtDeviceIoControlFile(
    HANDLE              FileHandle,
    HANDLE              Event,
    PIO_APC_ROUTINE     ApcRoutine,
    PVOID               ApcContext,
    PIO_STATUS_BLOCK    IoStatusBlock,
    ULONG               IoControlCode,
    PVOID               InputBuffer,
    ULONG               InputBufferLength,
    PVOID               OutputBuffer,
    ULONG               OutputBufferLength)
{    
    PVOID cInputBuffer, cOutputBuffer;
    ULONG cInputBufferLength, cOutputBufferLength;
    // save old params
    cInputBuffer        = InputBuffer;
    cInputBufferLength  = InputBufferLength;
    cOutputBuffer       = OutputBuffer;
    cOutputBufferLength = OutputBufferLength;

    KPROCESSOR_MODE PrevMode = ExGetPreviousMode();
    if (PrevMode == KernelMode)
    {
        // don't handle calls from kernel mode
        goto end;
    }    
    
    POBJECT_NAME_INFORMATION ObjectName;    
    PFILE_OBJECT pFileObject;
    // get device object by handle
    NTSTATUS ns = ObReferenceObjectByHandle(
        FileHandle, 
        0, 0, 
        KernelMode, 
        (PVOID *)&pFileObject, 
        NULL
    );
    if (NT_SUCCESS(ns))
    {
        PVOID pObject = NULL;

        // validate pointer to device object
        if (MmIsAddressValid(pFileObject->DeviceObject))
        {
            pObject = pFileObject->DeviceObject;
        }
        else
        {
            goto dereference;
        }

        if (pObject == DeviceObject)
        {
            // don't handle requests to our driver
            goto dereference;
        }

        // validate pointer to driver object
        if (!MmIsAddressValid(pFileObject->DeviceObject->DriverObject))
        {
            goto dereference;
        }

        PLDR_DATA_TABLE_ENTRY pModuleEntry = (PLDR_DATA_TABLE_ENTRY)
            pFileObject->DeviceObject->DriverObject->DriverSection;
        
        // validate pointer to loader's table and data from it
        if (!MmIsAddressValid(pModuleEntry) ||
            !ValidateUnicodeString(&pModuleEntry->FullDllName))
        {
            goto dereference;
        }

        // get device name by poinet
        if (ObjectName = GetObjectName(pObject))
        {            
            PEPROCESS Process = PsGetCurrentProcess();
            HANDLE ProcessId = PsGetCurrentProcessId();
            char *lpszProcessName = (char *)((PUCHAR)Process + EPROCESS_name);

            LARGE_INTEGER Timeout;
            Timeout.QuadPart = RELATIVE(SECONDS(2));

            ns = KeWaitForMutexObject(&ListMutex, Executive, KernelMode, FALSE, &Timeout);               
            if (ns == STATUS_TIMEOUT)
            {
                DbgMsg(__FUNCTION__"(): Wait timeout\n");
                goto wait_timeout;
            }

            if (pModuleEntry)
            {
                UNICODE_STRING ImagePath;
                // get process image path
                if (GetProcessFullImagePath(Process, &ImagePath))
                {                    
                    PWSTR lpwcMethod = L"<unknown method>";
                    ULONG Method = IoControlCode & 3;

                    BOOLEAN bLogEvent = FltIsMatchedRequest(
                        &ObjectName->Name,
                        &pModuleEntry->FullDllName,
                        IoControlCode,
                        &ImagePath
                    );

                    // get text name of the method
                    switch (Method)
                    {
                    case METHOD_BUFFERED:
                        lpwcMethod = L"METHOD_BUFFERED";
                        break;

                    case METHOD_IN_DIRECT:
                        lpwcMethod = L"METHOD_IN_DIRECT";
                        break;

                    case METHOD_OUT_DIRECT:
                        lpwcMethod = L"METHOD_OUT_DIRECT";
                        break;

                    case METHOD_NEITHER:
                        lpwcMethod = L"METHOD_NEITHER";
                        break;
                    }

                    if (bLogEvent)
                    {                        
                        // send info about this IOCTL and hexdumps of buffers into pipe
                        PipeWrite("'%wZ' (PID: %d)\r\n'%wZ' (0x%.8x) [%wZ]\r\nIOCTL Code: 0x%.8x,  Method: %ws\r\n",
                            &ImagePath, ProcessId, &ObjectName->Name, pObject, 
                            &pModuleEntry->FullDllName, IoControlCode, lpwcMethod
                        );

                        if (bHexDump)
                        {
                            PipeWrite("\r\n");
                        }

                        PipeWrite("    InBuff: 0x%.8x,  InSize: 0x%.8x\r\n", InputBuffer, InputBufferLength);

                        if (bHexDump && InputBufferLength > 0)
                        {
                            PipeWrite("--------------------------------------------------------------------\r\n");
                            Hexdump((PUCHAR)InputBuffer, InputBufferLength);
                        }

                        PipeWrite("   OutBuff: 0x%.8x, OutSize: 0x%.8x\r\n", OutputBuffer, OutputBufferLength);

                        if (bHexDump && OutputBufferLength > 0)
                        {
                            PipeWrite("--------------------------------------------------------------------\r\n");
                            Hexdump((PUCHAR)OutputBuffer, OutputBufferLength);
                        }

                        PipeWrite("\r\n");
                    }    

                    if (InputBuffer && InputBufferLength > 0 &&
                        bFuzeRequests && bLogEvent)
                    {                            
                        // allocate temporary buffer for original request
                        PUCHAR NewBuff = (PUCHAR)ExAllocatePool(NonPagedPool, InputBufferLength);
                        if (NewBuff)
                        {
                            RtlCopyMemory(NewBuff, InputBuffer, InputBufferLength);

                            for (int i = 0; i < FUZE_ITERATIONS; i++)
                            {
                                ULONG InputLength = InputBufferLength;

                                if (bFuzeSize)
                                {
                                    InputLength = getrand(1, InputLength);
                                }

                                // fill buffer with random data
                                for (ULONG s = 0; s < InputBufferLength; s++)
                                {
                                    *(PUCHAR)((ULONG)InputBuffer + s) = (UCHAR)getrand(1, 0xff);
                                }

                                // change previous mode to UserMode
                                SetPreviousMode(PrevMode);

                                // send fuzzed request
                                NTSTATUS status = OldNtDeviceIoControlFile(
                                    FileHandle, 
                                    Event, ApcRoutine, 
                                    ApcContext, 
                                    IoStatusBlock, 
                                    IoControlCode, 
                                    InputBuffer, 
                                    InputBufferLength, 
                                    OutputBuffer, 
                                    OutputBufferLength
                                );
                            }

                            RtlCopyMemory(InputBuffer, NewBuff, InputBufferLength);

                            ExFreePool(NewBuff);
                        }
                        else
                        {
                            DbgMsg("ExAllocatePool() ERROR\n");
                        }

                        if (Method != METHOD_BUFFERED)
                        {
                            // try to fuze address of a buffers, if method is not buffered
                            for (int i = 0; i < FUZE_ITERATIONS; i++)
                            {
                                // ... with user-mode buffers
                                ULONG TmpInputBuffer  = getrand(0, (ULONG)MM_HIGHEST_USER_ADDRESS);
                                ULONG TmpOutputBuffer = getrand(0, (ULONG)MM_HIGHEST_USER_ADDRESS);
                                ULONG TmpInputBufferLength  = getrand(0, 0x100);
                                ULONG TmpOutputBufferLength = getrand(0, 0x100);

                                // change previous mode to UserMode
                                SetPreviousMode(PrevMode);

                                // send fuzzed request
                                NTSTATUS status = OldNtDeviceIoControlFile(
                                    FileHandle, 
                                    Event, ApcRoutine, 
                                    ApcContext, 
                                    IoStatusBlock, 
                                    IoControlCode, 
                                    (PVOID)TmpInputBuffer, 
                                    TmpInputBufferLength, 
                                    (PVOID)TmpOutputBuffer, 
                                    TmpOutputBufferLength
                                );
                            }

                            for (int i = 0; i < FUZE_ITERATIONS; i++)
                            {
                                // ... with kernel-mode buffers
                                ULONG TmpInputBuffer  = getrand((ULONG)MM_HIGHEST_USER_ADDRESS, 0xFFFFFFFF);
                                ULONG TmpOutputBuffer = getrand((ULONG)MM_HIGHEST_USER_ADDRESS, 0xFFFFFFFF);
                                ULONG TmpInputBufferLength  = getrand(0, 0x100);
                                ULONG TmpOutputBufferLength = getrand(0, 0x100);

                                // change previous mode to UserMode
                                SetPreviousMode(PrevMode);

                                // send fuzzed request
                                NTSTATUS status = OldNtDeviceIoControlFile(
                                    FileHandle, 
                                    Event, ApcRoutine, 
                                    ApcContext, 
                                    IoStatusBlock, 
                                    IoControlCode, 
                                    (PVOID)TmpInputBuffer, 
                                    TmpInputBufferLength, 
                                    (PVOID)TmpOutputBuffer, 
                                    TmpOutputBufferLength
                                );
                            }
                        }
                    }

                    RtlFreeUnicodeString(&ImagePath);
                }
            }                    

            KeReleaseMutex(&ListMutex, FALSE);


wait_timeout:
            ExFreePool(ObjectName);
        }

dereference:
        ObDereferenceObject(pFileObject);
    }        
    else
    {
        DbgMsg("ObReferenceObjectByHandle() fails; status: 0x%.8x\n", ns);            
    }

end:
    SetPreviousMode(PrevMode);
    ns = OldNtDeviceIoControlFile(
        FileHandle, 
        Event, 
        ApcRoutine, 
        ApcContext, 
        IoStatusBlock, 
        IoControlCode, 
        cInputBuffer, 
        cInputBufferLength, 
        cOutputBuffer, 
        cOutputBufferLength
    );    

    return ns;
}
//--------------------------------------------------------------------------------------
NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    NTSTATUS ns = STATUS_SUCCESS;

    Irp->IoStatus.Status = ns;
    Irp->IoStatus.Information = 0;

    stack = IoGetCurrentIrpStackLocation(Irp);

    if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) 
    {
        ULONG Code = stack->Parameters.DeviceIoControl.IoControlCode;        
        ULONG Size = stack->Parameters.DeviceIoControl.InputBufferLength;
        PREQUEST_BUFFER Buff = (PREQUEST_BUFFER)Irp->AssociatedIrp.SystemBuffer;

        DbgMsg(__FUNCTION__"(): IRP_MJ_DEVICE_CONTROL 0x%.8x\n", Code);

        Irp->IoStatus.Information = Size;

        switch (Code)
        {
        case IOCTL_DRV_CONTROL:
            {
                if (Size >= sizeof(REQUEST_BUFFER))
                {
                    IOCTL_FILTER Flt;
                    RtlZeroMemory(&Flt, sizeof(Flt));

                    switch (Buff->Code)
                    {
                    case C_ADD_DRIVER:
                    case C_ADD_DEVICE:
                    case C_ADD_PROCESS:
                    case C_SET_LOG_FILE:
                        {
                            Buff->Status = S_ERROR;

                            // check for zero byte at the end of the string
                            if (Size > sizeof(REQUEST_BUFFER) &&
                                Buff->Buff[Size - sizeof(REQUEST_BUFFER) - 1] == 0)
                            {          
                                ANSI_STRING asName;

                                RtlInitAnsiString(
                                    &asName,
                                    Buff->Buff
                                );

                                NTSTATUS status = RtlAnsiStringToUnicodeString(&Flt.usName, &asName, TRUE);
                                if (NT_SUCCESS(status))
                                {
                                    if (Buff->Code == C_SET_LOG_FILE)
                                    {
                                        OBJECT_ATTRIBUTES ObjAttr;
                                        IO_STATUS_BLOCK IoStatusBlock;
                                        HANDLE hFile;

                                        InitializeObjectAttributes(&ObjAttr, &Flt.usName, 
                                            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

                                        // open logfile by name
                                        status = ZwCreateFile(
                                            &hFile,
                                            FILE_ALL_ACCESS | SYNCHRONIZE,
                                            &ObjAttr,
                                            &IoStatusBlock,
                                            NULL,
                                            FILE_ATTRIBUTE_NORMAL,
                                            0,
                                            FILE_OVERWRITE_IF,
                                            FILE_SYNCHRONOUS_IO_NONALERT,
                                            NULL,
                                            0
                                        );   
                                        if (NT_SUCCESS(status))
                                        {
                                            KeWaitForMutexObject(&ListMutex, Executive, KernelMode, FALSE, NULL);   

                                            if (hLogFile)
                                            {
                                                // close old file handle
                                                ZwClose(hLogFile);
                                            }

                                            hLogFile = hFile;

                                            KeReleaseMutex(&ListMutex, FALSE);

                                            Buff->Status = S_SUCCESS;                                            
                                        }
                                        else
                                        {
                                            DbgMsg("ZwCreateFile() fails; status: 0x%.8x\n", ns);
                                        }

                                        RtlFreeUnicodeString(&Flt.usName);
                                    }
                                    else
                                    {
                                        if (Buff->Code == C_ADD_DRIVER)
                                        {
                                            Flt.Type = FLT_DRIVER_NAME;
                                        }
                                        else if (Buff->Code == C_ADD_DEVICE)
                                        {
                                            Flt.Type = FLT_DEVICE_NAME;
                                        }
                                        else if (Buff->Code == C_ADD_PROCESS)
                                        {
                                            Flt.Type = FLT_PROCESS_PATH;
                                        }

                                        // add filter rule by driver or device name
                                        if (Buff->bAllow)
                                        {
                                            if (!FltAllowAdd(&Flt))
                                            {
                                                RtlFreeUnicodeString(&Flt.usName);
                                            }
                                            else
                                            {
                                                Buff->Status = S_SUCCESS;
                                            }
                                        }    
                                        else
                                        {
                                            if (!FltDenyAdd(&Flt))
                                            {
                                                RtlFreeUnicodeString(&Flt.usName);
                                            }
                                            else
                                            {
                                                Buff->Status = S_SUCCESS;
                                            }
                                        }
                                    }                                    
                                }
                                else
                                {
                                    DbgMsg("RtlAnsiStringToUnicodeString() fails; status: 0x%.8x\n", status);
                                }
                            }

                            break;
                        }

                    case C_ADD_IOCTL:
                        {
                            Flt.IoctlCode = Buff->IoctlCode;
                            Flt.Type = FLT_IOCTL_CODE;

                            Buff->Status = S_ERROR;

                            // add filter rule by IOCTL code
                            if (Buff->bAllow)
                            {
                                if (FltAllowAdd(&Flt))
                                {
                                    Buff->Status = S_SUCCESS;
                                }
                            }
                            else
                            {
                                if (FltDenyAdd(&Flt))
                                {
                                    Buff->Status = S_SUCCESS;
                                }
                            }

                            break;
                        }

                    case C_SET_LOG_PIPE:
                        {
                            Buff->Status = S_ERROR;

                            // check for zero byte at the end of the string
                            if (Size > sizeof(REQUEST_BUFFER) &&
                                Buff->Buff[Size - sizeof(REQUEST_BUFFER) - 1] == 0)
                            {          
                                UNICODE_STRING usPipeName;
                                ANSI_STRING asPipeName;

                                RtlInitAnsiString(
                                    &asPipeName,
                                    Buff->Buff
                                );

                                NTSTATUS status = RtlAnsiStringToUnicodeString(&usPipeName, &asPipeName, TRUE);
                                if (NT_SUCCESS(status))
                                {
                                    HANDLE hPipe;
                                    OBJECT_ATTRIBUTES ObjAttr; 
                                    IO_STATUS_BLOCK IoStatusBlock;

                                    InitializeObjectAttributes(&ObjAttr, &usPipeName, 
                                        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

                                    DbgMsg("Opening pipe '%wZ'\n", &usPipeName);

                                    // open data pipe by name
                                    status = ZwCreateFile(
                                        &hPipe, 
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
                                    if (NT_SUCCESS(status))
                                    {
                                        KeWaitForMutexObject(&ListMutex, Executive, KernelMode, FALSE, NULL);   

                                        if (hLogPipe)
                                        {
                                            // close old pipe handle
                                            ZwClose(hLogPipe);
                                        }

                                        hLogPipe = hPipe;

                                        KeReleaseMutex(&ListMutex, FALSE);

                                        PipeWrite("Log started...\n");

                                        Buff->Status = S_SUCCESS;
                                    } 
                                    else 
                                    {
                                        DbgMsg("ZwCreateFile() fails; status: 0x%.8x\n", status);
                                    }
                                }
                                else
                                {
                                    DbgMsg("RtlAnsiStringToUnicodeString() fails; status: 0x%.8x\n", status);
                                }
                            }

                            break;
                        }

                    case C_SET_OPTIONS:
                        {
                            KeWaitForMutexObject(&ListMutex, Executive, KernelMode, FALSE, NULL);   

                            bHexDump = Buff->Options.bHexDump;                            
                            bLogRequests = Buff->Options.bLogRequests;
                            bDebugLogRequests = Buff->Options.bDebugLogRequests;
                            bFuzeRequests = Buff->Options.bFuzeRequests;
                            bFuzeSize = Buff->Options.bFuzeSize;

                            KeReleaseMutex(&ListMutex, FALSE);

                            break;
                        }
                    }
                }

                break;
            }            

        default:
            {
                ns = STATUS_INVALID_DEVICE_REQUEST;
                Irp->IoStatus.Information = 0;
                break;
            }            
        }
    }
    else if (stack->MajorFunction == IRP_MJ_CREATE) 
    {
        DbgMsg(__FUNCTION__"(): IRP_MJ_CREATE\n");
    }
    else if (stack->MajorFunction == IRP_MJ_CLOSE) 
    {
        DbgMsg(__FUNCTION__"(): IRP_MJ_CLOSE\n");

        // delete all filter rules
        FltAllowFlushList();
        FltDenyFlushList();

        KeWaitForMutexObject(&ListMutex, Executive, KernelMode, FALSE, NULL);   

        // close pipe handle
        if (hLogPipe)
        {
            ZwClose(hLogPipe);
            hLogPipe = NULL;
        }

        // close logfile handle
        if (hLogFile)
        {
            ZwClose(hLogFile);
            hLogFile = NULL;
        }

        bHexDump = FALSE;
        bLogRequests = FALSE;
        bDebugLogRequests = FALSE;
        bFuzeRequests = FALSE;
        bFuzeSize = FALSE;

        KeReleaseMutex(&ListMutex, FALSE);
    }

    if (ns != STATUS_PENDING)
    {        
        Irp->IoStatus.Status = ns;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return ns;
}
//--------------------------------------------------------------------------------------
void DriverUnload(PDRIVER_OBJECT DriverObject)
{   
    DbgMsg("DriverUnload()\n");

    // delete device
    IoDeleteSymbolicLink(&usDosDeviceName);
    IoDeleteDevice(DeviceObject);

    // delete all filter rules
    FltAllowFlushList();
    FltDenyFlushList();

    if (OldNtDeviceIoControlFile)
    {
        ForEachProcessor(ClearWp, NULL);

        // delete hooks
        InterlockedExchange(
            (PLONG)&SYSTEM_SERVICE(SDT_NtDeviceIoControlFile), 
            (ULONG)OldNtDeviceIoControlFile
        );

        ForEachProcessor(SetWp, NULL);
    }

    LARGE_INTEGER Timeout = { 0 };
    Timeout.QuadPart = RELATIVE(SECONDS(1));
    KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
}
//--------------------------------------------------------------------------------------
NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{    
    DbgMsg(__FUNCTION__"(): '%wZ'\n", RegistryPath);    

    switch (*NtBuildNumber)
    {
    case 2600:           // win xp
        KTHREAD_PrevMode = 0x140;
        break;

    case 3790:           // win 2003 server
        KTHREAD_PrevMode = 0x0d7;
        break;

    case 6000:           // win vista
        KTHREAD_PrevMode = 0x0e7;
        break;

    case 6001:           // win vista SP1/2008 server
        KTHREAD_PrevMode = 0x0e7;
        break;

    default:
        DbgMsg("ERROR: Unknown NtBuildNumber, cant install hooks\n");
        return STATUS_UNSUCCESSFUL;
    }

    DriverObject->DriverUnload = DriverUnload;

    // initialize random number generator
    LARGE_INTEGER TickCount;
    KeQueryTickCount(&TickCount);
    init_genrand(TickCount.LowPart);

    // Get offset of EPROCESS::Name field
    EPROCESS_name = GetProcessNameOffset();
    if (EPROCESS_name == 0)
    {
        DbgMsg("Error while lookuping EPROCESS::Name offset.\n");
        return STATUS_UNSUCCESSFUL;
    }

    KeInitializeMutex(&ListMutex, NULL);

    RtlInitUnicodeString(&usDeviceName, L"\\Device\\" DEVICE_NAME);
    RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\" DEVICE_NAME);            

    // lookup sdt indexes
    InitSdtNumbers();
    if (SDT_NtDeviceIoControlFile)
    {
        // create driver communication device
        NTSTATUS ns = IoCreateDevice(
            DriverObject, 
            0, 
            &usDeviceName, 
            FILE_DEVICE_UNKNOWN, 
            FILE_DEVICE_SECURE_OPEN, 
            FALSE, 
            &DeviceObject
        );
        if (NT_SUCCESS(ns))
        {
            DriverObject->MajorFunction[IRP_MJ_CREATE]         = 
            DriverObject->MajorFunction[IRP_MJ_CLOSE]          = 
            DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;

            ns = IoCreateSymbolicLink(&usDosDeviceName, &usDeviceName);
            if (NT_SUCCESS(ns))
            {
                ForEachProcessor(ClearWp, NULL);

                // set up hooks
                OldNtDeviceIoControlFile = (NT_DEVICE_IO_CONTROL_FILE)InterlockedExchange(
                    (PLONG)&SYSTEM_SERVICE(SDT_NtDeviceIoControlFile), 
                    (ULONG)NewNtDeviceIoControlFile
                );

                ForEachProcessor(SetWp, NULL);

                return STATUS_SUCCESS;
            }
            else
            {
                DbgMsg("IoCreateSymbolicLink() fails: 0x%.8x\n", ns);            
            }

            IoDeleteDevice(DeviceObject);
        } 
        else 
        {
            DbgMsg("IoCreateDevice() fails: 0x%.8x\n", ns);
        }
    }
    else
    {
        DbgMsg("Error while lookuping SDT index.\n");        
    }

    return STATUS_UNSUCCESSFUL;
}
//--------------------------------------------------------------------------------------
// EoF
