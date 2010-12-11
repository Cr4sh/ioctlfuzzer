#include "stdafx.h"

#define CHECK_PREV_MODE

NT_DEVICE_IO_CONTROL_FILE old_NtDeviceIoControlFile = NULL;

/**
 * Fuzzing settings
 */
ULONG m_FuzzOptions = 0;
FUZZING_TYPE m_FuzzingType = FuzzingType_Random;

/**
 * Handle and objetc pointer of the fizzer's process (uses for fair fuzzing mode)
 */
HANDLE m_FuzzThreadId = 0;
PEPROCESS m_FuzzProcess = NULL;
PUSER_MODE_DATA m_UserModeData = NULL;

/**
* Some fuzzing parameters
*/
#define RANDOM_FUZZING_ITERATIONS   10
#define BUFFERED_FUZZING_ITERATIONS 5
#define DWORD_FUZZING_MAX_LENGTH    0x100
#define DWORD_FUZZING_DELTA         4

// constants for dword fuzzing
ULONG m_DwordFuzzingConstants[] =
{
    0x00000000,
    0x00001000,
    0xFFFF0000,
    0xFFFFFFFF
};

// defined in driver.cpp
extern PDEVICE_OBJECT m_DeviceObject;
extern KMUTEX m_CommonMutex;
extern PCOMMON_LST m_ProcessesList;
//--------------------------------------------------------------------------------------
PCOMMON_LST_ENTRY LookupProcessInfo(PEPROCESS Process)
{
    PCOMMON_LST_ENTRY process_entry = NULL;
    KIRQL OldIrql;
    KeAcquireSpinLock(&m_ProcessesList->ListLock, &OldIrql);

    __try
    {
        PCOMMON_LST_ENTRY e = m_ProcessesList->list_head;

        // enumerate all processes
        while (e)
        {
            if (e->Data && e->DataSize == sizeof(LST_PROCESS_INFO))
            {                
                PLST_PROCESS_INFO Info = (PLST_PROCESS_INFO)e->Data;
                if (Info->Process == Process)
                {
                    process_entry = e;
                    break;
                }
            }

            e = e->next;
        }
    }    
    __finally
    {
        KeReleaseSpinLock(&m_ProcessesList->ListLock, OldIrql);
    }

    return process_entry;
}
//--------------------------------------------------------------------------------------
void FreeProcessInfo(void)
{
    KIRQL OldIrql;
    KeAcquireSpinLock(&m_ProcessesList->ListLock, &OldIrql);

    __try
    {
        PCOMMON_LST_ENTRY e = m_ProcessesList->list_head;

        // enumerate all processes
        while (e)
        {
            if (e->Data && e->DataSize == sizeof(LST_PROCESS_INFO))
            {                
                PLST_PROCESS_INFO Info = (PLST_PROCESS_INFO)e->Data;
                if (Info->usImagePath.Buffer)
                {
                    // free process image path
                    RtlFreeUnicodeString(&Info->usImagePath);
                }
            }

            e = e->next;
        }
    }    
    __finally
    {
        KeReleaseSpinLock(&m_ProcessesList->ListLock, OldIrql);
    }
}
//--------------------------------------------------------------------------------------
void NTAPI ProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    PEPROCESS Process;
    NTSTATUS ns = PsLookupProcessByProcessId(ProcessId, &Process);
    if (NT_SUCCESS(ns))
    {
        KeWaitForMutexObject(&m_CommonMutex, UserRequest, KernelMode, FALSE, NULL);

        __try
        {
            if (Create)
            {                        
                // process has been created
                UNICODE_STRING ImagePath;

                // get full image path for this process
                if (GetProcessFullImagePath(Process, &ImagePath))
                {
                    WCHAR wcProcess[0x200];
                    UNICODE_STRING usProcess;

                    LogData("Process "IFMT" started: '%wZ' (PID: %d)\r\n\r\n", Process, &ImagePath, ProcessId);

                    swprintf(wcProcess, L"'%wZ' (" IFMT_W L")", &ImagePath, Process);
                    RtlInitUnicodeString(&usProcess, wcProcess);                               

                    LST_PROCESS_INFO Info;
                    Info.Process = Process;
                    Info.ProcessId = ProcessId;

                    Info.usImagePath.Buffer = ImagePath.Buffer;
                    Info.usImagePath.Length = ImagePath.Length;
                    Info.usImagePath.MaximumLength = ImagePath.MaximumLength;

                    // add process information into the list
                    if (LstAddEntry(m_ProcessesList, &usProcess, &Info, sizeof(Info)) == NULL)
                    {
                        RtlFreeUnicodeString(&ImagePath);
                    }                                
                }                                    
            }
            else
            {
                LogData("Process "IFMT" terminated\r\n\r\n", Process);

                // process terminating
                PCOMMON_LST_ENTRY process_entry = LookupProcessInfo(Process);            
                if (process_entry)
                {
                    if (process_entry->Data && 
                        process_entry->DataSize == sizeof(LST_PROCESS_INFO))
                    {                
                        PLST_PROCESS_INFO Info = (PLST_PROCESS_INFO)process_entry->Data;
                        if (Info->usImagePath.Buffer)
                        {
                            // free process image path
                            RtlFreeUnicodeString(&Info->usImagePath);
                        }
                    }

                    // delete information about this process from list
                    LstDelEntry(m_ProcessesList, process_entry);
                }
            }
        }
        __finally
        {
            KeReleaseMutex(&m_CommonMutex, FALSE);
        }        
        
        ObDereferenceObject(Process);
    } 
    else 
    {
        DbgMsg(__FILE__, __LINE__, "PsLookupProcessByProcessId() fails; status: 0x%.8x\n", ns);
    }
}
//--------------------------------------------------------------------------------------
PUNICODE_STRING LookupProcessName(PEPROCESS TargetProcess)
{
    PEPROCESS Process = TargetProcess;

    if (Process == NULL)
    {
        // lookup current process information entry
        Process = PsGetCurrentProcess();
    }
    
    PCOMMON_LST_ENTRY process_entry = LookupProcessInfo(Process);
    if (process_entry)
    {
        if (process_entry->Data && 
            process_entry->DataSize == sizeof(LST_PROCESS_INFO))
        {                
            PLST_PROCESS_INFO Info = (PLST_PROCESS_INFO)process_entry->Data;
            if (Info->usImagePath.Buffer)
            {
                // return process image path
                return &Info->usImagePath;
            }
        }

        return NULL;
    }

    // information entry for current process is not found, allocate it
    HANDLE ProcessId = PsGetCurrentProcessId();
    UNICODE_STRING ImagePath, *Ret = NULL;

    // get full image path for this process
    if (GetProcessFullImagePath(Process, &ImagePath))
    {
        WCHAR wcProcess[0x200];
        UNICODE_STRING usProcess;

        swprintf(wcProcess, L"'%wZ' (" IFMT_W L")", &ImagePath, Process);
        RtlInitUnicodeString(&usProcess, wcProcess);

        LST_PROCESS_INFO Info;
        Info.Process = Process;
        Info.ProcessId = ProcessId;

        Info.usImagePath.Buffer = ImagePath.Buffer;
        Info.usImagePath.Length = ImagePath.Length;
        Info.usImagePath.MaximumLength = ImagePath.MaximumLength;

        // add process information into the list
        if (process_entry = LstAddEntry(m_ProcessesList, &usProcess, &Info, sizeof(Info)))
        {
            PLST_PROCESS_INFO pInfo = (PLST_PROCESS_INFO)process_entry->Data;
            Ret = &pInfo->usImagePath;
        }
        else
        {
            RtlFreeUnicodeString(&ImagePath);
        }                
    }

    return Ret;
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
void FuzzContinue_NtDeviceIoControlFile(
    KPROCESSOR_MODE PrevMode,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength)
{                       
    // allocate temporary buffer for original request
    PUCHAR NewBuff = (PUCHAR)M_ALLOC(InputBufferLength);
    if (NewBuff)
    {
        RtlCopyMemory(NewBuff, InputBuffer, InputBufferLength);

        if (m_FuzzingType == FuzzingType_Random)
        {
            /**
            * Fuzzing with random values
            */

            for (int i = 0; i < RANDOM_FUZZING_ITERATIONS; i++)
            {
                ULONG TmpInputLength = InputBufferLength;

                if (m_FuzzOptions & FUZZ_OPT_FUZZSIZE)
                {
                    TmpInputLength = getrand(1, TmpInputLength * 4);
                }
              
                // fill buffer with random data
                for (ULONG s = 0; s < InputBufferLength; s++)
                {
                    *((PUCHAR)InputBuffer + s) = (UCHAR)getrand(1, 0xff);
                }
              
                // change previous mode to UserMode
                SetPreviousMode(PrevMode);

                // send fuzzed request
                NTSTATUS status = old_NtDeviceIoControlFile(
                    FileHandle, 
                    Event, ApcRoutine, 
                    ApcContext, 
                    IoStatusBlock, 
                    IoControlCode, 
                    InputBuffer, 
                    TmpInputLength, 
                    OutputBuffer, 
                    OutputBufferLength
                );
            }
        }
        else if (m_FuzzingType == FuzzingType_Dword)
        {             
            /**
            * Fuzzing with predefined dwords
            */

            // check buffer length 
            ULONG FuzzingLength = XALIGN_DOWN(InputBufferLength, sizeof(ULONG));
            if (FuzzingLength <= DWORD_FUZZING_MAX_LENGTH && FuzzingLength >= sizeof(ULONG))
            {
                // fuze each dword in input buffer
                for (ULONG i = 0; i < FuzzingLength; i += DWORD_FUZZING_DELTA)
                {
                    for (ULONG i_v = 0; i_v < sizeof(m_DwordFuzzingConstants) / sizeof(ULONG); i_v++)
                    {                        
                        // put dword constant into the buffer
                        ULONG OldBuffVal = *(PULONG)((PUCHAR)InputBuffer + i);
                        *(PULONG)((PUCHAR)InputBuffer + i) = m_DwordFuzzingConstants[i_v];                        
                        
                        // set previous mode to UserMode
                        SetPreviousMode(PrevMode);

                        // send fuzzed request
                        NTSTATUS status = old_NtDeviceIoControlFile(
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

                        // restore changed dword
                        *(PULONG)((PUCHAR)InputBuffer + i) = OldBuffVal;                        
                    }
                }
            }
        }

        
        // restore buffer
        RtlCopyMemory(InputBuffer, NewBuff, InputBufferLength);        
        ExFreePool(NewBuff);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR\n");
    }

    ULONG Method = IoControlCode & 3;
    if (Method != METHOD_BUFFERED)
    {
        // try to fuze addresses, if the method is not buffered
        for (int i = 0; i < BUFFERED_FUZZING_ITERATIONS; i++)
        {
            // ... with user-mode addresses
            PVOID TmpInputBuffer  = (PVOID)((PUCHAR)MM_HIGHEST_USER_ADDRESS - 0x1000);
            PVOID TmpOutputBuffer = (PVOID)((PUCHAR)MM_HIGHEST_USER_ADDRESS - 0x1000);
            ULONG TmpInputBufferLength  = getrand(0, 0x100);
            ULONG TmpOutputBufferLength = getrand(0, 0x100);

            // set previous mode to UserMode
            SetPreviousMode(PrevMode);

            // send fuzzed request
            NTSTATUS status = old_NtDeviceIoControlFile(
                FileHandle, 
                Event, ApcRoutine, 
                ApcContext, 
                IoStatusBlock, 
                IoControlCode, 
                TmpInputBuffer, 
                TmpInputBufferLength, 
                TmpOutputBuffer, 
                TmpOutputBufferLength
            );
        }

        for (int i = 0; i < BUFFERED_FUZZING_ITERATIONS; i++)
        {
            // ... with kernel-mode addresses
            PVOID TmpInputBuffer  = (PVOID)((PUCHAR)MM_HIGHEST_USER_ADDRESS + 0xC000);
            PVOID TmpOutputBuffer = (PVOID)((PUCHAR)MM_HIGHEST_USER_ADDRESS + 0xC000);
            ULONG TmpInputBufferLength  = getrand(0, 0x100);
            ULONG TmpOutputBufferLength = getrand(0, 0x100);

            // change previous mode to UserMode
            SetPreviousMode(PrevMode);

            // send fuzzed request
            NTSTATUS status = old_NtDeviceIoControlFile(
                FileHandle, 
                Event, 
                ApcRoutine, 
                ApcContext, 
                IoStatusBlock, 
                IoControlCode, 
                TmpInputBuffer, 
                TmpInputBufferLength, 
                TmpOutputBuffer, 
                TmpOutputBufferLength
            );
        }
    }
}
//--------------------------------------------------------------------------------------
typedef struct _FUZZ_THREAD_PARAMS
{
    KPROCESSOR_MODE PrevMode;
    HANDLE hFuzzHandle;
    PIO_STATUS_BLOCK cIoStatusBlock;
    ULONG IoControlCode;
    PVOID cInputBuffer;
    PVOID cOutputBuffer;
    ULONG cInputBufferLength;
    ULONG cOutputBufferLength;
    KEVENT OperationComplete;

} FUZZ_THREAD_PARAMS,
*PFUZZ_THREAD_PARAMS;

VOID ApcNormalRoutine(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2)
{
    /**
     * This code exeuting in context of the fuzzer's process 
     * as normal APC routine.
     */
    PFUZZ_THREAD_PARAMS ThreadParams = (PFUZZ_THREAD_PARAMS)NormalContext;

    // continue fuzzing
    FuzzContinue_NtDeviceIoControlFile(
        ThreadParams->PrevMode,
        ThreadParams->hFuzzHandle,
        NULL, NULL, NULL,
        ThreadParams->cIoStatusBlock,
        ThreadParams->IoControlCode,
        ThreadParams->cInputBuffer,
        ThreadParams->cInputBufferLength,
        ThreadParams->cOutputBuffer,
        ThreadParams->cOutputBufferLength
    );
    
    // notify caller thread about APC termination
    KeSetEvent(&ThreadParams->OperationComplete, 0, FALSE); 
}

VOID ApcKernelRoutine(
    struct _KAPC *Apc,
    PKNORMAL_ROUTINE *NormalRoutine,
    PVOID *NormalContext,
    PVOID *SystemArgument1,
    PVOID *SystemArgument2) 
{
    /**
     * This code exeuting in context of the fuzzer's process at APC_LEVEL.
     * Nothing to do here...
     */
}
//--------------------------------------------------------------------------------------
void Fuzz_NtDeviceIoControlFile(
    KPROCESSOR_MODE PrevMode,
    PUNICODE_STRING usDeviceName,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength)
{    
    MAPPED_MDL InBuffMapped, OutBuffMapped;
    KAPC_STATE ApcState;
    BOOLEAN bInBuffMapped = FALSE, bOutBuffMapped = FALSE, bNeedToDetach = FALSE;
    PVOID TmpInputBuffer = NULL, TmpOutputBuffer = NULL;

    // save original parameters from the nt!NtDeviceIoControlFile()
    FUZZ_THREAD_PARAMS ThreadParams;
    ThreadParams.PrevMode = PrevMode;
    ThreadParams.hFuzzHandle = FileHandle;
    ThreadParams.cIoStatusBlock = IoStatusBlock;
    ThreadParams.IoControlCode = IoControlCode;
    ThreadParams.cInputBuffer = InputBuffer;
    ThreadParams.cOutputBuffer = OutputBuffer;
    ThreadParams.cInputBufferLength = InputBufferLength;
    ThreadParams.cOutputBufferLength = OutputBufferLength;    

    if (m_FuzzOptions & FUZZ_OPT_FAIRFUZZ)
    {
        /**
         * Sending IOCTL's from context of the fuzzer process.
         */

        // check for available process, thread and pointer to the user mode data
        if (m_FuzzProcess && m_FuzzThreadId && m_UserModeData)
        {            
            if (InputBuffer != NULL && InputBufferLength > 0)
            {
                // allocate user mode buffer for input data
                if (TmpInputBuffer = M_ALLOC(InputBufferLength))
                {
                    memcpy(TmpInputBuffer, InputBuffer, InputBufferLength);
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, "M_ALLOC() fails\n"); 
                    goto exit;
                }
            }

            if (OutputBuffer != NULL && OutputBufferLength > 0)
            {
                // allocate user mode buffer for output data
                if (TmpOutputBuffer = M_ALLOC(OutputBufferLength))
                {
                    memcpy(TmpOutputBuffer, OutputBuffer, OutputBufferLength);
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, "M_ALLOC() fails\n"); 
                    goto exit;
                }
            }

            // attach to the fuzzer process
            KeStackAttachProcess(m_FuzzProcess, &ApcState);

            bNeedToDetach = TRUE;
            ThreadParams.cIoStatusBlock = &m_UserModeData->IoStatus;

            OBJECT_ATTRIBUTES ObjAttr;
            InitializeObjectAttributes(&ObjAttr, usDeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

            // open target device object
            NTSTATUS ns = ZwOpenFile(
                &ThreadParams.hFuzzHandle,
                FILE_READ_DATA | FILE_WRITE_DATA,
                &ObjAttr, 
                &m_UserModeData->IoStatus,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
                FILE_SYNCHRONOUS_IO_NONALERT
            );
            if (!NT_SUCCESS(ns))
            {
                DbgMsg(__FILE__, __LINE__, "ZwOpenFile() fails; status: 0x%.8x\r\n", ns);
                DbgMsg(__FILE__, __LINE__, "Error while opening device '%wZ'\r\n\r\n", usDeviceName);
                goto exit;
            }

            if (InputBuffer != NULL && InputBufferLength > 0)
            {
                // allocate user mode memory for input buffer
                if (bInBuffMapped = AllocateUserMemory(InputBufferLength, &InBuffMapped))
                {
                    ThreadParams.cInputBuffer = InBuffMapped.MappedBuffer;
                    memcpy(ThreadParams.cInputBuffer, TmpInputBuffer, InputBufferLength);
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Can't allocate memory for input buffer\r\n");
                    goto exit;
                }
            }

            if (OutputBuffer != NULL && OutputBufferLength > 0)
            {
                // allocate user mode memory for output buffer
                if (bOutBuffMapped = AllocateUserMemory(OutputBufferLength, &OutBuffMapped))
                {
                    ThreadParams.cOutputBuffer = OutBuffMapped.MappedBuffer;
                    memcpy(ThreadParams.cOutputBuffer, TmpOutputBuffer, OutputBufferLength);
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Can't allocate memory for output buffer\r\n");
                    goto exit;
                }
            }
            
            PETHREAD Thread = NULL;
            KAPC Apc;

            // get pointer to the fuzzer's thread            
            ns = PsLookupThreadByThreadId(m_FuzzThreadId, &Thread);
            if (NT_SUCCESS(ns))
            {
                // initialize synchronization event
                KeInitializeEvent(
                    &ThreadParams.OperationComplete,
                    NotificationEvent,
                    FALSE
                );

                // initialize APC    
                KeInitializeApc(
                    &Apc, 
                    (PKTHREAD)Thread, 
                    OriginalApcEnvironment, 
                    ApcKernelRoutine, 
                    NULL, 
                    ApcNormalRoutine, 
                    KernelMode, 
                    &ThreadParams
                );

                // queue APC execution
                if (KeInsertQueueApc(&Apc, NULL, NULL, 0))
                {
                    // waiting for APC execution
                    KeWaitForSingleObject(
                        &ThreadParams.OperationComplete,
                        Executive,
                        KernelMode,
                        FALSE, NULL
                    );
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, "KeInsertQueueApc() fails\n");
                }
            }      
            else
            {
                DbgMsg(__FILE__, __LINE__, "PsLookupThreadByThreadId() fails; status: 0x%.8x\n", ns);
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() WARNING: Fuzzer process/thread is not opened\n");
        }
    }
    else
    {
        /**
         * Sending IOCTL's from context of the original process.
         */
        FuzzContinue_NtDeviceIoControlFile(
            PrevMode,
            ThreadParams.hFuzzHandle,
            NULL, NULL, NULL,
            ThreadParams.cIoStatusBlock,
            IoControlCode,
            ThreadParams.cInputBuffer,
            ThreadParams.cInputBufferLength,
            ThreadParams.cOutputBuffer,
            ThreadParams.cOutputBufferLength
        );
    }    

exit:

    if (bOutBuffMapped)
    {
        // unmap input buffer
        FreeUserMemory(&OutBuffMapped);
    }

    if (bInBuffMapped)
    {
        // unmap input buffer
        FreeUserMemory(&InBuffMapped);
    }

    if (ThreadParams.hFuzzHandle != FileHandle)
    {
        ZwClose(ThreadParams.hFuzzHandle);
    }

    if (bNeedToDetach)
    {
        // detach from the fuzzer process
        KeUnstackDetachProcess(&ApcState);
    }

    if (TmpOutputBuffer)
    {
        M_FREE(TmpOutputBuffer);
    }

    if (TmpInputBuffer)
    {
        M_FREE(TmpInputBuffer);
    }
}
//--------------------------------------------------------------------------------------
NTSTATUS NTAPI new_NtDeviceIoControlFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength)
{    
    KPROCESSOR_MODE PrevMode = ExGetPreviousMode();

#ifdef CHECK_PREV_MODE    

    // handle only user mode calls
    if (PrevMode != KernelMode)

#endif // CHECK_PREV_MODE

    {
        POBJECT_NAME_INFORMATION ObjectName = NULL;    
        PFILE_OBJECT pFileObject = NULL;

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
                goto end;
            }

            if (pObject == m_DeviceObject)
            {
                // don't handle requests to our driver
                goto end;
            }

            // validate pointer to driver object
            if (!MmIsAddressValid(pFileObject->DeviceObject->DriverObject))
            {
                goto end;
            }

            // get loader information entry for the driver module
            PLDR_DATA_TABLE_ENTRY pModuleEntry = (PLDR_DATA_TABLE_ENTRY)
                pFileObject->DeviceObject->DriverObject->DriverSection;

            if (pModuleEntry == NULL)
            {
                goto end;
            }

            // validate pointer to loader's table and data from it
            if (!MmIsAddressValid(pModuleEntry) ||
                !ValidateUnicodeString(&pModuleEntry->FullDllName))
            {
                goto end;
            }

            // get device name by poinet
            if (ObjectName = GetObjectName(pObject))
            {            
                PEPROCESS Process = PsGetCurrentProcess();
                HANDLE ProcessId = PsGetCurrentProcessId();

                LARGE_INTEGER Timeout;
                Timeout.QuadPart = RELATIVE(SECONDS(5));

                ns = KeWaitForMutexObject(&m_CommonMutex, Executive, KernelMode, FALSE, &Timeout);               
                if (ns == STATUS_TIMEOUT)
                {
                    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Wait timeout\n");
                    ExFreePool(ObjectName);
                    goto end;
                }

                __try
                {
                    // get process image path
                    PUNICODE_STRING ImagePath = LookupProcessName(NULL);                
                    if (ImagePath)
                    {                                            
                        BOOLEAN bProcessEvent = FltIsMatchedRequest(
                            &ObjectName->Name,
                            &pModuleEntry->FullDllName,
                            IoControlCode,
                            ImagePath
                        );                       

                        if (bProcessEvent &&
                            (m_FuzzOptions & FUZZ_OPT_LOG_IOCTLS))
                        {    
                            PWSTR Methods[] = 
                            {
                                L"METHOD_BUFFERED",
                                L"METHOD_IN_DIRECT",
                                L"METHOD_OUT_DIRECT",
                                L"METHOD_NEITHER"
                            };

                            // get text name of the method
                            PWSTR lpwcMethod = Methods[IoControlCode & 3];

                            // log common information about this IOCTL
                            LogData(
                                "'%wZ' (PID: %d)\r\n"
                                "'%wZ' ("IFMT") [%wZ]\r\n"
                                "IOCTL Code: 0x%.8x,  Method: %ws\r\n",
                                ImagePath, ProcessId, &ObjectName->Name, pObject, 
                                &pModuleEntry->FullDllName, IoControlCode, lpwcMethod
                            );

                            if (m_FuzzOptions & FUZZ_OPT_HEXDUMP)
                            {
                                LogData("\r\n");
                            }

                            // log input buffer information
                            LogData("    InBuff: "IFMT",  InSize: 0x%.8x\r\n", InputBuffer, InputBufferLength);

                            if ((m_FuzzOptions & FUZZ_OPT_HEXDUMP) && InputBufferLength > 0)
                            {
                                // print input buffer contents
                                LogData("--------------------------------------------------------------------\r\n");
                                Hexdump((PUCHAR)InputBuffer, InputBufferLength);
                            }

                            // log output buffer information
                            LogData("   OutBuff: "IFMT", OutSize: 0x%.8x\r\n", OutputBuffer, OutputBufferLength);

                            if ((m_FuzzOptions & FUZZ_OPT_HEXDUMP) && OutputBufferLength > 0)
                            {
                                // print output buffer contents
                                LogData("--------------------------------------------------------------------\r\n");
                                Hexdump((PUCHAR)OutputBuffer, OutputBufferLength);
                            }

                            LogData("\r\n");
                        }    

                        if (InputBuffer != NULL && InputBufferLength > 0 &&
                            (m_FuzzOptions & FUZZ_OPT_FUZZ) && bProcessEvent)
                        {   
                            // fuze this request
                            Fuzz_NtDeviceIoControlFile(
                                PrevMode,
                                &ObjectName->Name,
                                FileHandle,    
                                IoStatusBlock,
                                IoControlCode,
                                InputBuffer,
                                InputBufferLength,
                                OutputBuffer,
                                OutputBufferLength
                            );
                        }
                    }
                }
                __finally
                {
                    KeReleaseMutex(&m_CommonMutex, FALSE);
                }
                
                ExFreePool(ObjectName);
            }
end:
            ObDereferenceObject(pFileObject);
        }        
        else
        {
            DbgMsg(__FILE__, __LINE__, "ObReferenceObjectByHandle() fails; status: 0x%.8x\n", ns);            
        }

        // restore KTHREAD::PreviousMode
        SetPreviousMode(PrevMode);        
    }

    // call original function
    NTSTATUS ns = old_NtDeviceIoControlFile(
        FileHandle, 
        Event, 
        ApcRoutine, 
        ApcContext, 
        IoStatusBlock, 
        IoControlCode, 
        InputBuffer, 
        InputBufferLength, 
        OutputBuffer, 
        OutputBufferLength
    );    

    return ns;
}
//--------------------------------------------------------------------------------------
// EoF
