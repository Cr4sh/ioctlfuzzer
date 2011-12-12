#include "stdafx.h"

NT_DEVICE_IO_CONTROL_FILE old_NtDeviceIoControlFile = NULL;

/**
 * Fuzzing settings
 */
ULONG m_FuzzOptions = 0;
FUZZING_TYPE m_FuzzingType = FuzzingType_Random;
BOOLEAN m_bEnableDbgcb = FALSE;

/**
 * Exported variables for acessing to the 
 * last IOCTL request information from the kernel debugger.
 */
PDEVICE_OBJECT currentDeviceObject = NULL;
PDRIVER_OBJECT currentDriverObject = NULL;
ULONG currentIoControlCode = 0;
PVOID currentInputBuffer = NULL;
ULONG currentInputBufferLength = 0;
PVOID currentOutputBuffer = NULL;
ULONG currentOutputBufferLength = 0;

/**
 * Handle and objetc pointer of the fuzzer's process (uses for fair fuzzing mode)
 */
HANDLE m_FuzzThreadId = 0;
PEPROCESS m_FuzzProcess = NULL;
PUSER_MODE_DATA m_UserModeData = NULL;

/**
* Some fuzzing parameters
*/
#define RANDOM_FUZZING_ITERATIONS   10
#define BUFFERED_FUZZING_ITERATIONS 5
#define DWORD_FUZZING_MAX_LENGTH    0x200
#define DWORD_FUZZING_DELTA         4

#ifdef _X86_

// pointer values for invalid kernel and user buffers
#define KERNEL_BUFFER_ADDRESS (PVOID)(0xFFFF0000)
#define USER_BUFFER_ADDRESS   (PVOID)(0x00001000)

#elif _AMD64_

#define KERNEL_BUFFER_ADDRESS (PVOID)(0xFFFFFFFFFFFF0000)
#define USER_BUFFER_ADDRESS   (PVOID)(0x0000000000001000)

#endif

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

                if (m_FuzzOptions & FUZZ_OPT_FUZZ_SIZE)
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
                // fuzz each dword value in input buffer
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

    // try to fuzz missing output buffer length checks
    if (OutputBufferLength > 0)
    {        
        // ... with user-mode buffer addresses
        PVOID TmpOutputBuffer = USER_BUFFER_ADDRESS;

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
            TmpOutputBuffer, 0
        );        

        // ... with kernel-mode buffer addresses
        TmpOutputBuffer = KERNEL_BUFFER_ADDRESS;

        // set previous mode to UserMode
        SetPreviousMode(PrevMode);

        // send fuzzed request
        status = old_NtDeviceIoControlFile(
            FileHandle, 
            Event, ApcRoutine, 
            ApcContext, 
            IoStatusBlock, 
            IoControlCode, 
            InputBuffer, 
            InputBufferLength, 
            TmpOutputBuffer, 0
        );
    }

    ULONG Method = IoControlCode & 3;
    if (Method != METHOD_BUFFERED)
    {
        // try to fuzz buffer addresses, if method is not buffered
        for (int i = 0; i < BUFFERED_FUZZING_ITERATIONS; i++)
        {
            // ... with user-mode addresses
            PVOID TmpInputBuffer  = USER_BUFFER_ADDRESS;
            PVOID TmpOutputBuffer = USER_BUFFER_ADDRESS;
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
            PVOID TmpInputBuffer  = KERNEL_BUFFER_ADDRESS;
            PVOID TmpOutputBuffer = KERNEL_BUFFER_ADDRESS;
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

    if (m_FuzzOptions & FUZZ_OPT_FUZZ_FAIR)
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
    BOOLEAN bLogOutputBuffer = FALSE;

#ifdef USE_CHECK_PREV_MODE    

    // handle only user mode calls
    if (PrevMode != KernelMode)

#endif // CHECK_PREV_MODE

    {
        POBJECT_NAME_INFORMATION DeviceObjectName = NULL, DriverObjectName = NULL;    
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
            PVOID pDeviceObject = NULL;

            // validate pointer to device object
            if (MmIsAddressValid(pFileObject->DeviceObject))
            {
                pDeviceObject = pFileObject->DeviceObject;
            }
            else
            {
                goto end;
            }

            if (pDeviceObject == m_DeviceObject)
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
            if (DeviceObjectName = GetObjectName(pDeviceObject))
            {            
                if (DriverObjectName = GetObjectName(pFileObject->DeviceObject->DriverObject))
                {
                    PEPROCESS Process = PsGetCurrentProcess();
                    HANDLE ProcessId = PsGetCurrentProcessId();

                    LARGE_INTEGER Timeout;
                    Timeout.QuadPart = RELATIVE(SECONDS(5));

                    ns = KeWaitForMutexObject(&m_CommonMutex, Executive, KernelMode, FALSE, &Timeout);
                    if (ns == STATUS_TIMEOUT)
                    {
                        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Wait timeout\n");
                        ExFreePool(DeviceObjectName);
                        goto end;
                    }

                    BOOLEAN bProcessEvent = FALSE;

                    __try
                    {
                        // get process image path
                        PUNICODE_STRING ProcessImagePath = LookupProcessName(NULL);                
                        if (ProcessImagePath)
                        {                                                                              
                            LARGE_INTEGER Time;
                            KeQuerySystemTime(&Time);

                            PWSTR Methods[] = 
                            {
                                L"METHOD_BUFFERED",
                                L"METHOD_IN_DIRECT",
                                L"METHOD_OUT_DIRECT",
                                L"METHOD_NEITHER"
                            };

                            // get text name of the method
                            PWSTR lpwcMethod = Methods[IoControlCode & 3];

                            currentDeviceObject = pFileObject->DeviceObject;
                            currentDriverObject = pFileObject->DeviceObject->DriverObject;
                            currentIoControlCode = IoControlCode;
                            currentInputBuffer = InputBuffer;
                            currentInputBufferLength = InputBufferLength;
                            currentOutputBuffer = OutputBuffer;
                            currentOutputBufferLength = OutputBufferLength;

                            if (m_FuzzOptions & FUZZ_OPT_LOG_IOCTL_GLOBAL)
                            {
                                // log IOCTL information into the global log
                                LogDataIoctls("timestamp=0x%.8x%.8x\r\n", Time.HighPart, Time.LowPart);
                                LogDataIoctls("process_id=%d\r\n", ProcessId);
                                LogDataIoctls("process_path=%wZ\r\n", ProcessImagePath);
                                LogDataIoctls("device=%wZ\r\n", &DeviceObjectName->Name);
                                LogDataIoctls("driver=%wZ\r\n", &DriverObjectName->Name);
                                LogDataIoctls("image_file=%wZ\r\n", &pModuleEntry->FullDllName);
                                LogDataIoctls("code=0x%.8x\r\n", IoControlCode);
                                LogDataIoctls("method=%ws\r\n", lpwcMethod);
                                LogDataIoctls("in_size=%d\r\n", InputBufferLength);
                                LogDataIoctls("out_size=%d\r\n", OutputBufferLength);
                                LogDataIoctls("\r\n");
                            }

                            // get debugger command, that can be associated with this IOCTL
                            char *lpszKdCommand = FltGetKdCommand(
                                &DeviceObjectName->Name,
                                &pModuleEntry->FullDllName,
                                IoControlCode,
                                ProcessImagePath
                            );

                            bProcessEvent = FltIsMatchedRequest(
                                &DeviceObjectName->Name,
                                &pModuleEntry->FullDllName,
                                IoControlCode,
                                ProcessImagePath
                            );

                            if ((bProcessEvent || (lpszKdCommand && m_bEnableDbgcb)) &&
                                (m_FuzzOptions & FUZZ_OPT_LOG_IOCTL))
                            {
                                bLogOutputBuffer = TRUE;

                                // log common information about this IOCTL
                                LogData(
                                    "'%wZ' (PID: %d)\r\n"
                                    "'%wZ' ("IFMT") [%wZ]\r\n"
                                    "IOCTL Code: 0x%.8x,  Method: %ws\r\n",
                                    ProcessImagePath, ProcessId, &DeviceObjectName->Name, pDeviceObject, 
                                    &pModuleEntry->FullDllName, IoControlCode, lpwcMethod
                                );

                                if (m_FuzzOptions & FUZZ_OPT_LOG_IOCTL_BUFFERS)
                                {
                                    LogData("\r\n");
                                }

                                // log output buffer information
                                LogData("   OutBuff: "IFMT", OutSize: 0x%.8x\r\n", OutputBuffer, OutputBufferLength);

                                // log input buffer information
                                LogData("    InBuff: "IFMT",  InSize: 0x%.8x\r\n", InputBuffer, InputBufferLength);

                                if ((m_FuzzOptions & FUZZ_OPT_LOG_IOCTL_BUFFERS) && 
                                    InputBufferLength > 0 && InputBufferLength)
                                {
                                    // print input buffer contents
                                    LogData("--------------------------------------------------------------------\r\n");
                                    LogDataHexdump((PUCHAR)InputBuffer, min(InputBufferLength, MAX_IOCTL_BUFFER_LEGTH));
                                }                                

                                LogData("\r\n");

                                if (lpszKdCommand && m_bEnableDbgcb)
                                {
                                    DbgPrint(
                                        "<?dml?>" __FUNCTION__ "(): <exec cmd=\"eb " DRIVER_SERVICE_NAME "!m_bEnableDbgcb 0\">"
                                        "Disable kernel debugger interaction</exec>\n"
                                    );

                                    if (strlen(lpszKdCommand) > 0)
                                    {
                                        // execute specified debugger command
                                        DbgPrint(
                                            "<?dml?>" __FUNCTION__ "(): Command=<exec cmd=\"%s\">%s</exec>\n",
                                            lpszKdCommand, lpszKdCommand
                                        );

                                        dbg_exec(lpszKdCommand);
                                    }
                                    else
                                    {
                                        // empty command, break into the kernel debugger
                                        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Breaking into the kernel debugger...\n");
                                        DbgBreakPoint();
                                    }

                                    DbgPrint("\r\n");
                                }
                            }    

                            currentDeviceObject = NULL;
                            currentDriverObject = NULL;
                            currentIoControlCode = 0;
                            currentInputBuffer = NULL;
                            currentInputBufferLength = 0;
                            currentOutputBuffer = NULL;
                            currentOutputBufferLength = 0;
                        }
                    }
                    __finally
                    {
                        KeReleaseMutex(&m_CommonMutex, FALSE);
                    }

                    if (InputBuffer != NULL && InputBufferLength > 0 &&
                        (m_FuzzOptions & FUZZ_OPT_FUZZ) && bProcessEvent)
                    {   
                        // fuzz this request
                        Fuzz_NtDeviceIoControlFile(
                            PrevMode,
                            &DeviceObjectName->Name,
                            FileHandle,    
                            IoStatusBlock,
                            IoControlCode,
                            InputBuffer,
                            InputBufferLength,
                            OutputBuffer,
                            OutputBufferLength
                        );
                    }

                    ExFreePool(DriverObjectName);
                }                
                
                ExFreePool(DeviceObjectName);
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
    NTSTATUS status = old_NtDeviceIoControlFile(
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

    return status;
}
//--------------------------------------------------------------------------------------
// EoF
