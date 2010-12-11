#include "stdafx.h"

// kernel image base address and size
PVOID m_KernelBase = NULL;
ULONG m_KernelSize = 0;

BOOLEAN m_bKiDispatchExceptionHooked = FALSE;
BOOLEAN m_bLogExceptions = FALSE;

ULONG m_KiDispatchException_Offset = 0, m_KiDispatchException_BytesPatched = 0;
PVOID f_KiDispatchException = NULL;

func_KiDispatchException old_KiDispatchException = NULL;

// defined in driver.cpp
extern PDEVICE_OBJECT m_DeviceObject;
extern KMUTEX m_CommonMutex;

#define KI_EXCEPTION_INTERNAL               0x10000000
#define KI_EXCEPTION_GP_FAULT               (KI_EXCEPTION_INTERNAL | 0x1)
#define KI_EXCEPTION_INVALID_OP             (KI_EXCEPTION_INTERNAL | 0x2)
#define KI_EXCEPTION_INTEGER_DIVIDE_BY_ZERO (KI_EXCEPTION_INTERNAL | 0x3)
#define KI_EXCEPTION_ACCESS_VIOLATION       (KI_EXCEPTION_INTERNAL | 0x4)
//--------------------------------------------------------------------------------------
/**
 * Function from ExcpHook Global ring0 Exception Monitor 
 * By gynvael.coldwind//vx (http://gynvael.coldwind.pl)
 *
 * http://code.google.com/p/openrce-snippets/source/browse/trunk/standalone/ExcpHook/src/ExcpHook.cpp
 *
 */
char *ExceptionStr(ULONG ExceptionCode)
{
    switch (ExceptionCode)
    {
    case STATUS_SEGMENT_NOTIFICATION:         return "STATUS_SEGMENT_NOTIFICATION";
    case STATUS_GUARD_PAGE_VIOLATION:         return "STATUS_GUARD_PAGE_VIOLATION";
    case STATUS_DATATYPE_MISALIGNMENT:        return "STATUS_DATATYPE_MISALIGNMENT";
    case STATUS_BREAKPOINT:                   return "STATUS_BREAKPOINT";
    case STATUS_SINGLE_STEP:                  return "STATUS_SINGLE_STEP";
    case STATUS_ACCESS_VIOLATION:             return "STATUS_ACCESS_VIOLATION";
    case STATUS_IN_PAGE_ERROR:                return "STATUS_IN_PAGE_ERROR";
    case STATUS_INVALID_HANDLE:               return "STATUS_INVALID_HANDLE";
    case STATUS_NO_MEMORY:                    return "STATUS_NO_MEMORY";
    case STATUS_ILLEGAL_INSTRUCTION:          return "STATUS_ILLEGAL_INSTRUCTION";
    case STATUS_NONCONTINUABLE_EXCEPTION:     return "STATUS_NONCONTINUABLE_EXCEPTION";
    case STATUS_INVALID_DISPOSITION:          return "STATUS_INVALID_DISPOSITION";
    case STATUS_ARRAY_BOUNDS_EXCEEDED:        return "STATUS_ARRAY_BOUNDS_EXCEEDED";
    case STATUS_FLOAT_DENORMAL_OPERAND:       return "STATUS_FLOAT_DENORMAL_OPERAND";
    case STATUS_FLOAT_DIVIDE_BY_ZERO:         return "STATUS_FLOAT_DIVIDE_BY_ZERO";
    case STATUS_FLOAT_INEXACT_RESULT:         return "STATUS_FLOAT_INEXACT_RESULT";
    case STATUS_FLOAT_INVALID_OPERATION:      return "STATUS_FLOAT_INVALID_OPERATION";
    case STATUS_FLOAT_OVERFLOW:               return "STATUS_FLOAT_OVERFLOW";
    case STATUS_FLOAT_STACK_CHECK:            return "STATUS_FLOAT_STACK_CHECK";
    case STATUS_FLOAT_UNDERFLOW:              return "STATUS_FLOAT_UNDERFLOW";
    case STATUS_INTEGER_DIVIDE_BY_ZERO:       return "STATUS_INTEGER_DIVIDE_BY_ZERO";
    case STATUS_INTEGER_OVERFLOW:             return "STATUS_INTEGER_OVERFLOW";
    case STATUS_PRIVILEGED_INSTRUCTION:       return "STATUS_PRIVILEGED_INSTRUCTION";
    case STATUS_STACK_OVERFLOW:               return "STATUS_STACK_OVERFLOW";
    case STATUS_CONTROL_C_EXIT:               return "STATUS_CONTROL_C_EXIT";
    case KI_EXCEPTION_GP_FAULT:               return "KI_EXCEPTION_GP_FAULT";
    case KI_EXCEPTION_INVALID_OP:             return "KI_EXCEPTION_INVALID_OP";
    case KI_EXCEPTION_INTEGER_DIVIDE_BY_ZERO: return "KI_EXCEPTION_INTEGER_DIVIDE_BY_ZERO";
    case KI_EXCEPTION_ACCESS_VIOLATION:       return "KI_EXCEPTION_ACCESS_VIOLATION";
    }

    return NULL;
}
//--------------------------------------------------------------------------------------
void ProcessExceptionQueue(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    PEXCPT_HOOK_INFO Info = (PEXCPT_HOOK_INFO)Context;

    KeWaitForMutexObject(&m_CommonMutex, Executive, KernelMode, FALSE, NULL);
    
    __try
    {
        if (!m_bLogExceptions)
        {
            // exceptions monitor is not enabled
            __leave;
        }

        // ookup for process image path
        PUNICODE_STRING ImagePath = LookupProcessName(Info->Process);
        if (ImagePath)
        {
            ULONG Code = Info->ExceptionRecord.ExceptionCode;
            PVOID Addr = Info->ExceptionRecord.ExceptionAddress;

            // print process information
            LogData("'%wZ' (PID: %d, TID: %d)\r\n", ImagePath, Info->ProcessId, Info->ThreadId);

            char *lpszExceptionStr = ExceptionStr(Code);
            if (lpszExceptionStr)
            {
                // print general exception information
                LogData("%s at "IFMT"\r\n", lpszExceptionStr, Addr);
            }            
            else
            {
                LogData("Unknown exception 0x%.8x at "IFMT"\r\n", Code, Addr);
            }

            LogData(" First chance: %s\r\n", Info->FirstChance?"Yes":"No");

#ifdef _AMD64_
            LogData("        WOW64: %s\r\n", Info->bWow64?"Yes":"No");
#endif

            if (Code == STATUS_ACCESS_VIOLATION ||
                Code == KI_EXCEPTION_ACCESS_VIOLATION)
            {
                // print information for access violation exceptions
                LogData(
                    "  Access type: %s\r\n"
                    "      Address: "IFMT"\r\n",
                    Info->ExceptionRecord.ExceptionInformation[0]?"Write":"Read",
                    Info->ExceptionRecord.ExceptionInformation[1]
                );
            }
            else
            {                
                char szMsg[0x100];
                strcpy(szMsg, "   Parameters: ");

                if (Info->ExceptionRecord.NumberParameters > 0)
                {
                    // print information for other exceptions
                    for (ULONG i = 0; i < Info->ExceptionRecord.NumberParameters; i++)
                    {
                        if (i > 0 && i % 4 == 0)
                        {
                            strcat(szMsg, "\r\n               ");
                        }

                        char szParamStr[0x20];
                        sprintf(szParamStr, IFMT " ", Info->ExceptionRecord.ExceptionInformation[i]);
                        strcat(szMsg, szParamStr);
                    }
                }   
                else
                {
                    // there is no parameters for this exception
                    strcat(szMsg, "N/A");
                }

                LogData("%s\r\n", szMsg);
            }
            
            LogData("  Instruction: %s\r\n", Info->szInst);

#ifdef _X86_

            // log 32-bit registers
            LogData(
                "EAX=0x%.8x EBX=0x%.8x ECX=0x%.8x EDX=0x%.8x\r\n"
                "ESI=0x%.8x EDI=0x%.8x EBP=0x%.8x\r\n\r\n",
                Info->TrapFrame.Eax, Info->TrapFrame.Ebx, Info->TrapFrame.Ecx, Info->TrapFrame.Edx, 
                Info->TrapFrame.Esi, Info->TrapFrame.Edi, Info->TrapFrame.Ebp
            );

#elif _AMD64_

            // log 64-bit registers
            LogData(
                "RAX=0x%.16I64x RBX=0x%.16I64x RCX=0x%.16I64x\r\n"
                "RDX=0x%.16I64x RSI=0x%.16I64x RDI=0x%.16I64x\r\n"
                "RSP=0x%.16I64x RBP=0x%.16I64x  R8=0x%.16I64x\r\n" 
                " R9=0x%.16I64x R10=0x%.16I64x R11=0x%.16I64x\r\n\r\n",
                Info->TrapFrame.Rax, Info->TrapFrame.Rbx, Info->TrapFrame.Rcx,
                Info->TrapFrame.Rdx, Info->TrapFrame.Rsi, Info->TrapFrame.Rdi,
                Info->TrapFrame.Rsp, Info->TrapFrame.Rbp, Info->TrapFrame.R8, 
                Info->TrapFrame.R9, Info->TrapFrame.R10, Info->TrapFrame.R11
            );
#endif

        }    
    }    
    __finally
    {
        KeReleaseMutex(&m_CommonMutex, FALSE);
    }    

    // free work item
    IoFreeWorkItem(Info->WorkItem); 

    // free exception information structure
    ObDereferenceObject(Info->Process);
    M_FREE(Info);
}
//--------------------------------------------------------------------------------------
BOOLEAN IsValidMemory(PVOID Address)
{
    if (Address > MmHighestUserAddress)
    {
        // probe as kernel mode address
        return MmIsAddressValid(Address);
    }
    else
    {
        // probe as user mode address
        __try
        {
            ProbeForRead(Address, MAX_INST_LEN, 1);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return FALSE;
        }
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
VOID NTAPI new_KiDispatchException(
    PEXCEPTION_RECORD ExceptionRecord,
    PKEXCEPTION_FRAME ExceptionFrame,
    PKTRAP_FRAME TrapFrame,
    KPROCESSOR_MODE PreviousMode,
    BOOLEAN FirstChance)
{    
    if (ExceptionRecord->ExceptionAddress > m_KernelBase &&
        ExceptionRecord->ExceptionAddress < RVATOVA(m_KernelBase, m_KernelSize))
    {
        // skip exceptions inside kernel
        goto end;
    }

    PEXCPT_HOOK_INFO Info = (PEXCPT_HOOK_INFO)M_ALLOC(sizeof(EXCPT_HOOK_INFO));
    if (Info)
    {
        // copy current process information
        Info->Process = PsGetCurrentProcess();
        Info->ProcessId = PsGetCurrentProcessId();
        Info->ThreadId = PsGetCurrentThreadId();
        Info->FirstChance = FirstChance;
        Info->bWow64 = FALSE;

        ObReferenceObject(Info->Process);

        // copy exception information and trap frame
        RtlCopyMemory(&Info->ExceptionRecord, ExceptionRecord, sizeof(EXCEPTION_RECORD));
        RtlCopyMemory(&Info->TrapFrame, TrapFrame, sizeof(KTRAP_FRAME));

        // validate instruction pointer
        if (KeGetCurrentIrql() == PASSIVE_LEVEL &&
            IsValidMemory(ExceptionRecord->ExceptionAddress))
        {
            BOOLEAN bIsWow64 = FALSE;

            // query process type
            if (IsWow64Process(Info->Process, &bIsWow64))
            {
                ud_t ud_obj;

                // set disassembler options
                ud_init(&ud_obj);            
                ud_set_syntax(&ud_obj, UD_SYN_INTEL);
                ud_set_vendor(&ud_obj, UD_VENDOR_INTEL);                

#ifdef _X86_

                ud_set_mode(&ud_obj, 32);

#elif _AMD64_

                if (ExceptionRecord->ExceptionAddress > MmHighestUserAddress || 
                    !bIsWow64)
                {
                    ud_set_mode(&ud_obj, 64);
                }
                else
                {
                    ud_set_mode(&ud_obj, 32);
                }            
#endif

                // set input buffer for disassembler
                ud_set_input_buffer(&ud_obj, (PUCHAR)ExceptionRecord->ExceptionAddress, MAX_INST_LEN);
                ud_set_pc(&ud_obj, NULL);

                strcpy(Info->szInst, "<disassembling_error>");

                // disassembly single instruction
                if (ud_disassemble(&ud_obj))
                {
                    // copy mnemonic
                    strcpy(Info->szInst, ud_insn_asm(&ud_obj));
                }

                Info->bWow64 = bIsWow64;
            }
            else
            {
                strcpy(Info->szInst, "<internal_error>");
            }
        }   
        else
        {
            strcpy(Info->szInst, "<invalid_instruction_pointer>");
        }

        if (Info->WorkItem = IoAllocateWorkItem(m_DeviceObject))
        {
            // process exception in worker thread
            IoQueueWorkItem(
                Info->WorkItem, 
                ProcessExceptionQueue, 
                DelayedWorkQueue, 
                Info
            );
        }
        else
        {
            M_FREE(Info);
        }
    }

end:
    // call original function
    old_KiDispatchException(
        ExceptionRecord,
        ExceptionFrame,
        TrapFrame,
        PreviousMode,
        FirstChance
    );
}
//--------------------------------------------------------------------------------------
BOOLEAN ExcptHook(void)
{
    if (m_KiDispatchException_Offset == 0)
    {
        return FALSE;
    }

    if (m_KiDispatchException_BytesPatched != 0)
    {
        return FALSE;
    }

    if (m_KernelBase = KernelGetModuleBase("ntoskrnl.exe"))
    {
        f_KiDispatchException = RVATOVA(m_KernelBase, m_KiDispatchException_Offset);

        DbgMsg(__FILE__, __LINE__, "nt!KiDispatchException() is at "IFMT"\n", f_KiDispatchException);

        PIMAGE_NT_HEADERS32 pHeaders32 = (PIMAGE_NT_HEADERS32)
            ((PUCHAR)m_KernelBase + ((PIMAGE_DOS_HEADER)m_KernelBase)->e_lfanew);

        if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        {
            // 32-bit image
            m_KernelSize = pHeaders32->OptionalHeader.SizeOfImage;
        }        
        else if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            // 64-bit image
            PIMAGE_NT_HEADERS64 pHeaders64 = (PIMAGE_NT_HEADERS64)
                ((PUCHAR)m_KernelBase + ((PIMAGE_DOS_HEADER)m_KernelBase )->e_lfanew);

            m_KernelSize = pHeaders64->OptionalHeader.SizeOfImage;
        }

        // disable memory write protection
        ForEachProcessor(ClearWp, NULL); 

        old_KiDispatchException = (func_KiDispatchException)Hook(
            f_KiDispatchException,
            new_KiDispatchException,
            &m_KiDispatchException_BytesPatched
        );

        // enable memory write protection
        ForEachProcessor(SetWp, NULL);

        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOLEAN ExcptUnhook(void)
{
    if (f_KiDispatchException &&
        old_KiDispatchException &&
        m_KiDispatchException_BytesPatched > 0)
    {
        // disable memory write protection
        ForEachProcessor(ClearWp, NULL); 

        RtlCopyMemory(
            f_KiDispatchException,
            old_KiDispatchException,
            m_KiDispatchException_BytesPatched
        );

        // enable memory write protection
        ForEachProcessor(SetWp, NULL);

        M_FREE(old_KiDispatchException);

        old_KiDispatchException = NULL;
        m_KiDispatchException_BytesPatched = 0;

        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
// EoF
