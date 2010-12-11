
#ifdef _X86_

/**
 *
 * TRAP FRAME FOR i386
 *
 */

//
// Exception Registration structure
//
// X86 Call frame record definition, normally defined in nti386.h
// which is not included on risc.
//

typedef struct _EXCEPTION_REGISTRATION_RECORD 
{
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_ROUTINE Handler;

} EXCEPTION_REGISTRATION_RECORD,
*PEXCEPTION_REGISTRATION_RECORD;

typedef struct _KTRAP_FRAME 
{
    //
    //  Following 4 values are only used and defined for DBG systems,
    //  but are always allocated to make switching from DBG to non-DBG
    //  and back quicker.  They are not DEVL because they have a non-0
    //  performance impact.
    //

    ULONG DbgEbp;         // Copy of User EBP set up so KB will work.
    ULONG DbgEip;         // EIP of caller to system call, again, for KB.
    ULONG DbgArgMark;     // Marker to show no args here.
    ULONG DbgArgPointer;  // Pointer to the actual args

    //
    //  Temporary values used when frames are edited.
    //
    //
    //  NOTE:   Any code that want's ESP must materialize it, since it
    //          is not stored in the frame for kernel mode callers.
    //
    //          And code that sets ESP in a KERNEL mode frame, must put
    //          the new value in TempEsp, make sure that TempSegCs holds
    //          the real SegCs value, and put a special marker value into SegCs.
    //

    ULONG TempSegCs;
    ULONG TempEsp;

    //
    //  Debug registers.
    //

    ULONG Dr0;
    ULONG Dr1;
    ULONG Dr2;
    ULONG Dr3;
    ULONG Dr6;
    ULONG Dr7;

    //
    //  Segment registers
    //

    ULONG SegGs;
    ULONG SegEs;
    ULONG SegDs;

    //
    //  Volatile registers
    //

    ULONG Edx;
    ULONG Ecx;
    ULONG Eax;

    //
    //  Nesting state, not part of context record
    //

    ULONG PreviousPreviousMode;

    PEXCEPTION_REGISTRATION_RECORD ExceptionList;

    // Trash if caller was user mode.
    // Saved exception list if caller
    // was kernel mode or we're in
    // an interrupt.

    //
    //  FS is TIB/PCR pointer, is here to make save sequence easy
    //

    ULONG SegFs;

    //
    //  Non-volatile registers
    //

    ULONG Edi;
    ULONG Esi;
    ULONG Ebx;
    ULONG Ebp;

    //
    //  Control registers
    //

    ULONG ErrCode;
    ULONG Eip;
    ULONG SegCs;
    ULONG EFlags;

    ULONG HardwareEsp;    // WARNING - segSS:esp are only here for stacks
    ULONG HardwareSegSs;  // that involve a ring transition.

    ULONG V86Es;          // these will be present for all transitions from
    ULONG V86Ds;          // V86 mode
    ULONG V86Fs;
    ULONG V86Gs;

} KTRAP_FRAME,
*PKTRAP_FRAME;

typedef KTRAP_FRAME *PKEXCEPTION_FRAME;

#endif

typedef struct _EXCPT_HOOK_INFO
{
    PEPROCESS Process;
    HANDLE ProcessId;
    HANDLE ThreadId;
    BOOLEAN bWow64;

    EXCEPTION_RECORD ExceptionRecord;
    KTRAP_FRAME TrapFrame;
    BOOLEAN FirstChance;

    char szInst[0x50];

    PIO_WORKITEM WorkItem;    

} EXCPT_HOOK_INFO,
*PEXCPT_HOOK_INFO;

BOOLEAN ExcptHook(void);
BOOLEAN ExcptUnhook(void);


typedef VOID (NTAPI * func_KiDispatchException)(
    PEXCEPTION_RECORD ExceptionRecord,
    PKEXCEPTION_FRAME ExceptionFrame,
    PKTRAP_FRAME TrapFrame,
    KPROCESSOR_MODE PreviousMode,
    BOOLEAN FirstChance
);
