
// ********************************************************
// some user-mode structures

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;

} LDR_DATA_TABLE_ENTRY, 
*PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA 
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY ModuleListLoadOrder;
    LIST_ENTRY ModuleListMemoryOrder;
    LIST_ENTRY ModuleListInitOrder;

} PEB_LDR_DATA, 
*PPEB_LDR_DATA;

// ********************************************************

typedef struct SERVICE_DESCRIPTOR_ENTRY
{
    PULONG	ServiceTableBase;
    PULONG	ServiceCounterTableBase;
    ULONG	NumberOfServices;
    PUCHAR	ParamTableBase;

} SERVICE_DESCRIPTOR_ENTRY,
*PSERVICE_DESCRIPTOR_ENTRY;

typedef struct _SERVICE_DESCRIPTOR_TABLE 
{
    SERVICE_DESCRIPTOR_ENTRY Entry[4];

} SERVICE_DESCRIPTOR_TABLE,
*PSERVICE_DESCRIPTOR_TABLE;

typedef enum _SYSTEM_INFORMATION_CLASS 
{
    SystemBasicInformation,
    SystemProcessorInformation,             // obsolete...delete
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
    
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION 
{
    HANDLE Section;                 // Not filled in
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[ 256 ];
    
} RTL_PROCESS_MODULE_INFORMATION, 
*PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES 
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];
    
} RTL_PROCESS_MODULES, 
*PRTL_PROCESS_MODULES;

typedef enum
{
    StateInitialized,
    StateReady,
    StateRunning,
    StateStandby,
    StateTerminated,
    StateWait,
    StateTransition,
    StateUnknown

} THREAD_STATE;

typedef struct _SYSTEM_THREAD 
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
    ULONG ContextSwitchCount;
    THREAD_STATE State;
    KWAIT_REASON WaitReason;

} SYSTEM_THREAD, 
*PSYSTEM_THREAD;

typedef struct _SYSTEM_PROCESSES_INFORMATION
{
    ULONG NextEntryDelta;
    ULONG ThreadCount;
    ULONG Reserved1[6];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ProcessName; 
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    ULONG InheritedFromProcessId;
    ULONG HandleCount;
    ULONG Reserved2[2];
    VM_COUNTERS VmCounters;
    IO_COUNTERS IoCounters;
    SYSTEM_THREAD Threads[1];

} SYSTEM_PROCESSES_INFORMATION, 
*PSYSTEM_PROCESSES_INFORMATION;

NTSYSAPI 
NTSTATUS 
NTAPI 
ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI
ZwAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PULONG AllocationSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSYSAPI
NTSTATUS
NTAPI
ZwFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PULONG FreeSize,
    ULONG FreeType
);


NTSYSAPI 
NTSTATUS 
NTAPI 
ZwOpenThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

typedef struct _KAPC_STATE 
{
    LIST_ENTRY ApcListHead[2];
    PVOID Process;
    BOOLEAN KernelApcInProgress;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;

} KAPC_STATE, 
*PKAPC_STATE;

NTSYSAPI
VOID
NTAPI 
KeStackAttachProcess(
    PEPROCESS Process,
    PKAPC_STATE ApcState
);

NTSYSAPI
VOID
NTAPI
KeUnstackDetachProcess(
    PKAPC_STATE ApcState
);

NTKERNELAPI 
NTSTATUS 
PsLookupProcessByProcessId(
    HANDLE ProcessId,
    PEPROCESS *Process
);

NTKERNELAPI 
NTSTATUS 
PsLookupThreadByThreadId(
    HANDLE ThreadId,
    PETHREAD *Thread
);

NTKERNELAPI 
NTSTATUS 
PsGetContextThread(
    PETHREAD Thread,
    PCONTEXT ThreadContext,
    KPROCESSOR_MODE Mode
);

NTKERNELAPI 
NTSTATUS 
PsSetContextThread(
    PETHREAD Thread,
    PCONTEXT ThreadContext,
    KPROCESSOR_MODE Mode
);

NTSYSAPI
NTSTATUS
NTAPI
ObOpenObjectByPointer(
    PVOID Object,
    ULONG HandleAttributes,
    PACCESS_STATE PassedAccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PHANDLE Handle
);

NTSYSAPI
NTSTATUS
NTAPI
ObOpenObjectByName(
    POBJECT_ATTRIBUTES ObjectAttributes,
    POBJECT_TYPE ObjectType, 
    KPROCESSOR_MODE AccessMode,
    PACCESS_STATE AccessState, 
    ACCESS_MASK DesiredAccess,
    PVOID ParseContext, 
    PHANDLE Handle
);

NTKERNELAPI 
NTSTATUS 
ObQueryNameString(
    PVOID Object,
    POBJECT_NAME_INFORMATION ObjectNameInfo,
    ULONG Length,
    PULONG ReturnLength
);

NTKERNELAPI
VOID
KeSetSystemAffinityThread(
    KAFFINITY Affinity
);
