#define SYSTEM_SERVICE(_p_) KeServiceDescriptorTable->Entry[0].ServiceTableBase[_p_]

#define RVATOVA(_base_, _offset_) ((ULONG)(_base_) + (ULONG)(_offset_))

#define CLEAR_WP()                      \
    __asm   cli                         \
    __asm   mov     eax,cr0             \
    __asm   and     eax,not 000010000h  \
    __asm   mov     cr0,eax

#define SET_WP()                        \
    __asm   mov     eax,cr0             \
    __asm   or      eax,000010000h      \
    __asm   mov     cr0,eax             \
    __asm   sti

#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos)      \
    (((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros)    \
    (((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli)     \
    (((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds)        \
    (((signed __int64)(seconds)) * MILLISECONDS(1000L))


typedef NTSTATUS (__stdcall * NT_DEVICE_IO_CONTROL_FILE)(
    IN HANDLE               FileHandle,
    IN HANDLE               Event OPTIONAL,
    IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
    IN PVOID                ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK    IoStatusBlock,
    IN ULONG                IoControlCode,
    IN PVOID                InputBuffer OPTIONAL,
    IN ULONG                InputBufferLength,
    OUT PVOID               OutputBuffer OPTIONAL,
    IN ULONG                OutputBufferLength
);
