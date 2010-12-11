#define DEVICE_NAME L"IOCTLfuzzer"
#define DBG_PIPE_NAME L"IOCTLfuzzer"
#define DBG_PIPE_NAME_A "IOCTLfuzzer"

#define IOCTL_DRV_CONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x01, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define S_ERROR             0x00
#define S_SUCCESS           0x01

#define C_ADD_DEVICE        0x01
#define C_ADD_DRIVER        0x02
#define C_ADD_IOCTL         0x03
#define C_ADD_PROCESS       0x04
#define C_SET_LOG_PIPE      0x05
#define C_SET_OPTIONS       0x06
#define C_SET_LOG_FILE      0x07

// fuzzing options
#define FUZZ_OPT_HEXDUMP    0x00000001
#define FUZZ_OPT_LOG        0x00000002
#define FUZZ_OPT_DEBUGLOG   0x00000004
#define FUZZ_OPT_FUZZ       0x00000008
#define FUZZ_OPT_FUZZSIZE   0x00000010
#define FUZZ_OPT_FAIRFUZZ   0x00000020
#define FUZZ_OPT_BOOTFUZZ   0x00000040
#define FUZZ_OPT_LOG_IOCTLS 0x00000080

typedef ULONG FUZZING_TYPE;

#define FuzzingType_Random  0x00000001
#define FuzzingType_Dword   0x00000002

// area to store some variables, that must located in user mode
#pragma pack(push, 1)
typedef struct _USER_MODE_DATA
{
    IO_STATUS_BLOCK IoStatus;

} USER_MODE_DATA,
*PUSER_MODE_DATA;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _REQUEST_BUFFER
{
    // operation status (see S_* definitions)
    ULONG Status;
    
    // operation code (see C_* definitions)
    ULONG Code;

    struct
    {
        ULONG Options;
        ULONG FuzzThreadId;
        FUZZING_TYPE FuzzingType;
        PUSER_MODE_DATA UserModeData;
        ULONG KiDispatchException_Offset;

    } Options;

    // for C_ADD_IOCTL
    ULONG IoctlCode;

    // for C_SET_LOG_PIPE
    HANDLE hPipe;

    // for all C_ADD_*
    BOOLEAN bAllow;

    // for C_ADD_DEVICE,  C_ADD_DRIVER and C_ADD_PROCESS
    char Buff[];

} REQUEST_BUFFER,
*PREQUEST_BUFFER;
#pragma pack(pop)
