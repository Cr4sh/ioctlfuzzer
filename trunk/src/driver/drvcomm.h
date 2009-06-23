#define DEVICE_NAME L"IOCTL_fuzzer"

#define IOCTL_DRV_CONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x01, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define S_ERROR                 0
#define S_SUCCESS               1

#define C_ADD_DEVICE            1
#define C_ADD_DRIVER            2
#define C_ADD_IOCTL             3
#define C_ADD_PROCESS           4
#define C_SET_LOG_PIPE          5
#define C_SET_OPTIONS           6
#define C_SET_LOG_FILE          7

typedef struct _REQUEST_BUFFER
{
    // operation status (see S_* definitions)
    ULONG       Status;
    
    // operation code (see C_* definitions)
    ULONG       Code;

    struct
    {
        BOOLEAN bHexDump;
        BOOLEAN bLogRequests;
        BOOLEAN bDebugLogRequests;
        BOOLEAN bFuzeRequests;
        BOOLEAN bFuzeSize;

    } Options;

    // for C_ADD_IOCTL
    ULONG       IoctlCode;

    // for C_SET_LOG_PIPE
    HANDLE      hPipe;

    // for all C_ADD_*
    BOOLEAN     bAllow;

    // for C_ADD_DEVICE,  C_ADD_DRIVER and C_ADD_PROCESS
    char        Buff[];

} REQUEST_BUFFER,
*PREQUEST_BUFFER;

