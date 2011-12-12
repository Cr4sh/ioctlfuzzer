
/**
* Structures and defines for IOCTL filtering
*/
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

    BOOLEAN bDbgcbAction;
    char szKdCommand[1];

} IOCTL_FILTER,
*PIOCTL_FILTER;

typedef struct _IOCTL_FILTER_SERIALIZED
{
    ULONG Type;
    ULONG IoctlCode;
    ULONG NameLen;
    WCHAR Name[];

} IOCTL_FILTER_SERIALIZED,
*PIOCTL_FILTER_SERIALIZED;

PIOCTL_FILTER FltAdd(PIOCTL_FILTER f, PIOCTL_FILTER *f_head, PIOCTL_FILTER *f_end, ULONG KdCommandLength);
void FltFlushList(PIOCTL_FILTER *f_head, PIOCTL_FILTER *f_end);

BOOLEAN FltIsMatchedRequest(
    PUNICODE_STRING fDeviceName, 
    PUNICODE_STRING fDriverName,
    ULONG IoControlCode,
    PUNICODE_STRING fProcessName
);

char *FltGetKdCommand(
    PUNICODE_STRING fDeviceName, 
    PUNICODE_STRING fDriverName,
    ULONG IoControlCode,
    PUNICODE_STRING fProcessName
);

BOOLEAN SaveRules(PIOCTL_FILTER *f_head, PIOCTL_FILTER *f_end, HANDLE hKey, PUNICODE_STRING usValueName);
BOOLEAN LoadRules(PIOCTL_FILTER *f_head, PIOCTL_FILTER *f_end, HANDLE hKey, PUNICODE_STRING usValueName);

/**
* Macro defines for allow/deny lists of IOCTL filtering
*/
#define FltAllowAdd(_entry_, _len_) FltAdd((_entry_), &f_allow_head, &f_allow_end, (_len_))
#define FltAllowFlushList() FltFlushList(&f_allow_head, &f_allow_end)
#define FltAllowMatch(_drv_, _dev_, _c_, _p_) FltMatch(&f_allow_head, (_drv_), (_dev_), (_c_), (_p_))

#define FltDenyAdd(_entry_, _len_) FltAdd((_entry_), &f_deny_head, &f_deny_end, (_len_))
#define FltDenyFlushList() FltFlushList(&f_deny_head, &f_deny_end)
#define FltDenyMatch(_drv_, _dev_, _c_, _p_) FltMatch(&f_deny_head, (_drv_), (_dev_), (_c_), (_p_))

#define FltDbgcbAdd(_entry_, _len_) FltAdd((_entry_), &f_dbgcb_head, &f_dbgcb_end, (_len_))
#define FltDbgcbFlushList() FltFlushList(&f_dbgcb_head, &f_dbgcb_end)
