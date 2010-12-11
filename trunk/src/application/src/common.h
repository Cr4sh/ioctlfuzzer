#define RVATOVA(_base_, _offset_) ((ULONG)(_base_) + (ULONG)(_offset_))

#define XALIGN_DOWN(x, align)(x &~ (align - 1))
#define XALIGN_UP(x, align)((x & (align - 1))?XALIGN_DOWN(x, align) + align:x)

#define M_ALLOC(_size_) LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, (ULONG)(_size_))
#define M_FREE(_addr_) LocalFree((_addr_))

#define HIDWORD(_val_) ((DWORD)(((ULONGLONG)(_val_) >> 32) & 0xFFFFFFFF))
#define LODWORD(_val_) ((DWORD)(ULONGLONG)(_val_))

#define GET_NATIVE(_name_)                                      \
                                                                \
    func_##_name_ f_##_name_ = (func_##_name_)GetProcAddress(   \
        GetModuleHandleA("ntdll.dll"),                          \
        (#_name_)                                               \
    );


#define MAX_STRING_SIZE 255

BOOL LoadPrivileges(char *lpszName);
BOOL DumpToFile(char *lpszFileName, PVOID pData, ULONG DataSize);
BOOL ReadFromFile(LPCTSTR lpszFileName, PVOID *pData, PDWORD lpdwDataSize);
