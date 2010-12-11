#include "stdafx.h"

// defined in driver.cpp
extern UNICODE_STRING m_RegistryPath;
extern KMUTEX m_CommonMutex;

PIOCTL_FILTER f_allow_head = NULL, f_allow_end = NULL;
PIOCTL_FILTER f_deny_head = NULL, f_deny_end = NULL;
//--------------------------------------------------------------------------------------
wchar_t xchrlower_w(wchar_t chr)
{
    if ((chr >= 'A') && (chr <= 'Z')) 
    {
        return chr + ('a'-'A');
    }

    return chr;
}
//--------------------------------------------------------------------------------------
BOOLEAN EqualUnicodeString_r(PUNICODE_STRING Str1, PUNICODE_STRING Str2, BOOLEAN CaseInSensitive)
{
    USHORT CmpLen = min(Str1->Length, Str2->Length) / sizeof(WCHAR);

    for (USHORT i = 1; i < CmpLen; i++)
    {
        WCHAR Chr1 = Str1->Buffer[Str1->Length / sizeof(WCHAR) - i], 
            Chr2 = Str2->Buffer[Str2->Length / sizeof(WCHAR) - i];

        if (CaseInSensitive)
        {
            Chr1 = xchrlower_w(Chr1);
            Chr2 = xchrlower_w(Chr2);
        }

        if (Chr1 != Chr2)
        {
            return FALSE;
        }
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
BOOLEAN FltAdd(PIOCTL_FILTER f, PIOCTL_FILTER *f_head, PIOCTL_FILTER *f_end)
{
    BOOLEAN bRet = FALSE;

    KeWaitForMutexObject(&m_CommonMutex, Executive, KernelMode, FALSE, NULL); 

    __try
    {
        PIOCTL_FILTER f_entry = (PIOCTL_FILTER)ExAllocatePool(NonPagedPool, sizeof(IOCTL_FILTER));
        if (f_entry)
        {
            RtlCopyMemory(f_entry, f, sizeof(IOCTL_FILTER));

            if (*f_end)
            {
                (*f_end)->next = f_entry;
                f_entry->prev = *f_end;
                (*f_end) = f_entry;
            } 
            else 
            {
                *f_end = *f_head = f_entry;    
            }

            bRet = TRUE;        
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "ExAllocatePool() fails\n");
        }
    }    
    __finally
    {
        KeReleaseMutex(&m_CommonMutex, FALSE);
    }    

    return bRet;
}
//--------------------------------------------------------------------------------------
void FltFlushList(PIOCTL_FILTER *f_head, PIOCTL_FILTER *f_end)
{
    PIOCTL_FILTER f_entry = *f_head;
    while (f_entry)
    {
        PIOCTL_FILTER f_tmp = f_entry->next;

        if (f_entry->Type == FLT_DEVICE_NAME ||
            f_entry->Type == FLT_DRIVER_NAME)
        {
            RtlFreeUnicodeString(&f_entry->usName);
        }

        ExFreePool(f_entry);

        f_entry = f_tmp;
    }

    *f_head = *f_end = NULL;
}
//--------------------------------------------------------------------------------------
PIOCTL_FILTER FltMatch(
    PIOCTL_FILTER   *f_head,
    PUNICODE_STRING fDeviceName, 
    PUNICODE_STRING fDriverName,
    ULONG           IoControlCode,
    PUNICODE_STRING fProcessName)
{
    PIOCTL_FILTER ret = NULL;

    // match parameters by filter list
    PIOCTL_FILTER f_entry = *f_head;

    while (f_entry)
    {
        if (f_entry->Type == FLT_DEVICE_NAME)
        {
            if (EqualUnicodeString_r(&f_entry->usName, fDeviceName, TRUE))
            {
                ret = f_entry;
                break;
            }
        }
        else if (f_entry->Type == FLT_DRIVER_NAME)
        {
            if (EqualUnicodeString_r(&f_entry->usName, fDriverName, TRUE))
            {
                ret = f_entry;
                break;
            }
        }
        else if (f_entry->Type == FLT_IOCTL_CODE)
        {
            if (f_entry->IoctlCode == IoControlCode)
            {
                ret = f_entry;
                break;
            }
        }
        else if (f_entry->Type == FLT_PROCESS_PATH)
        {
            if (EqualUnicodeString_r(&f_entry->usName, fProcessName, TRUE))
            {
                ret = f_entry;
                break;
            }
        }

        f_entry = f_entry->next;
    }

    return ret;
}
//--------------------------------------------------------------------------------------
BOOLEAN FltIsMatchedRequest(
    PUNICODE_STRING fDeviceName, 
    PUNICODE_STRING fDriverName,
    ULONG IoControlCode,
    PUNICODE_STRING fProcessName)
{
    // match process by allow/deny list
    if ((f_allow_head == NULL || 
        FltAllowMatch(fDeviceName, fDriverName, IoControlCode, fProcessName)) &&
        FltDenyMatch(fDeviceName, fDriverName, IoControlCode, fProcessName) == NULL)
    {
        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOLEAN SaveRules(PIOCTL_FILTER *f_head, PIOCTL_FILTER *f_end, HANDLE hKey, PUNICODE_STRING usValueName)
{
    BOOLEAN bRet = FALSE;
    ULONG BuffSize = 0, RulesToSerialize = 0;

    // calculate reqired buffer size
    PIOCTL_FILTER f = *f_head;
    while (f)
    {
        BuffSize += sizeof(IOCTL_FILTER_SERIALIZED);

        if (f->Type == FLT_DEVICE_NAME ||
            f->Type == FLT_DRIVER_NAME ||
            f->Type == FLT_PROCESS_PATH)
        {
            // we an have object name
            BuffSize += f->usName.Length;
        }

        RulesToSerialize++;
        
        f = f->next;
    }

    if (BuffSize > 0)
    {
        // allocate memory for serialized rules
        PUCHAR Buff = (PUCHAR)M_ALLOC(BuffSize);
        if (Buff)
        {
            RtlZeroMemory(Buff, BuffSize);            
            PIOCTL_FILTER_SERIALIZED f_s = (PIOCTL_FILTER_SERIALIZED)Buff;

            // serialize available entries
            f = *f_head;
            while (f)
            {
                ULONG NextEntryOffset = sizeof(IOCTL_FILTER_SERIALIZED);

                f_s->Type = f->Type;
                f_s->IoctlCode = f->IoctlCode;

                if (f->Type == FLT_DEVICE_NAME ||
                    f->Type == FLT_DRIVER_NAME ||
                    f->Type == FLT_PROCESS_PATH)
                {
                    // we have an object name
                    f_s->NameLen = f->usName.Length;
                    NextEntryOffset += f_s->NameLen;
                    memcpy(&f_s->Name, f->usName.Buffer, f_s->NameLen);
                }

                // go to the next serialized entry
                f_s = (PIOCTL_FILTER_SERIALIZED)((PUCHAR)f_s + NextEntryOffset);              
                f = f->next;                    
            }
            
            NTSTATUS ns = ZwSetValueKey(hKey, usValueName, NULL, REG_BINARY, Buff, BuffSize);
            if (NT_SUCCESS(ns))
            {
                bRet = TRUE;

                DbgMsg(
                    __FILE__, __LINE__, 
                    __FUNCTION__"(): %d rules (%d bytes) saved in '%wZ'\n", 
                    RulesToSerialize, BuffSize, usValueName
                );
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "ZwSetValueKey() fails; status: 0x%.8x\n", ns);
            }                                    
            
            M_FREE(Buff);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "M_ALLOC() fails\n");
        }
    }        

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOLEAN LoadRules(PIOCTL_FILTER *f_head, PIOCTL_FILTER *f_end, HANDLE hKey, PUNICODE_STRING usValueName)
{
    BOOLEAN bRet = FALSE;             
    PKEY_VALUE_FULL_INFORMATION KeyInfo = NULL;
    ULONG Length = 0, RulesLoaded = 0; 

    // query buffer size
    NTSTATUS ns = ZwQueryValueKey(
        hKey, 
        usValueName,  
        KeyValueFullInformation, 
        KeyInfo, 
        0, 
        &Length
    );
    if (ns == STATUS_BUFFER_OVERFLOW || 
        ns == STATUS_BUFFER_TOO_SMALL)
    {            
        // allocate buffer
        PKEY_VALUE_FULL_INFORMATION KeyInfo = (PKEY_VALUE_FULL_INFORMATION)M_ALLOC(Length);
        if (KeyInfo)
        {
            // query value
            ns = ZwQueryValueKey(
                hKey, 
                usValueName,  
                KeyValueFullInformation, 
                KeyInfo, 
                Length, 
                &Length
            );
            if (NT_SUCCESS(ns))
            {
                if (KeyInfo->DataLength > 0)
                {
                    // deserialize rules
                    PUCHAR Buff = (PUCHAR)KeyInfo + KeyInfo->DataOffset;
                    PIOCTL_FILTER_SERIALIZED f_s = (PIOCTL_FILTER_SERIALIZED)Buff;

                    while ((ULONG)((PUCHAR)f_s - Buff) < KeyInfo->DataLength)
                    {
                        // add rule into list
                        IOCTL_FILTER Flt;
                        RtlZeroMemory(&Flt, sizeof(Flt));

                        Flt.Type = f_s->Type;
                        Flt.IoctlCode = f_s->IoctlCode;

                        if ((f_s->Type == FLT_DEVICE_NAME ||
                             f_s->Type == FLT_DRIVER_NAME ||
                             f_s->Type == FLT_PROCESS_PATH) &&
                             f_s->NameLen > 0)
                        {
                            // we have an object name
                            if (AllocUnicodeString(&Flt.usName, f_s->NameLen))
                            {
                                Flt.usName.Length = f_s->NameLen;
                                memcpy(Flt.usName.Buffer, &f_s->Name, f_s->NameLen);
                                DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): '%wZ'\n", &Flt.usName);
                            }
                            else
                            {
                                goto err;
                            }
                        }

                        if (!FltAdd(&Flt, f_head, f_end))
                        {
                            if (Flt.usName.Buffer)
                            {
                                RtlFreeUnicodeString(&Flt.usName);
                            }                            
                        }
                        else
                        {
                            RulesLoaded++;
                        }
err:
                        // go to the next serialized entry
                        f_s = (PIOCTL_FILTER_SERIALIZED)((PUCHAR)f_s + 
                            sizeof(IOCTL_FILTER_SERIALIZED) + f_s->NameLen);
                    }                        
                }

                DbgMsg(
                    __FILE__, __LINE__, 
                    __FUNCTION__"(): %d rules loaded from '%wZ'\n", 
                    RulesLoaded, usValueName
                );

                bRet = TRUE;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "ZwQueryValueKey() fails; status: 0x%.8x\n", ns);
            }

            M_FREE(KeyInfo);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "M_ALLOC() fails\n");
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() WARNING: '%wZ' value is not set\n", usValueName);
    }      

    return bRet;
}
//--------------------------------------------------------------------------------------
