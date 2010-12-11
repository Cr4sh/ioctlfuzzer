.386p


_TEXT$00   SEGMENT DWORD PUBLIC 'CODE'
        ASSUME  DS:FLAT, ES:FLAT, SS:NOTHING, FS:NOTHING, GS:NOTHING 


public __clear_wp@0
public __set_wp@0
public __ZwProtectVirtualMemory@20


extern _m_SDT_NtProtectVirtualMemory:dword


__clear_wp@0:

    push    eax                 
    mov     eax,cr0             
    and     eax,not 000010000h
    mov     cr0,eax
    pop     eax
    ret


__set_wp@0:

    push    eax
    mov     eax,cr0
    or      eax,000010000h
    mov     cr0,eax
    pop     eax
    ret


__ZwProtectVirtualMemory@20:
 
    mov     eax,_m_SDT_NtProtectVirtualMemory
    lea     edx,[esp+4]
    int     2Eh
    retn    14h


_TEXT$00   ends

end