#include "stdafx.h"

EXT_API_VERSION g_ExtApiVersion = { 1, 1, EXT_API_VERSION_NUMBER, 0 };

WINDBG_EXTENSION_APIS ExtensionApis = { 0 };

IDebugClient *g_Client = NULL;
PDEBUG_CONTROL g_Control = NULL;
IDebugSymbols3 *g_Symbols = NULL;
IDebugSystemObjects *g_SystemObjects = NULL;
IDebugRegisters *g_Registers = NULL;
IDebugDataSpaces *g_DataSpaces = NULL;

ULONG g_EipIndex = DEBUG_ANY_ID;
ULONG g_EaxIndex = DEBUG_ANY_ID, g_EcxIndex = DEBUG_ANY_ID, g_EdxIndex = DEBUG_ANY_ID;

LONG g_RefCount = 0;

BOOL g_bIs64 = FALSE;
ULONG g_RegPtrType = 0;

#define SIGN_EXTEND(_x_) (ULONG64)(LONG)(_x_)
//--------------------------------------------------------------------------------------

/**
 * Wrappers for working with registry values as 32/64-bit pointers.
 */

ULONG64 RegPtrGet(PDEBUG_VALUE Register)
{
    if (g_bIs64)
    {
        return Register->I64;
    }

    return SIGN_EXTEND(Register->I32);
}

VOID RegPtrSet(PDEBUG_VALUE Register, ULONG64 Value)
{
    if (g_bIs64)
    {
        Register->Type = DEBUG_VALUE_INT64;
        Register->I64 = Value;
    }
    else
    {
        Register->Type = DEBUG_VALUE_INT32;
        Register->I32 = (ULONG)Value;
    }
}
//--------------------------------------------------------------------------------------
void __cdecl ExtOut(PCSTR Format, ...)
{
    va_list Args;
    va_start(Args, Format);
    
    g_Control->ControlledOutputVaList(
        DEBUG_OUTCTL_AMBIENT_DML, 
        DEBUG_OUTPUT_NORMAL, 
        Format, Args
    );

    va_end(Args);
}

void ExtCleanup(void)
{
    /**
     * clean up any resources
     */

    ExtOut(__FUNCTION__"()\n");

    if (g_DataSpaces)
    {
        g_DataSpaces->Release();
    }

    if (g_Registers)
    {
        g_Registers->Release();
    }

    if (g_Control)
    {
        g_Control->Release();
    }

    if (g_Symbols)
    {
        g_Symbols->Release();
    }

    if (g_SystemObjects)
    {
        g_SystemObjects->Release();
    }
    
    if (g_Client)
    {
        g_Client->Release();
    } 
}

void __cdecl ExtErr(PCSTR Format, ...)
{
    va_list Args;
    va_start(Args, Format);
    
    g_Control->ControlledOutputVaList(
        DEBUG_OUTCTL_AMBIENT_DML, 
        DEBUG_OUTPUT_ERROR, 
        Format, Args
    );
    
    va_end(Args);
}

void ExtExec(PCSTR Command)
{
    g_Control->Execute(
        DEBUG_OUTCTL_ALL_CLIENTS | DEBUG_OUTCTL_AMBIENT_DML, 
        Command, DEBUG_EXECUTE_DEFAULT
    );
}
//----------------------------------------------------------------------------
class EventCallbacks : public DebugBaseEventCallbacks
{
public:

    // IUnknown.
    STDMETHOD_(ULONG, AddRef)(
        THIS
    );

    STDMETHOD_(ULONG, Release)(
        THIS
    );

    // IDebugEventCallbacks.
    STDMETHOD(GetInterestMask)(
        THIS_
        OUT PULONG Mask
    );
    
    STDMETHOD(Exception)(
        THIS_
        IN PEXCEPTION_RECORD64 Exception,
        IN ULONG FirstChance
    );   

    STDMETHOD(ChangeEngineState)(
        THIS_
        IN ULONG Flags,
        IN ULONG64 Argument
    );
};

BOOL g_ResumeState = FALSE;

STDMETHODIMP_(ULONG)
EventCallbacks::AddRef(THIS)
{
    ExtOut(__FUNCTION__"()\n");

    InterlockedIncrement(&g_RefCount);

    return 1;
}

STDMETHODIMP_(ULONG)
EventCallbacks::Release(THIS)
{
    ExtOut(__FUNCTION__"()\n");

    return 0;
}

STDMETHODIMP
EventCallbacks::GetInterestMask(
    THIS_
    OUT PULONG Mask)
{
    *Mask = DEBUG_EVENT_EXCEPTION | DEBUG_EVENT_CHANGE_ENGINE_STATE;
    return S_OK;
}

STDMETHODIMP
EventCallbacks::ChangeEngineState(
    THIS_
    IN ULONG Flags,
    IN ULONG64 Argument)
{
    if (Flags == DEBUG_CES_EXECUTION_STATUS && 
        Argument == DEBUG_STATUS_BREAK)
    {
        if (g_ResumeState)
        {
            // Resume execution due to handled int 3 exception.
            ExtExec("g");
        }        

        g_ResumeState = FALSE;
    }

    return S_OK;
}

STDMETHODIMP
EventCallbacks::Exception(
    THIS_
    IN PEXCEPTION_RECORD64 Exception,
    IN ULONG FirstChance)
{    
    g_ResumeState = FALSE;

    if (Exception->ExceptionCode == STATUS_BREAKPOINT)
    {
        if (FirstChance)
        {
            DEBUG_VALUE Reg, Ecx, Edx;            

            // Query EIP, EAX and ECX value.
            if (g_Registers->GetValue(g_EipIndex, &Reg) == S_OK &&
                g_Registers->GetValue(g_EdxIndex, &Edx) == S_OK &&
                g_Registers->GetValue(g_EcxIndex, &Ecx) == S_OK)
            {
                char szParam[MAX_PATH];
                ULONG ReadedBytes = 0;

                // Read current instruction opcode value.
                ZeroMemory(szParam, sizeof(szParam));
                HRESULT Hr = g_DataSpaces->ReadVirtual(RegPtrGet(&Reg), &szParam, 1, &ReadedBytes);                
                if (Hr != S_OK)
                {
                    ExtErr(__FUNCTION__"() ERROR: IDebugDataSpaces::ReadVirtual() fails: %lx\n", Hr);
                    return DEBUG_STATUS_NO_CHANGE;
                }

                // Check for int 3 at EIP.
                if (szParam[0] != '\xCC')
                {
                    return DEBUG_STATUS_NO_CHANGE;
                }

                // Check for the magic engine constnat in EDX.
                if (Edx.I32 != DBGCB_GET_SYMBOL &&
                    Edx.I32 != DBGCB_EXECUTE &&
                    Edx.I32 != DBGCB_FIELD_OFFSET)
                {
                    return DEBUG_STATUS_NO_CHANGE;
                }
                
                g_ResumeState = TRUE;                

                // Read ASCII string with command arguments.
                ZeroMemory(szParam, sizeof(szParam));
                Hr = g_DataSpaces->ReadVirtual(RegPtrGet(&Ecx), &szParam, sizeof(szParam), &ReadedBytes);
                if (Hr != S_OK)
                {
                    ExtErr(__FUNCTION__"() ERROR: IDebugDataSpaces::ReadVirtual() fails: %lx\n", Hr);
                    return DEBUG_STATUS_NO_CHANGE;
                }

                switch (Edx.I32)
                {
                case DBGCB_GET_SYMBOL:
                    {
                        ExtOut("<col fg=\"srccmnt\">" __FUNCTION__"(): DBGCB_GET_SYMBOL \"%s\"</col>\n", szParam);

                        RegPtrSet(&Reg, 0);
                        g_Registers->SetValue(g_EaxIndex, &Reg);

                        Hr = g_Control->Evaluate(szParam, g_RegPtrType, &Reg, NULL);
                        if (Hr == S_OK)
                        {
                            // Return symbol address in EAX.
                            g_Registers->SetValue(g_EaxIndex, &Reg);
                        }
                        else
                        {
                            ExtErr(__FUNCTION__"() WARNING: IDebugControl::Evaluate() fails: %lx\n", Hr);
                        }

                        break;
                    }                                 

                case DBGCB_EXECUTE:
                    {
                        ExtOut("<col fg=\"srccmnt\">" __FUNCTION__ "(): DBGCB_EXECUTE</col>\n");

                        // execute debugger command
                        Hr = g_Control->Execute(
                            DEBUG_OUTCTL_ALL_CLIENTS | DEBUG_OUTCTL_AMBIENT_DML, 
                            szParam, 
                            DEBUG_EXECUTE_DEFAULT
                        );
                        if (Hr == S_OK)
                        {
                            // Return TRUE in EAX
                            RegPtrSet(&Reg, 1);
                            g_Registers->SetValue(g_EaxIndex, &Reg);
                        }
                        else
                        {
                            ExtErr(__FUNCTION__"() WARNING: IDebugControl::Execute() fails: %lx\n", Hr);
                        }

                        break;
                    }                    

                case DBGCB_FIELD_OFFSET:
                    {
                        RegPtrSet(&Reg, (ULONG64)-1);

                        char *lpszModule = szParam, *lpszStruct = NULL, *lpszField = NULL;

                        ExtOut("<col fg=\"srccmnt\">" __FUNCTION__"(): DBGCB_FIELD_OFFSET \"%s\"</col>\n", szParam);

                        // parse structure and field description string
                        if (lpszStruct = strstr(lpszModule, "!"))
                        {
                            *lpszStruct = '\x00';
                            lpszStruct += 1;

                            if (lpszField = strstr(lpszStruct, "::"))
                            {
                                *lpszField = '\x00';
                                lpszField += 2;
                            }
                        }                        

                        if (lpszStruct && lpszField)
                        {
                            // enumerate fields
                            for (ULONG i = 0; ;i++) 
                            {   
                                ULONG64 Module = 0;
                                ULONG TypeId = 0;    

                                // get ID of this symbol
                                Hr = g_Symbols->GetSymbolTypeId(lpszStruct, &TypeId, &Module);
                                if (Hr == S_OK) 
                                {
                                    char szFieldName[MAX_PATH];

                                    // query name of the filed
                                    HRESULT Hr = g_Symbols->GetFieldName(Module, TypeId, i, szFieldName, MAX_PATH, NULL);
                                    if (Hr == S_OK) 
                                    {
                                        ULONG Offset = 0, FieldTypeId = 0;

                                        // query filed type and offset
                                        Hr = g_Symbols->GetFieldTypeAndOffset(Module, TypeId, szFieldName, &FieldTypeId, &Offset);                                   
                                        if (Hr == S_OK)
                                        {
                                            if (!strcmp(szFieldName, lpszField))
                                            {
                                                // Return symbol offset in EAX
                                                RegPtrSet(&Reg, (ULONG64)Offset);                                                
                                                break;
                                            }
                                        }            
                                        else 
                                        {
                                            ExtErr(__FUNCTION__"() WARNING: IDebugSymbols3::GetFieldTypeAndOffset() fails: %lx\n", Hr);
                                        }
                                    } 
                                    else if (Hr == E_INVALIDARG) 
                                    {
                                        // All Fields done
                                        break;
                                    } 
                                    else 
                                    {
                                        ExtErr(__FUNCTION__"() WARNING: IDebugSymbols3::GetFieldName() fails: %lx\n", Hr);
                                    }
                                }
                                else
                                {
                                    ExtErr(__FUNCTION__"() WARNING: IDebugSymbols3::GetSymbolTypeId() fails: %lx\n", Hr);
                                }                                
                            }
                        }
                        else
                        {
                            ExtErr(__FUNCTION__"() WARNING: Bad name format (must be <module>!<struct_name>::<field_name>)\n");
                        }

                        g_Registers->SetValue(g_EaxIndex, &Reg);

                        break;
                    }                    

                default:

                    return DEBUG_STATUS_NO_CHANGE;
                }

                // Skip current int 3 instruction and continue execution
                if (g_Registers->GetValue(g_EipIndex, &Reg) == S_OK && Reg.Type == DEBUG_VALUE_INT32)
                {
                    if (g_bIs64)
                    {
                        Reg.I64 += 1;
                    }
                    else
                    {
                        Reg.I32 += 1;
                    }

                    g_Registers->SetValue(g_EipIndex, &Reg);                    
                }                 

                return DEBUG_STATUS_GO_HANDLED;
            }                      
        }
    }    

    return DEBUG_STATUS_NO_CHANGE;
}

EventCallbacks g_EventCb;
//--------------------------------------------------------------------------------------
VOID WDBGAPI WinDbgExtensionDllInit(
    PWINDBG_EXTENSION_APIS lpExtensionApis, 
    USHORT usMajorVersion, USHORT usMinorVersion)
{
    if (g_RefCount > 0)
    {
        // extension is allready initialized
        return;
    }

    HRESULT Hr = DebugCreate(__uuidof(IDebugClient), (void **)&g_Client);
    if (Hr != S_OK)
    {
        MessageBoxA(0, "DebugCreate() fails", __FUNCTION__, MB_ICONERROR);
        return;
    }

    Hr = g_Client->QueryInterface(__uuidof(IDebugControl), (void **)&g_Control);
    if (Hr != S_OK)
    {    
        MessageBoxA(
            0, 
            "DebugClient::QueryInterface(IDebugControl) fails", 
            __FUNCTION__, MB_ICONERROR
        );

        ExitProcess(0);
    }

    ULONG TargetMachine = 0;
    Hr = g_Control->GetActualProcessorType(&TargetMachine);
    if (Hr == S_OK)
    {                                                     
        switch (TargetMachine)
        {
        case IMAGE_FILE_MACHINE_I386:
            
            g_bIs64 = FALSE;
            g_RegPtrType = DEBUG_VALUE_INT32;
            break;


        case IMAGE_FILE_MACHINE_AMD64:

            g_bIs64 = TRUE;
            g_RegPtrType = DEBUG_VALUE_INT64;
            break;

        default:

            MessageBoxA(
                0, 
                "Target architecture is not supported", 
                __FUNCTION__, MB_ICONERROR
            );

            ExitProcess(0);

            break;
        }
    }
    else
    {
        MessageBoxA(
            0, 
            "DebugControl::GetActualProcessorType() fails", 
            __FUNCTION__, MB_ICONERROR
        );

        ExitProcess(0);
    }

    Hr = g_Client->QueryInterface(__uuidof(IDebugSymbols3), (void **)&g_Symbols);
    if (Hr != S_OK)
    {    
        MessageBoxA(
            0, 
            "DebugClient::QueryInterface(IDebugSymbols3) fails", 
            __FUNCTION__, MB_ICONERROR
        );

        ExitProcess(0);
    }

    Hr = g_Client->QueryInterface(__uuidof(IDebugSystemObjects), (void **)&g_SystemObjects);
    if (Hr != S_OK)
    {    
        MessageBoxA(
            0, 
            "DebugClient::QueryInterface(IDebugSystemObjects) fails", 
            __FUNCTION__, MB_ICONERROR
        );

        ExitProcess(0);
    }

    Hr = g_Client->QueryInterface(__uuidof(IDebugRegisters), (void **)&g_Registers);
    if (Hr != S_OK)
    {    
        MessageBoxA(
            0, 
            "DebugClient::QueryInterface(IDebugRegisters) fails", 
            __FUNCTION__, MB_ICONERROR
        );

        ExitProcess(0);
    }

    Hr = g_Client->QueryInterface(__uuidof(IDebugDataSpaces), (void **)&g_DataSpaces);
    if (Hr != S_OK)
    {    
        MessageBoxA(
            0, 
            "DebugClient::QueryInterface(IDebugDataSpaces) fails", 
            __FUNCTION__, MB_ICONERROR
        );

        ExitProcess(0);
    }

    char *lpszEip = "eip", *lpszEax = "eax", *lpszEcx = "ecx";
    if (g_bIs64)
    {
        // use 64-bit registers for parameter and return value
        lpszEip = "rip";
        lpszEax = "rax";
        lpszEcx = "rcx";
    }

    // Find the register index for eip/rip
    Hr = g_Registers->GetIndexByName(lpszEip, &g_EipIndex);
    if (Hr != S_OK)
    {
        MessageBoxA(
            0, 
            "DebugRegisters::GetIndexByName() fails", 
            __FUNCTION__, MB_ICONERROR
        );

        ExitProcess(0);
    }    

    // Find the register index for eax/rax
    Hr = g_Registers->GetIndexByName(lpszEax, &g_EaxIndex);
    if (Hr != S_OK)
    {
        MessageBoxA(
            0, 
            "DebugRegisters::GetIndexByName() fails", 
            __FUNCTION__, MB_ICONERROR
        );

        ExitProcess(0);
    }    

    // Find the register index for ecx/rcx
    Hr = g_Registers->GetIndexByName(lpszEcx, &g_EcxIndex);
    if (Hr != S_OK)
    {
        MessageBoxA(
            0, 
            "DebugRegisters::GetIndexByName() fails", 
            __FUNCTION__, MB_ICONERROR
        );

        ExitProcess(0);
    }

    // Find the register index for edx
    Hr = g_Registers->GetIndexByName("edx", &g_EdxIndex);
    if (Hr != S_OK)
    {
        MessageBoxA(
            0, 
            "DebugRegisters::GetIndexByName() fails", 
            __FUNCTION__, MB_ICONERROR
        );

        ExitProcess(0);
    }

    // Register our event callbacks.
    Hr = g_Client->SetEventCallbacks(&g_EventCb);
    if (Hr != S_OK)
    {
        MessageBoxA(
            0, 
            "DebugClient::SetEventCallbacks() fails", 
            __FUNCTION__, MB_ICONERROR
        );

        ExitProcess(0);
    }

    ExtOut("<col fg=\"srckw\">" __FUNCTION__"(): Initialized (x64: %s)</col>\n", g_bIs64 ? "Yes" : "No");
}
//--------------------------------------------------------------------------------------
LPEXT_API_VERSION WDBGAPI ExtensionApiVersion(void)
{
    return &g_ExtApiVersion;
}
//--------------------------------------------------------------------------------------
BOOL APIENTRY DllMain(
    HANDLE hModule,
    DWORD  dwReason,
    DWORD  dwReserved)
{
    switch (dwReason) 
    {
        case DLL_THREAD_ATTACH:            
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_ATTACH:

            break;

        case DLL_PROCESS_DETACH:            

            ExtCleanup();
            break;
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
// EoF
