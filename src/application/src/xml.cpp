#include "stdafx.h"
//--------------------------------------------------------------------------------------
IXMLDOMNode * WINAPI ConfGetListNodeByName(BSTR NodeName, IXMLDOMNodeList *pIDOMNodeList)
{    
    IXMLDOMNode *Ret = NULL;
    LONG len = 0;
    
    if (pIDOMNodeList == NULL)
    {
        return NULL;
    }

    if (IsBadStringPtrW(NodeName, MAX_STRING_SIZE) ||
        IsBadReadPtr(pIDOMNodeList, sizeof(PVOID)))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__ "() ERROR: invalid parameter\n");
        return NULL;
    } 

    HRESULT hr = pIDOMNodeList->get_length(&len);
    if (SUCCEEDED(hr))
    {
        pIDOMNodeList->reset();
        for (int i = 0; i < len; i++)
        {
            IXMLDOMNode *pIDOMChildNode = NULL;
            hr = pIDOMNodeList->get_item(i, &pIDOMChildNode);
            if (SUCCEEDED(hr))
            {
                BSTR ChildNodeName = NULL;
                hr = pIDOMChildNode->get_nodeName(&ChildNodeName);
                if (SUCCEEDED(hr))
                {
                    if (!wcscmp(NodeName, ChildNodeName))
                    {
                        Ret = pIDOMChildNode;
                    }
                }                

                if (ChildNodeName)
                {
                    typedef void (WINAPI * func_SysFreeString)(BSTR bstrString);

                    func_SysFreeString f_SysFreeString = (func_SysFreeString)
                        GetProcAddress(
                        LoadLibrary("oleaut32.dll"),
                        "SysFreeString"
                    );
                    if (f_SysFreeString)
                    {
                        f_SysFreeString(ChildNodeName);
                    }
                    else
                    {
#ifdef DBG
                        DbgMsg(__FILE__, __LINE__, "GetProcAddress() ERROR %d\n", GetLastError());
#endif
                    }
                }

                if (Ret)
                {
                    return Ret;
                }

                pIDOMChildNode->Release();
                pIDOMChildNode = NULL;                
            } 
            else 
            {
#ifdef DBG
                DbgMsg(__FILE__, __LINE__, "pIDOMNodeList->get_item() ERROR 0x%.8x\n", hr);
#endif
            }
        }
    } 
    else 
    {
#ifdef DBG
        DbgMsg(__FILE__, __LINE__, "pIDOMNodeList->get_length() ERROR 0x%.8x\n", hr);
#endif
    }

    return NULL;
}
//--------------------------------------------------------------------------------------
IXMLDOMNode * WINAPI ConfGetNodeByName(BSTR NodeName, IXMLDOMNode *pIDOMNode)
{
    IXMLDOMNode *pIDOMRetNode = NULL;
    IXMLDOMNodeList *pIDOMNodeList = NULL;

    if (pIDOMNode == NULL)
    {
        return NULL;
    }

    if (IsBadStringPtrW(NodeName, MAX_STRING_SIZE) ||
        IsBadReadPtr(pIDOMNode, sizeof(PVOID)))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__ "() ERROR: invalid parameter\n");
        return NULL;
    }

    HRESULT hr = pIDOMNode->get_childNodes(&pIDOMNodeList);
    if (SUCCEEDED(hr) && pIDOMNodeList)
    {
        pIDOMRetNode = ConfGetListNodeByName(NodeName, pIDOMNodeList);
        pIDOMNodeList->Release();        
    } 
    else 
    {
#ifdef DBG
        DbgMsg(__FILE__, __LINE__, "pIDOMNodeList->get_length() ERROR 0x%.8x\n", hr);
#endif
    }

    return pIDOMRetNode;
} 
//--------------------------------------------------------------------------------------
BOOL WINAPI ConfGetNodeTextW(IXMLDOMNode *pIDOMNode, PWSTR *str)
{
    BOOL bRet = FALSE;
    BSTR val = NULL;

    if (pIDOMNode == NULL)
    {
        return FALSE;
    }

    if (IsBadReadPtr(pIDOMNode, sizeof(PVOID)) ||
        IsBadWritePtr(str, sizeof(PWSTR)))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__ "() ERROR: invalid parameter\n");
        return FALSE;
    }

    HRESULT hr = pIDOMNode->get_text(&val);
    if (FAILED(hr))
    {
#ifdef DBG
        DbgMsg(__FILE__, __LINE__, "pIDOMNode->get_text() ERROR 0x%.8x\n", hr);
#endif
        return FALSE;
    }

    DWORD Len = (wcslen((PWSTR)val) + 1) * sizeof(WCHAR);
    if (*str = (PWSTR)M_ALLOC(Len))
    {
        memset(*str, 0, Len);
        wcscpy(*str, (PWSTR)val);
        bRet = TRUE;
    }
    else
    {
#ifdef DBG
        DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
#endif
    }

    if (val)
    {
        typedef void (WINAPI * func_SysFreeString)(BSTR bstrString);

        func_SysFreeString f_SysFreeString = (func_SysFreeString)
            GetProcAddress(
            LoadLibrary("oleaut32.dll"),
            "SysFreeString"
        );
        if (f_SysFreeString)
        {
            f_SysFreeString(val);
        }
        else
        {
#ifdef DBG
            DbgMsg(__FILE__, __LINE__, "GetProcAddress() ERROR %d\n", GetLastError());
#endif
        }
    }            

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL WINAPI ConfGetNodeTextA(IXMLDOMNode *pIDOMNode, PCHAR *str)
{
    BOOL bRet = FALSE;
    PWSTR str_w = NULL;

    if (pIDOMNode == NULL)
    {
        return FALSE;
    }

    if (IsBadReadPtr(pIDOMNode, sizeof(PVOID)) ||
        IsBadWritePtr(str, sizeof(PCHAR)))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__ "() ERROR: invalid parameter\n");
        return FALSE;
    }

    if (ConfGetNodeTextW(pIDOMNode, &str_w))
    {
        int len = wcslen(str_w);
        if (*str = (PCHAR)M_ALLOC(len + 1))
        {
            memset(*str, 0, len + 1);
            WideCharToMultiByte(CP_ACP, 0, str_w, -1, *str, len, NULL, NULL);    
            bRet = TRUE;
        }
        else
        {
#ifdef DBG
            DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
#endif
        }

        M_FREE(str_w);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL WINAPI ConfAllocGetTextByNameW(IXMLDOMNode *pIDOMNode, PWSTR name, PWSTR *value)
{
    BOOL bRet = FALSE;

    if (IsBadStringPtrW(name, MAX_STRING_SIZE) ||
        IsBadReadPtr(pIDOMNode, sizeof(PVOID)) ||
        IsBadWritePtr(value, sizeof(PWSTR)))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__ "() ERROR: invalid parameter\n");
        return FALSE;
    }
    
    IXMLDOMNode *pIDOMChildNode = ConfGetNodeByName(name, pIDOMNode);
    if (pIDOMChildNode)
    {
        bRet = ConfGetNodeTextW(pIDOMChildNode, value);        
    
        pIDOMChildNode->Release();
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL WINAPI ConfAllocGetTextByNameA(IXMLDOMNode *pIDOMNode, PWSTR name, PCHAR *value)
{
    BOOL bRet = FALSE;
    PWSTR value_w = NULL;

    if (IsBadStringPtrW(name, MAX_STRING_SIZE) ||
        IsBadReadPtr(pIDOMNode, sizeof(PVOID)) ||
        IsBadWritePtr(value, sizeof(PCHAR)))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__ "() ERROR: invalid parameter\n");
        return FALSE;
    }

    if (ConfAllocGetTextByNameW(pIDOMNode, name, &value_w))
    {
        int len = wcslen(value_w);
        if (*value = (PCHAR)M_ALLOC(len + 1))
        {
            memset(*value, 0, len + 1);
            WideCharToMultiByte(CP_ACP, 0, value_w, -1, *value, len, NULL, NULL);    
            bRet = TRUE;
        }
        else
        {
#ifdef DBG
            DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
#endif
        }

        M_FREE(value_w);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
// EoF
