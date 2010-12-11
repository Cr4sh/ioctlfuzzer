IXMLDOMNode * WINAPI ConfGetListNodeByName(BSTR NodeName, IXMLDOMNodeList *pIDOMNodeList);
IXMLDOMNode * WINAPI ConfGetNodeByName(BSTR NodeName, IXMLDOMNode *pIDOMNode);
BOOL WINAPI ConfGetNodeTextW(IXMLDOMNode *pIDOMNode, PWSTR *str);
BOOL WINAPI ConfGetNodeTextA(IXMLDOMNode *pIDOMNode, PCHAR *str);
BOOL WINAPI ConfAllocGetTextByNameW(IXMLDOMNode *pIDOMNode, PWSTR name, PWSTR *value);
BOOL WINAPI ConfAllocGetTextByNameA(IXMLDOMNode *pIDOMNode, PWSTR name, PCHAR *value);
