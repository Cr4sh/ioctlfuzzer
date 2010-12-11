IXMLDOMNode * __stdcall ConfGetListNodeByName(BSTR NodeName, IXMLDOMNodeList *pIDOMNodeList);
IXMLDOMNode * __stdcall ConfGetNodeByName(BSTR NodeName, IXMLDOMNode *pIDOMNode);
BOOL __stdcall ConfGetNodeTextW(IXMLDOMNode *pIDOMNode, PWSTR *str);
BOOL __stdcall ConfGetNodeTextA(IXMLDOMNode *pIDOMNode, PCHAR *str);
BOOL __stdcall ConfAllocGetTextByNameW(IXMLDOMNode *pIDOMNode, PWSTR name, PWSTR *value);
BOOL __stdcall ConfAllocGetTextByNameA(IXMLDOMNode *pIDOMNode, PWSTR name, PCHAR *value);