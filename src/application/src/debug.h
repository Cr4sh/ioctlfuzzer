#ifdef DBG

void DbgMsg(char *lpszFile, int Line, char *lpszMsg, ...);
void DbgInit(char *lpszDebugPipeName, char *lpszLogFileName);

#else

#define DbgMsg
#define DbgInit

#endif
