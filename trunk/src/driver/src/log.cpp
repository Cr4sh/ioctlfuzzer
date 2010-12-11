#include "stdafx.h"

// defined in handlers.cpp
extern ULONG m_FuzzOptions;

// defined in debug.cpp
extern HANDLE hDbgPipe;
extern KMUTEX DbgMutex;
//--------------------------------------------------------------------------------------
void LogData(char *lpszFormat, ...)
{
    IO_STATUS_BLOCK IoStatusBlock;
    char szBuff[0x200];
    va_list mylist;

    va_start(mylist, lpszFormat);
    vsprintf(szBuff, lpszFormat, mylist);	
    va_end(mylist);

    if (m_FuzzOptions & FUZZ_OPT_DEBUGLOG)
    {
        // post message into debug output
        DbgPrint(szBuff);
    }

    if (m_FuzzOptions & FUZZ_OPT_LOG)
    {
#ifdef DBGPIPE

        if (KeGetCurrentIrql() == PASSIVE_LEVEL)
        {
            KeWaitForMutexObject(&DbgMutex, Executive, KernelMode, FALSE, NULL);

            if (hDbgPipe)
            {
                // write debug message into pipe
                IO_STATUS_BLOCK IoStatusBlock;
                ULONG Len = (ULONG)strlen(szBuff) + 1;

                ZwWriteFile(hDbgPipe, 0, NULL, NULL, &IoStatusBlock, (PVOID)&Len, sizeof(Len), NULL, NULL);
                ZwWriteFile(hDbgPipe, 0, NULL, NULL, &IoStatusBlock, szBuff, Len, NULL, NULL);
            }            

            KeReleaseMutex(&DbgMutex, FALSE);
        }    

#endif // DBGPIPE
    }
}
//--------------------------------------------------------------------------------------
void Hexdump(PUCHAR Data, ULONG Size) 
{
    unsigned int dp = 0, p = 0;
    const char trans[] =
        "................................ !\"#$%&'()*+,-./0123456789"
        ":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
        "nopqrstuvwxyz{|}~...................................."
        "....................................................."
        "........................................";

    char szBuff[0x100], szChr[10];
    RtlZeroMemory(szBuff, sizeof(szBuff));

    for (dp = 1; dp <= Size; dp++)  
    {
        sprintf(szChr, "%02x ", Data[dp-1]);
        strcat(szBuff, szChr);

        if ((dp % 8) == 0)
        {
            strcat(szBuff, " ");
        }

        if ((dp % 16) == 0) 
        {
            strcat(szBuff, "| ");
            p = dp;

            for (dp -= 16; dp < p; dp++)
            {
                sprintf(szChr, "%c", trans[Data[dp]]);
                strcat(szBuff, szChr);
            }

            LogData("%s\r\n", szBuff);
            RtlZeroMemory(szBuff, sizeof(szBuff));
        }
    }

    if ((Size % 16) != 0) 
    {
        p = dp = 16 - (Size % 16);

        for (dp = p; dp > 0; dp--) 
        {
            strcat(szBuff, "   ");

            if (((dp % 8) == 0) && (p != 8))
            {
                strcat(szBuff, " ");
            }
        }

        strcat(szBuff, " | ");
        for (dp = (Size - (16 - p)); dp < Size; dp++)
        {
            sprintf(szChr, "%c", trans[Data[dp]]);
            strcat(szBuff, szChr);
        }

        LogData("%s\r\n", szBuff);
    }

    LogData("\r\n");
}
//--------------------------------------------------------------------------------------
// EoF
