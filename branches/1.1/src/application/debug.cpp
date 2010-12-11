/*

	(c) eSage lab
	http://www.esagelab.ru

*/
#include "stdafx.h"
//--------------------------------------------------------------------------------------
/** 
* пишет текст в отладочный вывод
* @param file имя файла
* @param line номер строки
* @param msg текст
* в качестве значений параметров file и line обычно передаются константы __FILE__ и __LINE__ соответственно 
*/
void DbgMsg(char *file, int line, char *msg, ...)
{
    char buff[1024], obuff[1024]="\0";
    va_list mylist;

    va_start(mylist, msg);
    wvsprintf(buff, msg, mylist);	
    va_end(mylist);

    wsprintf(obuff, "%s(%d) : %s", file, line, buff);	

#ifdef DBG
    OutputDebugString(obuff);
#endif

    HANDLE hStd = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStd != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten;
        WriteFile(hStd, buff, lstrlen(buff), &dwWritten, NULL);
    }
}
//--------------------------------------------------------------------------------------
// EoF
