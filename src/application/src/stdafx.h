#define _WIN32_WINNT  0x0500

#include <stdio.h>
#include <tchar.h>
#include <conio.h>
#include <windows.h>
#include <Shlwapi.h>
#include "../../dbgsdk/inc/dbghelp.h"

#include "ntdll_defs.h"
#include "undocnt.h"
#include "..\..\driver\src\drvcomm.h"
#include "common.h"
#include "debug.h"
#include "service.h"
#include "xml.h"
