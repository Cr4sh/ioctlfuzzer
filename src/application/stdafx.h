#pragma once

#define _WIN32_WINNT 0x0500

#include <iostream>
#include <tchar.h>
#include <windows.h>
#include <ComDef.h>
#include <Shlwapi.h>

#define M_ALLOC(_size_) LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, (ULONG)(_size_))
#define M_FREE(_addr_) LocalFree((_addr_))

#include "../driver/drvcomm.h"
#include "debug.h"
#include "xml.h"

#pragma comment(lib, "shlwapi.lib")
