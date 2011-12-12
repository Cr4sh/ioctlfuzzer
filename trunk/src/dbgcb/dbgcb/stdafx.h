#pragma once

#include "targetver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <DbgHelp.h>

// DbgHelp API headers
#define KDEXT_64BIT
#include <wdbgexts.h>
#include <dbgeng.h>

#pragma warning(disable:4201) // nonstandard extension used : nameless struct
#pragma warning(disable:4995)
#include <extsfns.h>

#include "../common/dbgcb_api.h"
