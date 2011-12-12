extern "C"
{
#include <ntifs.h>
#include <stdio.h>
#include <stdarg.h>
#include <ntimage.h>
#include "r0_common/undocnt.h"
}

#define WP_STUFF
#define USE_CHECK_PREV_MODE

#include "r0_common/debug.h"
#include "r0_common/common.h"
#include "r0_common/lst.h"

#include "../../options.h"

#include "asm/common_asm.h"
#include "drvcomm.h"
#include "rng.h"
#include "driver.h"
#include "handlers.h"
#include "hook.h"
#include "log.h"
#include "rules.h"
#include "excpthook.h"

// udis86 disasm engine
#include "../../udis86/extern.h"

// kernel debugger communication engine (dbgcb) client
#include "../../dbgcb/common/dbgcb_api.h"

#ifdef _X86_
#pragma comment(lib,"../udis86/udis86_i386.lib")
#elif _AMD64_
#pragma comment(lib,"../udis86/udis86_amd64.lib")
#endif
