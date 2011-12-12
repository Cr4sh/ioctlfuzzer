
#ifndef _DBGCB_H_
#define _DBGCB_H_

/**
 * Magic constants for Kernel Debugger Communication Engine commands.
 */
#define DBGCB_GET_SYMBOL    'DBGS'
#define DBGCB_EXECUTE       'DBGE'
#define DBGCB_FIELD_OFFSET  'DBGF'


/**
 * Format strings for 32/64-bit pointers.
 */

#define IFMT32 "0x%.8x"
#define IFMT64 "0x%.16I64x"

#define IFMT32_W L"0x%.8x"
#define IFMT64_W L"0x%.16I64x"

#ifdef _X86_

#define IFMT IFMT32
#define IFMT_W IFMT32_W

#elif _AMD64_

#define IFMT IFMT64
#define IFMT_W IFMT64_W

#endif


/**
 * Kernel Debugger Communication Engine functions.
 */

/**
 * Execute debuuger command (IDebugControl::Execute()).
 */
BOOLEAN dbg_exec(PCHAR lpFormat, ...);

/**
 * Evaluate debuuger expression (IDebugControl::Evaluate()).
 */
PVOID dbg_eval(PCHAR lpFormat, ...);

/**
 * Get offset of the some structure field
 */
LONG dbg_field_offset(PCHAR lpFormat, ...);

#endif // _DBGCB_H_
