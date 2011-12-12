

  DBGCB Engine
    
  by Oleksiuk Dmytro (aka Cr4sh), Esage Lab

  http://d-olex.blogspot.com/
  mailto:dmitry@esagelab.com

================================= 

Engine for communication with remote kernel debugger (WinDBG, KD) from drivers or user mode application.
 
./dbgcb.dll - WinDbg extension, that must be loaded in remote kernel debugger
./common/ - dbgcb client code (can be used in your own applications)
./_Examples/dbgcb_drv.sys - Sample driver
./_Examples/dbgcb_app.exe - Sample user mode application

Engine working scheme: ./dbgcb_scheme.png
Engine with test driver (dbgcb_drv.sys): ./dbgcb_in_work.png


  Currently supported functions (see ./common/dbgcb_api.h):
  
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


