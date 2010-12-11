
driver.obj: src/driver.cpp
    $(CC) $(CFLAGS) src/driver.cpp

debug.obj: src/r0_common/debug.cpp
    $(CC) $(CFLAGS) src/r0_common/debug.cpp

common.obj: src/r0_common/common.cpp
    $(CC) $(CFLAGS) src/r0_common/common.cpp
    
lst.obj: src/r0_common/lst.cpp
    $(CC) $(CFLAGS) src/r0_common/lst.cpp

rng.obj: src/rng.cpp
    $(CC) $(CFLAGS) src/rng.cpp

handlers.obj: src/handlers.cpp
    $(CC) $(CFLAGS) src/handlers.cpp

hook.obj: src/hook.cpp
    $(CC) $(CFLAGS) src/hook.cpp
    
log.obj: src/log.cpp
    $(CC) $(CFLAGS) src/log.cpp    
    
rules.obj: src/rules.cpp
    $(CC) $(CFLAGS) src/rules.cpp    
    
excpthook.obj: src/excpthook.cpp
    $(CC) $(CFLAGS) src/excpthook.cpp

LLIBS = ntoskrnl.lib hal.lib

LOBJS = driver.obj debug.obj common.obj lst.obj rng.obj common_asm.obj handlers.obj hook.obj log.obj rules.obj excpthook.obj
