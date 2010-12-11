ioctlfuzzer.obj: src/ioctlfuzzer.cpp
    $(CC) $(CFLAGS) src/ioctlfuzzer.cpp

debug.obj: src/debug.cpp
    $(CC) $(CFLAGS) src/debug.cpp

common.obj: src/common.cpp
    $(CC) $(CFLAGS) src/common.cpp

service.obj: src/service.cpp
    $(CC) $(CFLAGS) src/service.cpp

xml.obj: src/xml.cpp
    $(CC) $(CFLAGS) src/xml.cpp
	 
LLIBS = kernel32.lib user32.lib advapi32.lib shlwapi.lib version.lib

LOBJS = ioctlfuzzer.obj debug.obj common.obj service.obj xml.obj
