@echo off

if (%PROCESSOR_ARCHITECTURE%) == (AMD64) (goto _x64) else (goto _x86)
 
:_x86
echo Windows x86 detected
set IOCTLFUZZER=.\ioctlfuzzer.exe
goto _end
 
:_x64
echo Windows x64 detected
set IOCTLFUZZER=.\x64\ioctlfuzzer64.exe
goto _end

:_end
