@echo off

set SRCPATH=dbgcb_drv.sys
set DSTPATH=%SystemRoot%\system32\drivers\dbgcb_drv.sys

:: copy driver to the system directory
copy %SRCPATH% %DSTPATH% /Y

:: create service
sc create dbgcb_drv binPath= %DSTPATH% type= kernel start= demand

:: start service
sc start dbgcb_drv

:: stop service
sc stop dbgcb_drv

:: delete service
sc delete dbgcb_drv

:: delete file
del %DSTPATH%

pause
