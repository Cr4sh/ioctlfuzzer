@echo off

:: delete old files
cmd.exe /C clean.bat
del ..\bin\ioctlfuzzer.exe ..\bin\ioctlfuzzer.pdb

echo ------------------------------------------------------
echo  BUILDING DRIVER
echo ------------------------------------------------------

:: build driver
cd driver
cmd.exe /C build.bat
cd ..

if not exist driver_i386.sys exit

echo ------------------------------------------------------
echo  BUILDING APPLICATION
echo ------------------------------------------------------

:: build application
cd application
cmd.exe /C build.bat
cd ..

if not exist ..\bin\ioctlfuzzer.exe exit

echo ------------------------------------------------------
echo  DONE
echo ------------------------------------------------------
