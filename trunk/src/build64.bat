@echo off

:: delete old files
cmd.exe /C clean.bat
del ..\bin\x64\ioctlfuzzer64.exe ..\bin\x64\ioctlfuzzer64.pdb

echo ------------------------------------------------------
echo  BUILDING DRIVER
echo ------------------------------------------------------

:: build driver
cd driver
cmd.exe /C build64.bat
cd ..

if not exist driver_amd64.sys exit

echo ------------------------------------------------------
echo  BUILDING APPLICATION
echo ------------------------------------------------------

:: build application
cd application
cmd.exe /C build64.bat
cd ..

if not exist ..\bin\x64\ioctlfuzzer64.exe exit

echo ------------------------------------------------------
echo  DONE
echo ------------------------------------------------------
