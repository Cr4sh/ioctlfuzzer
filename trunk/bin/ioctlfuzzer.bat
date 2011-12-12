@echo off

:: check for OS architecture
call .\_config.bat

%IOCTLFUZZER% --config ioctlfuzzer.xml
