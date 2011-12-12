@echo off

:: check for OS architecture
call .\_config.bat

if not exist %SystemDrive%\ioctls.log goto _analyze

:: analyze IOCTLs log and print information
%IOCTLFUZZER% --analyze --loadlog %SystemDrive%\ioctls.log
goto _end

:_analyze

:: just print information
%IOCTLFUZZER% --analyze

:_end
