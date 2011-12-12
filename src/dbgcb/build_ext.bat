@echo off

:: Path to the SDK from Microsoft Debugging Tools for Windows
set DBGSDK_PATH=D:\dbg\sdk

set DBGSDK_INC_PATH=$(DBGSDK_PATH)\inc
set DBGSDK_LIB_PATH=$(DBGSDK_PATH)\lib
set DBGLIB_LIB_PATH=$(DBGSDK_PATH)\lib

build
