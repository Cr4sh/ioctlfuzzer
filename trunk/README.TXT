
  IOCTL Fuzzer ver. 1.2
  http://code.google.com/p/ioctlfuzzer/
  
  (c) 2009-2010 eSage lab
  http://www.esagelab.com/
  support@esagelab.com
 
 
============================================
  Overview
============================================

 IOCTL Fuzzer is a tool designed to automate the task of searching vulnerabilities in Windows kernel drivers by performing fuzz tests on them.

Current OS support (x32 and x64): Windows XP, Vista, 2003 Server, 2008 Server, 7.

 The fuzzer’s own driver hooks nt!NtDeviceIoControlFile() in order to take control of all IOCTL requests throughout the system. 

 While processing IOCTLs, the fuzzer will spoof those IOCTLs conforming to conditions specified in the configuration file. A spoofed IOCTL is identical to the original IRP in all respects except the input data, which is changed to randomly generated fuzz.

 Besides the fuzzing functionality, monitoring mode is also available with the tool. The monitoring mode allows logging of IRPs, optionally including their HEX dumps, into a file and/or a console. 
 
 Also, in 1.2 version is available exceptions monitoring feature, that can be usefull while fuzzing not only a kernel drivers. Exception monitoring is working through unexported function nt!KiDispatchException() pathing, which address obtained from Windows kernel debug symbols (they are automatically downloading from Microsoft's PDB server, during fuzzer initialization).

 Specific IOCTLs which are to be logged or fuzzed by the tool are defined in the XML configuration file. IOCTLs may be filtered by the following parameters:

 * Path to executable file corresponding to a process from which an IOCTL request is sent.
 * IOCTL destination device name.
 * IOCTL destination driver name.
 * IOCTL Control Code.


============================================
  Command line options
============================================

--config <path> - Specify path to the fuzzer XML configuration file. For more information about configuration file format see example in bin/ioctlfuzzer.xml. If '--config' option is not specified - application will start in IOCTLs monitoring mode.

--boot - Boot time fuzzing/monitoring. This option will run fuzzer with the next system reboot.

--exceptions - Enable exceptions monitoring. Notice: files dbgeng.dll, dbghelp.dll and symsrv.dll are required for exceptions monitoring and must be placed into the same directory, as IOCTL Fuzzer executable.

--noioctls - Disable IOCTLs monitoring, show exceptions only (this option valid if '--exceptions' has been specified).

--uninstall - Uninstall IOCTL Fuzzer kernel driver and exit.


EXAMPLE:

 > ioctlfuzzer.exe --config ioctlfuzzer.xml --exceptions


============================================
  Using the fuzzer
============================================

General algorithm for fuzz-testing an application is as follows.

1. Install target application onto a virtual machine.

2. Attach a remote debugger to the virtual machine. Notice: how to configure WinDbg remote connection to VMware: http://silverstr.ufies.org/lotr0/windbg-vmware.html.

3. Run IOCTL Fuzzer in fuzzing mode on the guest OS.

4. Play around with target application unless an unhandled exception is displayed in the remotely attached debugger. Notice: normally, i.e. with no debugger attached, an unhandled exception will provoke a BSOD.  

5. Release code execution on the virtual machine (F5 in WinDbg) to allow guest OS generate a crash dump.

6. Analyze the crash dump. IOCTL which provoked the unhandled exception should be found at this step. 

7. If necessary, manual analysis of the application binary code may be performed.

 
============================================
  Building the sources
============================================

1. Download and install Windows Driver Kit Version 7.1.0
http://www.microsoft.com/downloads/en/details.aspx?displaylang=en&FamilyID=36a2630f-5d56-43b5-b996-7633f2ec14ff   
 
2. Run Windows Server 2003 x86 (or x64, to build 64-bit version) Free Build Environment (Start -> «Windows Driver Kits» -> «WDK 7600.16385.1» -> 
«Build Environments» -> «Windows Server 2003» -> «x86 Free Build Environment»).

3. Go to the directory ./src/ and execute .\build.bat (or .\build64.bat, to build 64-bit version) from the Build Environment.

