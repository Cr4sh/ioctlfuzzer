# General information #

IOCTL Fuzzer is a tool designed to automate the task of searching vulnerabilities in Windows kernel drivers by performing fuzz tests on them.

The fuzzer’s own driver hooks [NtDeviceIoControlFile](http://msdn.microsoft.com/en-us/library/ms648411(VS.85).aspx) in order to take control of all IOCTL requests throughout the system.

While processing IOCTLs, the fuzzer will spoof those IOCTLs conforming to conditions specified in the configuration file. A spoofed IOCTL is identical to the original in all respects except the input data, which is changed to randomly generated fuzz.

IOCTL Fuzzer works on x86 and x64 Windows XP, 2003 Server, Vista, 2008 Server and 7.

Actual readme file: http://code.google.com/p/ioctlfuzzer/source/browse/trunk/README.TXT


# New features in 1.3 version #

  * GUI for fuzzing/monitoring settings management ([screenshot](http://dl.dropbox.com/u/22903093/blog/ioctlfuzzer-1.3/GUI.png)).

  * Attack surface analysis feature: print list of drivers, devices and their information (security settings, number of catched IOCTL requests, driver file product/vendor information, opened handles for devices): [screenshot](http://dl.dropbox.com/u/22903093/blog/ioctlfuzzer-1.3/attack-surface-analysis.png), complete log file example: http://code.google.com/p/ioctlfuzzer/source/browse/trunk/attack-surface-analysis_NT6.1_x86.log

  * Integration with Kernel Debugger Communicatioin Engine (https://github.com/Cr4sh/DbgCb). Now IOCTL Fuzzer can execute any commands in remote kernel debugger for IOCTL requests parameters, which were specified in the XML configuration file.

  * Some fuzzing improvements.


# New features in 1.2 version #

  * Windows 7 support
  * Full support of 64-bit versions of Windows
  * Exceptions monitoring
  * "Fair Fuzzing" feature
  * Different data generation modes
  * Boot fuzzing (during OS initialization)

Download binaries and sources:
http://ioctlfuzzer.googlecode.com/files/ioctl_fuzzer-1.2.zip

![http://dl.dropbox.com/u/22903093/blog/ioctlfuzzer-2010/ioctlfuzzer64.png](http://dl.dropbox.com/u/22903093/blog/ioctlfuzzer-2010/ioctlfuzzer64.png)
