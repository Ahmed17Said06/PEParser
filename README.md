PE (Portable Executable) is the core executable file format in Windows OS. In this assignment, you are asked to write a static parser to extract the basic information of a legitimate PE file, as follows:

Write a C/C++ or using any system-level lang a PE parser
Your input program is a path/or file name of a legitimate .exe file (i.e., notepad.exe or cmd.exe)
Your program can use something like (winnt.h) data structure to parse the PE headers and section.
Your program should extract information such as:
PE compile time, PE characteristics, Address of entry point, sections info, section locations, parse .rsrc section and extract the content, and any other essential information.  
What to submit:

The full source code of your program
Compiled binaries of your program
Screenshots of your program working successfully from the command line.
Reference:

https://docs.microsoft.com/en-us/windows/win32/debug/pe-format


C:\Windows\System32\calc.exe

C:\Windows\System32\notepad.exe


DLLs and SYS device drivers are both subsets of executables in Windows. They all use the PE file structure. Two places to look to determine if regular executable, DLL, or SYS:
	1) To determine if DLL: struct IMAGE_NT_HEADERS -> struct IMAGE_FILE_HEADERS ->  WORD Characteristics
		0x0002 means EXE. DLLs and SYS device drivers are both subsets of executables, so they will both contain 0x0002 in Characteristics.
		If the executable is a DLL, Characteristics will be added by 0x2000. Sum of all the file's Characteristics becomes final Characteristics word value.
		Can "and" with any individual Characteristic value to determine if file has that Characteristic added.
	2) To determine if SYS: struct IMAGE_NT_HEADERS -> struct IMAGE_OPTIONAL_HEADER -> WORD Subsystem
		0001 means IMAGE_SUBSYSTEM_NATIVE, indicative of SYS file

1- https://www.unknowncheats.me/forum/general-programming-and-reversing/326543-winapi-pe-file-read-access-violation-trying-headers-dos-header.html

2- https://reverseengineering.stackexchange.com/questions/17110/run-pe-file-executable-from-memory

3- https://www.google.com/search?q=IMAGE_NT_HEADERS+unable+to+read+memory&rlz=1C1CHBD_arEG976EG976&biw=1270&bih=581&sxsrf=APq-WBuWEpvL-xqumvIEiEsjCp0kirSxbQ%3A1649375874557&ei=gnpPYonMIaGCi-gP-bi62A0&ved=0ahUKEwiJler4k4P3AhUhwQIHHXmcDtsQ4dUDCA4&uact=5&oq=IMAGE_NT_HEADERS+unable+to+read+memory&gs_lcp=Cgdnd3Mtd2l6EAM6BwgjELADECc6BwgAEEcQsAM6BAgjECc6BAgAEB46BggAEAUQHjoFCCEQoAE6CAghEBYQHRAeOgcIIRAKEKABOgQIIRAVSgQIQRgASgQIRhgAULkGWKnUAWC53AFoB3ABeACAAbQBiAHBH5IBBDAuMjeYAQCgAQHIAQrAAQE&sclient=gws-wiz

4- https://stackoverflow.com/questions/34109184/how-to-get-use-user-input-to-specify-outside-file-location-in-c-will-this-work

5- https://stackoverflow.com/questions/42638242/get-path-from-input-to-read-a-file


![SC1](https://user-images.githubusercontent.com/97065109/230692576-94b125c1-b233-45cb-8ad6-f8d7eb25fb32.png)
![SC2](https://user-images.githubusercontent.com/97065109/230692577-8465092c-9c5d-4980-8fe1-ec20b88456de.png)
![SC3](https://user-images.githubusercontent.com/97065109/230692578-409b4314-f199-4a8b-948b-7ff1b889e653.png)
![SC4](https://user-images.githubusercontent.com/97065109/230692579-2aed71b9-3c47-448e-843c-8c6c4ebb6f76.png)
