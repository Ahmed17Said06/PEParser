/*
Name: Ahmed Said AbdelSattar
NU ID: 211000541
32-bit PE parser
CIT 661 MalwareAnalysis
*/


#include "stdio.h"
#include "string.h"
#include "Windows.h"
#include <time.h>
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"

#ifdef _WIN32

void enableColors()
{
	DWORD consoleMode;
	HANDLE outputHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	if (GetConsoleMode(outputHandle, &consoleMode))
	{
		SetConsoleMode(outputHandle, consoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
	}
}

#endif

void checkValidExecutable(const char* executableNameUTF8) {
	FILE* pFile = fopen(executableNameUTF8, "rb");
	if (pFile == NULL) { fputs("File error", stderr); exit(1); }

	// Allocate a buffer to contain first 4 KB of executable size
	char* executableBuffer = malloc(2);
	if (executableBuffer == NULL) { fputs("Memory error", stderr); exit(2); }

	// Copy the first 2b of the executable into the buffer
	size_t result = fread(executableBuffer, 1, 2, pFile);
	if (result != 2) { fputs("Reading error", stderr); exit(3); }

	// If the first two bytes are not "MZ", or file does not end in .exe, .dll, .sys, then not valid executable
	const char* extension = strrchr(executableNameUTF8, '.');
	if (memcmp(executableBuffer, "MZ", 2) || (strcmp(extension, ".exe") && strcmp(extension, ".dll") && strcmp(extension, ".sys"))) {
		printf("[---] %s is not a valid executable.", executableNameUTF8);
		getchar();
		exit(-1);
	}

	// Close the file, free the buffer
	fclose(pFile);
	free(executableBuffer);
}

int wmain() {
	
	while (1) {

		enableColors();

		printf("Please enter a valid path to a 32-bit PE file: ");


		char filepath1[100] = { 0 };

		scanf("%s", filepath1);

		LPCWSTR executableName = filepath1;

		// Convert WCHAR to char
		const char* executableNameUTF8[MAX_PATH];

		strcpy(executableNameUTF8, filepath1);

		wcstombs(executableNameUTF8, filepath1, MAX_PATH);

		// Exits if first two bytes of file not "MZ", or file does not end in .exe, .dll, or .sys

		checkValidExecutable(executableNameUTF8);
		HANDLE hExecutable = CreateFileA(executableName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hExecutable == INVALID_HANDLE_VALUE) {
			printf("Could not find %s\n", executableName);
			getchar();
			exit(-1);
		};

		HANDLE hExecutableMapping = CreateFileMapping(hExecutable, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hExecutableMapping == 0) {
			CloseHandle(hExecutable);
			printf("Could not map %s \n", executableName);
			getchar();
			exit(-1);
		}

		LPVOID pMappedBase = MapViewOfFile(hExecutableMapping, FILE_MAP_READ, 0, 0, 0);
		if (pMappedBase == 0) {
			CloseHandle(hExecutableMapping);
			CloseHandle(hExecutable);
			printf("Could not map view of %s\n", executableName);
			getchar();
			exit(-1);
		}

		printf("\nThe Entered Path is: %s\n", executableName);


		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pMappedBase;
		PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);

		/*
		 DLLs and SYS device drivers are both subsets of executables in Windows. They all use the PE file structure. Two places to look to determine if regular executable, DLL, or SYS:
		*/
		if (ntHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
			// struct IMAGE_NT_HEADERS -> struct IMAGE_FILE_HEADERS ->  WORD Characteristics
			// If can AND with 0x2000, this executable is a DLL
			if (ntHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) {
				printf(ANSI_COLOR_GREEN "Executable type			: Dynamic-link library (.dll)\n" ANSI_COLOR_RESET);
				// struct IMAGE_NT_HEADERS -> struct IMAGE_OPTIONAL_HEADER -> WORD Subsystem
				// If can AND with 1, this executable is a SYS device driver
			}
			else if (ntHeader->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_NATIVE) {
				printf(ANSI_COLOR_GREEN "Executable type			: SYS device driver\n" ANSI_COLOR_RESET);
				// Else, it is just an executable
			}
			else {
				printf(ANSI_COLOR_GREEN "Executable type			: Regular executable (.exe)\n" ANSI_COLOR_RESET);
			}
			// This is not a proper executable file
		}
		else {
			wprintf("[---] %s is not a valid executable.", executableName);
			getchar();
			return FALSE;
		}
		printf("Size in memory of binary	: %#x\n", ntHeader->OptionalHeader.SizeOfImage);

		printf("\n-----------------------------------------------------------------------------------------------\n");

		printf("PE DOS Header Info: \n\n");

		printf("e_magic:	%x \n", dosHeader->e_magic);
		printf("e_cblp:		%x \n", dosHeader->e_cblp);
		printf("e_cp:		%x \n", dosHeader->e_cp);
		printf("e_crlc:		%x \n", dosHeader->e_crlc);
		printf("e_cparhdr:	%x \n", dosHeader->e_cparhdr);
		printf("e_minalloc:	%x \n", dosHeader->e_minalloc);
		printf("e_maxalloc:	%x \n", dosHeader->e_maxalloc);
		printf("e_ss:		%x \n", dosHeader->e_ss);
		printf("e_sp:		%x \n", dosHeader->e_sp);
		printf("e_csum:		%x \n", dosHeader->e_csum);
		printf("e_ip:		%x \n", dosHeader->e_ip);
		printf("e_cs:		%x \n", dosHeader->e_cs);
		printf("e_lfarlc:	%x \n", dosHeader->e_lfarlc);
		printf("e_ovno:		%x \n", dosHeader->e_ovno);
		printf("e_res:		%x, %x, %x, %x \n", dosHeader->e_res[0], dosHeader->e_res[1], dosHeader->e_res[2], dosHeader->e_res[3]);
		printf("e_oemid:	%x \n", dosHeader->e_oemid);
		printf("e_oeminfo:	%x \n", dosHeader->e_oeminfo);
		printf("e_res2:		%x, %x, %x, %x, %x, %x, %x, %x, %x, %x \n", dosHeader->e_res2[0], dosHeader->e_res2[1], dosHeader->e_res2[2], dosHeader->e_res2[3], dosHeader->e_res2[4], dosHeader->e_res2[5], dosHeader->e_res2[6], dosHeader->e_res2[7], dosHeader->e_res2[8], dosHeader->e_res2[9]);
		printf("e_lfanew:	%x \n", dosHeader->e_lfanew);

		printf("-----------------------------------------------------------------------------------------------\n");
		printf("-----------------------------------------------------------------------------------------------\n");
		printf("-----------------------------------------------------------------------------------------------\n");


		printf("PE NT Headers Info: \n\n");

		printf("Signature:			%x \n\n\n", ntHeader->Signature);


		printf("File Header-------> \n\n");

		printf("Machine:			%x \n", ntHeader->FileHeader.Machine);
		printf("NumberOfSections:		%x \n", ntHeader->FileHeader.NumberOfSections);
		printf(ANSI_COLOR_CYAN "TimeDateStamp:			%x		%s" ANSI_COLOR_RESET, ntHeader->FileHeader.TimeDateStamp, ctime(&(ntHeader->FileHeader.TimeDateStamp)));
		printf("PointerToSymbolTable:		%x \n", ntHeader->FileHeader.PointerToSymbolTable);
		printf("NumberOfSymbols:		%x \n", ntHeader->FileHeader.NumberOfSymbols);
		printf("SizeOfOptionalHeader:		%x \n", ntHeader->FileHeader.SizeOfOptionalHeader);
		printf(ANSI_COLOR_GREEN "Characteristics:		%x \n" ANSI_COLOR_RESET, ntHeader->FileHeader.Characteristics);



		printf("\n\nOptinal Header------> \n\n");

		printf("Magic:				%x \n", ntHeader->OptionalHeader.Magic);
		printf("MajorLinkerVersion:		%x \n", ntHeader->OptionalHeader.MajorLinkerVersion);
		printf("MinorLinkerVersion:		%x \n", ntHeader->OptionalHeader.MinorLinkerVersion);
		printf("SizeOfCode:			%x \n", ntHeader->OptionalHeader.SizeOfCode);
		printf("SizeOfInitializedData:		%x \n", ntHeader->OptionalHeader.SizeOfInitializedData);
		printf("SizeOfUninitializedData:	%x \n", ntHeader->OptionalHeader.SizeOfUninitializedData);
		printf(ANSI_COLOR_YELLOW "AddressOfEntryPoint:		%x \n" ANSI_COLOR_RESET, ntHeader->OptionalHeader.AddressOfEntryPoint);
		printf("BaseOfCode:			%x \n", ntHeader->OptionalHeader.BaseOfCode);
		printf("ImageBase:			%x \n", ntHeader->OptionalHeader.ImageBase);
		printf("SectionAlignment:		%x \n", ntHeader->OptionalHeader.SectionAlignment);
		printf("FileAlignment:			%x \n", ntHeader->OptionalHeader.FileAlignment);
		printf("MajorOperatingSystemVersion:	%x \n", ntHeader->OptionalHeader.MajorOperatingSystemVersion);
		printf("MinorOperatingSystemVersion:	%x \n", ntHeader->OptionalHeader.MinorOperatingSystemVersion);
		printf("MajorImageVersion:		%x \n", ntHeader->OptionalHeader.MajorImageVersion);
		printf("MinorImageVersion:		%x \n", ntHeader->OptionalHeader.MajorSubsystemVersion);
		printf("MajorSubsystemVersion:		%x \n", ntHeader->OptionalHeader.MinorSubsystemVersion);
		printf("MinorSubsystemVersion:		%x \n", ntHeader->OptionalHeader.MinorSubsystemVersion);
		printf("Win32VersionValue:		%x \n", ntHeader->OptionalHeader.Win32VersionValue);
		printf("SizeOfImage:			%x \n", ntHeader->OptionalHeader.SizeOfImage);
		printf("SizeOfHeaders:			%x \n", ntHeader->OptionalHeader.SizeOfHeaders);
		printf("CheckSum:			%x \n", ntHeader->OptionalHeader.CheckSum);
		printf("Subsystem:			%x \n", ntHeader->OptionalHeader.Subsystem);
		printf("DllCharacteristics:		%x \n", ntHeader->OptionalHeader.DllCharacteristics);
		printf("SizeOfStackReserve:		%x \n", ntHeader->OptionalHeader.SizeOfStackReserve);
		printf("SizeOfStackCommit:		%x \n", ntHeader->OptionalHeader.SizeOfStackCommit);
		printf("SizeOfHeapReserve:		%x \n", ntHeader->OptionalHeader.SizeOfHeapReserve);
		printf("SizeOfHeapCommit:		%x \n", ntHeader->OptionalHeader.SizeOfHeapCommit);
		printf("LoaderFlags:			%x \n", ntHeader->OptionalHeader.LoaderFlags);
		printf("NumberOfRvaAndSizes:		%x \n", ntHeader->OptionalHeader.NumberOfRvaAndSizes);

		printf("-----------------------------------------------------------------------------------------------\n");
		printf("-----------------------------------------------------------------------------------------------\n");
		printf("-----------------------------------------------------------------------------------------------\n");



		/* Gets PE section names
		  IMAGE_OPTIONAL_HEADER struct contains DWORD NumberOfSections
		  There is already a ptr to IMAGE_NT_HEADERS where it starts. After this struct will be NumberOfSections structs of type SECTION.
		  By adding sizeof(ntHeader) struct to the ntHeader base address, will get a ptr to the first section.
		  This ptr of type IMAGE_SECTION_HEADER then use array indexing to jump to the next section (e.g. header[0], ... header[numSections-1]).
		*/

		WORD numSections = ntHeader->FileHeader.NumberOfSections;
		PIMAGE_SECTION_HEADER header = (sizeof(*ntHeader) + (BYTE*)ntHeader);

		printf(ANSI_COLOR_MAGENTA "PE Section Headers:\n" ANSI_COLOR_RESET);

		for (int i = 0; i < numSections; ++i) {
			if (i == 0) {
				printf(ANSI_COLOR_MAGENTA "\n\nName: %s\n\nVirtualSize:		%x\nVirtualAddress:		%x\nSizeOfRawData:		%x\nPointerToRawData:	%x\nPointerToRelocations:	%x\nPointerToLinenumbers:	%x\nNumberOfRelocations:	%x\nNumberOfLinenumbers:	%x\nCharacteristics:	%x\n" ANSI_COLOR_RESET, header[i].Name, header[i].Misc.VirtualSize, header[i].VirtualAddress, header[i].SizeOfRawData, header[i].PointerToRawData, header[i].PointerToRelocations, header[i].PointerToLinenumbers, header[i].NumberOfRelocations, header[i].NumberOfLinenumbers, header[i].Characteristics);
			}
			else {

				printf(ANSI_COLOR_MAGENTA "\n\nName: %s\n\nVirtualSize:		%x\nVirtualAddress:		%x\nSizeOfRawData:		%x\nPointerToRawData:	%x\nPointerToRelocations:	%x\nPointerToLinenumbers:	%x\nNumberOfRelocations:	%x\nNumberOfLinenumbers:	%x\nCharacteristics:	%x\n" ANSI_COLOR_RESET, header[i].Name, header[i].Misc.VirtualSize, header[i].VirtualAddress, header[i].SizeOfRawData, header[i].PointerToRawData, header[i].PointerToRelocations, header[i].PointerToLinenumbers, header[i].NumberOfRelocations, header[i].NumberOfLinenumbers, header[i].Characteristics);

			}

		}

		printf("\n\n-----------------------------------------------------------------------------------------------\n");
		printf("-----------------------------------------------------------------------------------------------\n");
		printf("-----------------------------------------------------------------------------------------------\n");


		printf("\n\n\n\n");
	}

	getchar();
	return 0;
}


