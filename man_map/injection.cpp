#include "injection.h"
bool ManualMap(HANDLE hProc, const char* szDllFile) 
{
	BYTE *				pSrcData = nullptr;
	IMAGE_NT_HEADERS *	pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER * pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER * pOldFileHeader = nullptr;
	BYTE *				pTargetBase = nullptr;

	DWORD dwCheck = 0;
	if (!GetFileAttributesA(szDllFile))
	{
		printf("File doesn't exist\n");
		return false;
	}

	std::ifstream File(szDllFile, std::ios::binary || std::ios::ate);

	if (File.fail())
	{
		printf("Opening the file failed: %X\n", (DWORD)File.rdstate());
		return false;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000)
	{
		printf("File size is invalid. \n");
		File.close();
		return false;
	}


	pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];
	if (!pSrcData)
	{
		printf("Mem alloc failed\n");
		File.close();
		return false;
	}

	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(pSrcData),FileSize);
	File.close();

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) //"MZ"
	{
		printf("Invalid file\n");
		delete[] pSrcData;
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		printf("invalid platform\n");
		delete[] pSrcData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		printf("invalid platform\n");
		delete[] pSrcData;
		return false;
	}
#endif

	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader->ImageBase),pOldOptHeader->SizeOfImage,MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (pTargetBase)
	{
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase)
		{
			printf("Memory allocation failed (ex) 0x%X\n", GetLastError());
			delete[] pSrcData;
			return false;
		}
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
			{
				printf("Can't map sections: 0x%x\n", GetLastError());
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

}