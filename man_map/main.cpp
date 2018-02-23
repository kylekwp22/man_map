#include "injection.h"
const char szDllFile[] = "C:\\Users\\Kwangil\\source\\repos\\wannaBePro\\x64\\Release\\wannaBePro.dll";
const char szProc[] = "overWatch.exe";

DWORD getPID_Snap() {
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);
	DWORD PID = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap = INVALID_HANDLE_VALUE)
	{

		DWORD Err = GetLastError();
		printf("CreateTollHep32Snapshot failed: 0x%X\n", Err);
		//system("PAUSE");
		return 0;
	}


	BOOL bRet = Process32First(hSnap, &PE32);
	while (bRet)
	{
		if (!strcmp(szProc, PE32.szExeFile))
		{
			
			PID = PE32.th32ParentProcessID;
			return PID;
		}
		bRet = Process32Next(hSnap, &PE32);
	}
	CloseHandle(hSnap);
}

int main() 
{
	
	DWORD PID = 0;
	PID = getPID_Snap();
	if (!PID) {
		HWND hWnd = FindWindowA(0, ("Overwatch"));
		GetWindowThreadProcessId(hWnd, &PID);
		if (!PID) {
			DWORD Err = GetLastError();
			printf("Get PID via Windows failed: 0x%X\n", Err);
			return 0;
		}

	}
	printf("PID = %d\n", (int)PID);

	

	

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,FALSE,PID);
	if (!hProc) {
		DWORD Err = GetLastError();
		printf("OpenProcess failed: 0x%X\n",Err);
		system("PAUSE");
		return 0;
	}

	if (!ManualMap(hProc, szDllFile)) {
		CloseHandle(hProc);
		printf("Something went wrong\n");
		system("PAUSE");
		return 0;
	}

	CloseHandle(hProc);
	return 0;

}