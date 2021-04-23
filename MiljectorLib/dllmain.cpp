
#include "framework.h"
/* inspired from https://github.com/danielkrupinski/curiuminjector-csgo */

/*
* MIT License
*
* Copyright (c) 2017-2018 Daniel Krupiñski
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#define ASM_CODE \
__asm _emit 0x89 \
__asm _emit 0x06 \
__asm _emit 0x80 \
__asm _emit 0x97 \
__asm _emit 0x12 \
__asm _emit 0x98 \
__asm _emit 0x67 \
__asm _emit 0x64 \
__asm _emit 0x74 \
__asm _emit 0x22 \
__asm _emit 0x96 \
__asm _emit 0x95 \
__asm _emit 0x35 \
__asm _emit 0x60 \
__asm _emit 0x53 \
__asm _emit 0x64 \
__asm _emit 0x77 \
__asm _emit 0x52 \
__asm _emit 0x17 \
__asm _emit 0x12 \
__asm _emit 0x22 \
__asm _emit 0x49 \
__asm _emit 0x90 \
__asm _emit 0x67 \
__asm _emit 0x04 \
__asm _emit 0x26 \
__asm _emit 0x59 \
__asm _emit 0x33 \
__asm _emit 0x10 \
__asm _emit 0x98 \
__asm _emit 0x64 \
__asm _emit 0x96 \
__asm _emit 0x74 \
__asm _emit 0x64 \
__asm _emit 0x55 \
__asm _emit 0x35 \
__asm _emit 0x48 \
__asm _emit 0x47 \
__asm _emit 0x44 \
__asm _emit 0x89 \
__asm _emit 0x97 \
__asm _emit 0x78 \
__asm _emit 0x56 \
__asm _emit 0x50 \
__asm _emit 0x87 \
__asm _emit 0x69 \
__asm _emit 0x88 \
__asm _emit 0x79 \
__asm _emit 0x89 \
__asm _emit 0x23 \
__asm _emit 0x44 \
__asm _emit 0x16 \
__asm _emit 0x18 \
__asm _emit 0x03 \
__asm _emit 0x50 \
__asm _emit 0x76 \
__asm _emit 0x75 \
__asm _emit 0x53 \
__asm _emit 0x73 \
__asm _emit 0x35 \
__asm _emit 0x48 \
__asm _emit 0x78 \
__asm _emit 0x80 \
__asm _emit 0x67 \
__asm _emit 0x30 \
__asm _emit 0x02 \
__asm _emit 0x21 \
__asm _emit 0x07 \
__asm _emit 0x30 \
__asm _emit 0x37 \
__asm _emit 0x82 \
__asm _emit 0x59 \
__asm _emit 0x13 \
__asm _emit 0x88 \
__asm _emit 0x65 \
__asm _emit 0x22 \
__asm _emit 0x37 \
__asm _emit 0x14 \
__asm _emit 0x46 \
__asm _emit 0x72 \
__asm _emit 0x23 \
__asm _emit 0x63 \
__asm _emit 0x91 \
__asm _emit 0x83 \
__asm _emit 0x37 \
__asm _emit 0x51 \
__asm _emit 0x71 \
__asm _emit 0x08 \
__asm _emit 0x30 \
__asm _emit 0x37 \
__asm _emit 0x59 \
__asm _emit 0x22 \
__asm _emit 0x72 \
__asm _emit 0x74 \
__asm _emit 0x06 \
__asm _emit 0x99 \
__asm _emit 0x21 \
__asm _emit 0x85 \
__asm _emit 0x42 \
__asm _emit 0x47 \

#define _JUNK_BLOCK(s) __asm jmp s ASM_CODE __asm s:

using namespace std;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		cout << "IN  -> PROCESS ATTACH" << endl;
    case DLL_THREAD_ATTACH:
		cout << "IN  -> THREAD  ATTACH" << endl;
    case DLL_THREAD_DETACH:
		cout << "OUT <- THREAD  DETACH" << endl;
    case DLL_PROCESS_DETACH:
		cout << "OUT <- PROCESS DETACH" << endl;
        break;
    }
    return TRUE;
}

extern "C" DWORD EXPORT Process(char* process_name)
{
	cout << "FNC <- Process" << endl;
	_JUNK_BLOCK(jmp_label1)
	HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	cout << "FNC <- Process CreateToolhelp32Snapshot: " << hPID << endl;
	_JUNK_BLOCK(jmp_label2)
	PROCESSENTRY32 ProcEntry;
	_JUNK_BLOCK(jmp_label3)
	ProcEntry.dwSize = sizeof(ProcEntry);
	_JUNK_BLOCK(jmp_label4)
	do
	{
		cout << "FNC <- Process do loop" << endl;
		_JUNK_BLOCK(jmp_label5)
		char* exeFile;
		wcstombs(exeFile, ProcEntry.szExeFile, MAX_PATH);
		if (!strcmp(exeFile, process_name))
		{
			_JUNK_BLOCK(jmp_label6)
			DWORD dwPID = ProcEntry.th32ProcessID;
			_JUNK_BLOCK(jmp_label7)
			CloseHandle(hPID);
			_JUNK_BLOCK(jmp_label8)
			cout << "FNC -> Process do loop dwPID: " << dwPID << endl;
			return dwPID;
		}
		_JUNK_BLOCK(jmp_label9)
	}
	while (Process32Next(hPID, &ProcEntry));
	_JUNK_BLOCK(jmp_label10)
	cout << "FNC -> Process End" << endl;
}

extern "C" int EXPORT Inject(char *process_name, LPCWSTR library)
{
	DWORD retval = 0;
	TCHAR** lppPart = { NULL };
	cout << "FNC <- Inject" << endl;
	_JUNK_BLOCK(jmp_label11)
	DWORD dwProcess;
	_JUNK_BLOCK(jmp_label12)
	TCHAR  myLibrary[BUFSIZE] = TEXT("");
	_JUNK_BLOCK(jmp_label13)

	retval = GetFullPathName(library, BUFSIZE, myLibrary, lppPart);
	if (retval == 0)
	{
		printf("GetFullPathName failed (%d)\n", GetLastError());
	}

	_JUNK_BLOCK(jmp_label4)
	dwProcess = Process(process_name);
	_JUNK_BLOCK(jmp_label15)
	pBut();
	yAD();
	mop();
	LlKk();
	AfUh();
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcess);
	_JUNK_BLOCK(jmp_label16)
	xtXP();
	BNxW();
	Wchh();
	Xze();
	DbL();
	LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(myLibrary), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	_JUNK_BLOCK(jmp_label17)
	dmfc();
	tXm();
	dgm();
	qmY();
	MYa();
	WriteProcessMemory(hProcess, allocatedMem, myLibrary, sizeof(myLibrary), NULL);
	_JUNK_BLOCK(jmp_label18)
	gHo();
	iHj();
	TNsp();
	DHaz();
	SieU();
	CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, allocatedMem, 0, 0);
	_JUNK_BLOCK(jmp_label19)
	CloseHandle(hProcess);
	_JUNK_BLOCK(jmp_label20)
	return 0;
}