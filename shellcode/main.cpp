#include <windows.h>
#include <cstdint>

#ifdef _WIN64
extern "C" DWORD64 GetK32();
#define GetK32Proc GetK32Proc64
DWORD64 GetK32Proc64(const char* proc);
#else
#define GetK32Proc GetK32Proc32
DWORD GetK32Proc32(const char* proc);
#endif

typedef HMODULE(WINAPI* LoadLibraryA_t)(
	LPCSTR lpLibFileName
	);
typedef FARPROC(WINAPI* GetProcAddress_t)(
	HMODULE hModule,
	LPCSTR  lpProcName
	);
typedef int(WINAPI* MessageBoxA_t)(
	HWND   hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT   uType
	);

void shellcode() {
	const char LoadLibraryA_s[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
	const char MessageBoxA_s[] = { 'M','e','s','s','a','g','e','B','o','x','A',0 };
	const char hello_world_s[] = { 'h','e','l','l','o',' ','w','o','r','l','d',0 };
	const char user32_dll_s[] = { 'u','s','e','r','3','2','.','d','l','l',0 };
	const char GetProcAddress_s[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };

	LoadLibraryA_t MyLoadLibrary = (LoadLibraryA_t)GetK32Proc(LoadLibraryA_s);
	GetProcAddress_t MyGetProcAddress = (GetProcAddress_t)GetK32Proc(GetProcAddress_s);

	MessageBoxA_t MyMessageBoxA = (MessageBoxA_t)MyGetProcAddress(MyLoadLibrary(user32_dll_s),MessageBoxA_s);

	MyMessageBoxA(0, hello_world_s, 0, 0);
}

#ifdef _WIN64
DWORD64 GetK32Proc64(const char* proc) {
	DWORD64 k32 = GetK32();

	DWORD e_lfanew = *(DWORD*)(k32 + 60);

	DWORD export_rva = *(DWORD*)(k32 + e_lfanew + 136);

	DWORD AddressOfFunctions = *(DWORD*)(k32 + export_rva + 28);
	DWORD AddressOfNames = *(DWORD*)(k32 + export_rva + 32);
	DWORD AddressOfNameOrdinals = *(DWORD*)(k32 + export_rva + 36);

	DWORD* AddressOfFunctions_va = (DWORD*)(k32 + AddressOfFunctions);
	DWORD* AddressOfNames_va = (DWORD*)(k32 + AddressOfNames);
	WORD* AddressOfNameOrdinals_va = (WORD*)(k32 + AddressOfNameOrdinals);

	DWORD NumberOfNames = *(DWORD*)(k32 + export_rva + 24);
	for (size_t i = 0; i < NumberOfNames; i++) {
		const char* func = (const char*)(k32 + AddressOfNames_va[i]);

		const char* _proc = proc;
		while (*func && (*func == *_proc)) {
			func++;
			_proc++;
		}

		if (*(unsigned char*)func - *(unsigned char*)_proc == 0) {
			return k32 + AddressOfFunctions_va[AddressOfNameOrdinals_va[i]];
		}
	}
	return 0;
}
#else
DWORD GetK32Proc32(const char* proc) {
	DWORD k32 = 0;
	__asm
	{
		mov eax, fs: [0x30] ;
		mov eax, [eax + 0xc];
		mov eax, [eax + 0x14];
		mov eax, [eax];
		mov eax, [eax];
		mov eax, [eax + 0x10];
		mov k32, eax;
	}

	DWORD e_lfanew = *(DWORD*)(k32 + 60);

	DWORD export_rva = *(DWORD*)(k32 + e_lfanew + 120);

	DWORD AddressOfFunctions = *(DWORD*)(k32 + export_rva + 28);
	DWORD AddressOfNames = *(DWORD*)(k32 + export_rva + 32);
	DWORD AddressOfNameOrdinals = *(DWORD*)(k32 + export_rva + 36);

	DWORD* AddressOfFunctions_va = (DWORD*)(k32 + AddressOfFunctions);
	DWORD* AddressOfNames_va = (DWORD*)(k32 + AddressOfNames);
	WORD* AddressOfNameOrdinals_va = (WORD*)(k32 + AddressOfNameOrdinals);

	DWORD NumberOfNames = *(DWORD*)(k32 + export_rva + 24);
	for (size_t i = 0; i < NumberOfNames; i++) {
		const char* func = (const char*)(k32 + AddressOfNames_va[i]);

		const char* _proc = proc;
		while (*func && (*func == *_proc)) {
			func++;
			_proc++;
		}

		if (*(unsigned char*)func - *(unsigned char*)_proc == 0) {
			return k32 + AddressOfFunctions_va[AddressOfNameOrdinals_va[i]];
		}
	}
	return 0;
}
#endif
