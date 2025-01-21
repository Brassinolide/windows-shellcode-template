#include <windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
using namespace std;

static bool IsFileExistsA(const char* file) {
	DWORD attr = GetFileAttributesA(file);
	return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

static void dump_text_section(const char* in, const char* out1, const char* out2) {
	HANDLE hIn = INVALID_HANDLE_VALUE, hOut1 = INVALID_HANDLE_VALUE, hOut2 = INVALID_HANDLE_VALUE;
	char* in_buffer = nullptr;
	DWORD file_size = 0;
	const char text[8] = { '.','t','e','x','t' , 0, 0, 0 };
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS32 nt_header_32;
	PIMAGE_SECTION_HEADER section_header;

	printf("processing %s...", in);

	hIn = CreateFileA(in, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
	if (hIn == INVALID_HANDLE_VALUE) {
		printf("无法打开文件\n");
		goto exit;
	}

	file_size = GetFileSize(hIn, 0);
	in_buffer = new char[file_size];
	DWORD dwRead;
	if (!ReadFile(hIn, in_buffer, file_size, &dwRead, 0)) {
		printf("无法读取文件\n");
		goto exit;
	}

	dos_header = (PIMAGE_DOS_HEADER)in_buffer;
	nt_header_32 = (PIMAGE_NT_HEADERS32)(in_buffer + dos_header->e_lfanew);
	section_header = IMAGE_FIRST_SECTION(nt_header_32);

	for (int i = section_header->PointerToRawData + section_header->SizeOfRawData - 1; i >= 0; --i) {
		if (in_buffer[i] != 0)break;
		--section_header->SizeOfRawData;
	}

	for (int i = 0; i < nt_header_32->FileHeader.NumberOfSections; ++i, ++section_header) {
		if (memcmp(section_header->Name, text, 8) == 0) {
			printf("\n   - dump to %s...", out1);
			hOut1 = CreateFileA(out1, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, 0);
			if (hOut1 == INVALID_HANDLE_VALUE) {
				printf("无法创建文件\n");
				goto exit;
			}

			DWORD write;
			if (!WriteFile(hOut1, in_buffer + section_header->PointerToRawData, section_header->SizeOfRawData, &write, 0)) {
				printf("无法写入文件\n");
				goto exit;
			}
			printf("成功\n");

			printf("   - dump to %s...", out2);

			hOut2 = CreateFileA(out2, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, 0);
			if (hOut2 == INVALID_HANDLE_VALUE) {
				printf("无法创建文件\n");
				goto exit;
			}

			std::stringstream ss;
			ss << "const unsigned char shellcode[" << section_header->SizeOfRawData << "] = {";
			ss << std::showbase << std::hex << std::setfill('0') << std::setw(2);
			for (DWORD i = 0; i < section_header->SizeOfRawData; ++i) {
				if (i % 32 == 0) {
					ss << "\n    ";
				}

				ss << static_cast<unsigned int>(static_cast<unsigned char>((in_buffer + section_header->PointerToRawData)[i])) << ",";
			}
			ss << "\n};";

			if (!WriteFile(hOut2, ss.str().c_str(), ss.str().size(), &write, 0)) {
				printf("无法写入文件\n");
				goto exit;
			}

			printf("成功\n");
			goto exit;
		}
	}
	printf("未找到.text区段\n");

exit:
	if (hIn != INVALID_HANDLE_VALUE) CloseHandle(hIn);
	if (hOut1 != INVALID_HANDLE_VALUE) CloseHandle(hOut1);
	if (hOut2 != INVALID_HANDLE_VALUE) CloseHandle(hOut2);
	if (in_buffer != nullptr) delete[] in_buffer;
}

int main(int argc, char** argv) {
	if (argc != 2)return 1;

	if (strcmp(argv[1], "32") == 0) {
		dump_text_section("build/shellcode32.exe", "build/shellcode32.bin", "build/shellcode32.h");
	}

	if (strcmp(argv[1], "64") == 0) {
		dump_text_section("build/shellcode64.exe", "build/shellcode64.bin", "build/shellcode64.h");
	}
}
