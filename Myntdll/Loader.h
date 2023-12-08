using dllmain = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);
typedef struct IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;
class MemoryLoader
{
public:
	static LPVOID LoadDLL(const LPSTR lpDLLPath);
	static LPVOID GetFunctionAddress(const LPVOID lpModule, const LPSTR lpFunctionName);
	static LPVOID GetFunctionAddressByOrdinal(const LPVOID lpModule, const DWORD_PTR dOrdinal);
	static BOOL FreeDLL(const LPVOID lpModule);
private:
	static HANDLE GetFileContent(const LPSTR lpFilePath);
	static BOOL IsValidPE(const LPVOID lpImage);
	static BOOL IsDLL(const LPVOID hDLLData);
	static BOOL IsValidArch(const LPVOID lpImage);
	static DWORD_PTR GetImageSize(const LPVOID lpImage);
	static BOOL HasCallbacks(const LPVOID lpImage);
};
inline HANDLE MemoryLoader::GetFileContent(const LPSTR lpFilePath){
	const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE){
		CloseHandle(hFile);
		return nullptr;
	}
	const DWORD dFileSize = GetFileSize(hFile, nullptr);
	if (dFileSize == INVALID_FILE_SIZE){
		CloseHandle(hFile);
		return nullptr;
	}
	const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
	if (hFileContent == INVALID_HANDLE_VALUE){
		CloseHandle(hFile);
		CloseHandle(hFileContent);
		return nullptr;
	}
	const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, nullptr, nullptr);
	if (!bFileRead){
		CloseHandle(hFile);
		if (hFileContent != nullptr)
			CloseHandle(hFileContent);
		return nullptr;
	}
	CloseHandle(hFile);
	return hFileContent;
}
inline BOOL MemoryLoader::IsValidPE(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
		return TRUE;

	return FALSE;
}
inline BOOL MemoryLoader::IsDLL(const LPVOID hDLLData)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)(hDLLData);
	const auto lpImageNtHeader = (PIMAGE_NT_HEADERS32)((DWORD_PTR)hDLLData + lpImageDOSHeader->e_lfanew);

	if (lpImageNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
		return TRUE;
	return FALSE;
}
inline BOOL MemoryLoader::IsValidArch(const LPVOID lpImage){
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return TRUE;
	return FALSE;
}
inline DWORD_PTR MemoryLoader::GetImageSize(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	return lpImageNTHeader->OptionalHeader.SizeOfImage;
}
inline BOOL MemoryLoader::HasCallbacks(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);
	const DWORD_PTR dVirtualAddress = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	return dVirtualAddress != 0;
}
inline LPVOID MemoryLoader::LoadDLL(const LPSTR lpDLLPath){
	const HANDLE hDLLData = GetFileContent(lpDLLPath);
	if (hDLLData == INVALID_HANDLE_VALUE || hDLLData == nullptr){
		return nullptr;
	}
	if (!IsValidPE(hDLLData)){

		if (hDLLData != nullptr)
			HeapFree(GetProcessHeap(), 0, hDLLData);
		return nullptr;
	}
	if (!IsDLL(hDLLData)){
		return nullptr;
	}
	if (!IsValidArch(hDLLData)){
		return nullptr;
	}
	const DWORD_PTR dImageSize = GetImageSize(hDLLData);
	const LPVOID lpAllocAddress = VirtualAlloc(nullptr, dImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr){
		return nullptr;
	}
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)hDLLData;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageNTHeader + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader->FileHeader.SizeOfOptionalHeader);
	const DWORD_PTR dDeltaAddress = (DWORD_PTR)lpAllocAddress - lpImageNTHeader->OptionalHeader.ImageBase;
	lpImageNTHeader->OptionalHeader.ImageBase = (DWORD_PTR)lpAllocAddress;
	RtlCopyMemory(lpAllocAddress, hDLLData, lpImageNTHeader->OptionalHeader.SizeOfHeaders);
	const IMAGE_DATA_DIRECTORY ImageDataReloc = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	const IMAGE_DATA_DIRECTORY ImageDataImport = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_SECTION_HEADER lpImageRelocHeader = nullptr;
	PIMAGE_SECTION_HEADER lpImageImportHeader = nullptr;
	for (int i = 0; i < lpImageNTHeader->FileHeader.NumberOfSections; i++){
		const auto lpCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageSectionHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (ImageDataReloc.VirtualAddress >= lpCurrentSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpCurrentSectionHeader->VirtualAddress + lpCurrentSectionHeader->Misc.VirtualSize))
			lpImageRelocHeader = lpCurrentSectionHeader;
		if (ImageDataImport.VirtualAddress >= lpCurrentSectionHeader->VirtualAddress && ImageDataImport.VirtualAddress < (lpCurrentSectionHeader->VirtualAddress + lpCurrentSectionHeader->Misc.VirtualSize))
			lpImageImportHeader = lpCurrentSectionHeader;
		RtlCopyMemory((LPVOID)((DWORD_PTR)lpAllocAddress + lpCurrentSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)hDLLData + lpCurrentSectionHeader->PointerToRawData), lpCurrentSectionHeader->SizeOfRawData);
	}
	if (lpImageRelocHeader == nullptr){
		return nullptr;
	}
	if (lpImageImportHeader == nullptr){
		return nullptr;
	}
	DWORD_PTR RelocOffset = 0;
	while (RelocOffset < ImageDataReloc.Size){
		const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)hDLLData + lpImageRelocHeader->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD_PTR NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
		for (DWORD_PTR i = 0; i < NumberOfEntries; i++){
			const auto lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD_PTR)hDLLData + lpImageRelocHeader->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			const DWORD_PTR AddressLocation = (DWORD_PTR)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
			DWORD_PTR PatchedAddress = 0;
			RtlCopyMemory((LPVOID)&PatchedAddress, (LPVOID)AddressLocation, sizeof(DWORD_PTR));
			PatchedAddress += dDeltaAddress;
			RtlCopyMemory((LPVOID)AddressLocation, (LPVOID)&PatchedAddress, sizeof(DWORD_PTR));
		}
	}
	auto lpImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if (lpImageImportDescriptor == nullptr){
		return nullptr;
	}
	while(lpImageImportDescriptor->Name != 0){
		const auto lpLibraryName = (LPSTR)((DWORD_PTR)lpAllocAddress + lpImageImportDescriptor->Name);
		const HMODULE hModule = LoadLibraryA(lpLibraryName);
		if (hModule == nullptr)
		{
			return nullptr;
		}
		auto lpThunkData = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpAllocAddress + lpImageImportDescriptor->FirstThunk);
		while (lpThunkData->u1.AddressOfData != 0)
		{
			if (IMAGE_SNAP_BY_ORDINAL(lpThunkData->u1.Ordinal))
			{
				const auto functionOrdinal = (UINT)IMAGE_ORDINAL(lpThunkData->u1.Ordinal);
				lpThunkData->u1.Function = (DWORD_PTR)GetProcAddress(hModule, MAKEINTRESOURCEA(functionOrdinal));
			}
			else
			{
				const auto lpData = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpAllocAddress + lpThunkData->u1.AddressOfData);
				const auto functionAddress = (DWORD_PTR)GetProcAddress(hModule, lpData->Name);
				lpThunkData->u1.Function = functionAddress;
			}

			lpThunkData++;
		}

		lpImageImportDescriptor++;
	}
	if (HasCallbacks(hDLLData)){
		const auto lpImageTLSDirectory = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto lpCallbackArray = (PIMAGE_TLS_CALLBACK*)lpImageTLSDirectory->AddressOfCallBacks;
		while (*lpCallbackArray != nullptr)
		{
			const auto lpImageCallback = *lpCallbackArray;
			lpImageCallback(hDLLData, DLL_PROCESS_ATTACH, nullptr);
			lpCallbackArray++;
		}
	}
	const auto main = (dllmain)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint);
	BOOL result;
	if(main)result=main((HINSTANCE)lpAllocAddress, DLL_PROCESS_ATTACH, nullptr);
	if (!result){
		return nullptr;
	}
	HeapFree(GetProcessHeap(), 0, hDLLData);
	return (LPVOID)lpAllocAddress;
}
inline LPVOID MemoryLoader::GetFunctionAddress(const LPVOID lpModule, const LPSTR lpFunctionName){
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return nullptr;
	const auto lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	const DWORD_PTR dNumberOfNames = lpImageExportDirectory->NumberOfNames;
	for (int i = 0; i < (int)dNumberOfNames; i++)
	{
		const auto lpCurrentFunctionName = (LPSTR)(((DWORD*)(lpImageExportDirectory->AddressOfNames + (DWORD_PTR)lpModule))[i] + (DWORD_PTR)lpModule);
		const auto lpCurrentOridnal = ((WORD*)(lpImageExportDirectory->AddressOfNameOrdinals + (DWORD_PTR)lpModule))[i];
		const auto addRVA = ((DWORD*)((DWORD_PTR)lpModule + lpImageExportDirectory->AddressOfFunctions))[lpCurrentOridnal];
		if (strcmp(lpCurrentFunctionName, lpFunctionName) == 0)
			return (LPVOID)((DWORD_PTR)lpModule + addRVA);
	}
	return nullptr;
}
inline LPVOID MemoryLoader::GetFunctionAddressByOrdinal(const LPVOID lpModule, const DWORD_PTR dOrdinal){
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return nullptr;
	const auto lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	const auto addRVA = ((DWORD*)((DWORD_PTR)lpModule + lpImageExportDirectory->AddressOfFunctions))[dOrdinal];
	return (LPVOID)((DWORD_PTR)lpModule + addRVA);
}
inline BOOL MemoryLoader::FreeDLL(const LPVOID lpModule){
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (HasCallbacks(lpModule)){
		const auto lpImageTLSDirectory = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto lpCallbackArray = (PIMAGE_TLS_CALLBACK*)lpImageTLSDirectory->AddressOfCallBacks;

		while (*lpCallbackArray != nullptr){
			const auto lpImageCallback = *lpCallbackArray;
			lpImageCallback(lpModule, DLL_PROCESS_DETACH, nullptr);
			lpCallbackArray++;
		}
	}
	const auto main = (dllmain)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint);
	const BOOL result = main((HINSTANCE)lpModule, DLL_PROCESS_DETACH, nullptr);
	if (!result){
		return FALSE;
	}
	const BOOL bFree = VirtualFree(lpModule, 0, MEM_RELEASE);
	if (!bFree){
		return FALSE;
	}
	return TRUE;
}
