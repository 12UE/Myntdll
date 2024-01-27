

#include<iostream>


#include"ntdll.h"
#include <stdarg.h>
#include"Loader.h"
#include<unordered_map>
#include"XorLib.h"
#include<type_traits>
constexpr auto USERADDR_MIN = 0x10000;
#if defined _WIN64
using UDWORD = DWORD64;
#define XIP Rip
#define XAX Rax
constexpr auto USERADDR_MAX = 0x7fffffff0000;
#define U64_ "%llx"  //U64_使用的时候注意不要多加"%" 号了
#else
using UDWORD = DWORD32;
#define XIP Eip
#define XAX Eax
#define U64_ "%x"//U64_使用的时候注意不要多加"%" 号了
constexpr auto USERADDR_MAX = 0xBFFE'FFFF;
#endif
HMODULE hNtdll = nullptr;
inline HMODULE LoadApi(_In_ LPSTR lpLibFileName) {//自定义加载函数 参数文件名
    return (HMODULE)MemoryLoader::LoadDLL(lpLibFileName);
}

PIMAGE_NT_HEADERS GetNtHeader(LPVOID buffer) {
    auto pDosHeader = (PIMAGE_DOS_HEADER)buffer;
    if (!pDosHeader) return nullptr;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto pNtHeader = (PIMAGE_NT_HEADERS)((UDWORD)buffer + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE || !pNtHeader) return nullptr;
    return pNtHeader;
}
std::string GetSystem32Path() {
    char szSystemDir[MAX_PATH] = { 0 };
    GetSystemDirectoryA(szSystemDir, MAX_PATH);
    return std::string(szSystemDir);
}
HMODULE ReloadSystemdll(const char* lpszdllname) {
    static std::unordered_map<std::string, LPVOID> namebase;
    BYTE* BaseAddr = nullptr;
    auto iter = namebase.find(lpszdllname);
    if (iter != namebase.end())BaseAddr = (BYTE*)iter->second;
    if (!BaseAddr) {
        HMODULE hModule{};
        std::string SystemPath = GetSystem32Path() + "\\" + lpszdllname;
        auto olddll = GetModuleHandleA(lpszdllname);
        if (!olddll)LoadApi((char*)lpszdllname);
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)olddll, &hModule);
        auto cb = sizeof(MODULEINFO);
        MODULEINFO modinfo{};
        GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, cb);
        int MaxSize = modinfo.SizeOfImage;
        UDWORD CurrentAddr = (UDWORD)modinfo.lpBaseOfDll;
        UDWORD realsize = 0;
        while (true) {
            MEMORY_BASIC_INFORMATION mbi{};
            VirtualQuery((LPVOID)CurrentAddr, &mbi, sizeof(mbi));
            CurrentAddr = (UDWORD)mbi.BaseAddress + mbi.RegionSize;
            if (CheckMask(mbi.Protect, PAGE_NOACCESS | PAGE_GUARD)) {
                realsize = CurrentAddr - (UDWORD)modinfo.lpBaseOfDll;
                break;
            }
            if (CurrentAddr - (UDWORD)modinfo.lpBaseOfDll > MaxSize) {
                realsize = MaxSize;
            }
        }
        auto newdll = (BYTE*)VirtualAlloc(NULL, MaxSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        namebase.insert(std::make_pair(lpszdllname, (LPVOID)newdll));
        BaseAddr = newdll;
        ZeroMemory(newdll, MaxSize);
        memcpy(newdll, modinfo.lpBaseOfDll, MaxSize);
        auto dllbase = (HMODULE)newdll;
        WIN32_FIND_DATAA FindFileData{};
        auto hFind = FindFirstFileA(SystemPath.c_str(), &FindFileData);
        if (hFind == INVALID_HANDLE_VALUE) {
            return nullptr;
        }
        auto dllfile = CreateFileA(SystemPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        auto ntdllMapping = CreateFileMapping(dllfile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        auto dllmappingaddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
        auto hookedDosHeader = (PIMAGE_DOS_HEADER)dllbase;
        auto hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllbase + hookedDosHeader->e_lfanew);
        for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; ++i) {
            PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
            if (!strcmp((char*)hookedSectionHeader->Name, (char*)xor_str(".text"))) {
                memcpy((LPVOID)((DWORD_PTR)dllbase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)dllmappingaddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
            }
        }
        UnmapViewOfFile(dllmappingaddress);
        CloseHandle(dllfile);
    }
    return (HMODULE)BaseAddr;
}
FARPROC GetFunctionByName(LPVOID pDllImageBuffer, LPCSTR lpszFunc) {
    if (pDllImageBuffer == NULL) pDllImageBuffer = ReloadSystemdll(xor_str("ntdll.dll"));
    PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDllImageBuffer);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pDllImageBuffer +
        pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
    PDWORD AddressOfFunctions = (PDWORD)((PBYTE)pDllImageBuffer + pExport->AddressOfFunctions);
    PDWORD AddressOfNames = (PDWORD)((PBYTE)pDllImageBuffer + pExport->AddressOfNames);
    PUSHORT AddressOfNameOrdinals = (PUSHORT)((PBYTE)pDllImageBuffer + pExport->AddressOfNameOrdinals);
    for (size_t i = 0; i < pExport->NumberOfNames; i++) {
        if (0 == strcmp(lpszFunc, (char*)pDllImageBuffer + AddressOfNames[i])) {
            return (FARPROC)(AddressOfFunctions[AddressOfNameOrdinals[i]] + (PBYTE)pDllImageBuffer);
        }
    }
    return NULL;
}
void SetLastWin32Error(ULONG WinError) {
    typedef ULONG(NTAPI* _pRtlSetLastWin32Error)(ULONG WinError);
    static _pRtlSetLastWin32Error pRtlSetLastWin32Error = (_pRtlSetLastWin32Error)GetFunctionByName(hNtdll, xor_str("RtlSetLastWin32Error"));
    if (pRtlSetLastWin32Error)pRtlSetLastWin32Error(WinError);
}
void SetFuncLastError(IN    NTSTATUS status) {
    if (!NT_SUCCESS(status)) {
        typedef DWORD(NTAPI* _pRtlNtStatusToDosError)(NTSTATUS status);
        static _pRtlNtStatusToDosError pRtlNtStatusToDosError = (_pRtlNtStatusToDosError)GetFunctionByName(hNtdll, xor_str("RtlNtStatusToDosError"));
        auto ErrorCode = 0;
        if (pRtlNtStatusToDosError) ErrorCode = pRtlNtStatusToDosError(status);
        SetLastWin32Error(ErrorCode);
    }
}
class NormalStatus {
public:
    inline static NTSTATUS InvalidStatuc() {
        return NULL;
    }
};
template<class T,class Traits>
class NTSTATUSHANDLER {
private:
    T status;
    bool Own;
public:
    NTSTATUSHANDLER(const T& _status, bool _Own = false) :status(_status), Own(_Own) {}
    ~NTSTATUSHANDLER(){
        SetFuncLastError(status);
        status = Traits::InvalidStatuc();
    }
    //转换为bool类型
    operator bool() const {
        return NT_SUCCESS(status);
    }
    //转换为T类型
    operator T() const {
        return status;
    }
    //判等
    bool operator==(const T& _status) const {
        return status == _status;
    }
    //判不等
    bool operator!=(const T& _status) const {
        return status != _status;
    }
};
template<typename T>
class function {
    using FnPtr = T(*)();
public:
    FnPtr _pFn = nullptr;
    function() = default;
    function(function&& other) : _pFn(other._pFn) {
        other._pFn = nullptr;
    }
    function(void* pfn) {
        _pFn = (FnPtr)pfn;
    }
    ~function() {  }
    template <class... _Args> decltype(auto) operator()(_Args&&... args) {//有参数
        if constexpr (std::is_same_v<T, void>) {
            ExecuteFunc(_pFn, std::forward<_Args>(args)...);
        }else {
			T ret{};
			ret = ExecuteFunc<T>(_pFn, std::forward<_Args>(args)...);
            if constexpr (std::is_same_v<T, NTSTATUS>) {
				NTSTATUSHANDLER<T, NormalStatus> handler(ret);
			}
			return ret;
		}   
    }
    decltype(auto) invoke() {
        if constexpr (std::is_same_v<T, void>) {
           ExecuteFunc(_pFn);
        }else{
           T ret{};
           ret = ExecuteFunc<T>(_pFn);
           if constexpr (std::is_same_v<T, NTSTATUS>) {
               NTSTATUSHANDLER<T, NormalStatus> handler(ret);
           }
           return ret;
        } 
    }
    template<class U> operator U() { return function<U>(_pFn); }
    void* operator &() { return static_cast<void*>(_pFn); }
    bool operator==(const function& other) {
        if (_pFn == other._pFn) return true;
        return _pFn == other._pFn;
    }
    bool operator!=(const function& other) {
        return _pFn != other._pFn;
    }
    function& operator=(const function& other) {
        _pFn = other._pFn;
        return *this;
    }
    function& operator=(function&& other) noexcept {
        _pFn = other._pFn;
        other._pFn = nullptr;
        return *this;
    }
    void* funcptr() { return reinterpret_cast<void*>(_pFn); }
    operator bool() { return _pFn != nullptr; }
    size_t Size() { return GetLength((BYTE*)_pFn); }
private:
    template <class Ty = int, class F, class... Args> [[nodiscard]] decltype(auto) ExecuteFunc(F f, Args&&...args) {
        if constexpr (sizeof...(Args)) {
            using FunctionType = Ty(__stdcall*)(Args...);
			return((UDWORD)f > USERADDR_MIN && (UDWORD)f < USERADDR_MAX) ? FunctionType(reinterpret_cast<FunctionType>(f))(std::forward<Args>(args)...) : Ty();//__stdcall 
		}else {
			using FunctionType = Ty(__stdcall*)();
			return((UDWORD)f > USERADDR_MIN && (UDWORD)f < USERADDR_MAX) ? FunctionType(reinterpret_cast<FunctionType>(f))() : Ty();//__stdcall     
        }
    }
};
#pragma region NATIVE API
    EXPORT DWORD NTAPI RtlNtStatusToDosError(
        IN    NTSTATUS status
    ) {
        static function<DWORD> pRtlNtStatusToDosError = (void*)GetFunctionByName(hNtdll, xor_str("RtlNtStatusToDosError"));
        return pRtlNtStatusToDosError(status);
    }
     EXPORT NTSTATUS NTAPI NtAcceptConnectPort(
        OUT    PHANDLE PortHandle,
        IN    PVOID  PortContext OPTIONAL,
        IN    PPORT_MESSAGE ConnectionRequest,
        IN    BOOLEAN AcceptConnection,
        IN OUT    PPORT_VIEW ServerView OPTIONAL,
        OUT    PREMOTE_PORT_VIEW ClientView OPTIONAL
    ){
         static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAcceptConnectPort"));
         return pfun(PortHandle, PortContext, ConnectionRequest, AcceptConnection, ServerView, ClientView);
    }

     EXPORT NTSTATUS NTAPI NtAccessCheck(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    HANDLE TokenHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    PGENERIC_MAPPING GenericMapping,
        OUT    PPRIVILEGE_SET PrivilegeSet,
        IN    PULONG PrivilegeSetLength,
        OUT    PACCESS_MASK GrantedAccess,
        OUT    PBOOLEAN AccessStatus
    ){
         static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAccessCheck"));
         return pfun(SecurityDescriptor, TokenHandle, DesiredAccess, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus);
    }

     EXPORT NTSTATUS NTAPI NtAccessCheckAndAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    PUNICODE_STRING ObjectTypeName,
        IN    PUNICODE_STRING ObjectName,
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    ACCESS_MASK DesiredAccess,
        IN    PGENERIC_MAPPING GenericMapping,
        IN    BOOLEAN ObjectCreation,
        OUT    PACCESS_MASK GrantedAccess,
        OUT    PBOOLEAN AccessStatus,
        OUT    PBOOLEAN GenerateOnClose
    ){
         static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAccessCheckAndAuditAlarm"));
         return pfun(SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, DesiredAccess, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, GenerateOnClose);
    }

     EXPORT NTSTATUS NTAPI NtAccessCheckByType(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    PSID PrincipalSelfSid,
        IN    HANDLE TokenHandle,
        IN    ULONG DesiredAccess,
        IN    POBJECT_TYPE_LIST ObjectTypeList,
        IN    ULONG ObjectTypeListLength,
        IN    PGENERIC_MAPPING GenericMapping,
        IN    PPRIVILEGE_SET PrivilegeSet,
        IN    PULONG PrivilegeSetLength,
        OUT    PACCESS_MASK GrantedAccess,
        OUT    PULONG AccessStatus
    ){
         static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAccessCheckByType"));
         return pfun(SecurityDescriptor, PrincipalSelfSid, TokenHandle, DesiredAccess, ObjectTypeList, ObjectTypeListLength, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus);
    }

     EXPORT NTSTATUS NTAPI NtAccessCheckByTypeAndAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    PUNICODE_STRING ObjectTypeName,
        IN    PUNICODE_STRING ObjectName,
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    PSID PrincipalSelfSid,
        IN    ACCESS_MASK DesiredAccess,
        IN    AUDIT_EVENT_TYPE AuditType,
        IN    ULONG Flags,
        IN    POBJECT_TYPE_LIST ObjectTypeList,
        IN    ULONG ObjectTypeListLength,
        IN    PGENERIC_MAPPING GenericMapping,
        IN    BOOLEAN ObjectCreation,
        OUT    PACCESS_MASK GrantedAccess,
        OUT    PULONG AccessStatus,
        OUT    PBOOLEAN GenerateOnClose
    ){
         static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAccessCheckByTypeAndAuditAlarm"));
         return pfun(SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, GenerateOnClose);
    }

     EXPORT NTSTATUS NTAPI NtAccessCheckByTypeResultList(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    PSID PrincipalSelfSid,
        IN    HANDLE TokenHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_TYPE_LIST ObjectTypeList,
        IN    ULONG ObjectTypeListLength,
        IN    PGENERIC_MAPPING GenericMapping,
        IN    PPRIVILEGE_SET PrivilegeSet,
        IN    PULONG PrivilegeSetLength,
        OUT    PACCESS_MASK GrantedAccessList,
        OUT    PULONG AccessStatusList
    ){
         static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAccessCheckByTypeResultList"));
         return pfun(SecurityDescriptor, PrincipalSelfSid, TokenHandle, DesiredAccess, ObjectTypeList, ObjectTypeListLength, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccessList, AccessStatusList);
    }

     EXPORT NTSTATUS NTAPI NtAccessCheckByTypeResultListAndAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    PUNICODE_STRING ObjectTypeName,
        IN    PUNICODE_STRING ObjectName,
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    PSID PrincipalSelfSid,
        IN    ACCESS_MASK DesiredAccess,
        IN    AUDIT_EVENT_TYPE AuditType,
        IN    ULONG Flags,
        IN    POBJECT_TYPE_LIST ObjectTypeList,
        IN    ULONG ObjectTypeListLength,
        IN    PGENERIC_MAPPING GenericMapping,
        IN    BOOLEAN ObjectCreation,
        OUT    PACCESS_MASK GrantedAccessList,
        OUT    PULONG AccessStatusList,
        OUT    PULONG GenerateOnClose
    ){
         static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAccessCheckByTypeResultListAndAuditAlarm"));
         return pfun(SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccessList, AccessStatusList, GenerateOnClose);
    }

     EXPORT NTSTATUS NTAPI NtAccessCheckByTypeResultListAndAuditAlarmByHandle(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    HANDLE TokenHandle,
        IN    PUNICODE_STRING ObjectTypeName,
        IN    PUNICODE_STRING ObjectName,
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    PSID PrincipalSelfSid,
        IN    ACCESS_MASK DesiredAccess,
        IN    AUDIT_EVENT_TYPE AuditType,
        IN    ULONG Flags,
        IN    POBJECT_TYPE_LIST ObjectTypeList,
        IN    ULONG ObjectTypeListLength,
        IN    PGENERIC_MAPPING GenericMapping,
        IN    BOOLEAN ObjectCreation,
        OUT    PACCESS_MASK GrantedAccessList,
        OUT    PULONG AccessStatusList,
        OUT    PULONG GenerateOnClose
    ){
         static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAccessCheckByTypeResultListAndAuditAlarmByHandle"));
         return pfun(SubsystemName, HandleId, TokenHandle, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccessList, AccessStatusList, GenerateOnClose);
    }

     EXPORT NTSTATUS NTAPI NtAddAtom(
        IN    PWSTR String,
        IN    ULONG StringLength,
        OUT    PUSHORT Atom
    ){
         static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAddAtom"));
        return pfun(String, StringLength, Atom);
    }

     EXPORT NTSTATUS NTAPI NtAddBootEntry(
        IN    PUNICODE_STRING EntryName,
        IN    PUNICODE_STRING EntryValue
    ){
         static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAddBootEntry"));
         return pfun(EntryName, EntryValue);
    }

     EXPORT NTSTATUS NTAPI NtAddDriverEntry(
        IN    PUNICODE_STRING DriverName,
        IN    PUNICODE_STRING DriverPath
    ){
         static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAddDriverEntry"));
         return pfun(DriverName, DriverPath);
    }

     EXPORT NTSTATUS NTAPI NtAdjustGroupsToken(
        IN    HANDLE TokenHandle,
        IN    BOOLEAN ResetToDefault,
        IN    PTOKEN_GROUPS NewState,
        IN    ULONG BufferLength,
        OUT    PTOKEN_GROUPS PreviousState OPTIONAL,
        OUT    PULONG ReturnLength
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAdjustGroupsToken"));
        return pfun(TokenHandle, ResetToDefault, NewState, BufferLength, PreviousState, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtAdjustPrivilegesToken(
        IN    HANDLE TokenHandle,
        IN    BOOLEAN DisableAllPrivileges,
        IN    PTOKEN_PRIVILEGES NewState OPTIONAL,
        IN    ULONG BufferLength OPTIONAL,
        IN    PTOKEN_PRIVILEGES PreviousState OPTIONAL,
        OUT    PULONG ReturnLength
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAdjustPrivilegesToken"));
        return pfun(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtAlertResumeThread(
        IN    HANDLE ThreadHandle,
        OUT    PULONG PreviousSuspendCount OPTIONAL
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAlertResumeThread"));
        return pfun(ThreadHandle, PreviousSuspendCount);
    }

     EXPORT NTSTATUS NTAPI NtAllocateLocallyUniqueId(
        OUT    PLUID Luid
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAllocateLocallyUniqueId"));
        return pfun(Luid);
    }

     EXPORT NTSTATUS NTAPI NtAllocateUserPhysicalPages(
        IN    HANDLE ProcessHandle,
        IN    PULONG NumberOfPages,
        OUT    PULONG PageFrameNumbers
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAllocateUserPhysicalPages"));
        return pfun(ProcessHandle, NumberOfPages, PageFrameNumbers);
    }

     EXPORT NTSTATUS NTAPI NtAllocateUuids(
        OUT    PLARGE_INTEGER UuidLastTimeAllocated,
        OUT    PULONG UuidDeltaTime,
        OUT    PULONG UuidSequenceNumber,
        OUT    PUCHAR UuidSeed
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAllocateUuids"));
        return pfun(UuidLastTimeAllocated, UuidDeltaTime, UuidSequenceNumber, UuidSeed);
    }
     EXPORT NTSTATUS NTAPI NtAllocateVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN    ULONG ZeroBits,
        IN OUT    PULONG AllocationSize,
        IN    ULONG AllocationType,
        IN    ULONG Protect
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAllocateVirtualMemory"));
        return pfun(ProcessHandle, BaseAddress, ZeroBits, AllocationSize, AllocationType, Protect);
    }

     EXPORT NTSTATUS NTAPI NtAreMappedFilesTheSame(
        IN    PVOID Address1,
        IN    PVOID Address2
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAreMappedFilesTheSame"));
        return pfun(Address1, Address2);
    }

     EXPORT NTSTATUS NTAPI NtAssignProcessToJobObject(
        IN    HANDLE JobHandle,
        IN    HANDLE ProcessHandle
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtAssignProcessToJobObject"));
        return pfun(JobHandle, ProcessHandle);
    }

     EXPORT NTSTATUS NTAPI NtCallbackReturn(
        IN    PVOID Result OPTIONAL,
        IN    ULONG ResultLength,
        IN    NTSTATUS Status
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtCallbackReturn"));
        return pfun(Result, ResultLength, Status);
    }

     EXPORT NTSTATUS NTAPI NtCancelDeviceWakeupRequest(
        IN    HANDLE DeviceHandle
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtCancelDeviceWakeupRequest"));
        return pfun(DeviceHandle);
    }

     EXPORT NTSTATUS NTAPI NtCancelIoFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtCancelIoFile"));
        return pfun(FileHandle, IoStatusBlock);
    }

     EXPORT NTSTATUS NTAPI NtCancelTimer(
        IN    HANDLE TimerHandle,
        OUT    PBOOLEAN PreviousState OPTIONAL
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtCancelTimer"));
        return pfun(TimerHandle, PreviousState);
    }

     EXPORT NTSTATUS NTAPI NtClearEvent(
        IN    HANDLE EventHandle
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtClearEvent"));
        return pfun(EventHandle);
    }

     EXPORT NTSTATUS NTAPI NtClose(
        IN    HANDLE Handle
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtClose"));
        return pfun(Handle);
    }

     EXPORT NTSTATUS NTAPI NtCloseObjectAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    BOOLEAN GenerateOnClose
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtCloseObjectAuditAlarm"));
        return pfun(SubsystemName, HandleId, GenerateOnClose);
    }

     EXPORT NTSTATUS NTAPI NtCompactKeys(
        IN    ULONG Length,
        IN    HANDLE Key
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtCompactKeys"));
        return pfun(Length, Key);
    }

     EXPORT NTSTATUS NTAPI NtCompareTokens(
        IN    HANDLE FirstTokenHandle,
        IN    HANDLE SecondTokenHandle,
        OUT    PBOOLEAN IdenticalTokens
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtCompareTokens"));
        return pfun(FirstTokenHandle, SecondTokenHandle, IdenticalTokens);
    }

     EXPORT NTSTATUS NTAPI NtCompleteConnectPort(
        IN    HANDLE PortHandle
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtCompleteConnectPort"));
        return pfun(PortHandle);
    }

     EXPORT NTSTATUS NTAPI NtCompressKey(
        IN    HANDLE Key
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtCompressKey"));
        return pfun(Key);
    }

     EXPORT NTSTATUS NTAPI NtConnectPort(
        OUT    PHANDLE PortHandle,
        IN    PUNICODE_STRING PortName,
        IN    PSECURITY_QUALITY_OF_SERVICE SecurityQos,
        IN OUT    PLPC_SECTION_WRITE WriteSection OPTIONAL,
        IN OUT    PLPC_SECTION_READ ReadSection OPTIONAL,
        OUT    PULONG MaxMessageSize OPTIONAL,
        IN OUT    PVOID ConnectData OPTIONAL,
        IN OUT    PULONG ConnectDataLength OPTIONAL
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtConnectPort"));
        return pfun(PortHandle, PortName, SecurityQos, WriteSection, ReadSection, MaxMessageSize, ConnectData, ConnectDataLength);
    }

     EXPORT NTSTATUS NTAPI NtCreateDebugObject(
        OUT    PHANDLE DebugObject,
        IN    ULONG AccessRequired,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    BOOLEAN KillProcessOnExit
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateDebugObject"));
        return pfun(DebugObject, AccessRequired, ObjectAttributes, KillProcessOnExit);
    }

     EXPORT NTSTATUS NTAPI NtCreateDirectoryObject(
        OUT    PHANDLE DirectoryHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    ){
        static function<NTSTATUS> pfun = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateDirectoryObject"));
        return pfun(DirectoryHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtCreateEvent(
        OUT    PHANDLE EventHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    EVENT_TYPE EventType,
        IN    BOOLEAN InitialState
    ){
        static function<NTSTATUS> pNtCreateEvent = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateEvent"));
        return pNtCreateEvent(EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState);
    }

     EXPORT NTSTATUS NTAPI NtCreateEventPair(
        OUT    PHANDLE EventPairHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    ){
        static function<NTSTATUS> pNtCreateEventPair = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateEventPair"));
        return pNtCreateEventPair(EventPairHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtCreateFile(
        OUT    PHANDLE FileHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PLARGE_INTEGER AllocationSize OPTIONAL,
        IN    ULONG FileAttributes,
        IN    ULONG ShareAccess,
        IN    ULONG CreateDisposition,
        IN    ULONG CreateOptions,
        IN    PVOID EaBuffer OPTIONAL,
        IN    ULONG EaLength
    ){
        static function<NTSTATUS> pNtCreateFile = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateFile"));
        return pNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    }

     EXPORT NTSTATUS NTAPI NtCreateIoCompletion(
        OUT    PHANDLE IoCompletionHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    ULONG NumberOfConcurrentThreads
    ){
        static function<NTSTATUS> pNtCreateIoCompletion = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateIoCompletion"));
        return pNtCreateIoCompletion(IoCompletionHandle, DesiredAccess, ObjectAttributes, NumberOfConcurrentThreads);
    }

     EXPORT NTSTATUS NTAPI NtCreateJobObject(
        OUT    PHANDLE JobHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    ){
        static function<NTSTATUS> pNtCreateJobObject = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateJobObject"));
        return pNtCreateJobObject(JobHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtCreateJobSet(
        IN    ULONG Jobs,
        IN    PJOB_SET_ARRAY JobSet,
        IN    ULONG Reserved
    ){
        static function<NTSTATUS> pNtCreateJobSet = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateJobSet"));
        return pNtCreateJobSet(Jobs, JobSet, Reserved);
    }

     EXPORT NTSTATUS NTAPI NtCreateKey(
        OUT    PHANDLE KeyHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    ULONG TitleIndex,
        IN    PUNICODE_STRING Class OPTIONAL,
        IN    ULONG CreateOptions,
        OUT    PULONG Disposition OPTIONAL
    ){
        static function<NTSTATUS> pNtCreateKey = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateKey"));
        return pNtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
    }

     EXPORT NTSTATUS NTAPI NtCreateKeyedEvent(
        OUT    PHANDLE KeyedEventHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    ULONG Reserved
    ){
        static function<NTSTATUS> pNtCreateKeyedEvent = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateKeyedEvent"));
        return pNtCreateKeyedEvent(KeyedEventHandle, DesiredAccess, ObjectAttributes, Reserved);
    }

     EXPORT NTSTATUS NTAPI NtCreateMailslotFile(
        OUT    PHANDLE FileHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG CreateOptions,
        IN    ULONG InBufferSize,
        IN    ULONG MaxMessageSize,
        IN    PLARGE_INTEGER ReadTimeout OPTIONAL
    ){
        static function<NTSTATUS> pNtCreateMailslotFile = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateMailslotFile"));
        return pNtCreateMailslotFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, CreateOptions, InBufferSize, MaxMessageSize, ReadTimeout);
    }

     EXPORT NTSTATUS NTAPI NtCreateMutant(
        OUT    PHANDLE MutantHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN    BOOLEAN InitialOwner
    ){
        static function<NTSTATUS> pNtCreateMutant = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateMutant"));
        return pNtCreateMutant(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
    }

     EXPORT NTSTATUS NTAPI NtCreateNamedPipeFile(
        OUT    PHANDLE FileHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG ShareAccess,
        IN    ULONG CreateDisposition,
        IN    ULONG CreateOptions,
        IN    BOOLEAN TypeMessage,
        IN    BOOLEAN ReadmodeMessage,
        IN    BOOLEAN Nonblocking,
        IN    ULONG MaxInstances,
        IN    ULONG InBufferSize,
        IN    ULONG OutBufferSize,
        IN    PLARGE_INTEGER DefaultTimeout OPTIONAL
    ){
        static function<NTSTATUS> pNtCreateNamedPipeFile = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateNamedPipeFile"));
        return pNtCreateNamedPipeFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, TypeMessage, ReadmodeMessage, Nonblocking, MaxInstances, InBufferSize, OutBufferSize, DefaultTimeout);
    }

     EXPORT NTSTATUS NTAPI NtCreatePort(
        OUT    PHANDLE PortHandle,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    ULONG MaxConnectionInfoLength,
        IN    ULONG MaxMessageLength,
        IN    ULONG MaxPoolUsage
    ){
        static function<NTSTATUS> pNtCreatePort = (void*)GetFunctionByName(hNtdll, xor_str("NtCreatePort"));
        return pNtCreatePort(PortHandle, ObjectAttributes, MaxConnectionInfoLength, MaxMessageLength, MaxPoolUsage);
    }

     EXPORT NTSTATUS NTAPI NtCreateProcess(
        OUT    PHANDLE ProcessHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN    HANDLE ParentProcess,
        IN    BOOLEAN InheritObjectTable,
        IN    HANDLE SectionHandle OPTIONAL,
        IN    HANDLE DebugPort OPTIONAL,
        IN    HANDLE ExceptionPort OPTIONAL
    ){
        static function<NTSTATUS> pNtCreateProcess = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateProcess"));
        return pNtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
    }

     EXPORT NTSTATUS NTAPI NtCreateProcessEx(
        OUT    PHANDLE ProcessHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    HANDLE InheritFromProcessHandle,
        IN    ULONG CreateFlags,
        IN    HANDLE SectionHandle OPTIONAL,
        IN    HANDLE DebugObject OPTIONAL,
        IN    HANDLE ExceptionPort OPTIONAL,
        IN    ULONG JobMemberLevel
    ){
        static function<NTSTATUS> pNtCreateProcessEx = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateProcessEx"));
        return pNtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, InheritFromProcessHandle, CreateFlags, SectionHandle, DebugObject, ExceptionPort, JobMemberLevel);
    }

     EXPORT NTSTATUS NTAPI NtCreateProfile(
        OUT    PHANDLE ProfileHandle,
        IN    HANDLE ProcessHandle,
        IN    PVOID Base,
        IN    ULONG Size,
        IN    ULONG BucketShift,
        IN    PULONG Buffer,
        IN    ULONG BufferLength,
        IN    KPROFILE_SOURCE Source,
        IN    ULONG ProcessorMask
    ){
        static function<NTSTATUS> pNtCreateProfile = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateProfile"));
        return pNtCreateProfile(ProfileHandle, ProcessHandle, Base, Size, BucketShift, Buffer, BufferLength, Source, ProcessorMask);
    }

     EXPORT NTSTATUS NTAPI NtCreateSection(
        OUT    PHANDLE SectionHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    PLARGE_INTEGER SectionSize OPTIONAL,
        IN    ULONG Protect,
        IN    ULONG Attributes,
        IN    HANDLE FileHandle
    ){
        static function<NTSTATUS> pNtCreateSection = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateSection"));
        return pNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, SectionSize, Protect, Attributes, FileHandle);
    }

     EXPORT NTSTATUS NTAPI NtCreateSemaphore(
        OUT    PHANDLE SemaphoreHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN    ULONG InitialCount,
        IN    ULONG MaximumCount
    ){
        static function<NTSTATUS> pNtCreateSemaphore = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateSemaphore"));
        return pNtCreateSemaphore(SemaphoreHandle, DesiredAccess, ObjectAttributes, InitialCount, MaximumCount);
    }

     EXPORT NTSTATUS NTAPI NtCreateSymbolicLinkObject(
        OUT    PHANDLE SymbolicLinkHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    PUNICODE_STRING TargetName
    ){
        static function<NTSTATUS> pNtCreateSymbolicLinkObject = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateSymbolicLinkObject"));
        return pNtCreateSymbolicLinkObject(SymbolicLinkHandle, DesiredAccess, ObjectAttributes, TargetName);
    }


     EXPORT NTSTATUS NTAPI NtCreateToken(
        OUT    PHANDLE TokenHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    TOKEN_TYPE Type,
        IN    PLUID AuthenticationId,
        IN    PLARGE_INTEGER ExpirationTime,
        IN    PTOKEN_USER User,
        IN    PTOKEN_GROUPS Groups,
        IN    PTOKEN_PRIVILEGES Privileges,
        IN    PTOKEN_OWNER Owner,
        IN    PTOKEN_PRIMARY_GROUP PrimaryGroup,
        IN    PTOKEN_DEFAULT_DACL DefaultDacl,
        IN    PTOKEN_SOURCE Source
    ){
        static function<NTSTATUS> pNtCreateToken = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateToken"));
        return pNtCreateToken(TokenHandle, DesiredAccess, ObjectAttributes, Type, AuthenticationId, ExpirationTime, User, Groups, Privileges, Owner, PrimaryGroup, DefaultDacl, Source);
    }

     EXPORT NTSTATUS NTAPI NtCreateWaitablePort(
        OUT    PHANDLE PortHandle,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    ULONG MaxConnectionInfoLength,
        IN    ULONG MaxMessageLength,
        IN    ULONG MaxPoolUsage
    ){
        static function<NTSTATUS> pNtCreateWaitablePort = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateWaitablePort"));
        return pNtCreateWaitablePort(PortHandle, ObjectAttributes, MaxConnectionInfoLength, MaxMessageLength, MaxPoolUsage);
    }

     EXPORT NTSTATUS NTAPI NtDebugActiveProcess(
        IN    HANDLE Process,
        IN    HANDLE DebugObject
    ){
        static function<NTSTATUS> pNtDebugActiveProcess = (void*)GetFunctionByName(hNtdll, xor_str("NtDebugActiveProcess"));
        return pNtDebugActiveProcess(Process, DebugObject);
    }

     EXPORT NTSTATUS NTAPI NtDebugContinue(
        IN    HANDLE DebugObject,
        IN    PCLIENT_ID AppClientId,
        IN    NTSTATUS ContinueStatus
    ){
        static function<NTSTATUS> pNtDebugContinue = (void*)GetFunctionByName(hNtdll, xor_str("NtDebugContinue"));
        return pNtDebugContinue(DebugObject, AppClientId, ContinueStatus);
    }

     EXPORT NTSTATUS NTAPI NtDelayExecution(
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER DelayInterval
    ){
        static function<NTSTATUS> pNtDelayExecution = (void*)GetFunctionByName(hNtdll, xor_str("NtDelayExecution"));
        return pNtDelayExecution(Alertable, DelayInterval);
    }

     EXPORT NTSTATUS NTAPI NtDeleteAtom(
        IN    USHORT Atom
    ){
        static function<NTSTATUS> pNtDeleteAtom = (void*)GetFunctionByName(hNtdll, xor_str("NtDeleteAtom"));
        return pNtDeleteAtom(Atom);
    }

     EXPORT NTSTATUS NTAPI NtDeleteBootEntry(
        IN    PUNICODE_STRING EntryName,
        IN    PUNICODE_STRING EntryValue
    ){
        static function<NTSTATUS> pNtDeleteBootEntry = (void*)GetFunctionByName(hNtdll, xor_str("NtDeleteBootEntry"));
        return pNtDeleteBootEntry(EntryName, EntryValue);
    }

     EXPORT NTSTATUS NTAPI NtDeleteDriverEntry(
        IN    PUNICODE_STRING DriverName,
        IN    PUNICODE_STRING DriverPath
    ){
        static function<NTSTATUS> pNtDeleteDriverEntry = (void*)GetFunctionByName(hNtdll, xor_str("NtDeleteDriverEntry"));
        return pNtDeleteDriverEntry(DriverName, DriverPath);
    }

     EXPORT NTSTATUS NTAPI NtDeleteFile(
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    ){
        static function<NTSTATUS> pNtDeleteFile = (void*)GetFunctionByName(hNtdll, xor_str("NtDeleteFile"));
        return pNtDeleteFile(ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtDeleteKey(
        IN    HANDLE KeyHandle
    ){
        static function<NTSTATUS> pNtDeleteKey = (void*)GetFunctionByName(hNtdll, xor_str("NtDeleteKey"));     
        return pNtDeleteKey(KeyHandle);
    }

     EXPORT NTSTATUS NTAPI NtDeleteObjectAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    BOOLEAN GenerateOnClose
    ){
        static function<NTSTATUS> pNtDeleteObjectAuditAlarm = (void*)GetFunctionByName(hNtdll, xor_str("NtDeleteObjectAuditAlarm"));
        return pNtDeleteObjectAuditAlarm(SubsystemName, HandleId, GenerateOnClose);
    }

     EXPORT NTSTATUS NTAPI NtDeleteValueKey(
        IN    HANDLE KeyHandle,
        IN    PUNICODE_STRING ValueName
    ){
        static function<NTSTATUS> pNtDeleteValueKey = (void*)GetFunctionByName(hNtdll, xor_str("NtDeleteValueKey"));
        return pNtDeleteValueKey(KeyHandle, ValueName);
    }

     EXPORT NTSTATUS NTAPI NtDeviceIoControlFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG IoControlCode,
        IN    PVOID InputBuffer OPTIONAL,
        IN    ULONG InputBufferLength,
        OUT    PVOID OutputBuffer OPTIONAL,
        IN    ULONG OutputBufferLength
    ){
        static function<NTSTATUS> pNtDeviceIoControlFile = (void*)GetFunctionByName(hNtdll, xor_str("NtDeviceIoControlFile"));
        return pNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
    }

     EXPORT NTSTATUS NTAPI NtDisplayString(
        IN    PUNICODE_STRING String
    ){
        static function<NTSTATUS> pNtDisplayString = (void*)GetFunctionByName(hNtdll, xor_str("NtDisplayString"));
        return pNtDisplayString(String);
    }

     EXPORT NTSTATUS NTAPI NtDuplicateObject(
        IN    HANDLE SourceProcessHandle,
        IN    HANDLE SourceHandle,
        IN    HANDLE TargetProcessHandle OPTIONAL,
        OUT    PHANDLE TargetHandle OPTIONAL,
        IN    ACCESS_MASK DesiredAccess,
        IN    ULONG HandleAttributes,
        IN    ULONG Options
    ){
        static function<NTSTATUS> pNtDuplicateObject = (void*)GetFunctionByName(hNtdll, xor_str("NtDuplicateObject"));
        return pNtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
    }

     EXPORT NTSTATUS NTAPI NtDuplicateToken(
        IN    HANDLE ExistingTokenHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    BOOLEAN EffectiveOnly,
        IN    TOKEN_TYPE TokenType,
        OUT    PHANDLE NewTokenHandle
    ){
        static function<NTSTATUS> pNtDuplicateToken = (void*)GetFunctionByName(hNtdll, xor_str("NtDuplicateToken"));
        return pNtDuplicateToken(ExistingTokenHandle, DesiredAccess, ObjectAttributes, EffectiveOnly, TokenType, NewTokenHandle);
    }

     EXPORT NTSTATUS NTAPI NtEnumerateBootEntries(
        IN    ULONG Unknown1,
        IN    ULONG Unknown2
    ){
        static function<NTSTATUS> pNtEnumerateBootEntries = (void*)GetFunctionByName(hNtdll, xor_str("NtEnumerateBootEntries"));
        return pNtEnumerateBootEntries(Unknown1, Unknown2);
    }
     EXPORT NTSTATUS NTAPI NtEnumerateKey(
        IN    HANDLE KeyHandle,
        IN    ULONG Index,
        IN    KEY_INFORMATION_CLASS KeyInformationClass,
        OUT    PVOID KeyInformation,
        IN    ULONG KeyInformationLength,
        OUT    PULONG ResultLength
    ){
        static function<NTSTATUS> pNtEnumerateKey = (void*)GetFunctionByName(hNtdll, xor_str("NtEnumerateKey"));
        return pNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, KeyInformationLength, ResultLength);
    }

     EXPORT NTSTATUS NTAPI NtEnumerateSystemEnvironmentValuesEx(
        IN    ULONG Unknown1,
        IN    ULONG Unknown2,
        IN    ULONG Unknown3
    ){
         static function<NTSTATUS> pNtEnumerateSystemEnvironmentValuesEx = (void*)GetFunctionByName(hNtdll, xor_str("NtEnumerateSystemEnvironmentValuesEx"));
        return pNtEnumerateSystemEnvironmentValuesEx(Unknown1, Unknown2, Unknown3);
    }

     EXPORT NTSTATUS NTAPI NtEnumerateValueKey(
        IN    HANDLE KeyHandle,
        IN    ULONG Index,
        IN    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
        OUT    PVOID KeyValueInformation,
        IN    ULONG KeyValueInformationLength,
        OUT    PULONG ResultLength
    ){
        static function<NTSTATUS> pNtEnumerateValueKey = (void*)GetFunctionByName(hNtdll, xor_str("NtEnumerateValueKey"));
        return pNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, KeyValueInformationLength, ResultLength);
    }

     EXPORT NTSTATUS NTAPI NtExtendSection(
        IN    HANDLE SectionHandle,
        IN    PLARGE_INTEGER SectionSize
    ){
        static function<NTSTATUS> pNtExtendSection = (void*)GetFunctionByName(hNtdll, xor_str("NtExtendSection"));
        return pNtExtendSection(SectionHandle, SectionSize);
    }

     EXPORT NTSTATUS NTAPI NtFilterToken(
        IN    HANDLE ExistingTokenHandle,
        IN    ULONG Flags,
        IN    PTOKEN_GROUPS SidsToDisable,
        IN    PTOKEN_PRIVILEGES PrivilegesToDelete,
        IN    PTOKEN_GROUPS SidsToRestricted,
        OUT    PHANDLE NewTokenHandle
    ){
        static function<NTSTATUS> pNtFilterToken = (void*)GetFunctionByName(hNtdll, xor_str("NtFilterToken"));
        return pNtFilterToken(ExistingTokenHandle, Flags, SidsToDisable, PrivilegesToDelete, SidsToRestricted, NewTokenHandle);
    }

     EXPORT NTSTATUS NTAPI NtFindAtom(
        IN    PWSTR String,
        IN    ULONG StringLength,
        OUT    PUSHORT Atom
    ){
        static function<NTSTATUS> pNtFindAtom = (void*)GetFunctionByName(hNtdll, xor_str("NtFindAtom"));
        return pNtFindAtom(String, StringLength, Atom);
    }

     EXPORT NTSTATUS NTAPI NtFlushBuffersFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock
    ){
        static function<NTSTATUS> pNtFlushBuffersFile = (void*)GetFunctionByName(hNtdll, xor_str("NtFlushBuffersFile"));
        return pNtFlushBuffersFile(FileHandle, IoStatusBlock);
    }

     EXPORT NTSTATUS NTAPI NtFlushInstructionCache(
        IN    HANDLE ProcessHandle,
        IN    PVOID BaseAddress OPTIONAL,
        IN    ULONG FlushSize
    ){
        static function<NTSTATUS> pNtFlushInstructionCache = (void*)GetFunctionByName(hNtdll, xor_str("NtFlushInstructionCache"));
        return pNtFlushInstructionCache(ProcessHandle, BaseAddress, FlushSize);
    }

     EXPORT NTSTATUS NTAPI NtFlushKey(
        IN    HANDLE KeyHandle
    ){
        static function<NTSTATUS> pNtFlushKey = (void*)GetFunctionByName(hNtdll, xor_str("NtFlushKey"));
        return pNtFlushKey(KeyHandle);
    }

     EXPORT NTSTATUS NTAPI NtFlushVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN OUT    PULONG FlushSize,
        OUT    PIO_STATUS_BLOCK IoStatusBlock
    ){
        static function<NTSTATUS> pNtFlushVirtualMemory = (void*)GetFunctionByName(hNtdll, xor_str("NtFlushVirtualMemory"));
        return pNtFlushVirtualMemory(ProcessHandle, BaseAddress, FlushSize, IoStatusBlock);
    }

     EXPORT NTSTATUS NTAPI NtFlushWriteBuffer(
        VOID
    ){
        static function<NTSTATUS> pNtFlushWriteBuffer = (void*)GetFunctionByName(hNtdll, xor_str("NtFlushWriteBuffer"));
        return pNtFlushWriteBuffer();
    }

     EXPORT NTSTATUS NTAPI NtYieldExecution(
        VOID
    ){
        static function<NTSTATUS> pNtYieldExecution = (void*)GetFunctionByName(hNtdll, xor_str("NtYieldExecution"));
        return pNtYieldExecution();
    }

     EXPORT NTSTATUS NTAPI NtWriteVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN    PVOID BaseAddress,
        IN    PVOID Buffer,
        IN    ULONG BufferLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtWriteVirtualMemory = (void*)GetFunctionByName(hNtdll, xor_str("NtWriteVirtualMemory"));
        return pNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtWriteRequestData(
        IN    HANDLE PortHandle,
        IN    PPORT_MESSAGE Message,
        IN    ULONG Index,
        IN    PVOID Buffer,
        IN    ULONG BufferLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtWriteRequestData = (void*)GetFunctionByName(hNtdll, xor_str("NtWriteRequestData"));
        return pNtWriteRequestData(PortHandle, Message, Index, Buffer, BufferLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtWriteFileGather(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PFILE_SEGMENT_ELEMENT Buffer,
        IN    ULONG Length,
        IN    PLARGE_INTEGER ByteOffset OPTIONAL,
        IN    PULONG Key OPTIONAL
    ){
        static function<NTSTATUS> pNtWriteFileGather = (void*)GetFunctionByName(hNtdll, xor_str("NtWriteFileGather"));
        return pNtWriteFileGather(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }

     EXPORT NTSTATUS NTAPI NtWriteFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PVOID Buffer,
        IN    ULONG Length,
        IN    PLARGE_INTEGER ByteOffset OPTIONAL,
        IN    PULONG Key OPTIONAL
    ){
        static function<NTSTATUS> pNtWriteFile = (void*)GetFunctionByName(hNtdll, xor_str("NtWriteFile"));
        return pNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }

     EXPORT NTSTATUS NTAPI NtWaitLowEventPair(
        IN    HANDLE EventPairHandle
    ){
        static function<NTSTATUS> pNtWaitLowEventPair = (void*)GetFunctionByName(hNtdll, xor_str("NtWaitLowEventPair"));
        return pNtWaitLowEventPair(EventPairHandle);
    }

     EXPORT NTSTATUS NTAPI NtWaitHighEventPair(
        IN    HANDLE EventPairHandle
    ){
        static function<NTSTATUS> pNtWaitHighEventPair = (void*)GetFunctionByName(hNtdll, xor_str("NtWaitHighEventPair"));
        return pNtWaitHighEventPair(EventPairHandle);
    }

     EXPORT NTSTATUS NTAPI NtWaitForSingleObject(
        IN    HANDLE Handle,
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    ){
        static function<NTSTATUS> pNtWaitForSingleObject = (void*)GetFunctionByName(hNtdll, xor_str("NtWaitForSingleObject"));
        return pNtWaitForSingleObject(Handle, Alertable, Timeout);
    }

     EXPORT NTSTATUS NTAPI NtWaitForMultipleObjects32(
        IN    ULONG HandleCount,
        IN    PHANDLE Handles,
        IN    WAIT_TYPE WaitType,
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    ){
        static function<NTSTATUS> pNtWaitForMultipleObjects32 = (void*)GetFunctionByName(hNtdll, xor_str("NtWaitForMultipleObjects32"));
        return pNtWaitForMultipleObjects32(HandleCount, Handles, WaitType, Alertable, Timeout);
    }

     EXPORT NTSTATUS NTAPI NtWaitForMultipleObjects(
        IN    ULONG HandleCount,
        IN    PHANDLE Handles,
        IN    WAIT_TYPE WaitType,
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    ){
        static function<NTSTATUS> pNtWaitForMultipleObjects = (void*)GetFunctionByName(hNtdll, xor_str("NtWaitForMultipleObjects"));
        return pNtWaitForMultipleObjects(HandleCount, Handles, WaitType, Alertable, Timeout);
    }

     EXPORT NTSTATUS NTAPI NtWaitForKeyedEvent(
        IN    HANDLE KeyedEventHandle,
        IN    PVOID Key,
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    ){
        static function<NTSTATUS> pNtWaitForKeyedEvent = (void*)GetFunctionByName(hNtdll, xor_str("NtWaitForKeyedEvent"));
        return pNtWaitForKeyedEvent(KeyedEventHandle, Key, Alertable, Timeout);
    }

     EXPORT NTSTATUS NTAPI NtUnmapViewOfSection(
        IN    HANDLE ProcessHandle,
        IN    PVOID BaseAddress
    ){
        static function<NTSTATUS> pNtUnmapViewOfSection = (void*)GetFunctionByName(hNtdll, xor_str("NtUnmapViewOfSection"));
        return pNtUnmapViewOfSection(ProcessHandle, BaseAddress);
    }

     EXPORT NTSTATUS NTAPI NtUnlockVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN OUT    PULONG LockSize,
        IN    ULONG LockType
    ){
        static function<NTSTATUS> pNtUnlockVirtualMemory = (void*)GetFunctionByName(hNtdll, xor_str("NtUnlockVirtualMemory"));
        return pNtUnlockVirtualMemory(ProcessHandle, BaseAddress, LockSize, LockType);
    }

     EXPORT NTSTATUS NTAPI NtUnlockFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PULARGE_INTEGER LockOffset,
        IN    PULARGE_INTEGER LockLength,
        IN    ULONG Key
    ){
        static function<NTSTATUS> pNtUnlockFile = (void*)GetFunctionByName(hNtdll, xor_str("NtUnlockFile"));
        return pNtUnlockFile(FileHandle, IoStatusBlock, LockOffset, LockLength, Key);
    }

     EXPORT NTSTATUS NTAPI NtUnloadKeyEx(
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes,
        IN    HANDLE EventHandle OPTIONAL
    ){
        static function<NTSTATUS> pNtUnloadKeyEx = (void*)GetFunctionByName(hNtdll, xor_str("NtUnloadKeyEx"));
        return pNtUnloadKeyEx(KeyObjectAttributes, EventHandle);
    }

     EXPORT NTSTATUS NTAPI NtUnloadKey2(
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes,
        IN    BOOLEAN ForceUnload
    ){
        static function<NTSTATUS> pNtUnloadKey2 = (void*)GetFunctionByName(hNtdll, xor_str("NtUnloadKey2"));
        return pNtUnloadKey2(KeyObjectAttributes, ForceUnload);
    }

     EXPORT NTSTATUS NTAPI NtUnloadKey(
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes
    ){
        static function<NTSTATUS> pNtUnloadKey = (void*)GetFunctionByName(hNtdll, xor_str("NtUnloadKey"));
        return pNtUnloadKey(KeyObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtUnloadDriver(
        IN    PUNICODE_STRING DriverServiceName
    ){
        static function<NTSTATUS> pNtUnloadDriver = (void*)GetFunctionByName(hNtdll, xor_str("NtUnloadDriver"));
        return pNtUnloadDriver(DriverServiceName);
    }

     EXPORT NTSTATUS NTAPI NtTerminateThread(
        IN    HANDLE ThreadHandle OPTIONAL,
        IN    NTSTATUS ExitStatus
    ){
        static function<NTSTATUS> pNtTerminateThread = (void*)GetFunctionByName(hNtdll, xor_str("NtTerminateThread"));
        return pNtTerminateThread(ThreadHandle, ExitStatus);
    }

     EXPORT NTSTATUS NTAPI NtTerminateProcess(
        IN    HANDLE ProcessHandle OPTIONAL,
        IN    NTSTATUS ExitStatus
    ){
        static function<NTSTATUS> pNtTerminateProcess = (void*)GetFunctionByName(hNtdll, xor_str("NtTerminateProcess"));
        return pNtTerminateProcess(ProcessHandle, ExitStatus);
    }

     EXPORT NTSTATUS NTAPI NtTerminateJobObject(
        IN    HANDLE JobHandle,
        IN    NTSTATUS ExitStatus
    ){
        static function<NTSTATUS> pNtTerminateJobObject = (void*)GetFunctionByName(hNtdll, xor_str("NtTerminateJobObject"));
        return pNtTerminateJobObject(JobHandle, ExitStatus);
    }

     EXPORT NTSTATUS NTAPI NtSystemDebugControl(
        IN    DEBUG_CONTROL_CODE ControlCode,
        IN    PVOID InputBuffer OPTIONAL,
        IN    ULONG InputBufferLength,
        OUT    PVOID OutputBuffer OPTIONAL,
        IN    ULONG OutputBufferLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtSystemDebugControl = (void*)GetFunctionByName(hNtdll, xor_str("NtSystemDebugControl"));
        return pNtSystemDebugControl(ControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtSuspendThread(
        IN    HANDLE ThreadHandle,
        OUT    PULONG PreviousSuspendCount OPTIONAL
    ){
        static function<NTSTATUS> pNtSuspendThread = (void*)GetFunctionByName(hNtdll, xor_str("NtSuspendThread"));
        return pNtSuspendThread(ThreadHandle, PreviousSuspendCount);
    }

     EXPORT NTSTATUS NTAPI NtSuspendProcess(
        IN    HANDLE Process
    ){
        static function<NTSTATUS> pNtSuspendProcess = (void*)GetFunctionByName(hNtdll, xor_str("NtSuspendProcess"));
        return pNtSuspendProcess(Process);
    }

     EXPORT NTSTATUS NTAPI NtStopProfile(
        IN    HANDLE ProfileHandle
    ){
        static function<NTSTATUS> pNtStopProfile = (void*)GetFunctionByName(hNtdll, xor_str("NtStopProfile"));
        return pNtStopProfile(ProfileHandle);
    }
     EXPORT NTSTATUS NTAPI NtStartProfile(
        IN    HANDLE ProfileHandle
    ){
        static function<NTSTATUS> pNtStartProfile = (void*)GetFunctionByName(hNtdll, xor_str("NtStartProfile"));
        return pNtStartProfile(ProfileHandle);
    }

     EXPORT NTSTATUS NTAPI NtSignalAndWaitForSingleObject(
        IN    HANDLE HandleToSignal,
        IN    HANDLE HandleToWait,
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    ){
        static function<NTSTATUS> pNtSignalAndWaitForSingleObject = (void*)GetFunctionByName(hNtdll, xor_str("NtSignalAndWaitForSingleObject"));
        return pNtSignalAndWaitForSingleObject(HandleToSignal, HandleToWait, Alertable, Timeout);
    }

     EXPORT NTSTATUS NTAPI NtShutdownSystem(
        IN    SHUTDOWN_ACTION Action
    ){
        static function<NTSTATUS> pNtShutdownSystem = (void*)GetFunctionByName(hNtdll, xor_str("NtShutdownSystem"));
        return pNtShutdownSystem(Action);
    }

     EXPORT NTSTATUS NTAPI NtSetVolumeInformationFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PVOID Buffer,
        IN    ULONG BufferLength,
        IN    FS_INFORMATION_CLASS VolumeInformationClass
    ){
        static function<NTSTATUS> pNtSetVolumeInformationFile = (void*)GetFunctionByName(hNtdll, xor_str("NtSetVolumeInformationFile"));
        return pNtSetVolumeInformationFile(FileHandle, IoStatusBlock, Buffer, BufferLength, VolumeInformationClass);
    }

     EXPORT NTSTATUS NTAPI NtSetValueKey(
        IN    HANDLE KeyHandle,
        IN    PUNICODE_STRING ValueName,
        IN    ULONG TitleIndex OPTIONAL,
        IN    ULONG Type,
        IN    PVOID Data,
        IN    ULONG DataSize
    ){
        static function<NTSTATUS> pNtSetValueKey = (void*)GetFunctionByName(hNtdll, xor_str("NtSetValueKey"));
        return pNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
    }

     EXPORT NTSTATUS NTAPI NtSetUuidSeed(
        IN    PUCHAR UuidSeed
    ){
        static function<NTSTATUS> pNtSetUuidSeed = (void*)GetFunctionByName(hNtdll, xor_str("NtSetUuidSeed"));
        return pNtSetUuidSeed(UuidSeed);
    }

     EXPORT NTSTATUS NTAPI NtSetTimerResolution(
        IN    ULONG RequestedResolution,
        IN    BOOLEAN Set,
        OUT    PULONG ActualResolution
    ){
        static function<NTSTATUS> pNtSetTimerResolution = (void*)GetFunctionByName(hNtdll, xor_str("NtSetTimerResolution"));
        return pNtSetTimerResolution(RequestedResolution, Set, ActualResolution);
    }

     EXPORT NTSTATUS NTAPI NtSetThreadExecutionState(
        IN    EXECUTION_STATE ExecutionState,
        OUT    PEXECUTION_STATE PreviousExecutionState
    ){
        static function<NTSTATUS> pNtSetThreadExecutionState = (void*)GetFunctionByName(hNtdll, xor_str("NtSetThreadExecutionState"));
        return pNtSetThreadExecutionState(ExecutionState, PreviousExecutionState);
    }

     EXPORT NTSTATUS NTAPI NtSetSystemTime(
        IN    PLARGE_INTEGER NewTime,
        OUT    PLARGE_INTEGER OldTime OPTIONAL
    ){
        static function<NTSTATUS> pNtSetSystemTime = (void*)GetFunctionByName(hNtdll, xor_str("NtSetSystemTime"));
        return pNtSetSystemTime(NewTime, OldTime);
    }

     EXPORT NTSTATUS NTAPI NtSetSystemPowerState(
        IN    POWER_ACTION SystemAction,
        IN    SYSTEM_POWER_STATE MinSystemState,
        IN    ULONG Flags
    ){
        static function<NTSTATUS> pNtSetSystemPowerState = (void*)GetFunctionByName(hNtdll, xor_str("NtSetSystemPowerState"));
        return pNtSetSystemPowerState(SystemAction, MinSystemState, Flags);
    }

     EXPORT NTSTATUS NTAPI NtSetSystemInformation(
        IN    SYSTEM_INFORMATION_CLASS SystemInformationClass,
        IN OUT    PVOID SystemInformation,
        IN    ULONG SystemInformationLength
    ){
        static function<NTSTATUS> pNtSetSystemInformation = (void*)GetFunctionByName(hNtdll, xor_str("NtSetSystemInformation"));
        return pNtSetSystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength);
    }

     EXPORT NTSTATUS NTAPI NtSetSystemEnvironmentValue(
        IN    PUNICODE_STRING Name,
        IN    PUNICODE_STRING Value
    ){
        static function<NTSTATUS> pNtSetSystemEnvironmentValue = (void*)GetFunctionByName(hNtdll, xor_str("NtSetSystemEnvironmentValue"));
        return pNtSetSystemEnvironmentValue(Name, Value);
    }

     EXPORT NTSTATUS NTAPI NtSetSecurityObject(
        IN    HANDLE Handle,
        IN    SECURITY_INFORMATION SecurityInformation,
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor
    ){
        static function<NTSTATUS> pNtSetSecurityObject = (void*)GetFunctionByName(hNtdll, xor_str("NtSetSecurityObject"));
        return pNtSetSecurityObject(Handle, SecurityInformation, SecurityDescriptor);
    }

     EXPORT NTSTATUS NTAPI NtSetLowWaitHighEventPair(
        IN    HANDLE EventPairHandle
    ){
        static function<NTSTATUS> pNtSetLowWaitHighEventPair = (void*)GetFunctionByName(hNtdll, xor_str("NtSetLowWaitHighEventPair"));
        return pNtSetLowWaitHighEventPair(EventPairHandle);
    }

     EXPORT NTSTATUS NTAPI NtSetLowEventPair(
        IN    HANDLE EventPairHandle
    ){
        static function<NTSTATUS> pNtSetLowEventPair = (void*)GetFunctionByName(hNtdll, xor_str("NtSetLowEventPair"));
        return pNtSetLowEventPair(EventPairHandle);
    }

     EXPORT NTSTATUS NTAPI NtSetLdtEntries(
        IN    ULONG Selector1,
        IN    LDT_ENTRY LdtEntry1,
        IN    ULONG Selector2,
        IN    LDT_ENTRY LdtEntry2
    ){
        static function<NTSTATUS> pNtSetLdtEntries = (void*)GetFunctionByName(hNtdll, xor_str("NtSetLdtEntries"));
        return pNtSetLdtEntries(Selector1, LdtEntry1, Selector2, LdtEntry2);
    }

     EXPORT NTSTATUS NTAPI NtSetIoCompletion(
        IN    HANDLE IoCompletionHandle,
        IN    ULONG CompletionKey,
        IN    ULONG CompletionValue,
        IN    NTSTATUS Status,
        IN    ULONG Information
    ){
        static function<NTSTATUS> pNtSetIoCompletion = (void*)GetFunctionByName(hNtdll, xor_str("NtSetIoCompletion"));
        return pNtSetIoCompletion(IoCompletionHandle, CompletionKey, CompletionValue, Status, Information);
    }

     EXPORT NTSTATUS NTAPI NtSetIntervalProfile(
        IN    ULONG Interval,
        IN    KPROFILE_SOURCE Source
    ){
        static function<NTSTATUS> pNtSetIntervalProfile = (void*)GetFunctionByName(hNtdll, xor_str("NtSetIntervalProfile"));
        return pNtSetIntervalProfile(Interval, Source);
    }

     EXPORT NTSTATUS NTAPI NtSetInformationToken(
        IN    HANDLE TokenHandle,
        IN    TOKEN_INFORMATION_CLASS TokenInformationClass,
        IN    PVOID TokenInformation,
        IN    ULONG TokenInformationLength
    ){
        static function<NTSTATUS> pNtSetInformationToken = (void*)GetFunctionByName(hNtdll, xor_str("NtSetInformationToken"));
        return pNtSetInformationToken(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength);
    }

     EXPORT NTSTATUS NTAPI NtSetInformationThread(
        IN    HANDLE ThreadHandle,
        IN    THREADINFOCLASS ThreadInformationClass,
        IN    PVOID ThreadInformation,
        IN    ULONG ThreadInformationLength
    ){
        static function<NTSTATUS> pNtSetInformationThread = (void*)GetFunctionByName(hNtdll, xor_str("NtSetInformationThread"));
        return pNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
    }

     EXPORT NTSTATUS NTAPI NtSetInformationProcess(
        IN    HANDLE ProcessHandle,
        IN    PROCESSINFOCLASS ProcessInformationClass,
        IN    PVOID ProcessInformation,
        IN    ULONG ProcessInformationLength
    ){
        static function<NTSTATUS> pNtSetInformationProcess = (void*)GetFunctionByName(hNtdll, xor_str("NtSetInformationProcess"));
        return pNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
    }

     EXPORT NTSTATUS NTAPI NtSetInformationObject(
        IN    HANDLE ObjectHandle,
        IN    OBJECT_INFORMATION_CLASS ObjectInformationClass,
        IN    PVOID ObjectInformation,
        IN    ULONG ObjectInformationLength
    ){
        static function<NTSTATUS> pNtSetInformationObject = (void*)GetFunctionByName(hNtdll, xor_str("NtSetInformationObject"));
        return pNtSetInformationObject(ObjectHandle, ObjectInformationClass, ObjectInformation, ObjectInformationLength);
    }

     EXPORT NTSTATUS NTAPI NtSetInformationKey(
        IN    HANDLE KeyHandle,
        IN    KEY_SET_INFORMATION_CLASS KeyInformationClass,
        IN    PVOID KeyInformation,
        IN    ULONG KeyInformationLength
    ){
        static function<NTSTATUS> pNtSetInformationKey = (void*)GetFunctionByName(hNtdll, xor_str("NtSetInformationKey"));
        return pNtSetInformationKey(KeyHandle, KeyInformationClass, KeyInformation, KeyInformationLength);
    }

     EXPORT NTSTATUS NTAPI NtSetInformationJobObject(
        IN    HANDLE JobHandle,
        IN    JOBOBJECTINFOCLASS JobInformationClass,
        IN    PVOID JobInformation,
        IN    ULONG JobInformationLength
    ){
        static function<NTSTATUS> pNtSetInformationJobObject = (void*)GetFunctionByName(hNtdll, xor_str("NtSetInformationJobObject"));
        return pNtSetInformationJobObject(JobHandle, JobInformationClass, JobInformation, JobInformationLength);
    }

     EXPORT NTSTATUS NTAPI NtSetInformationFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PVOID FileInformation,
        IN    ULONG FileInformationLength,
        IN    FILE_INFORMATION_CLASS FileInformationClass
    ){
        static function<NTSTATUS> pNtSetInformationFile = (void*)GetFunctionByName(hNtdll, xor_str("NtSetInformationFile"));
        return pNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, FileInformationLength, FileInformationClass);
    }

     EXPORT NTSTATUS NTAPI NtSetHighWaitLowEventPair(
        IN    HANDLE EventPairHandle
    ){
        static function<NTSTATUS> pNtSetHighWaitLowEventPair = (void*)GetFunctionByName(hNtdll, xor_str("NtSetHighWaitLowEventPair"));
        return pNtSetHighWaitLowEventPair(EventPairHandle);
    }

     EXPORT NTSTATUS NTAPI NtSetHighEventPair(
        IN    HANDLE EventPairHandle
    ){
        static function<NTSTATUS> pNtSetHighEventPair = (void*)GetFunctionByName(hNtdll, xor_str("NtSetHighEventPair"));
        return pNtSetHighEventPair(EventPairHandle);
    }

     EXPORT NTSTATUS NTAPI NtSetEventBoostPriority(
        IN    HANDLE EventHandle
    ){
        static function<NTSTATUS> pNtSetEventBoostPriority = (void*)GetFunctionByName(hNtdll, xor_str("NtSetEventBoostPriority"));
        return pNtSetEventBoostPriority(EventHandle);
    }

     EXPORT NTSTATUS NTAPI NtSetEvent(
        IN    HANDLE EventHandle,
        OUT    PULONG PreviousState OPTIONAL
    ){
        static function<NTSTATUS> pNtSetEvent = (void*)GetFunctionByName(hNtdll, xor_str("NtSetEvent"));
        return pNtSetEvent(EventHandle, PreviousState);
    }

     EXPORT NTSTATUS NTAPI NtSetEaFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PFILE_FULL_EA_INFORMATION Buffer,
        IN    ULONG BufferLength
    ){
        static function<NTSTATUS> pNtSetEaFile = (void*)GetFunctionByName(hNtdll, xor_str("NtSetEaFile"));
        return pNtSetEaFile(FileHandle, IoStatusBlock, Buffer, BufferLength);
    }

     EXPORT NTSTATUS NTAPI NtSetDefaultUILanguage(
        IN    LANGID LanguageId
    ){
        static function<NTSTATUS> pNtSetDefaultUILanguage = (void*)GetFunctionByName(hNtdll, xor_str("NtSetDefaultUILanguage"));
        return pNtSetDefaultUILanguage(LanguageId);
    }

     EXPORT NTSTATUS NTAPI NtSetDefaultLocale(
        IN    BOOLEAN ThreadOrSystem,
        IN    LCID Locale
    ){
        static function<NTSTATUS> pNtSetDefaultLocale = (void*)GetFunctionByName(hNtdll, xor_str("NtSetDefaultLocale"));
        return pNtSetDefaultLocale(ThreadOrSystem, Locale);
    }

     EXPORT NTSTATUS NTAPI NtSetDefaultHardErrorPort(
        IN    HANDLE PortHandle
    ){
        static function<NTSTATUS> pNtSetDefaultHardErrorPort = (void*)GetFunctionByName(hNtdll, xor_str("NtSetDefaultHardErrorPort"));
        return pNtSetDefaultHardErrorPort(PortHandle);
    }

     EXPORT NTSTATUS NTAPI NtSetDebugFilterState(
        IN    ULONG ComponentId,
        IN    ULONG Level,
        IN    BOOLEAN Enable
    ){
        static function<NTSTATUS> pNtSetDebugFilterState = (void*)GetFunctionByName(hNtdll, xor_str("NtSetDebugFilterState"));
        return pNtSetDebugFilterState(ComponentId, Level, Enable);
    }
     EXPORT NTSTATUS NTAPI NtSetContextChannel(
        IN    HANDLE CHannelHandle
    ){
        static function<NTSTATUS> pNtSetContextChannel = (void*)GetFunctionByName(hNtdll, xor_str("NtSetContextChannel"));
        return pNtSetContextChannel(CHannelHandle);
    }

     EXPORT NTSTATUS NTAPI NtSetBootEntryOrder(
        IN    ULONG Unknown1,
        IN    ULONG Unknown2
    ){
        static function<NTSTATUS> pNtSetBootEntryOrder = (void*)GetFunctionByName(hNtdll, xor_str("NtSetBootEntryOrder"));
        return pNtSetBootEntryOrder(Unknown1, Unknown2);
    }

     EXPORT NTSTATUS NTAPI NtSecureConnectPort(
        OUT    PHANDLE PortHandle,
        IN    PUNICODE_STRING PortName,
        IN    PSECURITY_QUALITY_OF_SERVICE SecurityQos,
        IN OUT    PPORT_VIEW ClientView OPTIONAL,
        IN    PSID ServerSid OPTIONAL,
        OUT    PREMOTE_PORT_VIEW ServerView OPTIONAL,
        OUT    PULONG MaxMessageLength OPTIONAL,
        IN OUT    PVOID ConnectInformation OPTIONAL,
        IN OUT    PULONG ConnectInformationLength OPTIONAL
    ){
        static function<NTSTATUS> pNtSecureConnectPort = (void*)GetFunctionByName(hNtdll, xor_str("NtSecureConnectPort"));
        return pNtSecureConnectPort(PortHandle, PortName, SecurityQos, ClientView, ServerSid, ServerView, MaxMessageLength, ConnectInformation, ConnectInformationLength);
    }

     EXPORT NTSTATUS NTAPI NtSaveMergedKeys(
        IN    HANDLE KeyHandle1,
        IN    HANDLE KeyHandle2,
        IN    HANDLE FileHandle
    ){
        static function<NTSTATUS> pNtSaveMergedKeys = (void*)GetFunctionByName(hNtdll, xor_str("NtSaveMergedKeys"));
        return pNtSaveMergedKeys(KeyHandle1, KeyHandle2, FileHandle);
    }

     EXPORT NTSTATUS NTAPI NtSaveKeyEx(
        IN    HANDLE KeyHandle,
        IN    HANDLE FileHandle,
        IN    ULONG Flags
    ){
        static function<NTSTATUS> pNtSaveKeyEx = (void*)GetFunctionByName(hNtdll, xor_str("NtSaveKeyEx"));
        return pNtSaveKeyEx(KeyHandle, FileHandle, Flags);
    }

     EXPORT NTSTATUS NTAPI NtSaveKey(
        IN    HANDLE KeyHandle,
        IN    HANDLE FileHandle
    ){
        static function<NTSTATUS> pNtSaveKey = (void*)GetFunctionByName(hNtdll, xor_str("NtSaveKey"));
        return pNtSaveKey(KeyHandle, FileHandle);
    }

     EXPORT NTSTATUS NTAPI NtResumeThread(
        IN    HANDLE ThreadHandle,
        OUT    PULONG PreviousSuspendCount OPTIONAL
    ){
        static function<NTSTATUS> pNtResumeThread = (void*)GetFunctionByName(hNtdll, xor_str("NtResumeThread"));
        return pNtResumeThread(ThreadHandle, PreviousSuspendCount);
    }

     EXPORT NTSTATUS NTAPI NtResumeProcess(
        IN    HANDLE Process
    ){
        static function<NTSTATUS> pNtResumeProcess = (void*)GetFunctionByName(hNtdll, xor_str("NtResumeProcess"));
        return pNtResumeProcess(Process);
    }

     EXPORT NTSTATUS NTAPI NtRestoreKey(
        IN    HANDLE KeyHandle,
        IN    HANDLE FileHandle,
        IN    ULONG Flags
    ){
        static function<NTSTATUS> pNtRestoreKey = (void*)GetFunctionByName(hNtdll, xor_str("NtRestoreKey"));
        return pNtRestoreKey(KeyHandle, FileHandle, Flags);
    }

     EXPORT NTSTATUS NTAPI NtResetWriteWatch(
        IN    HANDLE ProcessHandle,
        IN    PVOID BaseAddress,
        IN    ULONG RegionSize
    ){
        static function<NTSTATUS> pNtResetWriteWatch = (void*)GetFunctionByName(hNtdll, xor_str("NtResetWriteWatch"));
        return pNtResetWriteWatch(ProcessHandle, BaseAddress, RegionSize);
    }

     EXPORT NTSTATUS NTAPI NtResetEvent(
        IN    HANDLE EventHandle,
        OUT    PULONG PreviousState OPTIONAL
    ){
        static function<NTSTATUS> pNtResetEvent = (void*)GetFunctionByName(hNtdll, xor_str("NtResetEvent"));
        return pNtResetEvent(EventHandle, PreviousState);

    }

     EXPORT NTSTATUS NTAPI NtRequestWakeupLatency(
        IN    LATENCY_TIME Latency
    ){
        static function<NTSTATUS> pNtRequestWakeupLatency = (void*)GetFunctionByName(hNtdll, xor_str("NtRequestWakeupLatency"));
        return pNtRequestWakeupLatency(Latency);
    }

     EXPORT NTSTATUS NTAPI NtRequestWaitReplyPort(
        IN    HANDLE PortHandle,
        IN    PPORT_MESSAGE RequestMessage,
        OUT    PPORT_MESSAGE ReplyMessage
    ){
        static function<NTSTATUS> pNtRequestWaitReplyPort = (void*)GetFunctionByName(hNtdll, xor_str("NtRequestWaitReplyPort"));
        return pNtRequestWaitReplyPort(PortHandle, RequestMessage, ReplyMessage);
    }

     EXPORT NTSTATUS NTAPI NtRequestPort(
        IN    HANDLE PortHandle,
        IN    PPORT_MESSAGE RequestMessage
    ){
        static function<NTSTATUS> pNtRequestPort = (void*)GetFunctionByName(hNtdll, xor_str("NtRequestPort"));
        return pNtRequestPort(PortHandle, RequestMessage);
    }

     EXPORT NTSTATUS NTAPI NtRequestDeviceWakeup(
        IN    HANDLE DeviceHandle
    ){
        static function<NTSTATUS> pNtRequestDeviceWakeup = (void*)GetFunctionByName(hNtdll, xor_str("NtRequestDeviceWakeup"));
        return pNtRequestDeviceWakeup(DeviceHandle);
    }

     EXPORT NTSTATUS NTAPI NtReplyWaitReplyPort(
        IN    HANDLE PortHandle,
        IN OUT    PPORT_MESSAGE ReplyMessage
    ){
        static function<NTSTATUS> pNtReplyWaitReplyPort = (void*)GetFunctionByName(hNtdll, xor_str("NtReplyWaitReplyPort"));
        return pNtReplyWaitReplyPort(PortHandle, ReplyMessage);
    }

     EXPORT NTSTATUS NTAPI NtReplyWaitReceivePortEx(
        IN    HANDLE PortHandle,
        OUT    PVOID* PortIdentifier OPTIONAL,
        IN    PPORT_MESSAGE ReplyMessage OPTIONAL,
        OUT    PPORT_MESSAGE Message,
        IN    PLARGE_INTEGER Timeout
    ){
        static function<NTSTATUS> pNtReplyWaitReceivePortEx = (void*)GetFunctionByName(hNtdll, xor_str("NtReplyWaitReceivePortEx"));
        return pNtReplyWaitReceivePortEx(PortHandle, PortIdentifier, ReplyMessage, Message, Timeout);
    }

     EXPORT NTSTATUS NTAPI NtReplyWaitReceivePort(
        IN    HANDLE PortHandle,
        OUT    PULONG PortIdentifier OPTIONAL,
        IN    PPORT_MESSAGE ReplyMessage OPTIONAL,
        OUT    PPORT_MESSAGE Message
    ){
        static function<NTSTATUS> pNtReplyWaitReceivePort = (void*)GetFunctionByName(hNtdll, xor_str("NtReplyWaitReceivePort"));
        return pNtReplyWaitReceivePort(PortHandle, PortIdentifier, ReplyMessage, Message);
    }

     EXPORT NTSTATUS NTAPI NtReplyPort(
        IN    HANDLE PortHandle,
        IN    PPORT_MESSAGE ReplyMessage
    ){
        static function<NTSTATUS> pNtReplyPort = (void*)GetFunctionByName(hNtdll, xor_str("NtReplyPort"));
        return pNtReplyPort(PortHandle, ReplyMessage);
    }

     EXPORT NTSTATUS NTAPI NtReplaceKey(
        IN    POBJECT_ATTRIBUTES NewFileObjectAttributes,
        IN    HANDLE KeyHandle,
        IN    POBJECT_ATTRIBUTES OldFileObjectAttributes
    ){
        static function<NTSTATUS> pNtReplaceKey = (void*)GetFunctionByName(hNtdll, xor_str("NtReplaceKey"));
        return pNtReplaceKey(NewFileObjectAttributes, KeyHandle, OldFileObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtRenameKey(
        IN    HANDLE KeyHandle,
        IN    PUNICODE_STRING ReplacementName
    ){
        static function<NTSTATUS> pNtRenameKey = (void*)GetFunctionByName(hNtdll, xor_str("NtRenameKey"));
        return pNtRenameKey(KeyHandle, ReplacementName);
    }

     EXPORT NTSTATUS NTAPI NtRemoveProcessDebug(
        IN    HANDLE Process,
        IN    HANDLE DebugObject
    ){
        static function<NTSTATUS> pNtRemoveProcessDebug = (void*)GetFunctionByName(hNtdll, xor_str("NtRemoveProcessDebug"));
        return pNtRemoveProcessDebug(Process, DebugObject);
    }

     EXPORT NTSTATUS NTAPI NtRemoveIoCompletion(
        IN    HANDLE IoCompletionHandle,
        OUT    PULONG CompletionKey,
        OUT    PULONG CompletionValue,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    ){
        static function<NTSTATUS> pNtRemoveIoCompletion = (void*)GetFunctionByName(hNtdll, xor_str("NtRemoveIoCompletion"));
        return pNtRemoveIoCompletion(IoCompletionHandle, CompletionKey, CompletionValue, IoStatusBlock, Timeout);
    }

     EXPORT NTSTATUS NTAPI NtReleaseSemaphore(
        IN    HANDLE SemaphoreHandle,
        IN    LONG ReleaseCount,
        OUT    PLONG PreviousCount OPTIONAL
    ){
        static function<NTSTATUS> pNtReleaseSemaphore = (void*)GetFunctionByName(hNtdll, xor_str("NtReleaseSemaphore"));
        return pNtReleaseSemaphore(SemaphoreHandle, ReleaseCount, PreviousCount);
    }

     EXPORT NTSTATUS NTAPI NtReleaseMutant(
        IN    HANDLE MutantHandle,
        OUT    PULONG PreviousState
    ){
        static function<NTSTATUS> pNtReleaseMutant = (void*)GetFunctionByName(hNtdll, xor_str("NtReleaseMutant"));
        return pNtReleaseMutant(MutantHandle, PreviousState);
    }

     EXPORT NTSTATUS NTAPI NtReleaseKeyedEvent(
        IN    HANDLE KeyedEventHandle,
        IN    PVOID Key,
        IN    BOOLEAN Alertable,
        IN    PLARGE_INTEGER Timeout OPTIONAL
    ){
        static function<NTSTATUS> pNtReleaseKeyedEvent = (void*)GetFunctionByName(hNtdll, xor_str("NtReleaseKeyedEvent"));
        return pNtReleaseKeyedEvent(KeyedEventHandle, Key, Alertable, Timeout);
    }

     EXPORT NTSTATUS NTAPI NtRegisterThreadTerminatePort(
        IN    HANDLE PortHandle
    ){
        static function<NTSTATUS> pNtRegisterThreadTerminatePort = (void*)GetFunctionByName(hNtdll, xor_str("NtRegisterThreadTerminatePort"));
        return pNtRegisterThreadTerminatePort(PortHandle);
    }

     EXPORT NTSTATUS NTAPI NtReadVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN    PVOID BaseAddress,
        OUT    PVOID Buffer,
        IN    ULONG BufferLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtReadVirtualMemory = (void*)GetFunctionByName(hNtdll, xor_str("NtReadVirtualMemory"));
        return pNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtReadRequestData(
        IN    HANDLE PortHandle,
        IN    PPORT_MESSAGE Message,
        IN    ULONG Index,
        OUT    PVOID Buffer,
        IN    ULONG BufferLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtReadRequestData = (void*)GetFunctionByName(hNtdll, xor_str("NtReadRequestData"));
        return pNtReadRequestData(PortHandle, Message, Index, Buffer, BufferLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtReadFileScatter(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PFILE_SEGMENT_ELEMENT Buffer,
        IN    ULONG Length,
        IN    PLARGE_INTEGER ByteOffset OPTIONAL,
        IN    PULONG Key OPTIONAL
    ){
        static function<NTSTATUS> pNtReadFileScatter = (void*)GetFunctionByName(hNtdll, xor_str("NtReadFileScatter"));
        return pNtReadFileScatter(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }

     EXPORT NTSTATUS NTAPI NtReadFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        OUT    PVOID Buffer,
        IN    ULONG Length,
        IN    PLARGE_INTEGER ByteOffset OPTIONAL,
        IN    PULONG Key OPTIONAL
    ){
        static function<NTSTATUS> pNtReadFile = (void*)GetFunctionByName(hNtdll, xor_str("NtReadFile"));
        return pNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }

     EXPORT NTSTATUS NTAPI NtRaiseHardError(
        IN    NTSTATUS Status,
        IN    ULONG NumberOfArguments,
        IN    ULONG StringArgumentsMask,
        IN    PULONG_PTR Arguments,
        IN    HARDERROR_RESPONSE_OPTION ResponseOption,
        OUT    PHARDERROR_RESPONSE Response
    ){
        static function<NTSTATUS> pNtRaiseHardError = (void*)GetFunctionByName(hNtdll, xor_str("NtRaiseHardError"));
        return pNtRaiseHardError(Status, NumberOfArguments, StringArgumentsMask, Arguments, ResponseOption, Response);
    }

     EXPORT NTSTATUS NTAPI NtQueueApcThread(
        IN    HANDLE ThreadHandle,
        IN    PKNORMAL_ROUTINE ApcRoutine,
        IN    PVOID ApcContext OPTIONAL,
        IN    PVOID Argument1 OPTIONAL,
        IN    PVOID Argument2 OPTIONAL
    ){
        static function<NTSTATUS> pNtQueueApcThread = (void*)GetFunctionByName(hNtdll, xor_str("NtQueueApcThread"));
        return pNtQueueApcThread(ThreadHandle, ApcRoutine, ApcContext, Argument1, Argument2);
    }

     EXPORT NTSTATUS NTAPI NtQueryVolumeInformationFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        OUT    PVOID VolumeInformation,
        IN    ULONG VolumeInformationLength,
        IN    FS_INFORMATION_CLASS VolumeInformationClass
    ){
        static function<NTSTATUS> pNtQueryVolumeInformationFile = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryVolumeInformationFile"));
        return pNtQueryVolumeInformationFile(FileHandle, IoStatusBlock, VolumeInformation, VolumeInformationLength, VolumeInformationClass);

    }

     EXPORT NTSTATUS NTAPI NtQueryVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN    PVOID BaseAddress,
        IN    MEMORY_INFORMATION_CLASS MemoryInformationClass,
        OUT    PVOID MemoryInformation,
        IN    ULONG MemoryInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtQueryVirtualMemory = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryVirtualMemory"));
        return pNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQueryValueKey(
        IN    HANDLE KeyHandle,
        IN    PUNICODE_STRING ValueName,
        IN    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
        OUT    PVOID KeyValueInformation,
        IN    ULONG KeyValueInformationLength,
        OUT    PULONG ResultLength
    ){
        static function<NTSTATUS> pNtQueryValueKey = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryValueKey"));
        return pNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, KeyValueInformationLength, ResultLength);
    }

     EXPORT NTSTATUS NTAPI NtQueryTimerResolution(
        OUT    PULONG CoarsestResolution,
        OUT    PULONG FinestResolution,
        OUT    PULONG ActualResolution
    ){
        static function<NTSTATUS> pNtQueryTimerResolution = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryTimerResolution"));
        return pNtQueryTimerResolution(CoarsestResolution, FinestResolution, ActualResolution);
    }

     EXPORT NTSTATUS NTAPI NtQuerySystemTime(
        OUT    PLARGE_INTEGER CurrentTime
    ){
        static function<NTSTATUS> pNtQuerySystemTime = (void*)GetFunctionByName(hNtdll, xor_str("NtQuerySystemTime"));
        return pNtQuerySystemTime(CurrentTime);
    }

     EXPORT NTSTATUS NTAPI NtQuerySystemInformation(
        IN    SYSTEM_INFORMATION_CLASS SystemInformationClass,
        IN OUT    PVOID SystemInformation,
        IN    ULONG SystemInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtQuerySystemInformation = (void*)GetFunctionByName(hNtdll, xor_str("NtQuerySystemInformation"));
        return pNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQuerySystemEnvironmentValueEx(
        IN    ULONG Unknown1,
        IN    ULONG Unknown2,
        IN    ULONG Unknown3,
        IN    ULONG Unknown4,
        IN    ULONG Unknown5
    ){
        static function<NTSTATUS> pNtQuerySystemEnvironmentValueEx = (void*)GetFunctionByName(hNtdll, xor_str("NtQuerySystemEnvironmentValueEx"));
        return pNtQuerySystemEnvironmentValueEx(Unknown1, Unknown2, Unknown3, Unknown4, Unknown5);
    }

     EXPORT NTSTATUS NTAPI NtQuerySystemEnvironmentValue(
        IN    PUNICODE_STRING Name,
        OUT    PVOID Value,
        IN    ULONG ValueLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtQuerySystemEnvironmentValue = (void*)GetFunctionByName(hNtdll, xor_str("NtQuerySystemEnvironmentValue"));
        return pNtQuerySystemEnvironmentValue(Name, Value, ValueLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQuerySymbolicLinkObject(
        IN    HANDLE SymbolicLinkHandle,
        IN OUT    PUNICODE_STRING TargetName,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtQuerySymbolicLinkObject = (void*)GetFunctionByName(hNtdll, xor_str("NtQuerySymbolicLinkObject"));
        return pNtQuerySymbolicLinkObject(SymbolicLinkHandle, TargetName, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQuerySecurityObject(
        IN    HANDLE ObjectHandle,
        IN    SECURITY_INFORMATION SecurityInformation,
        OUT    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    ULONG DescriptorLength,
        OUT    PULONG ReturnLength
    ){
        static function<NTSTATUS> pNtQuerySecurityObject = (void*)GetFunctionByName(hNtdll, xor_str("NtQuerySecurityObject"));
        return pNtQuerySecurityObject(ObjectHandle, SecurityInformation, SecurityDescriptor, DescriptorLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQuerySection(
        IN    HANDLE SectionHandle,
        IN    SECTION_INFORMATION_CLASS SectionInformationClass,
        OUT    PVOID SectionInformation,
        IN    ULONG SectionInformationLength,
        OUT    PULONG ResultLength OPTIONAL
    ){
        static function<NTSTATUS> pNtQuerySection = (void*)GetFunctionByName(hNtdll, xor_str("NtQuerySection"));
        return pNtQuerySection(SectionHandle, SectionInformationClass, SectionInformation, SectionInformationLength, ResultLength);
    }

     EXPORT BOOLEAN NTAPI NtQueryPortInformationProcess(
        VOID
    ){
        static function<BOOLEAN> pNtQueryPortInformationProcess = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryPortInformationProcess"));
        return pNtQueryPortInformationProcess();
    }

     EXPORT NTSTATUS NTAPI NtQueryPerformanceCounter(
        OUT    PLARGE_INTEGER PerformanceCount,
        OUT    PLARGE_INTEGER PerformanceFrequency OPTIONAL
    ){
        static function<NTSTATUS> pNtQueryPerformanceCounter = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryPerformanceCounter"));
        return pNtQueryPerformanceCounter(PerformanceCount, PerformanceFrequency);
    }

     EXPORT NTSTATUS NTAPI NtQueryOpenSubKeys(
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes,
        OUT    PULONG NumberOfKeys
    ){
        static function<NTSTATUS> pNtQueryOpenSubKeys = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryOpenSubKeys"));
        return pNtQueryOpenSubKeys(KeyObjectAttributes, NumberOfKeys);
    }

     EXPORT NTSTATUS NTAPI NtQueryObject(
        IN    HANDLE ObjectHandle,
        IN    OBJECT_INFORMATION_CLASS ObjectInformationClass,
        OUT    PVOID ObjectInformation,
        IN    ULONG ObjectInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtQueryObject = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryObject"));
        return pNtQueryObject(ObjectHandle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQueryMultipleValueKey(
        IN    HANDLE KeyHandle,
        IN OUT    PKEY_VALUE_ENTRY ValueList,
        IN    ULONG NumberOfValues,
        OUT    PVOID Buffer,
        IN OUT    PULONG Length,
        OUT    PULONG ReturnLength
    ){
        static function<NTSTATUS> pNtQueryMultipleValueKey = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryMultipleValueKey"));
        return pNtQueryMultipleValueKey(KeyHandle, ValueList, NumberOfValues, Buffer, Length, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQueryKey(
        IN    HANDLE KeyHandle,
        IN    KEY_INFORMATION_CLASS KeyInformationClass,
        OUT    PVOID KeyInformation,
        IN    ULONG KeyInformationLength,
        OUT    PULONG ResultLength
    ){
        static function<NTSTATUS> pNtQueryKey = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryKey"));
        return pNtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, KeyInformationLength, ResultLength);
    }

     EXPORT NTSTATUS NTAPI NtQueryIntervalProfile(
        IN    KPROFILE_SOURCE Source,
        OUT    PULONG Interval
    ){
        static function<NTSTATUS> pNtQueryIntervalProfile = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryIntervalProfile"));
        return pNtQueryIntervalProfile(Source, Interval);
    }

     EXPORT NTSTATUS NTAPI NtQueryInstallUILanguage(
        OUT    PLANGID LanguageId
    ){
        static function<NTSTATUS> pNtQueryInstallUILanguage = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryInstallUILanguage"));
        return pNtQueryInstallUILanguage(LanguageId);
    }

     EXPORT NTSTATUS NTAPI NtQueryInformationToken(
        IN    HANDLE TokenHandle,
        IN    TOKEN_INFORMATION_CLASS TokenInformationClass,
        OUT    PVOID TokenInformation,
        IN    ULONG TokenInformationLength,
        OUT    PULONG ReturnLength
    ){
        static function<NTSTATUS> pNtQueryInformationToken = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryInformationToken"));
        return pNtQueryInformationToken(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQueryInformationThread(
        IN    HANDLE ThreadHandle,
        IN    THREADINFOCLASS ThreadInformationClass,
        OUT    PVOID ThreadInformation,
        IN    ULONG ThreadInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtQueryInformationThread = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryInformationThread"));
        return pNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQueryInformationProcess(
        IN    HANDLE ProcessHandle,
        IN    PROCESSINFOCLASS ProcessInformationClass,
        OUT    PVOID ProcessInformation,
        IN    ULONG ProcessInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtQueryInformationProcess = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryInformationProcess"));
        return pNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQueryInformationPort(
        IN    HANDLE PortHandle,
        IN    PORT_INFORMATION_CLASS PortInformationClass,
        OUT    PVOID PortInformation,
        IN    ULONG PortInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtQueryInformationPort = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryInformationPort"));
        return pNtQueryInformationPort(PortHandle, PortInformationClass, PortInformation, PortInformationLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQueryInformationJobObject(
        IN    HANDLE JobHandle,
        IN    JOBOBJECTINFOCLASS JobInformationClass,
        OUT    PVOID JobInformation,
        IN    ULONG JobInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtQueryInformationJobObject = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryInformationJobObject"));
        return pNtQueryInformationJobObject(JobHandle, JobInformationClass, JobInformation, JobInformationLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQueryInformationFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        OUT    PVOID FileInformation,
        IN    ULONG FileInformationLength,
        IN    FILE_INFORMATION_CLASS FileInformationClass
    ){
        static function<NTSTATUS> pNtQueryInformationFile = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryInformationFile"));
        return pNtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, FileInformationLength, FileInformationClass);
    }

     EXPORT NTSTATUS NTAPI NtQueryInformationAtom(
        IN    USHORT Atom,
        IN    ATOM_INFORMATION_CLASS AtomInformationClass,
        OUT    PVOID AtomInformation,
        IN    ULONG AtomInformationLength,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtQueryInformationAtom = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryInformationAtom"));
        return pNtQueryInformationAtom(Atom, AtomInformationClass, AtomInformation, AtomInformationLength, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQueryFullAttributesFile(
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        OUT    PFILE_NETWORK_OPEN_INFORMATION FileInformation
    ){
        static function<NTSTATUS> pNtQueryFullAttributesFile = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryFullAttributesFile"));
        return pNtQueryFullAttributesFile(ObjectAttributes, FileInformation);
    }

     EXPORT NTSTATUS NTAPI NtQueryEvent(
        IN    HANDLE EventHandle,
        IN    EVENT_INFORMATION_CLASS EventInformationClass,
        OUT    PVOID EventInformation,
        IN    ULONG EventInformationLength,
        OUT    PULONG ResultLength OPTIONAL
    ){
        static function<NTSTATUS> pNtQueryEvent = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryEvent"));
        return pNtQueryEvent(EventHandle, EventInformationClass, EventInformation, EventInformationLength, ResultLength);
    }

     EXPORT NTSTATUS NTAPI NtQueryDirectoryObject(
        IN    HANDLE DirectoryHandle,
        OUT    PVOID Buffer,
        IN    ULONG BufferLength,
        IN    BOOLEAN ReturnSingleEntry,
        IN    BOOLEAN RestartScan,
        IN OUT    PULONG Context,
        OUT    PULONG ReturnLength OPTIONAL
    ){
        static function<NTSTATUS> pNtQueryDirectoryObject = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryDirectoryObject"));
        return pNtQueryDirectoryObject(DirectoryHandle, Buffer, BufferLength, ReturnSingleEntry, RestartScan, Context, ReturnLength);
    }

     EXPORT NTSTATUS NTAPI NtQueryDirectoryFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        OUT    PVOID FileInformation,
        IN    ULONG FileInformationLength,
        IN    FILE_INFORMATION_CLASS FileInformationClass,
        IN    BOOLEAN ReturnSingleEntry,
        IN    PUNICODE_STRING FileName OPTIONAL,
        IN    BOOLEAN RestartScan
    ){
        static function<NTSTATUS> pNtQueryDirectoryFile = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryDirectoryFile"));
        return pNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, FileInformationLength, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
    }

     EXPORT NTSTATUS NTAPI NtQueryDefaultUILanguage(
        OUT    PLANGID LanguageId
    ){
        static function<NTSTATUS> pNtQueryDefaultUILanguage = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryDefaultUILanguage"));
        return pNtQueryDefaultUILanguage(LanguageId);

    }

     EXPORT NTSTATUS NTAPI NtQueryDefaultLocale(
        IN    BOOLEAN ThreadOrSystem,
        OUT    PLCID Locale
    ){
        static function<NTSTATUS> pNtQueryDefaultLocale = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryDefaultLocale"));
        return pNtQueryDefaultLocale(ThreadOrSystem, Locale);
    }

     EXPORT NTSTATUS NTAPI NtQueryDebugFilterState(
        IN    ULONG ComponentId,
        IN    ULONG Level
    ){
        static function<NTSTATUS> pNtQueryDebugFilterState = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryDebugFilterState"));
        return pNtQueryDebugFilterState(ComponentId, Level);
    }

     EXPORT NTSTATUS NTAPI NtQueryBootOptions(
        IN    ULONG Unknown1,
        IN    ULONG Unknown2
    ){
        static function<NTSTATUS> pNtQueryBootOptions = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryBootOptions"));
        return pNtQueryBootOptions(Unknown1, Unknown2);
    }

     EXPORT NTSTATUS NTAPI NtQueryBootEntryOrder(
        IN    ULONG Unknown1,
        IN    ULONG Unknown2
    ){
        static function<NTSTATUS> pNtQueryBootEntryOrder = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryBootEntryOrder"));
        return pNtQueryBootEntryOrder(Unknown1, Unknown2);
    }

     EXPORT NTSTATUS NTAPI NtQueryAttributesFile(
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        OUT    PFILE_BASIC_INFORMATION FileInformation
    ){
        static function<NTSTATUS> pNtQueryAttributesFile = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryAttributesFile"));
        return pNtQueryAttributesFile(ObjectAttributes, FileInformation);
    }

     EXPORT NTSTATUS NTAPI NtPulseEvent(
        IN    HANDLE EventHandle,
        OUT    PULONG PreviousState OPTIONAL
    ){
        static function<NTSTATUS> pNtPulseEvent = (void*)GetFunctionByName(hNtdll, xor_str("NtPulseEvent"));
        return pNtPulseEvent(EventHandle, PreviousState);
    }

     EXPORT NTSTATUS NTAPI NtProtectVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN OUT    PULONG ProtectSize,
        IN    ULONG NewProtect,
        OUT    PULONG OldProtect
    ){
        static function<NTSTATUS> pNtProtectVirtualMemory = (void*)GetFunctionByName(hNtdll, xor_str("NtProtectVirtualMemory"));
        return pNtProtectVirtualMemory(ProcessHandle, BaseAddress, ProtectSize, NewProtect, OldProtect);
    }

     EXPORT NTSTATUS NTAPI NtPrivilegedServiceAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PUNICODE_STRING ServiceName,
        IN    HANDLE TokenHandle,
        IN    PPRIVILEGE_SET Privileges,
        IN    BOOLEAN AccessGranted
    ){
        static function<NTSTATUS> pNtPrivilegedServiceAuditAlarm = (void*)GetFunctionByName(hNtdll, xor_str("NtPrivilegedServiceAuditAlarm"));
        return pNtPrivilegedServiceAuditAlarm(SubsystemName, ServiceName, TokenHandle, Privileges, AccessGranted);
    }

     EXPORT NTSTATUS NTAPI NtPrivilegeObjectAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID HandleId,
        IN    HANDLE TokenHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    PPRIVILEGE_SET Privileges,
        IN    BOOLEAN AccessGranted
    ){
        static function<NTSTATUS> pNtPrivilegeObjectAuditAlarm = (void*)GetFunctionByName(hNtdll, xor_str("NtPrivilegeObjectAuditAlarm"));
        return pNtPrivilegeObjectAuditAlarm(SubsystemName, HandleId, TokenHandle, DesiredAccess, Privileges, AccessGranted);
    }

     EXPORT NTSTATUS NTAPI NtPrivilegeCheck(
        IN    HANDLE TokenHandle,
        IN    PPRIVILEGE_SET RequiredPrivileges,
        OUT    PBOOLEAN Result
    ){
        static function<NTSTATUS> pNtPrivilegeCheck = (void*)GetFunctionByName(hNtdll, xor_str("NtPrivilegeCheck"));
        return pNtPrivilegeCheck(TokenHandle, RequiredPrivileges, Result);
    }

     EXPORT NTSTATUS NTAPI NtPowerInformation(
        IN    POWER_INFORMATION_LEVEL PowerInformationLevel,
        IN    PVOID InputBuffer OPTIONAL,
        IN    ULONG InputBufferLength,
        OUT    PVOID OutputBuffer OPTIONAL,
        IN    ULONG OutputBufferLength
    ){
        static function<NTSTATUS> pNtPowerInformation = (void*)GetFunctionByName(hNtdll, xor_str("NtPowerInformation"));
        return pNtPowerInformation(PowerInformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
    }

     EXPORT NTSTATUS NTAPI NtPlugPlayControl(
        IN    ULONG ControlCode,
        IN OUT    PVOID Buffer,
        IN    ULONG BufferLength,
        IN    PVOID Unknown OPTIONAL
    ){
        static function<NTSTATUS> pNtPlugPlayControl = (void*)GetFunctionByName(hNtdll, xor_str("NtPlugPlayControl"));
        return pNtPlugPlayControl(ControlCode, Buffer, BufferLength, Unknown);
    }

     EXPORT NTSTATUS NTAPI NtOpenTimer(
        OUT    PHANDLE TimerHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    ){
        static function<NTSTATUS> pNtOpenTimer = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenTimer"));
        return pNtOpenTimer(TimerHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtOpenThreadTokenEx(
        IN    HANDLE ThreadHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    BOOLEAN OpenAsSelf,
        IN    ULONG HandleAttributes,
        OUT    PHANDLE TokenHandle
    ){
        static function<NTSTATUS> pNtOpenThreadTokenEx = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenThreadTokenEx"));
        return pNtOpenThreadTokenEx(ThreadHandle, DesiredAccess, OpenAsSelf, HandleAttributes, TokenHandle);
    }

     EXPORT NTSTATUS NTAPI NtOpenThreadToken(
        IN    HANDLE ThreadHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    BOOLEAN OpenAsSelf,
        OUT    PHANDLE TokenHandle
    ){
        static function<NTSTATUS> pNtOpenThreadToken = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenThreadToken"));
        return pNtOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
    }

     EXPORT NTSTATUS NTAPI NtOpenThread(
        OUT    PHANDLE ThreadHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    PCLIENT_ID ClientId
    ){
        static function<NTSTATUS> pNtOpenThread = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenThread"));
        return pNtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

     EXPORT NTSTATUS NTAPI NtOpenSymbolicLinkObject(
        OUT    PHANDLE SymbolicLinkHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    ){
        static function<NTSTATUS> pNtOpenSymbolicLinkObject = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenSymbolicLinkObject"));
        return pNtOpenSymbolicLinkObject(SymbolicLinkHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtOpenSemaphore(
        OUT    PHANDLE SemaphoreHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    ){
        static function<NTSTATUS> pNtOpenSemaphore = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenSemaphore"));
        return pNtOpenSemaphore(SemaphoreHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtOpenSection(
        OUT    PHANDLE SectionHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    ){
        static function<NTSTATUS> pNtOpenSection = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenSection"));
        return pNtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtOpenProcessTokenEx(
        IN    HANDLE ProcessHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    ULONG HandleAttributes,
        OUT    PHANDLE TokenHandle
    ){
        static function<NTSTATUS> pNtOpenProcessTokenEx = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenProcessTokenEx"));
        return pNtOpenProcessTokenEx(ProcessHandle, DesiredAccess, HandleAttributes, TokenHandle);
    }

     EXPORT NTSTATUS NTAPI NtOpenProcessToken(
        IN    HANDLE ProcessHandle,
        IN    ACCESS_MASK DesiredAccess,
        OUT    PHANDLE TokenHandle
    ){
        static function<NTSTATUS> pNtOpenProcessToken = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenProcessToken"));
        return pNtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
    }

     EXPORT NTSTATUS NTAPI NtOpenProcess(
        OUT    PHANDLE ProcessHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        IN    PCLIENT_ID ClientId OPTIONAL
    ){
        static function<NTSTATUS> pNtOpenProcess = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenProcess"));
        return pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

     EXPORT NTSTATUS NTAPI NtOpenObjectAuditAlarm(
        IN    PUNICODE_STRING SubsystemName,
        IN    PVOID* HandleId,
        IN    PUNICODE_STRING ObjectTypeName,
        IN    PUNICODE_STRING ObjectName,
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    HANDLE TokenHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    ACCESS_MASK GrantedAccess,
        IN    PPRIVILEGE_SET Privileges OPTIONAL,
        IN    BOOLEAN ObjectCreation,
        IN    BOOLEAN AccessGranted,
        OUT    PBOOLEAN GenerateOnClose
    ){
        static function<NTSTATUS> pNtOpenObjectAuditAlarm = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenObjectAuditAlarm"));
        return pNtOpenObjectAuditAlarm(SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, TokenHandle, DesiredAccess, GrantedAccess, Privileges, ObjectCreation, AccessGranted, GenerateOnClose);
    }

     EXPORT NTSTATUS NTAPI NtOpenMutant(
        OUT    PHANDLE MutantHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    ){
        static function<NTSTATUS> pNtOpenMutant = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenMutant"));
        return pNtOpenMutant(MutantHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtOpenKeyedEvent(
        OUT    PHANDLE KeyedEventHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    ){
        static function<NTSTATUS> pNtOpenKeyedEvent = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenKeyedEvent"));
        return pNtOpenKeyedEvent(KeyedEventHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtOpenKey(
        OUT    PHANDLE KeyHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    ){
        static function<NTSTATUS> pNtOpenKey = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenKey"));
        return pNtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtOpenJobObject(
        OUT    PHANDLE JobHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    ){
        static function<NTSTATUS> pNtOpenJobObject = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenJobObject"));
        return pNtOpenJobObject(JobHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtOpenIoCompletion(
        OUT    PHANDLE IoCompletionHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    ){
        static function<NTSTATUS> pNtOpenIoCompletion = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenIoCompletion"));
        return pNtOpenIoCompletion(IoCompletionHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtOpenFile(
        OUT    PHANDLE FileHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG ShareAccess,
        IN    ULONG OpenOptions
    ){
        static function<NTSTATUS> pNtOpenFile = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenFile"));
        return pNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
    }

     EXPORT NTSTATUS NTAPI NtOpenEventPair(
        OUT    PHANDLE EventPairHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    ){
        static function<NTSTATUS> pNtOpenEventPair = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenEventPair"));
        return pNtOpenEventPair(EventPairHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtOpenEvent(
        OUT    PHANDLE EventHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    ){
        static function<NTSTATUS> pNtOpenEvent = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenEvent"));
        return pNtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtOpenDirectoryObject(
        OUT    PHANDLE DirectoryHandle,
        IN    ACCESS_MASK DesiredAccess,
        IN    POBJECT_ATTRIBUTES ObjectAttributes
    ){
        static function<NTSTATUS> pNtOpenDirectoryObject = (void*)GetFunctionByName(hNtdll, xor_str("NtOpenDirectoryObject"));
        return pNtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtNotifyChangeMultipleKeys(
        IN    HANDLE KeyHandle,
        IN    ULONG Flags,
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes,
        IN    HANDLE EventHandle OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG NotifyFilter,
        IN    BOOLEAN WatchSubtree,
        IN    PVOID Buffer,
        IN    ULONG BufferLength,
        IN    BOOLEAN Asynchronous
    ){
        static function<NTSTATUS> pNtNotifyChangeMultipleKeys = (void*)GetFunctionByName(hNtdll, xor_str("NtNotifyChangeMultipleKeys"));
        return pNtNotifyChangeMultipleKeys(KeyHandle, Flags, KeyObjectAttributes, EventHandle, ApcRoutine, ApcContext, IoStatusBlock, NotifyFilter, WatchSubtree, Buffer, BufferLength, Asynchronous);
    }

     EXPORT NTSTATUS NTAPI NtNotifyChangeKey(
        IN    HANDLE KeyHandle,
        IN    HANDLE EventHandle OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG NotifyFilter,
        IN    BOOLEAN WatchSubtree,
        IN    PVOID Buffer,
        IN    ULONG BufferLength,
        IN    BOOLEAN Asynchronous
    ){
        static function<NTSTATUS> pNtNotifyChangeKey = (void*)GetFunctionByName(hNtdll, xor_str("NtNotifyChangeKey"));
        return pNtNotifyChangeKey(KeyHandle, EventHandle, ApcRoutine, ApcContext, IoStatusBlock, NotifyFilter, WatchSubtree, Buffer, BufferLength, Asynchronous);
    }

     EXPORT NTSTATUS NTAPI NtNotifyChangeDirectoryFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        OUT    PFILE_NOTIFY_INFORMATION Buffer,
        IN    ULONG BufferLength,
        IN    ULONG NotifyFilter,
        IN    BOOLEAN WatchSubtree
    ){
        static function<NTSTATUS> pNtNotifyChangeDirectoryFile = (void*)GetFunctionByName(hNtdll, xor_str("NtNotifyChangeDirectoryFile"));
        return pNtNotifyChangeDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, BufferLength, NotifyFilter, WatchSubtree);
    }

     EXPORT NTSTATUS NTAPI NtModifyDriverEntry(
        IN    PUNICODE_STRING DriverName,
        IN    PUNICODE_STRING DriverPath
    ){
        static function<NTSTATUS> pNtModifyDriverEntry = (void*)GetFunctionByName(hNtdll, xor_str("NtModifyDriverEntry"));
        return pNtModifyDriverEntry(DriverName, DriverPath);
    }

     EXPORT NTSTATUS NTAPI NtModifyBootEntry(
        IN    PUNICODE_STRING EntryName,
        IN    PUNICODE_STRING EntryValue
    ){
        static function<NTSTATUS> pNtModifyBootEntry = (void*)GetFunctionByName(hNtdll, xor_str("NtModifyBootEntry"));
        return pNtModifyBootEntry(EntryName, EntryValue);
    }

     EXPORT NTSTATUS NTAPI NtMapViewOfSection(
        IN    HANDLE SectionHandle,
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN    ULONG ZeroBits,
        IN    ULONG CommitSize,
        IN OUT    PLARGE_INTEGER SectionOffset OPTIONAL,
        IN OUT    PULONG ViewSize,
        IN    SECTION_INHERIT InheritDisposition,
        IN    ULONG AllocationType,
        IN    ULONG Protect
    ){
        static function<NTSTATUS> pNtMapViewOfSection = (void*)GetFunctionByName(hNtdll, xor_str("NtMapViewOfSection"));
        return pNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
    }

     EXPORT NTSTATUS NTAPI NtMapUserPhysicalPagesScatter(
        IN    PVOID* BaseAddresses,
        IN    PULONG NumberOfPages,
        IN    PULONG PageFrameNumbers
    ){
        static function<NTSTATUS> pNtMapUserPhysicalPagesScatter = (void*)GetFunctionByName(hNtdll, xor_str("NtMapUserPhysicalPagesScatter"));
        return pNtMapUserPhysicalPagesScatter(BaseAddresses, NumberOfPages, PageFrameNumbers);
    }

     EXPORT NTSTATUS NTAPI NtMapUserPhysicalPages(
        IN    PVOID BaseAddress,
        IN    PULONG NumberOfPages,
        IN    PULONG PageFrameNumbers
    ){
        static function<NTSTATUS> pNtMapUserPhysicalPages = (void*)GetFunctionByName(hNtdll, xor_str("NtMapUserPhysicalPages"));
        return pNtMapUserPhysicalPages(BaseAddress, NumberOfPages, PageFrameNumbers);
    }

     EXPORT NTSTATUS NTAPI NtMakeTemporaryObject(
        IN    HANDLE ObjectHandle
    ){
        static function<NTSTATUS> pNtMakeTemporaryObject = (void*)GetFunctionByName(hNtdll, xor_str("NtMakeTemporaryObject"));
        return pNtMakeTemporaryObject(ObjectHandle);
    }

     EXPORT NTSTATUS NTAPI NtMakePermanentObject(
        IN    HANDLE Object
    ){
        static function<NTSTATUS> pNtMakePermanentObject = (void*)GetFunctionByName(hNtdll, xor_str("NtMakePermanentObject"));
        return pNtMakePermanentObject(Object);
    }

     EXPORT NTSTATUS NTAPI NtLockVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN OUT    PULONG LockSize,
        IN    ULONG LockType
    ){
        static function<NTSTATUS> pNtLockVirtualMemory = (void*)GetFunctionByName(hNtdll, xor_str("NtLockVirtualMemory"));
        return pNtLockVirtualMemory(ProcessHandle, BaseAddress, LockSize, LockType);
    }

     EXPORT NTSTATUS NTAPI NtLockRegistryKey(
        IN    HANDLE Key
    ){
        static function<NTSTATUS> pNtLockRegistryKey = (void*)GetFunctionByName(hNtdll, xor_str("NtLockRegistryKey"));
        return pNtLockRegistryKey(Key);
    }

     EXPORT NTSTATUS NTAPI NtLockFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    PULARGE_INTEGER LockOffset,
        IN    PULARGE_INTEGER LockLength,
        IN    ULONG Key,
        IN    BOOLEAN FailImmediately,
        IN    BOOLEAN ExclusiveLock
    ){
        static function<NTSTATUS> pNtLockFile = (void*)GetFunctionByName(hNtdll, xor_str("NtLockFile"));
        return pNtLockFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, LockOffset, LockLength, Key, FailImmediately, ExclusiveLock);
    }

     EXPORT NTSTATUS NTAPI NtLoadKey(
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes,
        IN    POBJECT_ATTRIBUTES FileObjectAttributes
    ){
        static function<NTSTATUS> pNtLoadKey = (void*)GetFunctionByName(hNtdll, xor_str("NtLoadKey"));
        return pNtLoadKey(KeyObjectAttributes, FileObjectAttributes);
    }

     EXPORT NTSTATUS NTAPI NtLoadKey2(
        IN    POBJECT_ATTRIBUTES KeyObjectAttributes,
        IN    POBJECT_ATTRIBUTES FileObjectAttributes,
        IN    ULONG Flags
    ){
        static function<NTSTATUS> pNtLoadKey2 = (void*)GetFunctionByName(hNtdll, xor_str("NtLoadKey2"));
        return pNtLoadKey2(KeyObjectAttributes, FileObjectAttributes, Flags);
    }

     EXPORT NTSTATUS NTAPI NtLoadDriver(
        IN    PUNICODE_STRING DriverServiceName
    ){
        static function<NTSTATUS> pNtLoadDriver = (void*)GetFunctionByName(hNtdll, xor_str("NtLoadDriver"));
        return pNtLoadDriver(DriverServiceName);
    }

     EXPORT NTSTATUS NTAPI NtListenPort(
        IN    HANDLE PortHandle,
        OUT    PPORT_MESSAGE RequestMessage
    ){
        static function<NTSTATUS> pNtListenPort = (void*)GetFunctionByName(hNtdll, xor_str("NtListenPort"));
        return pNtListenPort(PortHandle, RequestMessage);
    }

     EXPORT NTSTATUS NTAPI NtFreeUserPhysicalPages(
        IN    HANDLE ProcessHandle,
        IN OUT    PULONG NumberOfPages,
        IN    PULONG PageFrameNumbers
    ){
        static function<NTSTATUS> pNtFreeUserPhysicalPages = (void*)GetFunctionByName(hNtdll, xor_str("NtFreeUserPhysicalPages"));
        return pNtFreeUserPhysicalPages(ProcessHandle, NumberOfPages, PageFrameNumbers);
    }

     EXPORT NTSTATUS NTAPI NtFreeVirtualMemory(
        IN    HANDLE ProcessHandle,
        IN OUT    PVOID* BaseAddress,
        IN OUT    PULONG FreeSize,
        IN    ULONG FreeType
    ){
        static function<NTSTATUS> pNtFreeVirtualMemory = (void*)GetFunctionByName(hNtdll, xor_str("NtFreeVirtualMemory"));
        return pNtFreeVirtualMemory(ProcessHandle, BaseAddress, FreeSize, FreeType);
    }

     EXPORT NTSTATUS NTAPI NtFsControlFile(
        IN    HANDLE FileHandle,
        IN    HANDLE Event OPTIONAL,
        IN    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN    PVOID ApcContext OPTIONAL,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        IN    ULONG FsControlCode,
        IN    PVOID InputBuffer OPTIONAL,
        IN    ULONG InputBufferLength,
        OUT    PVOID OutputBuffer OPTIONAL,
        IN    ULONG OutputBufferLength
    ){
        static function<NTSTATUS> pNtFsControlFile = (void*)GetFunctionByName(hNtdll, xor_str("NtFsControlFile"));
        return pNtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
    }

     EXPORT NTSTATUS NTAPI NtGetDevicePowerState(
        IN    HANDLE DeviceHandle,
        OUT    PDEVICE_POWER_STATE DevicePowerState
    ){
        static function<NTSTATUS> pNtGetDevicePowerState = (void*)GetFunctionByName(hNtdll, xor_str("NtGetDevicePowerState"));
        return pNtGetDevicePowerState(DeviceHandle, DevicePowerState);
    }

     EXPORT NTSTATUS NTAPI NtGetPlugPlayEvent(
        IN    ULONG Reserved1,
        IN    ULONG Reserved2,
        OUT    PVOID Buffer,
        IN    ULONG BufferLength
    ){
        static function<NTSTATUS> pNtGetPlugPlayEvent = (void*)GetFunctionByName(hNtdll, xor_str("NtGetPlugPlayEvent"));
        return pNtGetPlugPlayEvent(Reserved1, Reserved2, Buffer, BufferLength);
    }

     EXPORT NTSTATUS NTAPI NtGetWriteWatch(
        IN    HANDLE ProcessHandle,
        IN    ULONG Flags,
        IN    PVOID BaseAddress,
        IN    ULONG RegionSize,
        OUT    PULONG Buffer,
        IN OUT    PULONG BufferEntries,
        OUT    PULONG Granularity
    ){
        static function<NTSTATUS> pNtGetWriteWatch = (void*)GetFunctionByName(hNtdll, xor_str("NtGetWriteWatch"));
        return pNtGetWriteWatch(ProcessHandle, Flags, BaseAddress, RegionSize, Buffer, BufferEntries, Granularity);
    }

     EXPORT NTSTATUS NTAPI NtImpersonateAnonymousToken(
        IN    HANDLE ThreadHandle
    ){
        static function<NTSTATUS> pNtImpersonateAnonymousToken = (void*)GetFunctionByName(hNtdll, xor_str("NtImpersonateAnonymousToken"));
        return pNtImpersonateAnonymousToken(ThreadHandle);
    }

     EXPORT NTSTATUS NTAPI NtImpersonateClientOfPort(
        IN    HANDLE PortHandle,
        IN    PPORT_MESSAGE Message
    ){
        static function<NTSTATUS> pNtImpersonateClientOfPort = (void*)GetFunctionByName(hNtdll, xor_str("NtImpersonateClientOfPort"));
        return pNtImpersonateClientOfPort(PortHandle, Message);
    }

     EXPORT NTSTATUS NTAPI NtImpersonateThread(
        IN    HANDLE ThreadHandle,
        IN    HANDLE TargetThreadHandle,
        IN    PSECURITY_QUALITY_OF_SERVICE SecurityQos
    ){
        static function<NTSTATUS> pNtImpersonateThread = (void*)GetFunctionByName(hNtdll, xor_str("NtImpersonateThread"));
        return pNtImpersonateThread(ThreadHandle, TargetThreadHandle, SecurityQos);
    }

     EXPORT NTSTATUS NTAPI NtInitializeRegistry(
        IN    BOOLEAN Setup
    ){
        static function<NTSTATUS> pNtInitializeRegistry = (void*)GetFunctionByName(hNtdll, xor_str("NtInitializeRegistry"));
        return pNtInitializeRegistry(Setup);
    }

     EXPORT NTSTATUS NTAPI NtInitiatePowerAction(
        IN    POWER_ACTION SystemAction,
        IN    SYSTEM_POWER_STATE MinSystemState,
        IN    ULONG Flags,
        IN    BOOLEAN Asynchronous
    ){
        static function<NTSTATUS> pNtInitiatePowerAction = (void*)GetFunctionByName(hNtdll, xor_str("NtInitiatePowerAction"));
        return pNtInitiatePowerAction(SystemAction, MinSystemState, Flags, Asynchronous);
    }

     EXPORT NTSTATUS NTAPI NtIsProcessInJob(
        IN    HANDLE ProcessHandle,
        IN    HANDLE JobHandle OPTIONAL
    ){
        static function<NTSTATUS> pNtIsProcessInJob = (void*)GetFunctionByName(hNtdll, xor_str("NtIsProcessInJob"));
        return pNtIsProcessInJob(ProcessHandle, JobHandle);
    }

     EXPORT BOOLEAN NTAPI NtIsSystemResumeAutomatic(
        VOID
    ){
        static function<BOOLEAN> pNtIsSystemResumeAutomatic = (void*)GetFunctionByName(hNtdll, xor_str("NtIsSystemResumeAutomatic"));
        return pNtIsSystemResumeAutomatic();
    }

     EXPORT NTSTATUS NTAPI NtTestAlert(
        VOID
    ){
        static function<NTSTATUS> pNtTestAlert = (void*)GetFunctionByName(hNtdll, xor_str("NtTestAlert"));
        return pNtTestAlert();
    }

     EXPORT NTSTATUS NTAPI NtAlertThread(
        IN    HANDLE ThreadHandle
    ){
        static function<NTSTATUS> pNtAlertThread = (void*)GetFunctionByName(hNtdll, xor_str("NtAlertThread"));
        return pNtAlertThread(ThreadHandle);
    }

     EXPORT ULONG NTAPI NtGetTickCount(
        VOID
    ){
        static function<ULONG> pNtGetTickCount = (void*)GetFunctionByName(hNtdll, xor_str("NtGetTickCount"));
        return pNtGetTickCount();
    }

     EXPORT NTSTATUS NTAPI NtW32Call(
        IN    ULONG RoutineIndex,
        IN    PVOID Argument,
        IN    ULONG ArgumentLength,
        OUT    PVOID* Result OPTIONAL,
        OUT    PULONG ResultLength OPTIONAL
    ){
        static function<NTSTATUS> pNtW32Call = (void*)GetFunctionByName(hNtdll, xor_str("NtW32Call"));
        return pNtW32Call(RoutineIndex, Argument, ArgumentLength, Result, ResultLength);
    }

     EXPORT NTSTATUS NTAPI NtSetLowWaitHighThread(
        VOID
    ){
        static function<NTSTATUS> pNtSetLowWaitHighThread = (void*)GetFunctionByName(hNtdll, xor_str("NtSetLowWaitHighThread"));
        return pNtSetLowWaitHighThread();
    }

     EXPORT NTSTATUS NTAPI NtSetHighWaitLowThread(
        VOID
    ){
        static function<NTSTATUS> pNtSetHighWaitLowThread = (void*)GetFunctionByName(hNtdll, xor_str("NtSetHighWaitLowThread"));
        return pNtSetHighWaitLowThread();
    }

     EXPORT NTSTATUS NTAPI NtCreatePagingFile(
        IN    PUNICODE_STRING FileName,
        IN    PULARGE_INTEGER InitialSize,
        IN    PULARGE_INTEGER MaximumSize,
        IN    ULONG Priority OPTIONAL
    ){
        static function<NTSTATUS> pNtCreatePagingFile = (void*)GetFunctionByName(hNtdll, xor_str("NtCreatePagingFile"));
        return pNtCreatePagingFile(FileName, InitialSize, MaximumSize, Priority);
    }

     EXPORT NTSTATUS NTAPI NtVdmControl(
        IN    ULONG ControlCode,
        IN    PVOID ControlData
    ){
        static function<NTSTATUS> pNtVdmControl = (void*)GetFunctionByName(hNtdll, xor_str("NtVdmControl"));
        return pNtVdmControl(ControlCode, ControlData);
    }

     EXPORT NTSTATUS NTAPI NtQueryEaFile(
        IN    HANDLE FileHandle,
        OUT    PIO_STATUS_BLOCK IoStatusBlock,
        OUT    PVOID Buffer,
        IN    ULONG Length,
        IN    BOOLEAN ReturnSingleEntry,
        IN    PVOID EaList OPTIONAL,
        IN    ULONG EaListLength,
        IN    PULONG EaIndex OPTIONAL,
        IN    BOOLEAN RestartScan
    ){
        static function<NTSTATUS> pNtQueryEaFile = (void*)GetFunctionByName(hNtdll, xor_str("NtQueryEaFile"));
        return pNtQueryEaFile(FileHandle, IoStatusBlock, Buffer, Length, ReturnSingleEntry, EaList, EaListLength, EaIndex, RestartScan);
    }

    NTSTATUS NTAPI RtlCreateProcessParameters(
        OUT    PRTL_USER_PROCESS_PARAMETERS* ProcessParameters,
        IN    PUNICODE_STRING ImageFile,
        IN    PUNICODE_STRING DllPath OPTIONAL,
        IN    PUNICODE_STRING CurrentDirectory OPTIONAL,
        IN    PUNICODE_STRING CommandLine OPTIONAL,
        IN    PWSTR Environment OPTIONAL,
        IN    PUNICODE_STRING WindowTitle OPTIONAL,
        IN    PUNICODE_STRING DesktopInfo OPTIONAL,
        IN    PUNICODE_STRING ShellInfo OPTIONAL,
        IN    PUNICODE_STRING RuntimeInfo OPTIONAL
    ){
        static function<NTSTATUS> pRtlCreateProcessParameters = (void*)GetFunctionByName(hNtdll, xor_str("RtlCreateProcessParameters"));
        return pRtlCreateProcessParameters(ProcessParameters, ImageFile, DllPath, CurrentDirectory, CommandLine, Environment, WindowTitle, DesktopInfo, ShellInfo, RuntimeInfo);
    }

    NTSTATUS NTAPI RtlDestroyProcessParameters(
        IN    PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    ){
        static function<NTSTATUS> pRtlDestroyProcessParameters = (void*)GetFunctionByName(hNtdll, xor_str("RtlDestroyProcessParameters"));
        return pRtlDestroyProcessParameters(ProcessParameters);
    }

    PDEBUG_BUFFER NTAPI RtlCreateQueryDebugBuffer(
        IN    ULONG Size,
        IN    BOOLEAN EventPair
    ){
        static function<PDEBUG_BUFFER> pRtlCreateQueryDebugBuffer = (void*)GetFunctionByName(hNtdll, xor_str("RtlCreateQueryDebugBuffer"));
        return pRtlCreateQueryDebugBuffer(Size, EventPair);
    }

    NTSTATUS NTAPI RtlQueryProcessDebugInformation(
        IN    ULONG ProcessId,
        IN    ULONG DebugInfoClassMask,
        IN OUT    PDEBUG_BUFFER DebugBuffer
    ){
        static function<NTSTATUS> pRtlQueryProcessDebugInformation = (void*)GetFunctionByName(hNtdll, xor_str("RtlQueryProcessDebugInformation"));
        return pRtlQueryProcessDebugInformation(ProcessId, DebugInfoClassMask, DebugBuffer);
    }

    NTSTATUS NTAPI RtlDestroyQueryDebugBuffer(
        IN    PDEBUG_BUFFER DebugBuffer
    ){
        static function<NTSTATUS> pRtlDestroyQueryDebugBuffer = (void*)GetFunctionByName(hNtdll, xor_str("RtlDestroyQueryDebugBuffer"));
        return pRtlDestroyQueryDebugBuffer(DebugBuffer);
    }

     EXPORT VOID NTAPI RtlInitUnicodeString(
        OUT    PUNICODE_STRING DestinationString,
        IN    PCWSTR SourceString
    ){
        static function<VOID> pRtlInitUnicodeString = (void*)GetFunctionByName(hNtdll, xor_str("RtlInitUnicodeString"));
        return pRtlInitUnicodeString(DestinationString, SourceString);
    }

     EXPORT VOID NTAPI RtlInitString(
        PSTRING DestinationString,
        PCSTR SourceString
    ){
        static function<VOID> pRtlInitString = (void*)GetFunctionByName(hNtdll, xor_str("RtlInitString"));
        return pRtlInitString(DestinationString, SourceString);
    }

     EXPORT VOID NTAPI RtlInitAnsiString(
        OUT    PANSI_STRING DestinationString,
        IN    PCSTR SourceString
    ){
        static function<VOID> pRtlInitAnsiString = (void*)GetFunctionByName(hNtdll, xor_str("RtlInitAnsiString"));
        return pRtlInitAnsiString(DestinationString, SourceString);
    }

     EXPORT NTSTATUS NTAPI RtlAnsiStringToUnicodeString(
        OUT    PUNICODE_STRING DestinationString,
        IN    PANSI_STRING SourceString,
        IN    BOOLEAN AllocateDestinationString
    ){
        static function<NTSTATUS> pRtlAnsiStringToUnicodeString = (void*)GetFunctionByName(hNtdll, xor_str("RtlAnsiStringToUnicodeString"));
        return pRtlAnsiStringToUnicodeString(DestinationString, SourceString, AllocateDestinationString);
    }

     EXPORT NTSTATUS NTAPI RtlUnicodeStringToAnsiString(
        OUT    PANSI_STRING DestinationString,
        IN    PCUNICODE_STRING SourceString,
        IN    BOOLEAN AllocateDestinationString
    ){
        static function<NTSTATUS> pRtlUnicodeStringToAnsiString = (void*)GetFunctionByName(hNtdll, xor_str("RtlUnicodeStringToAnsiString"));
        return pRtlUnicodeStringToAnsiString(DestinationString, SourceString, AllocateDestinationString);
    }

     EXPORT LONG NTAPI RtlCompareUnicodeString(
        IN    PUNICODE_STRING String1,
        IN    PUNICODE_STRING String2,
        IN    BOOLEAN CaseInSensitive
    ){
        static function<LONG> pRtlCompareUnicodeString = (void*)GetFunctionByName(hNtdll, xor_str("RtlCompareUnicodeString"));
        return pRtlCompareUnicodeString(String1, String2, CaseInSensitive);
    }

     EXPORT BOOLEAN NTAPI RtlEqualUnicodeString(
        IN    PCUNICODE_STRING String1,
        IN    PCUNICODE_STRING String2,
        IN    BOOLEAN CaseInSensitive
    ){
        static function<BOOLEAN> pRtlEqualUnicodeString = (void*)GetFunctionByName(hNtdll, xor_str("RtlEqualUnicodeString"));
        return pRtlEqualUnicodeString(String1, String2, CaseInSensitive);
    }

     EXPORT NTSTATUS NTAPI RtlHashUnicodeString(
        IN    CONST UNICODE_STRING* String,
        IN    BOOLEAN CaseInSensitive,
        IN    ULONG HashAlgorithm,
        OUT    PULONG HashValue
    ){
        static function<NTSTATUS> pRtlHashUnicodeString = (void*)GetFunctionByName(hNtdll, xor_str("RtlHashUnicodeString"));
        return pRtlHashUnicodeString(String, CaseInSensitive, HashAlgorithm, HashValue);
    }

     EXPORT VOID NTAPI RtlCopyUnicodeString(
        OUT    PUNICODE_STRING DestinationString,
        IN    PUNICODE_STRING SourceString
    ){
        static function<VOID> pRtlCopyUnicodeString = (void*)GetFunctionByName(hNtdll, xor_str("RtlCopyUnicodeString"));
        return pRtlCopyUnicodeString(DestinationString, SourceString);
    }

     EXPORT NTSTATUS NTAPI RtlAppendUnicodeStringToString(
        IN OUT    PUNICODE_STRING Destination,
        IN    PUNICODE_STRING Source
    ){
        static function<NTSTATUS> pRtlAppendUnicodeStringToString = (void*)GetFunctionByName(hNtdll, xor_str("RtlAppendUnicodeStringToString"));
        return pRtlAppendUnicodeStringToString(Destination, Source);
    }

     EXPORT NTSTATUS NTAPI RtlAppendUnicodeToString(
        PUNICODE_STRING Destination,
        PCWSTR Source
    ){
        static function<NTSTATUS> pRtlAppendUnicodeToString = (void*)GetFunctionByName(hNtdll, xor_str("RtlAppendUnicodeToString"));
        return pRtlAppendUnicodeToString(Destination, Source);
    }

     EXPORT VOID NTAPI RtlFreeUnicodeString(
        PUNICODE_STRING UnicodeString
    ){
        static function<VOID> pRtlFreeUnicodeString = (void*)GetFunctionByName(hNtdll, xor_str("RtlFreeUnicodeString"));
        return pRtlFreeUnicodeString(UnicodeString);
    }

     EXPORT VOID NTAPI RtlFreeAnsiString(
        PANSI_STRING AnsiString
    ){
        static function<VOID> pRtlFreeAnsiString = (void*)GetFunctionByName(hNtdll, xor_str("RtlFreeAnsiString"));
        return pRtlFreeAnsiString(AnsiString);
    }

     EXPORT ULONG NTAPI RtlxUnicodeStringToAnsiSize(
        PCUNICODE_STRING UnicodeString
    ){
        static function<ULONG> pRtlxUnicodeStringToAnsiSize = (void*)GetFunctionByName(hNtdll, xor_str("RtlxUnicodeStringToAnsiSize"));
        return pRtlxUnicodeStringToAnsiSize(UnicodeString);
    }

     

     EXPORT NTSTATUS NTAPI RtlAdjustPrivilege(
        ULONG  Privilege,
        BOOLEAN Enable,
        BOOLEAN CurrentThread,
        PBOOLEAN Enabled
    ){
        static function<NTSTATUS> pRtlAdjustPrivilege = (void*)GetFunctionByName(hNtdll, xor_str("RtlAdjustPrivilege"));
        return pRtlAdjustPrivilege(Privilege, Enable, CurrentThread, Enabled);
    }

     EXPORT BOOLEAN NTAPI RtlCreateUnicodeString(
        OUT    PUNICODE_STRING DestinationString,
        IN    PCWSTR SourceString
    ){
        static function<BOOLEAN> pRtlCreateUnicodeString = (void*)GetFunctionByName(hNtdll, xor_str("RtlCreateUnicodeString"));
        return pRtlCreateUnicodeString(DestinationString, SourceString);
    }

     EXPORT BOOLEAN NTAPI RtlCreateUnicodeStringFromAsciiz(
        OUT    PUNICODE_STRING Destination,
        IN    PCSTR Source
    ){
        static function<BOOLEAN> pRtlCreateUnicodeStringFromAsciiz = (void*)GetFunctionByName(hNtdll, xor_str("RtlCreateUnicodeStringFromAsciiz"));
        return pRtlCreateUnicodeStringFromAsciiz(Destination, Source);
    }

     EXPORT BOOLEAN NTAPI RtlPrefixUnicodeString(
        IN    PUNICODE_STRING String1,
        IN    PUNICODE_STRING String2,
        IN    BOOLEAN CaseInSensitive
    ){
        static function<BOOLEAN> pRtlPrefixUnicodeString = (void*)GetFunctionByName(hNtdll, xor_str("RtlPrefixUnicodeString"));
        return pRtlPrefixUnicodeString(String1, String2, CaseInSensitive);
    }

     EXPORT NTSTATUS NTAPI RtlDuplicateUnicodeString(
        IN    BOOLEAN AllocateNew,
        IN    PUNICODE_STRING SourceString,
        OUT    PUNICODE_STRING TargetString
    ){
        static function<NTSTATUS> pRtlDuplicateUnicodeString = (void*)GetFunctionByName(hNtdll, xor_str("RtlDuplicateUnicodeString"));
        return pRtlDuplicateUnicodeString(AllocateNew, SourceString, TargetString);

    }

     EXPORT NTSTATUS NTAPI RtlUnicodeStringToInteger(
        IN    PUNICODE_STRING String,
        IN    ULONG Base OPTIONAL,
        OUT    PULONG Value
    ){
        static function<NTSTATUS> pRtlUnicodeStringToInteger = (void*)GetFunctionByName(hNtdll, xor_str("RtlUnicodeStringToInteger"));
        return pRtlUnicodeStringToInteger(String, Base, Value);
    }

     EXPORT NTSTATUS NTAPI RtlIntegerToUnicodeString(
        IN    ULONG Value,
        IN    ULONG Base OPTIONAL,
        IN OUT    PUNICODE_STRING String
    ){
        static function<NTSTATUS> pRtlIntegerToUnicodeString = (void*)GetFunctionByName(hNtdll, xor_str("RtlIntegerToUnicodeString"));
        return pRtlIntegerToUnicodeString(Value, Base, String);
    }

     EXPORT NTSTATUS NTAPI RtlGUIDFromString(
        IN    PUNICODE_STRING GuidString,
        OUT    GUID* Guid
    ){
        static function<NTSTATUS> pRtlGUIDFromString = (void*)GetFunctionByName(hNtdll, xor_str("RtlGUIDFromString"));
        return pRtlGUIDFromString(GuidString, Guid);
    }

     EXPORT NTSTATUS NTAPI RtlUpcaseUnicodeString(
        OUT    PUNICODE_STRING DestinationString,
        IN    PUNICODE_STRING SourceString,
        IN    BOOLEAN AllocateDestinationString
    ){
        static function<NTSTATUS> pRtlUpcaseUnicodeString = (void*)GetFunctionByName(hNtdll, xor_str("RtlUpcaseUnicodeString"));
        return pRtlUpcaseUnicodeString(DestinationString, SourceString, AllocateDestinationString);
    }

     EXPORT NTSTATUS NTAPI RtlDowncaseUnicodeString(
        OUT    PUNICODE_STRING DestinationString,
        IN    PUNICODE_STRING SourceString,
        IN    BOOLEAN AllocateDestinationString
    ){
        static function<NTSTATUS> pRtlDowncaseUnicodeString = (void*)GetFunctionByName(hNtdll, xor_str("RtlDowncaseUnicodeString"));
        return pRtlDowncaseUnicodeString(DestinationString, SourceString, AllocateDestinationString);
    }

     EXPORT NTSTATUS NTAPI RtlFormatCurrentUserKeyPath(
        OUT    PUNICODE_STRING CurrentUserKeyPath
    ){
        static function<NTSTATUS> pRtlFormatCurrentUserKeyPath = (void*)GetFunctionByName(hNtdll, xor_str("RtlFormatCurrentUserKeyPath"));
        return pRtlFormatCurrentUserKeyPath(CurrentUserKeyPath);
    }

     EXPORT VOID NTAPI RtlRaiseStatus(
        IN    NTSTATUS Status
    ){
        static function<VOID> pRtlRaiseStatus = (void*)GetFunctionByName(hNtdll, xor_str("RtlRaiseStatus"));
        return pRtlRaiseStatus(Status);
    }

     EXPORT ULONG NTAPI RtlRandom(
        IN OUT    PULONG Seed
    ){
        static function<ULONG> pRtlRandom = (void*)GetFunctionByName(hNtdll, xor_str("RtlRandom"));
        return pRtlRandom(Seed);
    }

     EXPORT NTSTATUS NTAPI RtlInitializeCriticalSection(
        IN    PRTL_CRITICAL_SECTION CriticalSection
    ){
        static function<NTSTATUS> pRtlInitializeCriticalSection = (void*)GetFunctionByName(hNtdll, xor_str("RtlInitializeCriticalSection"));
        return pRtlInitializeCriticalSection(CriticalSection);

    }

     EXPORT BOOL NTAPI RtlTryEnterCriticalSection(
        IN    PRTL_CRITICAL_SECTION CriticalSection
    ){
        static function<BOOL> pRtlTryEnterCriticalSection = (void*)GetFunctionByName(hNtdll, xor_str("RtlTryEnterCriticalSection"));
        return pRtlTryEnterCriticalSection(CriticalSection);
    }

     EXPORT NTSTATUS NTAPI RtlEnterCriticalSection(
        IN    PRTL_CRITICAL_SECTION CriticalSection
    ){
        static function<NTSTATUS> pRtlEnterCriticalSection = (void*)GetFunctionByName(hNtdll, xor_str("RtlEnterCriticalSection"));
        return pRtlEnterCriticalSection(CriticalSection);
    }

     EXPORT NTSTATUS NTAPI RtlLeaveCriticalSection(
        IN    PRTL_CRITICAL_SECTION CriticalSection
    ){
        static function<NTSTATUS> pRtlLeaveCriticalSection = (void*)GetFunctionByName(hNtdll, xor_str("RtlLeaveCriticalSection"));
        return pRtlLeaveCriticalSection(CriticalSection);
    }

     EXPORT NTSTATUS NTAPI RtlDeleteCriticalSection(
        IN    PRTL_CRITICAL_SECTION CriticalSection
    ){
        static function<NTSTATUS> pRtlDeleteCriticalSection = (void*)GetFunctionByName(hNtdll, xor_str("RtlDeleteCriticalSection"));
        return pRtlDeleteCriticalSection(CriticalSection);
    }

     EXPORT NTSTATUS NTAPI RtlCompressBuffer(
        IN    USHORT CompressionFormatAndEngine,
        IN    PUCHAR UncompressedBuffer,
        IN    ULONG UncompressedBufferSize,
        OUT    PUCHAR CompressedBuffer,
        IN    ULONG CompressedBufferSize,
        IN    ULONG UncompressedChunkSize,
        OUT    PULONG FinalCompressedSize,
        IN    PVOID WorkSpace
    ){
        static function<NTSTATUS> pRtlCompressBuffer = (void*)GetFunctionByName(hNtdll, xor_str("RtlCompressBuffer"));
        return pRtlCompressBuffer(CompressionFormatAndEngine, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, UncompressedChunkSize, FinalCompressedSize, WorkSpace);
    }

     EXPORT NTSTATUS NTAPI RtlDecompressBuffer(
        IN    USHORT CompressionFormat,
        OUT    PUCHAR UncompressedBuffer,
        IN    ULONG UncompressedBufferSize,
        IN    PUCHAR CompressedBuffer,
        IN    ULONG CompressedBufferSize,
        OUT    PULONG FinalUncompressedSize
    ){
        static function<NTSTATUS> pRtlDecompressBuffer = (void*)GetFunctionByName(hNtdll, xor_str("RtlDecompressBuffer"));
        return pRtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize);
    }

     EXPORT VOID NTAPI RtlInitializeHandleTable(
        IN    ULONG MaximumNumberOfHandles,
        IN    ULONG SizeOfHandleTableEntry,
        OUT    PRTL_HANDLE_TABLE HandleTable
    ){
        static function<VOID> pRtlInitializeHandleTable = (void*)GetFunctionByName(hNtdll, xor_str("RtlInitializeHandleTable"));
        return pRtlInitializeHandleTable(MaximumNumberOfHandles, SizeOfHandleTableEntry, HandleTable);
    }

     EXPORT PRTL_HANDLE_TABLE_ENTRY NTAPI RtlAllocateHandle(
        IN    PRTL_HANDLE_TABLE HandleTable,
        OUT    PULONG HandleIndex OPTIONAL
    ){
        static function<PRTL_HANDLE_TABLE_ENTRY> pRtlAllocateHandle = (void*)GetFunctionByName(hNtdll, xor_str("RtlAllocateHandle"));
        return pRtlAllocateHandle(HandleTable, HandleIndex);
    }

     EXPORT BOOLEAN NTAPI RtlFreeHandle(
        IN    PRTL_HANDLE_TABLE HandleTable,
        IN    PRTL_HANDLE_TABLE_ENTRY Handle
    ){
        static function<BOOLEAN> pRtlFreeHandle = (void*)GetFunctionByName(hNtdll, xor_str("RtlFreeHandle"));
        return pRtlFreeHandle(HandleTable, Handle);
    }

     EXPORT BOOLEAN NTAPI RtlIsValidIndexHandle(
        IN    PRTL_HANDLE_TABLE HandleTable,
        IN    ULONG HandleIndex,
        OUT    PRTL_HANDLE_TABLE_ENTRY* Handle
    ){
        static function<BOOLEAN> pRtlIsValidIndexHandle = (void*)GetFunctionByName(hNtdll, xor_str("RtlIsValidIndexHandle"));
        return pRtlIsValidIndexHandle(HandleTable, HandleIndex, Handle);
    }

     EXPORT NTSTATUS NTAPI RtlOpenCurrentUser(
        IN    ULONG DesiredAccess,
        OUT    PHANDLE CurrentUserKey
    ){
        static function<NTSTATUS> pRtlOpenCurrentUser = (void*)GetFunctionByName(hNtdll, xor_str("RtlOpenCurrentUser"));
        return pRtlOpenCurrentUser(DesiredAccess, CurrentUserKey);
    }

     EXPORT NTSTATUS NTAPI RtlCreateEnvironment(
        BOOLEAN CloneCurrentEnvironment,
        PVOID* Environment
    ){
        static function<NTSTATUS> pRtlCreateEnvironment = (void*)GetFunctionByName(hNtdll, xor_str("RtlCreateEnvironment"));
        return pRtlCreateEnvironment(CloneCurrentEnvironment, Environment);
    }

     EXPORT NTSTATUS NTAPI RtlQueryEnvironmentVariable_U(
        PVOID Environment,
        PUNICODE_STRING Name,
        PUNICODE_STRING Value
    ){
        static function<NTSTATUS> pRtlQueryEnvironmentVariable_U = (void*)GetFunctionByName(hNtdll, xor_str("RtlQueryEnvironmentVariable_U"));
        return pRtlQueryEnvironmentVariable_U(Environment, Name, Value);
    }

     EXPORT NTSTATUS NTAPI RtlSetEnvironmentVariable(
        PVOID* Environment,
        PUNICODE_STRING Name,
        PUNICODE_STRING Value
    ){
        static function<NTSTATUS> pRtlSetEnvironmentVariable = (void*)GetFunctionByName(hNtdll, xor_str("RtlSetEnvironmentVariable"));
        return pRtlSetEnvironmentVariable(Environment, Name, Value);
    }

     EXPORT NTSTATUS NTAPI RtlDestroyEnvironment(
        PVOID Environment
    ){
        static function<NTSTATUS> pRtlDestroyEnvironment = (void*)GetFunctionByName(hNtdll, xor_str("RtlDestroyEnvironment"));
        return pRtlDestroyEnvironment(Environment);
    }

     EXPORT BOOLEAN NTAPI RtlDosPathNameToNtPathName_U(
        IN    PWSTR DosPathName,
        OUT    PUNICODE_STRING NtPathName,
        OUT    PWSTR* NtFileNamePart OPTIONAL,
        OUT    PCURDIR DirectoryInfo OPTIONAL
    ){
        static function<BOOLEAN> pRtlDosPathNameToNtPathName_U = (void*)GetFunctionByName(hNtdll, xor_str("RtlDosPathNameToNtPathName_U"));
        return pRtlDosPathNameToNtPathName_U(DosPathName, NtPathName, NtFileNamePart, DirectoryInfo);
    }

     EXPORT NTSTATUS NTAPI RtlCreateUserProcess(
        PUNICODE_STRING NtImagePathName,
        ULONG Attributes,
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
        PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
        PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
        HANDLE ParentProcess,
        BOOLEAN InheritHandles,
        HANDLE DebugPort,
        HANDLE ExceptionPort,
        PRTL_USER_PROCESS_INFORMATION ProcessInformation
    ){
        static function<NTSTATUS> pRtlCreateUserProcess = (void*)GetFunctionByName(hNtdll, xor_str("RtlCreateUserProcess"));
        return pRtlCreateUserProcess(NtImagePathName, Attributes, ProcessParameters, ProcessSecurityDescriptor, ThreadSecurityDescriptor, ParentProcess, InheritHandles, DebugPort, ExceptionPort, ProcessInformation);
    }

     EXPORT NTSTATUS NTAPI RtlCreateUserThread(
        IN    HANDLE Process,
        IN    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
        IN    BOOLEAN CreateSuspended,
        IN    ULONG_PTR ZeroBits OPTIONAL,
        IN    SIZE_T MaximumStackSize OPTIONAL,
        IN    SIZE_T CommittedStackSize OPTIONAL,
        IN    PUSER_THREAD_START_ROUTINE StartAddress,
        IN    PVOID Parameter OPTIONAL,
        OUT    PHANDLE Thread OPTIONAL,
        OUT    PCLIENT_ID ClientId OPTIONAL
    ){
        static function<NTSTATUS> pRtlCreateUserThread = (void*)GetFunctionByName(hNtdll, xor_str("RtlCreateUserThread"));
        return pRtlCreateUserThread(Process, ThreadSecurityDescriptor, CreateSuspended, ZeroBits, MaximumStackSize, CommittedStackSize, StartAddress, Parameter, Thread, ClientId);
    }

     EXPORT HANDLE NTAPI RtlCreateHeap(
        IN    ULONG Flags,
        IN    PVOID BaseAddress OPTIONAL,
        IN    ULONG SizeToReserve,
        IN    ULONG SizeToCommit,
        IN    BOOLEAN Lock OPTIONAL,
        IN    PRTL_HEAP_PARAMETERS Definition OPTIONAL
    ){
        static function<HANDLE> pRtlCreateHeap = (void*)GetFunctionByName(hNtdll, xor_str("RtlCreateHeap"));
        return pRtlCreateHeap(Flags, BaseAddress, SizeToReserve, SizeToCommit, Lock, Definition);
    }

     EXPORT ULONG NTAPI RtlDestroyHeap(
        IN    HANDLE HeapHandle
    ){
        static function<ULONG> pRtlDestroyHeap = (void*)GetFunctionByName(hNtdll, xor_str("RtlDestroyHeap"));
        return pRtlDestroyHeap(HeapHandle);
    }

     EXPORT PVOID NTAPI RtlAllocateHeap(
        IN    HANDLE HeapHandle,
        IN    ULONG Flags,
        IN    SIZE_T Size
    ){
        static function<PVOID> pRtlAllocateHeap = (void*)GetFunctionByName(hNtdll, xor_str("RtlAllocateHeap"));
        return pRtlAllocateHeap(HeapHandle, Flags, Size);

    }

     EXPORT PVOID NTAPI RtlReAllocateHeap(
        IN    HANDLE HeapHandle,
        IN    ULONG Flags,
        IN    LPVOID Address,
        IN    SIZE_T Size
    ){
        static function<PVOID> pRtlReAllocateHeap = (void*)GetFunctionByName(hNtdll, xor_str("RtlReAllocateHeap"));
        return pRtlReAllocateHeap(HeapHandle, Flags, Address, Size);
    }

     EXPORT BOOLEAN NTAPI RtlFreeHeap(
        IN    HANDLE HeapHandle,
        IN    ULONG Flags,
        IN    PVOID Address
    ){
        static function<BOOLEAN> pRtlFreeHeap = (void*)GetFunctionByName(hNtdll, xor_str("RtlFreeHeap"));
        return pRtlFreeHeap(HeapHandle, Flags, Address);
    }

     EXPORT ULONG NTAPI RtlCompactHeap(
        IN    HANDLE HeapHandle,
        IN    ULONG Flags
    ){
        static function<ULONG> pRtlCompactHeap = (void*)GetFunctionByName(hNtdll, xor_str("RtlCompactHeap"));
        return pRtlCompactHeap(HeapHandle, Flags);
    }

     EXPORT BOOLEAN NTAPI RtlLockHeap(
        IN    HANDLE HeapHandle
    ){
        static function<BOOLEAN> pRtlLockHeap = (void*)GetFunctionByName(hNtdll, xor_str("RtlLockHeap"));
        return pRtlLockHeap(HeapHandle);
    }

     EXPORT BOOLEAN NTAPI RtlUnlockHeap(
        IN    HANDLE HeapHandle
    ){
        static function<BOOLEAN> pRtlUnlockHeap = (void*)GetFunctionByName(hNtdll, xor_str("RtlUnlockHeap"));
        return pRtlUnlockHeap(HeapHandle);
    }

     EXPORT ULONG NTAPI RtlSizeHeap(
        IN    HANDLE HeapHandle,
        IN    ULONG Flags,
        IN    PVOID Address
    ){
        static function<ULONG> pRtlSizeHeap = (void*)GetFunctionByName(hNtdll, xor_str("RtlSizeHeap"));
        return pRtlSizeHeap(HeapHandle, Flags, Address);
    }

     EXPORT BOOLEAN NTAPI RtlValidateHeap(
        IN    HANDLE HeapHandle,
        IN    ULONG Flags,
        IN    PVOID Address OPTIONAL
    ){
        static function<BOOLEAN> pRtlValidateHeap = (void*)GetFunctionByName(hNtdll, xor_str("RtlValidateHeap"));
        return pRtlValidateHeap(HeapHandle, Flags, Address);
    }

     EXPORT NTSTATUS NTAPI RtlCreateSecurityDescriptor(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    ULONG Revision
    ){
        static function<NTSTATUS> pRtlCreateSecurityDescriptor = (void*)GetFunctionByName(hNtdll, xor_str("RtlCreateSecurityDescriptor"));
        return pRtlCreateSecurityDescriptor(SecurityDescriptor, Revision);
    }

     EXPORT NTSTATUS NTAPI RtlGetDaclSecurityDescriptor(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        OUT    PBOOLEAN DaclPresent,
        OUT    PACL* Dacl,
        OUT    PBOOLEAN DaclDefaulted
    ){
        static function<NTSTATUS> pRtlGetDaclSecurityDescriptor = (void*)GetFunctionByName(hNtdll, xor_str("RtlGetDaclSecurityDescriptor"));
        return pRtlGetDaclSecurityDescriptor(SecurityDescriptor, DaclPresent, Dacl, DaclDefaulted);
    }

     EXPORT NTSTATUS NTAPI RtlSetDaclSecurityDescriptor(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    BOOLEAN DaclPresent,
        IN    PACL Dacl OPTIONAL,
        IN    BOOLEAN DaclDefaulted OPTIONAL
    ){
        static function<NTSTATUS> pRtlSetDaclSecurityDescriptor = (void*)GetFunctionByName(hNtdll, xor_str("RtlSetDaclSecurityDescriptor"));
        return pRtlSetDaclSecurityDescriptor(SecurityDescriptor, DaclPresent, Dacl, DaclDefaulted);
    }

     EXPORT NTSTATUS NTAPI RtlSetOwnerSecurityDescriptor(
        IN    PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN    PSID Owner OPTIONAL,
        IN    BOOLEAN OwnerDefaulted OPTIONAL
    ){
        static function<NTSTATUS> pRtlSetOwnerSecurityDescriptor = (void*)GetFunctionByName(hNtdll, xor_str("RtlSetOwnerSecurityDescriptor"));
        return pRtlSetOwnerSecurityDescriptor(SecurityDescriptor, Owner, OwnerDefaulted);
    }

     EXPORT NTSTATUS NTAPI RtlAllocateAndInitializeSid(
        IN    PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
        IN    UCHAR SubAuthorityCount,
        IN    ULONG SubAuthority0,
        IN    ULONG SubAuthority1,
        IN    ULONG SubAuthority2,
        IN    ULONG SubAuthority3,
        IN    ULONG SubAuthority4,
        IN    ULONG SubAuthority5,
        IN    ULONG SubAuthority6,
        IN    ULONG SubAuthority7,
        OUT    PSID* Sid
    ){
        static function<NTSTATUS> pRtlAllocateAndInitializeSid = (void*)GetFunctionByName(hNtdll, xor_str("RtlAllocateAndInitializeSid"));
        return pRtlAllocateAndInitializeSid(IdentifierAuthority, SubAuthorityCount, SubAuthority0, SubAuthority1, SubAuthority2, SubAuthority3, SubAuthority4, SubAuthority5, SubAuthority6, SubAuthority7, Sid);
    }

     EXPORT ULONG NTAPI RtlLengthSid(
        IN    PSID Sid
    ){
        static function<ULONG> pRtlLengthSid = (void*)GetFunctionByName(hNtdll, xor_str("RtlLengthSid"));
        return pRtlLengthSid(Sid);
    }

     EXPORT BOOLEAN NTAPI RtlEqualSid(
        IN    PSID Sid1,
        IN    PSID Sid2
    ){
        static function<BOOLEAN> pRtlEqualSid = (void*)GetFunctionByName(hNtdll, xor_str("RtlEqualSid"));
        return pRtlEqualSid(Sid1, Sid2);
    }

     EXPORT PVOID NTAPI RtlFreeSid(
        IN    PSID Sid
    ){
        static function<PVOID> pRtlFreeSid = (void*)GetFunctionByName(hNtdll, xor_str("RtlFreeSid"));
        return pRtlFreeSid(Sid);
    }

     EXPORT NTSTATUS NTAPI RtlCreateAcl(
        IN    PACL Acl,
        IN    ULONG AclLength,
        IN    ULONG AclRevision
    ){
        static function<NTSTATUS> pRtlCreateAcl = (void*)GetFunctionByName(hNtdll, xor_str("RtlCreateAcl"));
        return pRtlCreateAcl(Acl, AclLength, AclRevision);
    }

     EXPORT NTSTATUS NTAPI RtlGetAce(
        IN    PACL Acl,
        IN    ULONG AceIndex,
        OUT    PVOID* Ace
    ){
        static function<NTSTATUS> pRtlGetAce = (void*)GetFunctionByName(hNtdll, xor_str("RtlGetAce"));
        return pRtlGetAce(Acl, AceIndex, Ace);
    }

     EXPORT NTSTATUS NTAPI RtlAddAccessAllowedAce(
        IN OUT    PACL Acl,
        IN    ULONG AceRevision,
        IN    ACCESS_MASK AccessMask,
        IN    PSID Sid
    ){
        static function<NTSTATUS> pRtlAddAccessAllowedAce = (void*)GetFunctionByName(hNtdll, xor_str("RtlAddAccessAllowedAce"));
        return pRtlAddAccessAllowedAce(Acl, AceRevision, AccessMask, Sid);
    }

     EXPORT NTSTATUS NTAPI RtlAddAccessAllowedAceEx(
        IN OUT    PACL Acl,
        IN    ULONG AceRevision,
        IN    ULONG AceFlags,
        IN    ULONG AccessMask,
        IN    PSID Sid
    ){
        static function<NTSTATUS> pRtlAddAccessAllowedAceEx = (void*)GetFunctionByName(hNtdll, xor_str("RtlAddAccessAllowedAceEx"));
        return pRtlAddAccessAllowedAceEx(Acl, AceRevision, AceFlags, AccessMask, Sid);
    }

     EXPORT ULONG NTAPI RtlNtStatusToDosErrorNoTeb(
        NTSTATUS Status
    ){
        static function<ULONG> pRtlNtStatusToDosErrorNoTeb = (void*)GetFunctionByName(hNtdll, xor_str("RtlNtStatusToDosErrorNoTeb"));
        return pRtlNtStatusToDosErrorNoTeb(Status);
    }

     EXPORT NTSTATUS NTAPI RtlGetLastNtStatus(
    ){
        static function<NTSTATUS> pRtlGetLastNtStatus = (void*)GetFunctionByName(hNtdll, xor_str("RtlGetLastNtStatus"));
        return pRtlGetLastNtStatus();
    }

     EXPORT ULONG NTAPI RtlGetLastWin32Error(
    ){
        static function<ULONG> pRtlGetLastWin32Error = (void*)GetFunctionByName(hNtdll, xor_str("RtlGetLastWin32Error"));
        return pRtlGetLastWin32Error();
    }

     EXPORT VOID NTAPI RtlSetLastWin32Error(
        ULONG WinError
    ){
        static function<VOID> pRtlSetLastWin32Error = (void*)GetFunctionByName(hNtdll, xor_str("RtlSetLastWin32Error"));
        return pRtlSetLastWin32Error(WinError);
    }

     EXPORT VOID NTAPI RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
        NTSTATUS Status
    ){
        static function<VOID> pRtlSetLastWin32ErrorAndNtStatusFromNtStatus = (void*)GetFunctionByName(hNtdll, xor_str("RtlSetLastWin32ErrorAndNtStatusFromNtStatus"));
        return pRtlSetLastWin32ErrorAndNtStatusFromNtStatus(Status);
    }

     EXPORT VOID NTAPI DbgBreakPoint(
        VOID
    ){
        static function<VOID> pDbgBreakPoint = (void*)GetFunctionByName(hNtdll, xor_str("DbgBreakPoint"));
        return pDbgBreakPoint();
    }

     EXPORT ULONG _cdecl DbgPrint(
        PCH Format,
        ...
    ){
        va_list args;
        va_start(args, Format);
        static function<ULONG> pDbgPrint = (void*)GetFunctionByName(hNtdll, xor_str("DbgPrint"));
        return pDbgPrint(Format, args);

    }

     EXPORT NTSTATUS NTAPI LdrLoadDll(
        IN    PWSTR DllPath OPTIONAL,
        IN    PULONG DllCharacteristics OPTIONAL,
        IN    PUNICODE_STRING DllName,
        OUT    PVOID* DllHandle
    ){
        static function<NTSTATUS> pLdrLoadDll = (void*)GetFunctionByName(hNtdll, xor_str("LdrLoadDll"));
        return pLdrLoadDll(DllPath, DllCharacteristics, DllName, DllHandle);
    }

     EXPORT NTSTATUS NTAPI LdrGetDllHandle(
        IN    PWSTR DllPath OPTIONAL,
        IN    PULONG DllCharacteristics OPTIONAL,
        IN    PUNICODE_STRING DllName,
        OUT    PVOID* DllHandle
    ){
        static function<NTSTATUS> pLdrGetDllHandle = (void*)GetFunctionByName(hNtdll, xor_str("LdrGetDllHandle"));
        return pLdrGetDllHandle(DllPath, DllCharacteristics, DllName, DllHandle);
    }

     EXPORT NTSTATUS NTAPI LdrUnloadDll(
        IN    PVOID DllHandle
    ){
        static function<NTSTATUS> pLdrUnloadDll = (void*)GetFunctionByName(hNtdll, xor_str("LdrUnloadDll"));
        return pLdrUnloadDll(DllHandle);
    }

     EXPORT NTSTATUS NTAPI LdrGetProcedureAddress(
        IN    PVOID DllHandle,
        IN    PANSI_STRING ProcedureName OPTIONAL,
        IN    ULONG ProcedureNumber OPTIONAL,
        OUT    PVOID* ProcedureAddress
    ){
        static function<NTSTATUS> pLdrGetProcedureAddress = (void*)GetFunctionByName(hNtdll, xor_str("LdrGetProcedureAddress"));
        return pLdrGetProcedureAddress(DllHandle, ProcedureName, ProcedureNumber, ProcedureAddress);
    }

     EXPORT NTSTATUS NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
     {
         static function<NTSTATUS> pNtCreateThread = (void*)GetFunctionByName(hNtdll, xor_str("NtCreateThread"));
        return pNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
     }

     EXPORT  NTSTATUS NtGetThreadContext(HANDLE ThreadHandle, PCONTEXT Context)
     {
        static function<NTSTATUS> pNtGetThreadContext = (void*)GetFunctionByName(hNtdll, xor_str("NtGetThreadContext"));
        return pNtGetThreadContext(ThreadHandle, Context);
     }

     EXPORT NTSTATUS NtSetThreadContext(HANDLE ThreadHandle, PCONTEXT Context)
     {
         static function<NTSTATUS> pNtSetThreadContext = (void*)GetFunctionByName(hNtdll, xor_str("NtSetThreadContext"));
        return pNtSetThreadContext(ThreadHandle, Context);
     }
    
#pragma endregion

#pragma endregion
