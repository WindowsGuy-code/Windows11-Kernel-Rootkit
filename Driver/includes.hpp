#include "Windows.h"
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <vector>
#include <string>
#include <TlHelp32.h>
#include "ntdef.h"
#include "ks.h"
#include "stdio.h"
#include <thread>
//#include "MemoryManager.hpp"
#include <winternl.h>
#include <atomic>
#include <filesystem>
#include "ntdefs.h"
#include <tchar.h>
#include <stdlib.h>
#include <psapi.h>
#include <cstdint>
#include <shared_mutex>
#include <chrono>
#include "stdafx.h"
#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntstatus.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <intsafe.h>


#pragma comment(lib, "ntdll.lib")
