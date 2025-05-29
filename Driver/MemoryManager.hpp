#define UNICODE
#define _UNICODE

//OOOPS: Forgot to just include "includes.hpp" here
#include "Windows.h"
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <vector>
#include <string>
#include <TlHelp32.h>
using namespace std;

class CMemoryManager {
private:
    HANDLE m_hProcess;
    DWORD m_dwProcessId;
    std::vector<MODULEENTRY32> m_Modules;

public:
    static DWORD GetProcId(const char* procname) {
        DWORD pid = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
            return 0;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe)) {
            do {
#ifdef UNICODE
                std::wstring wprocname(procname, procname + strlen(procname));
                if (wcscmp(pe.szExeFile, wprocname.c_str()) == 0)
#else
                if (strcmp(pe.szExeFile, procname) == 0)
#endif
                {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
        return pid;
    }

    bool Attach(const std::string& strProcessName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32 ProcEntry;
        ProcEntry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &ProcEntry)) {
            if (!wcscmp(ProcEntry.szExeFile, std::wstring(strProcessName.begin(), strProcessName.end()).c_str())) {
                CloseHandle(hSnapshot);
                m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcEntry.th32ProcessID);
                m_dwProcessId = ProcEntry.th32ProcessID;
                return true;
            }
        } else {
            CloseHandle(hSnapshot);
            return false;
        }

        while (Process32Next(hSnapshot, &ProcEntry)) {
            if (!wcscmp(ProcEntry.szExeFile, std::wstring(strProcessName.begin(), strProcessName.end()).c_str())) {
                m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcEntry.th32ProcessID);
                m_dwProcessId = ProcEntry.th32ProcessID;
                CloseHandle(hSnapshot);
                return true;
            }
        }
        CloseHandle(hSnapshot);
        return false;
    }

    bool GrabModule(const std::string& strModuleName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_dwProcessId);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        MODULEENTRY32 ModEntry;
        ModEntry.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(hSnapshot, &ModEntry)) {
            if (!wcscmp(ModEntry.szModule, std::wstring(strModuleName.begin(), strModuleName.end()).c_str())) {
                CloseHandle(hSnapshot);
                m_Modules.push_back(ModEntry);
                return true;
            }
        } else {
            CloseHandle(hSnapshot);
            return false;
        }

        while (Module32Next(hSnapshot, &ModEntry)) {
            if (!wcscmp(ModEntry.szModule, std::wstring(strModuleName.begin(), strModuleName.end()).c_str())) {
                m_Modules.push_back(ModEntry);
                CloseHandle(hSnapshot);
                return true;
            }
        }
        CloseHandle(hSnapshot);
        return false;
    }

    CMemoryManager() {
        m_hProcess = INVALID_HANDLE_VALUE;
        m_dwProcessId = 0;
        m_Modules.clear();
    }

    CMemoryManager(const std::string& strProcessName = "csgo.exe") {
        m_hProcess = INVALID_HANDLE_VALUE;
        m_dwProcessId = 0;
        m_Modules.clear();
        if (!Attach(strProcessName)) throw;
    }

    template <class T>
    inline bool Read(DWORD dwAddress, T& Value) {
        return ReadProcessMemory(m_hProcess, reinterpret_cast<LPVOID>(dwAddress), &Value, sizeof(T), NULL) == TRUE;
    }

    template <class T>
    inline bool Write(DWORD dwAddress, const T& Value) {
        return WriteProcessMemory(m_hProcess, reinterpret_cast<LPVOID>(dwAddress), &Value, sizeof(T), NULL) == TRUE;
    }

    HANDLE GetHandle() { return m_hProcess; }
    DWORD GetProcId() { return m_dwProcessId; }
    std::vector<MODULEENTRY32> GetModules() { return m_Modules; }
};


