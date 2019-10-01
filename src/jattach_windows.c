/*
 * Copyright 2016 Andrei Pangin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

typedef HMODULE (WINAPI *GetModuleHandle_t)(LPCTSTR lpModuleName);
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef int (__stdcall *JVM_EnqueueOperation_t)(char* cmd, char* arg0, char* arg1, char* arg2, char* pipename);

typedef struct {
    GetModuleHandle_t GetModuleHandleA;
    GetProcAddress_t GetProcAddress;
    char strJvm[32];
    char strEnqueue[32];
    char pipeName[MAX_PATH];
    char args[4][MAX_PATH];
} CallData;


#pragma check_stack(off)

// This code is executed in remote JVM process; be careful with memory it accesses
DWORD WINAPI remote_thread_entry(LPVOID param) {
    CallData* data = (CallData*)param;

    HMODULE libJvm = data->GetModuleHandleA(data->strJvm);
    if (libJvm == NULL) {
        return 1001;
    }

    JVM_EnqueueOperation_t JVM_EnqueueOperation = (JVM_EnqueueOperation_t)data->GetProcAddress(libJvm, data->strEnqueue + 1);
    if (JVM_EnqueueOperation == NULL) {
        // Try alternative name: _JVM_EnqueueOperation@20
        data->strEnqueue[21] = '@';
        data->strEnqueue[22] = '2';
        data->strEnqueue[23] = '0';
        data->strEnqueue[24] = 0;

        JVM_EnqueueOperation = (JVM_EnqueueOperation_t)data->GetProcAddress(libJvm, data->strEnqueue);
        if (JVM_EnqueueOperation == NULL) {
            return 1002;
        }
    }

    return (DWORD)JVM_EnqueueOperation(data->args[0], data->args[1], data->args[2], data->args[3], data->pipeName);
}

#pragma check_stack


// Allocate executable memory in remote process
static LPTHREAD_START_ROUTINE allocate_code(HANDLE hProcess) {
    SIZE_T codeSize = 1024;
    LPVOID code = VirtualAllocEx(hProcess, NULL, codeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (code != NULL) {
        WriteProcessMemory(hProcess, code, remote_thread_entry, codeSize, NULL);
    }
    return (LPTHREAD_START_ROUTINE)code;
}

// Allocate memory for CallData in remote process
static LPVOID allocate_data(HANDLE hProcess, char* pipeName, int argc, char** argv) {
    CallData data;
    data.GetModuleHandleA = GetModuleHandleA;
    data.GetProcAddress = GetProcAddress;
    strcpy(data.strJvm, "jvm");
    strcpy(data.strEnqueue, "_JVM_EnqueueOperation");
    strcpy(data.pipeName, pipeName);

    int i;
    for (i = 0; i < 4; i++) {
        strcpy(data.args[i], i < argc ? argv[i] : "");
    }

    LPVOID remoteData = VirtualAllocEx(hProcess, NULL, sizeof(CallData), MEM_COMMIT, PAGE_READWRITE);
    if (remoteData != NULL) {
        WriteProcessMemory(hProcess, remoteData, &data, sizeof(data), NULL);
    }
    return remoteData;
}

static void print_error(const char* msg, DWORD code) {
    printf("%s (error code = %d)\n", msg, code);
}

// If the process is owned by another user, request SeDebugPrivilege to open it.
// Debug privileges are typically granted to Administrators.
static int enable_debug_privileges() {
    HANDLE hToken;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, FALSE, &hToken)) {
        if (!ImpersonateSelf(SecurityImpersonation) ||
            !OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, FALSE, &hToken)) {
            return 0;
        }
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        return 0;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return success ? 1 : 0;
}

// Fail if attaching 64-bit jattach to 32-bit JVM or vice versa
static int check_bitness(HANDLE hProcess) {
#ifdef _WIN64
    BOOL targetWow64 = FALSE;
    if (IsWow64Process(hProcess, &targetWow64) && targetWow64) {
        printf("Cannot attach 64-bit process to 32-bit JVM\n");
        return 0;
    }
#else
    BOOL thisWow64 = FALSE;
    BOOL targetWow64 = FALSE;
    if (IsWow64Process(GetCurrentProcess(), &thisWow64) && IsWow64Process(hProcess, &targetWow64)) {
        if (thisWow64 != targetWow64)  {
            printf("Cannot attach 32-bit process to 64-bit JVM\n");
            return 0;
        }
    }
#endif
    return 1;
}

// The idea of Dynamic Attach on Windows is to inject a thread into remote JVM
// that calls JVM_EnqueueOperation() function exported by HotSpot DLL
static int inject_thread(int pid, char* pipeName, int argc, char** argv) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    if (hProcess == NULL && GetLastError() == ERROR_ACCESS_DENIED) {
        if (!enable_debug_privileges()) {
            print_error("Not enough privileges", GetLastError());
            return 0;
        }
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    }
    if (hProcess == NULL) {
        print_error("Could not open process", GetLastError());
        return 0;
    }

    if (!check_bitness(hProcess)) {
        CloseHandle(hProcess);
        return 0;
    }

    LPTHREAD_START_ROUTINE code = allocate_code(hProcess);
    LPVOID data = code != NULL ? allocate_data(hProcess, pipeName, argc, argv) : NULL;
    if (data == NULL) {
        print_error("Could not allocate memory in target process", GetLastError());
        CloseHandle(hProcess);
        return 0;
    }

    int success = 1;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, code, data, 0, NULL);
    if (hThread == NULL) {
        print_error("Could not create remote thread", GetLastError());
        success = 0;
    } else {
        printf("Connected to remote process\n");
        WaitForSingleObject(hThread, INFINITE);
        DWORD exitCode;
        GetExitCodeThread(hThread, &exitCode);
        if (exitCode != 0) {
            print_error("Attach is not supported by the target process", exitCode);
            success = 0;
        }
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProcess, code, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, data, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return success;
}

// JVM response is read from the pipe and mirrored to stdout
static int read_response(HANDLE hPipe) {
    ConnectNamedPipe(hPipe, NULL);

    char buf[8192];
    DWORD bytesRead;
    if (!ReadFile(hPipe, buf, sizeof(buf) - 1, &bytesRead, NULL)) {
        print_error("Error reading response", GetLastError());
        return 1;
    }

    // First line of response is the command result code
    buf[bytesRead] = 0;
    int result = atoi(buf);

    do {
        fwrite(buf, 1, bytesRead, stdout);
    } while (ReadFile(hPipe, buf, sizeof(buf), &bytesRead, NULL));

    return result;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("jattach " JATTACH_VERSION " built on " __DATE__ "\n"
               "Copyright 2018 Andrei Pangin\n"
               "\n"
               "Usage: jattach <pid> <cmd> [args ...]\n");
        return 1;
    }

    int pid = atoi(argv[1]);

    char pipeName[MAX_PATH];
    sprintf(pipeName, "\\\\.\\pipe\\javatool%d", GetTickCount());
    HANDLE hPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 4096, 8192, NMPWAIT_USE_DEFAULT_WAIT, NULL);
    if (hPipe == NULL) {
        print_error("Could not create pipe", GetLastError());
        return 1;
    }

    if (!inject_thread(pid, pipeName, argc - 2, argv + 2)) {
        CloseHandle(hPipe);
        return 1;
    }

    printf("Response code = ");
    fflush(stdout);

    int result = read_response(hPipe);
    printf("\n");
    CloseHandle(hPipe);

    return result;
}
