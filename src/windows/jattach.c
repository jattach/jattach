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
#include <jni.h>

typedef HMODULE(WINAPI* GetModuleHandle_t)(LPCTSTR lpModuleName);
typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef int(__stdcall* JVM_EnqueueOperation_t)(char* cmd, char* arg0, char* arg1, char* arg2, char* pipename);
typedef int(__stdcall* JNI_GetCreatedJavaVMs_t)(JavaVM**, long, long*);
typedef void*(__stdcall* JVM_FindClassFromBootLoader_t)(JNIEnv* jniEnv, char* className);

typedef struct {
    GetModuleHandle_t GetModuleHandleA;
    GetProcAddress_t GetProcAddress;
    char j9ClassName[32];

    char IntegerClass[64];
    char valueOf[16];
    char valueOfDescriptor[64];

    char ReplyClass[64];
    char ReplyConstructorDescriptor[128];
    long replyPort;
    char replyKey[32];
    char strEmpty[2];

    char AttachmentClass[64];
    char AttachmentConstructorDescriptor[128];
    char AttachmentStartMethod[32];
    char AttachmentStartDescriptor[32];

    char initMethod[16];

    char strJvm[32];
    char strFindClass[32];
    char strGetVM[32];
    char strEnqueue[32];

    char pipeName[MAX_PATH];
    char args[4][MAX_PATH];
} CallData;

 


#pragma check_stack(off)

// This code is executed in remote JVM process; be careful with memory it accesses
static DWORD WINAPI remote_thread_entry(LPVOID param) {
    CallData* data = (CallData*)param;

    HMODULE libJvm = data->GetModuleHandleA(data->strJvm);

    if (libJvm == NULL) {
        return 1001;
    }

    //try to find class java/lang/J9VMInternals
    JNI_GetCreatedJavaVMs_t JNI_GetCreatedJavaVMs = (JNI_GetCreatedJavaVMs_t)data->GetProcAddress(libJvm, data->strGetVM + 1);
    if (JNI_GetCreatedJavaVMs == NULL) {
        return 1003;
    }

    long nVMs;
    JavaVM* vm = NULL;
    JavaVM* buffer[1];
    JNI_GetCreatedJavaVMs(buffer, 1, &nVMs);
    vm = buffer[0];
    if (vm == NULL) {
        return 1003;
    }
  
    JNIEnv* jni;
    (*vm)->AttachCurrentThread(vm, (JNIEnv*)&jni, NULL);
    if (jni == NULL) {
        return 1003;
    }

    JVM_FindClassFromBootLoader_t JVM_FindClassFromBootLoader = (JVM_FindClassFromBootLoader_t)data->GetProcAddress(libJvm, data->strFindClass + 1);
    if (JVM_FindClassFromBootLoader != NULL) {
        void* j9Class = JVM_FindClassFromBootLoader(jni, data->j9ClassName);
        if (j9Class != NULL) {
            jclass IntegerClass = (*jni)->FindClass(jni, data->IntegerClass);
            jmethodID IntegerValueOf = (*jni)->GetStaticMethodID(jni, IntegerClass, data->valueOf, data->valueOfDescriptor);
            jobject port = (*jni)->CallStaticObjectMethod(jni, IntegerClass, IntegerValueOf, data->replyPort);

            jclass replyClass = (*jni)->FindClass(jni, data->ReplyClass);
            if (replyClass == NULL) {
                (*vm)->DetachCurrentThread(vm);
                return 1004;
            }

            jstring replyKey = (*jni)->NewStringUTF(jni, data->replyKey);

            jstring emptyString = (*jni)->NewStringUTF(jni, data->strEmpty);
            jmethodID ReplyConstructor = (*jni)->GetMethodID(jni, replyClass, data->initMethod, data->ReplyConstructorDescriptor);
            if (ReplyConstructor == NULL) {
                (*vm)->DetachCurrentThread(vm);
                return 1005;
            }
            jobject reply = (*jni)->NewObject(jni, replyClass, ReplyConstructor, port, replyKey, emptyString, 0);

            jclass AttachmentClass = (*jni)->FindClass(jni, data->AttachmentClass);
            if (AttachmentClass == NULL) {
                (*vm)->DetachCurrentThread(vm);
                return 1006;
            }
            jmethodID AttachmentConstructor = (*jni)->GetMethodID(jni, AttachmentClass, data->initMethod, data->AttachmentConstructorDescriptor);
            if (AttachmentConstructor == NULL) {
                (*vm)->DetachCurrentThread(vm);
                return 1007;
            }
            jobject attachment = (*jni)->NewObject(jni, AttachmentClass, AttachmentConstructor, NULL, reply);
            jmethodID start = (*jni)->GetMethodID(jni, AttachmentClass, data->AttachmentStartMethod, data->AttachmentStartDescriptor);

            (*jni)->CallVoidMethod(jni, attachment, start);
            (*vm)->DetachCurrentThread(vm);
            return 1100;
        }
    }

    (*vm)->DetachCurrentThread(vm);

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

static VOID WINAPI remote_thread_entry_end() {
}

#pragma check_stack


// Allocate executable memory in remote process
static LPTHREAD_START_ROUTINE allocate_code(HANDLE hProcess) {
    SIZE_T codeSize = (SIZE_T)remote_thread_entry_end - (SIZE_T)remote_thread_entry;
    LPVOID code = VirtualAllocEx(hProcess, NULL, codeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (code != NULL) {
        WriteProcessMemory(hProcess, code, remote_thread_entry, codeSize, NULL);
    }
    return (LPTHREAD_START_ROUTINE)code;
}

// Allocate memory for CallData in remote process
static LPVOID allocate_data(HANDLE hProcess, char* pipeName, int argc, char** argv, long port, unsigned long long key) {
    CallData data;
    data.GetModuleHandleA = GetModuleHandleA;
    data.GetProcAddress = GetProcAddress;
    strcpy(data.j9ClassName, "java/lang/J9VMInternals");

    strcpy(data.IntegerClass, "java/lang/Integer");
    strcpy(data.valueOf, "valueOf");
    strcpy(data.valueOfDescriptor, "(I)Ljava/lang/Integer;");

    strcpy(data.ReplyClass, "openj9/internal/tools/attach/target/Reply");
    strcpy(data.ReplyConstructorDescriptor, "(Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;J)V");
    data.replyPort = port;
    char strKey[32];
    snprintf(strKey, sizeof(strKey), "%016llx", key);
    strKey[16] = 0;
    strcpy(data.replyKey, strKey);
    strcpy(data.strEmpty, "");

    strcpy(data.AttachmentClass, "openj9/internal/tools/attach/target/Attachment");
    strcpy(data.AttachmentConstructorDescriptor, "(Lopenj9/internal/tools/attach/target/AttachHandler;Lopenj9/internal/tools/attach/target/Reply;)V");
    strcpy(data.AttachmentStartMethod, "start");
    strcpy(data.AttachmentStartDescriptor, "()V");

    strcpy(data.initMethod, "<init>");

    strcpy(data.strJvm, "jvm");
    strcpy(data.strEnqueue, "_JVM_EnqueueOperation");
    strcpy(data.strGetVM, "_JNI_GetCreatedJavaVMs");
    strcpy(data.strFindClass, "_JVM_FindClassFromBootLoader");


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
        if (thisWow64 != targetWow64) {
            printf("Cannot attach 32-bit process to 64-bit JVM\n");
            return 0;
        }
    }
#endif
    return 1;
}

static unsigned long long random_key() {
    unsigned long long key = time(NULL) * 0xc6a4a7935bd1e995ULL;
    return key;
}
static void print_unescaped(char* str) {
    char* p = strchr(str, '\n');
    if (p != NULL) {
        *p = 0;
    }

    while ((p = strchr(str, '\\')) != NULL) {
        switch (p[1]) {
        case 0:
            break;
        case 'f':
            *p = '\f';
            break;
        case 'n':
            *p = '\n';
            break;
        case 'r':
            *p = '\r';
            break;
        case 't':
            *p = '\t';
            break;
        default:
            *p = p[1];
        }
        fwrite(str, 1, p - str + 1, stdout);
        str = p + 2;
    }

    fwrite(str, 1, strlen(str), stdout);

    printf("\n");
    fflush(stdout);
}

static int write_command(SOCKET client, const char* cmd) {
    size_t len = strlen(cmd) + 1;
    size_t off = 0;
    while (off < len) {
        size_t bytes = send(client, cmd + off, len - off,0);
        if (bytes <= 0) {
            return -1;
        }
        off += bytes;
    }
    return 0;
}

static void detach(SOCKET client) {
    if (write_command(client, "ATTACH_DETACHED") != 0) {
        return;
    }

    char buf[256];
    size_t bytes;
    do {
        bytes = recv(client, buf, sizeof(buf), 0);
    } while (bytes > 0 && buf[bytes - 1] != 0);
}

static int read_socket_response(SOCKET client, const char* cmd) {
    size_t size = 8192;
    char* buf = calloc(size, sizeof(char));
    size_t off = 0;

    int delayCounter = 0;
    while (buf != NULL) {
        int bytes = recv(client, buf + off, size - off, 0);
        if (bytes == 0) {
            fprintf(stderr, "Unexpected EOF reading response\n");
            return 1;
        }
        else if (bytes < 0) {
            if (delayCounter++ < 5) {
                //for some commands, the response is sent with a delay
                Sleep(100);
                continue;
            }          
            perror("Error reading response");
            return 1;
        }
        off += bytes;
        if (buf[off - 1] == 0) {
            break;
        }


        if (off >= size) {
            buf = realloc(buf, size *= 2);
        }

    }

    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate memory for response\n");
        return 1;
    }

    int result = 0;

    if (strncmp(cmd, "ATTACH_LOADAGENT", 16) == 0) {
        if (strncmp(buf, "ATTACH_ACK", 10) != 0) {
            // AgentOnLoad error code comes right after AgentInitializationException
            result = strncmp(buf, "ATTACH_ERR AgentInitializationException", 39) == 0 ? atoi(buf + 39) : -1;
        }
    }
    else if (strncmp(cmd, "ATTACH_DIAGNOSTICS:", 19) == 0) {
        char* p = strstr(buf, "openj9_diagnostics.string_result=");
        if (p != NULL) {
            // The result of a diagnostic command is encoded in Java Properties format
            print_unescaped(p + 33);
            free(buf);
            return result;
        }
    }

    buf[off - 1] = '\n';
    fwrite(buf, 1, off, stdout);
    fflush(stdout);
    free(buf);
    return result;
}

static void translate_command(char* buf, size_t bufsize, int argc, char** argv) {
    const char* cmd = argv[0];

    if (strcmp(cmd, "load") == 0 && argc >= 2) {
        if (argc > 2 && strcmp(argv[2], "true") == 0) {
            snprintf(buf, bufsize, "ATTACH_LOADAGENTPATH(%s,%s)", argv[1], argc > 3 ? argv[3] : "");
        }
        else {
            snprintf(buf, bufsize, "ATTACH_LOADAGENT(%s,%s)", argv[1], argc > 3 ? argv[3] : "");
        }

    }
    else if (strcmp(cmd, "jcmd") == 0) {
        snprintf(buf, bufsize, "ATTACH_DIAGNOSTICS:%s,%s", argc > 1 ? argv[1] : "help", argc > 2 ? argv[2] : "");

    }
    else if (strcmp(cmd, "threaddump") == 0) {
        snprintf(buf, bufsize, "ATTACH_DIAGNOSTICS:Thread.print,%s", argc > 1 ? argv[1] : "");

    }
    else if (strcmp(cmd, "dumpheap") == 0) {
        snprintf(buf, bufsize, "ATTACH_DIAGNOSTICS:Dump.heap,%s", argc > 1 ? argv[1] : "");

    }
    else if (strcmp(cmd, "inspectheap") == 0) {
        snprintf(buf, bufsize, "ATTACH_DIAGNOSTICS:GC.class_histogram,%s", argc > 1 ? argv[1] : "");

    }
    else if (strcmp(cmd, "datadump") == 0) {
        snprintf(buf, bufsize, "ATTACH_DIAGNOSTICS:Dump.java,%s", argc > 1 ? argv[1] : "");

    }
    else if (strcmp(cmd, "properties") == 0) {
        strcpy(buf, "ATTACH_GETSYSTEMPROPERTIES");

    }
    else if (strcmp(cmd, "agentProperties") == 0) {
        strcpy(buf, "ATTACH_GETAGENTPROPERTIES");

    }
    else {
        snprintf(buf, bufsize, "%s", cmd);
    }

    buf[bufsize - 1] = 0;
}

#include <winsock.h>

#pragma comment(lib, "Ws2_32.lib")
static SOCKET create_attach_socket(int* port) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s != -1) {
        struct sockaddr_in addr = { AF_INET, 0 };
        int addrlen = sizeof(addr);
        if (bind(s, (struct sockaddr*)&addr, addrlen) == 0 && listen(s, 0) == 0
            && getsockname(s, (struct sockaddr*)&addr, &addrlen) == 0) {
            *port = ntohs(addr.sin_port);
            return s;
        }
    }

    closesocket(s);
    return -1;
}

static SOCKET accept_client(SOCKET s, unsigned long long key) {
    struct timeval tv = { 5, 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*) &tv, sizeof(tv));

    SOCKET client = accept(s, NULL, NULL);
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    if (client < 0) {
        perror("JVM did not respond");
        return -1;
    }

    char buf[35];
    int off = 0;
    while (off < sizeof(buf)) {
        int bytes = recv(client, buf + off, sizeof(buf) - off, 0);
        if (bytes <= 0) {
            fprintf(stderr, "The JVM connection was prematurely closed\n");
            close(client);
            return -1;
        }
        off += bytes;
    }

    char expected[35];
    return client;
    snprintf(expected, sizeof(expected), "ATTACH_CONNECTED %016llx ", key);
    if (memcmp(buf, expected, sizeof(expected) - 1) != 0) {
        fprintf(stderr, "Unexpected JVM response\n");
        close(client);
        return -1;
    }

    return client;
}

// The idea of Dynamic Attach on Windows is to inject a thread into remote JVM
// that calls JVM_EnqueueOperation() function exported by HotSpot DLL
static int inject_thread(int pid, char* pipeName, int argc, char** argv, int* isOpenJ9) {
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
    int port;
    SOCKET socket = create_attach_socket(&port);
    if (socket < 0) {
        printf("Failed to listen to attach socket for OpenJ9 VM\n");
    }
    unsigned long long key = random_key();
    LPTHREAD_START_ROUTINE code = allocate_code(hProcess);
    LPVOID data = code != NULL ? allocate_data(hProcess, pipeName, argc, argv, port, key) : NULL;
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
    }
    else {
        printf("Connected");
        WaitForSingleObject(hThread, INFINITE);
        DWORD exitCode;
        GetExitCodeThread(hThread, &exitCode);
        if (exitCode == 1100) {
            *isOpenJ9 = 1;
            if (socket != -1) {
                SOCKET client = accept_client(socket, key);
                closesocket(socket);
                if (client != -1) {
                    printf(" to remote OpenJ9 process\n");
                    char cmd[8192];
                    translate_command(cmd, sizeof(cmd), argc, argv);
                    if (write_command(client, cmd) != 0) {
                        success = 0;
                        printf("Error writing to socket\r\n");
                        closesocket(client);
                    }
                    else {
                        int result = read_socket_response(client, cmd);
                        if (result != 1) {
                            detach(client);
                        }
                        closesocket(client);
                    }
                }
            }
        } else if (exitCode != 0) {
            print_error("\nAttach is not supported by the target process", exitCode);
            success = 0;
        }
        else {
            printf(" to remote HotSpot process\n");
        }
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProcess, code, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, data, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return success;
}

// JVM response is read from the pipe and mirrored to stdout
static int read_pipe_response(HANDLE hPipe) {
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
               "Copyright 2021 Andrei Pangin\n"
               "\n"
               "Usage: jattach <pid> <cmd> [args ...]\n"
               "\n"
               "Commands:\n"
               "    load  threaddump   dumpheap  setflag    properties\n"
               "    jcmd  inspectheap  datadump  printflag  agentProperties\n"
               );
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
    int isOpenJ9 = 0;
    if (!inject_thread(pid, pipeName, argc - 2, argv + 2, &isOpenJ9)) {
        CloseHandle(hPipe);
        return 1;
    }
    if (isOpenJ9) {
        CloseHandle(hPipe);
        return 0;
    }
    printf("Response code = ");
    fflush(stdout);

    int result = read_pipe_response(hPipe);
    printf("\n");
    CloseHandle(hPipe);

    return result;
}
