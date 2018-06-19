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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#define MAX_PATH 1024


#ifdef __APPLE__

// macOS has a secure per-user temporary directory
const char* get_temp_directory() {
    static char temp_path_storage[MAX_PATH] = {0};

    if (temp_path_storage[0] == 0) {
        int path_size = confstr(_CS_DARWIN_USER_TEMP_DIR, temp_path_storage, MAX_PATH);
        if (path_size == 0 || path_size > MAX_PATH) {
            strcpy(temp_path_storage, "/tmp");
        }
    }
    return temp_path_storage;
}

#else // Linux and FreeBSD

const char* get_temp_directory() {
    return "/tmp";
}

#endif

#ifdef __linux__

int get_process_info(int pid, uid_t* uid, gid_t* gid, int* nspid) {
    char status[64];
    snprintf(status, sizeof(status), "/proc/%d/status", pid);

    FILE* status_file = fopen(status, "r");
    if (status_file == NULL) {
        return 0;
    }

    char* line = NULL;
    size_t size;

    while (getline(&line, &size, status_file) != -1) {
        if (strncmp(line, "Uid:", 4) == 0) {
            // Get the effective UID, which is the second value in the line
            *uid = (uid_t)atoi(strchr(line + 5, '\t'));
        } else if (strncmp(line, "Gid:", 4) == 0) {
            // Get the effective GID, which is the second value in the line
            *gid = (gid_t)atoi(strchr(line + 5, '\t'));
        } else if (strncmp(line, "NStgid:", 7) == 0) {
            // PID namespaces can be nested; the last one is the innermost one
            *nspid = atoi(strrchr(line, '\t'));
        }
    }

    free(line);
    fclose(status_file);
    return 1;
}

int enter_mount_ns(int pid) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/ns/mnt", pid);

    // We're leaking the oldns and newns descriptors, but this is a short-running
    // tool, so they will be closed when the process exits anyway.
    int oldns, newns;
    if ((oldns = open("/proc/self/ns/mnt", O_RDONLY)) < 0 || (newns = open(path, O_RDONLY)) < 0) {
        return 0;
    }

    struct stat oldns_stat, newns_stat;
    if (fstat(oldns, &oldns_stat) < 0 || fstat(newns, &newns_stat) < 0) {
        return 0;
    }
    if (oldns_stat.st_ino == newns_stat.st_ino) {
        // Don't try to call setns() if we're in the same namespace already.
        return 1;
    }

    // Some ancient Linux distributions do not have setns() function
    return syscall(__NR_setns, newns, 0) < 0 ? 0 : 1;
}

// The first line of /proc/pid/sched looks like
// java (1234, #threads: 12)
// where 1234 is the required host PID
int sched_get_host_pid(const char* path) {
    static char* line = NULL;
    size_t size;
    int result = -1;

    FILE* sched_file = fopen(path, "r");
    if (sched_file != NULL) {
        if (getline(&line, &size, sched_file) != -1) {
            char* c = strrchr(line, '(');
            if (c != NULL) {
                result = atoi(c + 1);
            }
        }
        fclose(sched_file);
    }

    return result;
}

// Linux kernels < 4.1 do not export NStgid field in /proc/pid/status.
// Fortunately, /proc/pid/sched in a container exposes a host PID,
// so the idea is to scan all container PIDs to find which one matches the host PID.
int alt_lookup_nspid(int pid) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/ns/pid", pid);

    // Don't bother looking for container PID if we are already in the same PID namespace
    struct stat oldns_stat, newns_stat;
    if (stat("/proc/self/ns/pid", &oldns_stat) == 0 && stat(path, &newns_stat) == 0) {
        if (oldns_stat.st_ino == newns_stat.st_ino) {
            return pid;
        }
    }

    // Otherwise browse all PIDs in the namespace of the target process
    // trying to find which one corresponds to the host PID
    snprintf(path, sizeof(path), "/proc/%d/root/proc", pid);
    DIR* dir = opendir(path);
    if (dir != NULL) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] >= '1' && entry->d_name[0] <= '9') {
                // Check if /proc/<container-pid>/sched points back to <host-pid>
                snprintf(path, sizeof(path), "/proc/%d/root/proc/%s/sched", pid, entry->d_name);
                if (sched_get_host_pid(path) == pid) {
                    closedir(dir);
                    return atoi(entry->d_name);
                }
            }
        }
        closedir(dir);
    }

    return -1;
}

#else // macOS and FreeBSD

#include <sys/sysctl.h>

#ifdef __FreeBSD__
#include <sys/user.h>
#endif

int get_process_info(int pid, uid_t* uid, gid_t* gid, int* nspid) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc info;
    size_t len = sizeof(info);

    if (sysctl(mib, 4, &info, &len, NULL, 0) < 0 || len <= 0) {
        return 0;
    }

#ifdef __FreeBSD__
    *uid = info.ki_uid;
    *gid = info.ki_groups[0];
#else // macOS
    *uid = info.kp_eproc.e_ucred.cr_uid;
    *gid = info.kp_eproc.e_ucred.cr_gid;
#endif
    *nspid = pid;
    return 1;
}

// This is a Linux-specific API; nothing to do on macOS and FreeBSD
int enter_mount_ns(int pid) {
    return 1;
}

// Not used on macOS and FreeBSD
int alt_lookup_nspid(int pid) {
    return pid;
}

#endif


// Check if remote JVM has already opened socket for Dynamic Attach
static int check_socket(int pid) {
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%s/.java_pid%d", get_temp_directory(), pid);

    struct stat stats;
    return stat(path, &stats) == 0 && S_ISSOCK(stats.st_mode);
}

// Check if a file is owned by current user
static int check_file_owner(const char* path) {
    struct stat stats;
    if (stat(path, &stats) == 0 && stats.st_uid == geteuid()) {
        return 1;
    }

    // Some mounted filesystems may change the ownership of the file.
    // JVM will not trust such file, so it's better to remove it and try a different path
    unlink(path);
    return 0;
}

// Force remote JVM to start Attach listener.
// HotSpot will start Attach listener in response to SIGQUIT if it sees .attach_pid file
static int start_attach_mechanism(int pid, int nspid) {
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "/proc/%d/cwd/.attach_pid%d", nspid, nspid);
    
    int fd = creat(path, 0660);
    if (fd == -1 || (close(fd) == 0 && !check_file_owner(path))) {
        // Failed to create attach trigger in current directory. Retry in /tmp
        snprintf(path, MAX_PATH, "%s/.attach_pid%d", get_temp_directory(), nspid);
        fd = creat(path, 0660);
        if (fd == -1) {
            return 0;
        }
        close(fd);
    }
    
    // We have to still use the host namespace pid here for the kill() call
    kill(pid, SIGQUIT);
    
    int result;
    struct timespec ts = {0, 100000000};
    int retry = 0;
    do {
        nanosleep(&ts, NULL);
        result = check_socket(nspid);
    } while (!result && ++retry < 10);

    unlink(path);
    return result;
}

// Connect to UNIX domain socket created by JVM for Dynamic Attach
static int connect_socket(int pid) {
    int fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        return -1;
    }
    
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/.java_pid%d", get_temp_directory(), pid);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        close(fd);
        return -1;
    }
    return fd;
}

// Send command with arguments to socket
static int write_command(int fd, int argc, char** argv) {
    // Protocol version
    if (write(fd, "1", 2) <= 0) {
        return 0;
    }

    int i;
    for (i = 0; i < 4; i++) {
        const char* arg = i < argc ? argv[i] : "";
        if (write(fd, arg, strlen(arg) + 1) <= 0) {
            return 0;
        }
    }
    return 1;
}

// Mirror response from remote JVM to stdout
static int read_response(int fd) {
    char buf[8192];
    ssize_t bytes = read(fd, buf, sizeof(buf) - 1);
    if (bytes <= 0) {
        perror("Error reading response");
        return 1;
    }

    // First line of response is the command result code
    buf[bytes] = 0;
    int result = atoi(buf);

    do {
        fwrite(buf, 1, bytes, stdout);
        bytes = read(fd, buf, sizeof(buf));
    } while (bytes > 0);

    return result;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: jattach <pid> <cmd> <args> ...\n");
        return 1;
    }
    
    int pid = atoi(argv[1]);
    if (pid == 0) {
        perror("Invalid pid provided");
        return 1;
    }

    uid_t my_uid = geteuid();
    gid_t my_gid = getegid();
    uid_t target_uid = my_uid;
    gid_t target_gid = my_gid;
    int nspid = -1;
    if (!get_process_info(pid, &target_uid, &target_gid, &nspid)) {
        fprintf(stderr, "Process %d not found\n", pid);
        return 1;
    }

    if (nspid < 0 && (nspid = alt_lookup_nspid(pid)) < 0) {
        fprintf(stderr, "WARNING: couldn't find container pid of the target process\n");
        nspid = pid;
    }

    // Make sure our /tmp and target /tmp is the same
    if (!enter_mount_ns(pid)) {
        fprintf(stderr, "WARNING: couldn't enter target process mnt namespace\n");
    }
    
    // Dynamic attach is allowed only for the clients with the same euid/egid.
    // If we are running under root, switch to the required euid/egid automatically.
    if ((my_gid != target_gid && setegid(target_gid) != 0) ||
        (my_uid != target_uid && seteuid(target_uid) != 0)) {
        perror("Failed to change credentials to match the target process");
        return 1;
    }

    // Make write() return EPIPE instead of silent process termination
    signal(SIGPIPE, SIG_IGN);

    if (!check_socket(nspid) && !start_attach_mechanism(pid, nspid)) {
        perror("Could not start attach mechanism");
        return 1;
    }

    int fd = connect_socket(nspid);
    if (fd == -1) {
        perror("Could not connect to socket");
        return 1;
    }
    
    printf("Connected to remote JVM\n");
    if (!write_command(fd, argc - 2, argv + 2)) {
        perror("Error writing to socket");
        close(fd);
        return 1;
    }

    printf("Response code = ");
    fflush(stdout);

    int result = read_response(fd);
    printf("\n");
    close(fd);

    return result;
}
