/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/klog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#define min(x,y) ((x) < (y) ? (x) : (y))
#define KB 1024
#define LOG_BUF_SZ (KB * 128)
#define ERR(fmt...) fprintf(stderr, fmt)
#define UNLIMITED_FILE_SIZE 0
#define MAX_ROTATION_NUM 10
#define NO_ROTATION 0
#define DEFAULT_ROTATE_SIZE (KB * 16)
#define LOG_LEVEL_NOT_DECIDED (-1)

static void print_usage(void)
{
    ERR(
    "\nUsage: aklog [-f FILE [-s kB] [-n count]] [-a] [-l]\n"
    "-f: print log to file(s), otherwise output log to console.\n"
    "-s: max size of a log file in kB, requires -f, cannot work\n"
    "    with -a. When -s is not provided along with -n, size is\n"
    "    %d kB\n"
    "-n: max number of rotation log files up to %d, requires -f,\n"
    "    cannot work with -a. log files are named as FILE.x.\n"
    "-a: print all log data in kernel's log buffer and then exit,\n"
    "    otherwise aklog will keep running until it is killed.\n"
    "-l: set log level\n",
    DEFAULT_ROTATE_SIZE, MAX_ROTATION_NUM
    );
}

static FILE *init_log_file(const char *name)
{
    FILE *f = NULL;
    int fd;

    if (!name)
        return f;

    fd = creat(name, 0644);

    if (fd >= 0)
        f = fdopen(fd, "w");

    return f;
}

static void deinit_log_file(FILE *f)
{
    if (f)
        fclose(f);
}

static int do_rotation(const char *file_name, int rotate_num, FILE **pfile)
{
    int i;
    char *name = NULL;
    char *new_name = NULL;
    int ret = 0;

    if (!file_name || *file_name == '\0' || !pfile)
        return -EINVAL;

    deinit_log_file(*pfile);

    for (i = rotate_num; i > 0; i--) {

        ret = asprintf(&new_name, "%s.%d", file_name, i);

        if (ret != -1) {

            if (i == 1)
                ret = asprintf(&name, "%s", file_name);
            else
                ret = asprintf(&name, "%s.%d", file_name, i - 1);

            if (ret == -1) {
                free(name);

                return -ENOMEM;
            }
            rename(name, new_name);     // file could not exist, do it blindly

            free(name);
            free(new_name);
        }
        else
            return -ENOMEM;
    }

    *pfile = init_log_file(file_name);

    if (*pfile == NULL)
        ret = -EFAULT;

    return ret;
}

int main(int argc, char **argv)
{
    int ret;
    char *buf;
    int len;            // length of kernel buffer
    int written = 0;    // how many bytes written into current log file
    int count = 0;
    int opt;
    char * file_name = NULL;
    int read_all_once = 0;
    int log_level = LOG_LEVEL_NOT_DECIDED;
    FILE *output = NULL;
    int bytes = 0;
    int op_code;
    long int max_file_size = UNLIMITED_FILE_SIZE;
    int rotate_num = NO_ROTATION;

    while ((opt = getopt(argc, argv, "l:f:ahn:s:")) != -1) {
        switch (opt) {
        case 'f':
            file_name = optarg;
            break;
        case 'a':
            read_all_once = 1;
            break;
        case 'l':
            log_level = atoi(optarg);
            break;
        case 'h':
            print_usage();

            exit(EXIT_SUCCESS);
        case 's':
            max_file_size = strtol(optarg, (char **) NULL, 10);
            if (max_file_size == LONG_MAX || max_file_size <= 0
                    || (max_file_size *= KB) <= 0 ) {
                print_usage();

                exit(EXIT_FAILURE);
            }
            break;
        case 'n':
            rotate_num = strtol(optarg, (char **) NULL, 10);
            if (rotate_num <= NO_ROTATION || rotate_num > MAX_ROTATION_NUM) {
                print_usage();

                exit(EXIT_FAILURE);
            }
            break;
        default:
            print_usage();

            exit(EXIT_FAILURE);
        }
    }

    op_code = read_all_once ? KLOG_READ_ALL : KLOG_READ;

    output = file_name ? init_log_file(file_name) : stdout;

    if (!output) {
        ERR("failed to create log file\n");
        return -EINVAL;
    }

    if ((max_file_size != UNLIMITED_FILE_SIZE || rotate_num != NO_ROTATION) &&
            (file_name == NULL || op_code == KLOG_READ_ALL)) {
        ERR("-s and -n only apply with '-f' and without '-a'\n");

        return -EINVAL;
    }

    if (max_file_size == UNLIMITED_FILE_SIZE && rotate_num != NO_ROTATION)
        max_file_size = DEFAULT_ROTATE_SIZE;

    /* set log level if user wants to change it */
    if (log_level != LOG_LEVEL_NOT_DECIDED) {
        ret = klogctl(KLOG_CONSOLE_LEVEL, 0, log_level);

        if (ret) {
            ERR("failed to set log level, ret %d (%s)\n",
                    ret, strerror(errno));

            goto out;
        }
    }

    /* probe size of kernel log buffer */
    len = klogctl(KLOG_SIZE_BUFFER, 0, 0);

    if (len <= 0)
        return -EFAULT;

    if (max_file_size != UNLIMITED_FILE_SIZE)
        buf = malloc(sizeof(char) * min(len, max_file_size));
    else
        buf = malloc(sizeof(char) * len);

    if (!buf) {
        ERR("failed to alloc buf mem\n");
        ret = -ENOMEM;

        goto out;
    }

    do {
        if (max_file_size != UNLIMITED_FILE_SIZE) {
            count = min(len, max_file_size - written);
            if (count <= 0) {
                if (rotate_num == NO_ROTATION)
                    break;
                else {
                    ret = do_rotation(file_name, rotate_num, &output);
                    if (ret < 0) {
                        ERR("error when do rotation\n, stop\n");

                        goto out;
                    }
                    else {
                        written = 0;
                        count = min(len, max_file_size - written);
                    }
                }
            }
        }
        else
            count = len;

        if ((bytes = klogctl(op_code, buf, count)) >= 0) {
            if ((ret = fwrite(buf, 1, bytes, output)) != bytes) {
                ERR("only %d of %d bytes written, stop\n", ret, bytes);
                ret = -EFAULT;

                goto out;
            }
        } else {
            ERR("klogctl returned error %d (%s)\n", bytes, strerror(errno));
            ret = bytes;

            goto out;
        }

        fflush(output);

        if (file_name)
            fsync(fileno(output));

        written += bytes;

    } while (op_code == KLOG_READ);

out:
    deinit_log_file(output);
    free(buf);

    return ret;
}
