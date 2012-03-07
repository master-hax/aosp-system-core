/*
 *  sync_test.c
 *
 *   Copyright 2012 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sync/sync.h>

struct sync_thread_data {
    int thread_no;
    int fd[2];
};

void *sync_thread(void *data)
{
    struct sync_thread_data *sync_data = data;
    int err;
    int i;

    for (i = 0; i < 2; i++) {
        err = sync_wait(sync_data->fd[i]);
        if (err < 0)
            printf("thread %d wait %d failed: %s\n", sync_data->thread_no,
                   i, strerror(errno));
        else
            printf("thread %d wait %d done\n", sync_data->thread_no, i);
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    struct sync_thread_data sync_data[3];
    pthread_t threads[3];
    int sync_obj_fd;
    int i, j;
    sync_obj_fd = sw_sync_obj_create();
    if (sync_obj_fd < 0) {
        perror("can't create sw_sync_obj:");
        return 1;
    }

    for (i = 0; i < 3; i++) {
        sync_data[i].thread_no = i;

        for (j = 0; j < 2; j++) {
            unsigned val = i + j * 3 + 1;
            int fd = sw_sync_pt_create(sync_obj_fd, val);
            if (fd < 0) {
                printf("can't create sync pt %d: %s", val, strerror(errno));
                return 1;
            }
            sync_data[i].fd[j] = fd;
            printf("sync_data[%d].fd[%d] = %d;\n", i, j, fd);

        }
    }

    for (i = 0; i < 3; i++)
        pthread_create(&threads[i], NULL, sync_thread, &sync_data[i]);


    for (i = 0; i < 3; i++) {
        int err;
        err = sw_sync_obj_inc(sync_obj_fd, 1);
        if (err < 0) {
            perror("can't increment sync obj:");
            return 1;
        }
    }

    close(sync_obj_fd);

    for (i = 0; i < 3; i++) {
        void *val;
        pthread_join(threads[i], &val);
    }

    return 0;
}
