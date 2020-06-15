#pragma once

enum transfer_kind {
    TRUSTY_SHARE = 0,
    TRUSTY_LEND = 1,
};

struct trusty_shmem {
    int fd;
    enum transfer_kind transfer;
};
