
#include <inttypes.h>

// Port name of the Hello trusted application
#define HELLO_PORT "com.android.trusty.hello"
#define HELLO_SHMEM_SIZE 4096

// Request struct
struct hello_req {
    uint8_t cmd;
};

// Response
struct hello_resp {
    uint8_t cmd;
    uint8_t status;
};

// Common structure covering all possible hello messages, only used to
// determine the maximum message size
union hello_longest_msg {
    struct hello_req req;
    struct hello_resp resp;
} __PACKED;
