#include <linux/keyctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static inline long keyctl(int cmd, int spec, int flag, ...) {
    return syscall(SYS_keyctl, cmd, spec, flag);
}
