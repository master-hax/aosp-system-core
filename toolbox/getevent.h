#include <linux/input.h>

struct label {
    const char *name;
    int value;
};

#define LABEL(constant) { #constant, constant }
#define LABEL_END { NULL, -1 }

static struct label key_value_labels[] = {
        { "UP", 0 },
        { "DOWN", 1 },
        { "REPEAT", 2 },
        LABEL_END,
};

#include "input.h-labels.h"
