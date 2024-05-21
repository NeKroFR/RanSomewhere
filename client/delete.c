#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "delete.h"

void self_delete(const char *filename) {
    unlink(filename);
    exit(EXIT_FAILURE);
}
