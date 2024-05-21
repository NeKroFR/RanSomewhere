#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "delete.h"

void self_delete(const char *filename) {
    unlink(filename);
    // TODO: delete from memory
    exit(EXIT_FAILURE);
}
