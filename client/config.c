#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* get_config_value(const char* key) {
    FILE* file = fopen("config.ini", "r");
    if (!file) {
        return NULL;
    }
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '[') 
            continue; // Skip headers
        char* eq = strchr(line, '=');
        if (eq) {
            *eq = '\0';
            char* k = line;
            char* v = eq + 1;
            while (*k == ' ') k++;
            char* end = k + strlen(k) - 1;
            while (end > k && (*end == ' ' || *end == '\n' || *end == '\r')) *end-- = '\0';
            while (*v == ' ') v++;
            end = v + strlen(v) - 1;
            while (end > v && (*end == ' ' || *end == '\n' || *end == '\r')) *end-- = '\0';
            if (strcmp(k, key) == 0) {
                fclose(file);
                return strdup(v);
            }
        }
    }
    fclose(file);
    return NULL;
}
