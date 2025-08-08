#include "config.h"
#include "common.h"

char* get_config_value(const char* key) {
    if (!key)
        return NULL;
    FILE* file = fopen("config.ini", "r");
    if (!file)
        return NULL;
    
    char line[MAX_CONFIG_LINE];
    while (fgets(line, sizeof(line), file)) {
        if (ferror(file)) {
            fclose(file);
            return NULL;
        }
        if (line[0] == '[')
            continue;
        char* eq = strchr(line, '=');
        if (eq) {
            *eq = '\0';
            char* k = line;
            char* v = eq + 1;
            while (*k == ' ' || *k == '\t') {
                k++;
            }
            char* end = k + strlen(k) - 1;
            while (end > k && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
                *end-- = '\0';
            }
            while (*v == ' ' || *v == '\t') {
                v++;
            }
            end = v + strlen(v) - 1;
            while (end > v && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
                *end-- = '\0';
            }
            if (strcmp(k, key) == 0) {
                fclose(file);
                return strdup(v); // Caller must free
            }
        }
    }
    fclose(file);
    return NULL;
}
