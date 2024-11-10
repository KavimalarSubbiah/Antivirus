#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <yara.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h> // Include errno

#define PATH_SEPARATOR '/'
#define BUFFER_SIZE 1024

void displayErrorMessage(int errorCode) {
    // Use strerror to get error messages in Linux
    printf("Error: %s\n", strerror(errorCode));
}

int scanCallback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data) {

    // Cast user_data back to const char* to get the filePath
    const char* filePath = (const char*)user_data;
    static int ruleMatched = 0;

    switch (message) {
    case CALLBACK_MSG_RULE_MATCHING:
        printf("Matched rule: %s \n", ((YR_RULE*)message_data)->identifier);
        printf("%s probably contains malware based on Signature based detection", filePath)
        ruleMatched = 1; 
        break;
    case CALLBACK_MSG_RULE_NOT_MATCHING:
        printf("Did not match rule: %s \n", ((YR_RULE*)message_data)->identifier);
        break;
    case CALLBACK_MSG_SCAN_FINISHED:
        printf("Scan finished for file %s \n", filePath);
        fflush(stdout); 
        // if flag ==1  flag it
        if(ruleMatched==0){
        char cwd[BUFFER_SIZE];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("getcwd() failed");
        return CALLBACK_CONTINUE;
    }

        // Construct the command to call main.py with the file path as an argument
        char command[BUFFER_SIZE];

        const char* relativePath = filePath + strlen(cwd) + 1; // +1 to skip the '/'
        snprintf(command, sizeof(command), "python3 main.py %s", relativePath);

        // Call the Python script with the relative file path as an argument
        int result = system(command);
        if (result == -1) {
            perror("Error executing Python script");
        }}
        break;
    case CALLBACK_MSG_TOO_MANY_MATCHES:
        printf("Too many matches in file\n");
        break;
    case CALLBACK_MSG_CONSOLE_LOG:
        printf("Console log for file %s: %s\n", filePath, (char*)message_data);
        break;
    default:
        break;
    }

    return CALLBACK_CONTINUE;
}




void scanFile(const char* filePath, YR_RULES* rules) {
    // Corrected the last argument to 0 (for no timeout)
    yr_rules_scan_file(rules, filePath, SCAN_FLAGS_REPORT_RULES_MATCHING, scanCallback,(void*)filePath, 0);
}

void scanDirectory(const char* dirPath, YR_RULES* rules) {
    DIR* dir;
    struct dirent* entry;

    if (!(dir = opendir(dirPath))) {
        perror("Error opening directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            char path[BUFFER_SIZE];
            snprintf(path, sizeof(path), "%s%c%s", dirPath, PATH_SEPARATOR, entry->d_name);
            scanDirectory(path, rules);
        } else {
            char filePath[BUFFER_SIZE];
            snprintf(filePath, sizeof(filePath), "%s%c%s", dirPath, PATH_SEPARATOR, entry->d_name);
            scanFile(filePath, rules);
        }
    }
    closedir(dir);
}

void checkType(const char* path, YR_RULES* rules) {
    struct stat path_stat;
    if (stat(path, &path_stat) == 0) {
        if (S_ISREG(path_stat.st_mode)) {
            // Path is a regular file
            scanFile(path, rules);
        } else if (S_ISDIR(path_stat.st_mode)) {
            // Path is a directory
            scanDirectory(path, rules);
        } else {
            printf("Unknown file type\n");
        }
    } else {
        perror("Error getting file status");
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("[-] Incorrect parameters specified\n");
        return 1;
    }

    const char directory_path[] = "/home/elizabeth/Desktop/netsec/Antivirus/AV/rules";  // Update this path
    char* file_path = argv[1];

    // Initialize YARA
    int Initresult = yr_initialize();
    if (Initresult != 0) {
        printf("[-] Failed to initialize YARA\n");
        return 1;
    }

    printf("[+] Successfully initialized YARA\n");

    YR_COMPILER* compiler = NULL;
    int Compilerresult = yr_compiler_create(&compiler);
    if (Compilerresult != ERROR_SUCCESS) {
        printf("[-] Failed to initialize YARA\n");
        return 1;
    }

    printf("[+] Successfully created compiler\n");

    // Load YARA rules from each file in the directory
    DIR* directory = opendir(directory_path);
    if (directory == NULL) {
        printf("[-] Failed to open directory: %s\n", directory_path);
        yr_finalize();
        return 1;
    }

    printf("[+] Successfully opened rules directory\n");

    struct dirent* entry;
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, ".yar") != NULL) {
            char rule_file_path[BUFFER_SIZE];
            snprintf(rule_file_path, sizeof(rule_file_path), "%s/%s", directory_path, entry->d_name);
            FILE* rule_file = fopen(rule_file_path, "rb");
            if (rule_file != NULL) {
                int Addresult = yr_compiler_add_file(compiler, rule_file, NULL, NULL);
                if (Addresult > 0) {
                    printf("[-] Failed to compile YARA rule %s, number of errors found: %d\n", rule_file_path, Addresult);
                    displayErrorMessage(errno);  // Fixed the use of errno here
                } else {
                    printf("[+] Compiled rules %s\n", rule_file_path);
                }
                fclose(rule_file);
            } else {
                printf("[-] Failed to open rule file: %s\n", rule_file_path);
            }
        }
    }

    closedir(directory);

    YR_RULES* rules = NULL;
    yr_compiler_get_rules(compiler, &rules);

    checkType(file_path, rules);

    // Clean up
    yr_rules_destroy(rules);
    yr_finalize();

    return 0;
}