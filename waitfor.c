#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <pwd.h>
#include <errno.h>

#define DEFAULT_INTERVAL_SECONDS 2
#define MAX_PROCESS_NAME_LEN 256
#define MAX_USERNAME_LEN 32

// Function to display syntax help
void display_help(const char *prog_name) {
    fprintf(stderr, "Usage: %s [ -u USER | -a ] [ -i SECONDS ] PROCESS_NAME\n", prog_name);
    fprintf(stderr, "       %s -h\n", prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Monitors for the termination of a process matching PROCESS_NAME.\n");
    fprintf(stderr, "If the process does not exist initially, exits immediately with success.\n");
    fprintf(stderr, "If the process exists, waits for it to terminate.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i SECONDS   Interval in seconds to recheck. Default is %d.\n", DEFAULT_INTERVAL_SECONDS);
    fprintf(stderr, "  -u USER      Only consider processes owned by the specified user.\n");
    fprintf(stderr, "               Defaults to the current user if -a is not used.\n");
    fprintf(stderr, "  -a           Consider processes for any user in the system.\n");
    fprintf(stderr, "  -h           Show this syntax help.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "PROCESS_NAME   The (partial) name of the process to wait for.\n");
    fprintf(stderr, "               Matching is case-sensitive.\n");
}

// Function to retrieve process information
// Returns a dynamically allocated array of kinfo_proc structs. Caller must free.
struct kinfo_proc *get_process_info(size_t *num_processes) {
    struct kinfo_proc *proc_list = NULL;
    size_t length = 0;
    int mib[4];

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_ALL; // Get all processes

    // First call to sysctl to get the buffer size
    if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0) {
        perror("sysctl (estimate buffer size)");
        return NULL;
    }

    // Allocate memory for the process list
    proc_list = malloc(length);
    if (proc_list == NULL) {
        perror("malloc for process list");
        return NULL;
    }

    // Second call to sysctl to get the actual process data
    if (sysctl(mib, 3, proc_list, &length, NULL, 0) < 0) {
        perror("sysctl (retrieve process data)");
        free(proc_list);
        return NULL;
    }

    *num_processes = length / sizeof(struct kinfo_proc);
    return proc_list;
}

// Function to check if any matching process exists
int check_for_matching_process(const char *process_name, uid_t target_uid, int any_user) {
    struct kinfo_proc *proc_list = NULL;
    size_t num_processes = 0;
    int found = 0;

    proc_list = get_process_info(&num_processes);
    if (proc_list == NULL) {
        fprintf(stderr, "Error: Could not retrieve process information.\n");
        return -1; // Indicate a system error
    }

    for (size_t i = 0; i < num_processes; ++i) {
        // Check user ownership
        if (!any_user && proc_list[i].kp_eproc.e_pcred.p_ruid != target_uid) {
            continue; // Skip processes not owned by the target user
        }

        // Check for partial name match (case-sensitive)
        if (strstr(proc_list[i].kp_proc.p_comm, process_name) != NULL) {
            found = 1;
            break; // Found a match
        }
    }

    free(proc_list); // Always free the allocated memory
    return found;
}


int main(int argc, char *argv[]) {
    long interval_seconds = DEFAULT_INTERVAL_SECONDS;
    uid_t target_user_uid = geteuid(); // Default to current effective user
    int any_user = 0;
    char *process_name_arg = NULL;
    int opt;

    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:u:ah")) != -1) {
        switch (opt) {
            case 'i':
                interval_seconds = atol(optarg);
                if (interval_seconds <= 0) {
                    fprintf(stderr, "Error: Interval must be a positive number of seconds.\n");
                    display_help(argv[0]);
                    return EXIT_FAILURE;
                }
                break;
            case 'u': {
                if (any_user) {
                    fprintf(stderr, "Error: Cannot use -u and -a together.\n");
                    display_help(argv[0]);
                    return EXIT_FAILURE;
                }
                struct passwd *pw = getpwnam(optarg);
                if (pw == NULL) {
                    fprintf(stderr, "Error: User '%s' not found.\n", optarg);
                    return EXIT_FAILURE;
                }
                target_user_uid = pw->pw_uid;
                // Since -u is specified, we unset the default 'current user' logic,
                // and explicitly set any_user to 0.
                any_user = 0; 
                break;
            }
            case 'a':
                if (optind < argc && argv[optind] != NULL && argv[optind][0] != '-') {
                    // Check if -u was already used before -a
                    // This is a bit tricky with getopt, as -a might appear after -u
                    // The 'target_user_uid' would have been set by -u.
                    // A simple check here is that if -u was used, 'any_user' will not be true.
                    // This scenario is handled by checking any_user flag.
                }
                any_user = 1;
                break;
            case 'h':
                display_help(argv[0]);
                return EXIT_SUCCESS;
            case '?': // Unknown option or missing argument
                display_help(argv[0]);
                return EXIT_FAILURE;
            default:
                break; // Should not happen
        }
    }

    // The remaining argument after options is the process name
    if (optind < argc) {
        process_name_arg = argv[optind];
    } else {
        fprintf(stderr, "Error: PROCESS_NAME argument is required.\n");
        display_help(argv[0]);
        return EXIT_FAILURE;
    }

    // --- Initial Check ---
    int initial_check_result = check_for_matching_process(process_name_arg, target_user_uid, any_user);
    if (initial_check_result == -1) {
        return EXIT_FAILURE; // System error during process info retrieval
    } else if (initial_check_result == 0) {
        // Process not found on initial check, so it already "ended" or never started.
        fprintf(stderr, "Process '%s' (for ", process_name_arg);
        if (any_user) {
            fprintf(stderr, "any user");
        } else {
            struct passwd *pw = getpwuid(target_user_uid);
            if (pw) {
                fprintf(stderr, "user '%s'", pw->pw_name);
            } else {
                fprintf(stderr, "user with UID %d", target_user_uid);
            }
        }
        fprintf(stderr, ") is not running. Exiting.\n");
        return EXIT_SUCCESS; // Success: condition met (process not running)
    }

    // --- Monitoring Loop (if process was found initially) ---
    fprintf(stderr, "Process '%s' (for ", process_name_arg);
    if (any_user) {
        fprintf(stderr, "any user");
    } else {
        struct passwd *pw = getpwuid(target_user_uid);
        if (pw) {
            fprintf(stderr, "user '%s'", pw->pw_name);
        } else {
            fprintf(stderr, "user with UID %d", target_user_uid);
        }
    }
    fprintf(stderr, ") found. Waiting for it to terminate (recheck every %ld seconds)...\n", interval_seconds);

    while (1) {
        int current_check_result = check_for_matching_process(process_name_arg, target_user_uid, any_user);
        if (current_check_result == -1) {
            // System error, retry after interval, or consider exiting after too many errors
            fprintf(stderr, "Warning: System error during recheck. Retrying...\n");
        } else if (current_check_result == 0) {
            // Process is no longer found
            printf("Process '%s' has terminated.\n", process_name_arg);
            return EXIT_SUCCESS;
        }
        
        // Process still running, wait for interval
        sleep(interval_seconds);
    }

    return EXIT_FAILURE; // Should theoretically not be reached
}