#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <pwd.h>
#include <errno.h>

#define DEFAULT_INTERVAL_SECONDS 2
#define MAX_USERNAME_LEN 32 // Re-added this definition!

// Global flags
int verbose = 0;
int wait_for_start_flag = 0;

// Function to display syntax help
void display_help(const char *prog_name) {
    fprintf(stderr, "Usage: %s [ -v ] [ -w ] [ -u USER | -a ] [ -i SECONDS ] PROCESS_NAME\n", prog_name);
    fprintf(stderr, "       %s -h\n", prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Monitors for the termination of a process matching PROCESS_NAME.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Behavior:\n");
    fprintf(stderr, "  - If -w is NOT given: If the process does not exist initially, exits immediately with success.\n");
    fprintf(stderr, "    If the process exists, waits for it to terminate.\n");
    fprintf(stderr, "  - If -w IS given: First, waits indefinitely for the process to appear. Once it appears,\n");
    fprintf(stderr, "    then waits for it to terminate.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -v           Enable verbose output messages.\n");
    fprintf(stderr, "  -w           Wait for the process to start before waiting for it to end.\n");
    fprintf(stderr, "  -i SECONDS   Interval in seconds to recheck. Default is %d.\n", DEFAULT_INTERVAL_SECONDS); // Fixed typo here!
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
// Returns NULL on error.
struct kinfo_proc *get_process_info(size_t *num_processes) {
    struct kinfo_proc *proc_list = NULL;
    size_t length = 0;
    int mib[4];

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_ALL; // Get all processes

    // First call to sysctl to get the buffer size
    if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0) {
        if (verbose) perror("sysctl (estimate buffer size)");
        return NULL;
    }

    // Allocate memory for the process list
    proc_list = malloc(length);
    if (proc_list == NULL) {
        if (verbose) perror("malloc for process list");
        return NULL;
    }

    // Second call to sysctl to get the actual process data
    if (sysctl(mib, 3, proc_list, &length, NULL, 0) < 0) {
        if (verbose) perror("sysctl (retrieve process data)");
        free(proc_list);
        return NULL;
    }

    *num_processes = length / sizeof(struct kinfo_proc);
    return proc_list;
}

// Function to check if any matching process exists
// Returns:
//   1 if found
//   0 if not found
//  -1 on system error
int check_for_matching_process(const char *process_name, uid_t target_uid, int any_user) {
    struct kinfo_proc *proc_list = NULL;
    size_t num_processes = 0;
    int found = 0; // 0 for not found, 1 for found

    proc_list = get_process_info(&num_processes);
    if (proc_list == NULL) {
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
    while ((opt = getopt(argc, argv, "i:u:ahvw")) != -1) {
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
                any_user = 0; 
                break;
            }
            case 'a':
                any_user = 1;
                break;
            case 'v': // Handle verbose option
                verbose = 1;
                break;
            case 'w': // Handle wait-for-start option
                wait_for_start_flag = 1;
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

    char user_info_str[MAX_USERNAME_LEN + 20]; // Buffer for user info string (MAX_USERNAME_LEN is now defined)
    if (any_user) {
        snprintf(user_info_str, sizeof(user_info_str), "any user");
    } else {
        struct passwd *pw = getpwuid(target_user_uid);
        if (pw) {
            snprintf(user_info_str, sizeof(user_info_str), "user '%s'", pw->pw_name);
        } else {
            snprintf(user_info_str, sizeof(user_info_str), "user with UID %d", target_user_uid);
        }
    }

    // --- Phase 1: Wait for Process Apparition (if -w is given) ---
    if (wait_for_start_flag) {
        if (verbose) {
            fprintf(stderr, "Waiting for process '%s' (for %s) to appear (recheck every %ld seconds)...\n",
                    process_name_arg, user_info_str, interval_seconds);
        }
        while (1) {
            int current_check_result = check_for_matching_process(process_name_arg, target_user_uid, any_user);
            if (current_check_result == 1) { // Process appeared
                if (verbose) {
                    fprintf(stderr, "Process '%s' has appeared. Now waiting for its termination...\n", process_name_arg);
                }
                break; // Exit this loop, proceed to termination wait
            } else if (current_check_result == -1) { // System error
                if (verbose) fprintf(stderr, "Warning: System error during check for apparition. Retrying...\n");
            }
            // If current_check_result == 0 (not found yet), continue loop
            sleep(interval_seconds);
        }
    } else {
        // --- Phase 1 (Alternative): Initial Check for Termination (if -w is NOT given) ---
        int initial_check_result = check_for_matching_process(process_name_arg, target_user_uid, any_user);
        if (initial_check_result == -1) {
            return EXIT_FAILURE; // System error during process info retrieval
        } else if (initial_check_result == 0) {
            // Process not found on initial check, so it already "ended" or never started.
            if (verbose) {
                fprintf(stderr, "Process '%s' (for %s) is not running. Exiting.\n",
                        process_name_arg, user_info_str);
            }
            return EXIT_SUCCESS; // Success: condition met (process not running)
        }
    }

    // --- Phase 2: Wait for Process Termination (always reached) ---
    if (verbose && !wait_for_start_flag) { // Only print if not already printed by -w phase
        fprintf(stderr, "Process '%s' (for %s) found. Waiting for it to terminate (recheck every %ld seconds)...\n",
                process_name_arg, user_info_str, interval_seconds);
    }
    
    while (1) {
        int current_check_result = check_for_matching_process(process_name_arg, target_user_uid, any_user);
        if (current_check_result == -1) {
            // System error, retry after interval. Error message from get_process_info will be shown if verbose.
            if (verbose) fprintf(stderr, "Warning: System error during recheck for termination. Retrying...\n");
        } else if (current_check_result == 0) {
            // Process is no longer found
            if (verbose) printf("Process '%s' has terminated.\n", process_name_arg);
            return EXIT_SUCCESS;
        }
        
        // Process still running, wait for interval
        sleep(interval_seconds);
    }

    return EXIT_FAILURE; // Should theoretically not be reached
}