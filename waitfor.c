#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <pwd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>

#define DEFAULT_INTERVAL_SECONDS 2
#define MAX_USERNAME_LEN 32

// Global flags and enums
int verbose = 0;
int wait_for_start_flag = 0;

typedef enum {
    CONDITION_NONE,
    CONDITION_PROCESS,
    CONDITION_TCP_PORT,
    CONDITION_UDP_PORT,
    CONDITION_FILE
} ConditionType;

// --- Function Prototypes ---
void display_help(const char *prog_name);
struct kinfo_proc *get_process_info(size_t *num_processes);
int check_for_matching_process(const char *process_name, uid_t target_uid, int any_user);
int check_for_tcp_port(int port);
int check_for_udp_port(int port);
int check_for_file_existence(const char *file_path);
int wait_for_process_start(const char *command_name, uid_t target_uid, int any_user, long interval);
int wait_for_process_termination(const char *command_name, uid_t target_uid, int any_user, long interval);
int wait_for_port_condition(int port, int (*check_func)(int), long interval);
int wait_for_file_condition(const char *file_path, long interval);


// Function to display syntax help
void display_help(const char *prog_name) {
    fprintf(stderr, "Usage: %s [ -v ] [ -w ] [ -i SECONDS ] [ -P PROCESS_NAME [ -a | -u USER ] | -T TCP_PORT | -U UDP_PORT | -F FILE ]\n", prog_name);
    fprintf(stderr, "       %s -h\n", prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Monitors for the termination of a condition.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Behavior:\n");
    fprintf(stderr, "  - If -w is NOT given: If the condition is not met initially, exits immediately with success.\n");
    fprintf(stderr, "    If the condition is met, waits for it to become false.\n");
    fprintf(stderr, "  - If -w IS given: First, waits indefinitely for the condition to be met. Once it's met,\n");
    fprintf(stderr, "    then waits for it to become false.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -v               Enable verbose output messages.\n");
    fprintf(stderr, "  -w               Wait for the condition to start before waiting for it to end.\n");
    fprintf(stderr, "  -i SECONDS       Interval in seconds to recheck. Default is %d.\n", DEFAULT_INTERVAL_SECONDS);
    fprintf(stderr, "  -P PROCESS_NAME  Only considers processes that have COMMAND_NAME.\n");
    fprintf(stderr, "  -u USER          With -C, only consider processes owned by USER. Defaults to current user if -a is not used.\n");
    fprintf(stderr, "  -a               With -C, consider processes for any user in the system.\n");
    fprintf(stderr, "  -T TCP_PORT      Waits for a TCP port to open, then close.\n");
    fprintf(stderr, "  -U UDP_PORT      Waits for a UDP port to open, then close.\n");
    fprintf(stderr, "  -F FILE          Waits for a file to exist, then not exist.\n");
    fprintf(stderr, "  -h               Show this syntax help.\n");
    fprintf(stderr, "\n");
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
    mib[2] = KERN_PROC_ALL;

    if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0) {
        if (verbose) perror("sysctl (estimate buffer size)");
        return NULL;
    }

    proc_list = malloc(length);
    if (proc_list == NULL) {
        if (verbose) perror("malloc for process list");
        return NULL;
    }

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
    int found = 0;

    proc_list = get_process_info(&num_processes);
    if (proc_list == NULL) {
        return -1;
    }

    for (size_t i = 0; i < num_processes; ++i) {
        if (!any_user && proc_list[i].kp_eproc.e_pcred.p_ruid != target_uid) {
            continue;
        }
        if (strstr(proc_list[i].kp_proc.p_comm, process_name) != NULL) {
            found = 1;
            break;
        }
    }

    free(proc_list);
    return found;
}

// Checks if a TCP port is open.
// Returns 1 if open, 0 if closed, -1 on error.
int check_for_tcp_port(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        if (verbose) perror("socket(TCP)");
        return -1;
    }
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int result = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    close(sock);

    if (result == 0) {
        return 1;
    } else if (errno == ECONNREFUSED || errno == EHOSTUNREACH) {
        return 0;
    } else {
        if (verbose) perror("connect(TCP)");
        return -1;
    }
}

// Checks if a UDP port is open.
// Returns 1 if open, 0 if closed, -1 on error.
int check_for_udp_port(int port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        if (verbose) perror("socket(UDP)");
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        close(sock);
        return 0;
    } else if (errno == EADDRINUSE) {
        close(sock);
        return 1;
    } else {
        close(sock);
        if (verbose) perror("bind(UDP)");
        return -1;
    }
}

// Checks if a file exists.
// Returns 1 if it exists, 0 if it doesn't.
int check_for_file_existence(const char *file_path) {
    if (access(file_path, F_OK) == 0) {
        return 1;
    }
    return 0;
}

// Function to wait for the process to appear
int wait_for_process_start(const char *command_name, uid_t target_uid, int any_user, long interval) {
    if (verbose) {
        fprintf(stderr, "Waiting for process '%s' to appear...\n", command_name);
    }
    while (1) {
        int current_check_result = check_for_matching_process(command_name, target_uid, any_user);
        if (current_check_result == 1) {
            if (verbose) fprintf(stderr, "Process '%s' has appeared.\n", command_name);
            return EXIT_SUCCESS;
        } else if (current_check_result == -1) {
            if (verbose) fprintf(stderr, "Warning: System error during check. Retrying...\n");
        }
        sleep(interval);
    }
}

// Function to wait for the process to terminate
int wait_for_process_termination(const char *command_name, uid_t target_uid, int any_user, long interval) {
    if (verbose) {
        fprintf(stderr, "Waiting for process '%s' to terminate...\n", command_name);
    }
    while (1) {
        int current_check_result = check_for_matching_process(command_name, target_uid, any_user);
        if (current_check_result == -1) {
            if (verbose) fprintf(stderr, "Warning: System error during recheck. Retrying...\n");
        } else if (current_check_result == 0) {
            if (verbose) printf("Process '%s' has terminated.\n", command_name);
            return EXIT_SUCCESS;
        }
        sleep(interval);
    }
}

// Generic function to handle port waiting conditions
int wait_for_port_condition(int port, int (*check_func)(int), long interval) {
    int port_is_open = check_func(port);

    if (!wait_for_start_flag) {
        if (port_is_open == 0) {
            if (verbose) fprintf(stderr, "Port %d is not open. Exiting.\n", port);
            return EXIT_SUCCESS;
        } else if (port_is_open == -1) {
            if (verbose) fprintf(stderr, "Initial check failed for port %d. Exiting.\n", port);
            return EXIT_FAILURE;
        }
        if (verbose) fprintf(stderr, "Port %d is open. Waiting for it to close...\n", port);
    } else { // wait_for_start is true
        if (verbose) fprintf(stderr, "Waiting for port %d to open...\n", port);
        while (port_is_open == 0) {
            if (port_is_open == -1) {
                if (verbose) fprintf(stderr, "Warning: System error during port check. Retrying...\n");
            }
            sleep(interval);
            port_is_open = check_func(port);
        }
        if (verbose) fprintf(stderr, "Port %d is open. Now waiting for it to close...\n", port);
    }

    // Now, wait for the port to close
    while (port_is_open == 1) {
        sleep(interval);
        port_is_open = check_func(port);
        if (port_is_open == -1) {
            if (verbose) fprintf(stderr, "Warning: System error during port check. Retrying...\n");
        }
    }

    if (verbose) printf("Port %d is no longer open.\n", port);
    return EXIT_SUCCESS;
}

// Generic function to handle file waiting conditions
int wait_for_file_condition(const char *file_path, long interval) {
    int file_exists = check_for_file_existence(file_path);

    if (!wait_for_start_flag) {
        if (file_exists == 0) {
            if (verbose) fprintf(stderr, "File '%s' does not exist. Exiting.\n", file_path);
            return EXIT_SUCCESS;
        }
        if (verbose) fprintf(stderr, "File '%s' exists. Waiting for it to be removed...\n", file_path);
    } else { // wait_for_start is true
        if (verbose) fprintf(stderr, "Waiting for file '%s' to appear...\n", file_path);
        while (file_exists == 0) {
            sleep(interval);
            file_exists = check_for_file_existence(file_path);
        }
        if (verbose) fprintf(stderr, "File '%s' exists. Now waiting for it to be removed...\n", file_path);
    }

    // Now, wait for the file to be removed
    while (file_exists == 1) {
        sleep(interval);
        file_exists = check_for_file_existence(file_path);
    }

    if (verbose) printf("File '%s' has been removed.\n", file_path);
    return EXIT_SUCCESS;
}


int main(int argc, char *argv[]) {
    long interval_seconds = DEFAULT_INTERVAL_SECONDS;
    uid_t target_user_uid = geteuid();
    int any_user = 0;
    char *command_name_arg = NULL;
    int tcp_port_arg = 0;
    int udp_port_arg = 0;
    char *file_path_arg = NULL;
    ConditionType condition_to_wait_for = CONDITION_NONE;
    int opt;
    
    while ((opt = getopt(argc, argv, "i:u:P:T:U:F:ahvw")) != -1) {
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
                if (condition_to_wait_for != CONDITION_PROCESS && condition_to_wait_for != CONDITION_NONE) {
                    fprintf(stderr, "Error: -u can only be used with -P.\n");
                    display_help(argv[0]);
                    return EXIT_FAILURE;
                }
                struct passwd *pw = getpwnam(optarg);
                if (pw == NULL) {
                    fprintf(stderr, "Error: User '%s' not found.\n", optarg);
                    return EXIT_FAILURE;
                }
                target_user_uid = pw->pw_uid;
                break;
            }
            case 'a':
                if (condition_to_wait_for != CONDITION_PROCESS && condition_to_wait_for != CONDITION_NONE) {
                    fprintf(stderr, "Error: -a can only be used with -C.\n");
                    display_help(argv[0]);
                    return EXIT_FAILURE;
                }
                any_user = 1;
                break;
            case 'P':
                if (condition_to_wait_for != CONDITION_NONE) {
                    fprintf(stderr, "Error: Cannot use -P with other condition options.\n");
                    display_help(argv[0]);
                    return EXIT_FAILURE;
                }
                command_name_arg = optarg;
                condition_to_wait_for = CONDITION_PROCESS;
                break;
            case 'T':
                if (condition_to_wait_for != CONDITION_NONE) {
                    fprintf(stderr, "Error: Cannot use -T with other condition options.\n");
                    display_help(argv[0]);
                    return EXIT_FAILURE;
                }
                tcp_port_arg = atoi(optarg);
                condition_to_wait_for = CONDITION_TCP_PORT;
                break;
            case 'U':
                if (condition_to_wait_for != CONDITION_NONE) {
                    fprintf(stderr, "Error: Cannot use -U with other condition options.\n");
                    display_help(argv[0]);
                    return EXIT_FAILURE;
                }
                udp_port_arg = atoi(optarg);
                condition_to_wait_for = CONDITION_UDP_PORT;
                break;
            case 'F':
                if (condition_to_wait_for != CONDITION_NONE) {
                    fprintf(stderr, "Error: Cannot use -F with other condition options.\n");
                    display_help(argv[0]);
                    return EXIT_FAILURE;
                }
                file_path_arg = optarg;
                condition_to_wait_for = CONDITION_FILE;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'w':
                wait_for_start_flag = 1;
                break;
            case 'h':
                display_help(argv[0]);
                return EXIT_SUCCESS;
            case '?':
                display_help(argv[0]);
                return EXIT_FAILURE;
            default:
                break;
        }
    }
    
    if (condition_to_wait_for == CONDITION_NONE) {
        fprintf(stderr, "Error: One of -P, -T, -U, or -F must be specified.\n");
        display_help(argv[0]);
        return EXIT_FAILURE;
    }

    switch (condition_to_wait_for) {
        case CONDITION_PROCESS:
            if (wait_for_start_flag) {
                if (wait_for_process_start(command_name_arg, target_user_uid, any_user, interval_seconds) != EXIT_SUCCESS) {
                    return EXIT_FAILURE;
                }
            } else {
                int initial_check_result = check_for_matching_process(command_name_arg, target_user_uid, any_user);
                if (initial_check_result == -1) {
                    return EXIT_FAILURE;
                } else if (initial_check_result == 0) {
                    if (verbose) fprintf(stderr, "Process '%s' is not running. Exiting.\n", command_name_arg);
                    return EXIT_SUCCESS;
                }
            }
            return wait_for_process_termination(command_name_arg, target_user_uid, any_user, interval_seconds);
            
        case CONDITION_TCP_PORT:
            return wait_for_port_condition(tcp_port_arg, check_for_tcp_port, interval_seconds);
            
        case CONDITION_UDP_PORT:
            return wait_for_port_condition(udp_port_arg, check_for_udp_port, interval_seconds);
            
        case CONDITION_FILE:
            return wait_for_file_condition(file_path_arg, interval_seconds);
            
        default:
            return EXIT_FAILURE;
    }
}