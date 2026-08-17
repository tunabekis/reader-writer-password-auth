/*
 * Reader-Writer problem with password-based access control.
 *
 * Implements the classic "first readers-writers" solution with POSIX
 * semaphores. Each reader/writer thread must present a password drawn
 * from a shared password table before it may touch the shared resource
 * (buffer_value). An equal number of "dummy" threads run alongside the
 * real ones with passwords guaranteed to be absent from the table, to
 * demonstrate that unauthorized threads are correctly rejected.
 *
 * Assumptions (the assignment explicitly allows free assumptions as long
 * as they are documented):
 *  - Readers take priority over waiting writers (first-readers-writers
 *    solution), matching the semaphore pattern from the lecture notes.
 *  - Real threads receive password_table[0 .. num_readers+num_writers-1]
 *    in creation order (readers first, then writers).
 *  - A dummy thread's password only needs to be absent from the real
 *    password table; duplicate passwords among dummy threads themselves
 *    are harmless since all dummy threads are rejected regardless.
 *
 * Build:  gcc -Wall -Wextra -O2 -o reader_writer_password reader_writer_password.c -lpthread
 * Run:    ./reader_writer_password
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_PASSWORDS         10               // Size of the real password table
#define OPS_PER_THREAD         5               // Operations performed by each thread
#define PASSWORD_MIN       100000              // Smallest 6-digit password
#define PASSWORD_MAX       999999              // Largest 6-digit password
#define BUFFER_VALUE_MAX    10000              // Writers pick a value in [0, BUFFER_VALUE_MAX)
#define MAX_THREADS_PER_CASE (2 * MAX_PASSWORDS) // real + dummy threads, upper bound

// Shared resource guarded by the reader-writer synchronization below.
static int buffer_value = 0;

// Synchronization primitives.
static sem_t rw_mutex;           // Exclusive access to buffer_value for writers
static sem_t reader_count_mutex; // Protects read_count
static sem_t password_mutex;     // Protects password_table lookups
static sem_t print_mutex;        // Serializes stdout writes
static int read_count = 0;

static int password_table[MAX_PASSWORDS];

typedef struct {
    int thread_no;
    int password;
    bool is_real;
    const char *role;
} ThreadArgs;

// Aborts the program if a pthread_* call reports an error (nonzero return).
static void check_pthread(int rc, const char *what) {
    if (rc != 0) {
        fprintf(stderr, "Fatal error in %s: %s\n", what, strerror(rc));
        exit(EXIT_FAILURE);
    }
}

// Aborts the program if a sem_* call reports an error (-1 return, errno set).
static void check_sem(int rc, const char *what) {
    if (rc != 0) {
        fprintf(stderr, "Fatal error in %s: %s\n", what, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static int random_password(void) {
    return (rand() % (PASSWORD_MAX - PASSWORD_MIN + 1)) + PASSWORD_MIN;
}

static bool password_in_table(int pwd) {
    for (int i = 0; i < MAX_PASSWORDS; i++) {
        if (password_table[i] == pwd) {
            return true;
        }
    }
    return false;
}

// Fills the table with MAX_PASSWORDS unique random 6-digit passwords.
static void fill_password_table(void) {
    for (int i = 0; i < MAX_PASSWORDS; i++) {
        int candidate;
        do {
            candidate = random_password();
        } while (password_in_table(candidate));
        password_table[i] = candidate;
    }
}

// Generates a password guaranteed not to appear in the real password table.
static int random_dummy_password(void) {
    int candidate;
    do {
        candidate = random_password();
    } while (password_in_table(candidate));
    return candidate;
}

static bool is_valid_password(int pwd) {
    sem_wait(&password_mutex);
    bool found = password_in_table(pwd);
    sem_post(&password_mutex);
    return found;
}

// Prints one access-log row; serialized so concurrent threads never garble output.
static void log_access(int thread_no, bool is_real, const char *role, const char *value_desc) {
    sem_wait(&print_mutex);
    printf("%-10d %-15s %-15s %-15s\n", thread_no, is_real ? "Real" : "Dummy", role, value_desc);
    sem_post(&print_mutex);
}

// First-reader-locks-out-writers / last-reader-releases-writers protocol.
static void reader_enter(void) {
    sem_wait(&reader_count_mutex);
    read_count++;
    if (read_count == 1) {
        sem_wait(&rw_mutex); // First reader blocks writers
    }
    sem_post(&reader_count_mutex);
}

static void reader_exit(void) {
    sem_wait(&reader_count_mutex);
    read_count--;
    if (read_count == 0) {
        sem_post(&rw_mutex); // Last reader unblocks writers
    }
    sem_post(&reader_count_mutex);
}

static void *reader_thread(void *arg) {
    ThreadArgs *data = (ThreadArgs *)arg;

    for (int i = 0; i < OPS_PER_THREAD; i++) {
        if (is_valid_password(data->password)) {
            reader_enter();
            char value_desc[16];
            snprintf(value_desc, sizeof(value_desc), "%d", buffer_value);
            log_access(data->thread_no, true, "Reader", value_desc);
            reader_exit();
        } else {
            log_access(data->thread_no, false, "Reader", "Access Denied");
        }
        sleep(1); // Required 1 second pause between operations
    }
    return NULL;
}

static void *writer_thread(void *arg) {
    ThreadArgs *data = (ThreadArgs *)arg;

    for (int i = 0; i < OPS_PER_THREAD; i++) {
        if (is_valid_password(data->password)) {
            sem_wait(&rw_mutex); // Exclusive access
            buffer_value = rand() % BUFFER_VALUE_MAX;
            char value_desc[16];
            snprintf(value_desc, sizeof(value_desc), "%d", buffer_value);
            log_access(data->thread_no, true, "Writer", value_desc);
            sem_post(&rw_mutex);
        } else {
            log_access(data->thread_no, false, "Writer", "Access Denied");
        }
        sleep(1); // Required 1 second pause between operations
    }
    return NULL;
}

// Validates a test case against the assignment's stated constraints.
static void validate_case(int num_readers, int num_writers) {
    if (num_readers < 1 || num_readers > 9 || num_writers < 1 || num_writers > 9) {
        fprintf(stderr, "Invalid case: readers and writers must each be in [1, 9].\n");
        exit(EXIT_FAILURE);
    }
    if (num_readers + num_writers > MAX_PASSWORDS) {
        fprintf(stderr,
                "Invalid case: total real readers/writers (%d) exceeds the password table size (%d).\n",
                num_readers + num_writers, MAX_PASSWORDS);
        exit(EXIT_FAILURE);
    }
}

// Runs one test case: spawns real + dummy reader/writer threads and waits for them.
static void run_case(int num_readers, int num_writers, int case_num) {
    validate_case(num_readers, num_writers);

    int total_real = num_readers + num_writers;
    int total_dummy = num_readers + num_writers; // Equal number of dummy readers & writers
    int total_threads = total_real + total_dummy;
    assert(total_threads <= MAX_THREADS_PER_CASE);

    pthread_t threads[MAX_THREADS_PER_CASE];
    ThreadArgs args[MAX_THREADS_PER_CASE];

    sem_wait(&print_mutex);
    printf("\n--- TABLE %d: %d Readers, %d Writers ---\n", case_num, num_readers, num_writers);
    printf("%-10s %-15s %-15s %-15s\n", "Thread No", "Validity", "Role", "Value");
    printf("------------------------------------------------------------\n");
    sem_post(&print_mutex);

    int t_idx = 0;

    // Real readers, then real writers: each gets a unique password from the table.
    for (int i = 0; i < num_readers; i++) {
        args[t_idx] = (ThreadArgs){t_idx + 1, password_table[t_idx], true, "Reader"};
        check_pthread(pthread_create(&threads[t_idx], NULL, reader_thread, &args[t_idx]), "pthread_create(reader)");
        t_idx++;
    }
    for (int i = 0; i < num_writers; i++) {
        args[t_idx] = (ThreadArgs){t_idx + 1, password_table[t_idx], true, "Writer"};
        check_pthread(pthread_create(&threads[t_idx], NULL, writer_thread, &args[t_idx]), "pthread_create(writer)");
        t_idx++;
    }

    // Dummy readers, then dummy writers: passwords guaranteed absent from the table.
    for (int i = 0; i < total_dummy; i++) {
        bool as_reader = i < num_readers;
        args[t_idx] = (ThreadArgs){t_idx + 1, random_dummy_password(), false, as_reader ? "Reader" : "Writer"};
        check_pthread(
            pthread_create(&threads[t_idx], NULL, as_reader ? reader_thread : writer_thread, &args[t_idx]),
            "pthread_create(dummy)");
        t_idx++;
    }

    for (int i = 0; i < total_threads; i++) {
        check_pthread(pthread_join(threads[i], NULL), "pthread_join");
    }
}

int main(void) {
    srand((unsigned int)time(NULL));

    fill_password_table();

    check_sem(sem_init(&rw_mutex, 0, 1), "sem_init(rw_mutex)");
    check_sem(sem_init(&reader_count_mutex, 0, 1), "sem_init(reader_count_mutex)");
    check_sem(sem_init(&password_mutex, 0, 1), "sem_init(password_mutex)");
    check_sem(sem_init(&print_mutex, 0, 1), "sem_init(print_mutex)");

    // Three required test cases; each thread performs OPS_PER_THREAD operations.
    run_case(2, 3, 1);
    run_case(5, 5, 2);
    run_case(4, 1, 3);

    sem_destroy(&rw_mutex);
    sem_destroy(&reader_count_mutex);
    sem_destroy(&password_mutex);
    sem_destroy(&print_mutex);

    return 0;
}
