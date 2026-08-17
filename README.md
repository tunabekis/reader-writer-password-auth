# Reader-Writer Password Auth

A C implementation of the classic **Reader-Writer problem** extended with
password-based access control, built with POSIX threads (`pthread`) and
POSIX semaphores on Linux.

## Overview

The program simulates concurrent access to a shared in-memory resource
(`buffer_value`) by reader and writer threads. Before a thread may touch the
resource, it must present a password drawn from a shared password table:

- A table of `MAX_PASSWORDS` (10) unique random 6-digit passwords is
  generated once, in `main()`, before any threads are created.
- Each **real** reader/writer thread receives a unique password from that
  table and is granted access.
- For every real reader/writer, one **dummy** reader/writer is also spawned
  with a random 6-digit password guaranteed to be absent from the table, to
  demonstrate that access is correctly denied to unauthorized threads.
- Readers may access the resource concurrently with each other; writers get
  exclusive access. This is implemented as the classic **first
  readers-writers** solution (readers are prioritized over waiting writers).
- Each thread performs 5 operations, sleeping 1 second between them.

The program runs three fixed test cases — (2 readers, 3 writers),
(5 readers, 5 writers), and (4 readers, 1 writer) — and prints one table
per case with the columns: `Thread No | Validity | Role | Value`.

## Design / Synchronization

| Semaphore            | Purpose                                              |
|-----------------------|-------------------------------------------------------|
| `rw_mutex`            | Exclusive access to `buffer_value` for writers        |
| `reader_count_mutex`  | Protects the shared `read_count` variable             |
| `password_mutex`      | Protects lookups against the password table           |
| `print_mutex`         | Serializes stdout writes so log rows don't interleave |

## Assumptions

The assignment explicitly allows free assumptions as long as they are
documented:

- Readers take priority over waiting writers (first-readers-writers
  solution), matching the pattern taught in the course lecture notes.
- Real threads are assigned `password_table[0 .. readers+writers-1]` in
  creation order (readers first, then writers).
- A dummy thread's password only needs to be absent from the real password
  table; duplicate passwords among dummy threads themselves are harmless,
  since every dummy thread is rejected regardless.
- Each test case is validated against the assignment's stated bounds
  (1-9 readers, 1-9 writers, and a combined real-thread count that cannot
  exceed the 10-entry password table); the program aborts with a clear
  error message if a case violates these bounds.

## Requirements

- Linux (uses `pthread`, POSIX `sem_t`, and `unistd.h`'s `sleep`)
- `gcc` with pthread support

## Build

```bash
gcc -Wall -Wextra -O2 -std=c11 -o reader_writer_password reader_writer_password.c -lpthread
```

## Run

```bash
./reader_writer_password
```

### Sample output (excerpt)

```
--- TABLE 1: 2 Readers, 3 Writers ---
Thread No  Validity        Role            Value
------------------------------------------------------------
1          Real            Reader          0
2          Real            Reader          0
3          Real            Writer          3595
6          Dummy           Reader          Access Denied
...
```

Each run uses a freshly seeded random password table and random buffer
values, so exact numbers will differ between runs; the structure and
counts (5 operations per thread, one row per operation) stay the same.
