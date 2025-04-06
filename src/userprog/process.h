#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

#define MAX_ARGUMENT_LENGTH 64
#define MAX_ARG_NUM 32

typedef int tid_t;

struct process {
    struct thread *thread; // Thread of the process
    struct list_elem child_elem; // List element for the child process
    struct list_elem elem; // List element for the list containing all processes
    struct list child_list; // List of child processes
    struct process *parent; // Parent process
    // struct semaphore load_sema;   // Semaphore for waiting for the process to load
    struct semaphore death;   // Semaphore for waiting for the process to finish
    int exit_status; // Exit status of the process
    // bool load_success; // Whether the process loaded successfully
};

void process_init (void); // Initialize the process module
void init_process(struct thread *t); // Use ptr to thread rather than process because we aim to obtain the ptr to the thread
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);


#endif /**< userprog/process.h */
