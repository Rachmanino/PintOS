#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

#define MAX_ARGUMENT_LENGTH 64
#define MAX_ARG_NUM 32

typedef int tid_t;

struct open_file {
    int fd; // File descriptor
    struct file *file; // File pointer
    struct list_elem elem; // List element for the list containing all open files in a process
};
struct lock global_file_lock; // The global lock for accessing files

struct process {
    struct thread *thread; // Thread of the process
    struct list_elem child_elem; // List element for the child process
    struct list_elem elem; // List element for the list containing all processes
    struct list child_list; // List of child processes
    struct process *parent; // Parent process
    struct semaphore death;   // Semaphore for waiting for the process to finish
    int exit_status; // Exit status of the process

    /* Members below are for maintaining file descriptors. */
    struct list open_files; // list<open_file> for the process
    int fd_count; // Number of open files in the process
};

/* Find one open_file of a process with its fd, NULL if failed. */
struct open_file* get_open_file(struct process *p, int fd);

void process_init (void); // Initialize the process module
void init_process(struct thread *t); // Initialize a process instance
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);


#endif /**< userprog/process.h */
