#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"

/* Syscall handlers for dispatching. */
typedef void syscall_handler_t (struct intr_frame *f);
static syscall_handler_t *syscall_handlers[MAX_SYSCALL_NUM];

static void syscall_handler (struct intr_frame *);
static void syscall_halt_handler (struct intr_frame *);
static void syscall_exit_handler (struct intr_frame *);
static void syscall_write_handler (struct intr_frame *);
static void syscall_create_handler (struct intr_frame *);
static void syscall_wait_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  // Register implemented syscall handlers
  syscall_handlers[SYS_HALT] = &syscall_halt_handler;
  syscall_handlers[SYS_EXIT] = &syscall_exit_handler;
  syscall_handlers[SYS_WRITE] = &syscall_write_handler;
  syscall_handlers[SYS_CREATE] = &syscall_create_handler;
  syscall_handlers[SYS_WAIT] = &syscall_wait_handler; // Prerequisite: execute syscall
}

static void
syscall_handler (struct intr_frame *f) 
{
  
  // printf ("system call!\n");
  int intr_no = *(int*)f->esp;
  if (intr_no < 0 || intr_no >= MAX_SYSCALL_NUM) {
    printf ("Invalid syscall number: %d\n", intr_no);
    thread_exit ();
  }
  PANIC("Syscall number: %d\n", intr_no); // Debugging info
  syscall_handlers[intr_no] (f);
}

static void 
syscall_halt_handler (struct intr_frame *f UNUSED) {
  shutdown_power_off ();
}

static void
syscall_exit_handler (struct intr_frame *f) {
  int* pExitStatus = (int*)f->esp + 1; // Exit status is the first argument after the syscall number
  thread_current()->process->exit_status = *pExitStatus;
  thread_exit ();
}

static void
syscall_write_handler (struct intr_frame *f) {
  int fd = *(int*)(f->esp + 4);
  const char *buffer = *(const void**)(f->esp + 8);
  unsigned size = *(unsigned*)(f->esp + 12);

  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    f->eax = size; // Return the number of bytes written
  } else {
    PANIC("File descriptor other than -1 is not supported now!\n");
  }
}

static void
syscall_create_handler (struct intr_frame *f) {
  const char *file_name = *(const char**)(f->esp + 4);
  unsigned initial_size = *(unsigned*)(f->esp + 8);

  if (file_name == NULL) {
    thread_exit(); // Invalid file name, exit the thread
  }

  bool success = filesys_create(file_name, initial_size);
  f->eax = success; // Return true if file creation was successful, false otherwise
}

static void
syscall_wait_handler (struct intr_frame *f) {
  f->eax = process_wait(*(tid_t*)(f->esp + 4)); // Wait for the child process to finish and return its exit status
}
