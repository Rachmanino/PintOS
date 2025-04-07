#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

/* Syscall handlers for dispatching. */
typedef void syscall_handler_t (struct intr_frame *f);
static syscall_handler_t *syscall_handlers[MAX_SYSCALL_NUM];

bool valid_ptr(const void * ptr);
bool valid_buffer(const void * ptr, size_t size);
bool valid_str(const char * str);
#define CHECK(expr) \
  if (!(expr)) {      \
    thread_exit();  \
  }

static void syscall_handler (struct intr_frame *);
static void syscall_halt_handler (struct intr_frame *);
static void syscall_exit_handler (struct intr_frame *);
static void syscall_create_handler (struct intr_frame *);
static void syscall_remove_handler (struct intr_frame *);
static void syscall_open_handler (struct intr_frame *);
static void syscall_close_handler (struct intr_frame *);
static void syscall_filesize_handler (struct intr_frame *);
static void syscall_read_handler (struct intr_frame *);
static void syscall_write_handler (struct intr_frame *);
static void syscall_exec_handler (struct intr_frame *); 
static void syscall_wait_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  // Register implemented syscall handlers
  syscall_handlers[SYS_HALT] = &syscall_halt_handler;
  syscall_handlers[SYS_EXIT] = &syscall_exit_handler;
  syscall_handlers[SYS_CREATE] = &syscall_create_handler;
  syscall_handlers[SYS_REMOVE] = &syscall_remove_handler;
  syscall_handlers[SYS_OPEN] = &syscall_open_handler;
  syscall_handlers[SYS_CLOSE] = &syscall_close_handler;
  syscall_handlers[SYS_FILESIZE] = &syscall_filesize_handler;
  syscall_handlers[SYS_READ] = &syscall_read_handler;
  syscall_handlers[SYS_WRITE] = &syscall_write_handler;
  syscall_handlers[SYS_EXEC] = &syscall_exec_handler; 
  syscall_handlers[SYS_WAIT] = &syscall_wait_handler; 
}

static void
syscall_handler (struct intr_frame *f) 
{
  // printf ("system call!\n");
  CHECK (valid_buffer(f->esp, sizeof(int)));
  int intr_no = *(int*)f->esp;
  CHECK (intr_no >= 0 && intr_no < MAX_SYSCALL_NUM);
  syscall_handlers[intr_no] (f); // Dispatch to the appropriate syscall handler
}

static void 
syscall_halt_handler (struct intr_frame *f UNUSED) {
  shutdown_power_off ();
}

static void
syscall_exit_handler (struct intr_frame *f) {
  CHECK(valid_buffer(f->esp, sizeof(int) * 2)); // Check if the syscall number and exit status are valid
  int* pExitStatus = (int*)f->esp + 1; // Exit status is the first argument after the syscall number
  thread_current()->process->exit_status = *pExitStatus;
  thread_exit ();
}

static void
syscall_create_handler (struct intr_frame *f) {
  CHECK(valid_buffer(f->esp, sizeof(int) * 3)); // Check if the syscall number, file name, and initial size are valid
  const char *file_name = *(const char**)(f->esp + 4);
  CHECK(valid_str(file_name)); // Check if the file name pointer is valid
  unsigned initial_size = *(unsigned*)(f->esp + 8);

  lock_acquire(&global_file_lock);
  f->eax = filesys_create(file_name, initial_size); // Return true if file creation was successful, false otherwise
  lock_release(&global_file_lock);
}

static void
syscall_remove_handler (struct intr_frame *f) {
  CHECK(valid_buffer(f->esp, sizeof(int) * 2)); // Check if the syscall number and file name are valid
  CHECK(valid_str(*(const void**)(f->esp + 4))); // Check if the file name pointer is valid
  const char *file_name = *(const char**)(f->esp + 4);

  lock_acquire(&global_file_lock);
  f->eax = filesys_remove(file_name); // Return true if file removal was successful, false otherwise
  lock_release(&global_file_lock);
}

static void
syscall_open_handler (struct intr_frame *f) {
  CHECK(valid_buffer(f->esp, sizeof(int) * 2)); // Check if the syscall number and file name are valid
  CHECK(valid_str(*(const void**)(f->esp + 4))); // Check if the file name pointer is valid
  const char *file_name = *(const char**)(f->esp + 4);

  lock_acquire(&global_file_lock);
  struct file* file = filesys_open(file_name); // Return the file descriptor if file opening was successful, NULL otherwise
  lock_release(&global_file_lock);

  if (file == NULL) {
    f->eax = -1; // Note here we should return -1 instead of calling thread_exit()
    return;
  }

  struct open_file *open_file = malloc(sizeof(struct open_file)); 
  open_file->file = file;
  open_file->fd = thread_current()->process->fd_count++;
  list_push_back(&thread_current()->process->open_files, &open_file->elem); 
  f->eax = open_file->fd; // Return the file descriptor
}

static void
syscall_close_handler (struct intr_frame *f) {
  CHECK(valid_buffer(f->esp, sizeof(int) * 2)); // Check if the syscall number and file name are valid
  int fd = *(int*)(f->esp + 4);

  CHECK(fd >= 2); 
  struct open_file *open_file = get_open_file(thread_current()->process, fd);
  CHECK(open_file != NULL); // Check if the file descriptor is valid

  lock_acquire(&global_file_lock);
  file_close(open_file->file); // Close the file
  lock_release(&global_file_lock);

  list_remove(&open_file->elem);
  free(open_file);
}

static void
syscall_filesize_handler (struct intr_frame *f) {
  CHECK(valid_buffer(f->esp, sizeof(int) * 2)); // Check if the syscall number and file name are valid
  int fd = *(int*)(f->esp + 4);

  CHECK(fd >= 2); 
  struct open_file *open_file = get_open_file(thread_current()->process, fd);
  CHECK(open_file != NULL); // Check if the file descriptor is valid

  lock_acquire(&global_file_lock);
  f->eax = file_length(open_file->file); // Return the size of the file
  lock_release(&global_file_lock);
}

static void
syscall_read_handler (struct intr_frame *f) {

}

static void
syscall_write_handler (struct intr_frame *f) {
  CHECK(valid_buffer(f->esp, sizeof(int) * 4)); // Check if the syscall number, file descriptor, buffer, and size are valid
  CHECK(valid_str((const void*)(f->esp + 8))) // Check if the buffer pointer is valid
  int fd = *(int*)(f->esp + 4);
  const char *buffer = *(const void**)(f->esp + 8);
  unsigned size = *(unsigned*)(f->esp + 12);

  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    f->eax = size; // Return the number of bytes written
  } else {
    PANIC("File descriptor other than -1 is not supported now!\n"); //TODO
  }
}

static void
syscall_exec_handler (struct intr_frame *f) {
  CHECK(valid_buffer(f->esp, sizeof(int) * 2)); // Check if the syscall number and file name are valid
  const char *cmdline = *(const char**)(f->esp + 4);
  CHECK(valid_str(cmdline)); // Check if the command line pointer is valid

  // We acquire and release the file lock in process_execute()->start_process() instead of here
  f->eax = process_execute(cmdline); // Return the thread ID of the new process
}

static void
syscall_wait_handler (struct intr_frame *f) {
  f->eax = process_wait(*(tid_t*)(f->esp + 4)); // Wait for the child process to finish and return its exit status
}

/* Check if ptr is valid */
bool
valid_ptr(const void * ptr) {
  return ptr != NULL && is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr) != NULL;
}

/* Check if buffer: [ptr, ptr+size) is valid */
bool  
valid_buffer(const void * ptr, size_t size) {
  return valid_ptr(ptr) && valid_ptr(ptr + size - 1); //TODO: check every page
}

/* Check if str is valid */
bool
valid_str(const char * str) {
  if (!valid_ptr(str)) {
    return false;
  }
  return valid_buffer(str, strlen(str) + 1); // Check if the string is valid
}