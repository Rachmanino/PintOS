#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"

static thread_func start_process;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Initialize the process module. */
void process_init() {
  list_init(&all_process);
  lock_init(&global_file_lock); // Initialize the global file lock
}

/* Find one open_file of a process with its fd, NULL if failed. */
struct open_file* get_open_file(struct process *p, int fd) {
  for (struct list_elem *e = list_begin(&p->open_files); e != list_end(&p->open_files); e = list_next(e)) {
    struct open_file *f = list_entry(e, struct open_file, elem);
    if (f->fd == fd) {
      return f;
    }
  }
  return NULL;
}

/* Initialize a process instance. */
void 
init_process (struct thread* t) {
  struct process *p = palloc_get_page (0); // Allocate a new process structure
  ASSERT(p != NULL);
  t->process = p;
  t->process->thread = t;
  t->process->exit_status = -1;
  t->process->pid = t->tid; // Set the process ID to the thread ID
  list_init(&t->process->child_list);
  list_push_back(&all_process, &t->process->elem); // Add the process to the list of all processes

  list_init(&t->process->open_files); // Initialize the list of open files for the process
  t->process->fd_count = 2; // 0 and 1 are reserved for stdin and stdout

  sema_init(&t->process->death, 0); // Initialize the semaphore for waiting for the process to finish
}

/* Parse a command line into struct `parsed_cmd`. */
static void
parse_cmd (char* cmdline, struct parsed_cmd *cmd)
{
  char *token, *save_ptr;
  for (token = strtok_r (cmdline, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr))
    {
      if (cmd->argc == 0)
        strlcpy (cmd->file_name, token, strlen(token)+1); // First token is the file name
      strlcpy(cmd->argv[cmd->argc], token, strlen(token)+1);
      cmd->argc++;
    }
}

/* Find a process with its tid, return NULL if failed. */
static struct process* 
get_process(tid_t tid) {;
  for (struct list_elem *e = list_begin(&all_process); e != list_end(&all_process); e = list_next(e)) {
    struct process *p = list_entry(e, struct process, elem);
    if (p->pid == tid) {
      return p;
    }
  }
  return NULL;
}

/* Find one of current process's child processes with its tid, 
return NULL if failed. */
static struct process* 
get_child_process(tid_t tid) {
  struct thread *cur = thread_current ();
  for (struct list_elem *e = list_begin(&cur->process->child_list); e != list_end(&cur->process->child_list); e = list_next(e)) {
    struct process *p = list_entry(e, struct process, child_elem);
    if (p->pid == tid) {
      return p;
    }
  }
  return NULL;
}

/** Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmdline) 
{
  struct parsed_cmd *cmd;
  char* cmdline_copy; // Copy of the command line, since parse_cmd() modifies it
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  cmd = palloc_get_page (PAL_ZERO);
  cmdline_copy = palloc_get_page (0);
  strlcpy(cmdline_copy, cmdline, strlen(cmdline)+1); // Copy the command line
  parse_cmd (cmdline_copy, cmd);
  palloc_free_page(cmdline_copy); // Free the command line copy

  sema_init(&cmd->load_finished, 0); // Initialize the semaphore
  cmd->load_success = false; 
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (cmd->file_name, PRI_DEFAULT, start_process, cmd);
  if (tid == TID_ERROR) {
    palloc_free_page(cmd);
    return TID_ERROR;
  } else {
    sema_down(&cmd->load_finished); // Wait for the load to finish
    if (!cmd->load_success) {
      palloc_free_page(cmd);
      return TID_ERROR; // Load failed
    } else {      
      struct process *p = get_process(tid), *cur = thread_current()->process;
      p->parent = cur; // Set the parent process
      if (thread_current()->tid != 1) {
        list_push_back(&cur->child_list, &p->child_elem); // For the initial process, we don't need to add it to the list of child processes
      }
      palloc_free_page(cmd); // Free the command structure
      return tid;
    }
  }
}

/** A thread function that loads a user process and starts it
   running. */
static void
start_process (void *cmd_)
{
  struct parsed_cmd *cmd = cmd_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  lock_acquire(&global_file_lock); // Acquire the global file lock
  success = load (cmd->file_name, &if_.eip, &if_.esp);
  lock_release(&global_file_lock); // Release the global file lock

  cmd->load_success = success; // Set the load success flag

  if (success) {
    uint32_t top = (uint32_t)PHYS_BASE;
    uint32_t* argv_ptrs[MAX_ARG_NUM];
    memset(argv_ptrs, 0, sizeof(argv_ptrs));
    // 1. Push arg strings
    for (int i = cmd->argc - 1; i >= 0; i--) {
      top -= strlen(cmd->argv[i])+1;
      strlcpy((char*)top, cmd->argv[i], strlen(cmd->argv[i])+1);
      argv_ptrs[i] = (uint32_t*)top; 
    }
    // 2. Align to 4 bytes
    top -= top % 4; 
    // 3. Push argv_ptrs
    for (int i = cmd->argc; i >= 0; i--) {
      top -= 4;
      *(uint32_t**)top = argv_ptrs[i]; 
    }
    // 4. Push ptr to argv_ptrs
    top -= 4;
    *(uint32_t**)top = (uint32_t*)(top + 4); 
    // 5. Push argc
    top -= 4;
    *(int*)top = cmd->argc;
    // 6. Push return address (fake)  
    top -= 4;
    *(void**)top = NULL; 
    // 7. Set return value to %esp
    if_.esp= (void *) top;

    sema_up(&cmd->load_finished); // Signal that the load has finished
  } else {
    /* If load failed, exit the thread. */
    sema_up(&cmd->load_finished); 
    thread_exit ();
  }
  
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  // Check 1: Invalid child process
  if (child_tid == TID_ERROR) {
    return -1; 
  } 
  struct process *child;
  
  if (thread_current()->tid==1) {
    child = get_process(child_tid);
  } else {
    child = get_child_process(child_tid);
  }

  // Check 2: Wait twice (Child process has dead)
  if (child == NULL) { 
    return -1;
  }
 
  sema_down(&child->death); // Wait for the child process to finish
  if (thread_current()->tid!=1) {
    list_remove(&child->child_elem);
  }
  list_remove(&child->elem); // Remove the child process from the list of all processes
  int exit_status = child->exit_status; 
  palloc_free_page(child); 
  return exit_status; 
}

/** Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) // User process
    {
      printf("%s: exit(%d)\n", cur->name, cur->process->exit_status);
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  lock_acquire(&global_file_lock);
  for (struct list_elem *e = list_begin(&cur->process->open_files); e != list_end(&cur->process->open_files);) {
    struct open_file *f = list_entry(e, struct open_file, elem);
    file_close(f->file); // file_close() will call file_allow_write()
    e = list_remove(e);
    free(f); // Free the open file structure
  }
  lock_release(&global_file_lock);
  
  // Signal the parent process that this process has exited
  sema_up(&cur->process->death); 
}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32   /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /**< Ignore. */
#define PT_LOAD    1            /**< Loadable segment. */
#define PT_DYNAMIC 2            /**< Dynamic linking info. */
#define PT_INTERP  3            /**< Name of dynamic loader. */
#define PT_NOTE    4            /**< Auxiliary info. */
#define PT_SHLIB   5            /**< Reserved. */
#define PT_PHDR    6            /**< Program header table. */
#define PT_STACK   0x6474e551   /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /**< Executable. */
#define PF_W 2          /**< Writable. */
#define PF_R 4          /**< Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/** load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/** Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
