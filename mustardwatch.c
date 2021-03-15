// mustardwatch:
// Run a command, tracing it to detect files it uses (or might use), and watch
// those files for changes. When a file changes, rerun the command.

// There are many things that access files that this program doesn't track.
// For the most part it only looks for files opened for reading, or checked with
// stat.
// In particular, it doesn't track:
// * Files opened for writing
// * Files that exist at startup (like stdin)
// * rename, chmod, unlink, mkdir, bind, mknod, etc.
// * Files opened via io_uring?
// * Files monitored via inotify? (Seems redundant?)
// * Many things no one knows about like name_to_handle_at and open_tree?
// * File descriptors received over domain sockets?

// This program is only for amd64 Linux right now.


// TODO: watch_abs_path uses realpath(), which resolves symbolic links, which
// means that changes to symbolic links themselves aren't tracked. Maybe they
// should be?
// (If so, it would probably be good to look at AT_SYMLINK_{NO,}FOLLOW too.)

// TODO: It might make sense not to watch files that are written to by a tracee
// -- e.g. a common build process is to have a compiler write .o files and then
// have a linker read them (and cp stats the destination before copying, and so
// on). Right now this is handled by ignoring inotify events as long the the
// subprocess is still running, but maybe it's possible to do something better.

// TODO: Some kind of server mode that restarts programs immediately rather than
// waiting for them to finish could be useful. This is made a bit tricky by the
// above.

// TODO: This has some heuristics for files not to watch:
// * Files in common global directories.
// * Directories, except with -d (and then only directories that are open()ed).
// * Files open()ed/access()ed for writing.
// It might be good to make these more configurable, or to tweak them.
// There might also be other good heuristics, like skipping files owned by root.

// TODO: If a tracee tries to open a file that doesn't exist, we could watch its
// parent directory (or the first ancestor that exists). This is slightly tricky
// to do correctly -- better symlink handling should probably come first.
//
// It could also mean watching a lot of extraneous directories, because programs
// expect stat to be a cheap way to check if a file exists. E.g. this would
// watch every directory in $PATH as a shell searches for an executable.

// TODO: If ptrace slows programs down a lot, it might be useful to have a mode
// that detects files on the first run, and then remembers them, rather than
// clearing out the inotify list on each run.
// This might not be necessary, since you can use --out to write out a list of
// relevant files, and then use some other tool to watch them for changes.


#define _GNU_SOURCE 1

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/inotify.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef IN_MASK_CREATE
  #define IN_MASK_CREATE 0x20000000
#endif

#define MOP_IMPLEMENTATION 1
#include "extern/mop.h"

#define Struct(name) typedef struct name name; struct name
#define Union(name) typedef union name name; union name
#define Enum(name) typedef enum name name; enum name

#define cast

#define Case break; case
#define Default break; default
#define OrCase case
#define OrDefault default

#define numof(a) (sizeof (a) / sizeof (*(a)))

#define ALIGNED_AS(type) __attribute__((aligned(__alignof__ (type))))
#define NORETURN __attribute__((noreturn))

typedef uint8_t  U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef uint64_t U64;
typedef int8_t   S8;
typedef int16_t  S16;
typedef int32_t  S32;
typedef int64_t  S64;


void print_wstatus(pid_t pid, int w) {
  printf("wstatus (%d): 0x%x. ", pid, w);
  if (WIFEXITED(w))
    printf("exited %d. ", WEXITSTATUS(w));
  if (WIFSIGNALED(w))
    printf("signaled %d (%s). %s",
           WTERMSIG(w), strsignal(WTERMSIG(w)),
           WCOREDUMP(w) ? "(core dumped). " : "");
  if (WIFSTOPPED(w)) {
    printf("stopped %d (%s). ",
           WSTOPSIG(w), strsignal(WSTOPSIG(w) & 0x7f));
    if (w >> 16) {
      int event = w >> 16;
      printf("ptrace event: ");
      switch (event) {
      Case PTRACE_EVENT_FORK      : printf("FORK");
      Case PTRACE_EVENT_VFORK     : printf("VFORK");
      Case PTRACE_EVENT_CLONE     : printf("CLONE");
      Case PTRACE_EVENT_EXEC      : printf("EXEC");
      Case PTRACE_EVENT_VFORK_DONE: printf("VFORK_DONE");
      Case PTRACE_EVENT_EXIT      : printf("EXIT");
      Case PTRACE_EVENT_SECCOMP   : printf("SECCOMP");
      Case PTRACE_EVENT_STOP      : printf("STOP");
      Default                     : printf("unknown");
      }
      printf(". ");
    }
  }
  if (WIFCONTINUED(w)) printf("continued. ");
  printf("\n");
}

Struct(InotifyEventName) {
  U32 mask;
  char *name;
};

#define EVENT(x) { x, #x }
static InotifyEventName inotify_event_names[] = {
  EVENT(IN_ACCESS), EVENT(IN_MODIFY), EVENT(IN_ATTRIB),
  EVENT(IN_CLOSE_WRITE), EVENT(IN_CLOSE_NOWRITE), EVENT(IN_CLOSE),
  EVENT(IN_OPEN),
  EVENT(IN_MOVED_FROM), EVENT(IN_MOVED_TO), EVENT(IN_MOVE),
  EVENT(IN_CREATE),
  EVENT(IN_DELETE), EVENT(IN_DELETE_SELF), EVENT(IN_MOVE_SELF),

  EVENT(IN_UNMOUNT), EVENT(IN_Q_OVERFLOW), EVENT(IN_IGNORED),
};
#undef EVENT

void print_inotify_event(struct inotify_event *event) {
  printf("inotify event (%d): 0x%x (", event->wd, event->mask);
  bool first = true;
  for (U32 i = 0; i < numof(inotify_event_names); i++) {
    if ((event->mask & inotify_event_names[i].mask) == inotify_event_names[i].mask) {
      printf("%s%s", first ? "" : "|", inotify_event_names[i].name);
      first = false;
    }
  }
  printf(")");
  if (event->len) {
    printf(": [%s]", event->name);
  }
  printf("\n");
}

NORETURN
void die(const char *msg) {
  fprintf(stderr, "%s: %s\n", msg, strerror(errno));
  exit(1);
}

Enum(TraceeEventType) {
  TraceeEvent_Exited,        // Exited with exit
  TraceeEvent_Exited_Signal, // Died with a signal

  TraceeEvent_Syscall,       // Right before or right after a system call
  TraceeEvent_GroupStopped,  // Stopped due to stopping signal; see below
  TraceeEvent_Interrupted,   // Interrupted for various reasons
  TraceeEvent_GotSignal,     // Got a signal
  TraceeEvent_MadeChild,     // Forked, etc. (event delivered on the parent)
  TraceeEvent_Exec,          // About to exec
};

Struct(TraceeEvent) {
  TraceeEventType type;
  union {
    int signal;    // _Exited_Signal, _GotSignal
    int exit_code; // _Exited
  };
};

Enum(TraceeState) {
  TraceeState_Running,
  TraceeState_InSyscall,
};

Struct(Tracee) {
  TraceeState state;
  pid_t pid;
};

enum { MAX_TRACEES = 128 };

Struct(State) {
  char **program_argv;
  int verbose;
  bool clear;
  bool watch_directories;
  bool watch_common_directories;
  char *out_path;
  FILE *out_file;

  sigset_t orig_sigmask;
  int inotify_fd;
  int signal_fd;
  int child_pid;
  Tracee tracees[MAX_TRACEES];
  int tracees_len;
};


// Translate an event from the labyrinth of ptrace-related waitpid() statuses
// into a more reasonable form.
TraceeEvent translate_ptrace_event(int wstatus) {
  // The tracee might have exited, either due to exit() or due to a signal.
  if (WIFEXITED(wstatus)) {
    return (TraceeEvent){.type = TraceeEvent_Exited,
                         .signal = WEXITSTATUS(wstatus)};
  }
  if (WIFSIGNALED(wstatus)) {
    return (TraceeEvent){.type = TraceeEvent_Exited_Signal,
                         .signal = WTERMSIG(wstatus)};
  }

  assert(WIFSTOPPED(wstatus));

  // The tracee stopped. This can be for several reasons:
  // * Syscall-stop (the tracee is about to enter or just exited a syscall)
  // * PTRACE_EVENT stop (we got a PTRACE_EVENT like FORK)
  // * Group-stop (non-signal stops sent to all threads)
  // * Signal-delivery-stop (the tracee got a signal which we're intercepting)

  // The situation with group-stop is this:
  // When a tracee gets e.g. a SIGSTOP, it gets a signal-delivery-stop (on one
  // thread), which we treat like any signal (just pass the signal on). After
  // we forward the signal, we get a "group-stop": Every thread is stopped, and
  // is put in a special stopped state. We want the tracee to be in a regular
  // stopped state, so instead of resuming as normal (which would continue a
  // tracee that's supposed to be stopped), we use PTRACE_LISTEN, which puts it
  // in a regular stopped state.

  int sig = WSTOPSIG(wstatus);
  int event = wstatus >> 16;

  switch (event) {
  Case 0:
    if (sig == (SIGTRAP|0x80)) {
      // Syscall-stop (reported with TRACESYSGOOD).
      return (TraceeEvent){.type = TraceeEvent_Syscall};
    } else {
      // Signal-delivery-stop.
      return (TraceeEvent){.type = TraceeEvent_GotSignal, .signal = sig};
    }
  Case PTRACE_EVENT_FORK: OrCase PTRACE_EVENT_VFORK: OrCase PTRACE_EVENT_CLONE:
    return (TraceeEvent){.type = TraceeEvent_MadeChild};
  Case PTRACE_EVENT_EXEC:
    return (TraceeEvent){.type = TraceeEvent_Exec};
  Case PTRACE_EVENT_STOP:
    if (sig == SIGTRAP) {
      // SIGTRAP PTRACE_EVENT_STOP. The tracee stopped for various reasons:
      // We called INTERRUPT; this is a newly-forked child; child is resuming
      // execution after a SIGCONT?
      return (TraceeEvent){.type = TraceeEvent_Interrupted};
    } else {
      // Group-stop.
      assert(sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU);
      return (TraceeEvent){.type = TraceeEvent_GroupStopped, .signal = sig};
    }
  }

  fprintf(stderr, "unknown ptrace event! wstatus: %d\n", wstatus);
  exit(1);
}

// Continue normal execution after getting an event.
void tracee_continue_normal_execution(Tracee *tracee, TraceeEvent ev) {
  enum __ptrace_request req = PTRACE_SYSCALL;
  int continue_signal = 0;

  switch (ev.type) {
  Case TraceeEvent_Exited: OrCase TraceeEvent_Exited_Signal:
    return;

  Case TraceeEvent_Syscall:
    switch (tracee->state) {
    Case TraceeState_Running: tracee->state = TraceeState_InSyscall;
    Case TraceeState_InSyscall: tracee->state = TraceeState_Running;
    }

  Case TraceeEvent_Interrupted:
  OrCase TraceeEvent_MadeChild:
  OrCase TraceeEvent_Exec:
    {}

  Case TraceeEvent_GotSignal:
    // Forward a signal to the tracee.
    continue_signal = ev.signal;
  Case TraceeEvent_GroupStopped:
    // The tracee is group-stopped (due to a stopping signal like SIGSTOP),
    // which is a special ptrace-only stopped state. It's supposed to be
    // stopped, so we don't want to restart execution, but we do want it to be
    // in a regular non-ptrace stopped state, so we use PTRACE_LISTEN.
    req = PTRACE_LISTEN;
  }

  long res = ptrace(req, tracee->pid, 0, continue_signal);
  if (res < 0) {
    if (errno == ESRCH) {
      // Tracee died unexpectedly.
      return;
    }
    fprintf(stderr, "continue tracee execution (%d): %s\n",
                    tracee->pid, strerror(errno));
    exit(1);
  }
}


// How does a program use a file?
// Right now, the distinction is: If a program opens a directory, and we're in
// directory-watching mode, we watch the directory (under that assumption it
// opened it for getdents). If it only checks the directory, we don't.
// TODO: It may make sense to watch the directory itself (but not its contents)
// even when the directory is checked.
Enum(UseType) {
  UseType_Open, // E.g. openat
  UseType_Check, // E.g. stat, readlink
  // Maybe UseType_OpenAsDirectory would be good?
};

// Try to read a nul-terminated string from tracee memory, up to size n.
// It may span multiple pages, so read up to the page boundary each time to
// avoid unnecessary faults.
// Maybe this reads too much, since it's used to read paths, which tend to be
// much smaller than pages (even though PATH_MAX is 4096)?
bool read_tracee_string(int pid, U64 child_addr, char *buf, size_t buf_size) {
  const size_t page_size = 4096;

  U64 child_end_addr = child_addr + buf_size;
  U64 total_read_size = 0;
  U64 read_addr = child_addr;

  while (read_addr != child_end_addr) {
    U64 next_page_boundary = read_addr + (page_size - (read_addr & (page_size - 1)));
    U64 chunk_end = child_end_addr;
    if (chunk_end > next_page_boundary) {
      chunk_end = next_page_boundary;
    }

    U64 chunk_size = chunk_end - read_addr;

    struct iovec local = {buf + total_read_size, chunk_size};
    struct iovec remote = {cast(void *) read_addr, chunk_size};
    ssize_t res = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (res < 0) {
      fprintf(stderr, "error reading tracee memory: %s\n", strerror(errno));
      return false;
    }
    assert(cast(U64) res == chunk_size);

    if (memchr(buf + total_read_size, '\0', chunk_size)) {
      // Found a nul terminator.
      return true;
    }

    total_read_size += chunk_size;
    read_addr += chunk_size;
  }

  // Didn't find a nul terminator.
  return false;
}

// Get the path of a tracee file descriptor or (if passed AT_FDCWD) the tracee's
// cwd.
ssize_t get_tracee_fdpath(Tracee *tracee, int tracee_fd, char *buf, size_t buf_size) {
  char proc_path[PATH_MAX];
  if (tracee_fd == AT_FDCWD) {
    snprintf(proc_path, sizeof proc_path, "/proc/%d/cwd", tracee->pid);
  } else {
    snprintf(proc_path, sizeof proc_path, "/proc/%d/fd/%d",
             tracee->pid, tracee_fd);
  }
  ssize_t size = readlink(proc_path, buf, buf_size);
  if (size < 0) { return -1; }
  if (cast(size_t) size == buf_size) { return -1; }
  buf[size] = '\0';
  return size;
}

bool should_watch_resolved_path(State *state, char *path, UseType use_type) {
  // TODO: Make this configurable?
  static char *ignored_prefixes[] = {
    "/bin", "/dev", "/etc", "/lib", "/proc", "/sys", "/tmp", "/usr",
  };

  if (!state->watch_common_directories) {
    for (U32 i = 0; i < numof(ignored_prefixes); i++) {
      char *prefix = ignored_prefixes[i];
      size_t prefix_len = strlen(prefix);
      if (strncmp(prefix, path, prefix_len) == 0) {
        if (path[prefix_len] == '\0' || path[prefix_len] == '/')
          return false;
      }
    }
  }

  // Only watch regular files (and possibly directories).
  struct stat statbuf;
  int res = stat(path, &statbuf);
  if (res < 0) return false;
  mode_t type = statbuf.st_mode & S_IFMT;
  mode_t valid_type_mask = S_IFREG;
  if (state->watch_directories && use_type == UseType_Open)
    valid_type_mask |= S_IFDIR;
  if (!(type & valid_type_mask)) return false;

  // Could also ignore files owned by root or other heuristics.

  return true;
}

void handle_path_at(State *state, Tracee *tracee, UseType use_type,
                   int at_fd, U64 path_addr) {
  // Paths are capped at PATH_MAX (4096). If a path is longer, we'll truncate
  // it, and probably silently fail to track it, which seems fine.
  char path[PATH_MAX];
  bool found = read_tracee_string(tracee->pid, path_addr, path, PATH_MAX);
  if (!found) {
    // Couldn't get path.
    return;
  }

  if (path[0] == '\0') return;

  bool is_absolute = path[0] == '/';
  char full_path[PATH_MAX];
  if (is_absolute) {
    snprintf(full_path, sizeof full_path, "%s", path);
  } else {
    // Relative open path. Get the absolute path corresponding to it.
    char at_path[PATH_MAX];
    ssize_t res = get_tracee_fdpath(tracee, at_fd, at_path, sizeof at_path);
    if (res < 0)
      return;
    int n = snprintf(full_path, sizeof full_path, "%s/%s", at_path, path);
    if (n >= cast(int) sizeof full_path)
      return;
  }

  // It may be a good idea to exit before calling realpath() in some cases, if
  // we know we would skip the file anyway.

  char resolved_path[PATH_MAX];
  char *success = realpath(full_path, resolved_path);
  if (!success)
    return;

  if (!should_watch_resolved_path(state, resolved_path, use_type))
    return;

  // TODO: Figure out the right mask.
  U32 mask = 0;
  mask |= IN_CLOSE_WRITE | IN_MOVED_TO;
  if (state->watch_directories)
    mask |= IN_CREATE | IN_DELETE;
  //mask |= IN_MODIFY;
  //mask |= IN_DELETE_SELF;

  mask |= IN_MASK_CREATE;

  int wd = inotify_add_watch(state->inotify_fd, resolved_path, mask);
  if (wd < 0) {
    if (errno == EEXIST) {
      // We were already watching this file.
    } else {
      fprintf(stderr, "can't inotify_add [%s]: %s\n", resolved_path, strerror(errno));
    }
  } else {
    if (state->out_file) {
      fprintf(state->out_file, "%s\n", resolved_path);
    }

    if (state->verbose > 2) {
      printf("mustardwatch: Watching (%d, tracee: %d) %s\n",
             wd, tracee->pid, resolved_path);
    } else if (state->verbose > 1) {
      printf("mustardwatch: Watching (%d) %s\n", wd, resolved_path);
    }
  }
}

void handle_syscall(State *state, Tracee *tracee) {
  // PTRACE_GET_SYSCALL_INFO would be slightly more convenient than this, but
  // it's only available on pretty recent kernels right now, so I'll look at the
  // registers directly.

  //struct ptrace_syscall_info syscall_info;
  //long res = ptrace(PTRACE_GET_SYSCALL_INFO, tracee->pid,
  //                  sizeof syscall_info, &syscall_info);
  //if (res < 0) die("ptrace error (GET_SYSCALL_INFO)");
  //assert(syscall_info.op == PTRACE_SYSCALL_INFO_ENTRY);

  //U64 syscall_number = syscall_info.entry.nr;
  //U64 args[6] = {syscall_info.entry.args[0], syscall_info.entry.args[1],
  //               syscall_info.entry.args[2], syscall_info.entry.args[3],
  //               syscall_info.entry.args[4], syscall_info.entry.args[5],
  //               };

  struct user_regs_struct regs;
  long res = ptrace(PTRACE_GETREGS, tracee->pid, 0, &regs);
  if (res < 0) {
    if (errno == ESRCH) {
      // Tracee died unexpectedly.
      return;
    }
    die("ptrace error (GETREGS)");
  }

  U64 syscall_number = regs.orig_rax;
  U64 args[6] = {regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9};

  // Some of the *at system calls can operate on fds instead of paths (with ""
  // as the path and AT_EMPTY_PATH in the flags). We don't care about watching
  // fds, so we just treat it as an empty path, which handle_path_at ignores.

  switch (syscall_number) {
  Case __NR_open:
    // For open/openat: Skip files opened for writing, and directories.
    if (cast(int) args[1] & (O_RDWR|O_WRONLY)) break;
    if (!state->watch_directories && cast(int) args[1] & O_DIRECTORY) break;
    handle_path_at(state, tracee, UseType_Open, AT_FDCWD, args[0]);
  Case __NR_openat:
    if (cast(int) args[2] & (O_RDWR|O_WRONLY)) break;
    if (!state->watch_directories && cast(int) args[2] & O_DIRECTORY) break;
    handle_path_at(state, tracee, UseType_Open, cast(int) args[0], args[1]);
  Case __NR_stat:
    handle_path_at(state, tracee, UseType_Check, AT_FDCWD, args[0]);
  Case __NR_lstat:
    handle_path_at(state, tracee, UseType_Check, AT_FDCWD, args[0]);
  Case __NR_newfstatat:
    handle_path_at(state, tracee, UseType_Check, cast(int) args[0], args[1]);
  Case __NR_statx:
    handle_path_at(state, tracee, UseType_Check, cast(int) args[0], args[1]);
  Case __NR_access:
    // For access/faccessat: Skip files checked for writability.
    if (cast(int) args[1] & W_OK) break;
    handle_path_at(state, tracee, UseType_Check, AT_FDCWD, args[0]);
  Case __NR_faccessat:
    // Note: The system call doesn't take a flags argument.
    if (cast(int) args[2] & W_OK) break;
    handle_path_at(state, tracee, UseType_Check, cast(int) args[0], args[1]);
  Case __NR_readlink:
    handle_path_at(state, tracee, UseType_Check, AT_FDCWD, args[0]);
  Case __NR_readlinkat:
    handle_path_at(state, tracee, UseType_Check, cast(int) args[0], args[1]);
  Case __NR_execve:
    handle_path_at(state, tracee, UseType_Check, AT_FDCWD, args[0]);
  Case __NR_execveat:
    handle_path_at(state, tracee, UseType_Check, cast(int) args[0], args[1]);
  // These system calls are too new:
  //Case __NR_faccessat2:
  //Case __NR_readfile:
  }
}

int find_tracee(State *state, pid_t pid) {
  for (int i = 0; i < state->tracees_len; i++) {
    if (state->tracees[i].pid == pid) {
      return i;
    }
  }

  return -1;
}

int add_tracee(State *state, pid_t pid, TraceeState tracee_state) {
  if (state->tracees_len >= MAX_TRACEES) {
    fprintf(stderr, "Exceeded %d tracees! Exiting\n", MAX_TRACEES);
    exit(1);
  }
  int tracee_index = state->tracees_len++;
  state->tracees[tracee_index] = (Tracee){
    .state = tracee_state,
    .pid = pid,
  };
  if (state->verbose > 2) {
    printf("mustardwatch: Added tracee %d\n", pid);
  }

  return tracee_index;
}

void run_program(State *state) {
  if (state->clear) {
    printf("\033[H\033[J\033[2J\033[3J");
    fflush(stdout);
  }

  if (state->verbose > 0) {
    printf("mustardwatch: Running");
    for (char **arg = state->program_argv; *arg; arg++) {
      printf(" %s", *arg);
    }
    printf("\n");
  }

  pid_t child_pid = fork();
  if (child_pid < 0) die("fork error");

  if (child_pid == 0) {
    // We're the child. Reset the signal mask, then stop ourselves to let the
    // parent trace us.

    int r = sigprocmask(SIG_SETMASK, &state->orig_sigmask, 0);
    if (r < 0) die("resetting sigprocmask");

    r = kill(getpid(), SIGSTOP);
    if (r < 0) die("kill($$, SIGSTOP)");

    execvp(state->program_argv[0], state->program_argv);
    die("exec error");
  }

  // Parent.
  state->child_pid = child_pid;

  int wstatus;
  pid_t p = waitpid(state->child_pid, &wstatus, WSTOPPED);
  if (p < 0) die("waitpid for SIGSTOP");
  assert(p == state->child_pid);
  assert(WIFSTOPPED(wstatus));

  U64 flags = 0;
  flags |= PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK;
  flags |= PTRACE_O_TRACEEXEC;
  flags |= PTRACE_O_TRACESYSGOOD;
  flags |= PTRACE_O_EXITKILL;

  // Seize the child. This doesn't stop it (but it's already stopped).
  long res = ptrace(PTRACE_SEIZE, state->child_pid, 0, flags);
  if (res < 0) {
    fprintf(stderr, "ptrace (SEIZE) error: %s\n", strerror(errno));

    // We couldn't seize the child (ptrace_scope permissions?). Kill it.
    int r = kill(state->child_pid, SIGKILL);
    if (r < 0) die("unable to kill child");

    exit(1);
  }

  add_tracee(state, state->child_pid, TraceeState_Running);

  // This may not be necessary, since the child is already stopped?
  res = ptrace(PTRACE_INTERRUPT, state->child_pid, 0, 0);
  if (res < 0) die("ptrace (INTERRUPT) error");

  // Send the child a SIGCONT to resume execution.
  int r = kill(state->child_pid, SIGCONT);
  if (r < 0) die("kill(child, CONT)");
}

void setup_inotify(State *state) {
  state->inotify_fd = inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
  if (state->inotify_fd < 0) die("inotify_init1 error");
}

// Read from a non-blocking file descriptor until EAGAIN, without caring about
// the contents.
void drain_fd(int fd) {
  char buf[4096];
  while (1) {
    ssize_t n = read(fd, buf, sizeof buf);
    if (n < 0) {
      if (errno == EAGAIN)
        break;
      die("drain_fd");
    }
  }
}

int main(int argc, char **argv) {
  State state = {0};

  {
    MopUsageInfo infos[8];
    Mop mop = mop_begin_with_usage(argc, argv, infos, numof(infos));
    MOP_LOOP(&mop) {
      MOP_TEXT("\
Usage: mustardwatch [OPTION...] COMMAND [ARG...]\n\
Run a command, tracing it to detect files it uses (or might use), and watch\n\
those files for changes. When a file changes, rerun the command.\n\
\n\
File events generated while the command is running are ignored. Files in\n\
common global directories (/bin, /dev, /etc, /lib, /proc, /sys, /tmp, /usr)\n\
are skipped by default.\n\
\n\
Files used by subprocesses are also tracked (but note that all subprocesses\n\
are killed when the main process exits).\n\n\
Options:\n\
");
      MOP_OPT(.name = "clear", .short_name = 'c',
              .help = "clear screen before running program") {
        state.clear = true;
      }
      MOP_OPT(.name = "directories", .short_name = 'd',
              .help = "watch directories as well as regular files") {
        state.watch_directories = true;
      }
      MOP_OPT(.name = "global", .short_name = 'g',
              .help = "do not skip files in common global directories") {
        state.watch_common_directories = true;
      }
      MOP_OPT(.name = "out", .short_name = 'o',
              .help = "rather than respawning the process when files change,\n"
                      "  write out a list of watched files to FILE, then exit",
              .param = "FILE") {
        state.out_path = mop.optarg;
      }
      MOP_OPT(.name = "verbose", .short_name = 'v',
              .help = "show verbose output (watched files and events)\n"
                      "  (use multiple times for more verbose output)") {
        state.verbose++;
      }
      MOP_OPT(.name = "help", .help = "print this message") {
        mop_print_usage(&mop, stdout);
        exit(0);
      }
    }
    if (mop.error) {
      fprintf(stderr, "%s: %s\n", mop_error_string(mop.error), mop.error_detail);
      mop_print_usage(&mop, stderr);
      exit(1);
    }

    if (mop.argind == argc) {
      mop_print_usage(&mop, stderr);
      exit(1);
    }

    if (state.out_path) {
      state.out_file = fopen(state.out_path, "w");
      if (!state.out_file) {
        fprintf(stderr, "could not open %s: %s\n", state.out_path, strerror(errno));
        exit(1);
      }
    }

    state.program_argv = argv + mop.argind;
  }

  // Block SIGCHLD, and handle it via signalfd.
  sigset_t sigchld_mask;
  sigemptyset(&sigchld_mask);
  sigaddset(&sigchld_mask, SIGCHLD);
  int r = sigprocmask(SIG_BLOCK, &sigchld_mask, &state.orig_sigmask);
  if (r < 0) die("sigprocmask");

  state.signal_fd = signalfd(-1, &sigchld_mask, SFD_CLOEXEC|SFD_NONBLOCK);
  if (state.signal_fd < 0) die("signalfd");

  setup_inotify(&state);
  run_program(&state);

  while (1) {
    struct pollfd pfds[] = {
      [0] = {.fd = state.inotify_fd, .events = POLLIN},
      [1] = {.fd = state.signal_fd, .events = POLLIN},
    };
    r = ppoll(pfds, numof(pfds), 0, 0);
    if (r < 0 && errno != EINTR) die("ppoll");

    // See if we got any file event notifications.
    if (pfds[0].revents) {
      char buf[4096] ALIGNED_AS(struct inotify_event);
      while (1) {
        ssize_t n = read(state.inotify_fd, buf, sizeof buf);
        if (n < 0) {
          if (errno == EAGAIN) break;
          die("inotify read");
        }
        struct inotify_event *event;
        for (char *ptr = buf;
             ptr < buf + n;
             ptr += sizeof *event + event->len) {
          event = cast(struct inotify_event *) ptr;
          if (state.verbose > 1) {
            printf("mustardwatch: ");
            if (state.tracees_len > 0) {
              printf("ignoring ");
            }
            print_inotify_event(event);
          }
        }
      }

      // If the program is still running, don't do anything. Many build
      // processes do things like write to a .o file from one process and read
      // from it in another, so unless we detect that (e.g. by noting which
      // files they wrote to, and ignoring those), that would cause too many
      // false positives.
      if (state.tracees_len == 0) {
        close(state.inotify_fd);
        setup_inotify(&state);
        run_program(&state);
      }
    }

    // See if any child events happened. We get the information we need from wait,
    // not signalfd -- we only use the fd to wake up when something happens.
    if (pfds[1].revents) {
      drain_fd(state.signal_fd);
    }

    while (1) {
      int wstatus;
      pid_t pid = waitpid(-1, &wstatus, WNOHANG|__WALL);
      if (pid < 0) {
        if (errno == ECHILD) {
          // No children to wait for.
          break;
        }
        die("waitpid");
      }

      if (pid == 0) break;

      TraceeEvent ev = translate_ptrace_event(wstatus);

      if (state.verbose > 4 ||
          (state.verbose > 3 && ev.type != TraceeEvent_Syscall)) {
        printf("mustardwatch: ");
        print_wstatus(pid, wstatus);
      }

      int tracee_index = find_tracee(&state, pid);
      if (tracee_index == -1) {
        // We don't know this tracee, which means an existing tracee cloned.
        // Sometimes we see a new tracee via waitpid before we see get the
        // ptrace event, so we just treat any unknown pid as a new child.
        tracee_index = add_tracee(&state, pid, TraceeState_Running);
      }

      Tracee *tracee = &state.tracees[tracee_index];

      switch (ev.type) {
      Case TraceeEvent_Exited: OrCase TraceeEvent_Exited_Signal:
        if (tracee_index == 0) {
          // If the main process exited, kill all other processes.
          while (state.tracees_len > 1) {
            // It would possibly be nice to just detach from subprocesses
            // instead of killing, but apparently strace makes that kind of
            // complicated.
            pid_t subprocess_pid = state.tracees[state.tracees_len - 1].pid;
            printf("mustardwatch: Killing subprocess %d\n", subprocess_pid);

            kill(subprocess_pid, SIGKILL);

            while (1) {
              int subprocess_wstatus;
              pid_t p = waitpid(subprocess_pid, &subprocess_wstatus, __WALL);
              if (p < 0) die("could not waitpid after killing subprocess");
              if (WIFEXITED(subprocess_wstatus) || WIFSIGNALED(subprocess_wstatus))
                break;
            }

            state.tracees_len--;
          }
          if (state.verbose > 0) {
            printf("mustardwatch: Process exited\n");
          }
          state.tracees_len--;
          if (state.out_file) {
            // We were only writing out a list of watched files, so now that the
            // process has exited, we're done.
            fclose(state.out_file);
            exit(0);
          }
        } else {
          // A subprocess exited. Stop tracing it.
          if (state.verbose > 2) {
            printf("mustardwatch: Tracee %d exited\n", pid);
          }
          state.tracees[tracee_index] = state.tracees[state.tracees_len - 1];
          state.tracees_len--;
        }
      Case TraceeEvent_Syscall:
        if (tracee->state == TraceeState_Running) {
          // This is right before a syscall.
          handle_syscall(&state, tracee);
        }

      Case TraceeEvent_Interrupted: {}
      Case TraceeEvent_GroupStopped: {}
      Case TraceeEvent_GotSignal: {}
      Case TraceeEvent_MadeChild: {
        // We can request the new tracee PID here, but is there a point?
        // We're not guaranteed to see this event before seeing the pid via
        // wait, so we have to handle unknown pids anyway.
      }
      Case TraceeEvent_Exec:
        if (state.verbose > 2) {
          // Report tracee cmdlines as they exec.
          // (cmdline is nul-terminated so only argv[0] should be printed.)
          char path[128];
          snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
          int fd = open(path, O_RDONLY);
          if (fd >= 0) {
            char buf[4096];
            int n = read(fd, buf, sizeof buf);
            if (n > 0) {
              printf("mustardwatch: Tracee %d exec: %.*s\n", pid, n, buf);
            }
            close(fd);
          }
        }
      }

      tracee_continue_normal_execution(tracee, ev);
    }
  }

  return 0;
}
