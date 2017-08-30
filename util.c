#include "util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <err.h>

struct process drop_privs_and_exec_comms(char **argv) {
  // Begin pipe setup
  int parent_read_fd[2];
  int parent_write_fd[2];
  struct process child;

  // Create pipes for the parent and child to communicate
  if (pipe(parent_read_fd) == -1) {
    perror("pipe read failed");
    return child;
  }
  // Parent reads from child stdout
  child.stdout = parent_read_fd[0];
  if (pipe(parent_write_fd) == -1) {
    perror("pipe write failed");
    return child;
  }
  // Parent writes to child stdin
  child.stdin = parent_write_fd[1];

  // Create an unprivileged child to do external networking
  child.pid = fork();
  if (child.pid == -1) {
    perror("Failed to fork");
    return child;
  } else if (child.pid == 0) {
    /* Reset signal handlers. */
    signal(SIGFPE,    SIG_DFL);
    signal(SIGILL,    SIG_DFL);
    signal(SIGSEGV,   SIG_DFL);
    signal(SIGHUP,    SIG_DFL);
    signal(SIGTERM,   SIG_DFL);
    signal(SIGINT,    SIG_DFL);
    /* Close ends of the pipes we will not use */
    close(child.stdout);
    close(child.stdin);
    /* The other ends of the pipes become the child's stdin and stdout */
    if (dup2(parent_read_fd[1], STDOUT_FILENO) == -1) {
      perror("dup2 read failed");
      return child;
    }
    if (dup2(parent_write_fd[0], STDIN_FILENO) == -1) {
      perror("dup2 write failed");
      return child;
    }

    /* Relinquishing privileges from:
     * https://www.securecoding.cert.org/confluence/display/c/POS36-C.+Observe+correct+revocation+order+while+relinquishing+privileges
     */
    /*  Drop superuser privileges in correct order */
    if (setgid(getgid()) == -1) {
      perror("setgid failed");
      exit(errno);
    }
    if (setuid(getuid()) == -1) {
      perror("setuid failed");
      exit(errno);
    }
    /*
     * Not possible to regain group privileges due to correct relinquishment
     * order
     */

    /* Exec the child process which will deal with the packets */
    dprintf(STDERR_FILENO, "Using \'%s\' for comms\n", argv[0]);
    if (execvp(argv[0], argv) == -1) {
      dup2(STDERR_FILENO, STDOUT_FILENO);
      perror("execvp failed");
      exit(errno);
    }

    perror("WTF happened");
    exit(1);
  }

  /* Close ends of the pipes we will not use */
  close(parent_read_fd[1]);
  close(parent_write_fd[0]);

  return child;
}

static void line(const int fd, const unsigned int chop) {
  unsigned int i;
  for (i = 0; i < (8 + 1 + 1) + (chop / 2) + (chop * 2) - ((chop % 2 == 0) ? 1 : 0) + 2 + chop; ++i) {
    dprintf(fd, "-");
  }
  dprintf(fd, "\n");
}

void hexdump(int fd, const char *buf, size_t buf_size) {
  const unsigned int chop = 0x0010;
  size_t i, j, k, start_k;
  int newlined = 0;

  line(fd, chop);
  k = 0;
  for (i = 0; i < buf_size / chop && k < buf_size; ++i) {
    dprintf(fd, "%08x: ", (unsigned int)k);
    start_k = k;
    for (j = 0; j < chop && k < buf_size; ++j) {
      dprintf(fd, "%02x", (unsigned char)buf[k]);
      ++k;
      if ((j + 1) % 2 == 0 && j != 0) {
        dprintf(fd, " ");
      }
    }
    if (chop % 2 == 0) {
      dprintf(fd, " ");
    } else {
      dprintf(fd, "  ");
    }
    for (j = start_k; j < k; ++j) {
      if (buf[j] > ' ' && buf[j] < '~') {
        dprintf(fd, "%c", buf[j]);
      } else {
        dprintf(fd, ".");
      }
    }
    dprintf(fd, "\n");
    newlined = 1;
  }
  int last = buf_size - k;
  for (i = 0; i < last && k < buf_size; ++i) {
    dprintf(fd, "%08x: ", (unsigned int)k);
    start_k = k;
    for (j = 0; j < chop && k < buf_size; ++j) {
      dprintf(fd, "%02x", (unsigned char)buf[k]);
      ++k;
      if ((j + 1) % 2 == 0 && j != 0) {
        dprintf(fd, " ");
      }
    }
    for (j = 0; j < ((chop - last) / 2) + ((chop - last) * 2) + (((chop - last) % 2 == 0) ? 1 : 0); ++j) {
      dprintf(fd, " ");
    }
    if (chop % 2 == 0) {
      dprintf(fd, "  ");
    } else {
      dprintf(fd, " ");
    }
    for (j = start_k; j < k; ++j) {
      if (buf[j] > ' ' && buf[j] < '~') {
        dprintf(fd, "%c", buf[j]);
      } else {
        dprintf(fd, ".");
      }
    }
    dprintf(fd, "\n");
    newlined = 1;
  }
  if (!newlined) {
    dprintf(fd, "\n");
  }
  line(fd, chop);
}
