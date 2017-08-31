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
