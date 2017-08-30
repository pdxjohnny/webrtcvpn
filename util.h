#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>

struct process {
  pid_t pid;
  int stdin;
  int stdout;
};

struct process drop_privs_and_exec_comms(char **argv);
void hexdump(int fd, const char *buf, size_t buf_size);

#endif
