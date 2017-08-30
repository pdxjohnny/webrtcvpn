#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
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

#include "util.h"

int debugfd = STDERR_FILENO;
const char *ipaddr;
const char *netmask;

char interface_name[1024];

int ssystem(const char *fmt, ...) __attribute__((__format__(__printf__, 1, 2)));

int ssystem(const char *fmt, ...) {
  char cmd[128];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(cmd, sizeof(cmd), fmt, ap);
  va_end(ap);
  printf("%s\n", cmd);
  fflush(stdout);
  return system(cmd);
}

int open_tun(char *dev) {
  struct ifreq ifr;
  int fd, err;
#ifdef __APPLE__
  char devtun[] = "/dev/tun";
#else
  char devtun[] = "/dev/net/tun";
#endif

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TUN   - TUN device
   *        IFF_NO_PI - Do not provide packet information
   */
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if ((fd = open(devtun, O_RDWR)) < 0) {
    return -1;
  }
  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);
  return fd;
}

void cleanup(void) {
#ifndef __APPLE__
  ssystem("ifconfig %s down", interface_name);
#ifndef linux
  ssystem("sysctl -w net.ipv6.conf.all.forwarding=1");
#endif
  ssystem("netstat -nr"
          " | awk '{ if ($2 == \"%s\") print \"route delete -net \"$1; }'"
          " | sh",
          interface_name);
#else
  {
    char *itfaddr = strdup(ipaddr);
    char *prefix = index(itfaddr, '/');
    ssystem("ifconfig %s inet6 %s remove", interface_name, ipaddr);
    ssystem("ifconfig %s down", interface_name);
    if (prefix != NULL)
      *prefix = '\0';
    ssystem("route delete -inet6 %s", itfaddr);
    free(itfaddr);
  }
#endif
}

void sigcleanup(int signo) {
  dprintf(STDERR_FILENO, "signal %d\n", signo);
  exit(0); /* exit(0) will call cleanup() */
}

void ifconf() {
#ifdef linux
  {
    ssystem("ifconfig %s inet `hostname` up", interface_name);
    ssystem("ifconfig %s add %s", interface_name, ipaddr);

    /* Generate a link local address a la sixxs/aiccu */
    /* First a full parse, stripping off the prefix length */
    char lladdr[40];
    char c, *ptr = (char *)ipaddr;
    uint16_t digit, ai, a[8], cc, scc, i;
    for (ai = 0; ai < 8; ai++) {
      a[ai] = 0;
    }
    ai = 0;
    cc = scc = 0;
    while (c = *ptr++) {
      if (c == '/')
        break;
      if (c == ':') {
        if (cc)
          scc = ai;
        cc = 1;
        if (++ai > 7)
          break;
      } else {
        cc = 0;
        digit = c - '0';
        if (digit > 9)
          digit = 10 + (c & 0xdf) - 'A';
        a[ai] = (a[ai] << 4) + digit;
      }
    }
    /* Get # elided and shift what's after to the end */
    cc = 8 - ai;
    for (i = 0; i < cc; i++) {
      if ((8 - i - cc) <= scc) {
        a[7 - i] = 0;
      } else {
        a[7 - i] = a[8 - i - cc];
        a[8 - i - cc] = 0;
      }
    }
    sprintf(lladdr, "fe80::%x:%x:%x:%x", a[1] & 0xfefd, a[2], a[3], a[7]);

    ssystem("ifconfig %s add %s/64", interface_name, lladdr);
  }
#elif defined(__APPLE__)
  {
    char *itfaddr = strdup(ipaddr);
    char *prefix = index(itfaddr, '/');
    if (prefix != NULL) {
      *prefix = '\0';
      prefix++;
    } else {
      prefix = "64";
    }
    ssystem("ifconfig %s inet6 up", interface_name);
    ssystem("ifconfig %s inet6 %s add", interface_name, ipaddr);
    ssystem("sysctl -w net.inet6.ip6.forwarding=1");
    free(itfaddr);
  }
#else
  ssystem("ifconfig %s inet `hostname` %s up", interface_name, ipaddr);
  ssystem("sysctl -w net.inet.ip.forwarding=1");
#endif /* Not Linux or macOS */

  ssystem("ifconfig %s\n", interface_name);
}

int main(int argc, char **argv) {
  const unsigned int buf_size = 2000;
  int interface_fd;
  int status;
  int ret;
  int tun = 0;
  int n;
  char buf[buf_size];
  fd_set rset;
  FILE *inslip;
  struct process child;

  // Fill interface_name with the string "tun0"
  memset(interface_name, 0, sizeof(*interface_name) * sizeof(interface_name));
  strcpy(interface_name, "tun0");

  // Check arguments
  if (argc < 3) {
    dprintf(STDERR_FILENO, "Usage: %s ipaddress comms_program args for it\n", argv[0]);
    return EXIT_FAILURE;
  }
  ipaddr = argv[1];

  // Create a the child comms process
  child = drop_privs_and_exec_comms(&argv[2]);

  // Bring up the TUN interface
  interface_fd = open_tun(interface_name);
  if (interface_fd == -1) {
    perror("Failed to create TUN interface");
    goto error;
  }
  dprintf(STDERR_FILENO, "Opened \'/dev/%s\'\n", interface_name);

  // Register a cleanup function to do teardown of the interface
  atexit(cleanup);
  signal(SIGFPE,    sigcleanup);
  signal(SIGILL,    sigcleanup);
  signal(SIGSEGV,   sigcleanup);
  signal(SIGHUP,    sigcleanup);
  signal(SIGTERM,   sigcleanup);
  signal(SIGINT,    sigcleanup);

  // Configure the interface
  ifconf();

  // Send data from the child to the interface and vi sa versa
  while (1) {
    FD_ZERO(&rset);

    FD_SET(interface_fd, &rset);
    FD_SET(child.stdout, &rset);

    ret = select(interface_fd + 1, &rset, NULL, NULL, NULL);
    if (ret == -1 && errno != EINTR) {
      perror("Error selecting from TUN and child.stdout");
      goto error;
    } else if (ret > 0) {
      // TUN to Child
      if (FD_ISSET(interface_fd, &rset)) {
        if ((n = read(interface_fd, buf, buf_size)) != -1) {
          printf("TUN -> child\n");
          hexdump(debugfd, buf, n); // XXX
          if (write(child.stdin, buf, n) != n) {
            perror("Error writing from TUN to child");
            goto error;
          }
        } else {
          perror("Error reading from TUN");
          goto error;
        }
      }

      // Child to TUN
      if (FD_ISSET(child.stdout, &rset)) {
        if ((n = read(child.stdout, buf, buf_size)) != -1) {
          printf("child -> TUN\n");
          hexdump(debugfd, buf, n); // XXX
          if (write(interface_fd, buf, n) != n) {
            perror("Error writing from child to TUN");
            goto error;
          }
        } else {
          perror("Error reading from child");
          goto error;
        }
      }
    }
  }
  ret = EXIT_SUCCESS;

error:
  ret = EXIT_FAILURE;

stop_child:
  if (waitpid(child.pid, &status, WNOHANG) == -1) {
    perror("Error waiting on child");
    return ret;
  }
  if (!WIFEXITED(status)) {
    if (kill(child.pid, SIGTERM) == -1) {
      perror("Error sending SIGTERM to child");
      return ret;
    }
    if (waitpid(child.pid, &status, 0) == -1) {
      perror("Error waiting on child forever");
      return ret;
    }
  }
  return WEXITSTATUS(status);
}
