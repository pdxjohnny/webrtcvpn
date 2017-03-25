/*
 * Copyright (c) 2001, Adam Dunkels.
 * Copyright (c) 2009, 2010 Joakim Eriksson, Niclas Finne, Dogan Yazar.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack.
 *
 *
 */

/* Below define allows importing saved output into Wireshark as "Raw IP" packet
 * type */
#define WIRESHARK_IMPORT_FORMAT 1

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

int verbose = 1;
const char *ipaddr;
const char *netmask;
int slipfd = 0;
uint16_t basedelay = 0, delaymsec = 0;
uint32_t startsec, startmsec, delaystartsec, delaystartmsec;
int timestamp = 0, flowcontrol = 0;

int ssystem(const char *fmt, ...) __attribute__((__format__(__printf__, 1, 2)));
void write_to_serial(int outfd, void *inbuf, int len);

void slip_send(int fd, unsigned char c);
void slip_send_char(int fd, unsigned char c);

//#define PROGRESS(s) fprintf(stderr, s)
#define PROGRESS(s)                                                            \
  do {                                                                         \
  } while (0)

char tundev[1024] = {""};

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

#define SLIP_END 0300
#define SLIP_ESC 0333
#define SLIP_ESC_END 0334
#define SLIP_ESC_ESC 0335

/* get sockaddr, IPv4 or IPv6: */
void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in *)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}
void stamptime(void) {
  static long startsecs = 0, startmsecs = 0;
  long secs, msecs;
  struct timeval tv;
  time_t t;
  struct tm *tmp;
  char timec[20];

  gettimeofday(&tv, NULL);
  msecs = tv.tv_usec / 1000;
  secs = tv.tv_sec;
  if (startsecs) {
    secs -= startsecs;
    msecs -= startmsecs;
    if (msecs < 0) {
      secs--;
      msecs += 1000;
    }
    fprintf(stderr, "%04lu.%03lu ", secs, msecs);
  } else {
    startsecs = secs;
    startmsecs = msecs;
    t = time(NULL);
    tmp = localtime(&t);
    strftime(timec, sizeof(timec), "%T", tmp);
    //    fprintf(stderr,"\n%s.%03lu ",timec,msecs);
    fprintf(stderr, "\n%s ", timec);
  }
}

int is_sensible_string(const unsigned char *s, int len) {
  int i;
  for (i = 1; i < len; i++) {
    if (s[i] == 0 || s[i] == '\r' || s[i] == '\n' || s[i] == '\t') {
      continue;
    } else if (s[i] < ' ' || '~' < s[i]) {
      return 0;
    }
  }
  return 1;
}

/*
 * Read from serial, when we have a packet write it to tun. No output
 * buffering, input buffered by stdio.
 */
void serial_to_tun(FILE *inslip, int outfd) {
  static union { unsigned char inbuf[2000]; } uip;
  static int inbufptr = 0;
  int ret, i;
  unsigned char c;

  ret = fread(&c, 1, 1, inslip);
  if (ret == -1 || ret == 0)
    err(1, "serial_to_tun: read");
  goto after_fread;

read_more:
  if (inbufptr >= sizeof(uip.inbuf)) {
    if (timestamp)
      stamptime();
    fprintf(stderr, "*** dropping large %d byte packet\n", inbufptr);
    inbufptr = 0;
  }
  ret = fread(&c, 1, 1, inslip);
after_fread:
  if (ret == -1) {
    err(1, "serial_to_tun: read");
  }
  if (ret == 0) {
    clearerr(inslip);
    return;
  }
  /*  fprintf(stderr, ".");*/
  switch (c) {
  case SLIP_END:
    if (inbufptr > 0) {
      if (uip.inbuf[0] == '!') {
        if (uip.inbuf[1] == 'M') {
          /* Read gateway MAC address and autoconfigure tap0 interface */
          char macs[24];
          int i, pos;
          for (i = 0, pos = 0; i < 16; i++) {
            macs[pos++] = uip.inbuf[2 + i];
            if ((i & 1) == 1 && i < 14) {
              macs[pos++] = ':';
            }
          }
          if (timestamp)
            stamptime();
          macs[pos] = '\0';
          //	  printf("*** Gateway's MAC address: %s\n", macs);
          fprintf(stderr, "*** Gateway's MAC address: %s\n", macs);
          if (timestamp)
            stamptime();
          ssystem("ifconfig %s down", tundev);
          if (timestamp)
            stamptime();
          ssystem("ifconfig %s hw ether %s", tundev, &macs[6]);
          if (timestamp)
            stamptime();
          ssystem("ifconfig %s up", tundev);
        }
      } else if (uip.inbuf[0] == '?') {
        if (uip.inbuf[1] == 'P') {
          /* Prefix info requested */
          struct in6_addr addr;
          int i;
          char *s = strchr(ipaddr, '/');
          if (s != NULL) {
            *s = '\0';
          }
          inet_pton(AF_INET6, ipaddr, &addr);
          if (timestamp)
            stamptime();
          fprintf(stderr,
                  "*** Address:%s => %02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                  //         printf("*** Address:%s =>
                  //         %02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                  ipaddr, addr.s6_addr[0], addr.s6_addr[1], addr.s6_addr[2],
                  addr.s6_addr[3], addr.s6_addr[4], addr.s6_addr[5],
                  addr.s6_addr[6], addr.s6_addr[7]);
          slip_send(slipfd, '!');
          slip_send(slipfd, 'P');
          for (i = 0; i < 8; i++) {
            /* need to call the slip_send_char for stuffing */
            slip_send_char(slipfd, addr.s6_addr[i]);
          }
          slip_send(slipfd, SLIP_END);
        }
#define DEBUG_LINE_MARKER '\r'
      } else if (uip.inbuf[0] == DEBUG_LINE_MARKER) {
        fwrite(uip.inbuf + 1, inbufptr - 1, 1, stdout);
      } else if (is_sensible_string(uip.inbuf, inbufptr)) {
        if (verbose == 1) { /* strings already echoed below for verbose>1 */
          if (timestamp)
            stamptime();
          fwrite(uip.inbuf, inbufptr, 1, stdout);
        }
      } else {
        if (verbose > 2) {
          if (timestamp)
            stamptime();
          printf("Packet from SLIP of length %d - write TUN\n", inbufptr);
          if (verbose > 4) {
#if WIRESHARK_IMPORT_FORMAT
            printf("FEADFACE");
            for (i = 0; i < inbufptr; i++)
              printf(" %02x", uip.inbuf[i]);
#else
            printf("         ");
            for (i = 0; i < inbufptr; i++) {
              printf("%02x", uip.inbuf[i]);
              if ((i & 3) == 3)
                printf(" ");
              if ((i & 15) == 15)
                printf("\n         ");
            }
#endif
            printf("\n");
          }
        }
        if (write(outfd, uip.inbuf, inbufptr) != inbufptr) {
          err(1, "serial_to_tun: write");
        }
      }
      inbufptr = 0;
    }
    break;

  case SLIP_ESC:
    if (fread(&c, 1, 1, inslip) != 1) {
      clearerr(inslip);
      /* Put ESC back and give up! */
      ungetc(SLIP_ESC, inslip);
      return;
    }

    switch (c) {
    case SLIP_ESC_END:
      c = SLIP_END;
      break;
    case SLIP_ESC_ESC:
      c = SLIP_ESC;
      break;
    }
  /* FALLTHROUGH */
  default:
    uip.inbuf[inbufptr++] = c;

    /* Echo lines as they are received for verbose=2,3,5+ */
    /* Echo all printable characters for verbose==4 */
    if ((verbose == 2) || (verbose == 3) || (verbose > 4)) {
      if (c == '\n') {
        if (is_sensible_string(uip.inbuf, inbufptr)) {
          if (timestamp)
            stamptime();
          fwrite(uip.inbuf, inbufptr, 1, stdout);
          inbufptr = 0;
        }
      }
    } else if (verbose == 4) {
      if (c == 0 || c == '\r' || c == '\n' || c == '\t' ||
          (c >= ' ' && c <= '~')) {
        fwrite(&c, 1, 1, stdout);
        if (c == '\n')
          if (timestamp)
            stamptime();
      }
    }

    break;
  }

  goto read_more;
}

unsigned char slip_buf[2000];
int slip_end, slip_begin;

void slip_send_char(int fd, unsigned char c) {
  switch (c) {
  case SLIP_END:
    slip_send(fd, SLIP_ESC);
    slip_send(fd, SLIP_ESC_END);
    break;
  case SLIP_ESC:
    slip_send(fd, SLIP_ESC);
    slip_send(fd, SLIP_ESC_ESC);
    break;
  default:
    slip_send(fd, c);
    break;
  }
}

void slip_send(int fd, unsigned char c) {
  if (slip_end >= sizeof(slip_buf)) {
    err(1, "slip_send overflow");
  }
  slip_buf[slip_end] = c;
  slip_end++;
}

int slip_empty() { return slip_end == 0; }

void slip_flushbuf(int fd) {
  int n;

  if (slip_empty()) {
    return;
  }

  n = write(fd, slip_buf + slip_begin, (slip_end - slip_begin));

  if (n == -1 && errno != EAGAIN) {
    err(1, "slip_flushbuf write failed");
  } else if (n == -1) {
    PROGRESS("Q"); /* Outqueueis full! */
  } else {
    slip_begin += n;
    if (slip_begin == slip_end) {
      slip_begin = slip_end = 0;
    }
  }
}

void write_to_serial(int outfd, void *inbuf, int len) {
  u_int8_t *p = inbuf;
  int i;

  if (verbose > 2) {
    if (timestamp)
      stamptime();
    printf("Packet from TUN of length %d - write SLIP\n", len);
    if (verbose > 4) {
#if WIRESHARK_IMPORT_FORMAT
      printf("FEADFACE");
      for (i = 0; i < len; i++)
        printf(" %02x", p[i]);
#else
      printf("         ");
      for (i = 0; i < len; i++) {
        printf("%02x", p[i]);
        if ((i & 3) == 3)
          printf(" ");
        if ((i & 15) == 15)
          printf("\n         ");
      }
#endif
      printf("\n");
    }
  }

  /* It would be ``nice'' to send a SLIP_END here but it's not
   * really necessary.
   */
  /* slip_send(outfd, SLIP_END); */

  for (i = 0; i < len; i++) {
    switch (p[i]) {
    case SLIP_END:
      slip_send(outfd, SLIP_ESC);
      slip_send(outfd, SLIP_ESC_END);
      break;
    case SLIP_ESC:
      slip_send(outfd, SLIP_ESC);
      slip_send(outfd, SLIP_ESC_ESC);
      break;
    default:
      slip_send(outfd, p[i]);
      break;
    }
  }
  slip_send(outfd, SLIP_END);
  PROGRESS("t");
}

/*
 * Read from tun, write to slip.
 */
int tun_to_serial(int infd, int outfd) {
  struct {
    unsigned char inbuf[2000];
  } uip;
  int size;

  if ((size = read(infd, uip.inbuf, 2000)) == -1)
    err(1, "tun_to_serial: read");

  write_to_serial(outfd, uip.inbuf, size);
  return size;
}

#ifndef BAUDRATE
#define BAUDRATE B115200
#endif
speed_t b_rate = BAUDRATE;

void stty_telos(int fd) {
  struct termios tty;
  speed_t speed = b_rate;
  int i;

  if (tcflush(fd, TCIOFLUSH) == -1)
    err(1, "tcflush");

  if (tcgetattr(fd, &tty) == -1)
    err(1, "tcgetattr");

  cfmakeraw(&tty);

  /* Nonblocking read. */
  tty.c_cc[VTIME] = 0;
  tty.c_cc[VMIN] = 0;
  if (flowcontrol)
    tty.c_cflag |= CRTSCTS;
  else
    tty.c_cflag &= ~CRTSCTS;
  tty.c_cflag &= ~HUPCL;
  tty.c_cflag &= ~CLOCAL;

  cfsetispeed(&tty, speed);
  cfsetospeed(&tty, speed);

  if (tcsetattr(fd, TCSAFLUSH, &tty) == -1)
    err(1, "tcsetattr");

  /* Nonblocking read and write. */
  /* if(fcntl(fd, F_SETFL, O_NONBLOCK) == -1) err(1, "fcntl"); */

  tty.c_cflag |= CLOCAL;
  if (tcsetattr(fd, TCSAFLUSH, &tty) == -1)
    err(1, "tcsetattr");

  i = TIOCM_DTR;

  // if(ioctl(fd, TIOCMBIS, &i) == -1) err(1, "ioctl");

  usleep(10 * 1000); /* Wait for hardware 10ms. */

  /* Flush input and output buffers. */
  if (tcflush(fd, TCIOFLUSH) == -1)
    err(1, "tcflush");
}

int devopen(const char *dev, int flags) {
  if (dev[0] != '/') {
    char t[1024];
    strcpy(t, "/dev/");
    strncat(t, dev, sizeof(t) - 5);
    return open(t, flags);
  } else {
    return open(dev, flags);
  }
}

int tun_alloc(char *dev, int tap) {
  struct ifreq ifr;
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   */
  ifr.ifr_flags = (tap ? IFF_TAP : IFF_TUN) | IFF_NO_PI;
  if (*dev != 0)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    return err;
  }
  strcpy(dev, ifr.ifr_name);
  return fd;
}

void cleanup(void) {
#ifndef __APPLE__
  if (timestamp)
    stamptime();
  ssystem("ifconfig %s down", tundev);
#ifndef linux
  ssystem("sysctl -w net.ipv6.conf.all.forwarding=1");
#endif
  /* ssystem("arp -d %s", ipaddr); */
  if (timestamp)
    stamptime();
  ssystem("netstat -nr"
          " | awk '{ if ($2 == \"%s\") print \"route delete -net \"$1; }'"
          " | sh",
          tundev);
#else
  {
    char *itfaddr = strdup(ipaddr);
    char *prefix = index(itfaddr, '/');
    if (timestamp)
      stamptime();
    ssystem("ifconfig %s inet6 %s remove", tundev, ipaddr);
    if (timestamp)
      stamptime();
    ssystem("ifconfig %s down", tundev);
    if (prefix != NULL)
      *prefix = '\0';
    ssystem("route delete -inet6 %s", itfaddr);
    free(itfaddr);
  }
#endif
}

void sigcleanup(int signo) {
  fprintf(stderr, "signal %d\n", signo);
  exit(0); /* exit(0) will call cleanup() */
}

static int got_sigalarm;

void sigalarm(int signo) {
  got_sigalarm = 1;
  return;
}

void sigalarm_reset() {
#ifdef linux
#define TIMEOUT (997 * 1000)
#else
#define TIMEOUT (2451 * 1000)
#endif
  ualarm(TIMEOUT, TIMEOUT);
  got_sigalarm = 0;
}

void ifconf(const char *tundev, const char *ipaddr, int tap) {
#ifdef linux
  if (timestamp)
    stamptime();
  if (!tap) {
    ssystem("ifconfig %s inet `hostname` up", tundev);
    ssystem("ifconfig %s add %s", tundev, ipaddr);
  } else {
    ssystem("ifconfig %s up", tundev);
    ssystem("ip -6 route add 2001:db8::/64 dev %s", tundev);
    ssystem("ip -6 addr add 2001:db8::2/64 dev %s", tundev);
    ssystem("ip route add 192.0.2.0/24 dev %s", tundev);
    ssystem("ip addr add 192.0.2.2/24 dev %s", tundev);
  }
  if (timestamp)
    stamptime();

/* radvd needs a link local address for routing */
#if 0
/* fe80::1/64 is good enough */
  ssystem("ifconfig %s add fe80::1/64", tundev);
#elif 1
  /* Generate a link local address a la sixxs/aiccu */
  /* First a full parse, stripping off the prefix length */
  if (!tap) {
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
    if (timestamp)
      stamptime();
    ssystem("ifconfig %s add %s/64", tundev, lladdr);
  }
#endif /* link local */
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
    if (timestamp)
      stamptime();
    ssystem("ifconfig %s inet6 up", tundev);
    if (timestamp)
      stamptime();
    ssystem("ifconfig %s inet6 %s add", tundev, ipaddr);
    if (timestamp)
      stamptime();
    ssystem("sysctl -w net.inet6.ip6.forwarding=1");
    free(itfaddr);
  }
#else
  if (timestamp)
    stamptime();
  ssystem("ifconfig %s inet `hostname` %s up", tundev, ipaddr);
  if (timestamp)
    stamptime();
  ssystem("sysctl -w net.inet.ip.forwarding=1");
#endif /* !linux */

  if (timestamp)
    stamptime();
  ssystem("ifconfig %s\n", tundev);
}

int main(int argc, char **argv) {
  int tapfd;
  int ret;
  fd_set rset;
  FILE *inslip;
  int tap = 1;
  slipfd = 0;
  verbose = 5;

  setvbuf(stdout, NULL, _IOLBF, 0); /* Line buffered output. */

  if (argc < 2) {
    err(1, "usage: %s ipaddress [tapname]", argv[0]);
  }
  ipaddr = argv[1];

  if (argc == 3) {
    strcpy(tundev, argv[2]);
  } else {
    strcpy(tundev, "tap0");
  }

  // Begin slipfd setup
  int write_to_child, read_from_child;
  int parent_read_fd[2];
  int parent_write_fd[2];
  pipe(parent_read_fd);
  pipe(parent_write_fd);

  // Create an unprivileged child to do external networking
  if (fork()) {
    /* Close ends of the pipes we will not use */
    close(parent_read_fd[0]);
    close(parent_write_fd[1]);
    dup2(parent_read_fd[1], STDOUT_FILENO);
    dup2(parent_write_fd[0], STDIN_FILENO);

    /* Relinquishing privileges from:
     * https://www.securecoding.cert.org/confluence/display/c/POS36-C.+Observe+correct+revocation+order+while+relinquishing+privileges
     */
    /*  Drop superuser privileges in correct order */
    if (setgid(getgid()) == -1) {
      /* handle error condition */
    }
    if (setuid(getuid()) == -1) {
      /* handle error condition */
    }
    /*
     * Not possible to regain group privileges due to correct relinquishment
     * order
     */

    /* Exec the child process which will deal with the packets */
    char *child_argv[] = {"./test", NULL};
    exit(execvp(child_argv[0], child_argv));
  }

  tapfd = tun_alloc(tundev, tap);
  if (tapfd == -1) {
    err(1, "main: open");
  }
  fprintf(stderr, "opened %s device ``/dev/%s''\n", tap ? "tap" : "tun",
          tundev);

  atexit(cleanup);
  signal(SIGHUP, sigcleanup);
  signal(SIGTERM, sigcleanup);
  signal(SIGINT, sigcleanup);
  signal(SIGALRM, sigalarm);
  ifconf(tundev, ipaddr, tap);

  /* Close ends of the pipes we will not use */
  close(parent_read_fd[1]);
  close(parent_write_fd[0]);
  read_from_child = parent_read_fd[0];
  write_to_child = parent_write_fd[1];

  const int buf_size = 2000;
  char buf[buf_size];
  int n;
  while (1) {
    FD_ZERO(&rset);

    FD_SET(tapfd, &rset);
    FD_SET(read_from_child, &rset);

    ret = select(tapfd + 1, &rset, NULL, NULL, NULL);
    if (ret == -1 && errno != EINTR) {
      err(1, "select");
    } else if (ret > 0) {
      // If there is anything to read from the tap send it to the
      // child
      if (FD_ISSET(tapfd, &rset)) {
        if ((n = read(tapfd, buf, buf_size)) != -1) {
          if (write(write_to_child, buf, n) != n) {
            perror("Error writing from TAP to child");
          }
        } else {
          perror("Error reading from TAP");
        }
        // tun_to_serial(tapfd, write_to_child);
        // slip_flushbuf(write_to_child);
        // sigalarm_reset();
      }

      // If there is anything to read from the child send it to the
      // tap
      if (FD_ISSET(read_from_child, &rset)) {
        if ((n = read(read_from_child, buf, buf_size)) != -1) {
          if (write(tapfd, buf, n) != n) {
            perror("Error writing from child to TAP");
          }
        } else {
          perror("Error reading from child");
        }
        // serial_to_tun(read_from_child, tapfd);
      }
    }
  }
}
