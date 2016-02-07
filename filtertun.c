
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

#define MAC_LENGTH 6

static void check_ret(bool cond, char *perror_msg) {

  if (cond) {
    perror(perror_msg);
    exit(-1);
  }

}

int create_recv_socket(char *if_name) {

  int ret;

  // Create socket
  int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  check_ret(sock_fd == -1, "socket");

  // Make device promiscuous
  struct ifreq ifopts;
  strncpy(ifopts.ifr_name, if_name, IFNAMSIZ-1);
  ret = ioctl(sock_fd, SIOCGIFFLAGS, &ifopts);
  check_ret(ret, "ioctl(SIOCGIFFLAGS)");
  ifopts.ifr_flags |= IFF_PROMISC;
  ret = ioctl(sock_fd, SIOCSIFFLAGS, &ifopts);
  check_ret(ret, "ioctl(SIOCSIFFLAGS)");

  // Allow the socket to be reused
  int sockopt;
  ret = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt));
  check_ret(ret == -1, "setsockopt(SO_REUSEADDR)");

  // Bind to device
  ret = setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, if_name, IFNAMSIZ-1);
  check_ret(ret == -1, "setsockopt(SO_BINDTODEVICE)");

  return sock_fd;

}

int create_send_socket(char *if_name, char mac[MAC_LENGTH]) {

  int ret;

  // Create socket
  int sock_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
  check_ret(sock_fd == -1, "socket");

  // Retrieve interface index
  struct ifreq ifidx;
  bzero(&ifidx, sizeof(ifidx));
  strncpy(ifidx.ifr_name, if_name, IFNAMSIZ-1);
  ret = ioctl(sock_fd, SIOCGIFINDEX, &ifidx);
  check_ret(ret, "ioctl(SIOCGIFINDEX)");

  // Retrieve MAC address
  struct ifreq ifmac;
  bzero(&ifmac, sizeof(ifmac));
  strncpy(ifmac.ifr_name, if_name, IFNAMSIZ-1);
  ret = ioctl(sock_fd, SIOCGIFHWADDR, &ifmac);
  check_ret(ret, "ioctl(SIOCGIFHWADDR)");

}

int main(int argc, char **argv) {

  char *if_name = "eth0";
  char outer_mac[MAC_LENGTH];

  int recv_sock_fd = create_recv_socket(if_name);
  int send_sock_fd = create_send_socket(if_name, outer_mac);

  return 0;

}
