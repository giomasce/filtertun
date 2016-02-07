
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

#define MAC_LENGTH 6
#define PACKET_LENGTH 1600
#define QUEUE_LENGTH 256

char eth_queue[QUEUE_LENGTH][PACKET_LENGTH];
char tun_queue[QUEUE_LENGTH][PACKET_LENGTH];
int eth_queue_len[QUEUE_LENGTH];
int tun_queue_len[QUEUE_LENGTH];
int eth_queue_front = 0;
int eth_queue_back = 0;
int tun_queue_front = 0;
int tun_queue_back = 0;

volatile bool running = true;

void interrupt_handler(int signal) {

  running = false;

}

static void check_ret(bool cond, char *perror_msg) {

  if (cond) {
    perror(perror_msg);
    exit(-1);
  }

}

int create_eth_recv_socket(char *if_name) {

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

int create_eth_send_socket(char *if_name, char mac[MAC_LENGTH]) {

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

  return sock_fd;

}

void recv_eth_packet(int sock_fd) {

  int ret;

  // If the queue is full, we have to discard the packet; FIXME: is
  // this a good way to do it?
  if ((tun_queue_back + 1) % QUEUE_LENGTH == tun_queue_front) {
    ret = recvfrom(sock_fd, NULL, 0, MSG_TRUNC, NULL, NULL);
    check_ret(ret == -1, "recvfrom to discard");
    return;
  }

  // Receive the packet
  ret = recvfrom(sock_fd, tun_queue[tun_queue_back], PACKET_LENGTH, MSG_TRUNC, NULL, NULL);
  check_ret(ret == -1, "recvfrom");

  // Perform checks on the packet
  if (ret > PACKET_LENGTH) {
    fprintf(stderr, "Recevied packet too long (%d bytes)\n", ret);
    tun_queue_len[tun_queue_back] = PACKET_LENGTH;
  } else {
    tun_queue_len[tun_queue_back] = ret;
  }

  // Read Ethernet headers
  struct ether_header *eh = (struct ether_header*) tun_queue[tun_queue_back];
  fprintf(stderr, "Recevied packet from %02x:%02x:%02x:%02x:%02x:%02x to %02x:%02x:%02x:%02x:%02x:%02x (length: %d)\n",
          eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2],
          eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5],
          eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
          eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5],
          ret);

  // Accept the packet in the queue
  tun_queue_back = (tun_queue_back + 1) % QUEUE_LENGTH;

}

int main(int argc, char **argv) {

  char *if_name = "wlan0";
  char outer_mac[MAC_LENGTH];

  int recv_sock_fd = create_eth_recv_socket(if_name);
  int send_sock_fd = create_eth_send_socket(if_name, outer_mac);

  // Set up signal handler for SIGINT
  struct sigaction interrupt_action;
  bzero(&interrupt_action, sizeof(interrupt_action));
  interrupt_action.sa_handler = interrupt_handler;
  sigaction(SIGINT, &interrupt_action, NULL);

  while (running) {
    // Perform select
    fd_set rfds, wfds;
    int nfds = 0;
    FD_ZERO(&rfds);
    FD_SET(recv_sock_fd, &rfds);
    if (recv_sock_fd >= nfds) {
      nfds = recv_sock_fd + 1;
    }
    FD_ZERO(&wfds);
    if (eth_queue_back != eth_queue_front) {
      FD_SET(send_sock_fd, &wfds);
      if (send_sock_fd >= nfds) {
        nfds = send_sock_fd + 1;
      }
    }
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    int ret = select(nfds, &rfds, &wfds, NULL, &timeout);
    check_ret(ret == -1, "select");

    if (FD_ISSET(recv_sock_fd, &rfds)) {
      recv_eth_packet(recv_sock_fd);
    }
  }

  return 0;

}
