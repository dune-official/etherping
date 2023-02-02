#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <net/ethernet.h>

#define DEF_IF "eth0"

#define HARDWARE_ETHERNET_LOCATION_PROTOCOL 0x9001
#define MODE_SEND 0x0
#define MODE_REPLY 0x1
#define MODE_BROADSEND 0x2
#define MODE_BROADREPLY 0x3

#define MODE_LEN 1
#define PKT_ID_LEN 2
#define NETW_ID_LEN 4

/* function prototypes */
void print_mac(const unsigned char *mac_address);
void send_packet(const int socket_fd, const unsigned char *packet, const uint_fast16_t tx_len, unsigned char *destination_mac, struct ifreq interface_ID);

void print_mac(const unsigned char *mac_address) {
  int i;
  for (i = 0; i < 6; i++) {
    printf("%2x", mac_address[i]);
    if (i < 5) {
      putchar(':');
    }
  }
  putchar('\n');
}



void send_packet(const int socket_fd, const unsigned char *packet, const uint_fast16_t tx_len, unsigned char *destination_mac, struct ifreq interface_ID) {
  struct sockaddr_ll socket_address;
  socket_address.sll_ifindex = interface_ID.ifr_ifindex;
  socket_address.sll_halen = ETH_ALEN;

  strncpy(socket_address.sll_addr, destination_mac, 6);
  if (sendto(socket_fd, packet, tx_len, 0, (const struct sockaddr *) &socket_address, sizeof(struct sockaddr_ll)) < 0) {
    printf("\t[CRITICAL] Failed to answer host ");print_mac(destination_mac);
  }
}



int main(int argc, char *argv[]) {
  int socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (socket_fd < 0) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize socket object\n", stderr);
    exit(1);
  }

  struct ifreq interface_ID, interface_MAC;
  char interface_name[IFNAMSIZ];
  strncpy(interface_name, DEF_IF, IFNAMSIZ);

  memset(&interface_ID, 0, sizeof(struct ifreq));
  memset(&interface_MAC, 0, sizeof(struct ifreq));

  strncpy(interface_ID.ifr_name, interface_name, IFNAMSIZ-1);
  strncpy(interface_MAC.ifr_name, interface_name, IFNAMSIZ-1);

  if (ioctl(socket_fd, SIOCGIFINDEX, &interface_ID) < 0) {
    fputs("\t[\033[31mERROR\033[0m] Failed to bind network interface ID to socket\n", stderr);
    exit(1);
  }

  if (ioctl(socket_fd, SIOCGIFHWADDR, &interface_MAC) < 0) {
    fputs("\t[\033[31mERROR\033[0m] Failed to bind network MAC address to socket\n", stderr);
    exit(1);
  }

  printf("\t[\033[32;1mSUCCESS\033[0m] Listening on ");print_mac((uint8_t *) &interface_MAC.ifr_hwaddr.sa_data);
  puts("\t Status          \tcast type \t          \tmac address");
  puts("\t ------------------------------------------------------------------------");

  unsigned char *packet_sender = (unsigned char *) calloc(6, sizeof(*packet_sender));
  if (NULL == packet_sender) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize packet sender buffer\n", stderr);
    exit(1);
  }

  unsigned char *read_buffer = (unsigned char *) calloc(64, sizeof(*read_buffer));
  if (NULL == read_buffer) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize reading buffer\n", stderr);
    exit(1);
  }
  struct ether_header *rec_eh = (struct ether_header *) read_buffer;
  
  int i;
  while (1) {
    recvfrom(socket_fd, read_buffer, 64, 0, NULL, NULL);
    if (strncmp(rec_eh->ether_dhost, (uint8_t *) &interface_MAC.ifr_hwaddr.sa_data, 6) && strncmp(rec_eh->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6)) {
      continue;
    }
    strncpy(packet_sender, rec_eh->ether_shost, 6);

    if (rec_eh->ether_type != htons(HARDWARE_ETHERNET_LOCATION_PROTOCOL)) {
      continue;
    }
    
    read_buffer += 14;
    
    if (strncmp(read_buffer, "\x00\x00\x00\x00", NETW_ID_LEN)) {
      continue;
    }
  
    read_buffer += NETW_ID_LEN;
    
    if (strncmp(rec_eh->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6) && read_buffer[0] == MODE_SEND) {
      strncpy(rec_eh->ether_dhost, packet_sender, 6);
      strncpy(rec_eh->ether_shost, (uint8_t *) &interface_MAC.ifr_hwaddr.sa_data, 6);

      read_buffer[0] = MODE_REPLY;
      read_buffer -= (14 + NETW_ID_LEN);
      send_packet(socket_fd, read_buffer, 14 + NETW_ID_LEN + MODE_LEN + PKT_ID_LEN, packet_sender, interface_ID);  
      printf("\t[\033[32;1mSUCCESS\033[0m] Received \tunicast \tping from \t");print_mac(packet_sender);
    } else if (!strncmp(rec_eh->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6) && read_buffer[0] == MODE_BROADSEND) {
      strncpy(rec_eh->ether_dhost, packet_sender, 6);
      strncpy(rec_eh->ether_shost, (uint8_t *) &interface_MAC.ifr_hwaddr.sa_data, 6);
      
      read_buffer[0] = MODE_BROADREPLY;
      read_buffer -= (14 + NETW_ID_LEN);
      send_packet(socket_fd, read_buffer, 14 + NETW_ID_LEN + MODE_LEN + PKT_ID_LEN, packet_sender, interface_ID);

      printf("\t[\033[32;1mSUCCESS\033[0m] Received \tbroadcast \tping from \t");print_mac(packet_sender);
    }
  }
}
