#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <net/ethernet.h>

#define DEF_IF "eth0"

#define HARDWARE_ETHERNET_LOCATION_PROTOCOL 0x9001
#define HELP 0x9001

#define MODE_SEND 0x0
#define MODE_REPLY 0x1
#define MODE_BROADSEND 0x2
#define MODE_BROADREPLY 0x3

#define MODE_LEN 1 
#define PKG_ID_LEN 2
#define NETW_ID_LEN 4

/* function prototypes */
void print_mac(const unsigned char *mac_address, FILE *loc);
char char_to_hex(char input);
unsigned char *string_to_mac(const char *string);
unsigned char *create_packet(const char *restrict destination_mac, struct ifreq source_mac, const char *restrict network_id, unsigned char *restrict mode, const char *restrict packet_id, uint_fast16_t *restrict tx_len);
void send_packet(int socket_fd, const unsigned char *packet, const uint_fast16_t *tx_len, const unsigned char *destination_mac, struct ifreq interface_ID);
void *wait_for_packet(void *thread_argument);

/*************************************** Befinning of file ********************************/

void print_mac(const unsigned char *mac_address, FILE *loc) {
  int i;
  for (i = 0; i < 6; i++) {
    fprintf(loc, "%2x", mac_address[i]);
    if (i < 5) {
      putc(':', loc);
    }
  }
}



char char_to_hex(const char input) {
  switch (input) {
    case '0':
      return '\x0';
    case '1':
      return '\x1';
    case '2':
      return '\x2';
    case '3':
      return '\x3';
    case '4':
      return '\x4';
    case '5':
      return '\x5';
    case '6':
      return '\x6';
    case '7':
      return '\x7';
    case '8':
      return '\x8';
    case '9':
      return '\x9';
    case 'a':
    case 'A':
      return '\xA';
    case 'b':
    case 'B':
      return '\xB';
    case 'c':
    case 'C':
      return '\xC';
    case 'd':
    case 'D':
      return '\xD';
    case 'e':
    case 'E':
      return '\xE';
    case 'f':
    case 'F':
      return '\xF';
    default:
      fprintf(stderr, "\t[\033[31mERROR\033[0m] Unknown character in MAC address found: %c\n", input);
      exit(1);
  } 
}



unsigned char *string_to_mac(const char *string) {
  unsigned char *to_return = (unsigned char *) calloc(6, sizeof(*to_return));
  if (NULL == to_return) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize mac address\n", stderr);
    exit(1);
  }
  
  int i, mac_bit = 0;
  for (i = 0; i < 17; i++) {
    if (!(i % 3)) {
      to_return[mac_bit] = char_to_hex(string[i])*16;
    } else if (1 == (i % 3)) {
      to_return[mac_bit++] += char_to_hex(string[i]);
    }
  }
  return to_return;
}



unsigned char *create_packet(const char *restrict destination_mac, struct ifreq source_mac, const char *restrict network_id, unsigned char *restrict mode, const char *restrict packet_id, uint_fast16_t *restrict tx_len) {
  unsigned char *sendbuffer = (unsigned char *) calloc(23, sizeof(*sendbuffer));
  if (NULL == sendbuffer) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize send buffer\n", stderr);
    exit(1);
  }

  struct ether_header *eth = (struct ether_header *) sendbuffer;
  strncpy(eth->ether_shost, (uint8_t *) &source_mac.ifr_hwaddr.sa_data, 6);
  strncpy(eth->ether_dhost, destination_mac, 6);
  eth->ether_type = htons(HARDWARE_ETHERNET_LOCATION_PROTOCOL);
  
  tx_len[0] += sizeof(struct ether_header);
  int i;

  for (i = 0; i < NETW_ID_LEN; i++) {
    sendbuffer[tx_len[0]++] = network_id[i];
  }
  
  if (!strncmp(destination_mac, "\xff\xff\xff\xff\xff\xff", 6)) {
    sendbuffer[tx_len[0]++] = MODE_BROADSEND;
    mode[0] = MODE_BROADREPLY;
  } else {
    sendbuffer[tx_len[0]++] = MODE_SEND;
    mode[0] = MODE_REPLY;
  }

  for (i = 0; i < PKG_ID_LEN; i++) {
    sendbuffer[tx_len[0]++] = packet_id[i];
  }

  return sendbuffer;
}



void send_packet(const int socket_fd, const unsigned char *packet, const uint_fast16_t *tx_len, const unsigned char *destination_mac, struct ifreq interface_ID) {
  struct sockaddr_ll socket_address;
  socket_address.sll_ifindex = interface_ID.ifr_ifindex;
  socket_address.sll_halen = ETH_ALEN;

  strncpy(socket_address.sll_addr, destination_mac, 6);
  if (sendto(socket_fd, packet, tx_len[0], 0, (const struct sockaddr *) &socket_address, sizeof(struct sockaddr_ll)) < 0) {
    puts("\t[\033[31;1mCRITICAL\033[0m] Failed to send packet, please check your network connection");
    exit(1);
  } else {
    puts("\t[\033[32;1mSUCCESS\033[0m] Packet sent successfully, waiting for reply");
  }
}



void *wait_for_packet(void *thread_argument) {
  /* this function waits three seconds, prints out that the host is unavailable and quits the program */
  unsigned char *mac_address = (unsigned char *) calloc(6, sizeof(*mac_address));
  if (NULL == mac_address) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize mac address display buffer\n", stderr);
    exit(1);
  }
  strncpy(mac_address, (char *) thread_argument, 6);
  sleep(1);
  if (strncmp(mac_address, "\xff\xff\xff\xff\xff\xff", 6)) {
    fputs("\t[\033[31mERROR\033[0m] Failed to reach host ", stderr);print_mac(mac_address, stderr);fputs(" (Timeout), please check your ethernet configuration\n", stderr);
  }
  exit(0);
  pthread_exit(0);
}



int main(int argc, char *argv[]) {
  if (argc < 2) {
    puts("Usage: ./ping2 [\033[32;1mMAC_ADDRESS\033[0m] (Optional: [\033[32;1mINTERFACE\033[0m]) ()\n- Default Interface:\t\"eth0\"");
    exit(1);
  }
  int i;

  pthread_t pkt_timeout;
  unsigned char *destination_mac = string_to_mac(argv[1]);

  unsigned char *read_buffer = (unsigned char *) calloc(64, sizeof(*read_buffer));
  if (NULL == read_buffer) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize read buffer\n", stderr);
    exit(1);
  }

  int socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (socket_fd < 0) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize socket object\n", stderr);
    exit(1);
  }
  
  uint_fast16_t *transmission_length = (uint_fast16_t *) calloc(MODE_LEN, sizeof(*transmission_length));
  if (NULL == transmission_length) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize transmission length register\n", stderr);
    exit(1);
  }
  transmission_length[0] = 0;

  char *network_id = (char *) calloc(NETW_ID_LEN, sizeof(*network_id));
  if (NULL == network_id) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize network ID register\n", stderr);
    exit(1);
  }
  /* here, the program would, in the future, read the ID from a config */
 
  unsigned char *mode = (unsigned char *) calloc(1, sizeof(*mode));
  if (NULL == mode) {
    fputs("[\033[31mERROR\033[0m] Failed to initialize mode register\n", stderr);
    exit(1);
  }

  char *packet_id = (char *) calloc(PKG_ID_LEN, sizeof(*packet_id));
  if (NULL == packet_id) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize packet ID register\n", stderr);
    exit(1);
  };

  struct ifreq interface_ID, interface_MAC;

  char interface_name[IFNAMSIZ];
  strncpy(interface_name, DEF_IF, IFNAMSIZ);

  memset(&interface_ID, 0, sizeof(struct ifreq));
  memset(&interface_MAC, 0, sizeof(struct ifreq));

  strncpy(interface_ID.ifr_name, interface_name, IFNAMSIZ-1);
  strncpy(interface_MAC.ifr_name, interface_name, IFNAMSIZ-1);
  if (ioctl(socket_fd, SIOCGIFINDEX, &interface_ID) < 0) {
    fputs("\t[\033[31mERROR\033[0m] Failed to bind network interface to socket\n", stderr);
    exit(1);
  }
  if (ioctl(socket_fd, SIOCGIFHWADDR, &interface_MAC) < 0) {
    fputs("\t[\033[31mERROR\033[0m] Failed to bind network MAC address to socket\n", stderr);
    exit(1);
  }
  
  struct ether_header *rec_eh = (struct ether_header *) read_buffer;
  unsigned char *packet_sender = (unsigned char *) calloc(6, sizeof(*packet_sender));
  if (NULL == packet_sender) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize packet author object\n", stderr);
    exit(1);
  }
 
  unsigned char *transmission_packet = create_packet(destination_mac, interface_MAC, network_id, mode, packet_id, transmission_length);
  send_packet(socket_fd, transmission_packet, transmission_length, destination_mac, interface_ID);
  pthread_create(&pkt_timeout, NULL, wait_for_packet, destination_mac);

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

    if (strncmp(read_buffer, network_id, NETW_ID_LEN)) {
      continue;
    }
    read_buffer += NETW_ID_LEN;

    if (read_buffer[0] != mode[0]) {
      continue;
    }

    read_buffer += MODE_LEN;
    if (!strncmp(read_buffer, packet_id, PKG_ID_LEN)) {
      printf("\t[\033[32;1mSUCCESS\033[0m] Successfully located host ");print_mac(packet_sender, stdout);putchar('\n');
      if (MODE_BROADREPLY != mode[0]) {
        return 0;
      } else {
        read_buffer -= (14 + NETW_ID_LEN + MODE_LEN);
      }
    }
  }
}
