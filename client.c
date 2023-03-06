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

#define HARDWARE_ETHERNET_LOCATION_PROTOCOL 0x9001
#define HELP 0x9001

#define MODE_SEND 0x0
#define MODE_REPLY 0x1
#define MODE_BROADSEND 0x2
#define MODE_BROADREPLY 0x3

#define MODE_LEN 1 
#define PKT_ID_LEN 2
#define NETW_ID_LEN 4

/* function prototypes */
void process_arguments(int argc, char *argv[], char *default_interface, unsigned char *default_dest_mac);
void print_mac(const unsigned char *mac_address, FILE *loc);
char char_to_hex(char input);
void string_to_mac(const char *string, unsigned char *dest_mac);
unsigned char *create_packet(const char *restrict destination_mac, struct ifreq source_mac, const char *restrict network_id, unsigned char *restrict mode, const char *restrict packet_id);
void send_packet(int socket_fd, const unsigned char *packet, const unsigned char *destination_mac, struct ifreq interface_ID);
void *wait_for_packet(void *thread_argument);

/*************************************** Befinning of file ********************************/

typedef struct EtherPing {
  char network_id[NETW_ID_LEN];
  char mode;
  char packet_id[PKT_ID_LEN];
} EtherPing;

void process_arguments(int argc, char *argv[], char *default_interface, unsigned char *default_dest_mac) {

  int i;
  for (i = 1; i < argc; i++) {
    if (!memcmp(argv[i], "-i", 2) || !memcmp(argv[i], "--interface", 11)) {

      if (i+1 == argc) {
        fputs("\t[\033[31mERROR\033[0m] Could not find interface in command line argument\n", stderr);
        exit(1);
      }
      memcpy(default_interface, argv[i+1], IFNAMSIZ);

    } else if (!memcmp(argv[i], "-m", 2) || !memcmp(argv[i], "--mac", 5)) {

      if (i+1 == argc) {
        fputs("\t[\033[31mERROR\033[0m] Could not find hardware address in command line argument\n", stderr);
        exit(1);
      }
      string_to_mac(argv[i+1], default_dest_mac);
    }
  }

  if (0 == default_interface[0]) {
    memcpy(default_interface, "eth0\0\0\0\0\0\0\0\0\0\0\0", IFNAMSIZ);
  }
}

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
      fprintf(stderr, "\t[\033[31mERROR\033[0m] Unknown character in hardware address found: %c\n", input);
      exit(1);
  } 
}



void string_to_mac(const char *string, unsigned char *dest_mac) {
    
  int i, mac_bit = 0;
  for (i = 0; i < 17; i++) {
    if (!(i % 3)) {
      dest_mac[mac_bit] = char_to_hex(string[i])*16;
    } else if (1 == (i % 3)) {
      dest_mac[mac_bit++] += char_to_hex(string[i]);
    }
  }
}



unsigned char *create_packet(const char *restrict destination_mac, struct ifreq source_mac, const char *restrict network_id, unsigned char *restrict mode, const char *restrict packet_id) {
  unsigned char *sendbuffer = (unsigned char *) calloc(23, sizeof(*sendbuffer));
  if (NULL == sendbuffer) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize send buffer\n", stderr);
    exit(1);
  }

  struct ether_header *eth = (struct ether_header *) sendbuffer;
  memcpy(eth->ether_shost, (uint8_t *) &source_mac.ifr_hwaddr.sa_data, 6);
  memcpy(eth->ether_dhost, destination_mac, 6);
  eth->ether_type = htons(HARDWARE_ETHERNET_LOCATION_PROTOCOL);
  
  sendbuffer += 14;
  struct EtherPing *ether_ping = (struct EtherPing *) (sendbuffer);

  memcpy(ether_ping->network_id, network_id, NETW_ID_LEN);
  
  if (!memcmp(destination_mac, "\xff\xff\xff\xff\xff\xff", 6)) {
    ether_ping->mode = MODE_BROADSEND;
    mode[0] = MODE_BROADREPLY;
  } else {
    ether_ping->mode = MODE_SEND;
    mode[0] = MODE_REPLY;
  }

  memcpy(ether_ping->packet_id, packet_id, PKT_ID_LEN);
  
  sendbuffer -= 14;
  return sendbuffer;
}



void send_packet(const int socket_fd, const unsigned char *packet, const unsigned char *destination_mac, struct ifreq interface_ID) {
  struct sockaddr_ll socket_address;
  socket_address.sll_ifindex = interface_ID.ifr_ifindex;
  socket_address.sll_halen = ETH_ALEN;

  memcpy(socket_address.sll_addr, destination_mac, 6);
  if (sendto(socket_fd, packet, 21, 0, (const struct sockaddr *) &socket_address, sizeof(struct sockaddr_ll)) < 0) {
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
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize hardware address display buffer\n", stderr);
    exit(1);
  }
  memcpy(mac_address, (char *) thread_argument, 6);
  sleep(1);
  if (memcmp(mac_address, "\xff\xff\xff\xff\xff\xff", 6)) {
    fputs("\t[\033[31mERROR\033[0m] Failed to reach host ", stderr);print_mac(mac_address, stderr);fputs(" (Timeout), please check your ethernet configuration\n", stderr);
  }
  exit(0);
  pthread_exit(0);
}



int main(int argc, char *argv[]) {
  if (argc < 2) {
    puts("\nRequired:\n-m/--mac\t\t\tHW_ADDRESS\n\nOptionally:\n-i/--interface\t\t\tINTERFACE\n\nDefault configuration:\nINTERFACE=\"eth0\"\nCOUNT=1\n");
    exit(1);
  }
  int i;
  pthread_t pkt_timeout;

  unsigned char *destination_mac = (unsigned char *) calloc(6, sizeof(*destination_mac));
  if (NULL == destination_mac) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize hardware address register\n", stderr);
    exit(1);
  }

  char *interface_name = (char *) calloc(IFNAMSIZ, sizeof(*interface_name));
  if (NULL == interface_name) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize interface name register\n", stderr);
    exit(1);
  }


  unsigned char *read_buffer = (unsigned char *) calloc(64, sizeof(*read_buffer));
  if (NULL == read_buffer) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize receiving register\n", stderr);
    exit(1);
  }

  int socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (socket_fd < 0) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize socket object\n", stderr);
    exit(1);
  }

  char *network_id = (char *) calloc(NETW_ID_LEN, sizeof(*network_id));
  if (NULL == network_id) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize network ID register\n", stderr);
    exit(1);
  }
 
  unsigned char *mode = (unsigned char *) calloc(1, sizeof(*mode));
  if (NULL == mode) {
    fputs("[\033[31mERROR\033[0m] Failed to initialize mode register\n", stderr);
    exit(1);
  }

  char *packet_id = (char *) calloc(PKT_ID_LEN, sizeof(*packet_id));
  if (NULL == packet_id) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize packet ID register\n", stderr);
    exit(1);
  }

  struct ifreq interface_ID, interface_MAC;
  
  process_arguments(argc, argv, interface_name, destination_mac);

  memset(&interface_ID, 0, sizeof(struct ifreq));
  memset(&interface_MAC, 0, sizeof(struct ifreq));

  memcpy(interface_ID.ifr_name, interface_name, IFNAMSIZ-1);
  memcpy(interface_MAC.ifr_name, interface_name, IFNAMSIZ-1);
  if (ioctl(socket_fd, SIOCGIFINDEX, &interface_ID) < 0) {
    fprintf(stderr, "\t[\033[31mERROR\033[0m] Failed to bind network interface \"%s\" to socket\n", interface_name);
    exit(1);
  }
  if (ioctl(socket_fd, SIOCGIFHWADDR, &interface_MAC) < 0) {
    fputs("\t[\033[31mERROR\033[0m] Failed to bind network hardware address to socket\n", stderr);
    exit(1);
  }
  
  struct ether_header *rec_eh = (struct ether_header *) read_buffer;
  unsigned char *packet_sender = (unsigned char *) calloc(6, sizeof(*packet_sender));
  if (NULL == packet_sender) {
    fputs("\t[\033[31mERROR\033[0m] Failed to initialize packet author object\n", stderr);
    exit(1);
  }
 
  unsigned char *transmission_packet = create_packet(destination_mac, interface_MAC, network_id, mode, packet_id);
  send_packet(socket_fd, transmission_packet, destination_mac, interface_ID);
  pthread_create(&pkt_timeout, NULL, wait_for_packet, destination_mac);

  while (1) {
    recvfrom(socket_fd, read_buffer, 64, 0, NULL, NULL);
    if (memcmp(rec_eh->ether_dhost, (uint8_t *) &interface_MAC.ifr_hwaddr.sa_data, 6) && memcmp(rec_eh->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6)) {
      continue;
    }
    memcpy(packet_sender, rec_eh->ether_shost, 6);
     
    if (rec_eh->ether_type != htons(HARDWARE_ETHERNET_LOCATION_PROTOCOL)) {
      continue;
    }

    read_buffer += 14;

    if (memcmp(read_buffer, network_id, NETW_ID_LEN)) {
      continue;
    }
    read_buffer += NETW_ID_LEN;

    if (read_buffer[0] != mode[0]) {
      continue;
    }

    read_buffer += MODE_LEN;
    if (!memcmp(read_buffer, packet_id, PKT_ID_LEN)) {
      printf("\t[\033[32;1mSUCCESS\033[0m] Successfully located host ");print_mac(packet_sender, stdout);putchar('\n');
      if (MODE_BROADREPLY != mode[0]) {
        return 0;
      } else {
        read_buffer -= (14 + NETW_ID_LEN + MODE_LEN);
      }
    }
  }
}
