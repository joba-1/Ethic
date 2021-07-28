#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <netpacket/packet.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <malloc.h>
#include <string.h>

typedef struct options {
  bool receive;        // start receiver child
  bool send;           // send frame(s)
  uint32_t count;      // number of frames to send
  char name[IFNAMSIZ]; // sender interface
  uint8_t mac[6];      // receiver mac
  uint16_t type;       // ethernet frame type (default 0x88b5)
  size_t size;         // frame data size
  uint8_t *data;       // pointer to frame data
} options_t;

// Get interface number and mac from the interface name. 
// Return true if successful
// Prints errors to stderr
bool getInterface(int sock, char *name, int *index, uint8_t *mac) {
  struct ifreq ifr = {0};

  strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

  if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    perror("SIOCGIFINDEX");
    return false;
  }
  *index = ifr.ifr_ifindex;

  if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
    perror("SIOCGIFHWADDR");
    return false;
  }
  memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  return true;
}

// Get a raw socket of given type
// Return true if successful
// Prints errors to stderr
bool createSocket(uint16_t type, int *sock) {
  *sock = socket(AF_PACKET, SOCK_RAW, htons(type));
  if (*sock < 0) {
    perror("socket()");
    return false;
  }
  return true;
}

// Creates an ethernet frame of given type with source mac, destination mac and payload data
// Returns allocated buffer if successful, else NULL
// Prints errors to stderr
uint8_t *createFrame(uint16_t type, uint8_t *src_mac, uint8_t *dst_mac, uint8_t *data, size_t size) {
  uint8_t *buffer = malloc(sizeof(struct ethhdr) + size);
  if (buffer) {
    struct ethhdr *eh = (struct ethhdr *)buffer;
    memcpy(eh->h_source, src_mac, ETH_ALEN);
    memcpy(eh->h_dest, dst_mac, ETH_ALEN);
    eh->h_proto = htons(type);
    memcpy(buffer + sizeof(struct ethhdr), data, size);
  }
  else {
    char msg[30];
    snprintf(msg, sizeof(msg), "%s(%lu)", "createFrame", size);
    perror(msg);
  }
  return buffer;
}

// Sends an ethernet frame count times over a raw socket, closes the socket and frees the frame memory
// Return true if successful
// Prints errors to stderr
bool sendFrame(int sock, int iface, uint8_t *frame, size_t size, size_t count) {
  bool status = true;
  struct sockaddr_ll sa;

  sa.sll_ifindex = iface;
  sa.sll_halen = ETH_ALEN;
  memcpy(sa.sll_addr, ((struct ethhdr *)frame)->h_dest, ETH_ALEN);

  size += sizeof(struct ethhdr);

  while (status && count--) {
    if (size != sendto(sock, frame, size, 0, (struct sockaddr *)&sa, sizeof(sa))) {
      perror("sendto()");
      status = false;
    }
  }

  free(frame);
  close(sock);
  return status;
}

// Send data of given size count times over ethernet interface name as raw frames of given type to dst_mac
// Returns true if successful
// Prints errors to stderr
bool sendData(char *name, uint16_t type, uint8_t *dst_mac, uint8_t *data, size_t size, size_t count) {
  int sock;
  if (!createSocket(type, &sock)) {
    return false;
  }
  
  int iface;
  uint8_t src_mac[ETH_ALEN];
  if (!getInterface(sock, name, &iface, src_mac)) {
    return false;
  }

  uint8_t *frame = createFrame(type, src_mac, dst_mac, data, size);
  if (!frame) {
    return false;
  }

  return sendFrame(sock, iface, frame, size, count);
}

// Parse commandline arguments to option_t values
// Returns true if no syntax errors are found
// Prints diagnostics to stderr
bool parseArgs(options_t *opts, int argc, char *argv[]) {
  opts->count = 1;
  opts->data = (uint8_t *)"hi";
  memset(opts->mac, 0xff, sizeof(opts->mac));
  strncpy(opts->name, "eth0", sizeof(opts->name));
  opts->receive = false;
  opts->send = true;
  opts->size = strlen((char *)opts->data);
  opts->type = 0x88b5;

  bool verbose = true;
  unsigned m[6];
  char *endp;
  int ch;
  while ((ch = getopt(argc, argv, "hqc:d:m:i:t:")) != -1) {
    switch (ch) {
    case 'h':
      printf("syntax: %s -h | [-q] [-c frame_count] [-d payload_data] "
        "[-m destination_mac] [-i interface_name] [-t frame_type]\n", argv[0]);
      exit(0);
    case 'c':
      opts->count = strtoul(optarg, &endp, 0);
      if (endp == optarg) {
        fprintf(stderr, "Wrong repeat count '%s'.\n", optarg);
        return false;
      }
      break;
    case 'd':
      opts->data = (uint8_t *)strdup(optarg);
      if (!opts->data) {
        fprintf(stderr, "Copy data '%s' failed.\n", optarg);
        return false;
      }
      opts->size = strlen((char *)opts->data);
      break;
    case 'm':
      if (sscanf(optarg, "%x:%x:%x:%x:%x:%x", 
        &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
        fprintf(stderr, "Wrong mac address '%s'.\n", optarg);
        return false;
      }
      for (size_t i=0; i<sizeof(opts->mac); i++) {
        opts->mac[i] = m[i];
      }
      break;
    case 'i':
      strncpy(opts->name, optarg, sizeof(opts->name));
      break;
    case 't':
      opts->type = strtoul(optarg, &endp, 0);
      if (endp == optarg) {
        fprintf(stderr, "Wrong ethernet frame type '%s'.\n", optarg);
        return false;
      }
      break;
    case '?':
      if (optopt == 'c') {
        fprintf(stderr, "Option -%c requires an argument.\n", optopt);
      }
      else {
        fprintf(stderr, "Unknown option `-%c'.\n", optopt);
      }
      return false;
    default:
      return false;
    }
  }
  if (verbose) {
    printf("Send %u frame%s of type 0x%04x from %s to "
           "%02x:%02x:%02x:%02x:%02x:%02x -> '%s'\n",
           opts->count, (opts->count == 1) ? "" : "s", opts->type, opts->name,
           opts->mac[0], opts->mac[1], opts->mac[2], opts->mac[3], opts->mac[4],
           opts->mac[5], opts->data);
  }
  return true;
}

// Send data as payload of raw ethernet frames of a given type over an interface
// to a destination Options
// --data string: payload (default "hi")
// --count num: repeats (default 1)
// --type num: frame type number (default 0x88b5)
// --iface name: ethernet interface (default eth0)
// Returns 0 if successful, 1 on syntax errors and 2 on send errors
// Prints errors to stderr
int main(int argc, char *argv[]) {
  options_t opts;

  if (!parseArgs(&opts, argc, argv)) {
    return 1;
  }

  if (opts.receive) {
    // todo	startReceiver();
  }

  if (opts.send) {
    if (!sendData(opts.name, opts.type, opts.mac, opts.data, opts.size, opts.count)) {
      return 2;
    }
  }

  return 0;
}
