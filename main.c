#include <arpa/inet.h>
#include <ctype.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <malloc.h>
#include <netpacket/packet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

typedef struct options {
  bool receive;        // start receiver child
  bool send;           // send frame(s)
  bool verbose;        // print send parameters or received payload 
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

// Prepare a socket for receiving frames on a given interface 
// Returns true if successful
// Prints errors to stderr
bool prepareSocket(int sock, char *name) {
  struct ifreq ifr = {0};
  int s = 1;

  strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

  // Set interface to promiscuous mode.
	// Todo needed?
  if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
    perror("SIOCGIFFLAGS");
    return false;
  }
  ifr.ifr_flags |= IFF_PROMISC;
  if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
    perror("SIOCSIFFLAGS");
    return false;
  }

	// Configure socket for reuse
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &s, sizeof(s)) < 0) {
    perror("SO_REUSEADDR");
    return false;
  }

  // Bind to interface (does this work?)
  if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, name, IFNAMSIZ - 1) < 0) {
    perror("SO_BINDTODEVICE");
    return false;
  }

  return true;
}

// Print ethernet frame source, destination, payload size and payload, if not NULL
void printFrame(uint8_t *src, uint8_t *dst, char *payload, size_t size) {

  printf(MAC_FMT " -> " MAC_FMT " [%lu]",
		src[0], src[1], src[2], src[3], src[4], src[5], 
		dst[0], dst[1], dst[2], dst[3], dst[4], dst[5], size);

  if (payload) {
    printf(": '");
    while (size--) {
      if (isprint(*payload)) {
        putchar(*(payload++));
      } else {
        putchar('.');
        payload++;
      }
    }
    printf("'\n");
  } else {
    putchar('\n');
  }
}

// Listens on ethernet interface name for frames of given type
// If count > 0 stops listening after count frames
// Prints macs and if not quiet (-q) also the payload data
// Returns true if successful
// Prints errors to stderr
bool receiveFrames(char *name, uint16_t type, bool verbose, size_t count) {
  int sock;
  if (!createSocket(type, &sock)) {
    return false;
  }

  int iface;
  uint8_t our_mac[ETH_ALEN];
  if (!getInterface(sock, name, &iface, our_mac)) {
    return false;
  }

	if (!prepareSocket(sock, name)) {
		return false;
	}

	for(;;) {
		static uint8_t frame[ETH_FRAME_LEN];
		static uint8_t bcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

		struct ethhdr *eh = (struct ethhdr *) frame;
    ssize_t received = recvfrom (sock, frame, sizeof(frame), 0, NULL, NULL);
    if (received <= 0) {
      break;
		}

    // Frame not meant for us?
		if (memcmp (eh->h_dest, our_mac, ETH_ALEN) != 0 &&
				memcmp (eh->h_dest, bcast_mac, ETH_ALEN) != 0) {
			continue;
		}

		char *payload = verbose ? (char *)frame + sizeof(*eh) : NULL;
		printFrame(eh->h_source, eh->h_dest, payload, received - sizeof(*eh));

		if (count && !--count) {
			break;
		}
	}

	close(sock);
	return true;
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
  opts->verbose = true;

  unsigned mac[6];
  char *endp;
  int ch;
  while ((ch = getopt(argc, argv, "hvqrc:d:m:i:t:")) != -1) {
    switch (ch) {
    case 'h':
      printf("syntax: %s -h | -v | [-q] [-r] [-c frame_count] [-d payload_data] "
        "[-m remote_mac] [-i interface_name] [-t frame_type]\n", argv[0]);
      exit(0);
    case 'v':
      printf("%s version 1.0 compiled " __DATE__ " " __TIME__ "\n", argv[0]);
      exit(0);
    case 'q':
      opts->verbose = false;
      break;
    case 'r':
      opts->receive = true;
      opts->send = false;
      break;
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
      if (sscanf(optarg, MAC_FMT, 
        &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        fprintf(stderr, "Wrong mac address '%s'.\n", optarg);
        return false;
      }
      for (size_t i=0; i<sizeof(opts->mac); i++) {
        opts->mac[i] = mac[i];
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
  if (opts->verbose) {
		if (opts->send) {
			printf("Send %u frame%s of type 0x%04x from %s to " MAC_FMT " -> '%s'\n",
				opts->count, (opts->count == 1) ? "" : "s", opts->type, opts->name,
				opts->mac[0], opts->mac[1], opts->mac[2], opts->mac[3], opts->mac[4],
				opts->mac[5], opts->data);
		}
		if (opts->receive) {
			char count[20] = "";
			if (opts->count) {
				snprintf(count, sizeof(count), "%u ", opts->count);
			}
			printf("Receive %sframe%s of type 0x%04x on %s from " MAC_FMT "\n",
				count, (opts->count == 1) ? "" : "s", opts->type, opts->name,
				opts->mac[0], opts->mac[1], opts->mac[2], opts->mac[3], opts->mac[4], opts->mac[5]);
		}
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

  if (opts.send) {
    if (!sendData(opts.name, opts.type, opts.mac, opts.data, opts.size, opts.count)) {
      return 2;
    }
  }
	
  if (opts.receive) {
    if (!receiveFrames(opts.name, opts.type, opts.verbose, opts.count)) {
      return 3;
    }
  }

  return 0;
}
