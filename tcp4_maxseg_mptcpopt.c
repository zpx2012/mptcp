/*  Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Send an IPv4 TCP packet via raw socket at the link layer (ethernet frame).
// Need to have destination MAC address.
// Values set for SYN packet with two TCP options: set maximum
// segment size, and provide TCP timestamp.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_TCP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#define __FAVOR_BSD           // Use BSD format of tcp header
#include <netinet/tcp.h>      // struct tcphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

//××××××××××××××
//Variables need to be setted
#define interface "eth0" 
#define src_ip "169.235.31.179"
#define dst_ip "130.104.230.45"
#define src_port 60
#define dst_port 80
#define DEST_MAC0 0x00 
#define DEST_MAC1 0x00
#define DEST_MAC2 0x5e
#define DEST_MAC3 0x00
#define DEST_MAC4 0x01
#define DEST_MAC5 0x01



// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define TCP_HDRLEN 20  // TCP header length, excludes options data
#define KEY_LEN 8
// Function prototypes
uint16_t checksum (uint16_t *, int);
uint16_t tcp4_checksum (struct ip, struct tcphdr, uint8_t *, int);
char *allocate_strmem (int);
char **allocate_strmemp (int);
uint8_t *allocate_ustrmem (int);
uint8_t **allocate_ustrmemp (int);
int *allocate_intmem (int);
struct ip *get_iphdr(uint8_t*);
struct tcphdr *get_tcphdr(uint8_t*);


int send_mpcap_syn_ether_frame(uint8_t *ether_frame,int *frame_length,struct sockaddr_ll* device);
int send_ether_frame(uint8_t* ether_frame,int frame_length,struct sockaddr_ll* device);
int recv_mpcap_synack_ether_frame(uint8_t *recv_ether_frame);
int send_mpcap_ack_ether_frame(uint8_t* mpcap_syn_ether_frame,int mpcap_syn_frame_length,uint8_t* mpcap_synack_ether_frame,struct sockaddr_ll* device);


int
main (int argc, char **argv)
{
  int mpcap_syn_frame_length;
  struct sockaddr_ll device;
  uint8_t *mpcap_syn_ether_frame,*mpcap_synack_ether_frame;

  mpcap_syn_ether_frame = allocate_ustrmem (IP_MAXPACKET);
  mpcap_synack_ether_frame = allocate_ustrmem (IP_MAXPACKET);

  //first handshake
  send_mpcap_syn_ether_frame(mpcap_syn_ether_frame,&mpcap_syn_frame_length,&device);
  
  //second handshake
  recv_mpcap_synack_ether_frame(mpcap_synack_ether_frame);

  //third handshake
  send_mpcap_ack_ether_frame(mpcap_syn_ether_frame,mpcap_syn_frame_length,mpcap_synack_ether_frame,&device);


  free(mpcap_syn_ether_frame);
  free(mpcap_synack_ether_frame);

  return (EXIT_SUCCESS);
}

int send_mpcap_ack_ether_frame(uint8_t* mpcap_syn_ether_frame,int mpcap_syn_frame_length,uint8_t* mpcap_synack_ether_frame,struct sockaddr_ll* device)
{
	uint8_t* server_key,*opt_buffer_ack;
	struct ip *syn_iphdr;
	struct tcphdr *syn_tcphdr,*synack_tcphdr;
	int *tcp_flags;
	int i,opt_len_syn = 16;

	tcp_flags = allocate_intmem (8);
	opt_buffer_ack = allocate_ustrmem (opt_len_syn + KEY_LEN);
	
	syn_iphdr = get_iphdr(mpcap_syn_ether_frame);
	syn_tcphdr = get_tcphdr(mpcap_syn_ether_frame);
	synack_tcphdr = get_tcphdr(mpcap_synack_ether_frame);

	// Cast server_key
	server_key = (uint8_t*)(mpcap_synack_ether_frame + mpcap_syn_frame_length - KEY_LEN);

	//Modify syn frame to ack frame

	//IP level
	//Total length of IP datagram (16 bits)
	syn_iphdr->ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + opt_len_syn + KEY_LEN);
	syn_iphdr->ip_sum = checksum ((uint16_t *) &syn_iphdr, IP4_HDRLEN);

	//TCP level
	// Data offset (4 bits): size of TCP header + length of options, in 32-bit words
	syn_tcphdr->th_off = (TCP_HDRLEN  + opt_len_syn + KEY_LEN) / 4;
	printf("synack_tcphdr->th_seq:%x\nntohl(synack_tcphdr->th_seq):%x\nntohl(synack_tcphdr->th_seq)+1:%x\nhtonl(ntohl(synack_tcphdr->th_seq)+1):%x\n", \
		    synack_tcphdr->th_seq,    ntohl(synack_tcphdr->th_seq),    ntohl(synack_tcphdr->th_seq)+1,    htonl(ntohl(synack_tcphdr->th_seq)+1));
	syn_tcphdr->th_ack = htonl(ntohl(synack_tcphdr->th_seq) + 1);
	// Flags (8 bits)	
	// FIN flag (1 bit)
	tcp_flags[0] = 0;
	
	// SYN flag (1 bit): set to 1
	tcp_flags[1] = 0;
	
	// RST flag (1 bit)
	tcp_flags[2] = 0;
	
	// PSH flag (1 bit)
	tcp_flags[3] = 0;
	
	// ACK flag (1 bit)
	tcp_flags[4] = 1;
	
	// URG flag (1 bit)
	tcp_flags[5] = 0;
	
	// ECE flag (1 bit)
	tcp_flags[6] = 0;
	
	// CWR flag (1 bit)
	tcp_flags[7] = 0;
	
	syn_tcphdr->th_flags = 0;
	for (i=0; i<8; i++) {
	  syn_tcphdr->th_flags += (tcp_flags[i] << i);
	}

	memcpy(opt_buffer_ack,mpcap_syn_ether_frame + ETH_HDRLEN + IP4_HDRLEN + TCP_HDRLEN, opt_len_syn * sizeof(uint8_t));
	memcpy(opt_buffer_ack + opt_len_syn, server_key, KEY_LEN * sizeof(uint8_t));
	printf("opt_buffer_ack:%x\n&opt_buffer_ack[5]:%x\nopt_buffer_ack[5]:%x\nopt_buffer_ack + opt_len_syn:%x\n", opt_buffer_ack,&opt_buffer_ack[5],opt_buffer_ack[5],opt_buffer_ack+opt_len_syn);
	opt_buffer_ack[5] = 20u;
	for(i=0;i<opt_len_syn+KEY_LEN;i++){
		printf("%x:%d ", opt_buffer_ack[i],i);
	}
	syn_tcphdr->th_sum = tcp4_checksum (*syn_iphdr, *syn_tcphdr, opt_buffer_ack, opt_len_syn + KEY_LEN);

	// Patch Server key
	memcpy (mpcap_syn_ether_frame + ETH_HDRLEN + IP4_HDRLEN + TCP_HDRLEN, opt_buffer_ack, (opt_len_syn + KEY_LEN) * sizeof (uint8_t));
	
	send_ether_frame(mpcap_syn_ether_frame,mpcap_syn_frame_length + KEY_LEN, device);

	return 1;
}


int recv_mpcap_synack_ether_frame(uint8_t *recv_ether_frame)
{
	int recvsd,bytes,status;
	struct ip *recv_iphdr;
	struct tcphdr* recv_tcphdr;

	// Submit request for a raw socket descriptor to receive packets.
	if ((recvsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
	  perror ("socket() failed ");
	  exit (EXIT_FAILURE);
	}


	// Cast recv_iphdr as pointer to ip header within received ethernet frame.
	recv_iphdr = (struct ip *) (recv_ether_frame + ETH_HDRLEN);

	// Cast recv_tcphdr as pointer to tcp header within received ethernet frame.
	recv_tcphdr = (struct tcphdr *) (recv_ether_frame + ETH_HDRLEN + IP4_HDRLEN);

	// RECEIVE LOOP
    for (;;) {

      memset (recv_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
      if ((bytes = recv(recvsd, recv_ether_frame, IP_MAXPACKET, 0)) < 0) {

        status = errno;

        // Deal with error conditions first.
        if (status == EAGAIN) {  // EAGAIN = 11
          perror ("recvfrom() failed ");
          exit (EXIT_FAILURE);
        //  break;  // Break out of Receive loop.
        } else if (status == EINTR) {  // EINTR = 4
          continue;  // Something weird happened, but let's keep listening.
        } else {
          perror ("recvfrom() failed ");
          exit (EXIT_FAILURE);
        }
      }  // End of error handling conditionals.

      printf("ip_src.s_addr:%x\ndst_ip:%x\n", recv_iphdr->ip_src.s_addr,inet_addr(dst_ip));

      // Check for an IP ethernet frame. If not, ignore and keep listening.
      if ((recv_iphdr->ip_p == IPPROTO_TCP) && (inet_addr(dst_ip) == recv_iphdr->ip_src.s_addr) && 
      	  (htons(dst_port) == recv_tcphdr->th_sport) && (htons(src_port) == recv_tcphdr->th_dport)){
      		printf("th_ack:%x\n", recv_tcphdr->th_ack);
      		break;
      } 
    }  // End of Receive loop.
    return 1;
}


int send_ether_frame(uint8_t* ether_frame,int frame_length,struct sockaddr_ll* device)
{
  int sd,bytes;

 // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

  // Send ethernet frame to socket.
  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) device, sizeof (*device))) <= 0) {
    perror ("sendto() failed");
    exit (EXIT_FAILURE);
  }

  // Close socket descriptor.
  close (sd);

  return 1;

}


int send_mpcap_syn_ether_frame(uint8_t *ether_frame,int *frame_length,struct sockaddr_ll* device)
{
	int i, c, status, sd, bytes, *ip_flags, *tcp_flags, nopt, *opt_len, buf_len;
//	char *dst_ip;
	struct ip iphdr;
	struct tcphdr tcphdr;
	uint8_t *src_mac, *dst_mac;
	uint8_t **options, *opt_buffer;
	struct addrinfo hints, *res;
	struct sockaddr_in *ipv4;
	struct ifreq ifr;
	void *tmp;

	// Allocate memory for various arrays.
	src_mac = allocate_ustrmem (6);
	dst_mac = allocate_ustrmem (6);
	ip_flags = allocate_intmem (4);
	tcp_flags = allocate_intmem (8);
	opt_len = allocate_intmem (10);
	options = allocate_ustrmemp (10);
	for (i=0; i<10; i++) {
	  options[i] = allocate_ustrmem (40);
	}
	opt_buffer = allocate_ustrmem (40);
	
	// Submit request for a socket descriptor to look up interface.
	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
	  perror ("socket() failed to get socket descriptor for using ioctl() ");
	  exit (EXIT_FAILURE);
	}
	
	// Use ioctl() to look up interface name and get its MAC address.
	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
	if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
	  perror ("ioctl() failed to get source MAC address ");
	  return (EXIT_FAILURE);
	}
	close (sd);
	
	// Copy source MAC address.
	memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
	
	// Report source MAC address to stdout.
	printf ("MAC address for interface %s is ", interface);
	for (i=0; i<5; i++) {
	  printf ("%02x:", src_mac[i]);
	}
	printf ("%02x\n", src_mac[5]);
	
	// Find interface index from interface name and store index in
	// struct sockaddr_ll device, which will be used as an argument of sendto().
	memset (device, 0, sizeof (*device));
	if ((device->sll_ifindex = if_nametoindex (interface)) == 0) {
	  perror ("if_nametoindex() failed to obtain interface index ");
	  exit (EXIT_FAILURE);
	}
	printf ("Index for interface %s is %i\n", interface, device->sll_ifindex);
	
	// Set destination MAC address: you need to fill these out
	dst_mac[0] = DEST_MAC0;
	dst_mac[1] = DEST_MAC1;
	dst_mac[2] = DEST_MAC2;
	dst_mac[3] = DEST_MAC3;
	dst_mac[4] = DEST_MAC4;
	dst_mac[5] = DEST_MAC5;
	
	// Fill out hints for getaddrinfo().
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;
	
	// Fill out sockaddr_ll.
	device->sll_family = AF_PACKET;
	memcpy (device->sll_addr, src_mac, 6 * sizeof (uint8_t));
	device->sll_halen = 6;
	
	//×××××××××××××××××××××××
	// Number of TCP options
	nopt = 2;
	
	// First TCP option - Maximum segment size
	opt_len[0] = 0;
	options[0][0] = 2u; opt_len[0]++;  // Option kind 2 = maximum segment size
	options[0][1] = 4u; opt_len[0]++;  // This option kind is 4 bytes long
	options[0][2] = 0x05u; opt_len[0]++;  // Set maximum segment size to 0x100 = 256
	options[0][3] = 0xb4u; opt_len[0]++;
	
	// Second TCP option - Multipath Capable
	opt_len[1] = 0;
	options[1][0] = 30u; opt_len[1]++;	// Option kind 30 = MPTCP
	options[1][1] = 12u; opt_len[1]++;	// This option is 12 bytes long
	options[1][2] = 0; opt_len[1]++;	// Set subtype: MPCAP(0) Version(0)
	options[1][3] = 0x81u; opt_len[1]++;// Flags:10000001
	options[1][4] = 0x53u; opt_len[1]++;// Set Sender's Key
	options[1][5] = 0xddu; opt_len[1]++;
	options[1][6] = 0x5au; opt_len[1]++;  
	options[1][7] = 0x9fu; opt_len[1]++;
	options[1][8] = 0x95u; opt_len[1]++;
	options[1][9] = 0x31u; opt_len[1]++;
	options[1][10] = 0x82u; opt_len[1]++;
	options[1][11] = 0xc9u; opt_len[1]++;
	
	
	// Copy all options into single options buffer.
	buf_len = 0;
	c = 0;	// index to opt_buffer
	for (i=0; i<nopt; i++) {
	  memcpy (opt_buffer + c, options[i], opt_len[i] * sizeof (uint8_t));
	  c += opt_len[i];
	  buf_len += opt_len[i];
	}
	
	// Pad to the next 4-byte boundary.
	while ((buf_len%4) != 0) {
	  opt_buffer[buf_len] = 0;
	  buf_len++;
	}
	
	// IPv4 header
	
	// IPv4 header length (4 bits): Number of 32-bit words in header = 5
	iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);
	
	// Internet Protocol version (4 bits): IPv4
	iphdr.ip_v = 4;
	
	// Type of service (8 bits)
	iphdr.ip_tos = 0;
	
	// Total length of datagram (16 bits): IP header + TCP header + TCP options
	iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + buf_len);
	
	// ID sequence number (16 bits): unused, since single datagram
	iphdr.ip_id = htons (0);
	
	// Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
	
	// Zero (1 bit)
	ip_flags[0] = 0;
	
	// Do not fragment flag (1 bit)
	ip_flags[1] = 0;
	
	// More fragments following flag (1 bit)
	ip_flags[2] = 0;
	
	// Fragmentation offset (13 bits)
	ip_flags[3] = 0;
	
	iphdr.ip_off = htons ((ip_flags[0] << 15)
						+ (ip_flags[1] << 14)
						+ (ip_flags[2] << 13)
						+  ip_flags[3]);
	
	// Time-to-Live (8 bits): default to maximum value
	iphdr.ip_ttl = 255;
	
	// Transport layer protocol (8 bits): 6 for TCP
	iphdr.ip_p = IPPROTO_TCP;
	
	// Source IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
	  fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
	  exit (EXIT_FAILURE);
	}

	// Destination IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
	  fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
	  exit (EXIT_FAILURE);
	}
	
	// IPv4 header checksum (16 bits): set to 0 when calculating checksum
	iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);
	
	
	//××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××
	// TCP header
	
	// Source port number (16 bits)
	tcphdr.th_sport = htons (src_port);
	
	// Destination port number (16 bits)
	tcphdr.th_dport = htons (dst_port);
	
	// Sequence number (32 bits)
	tcphdr.th_seq = htonl (random() % 65535);
	printf("th_seq:%d\n", tcphdr.th_seq);
	
	// Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
	tcphdr.th_ack = htonl (0);
	
	// Reserved (4 bits): should be 0
	tcphdr.th_x2 = 0;
	
	// Data offset (4 bits): size of TCP header + length of options, in 32-bit words
	tcphdr.th_off = (TCP_HDRLEN  + buf_len) / 4;
	
	// Flags (8 bits)	
	// FIN flag (1 bit)
	tcp_flags[0] = 0;
	
	// SYN flag (1 bit): set to 1
	tcp_flags[1] = 1;
	
	// RST flag (1 bit)
	tcp_flags[2] = 0;
	
	// PSH flag (1 bit)
	tcp_flags[3] = 0;
	
	// ACK flag (1 bit)
	tcp_flags[4] = 0;
	
	// URG flag (1 bit)
	tcp_flags[5] = 0;
	
	// ECE flag (1 bit)
	tcp_flags[6] = 0;
	
	// CWR flag (1 bit)
	tcp_flags[7] = 0;
	
	tcphdr.th_flags = 0;
	for (i=0; i<8; i++) {
	  tcphdr.th_flags += (tcp_flags[i] << i);
	}
	
	// Window size (16 bits)
	tcphdr.th_win = htons (65535);
	
	// Urgent pointer (16 bits): 0 (only valid if URG flag is set)
	tcphdr.th_urp = htons (0);
	
	// TCP checksum (16 bits)
	tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, opt_buffer, buf_len);
	
	// Fill out ethernet frame header.
	
	// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header + TCP options)
	*frame_length = 6 + 6 + 2 + IP4_HDRLEN + TCP_HDRLEN + buf_len;
	
	// Destination and Source MAC addresses
	memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
	memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));
	
	// Next is ethernet type code (ETH_P_IP for IPv4).
	// http://www.iana.org/assignments/ethernet-numbers
	ether_frame[12] = ETH_P_IP / 256;
	ether_frame[13] = ETH_P_IP % 256;
	
	// Next is ethernet frame data (IPv4 header + TCP header).
	
	// IPv4 header
	memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof (uint8_t));
	
	// TCP header
	memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
	
	// TCP Options
	memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN + TCP_HDRLEN, opt_buffer, buf_len * sizeof (uint8_t));
	
    send_ether_frame(ether_frame,*frame_length,device);

	// Free allocated memory.
	free (src_mac);
	free (dst_mac);
///	free (dst_ip);
	free (ip_flags);
	free (tcp_flags);
	free (opt_len);
	for (i=0; i<10; i++) {
	  free (options[i]);
	}
	free (options);
	free (opt_buffer);

	return 1;
}


// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t
tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr, uint8_t *options, int opt_len)
{
  uint16_t svalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy TCP length to buf (16 bits)
  svalue = htons (sizeof (tcphdr) + opt_len);
  memcpy (ptr, &svalue, sizeof (svalue));
  ptr += sizeof (svalue);
  chksumlen += sizeof (svalue);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  // Copy TCP options to buf (variable length, but in 32-bit chunks)
  memcpy (ptr, options, opt_len);
  ptr += opt_len;
  chksumlen += opt_len;

  return checksum ((uint16_t *) buf, chksumlen);
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of pointers to arrays of unsigned chars.
uint8_t **
allocate_ustrmemp (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmemp().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t **) malloc (len * sizeof (uint8_t *));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t *));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmemp().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int *
allocate_intmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}

struct tcphdr *
get_tcphdr(uint8_t* ether_frame)
{
	return (struct tcphdr *) (ether_frame + ETH_HDRLEN + IP4_HDRLEN);
}

struct  ip *
get_iphdr(uint8_t* ether_frame)
{
	return (struct ip *) (ether_frame + ETH_HDRLEN);
}