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
#include <stdarg.h> 
#include "sha1.h"
#include <errno.h>            // errno, perror()
#include "little_endian.h"
#include "my_checksum.h"

// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define TCP_HDRLEN 20  // TCP header length, excludes options data
#define TCP_OPTION_MAX_LEN 40

//TCP Flag
#define FIN 0
#define SYN 1
#define RST 2
#define PSH 3
#define ACK 4
#define URG 5
#define ECE 6
#define CWR 7


//MPTCP
#define SUBFLOW_MASTER 0

#define MPTCP_VERSION_0 0
#define MPTCP_VERSION_1 1

#define MPTCP_SUB_CAPABLE			0
#define MPTCP_SUB_LEN_CAPABLE_SYN		12
#define MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN		12
#define MPTCP_SUB_LEN_CAPABLE_ACK		20
#define MPTCP_SUB_LEN_CAPABLE_ACK_ALIGN		20

#define MPTCP_SUB_JOIN			1
#define MPTCP_SUB_LEN_JOIN_SYN		12
#define MPTCP_SUB_LEN_JOIN_SYN_ALIGN	12
#define MPTCP_SUB_LEN_JOIN_SYNACK	16
#define MPTCP_SUB_LEN_JOIN_SYNACK_ALIGN	16
#define MPTCP_SUB_LEN_JOIN_ACK		24
#define MPTCP_SUB_LEN_JOIN_ACK_ALIGN	24

#define MPTCP_SUB_DSS		2
#define MPTCP_SUB_LEN_DSS	4
#define MPTCP_SUB_LEN_DSS_ALIGN	4

/* Lengths for seq and ack are the ones without the generic MPTCP-option header,
 * as they are part of the DSS-option.
 * To get the total length, just add the different options together.
 */
#define MPTCP_SUB_LEN_SEQ	10
#define MPTCP_SUB_LEN_SEQ_CSUM	12
#define MPTCP_SUB_LEN_SEQ_ALIGN	12

#define MPTCP_SUB_LEN_SEQ_64		14
#define MPTCP_SUB_LEN_SEQ_CSUM_64	16
#define MPTCP_SUB_LEN_SEQ_64_ALIGN	16

#define MPTCP_SUB_LEN_ACK	4
#define MPTCP_SUB_LEN_ACK_ALIGN	4

#define MPTCP_SUB_LEN_ACK_64		8
#define MPTCP_SUB_LEN_ACK_64_ALIGN	8

/* This is the "default" option-length we will send out most often.
 * MPTCP DSS-header
 * 32-bit data sequence number
 * 32-bit data ack
 *
 * It is necessary to calculate the effective MSS we will be using when
 * sending data.
 */
#define MPTCP_SUB_LEN_DSM_ALIGN  (MPTCP_SUB_LEN_DSS_ALIGN +		\
				  MPTCP_SUB_LEN_SEQ_ALIGN +		\
				  MPTCP_SUB_LEN_ACK_ALIGN)

#define MPTCP_SUB_ADD_ADDR		3
#define MPTCP_SUB_LEN_ADD_ADDR4		8
#define MPTCP_SUB_LEN_ADD_ADDR4_VER1	16
#define MPTCP_SUB_LEN_ADD_ADDR6		20
#define MPTCP_SUB_LEN_ADD_ADDR6_VER1	28
#define MPTCP_SUB_LEN_ADD_ADDR4_ALIGN	8
#define MPTCP_SUB_LEN_ADD_ADDR4_ALIGN_VER1	16
#define MPTCP_SUB_LEN_ADD_ADDR6_ALIGN	20
#define MPTCP_SUB_LEN_ADD_ADDR6_ALIGN_VER1	28

#define MPTCP_SUB_REMOVE_ADDR	4
#define MPTCP_SUB_LEN_REMOVE_ADDR	4

#define MPTCP_SUB_PRIO		5
#define MPTCP_SUB_LEN_PRIO	3
#define MPTCP_SUB_LEN_PRIO_ADDR	4
#define MPTCP_SUB_LEN_PRIO_ALIGN	4

#define MPTCP_SUB_FAIL		6
#define MPTCP_SUB_LEN_FAIL	12
#define MPTCP_SUB_LEN_FAIL_ALIGN	12

#define MPTCP_SUB_FCLOSE	7
#define MPTCP_SUB_LEN_FCLOSE	12
#define MPTCP_SUB_LEN_FCLOSE_ALIGN	12


#define OPTION_MPTCP		(1 << 5)


//this is the key for subflows, only 2 subflow
struct mpcb{

	//all subflow shares parts
	uint64_t key_loc_n;//network order
	uint64_t key_rem_n;
	uint64_t idsn_loc_n;
	uint64_t idsn_rem_n;
	uint32_t token_loc_n;
	uint32_t token_rem_n;

	uint32_t data_ack_h;//host order
	uint32_t data_seq_next_h;
};

struct subflow_cb
{
	uint32_t ip_loc_n;
	uint32_t ip_rem_n;
	uint16_t port_loc_h;//host order
	uint16_t port_rem_h;
	uint32_t tcp_ack_h;
	uint32_t tcp_seq_next_h;
	uint32_t sub_seq_next_h;

	uint32_t rand_loc_n;
	uint32_t rand_rem_n;
	uint8_t addr_id_loc;
	uint8_t addr_id_rem;

	uint8_t is_master;// 0 is master
};


// Function prototypes
char *allocate_strmem (int);
char **allocate_strmemp (int);
uint8_t *allocate_ustrmem (int);
uint8_t **allocate_ustrmemp (int);
int *allocate_intmem (int);

uint16_t checksum (uint16_t *, int);
uint16_t tcp4_checksum (struct ip, struct tcphdr, uint8_t *, int, const uint8_t *, int);
void mptcp_key_sha1(uint64_t key, uint32_t *token, uint64_t *idsn);

int init_subflow_cb(
	struct subflow_cb* p_sf_cb, 
	const char* ip_loc_str,
	const char* ip_rem_str, 
	uint16_t port_loc_h,
	uint16_t port_rem_h,
	uint8_t addr_id_loc,
	uint8_t is_master);

uint32_t get_rand() {
	uint32_t nmb;
	nmb = rand();
	nmb += ( (rand()%2) <<31);
	return nmb;
}


//seq = idsn+1
uint32_t get_data_seq_h_32(uint64_t idsn_n){
	uint64_t idsn_h = ntohll(idsn_n);
	uint32_t data_seq_h = (uint32_t)(idsn_h+1);
	return data_seq_h;
}


int create_packet(unsigned char *buf, uint16_t *plen, 
	struct subflow_cb* p_sf_cb, 
	unsigned char FLAG,//network format 
	uint16_t win, //host format
	unsigned char *buf_opt, 
	uint16_t len_opt,
	const unsigned char *buf_payload,
	uint16_t len_payload) {

	int *ip_flags, *tcp_flags;
	struct ip iphdr;
	struct tcphdr tcphdr;

	// Allocate memory for various arrays.
	ip_flags = allocate_intmem (4);
	tcp_flags = allocate_intmem (8);
	
	if((len_payload==0 && buf_payload!=NULL) || (len_payload!=0 && buf_payload==NULL)){
		perror("payload sanity check failed in create_packet.\n");
		return -1;
	}

	// IPv4 header
	// IP frame length = IP header + TCP header + TCP options
	*plen = IP4_HDRLEN + TCP_HDRLEN + len_opt + len_payload;
	
	// IPv4 header length (4 bits): Number of 32-bit words in header = 5
	iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);
	
	// Internet Protocol version (4 bits): IPv4
	iphdr.ip_v = 4;
	
	// Type of service (8 bits)
	iphdr.ip_tos = 0;
	
	// Total length of datagram (16 bits): IP header + TCP header + TCP options
	iphdr.ip_len = htons (*plen);
	
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

	iphdr.ip_src.s_addr = p_sf_cb->ip_loc_n;

	iphdr.ip_dst.s_addr = p_sf_cb->ip_rem_n;
	
	// IPv4 header checksum (16 bits): set to 0 when calculating checksum
	iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);
	
	// TCP header
	
	// Source port number (16 bits)
	tcphdr.th_sport = htons (p_sf_cb->port_loc_h);
	
	// Destination port number (16 bits)
	tcphdr.th_dport = htons (p_sf_cb->port_rem_h);
	
	// Sequence number (32 bits)
	tcphdr.th_seq = htonl (p_sf_cb->tcp_seq_next_h);

	
	// Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
	tcphdr.th_ack = htonl (p_sf_cb->tcp_ack_h);
	
	// Reserved (4 bits): should be 0
	tcphdr.th_x2 = 0;
	
	// Data offset (4 bits): size of TCP header + length of options, in 32-bit words
	tcphdr.th_off = (TCP_HDRLEN  + len_opt) / 4;
	
	// Flags (8 bits)	
	tcp_flags[FLAG] = 1;	
	tcphdr.th_flags = 0;
	for (int i=0; i<8; i++) {
		tcphdr.th_flags += (tcp_flags[i] << i);
	}
	
	// Window size (16 bits)
	tcphdr.th_win = htons (win);
	
	// Urgent pointer (16 bits): 0 (only valid if URG flag is set)
	tcphdr.th_urp = htons (0);
	
	// TCP checksum (16 bits)
	tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, buf_opt, len_opt, buf_payload, len_payload);
		
	// IPv4 header
	memcpy (buf, &iphdr, IP4_HDRLEN * sizeof (uint8_t));
	
	// TCP header
	memcpy (buf + IP4_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
	
	// TCP Options
	memcpy (buf + IP4_HDRLEN + TCP_HDRLEN, buf_opt, len_opt * sizeof (uint8_t));

	//Payload
	if(len_payload == 0){
		//Update Seq num
		if(FLAG != ACK)
			p_sf_cb->tcp_seq_next_h++;
		return 1;
	}

	memcpy (buf + IP4_HDRLEN + TCP_HDRLEN + len_opt, buf_payload, len_payload * sizeof (uint8_t));
	p_sf_cb->tcp_seq_next_h += len_payload;
	return 1;
}

/* one problem: uint64 is only accessable in 64bit machine, that's why they use 2 32bit array to present 64bit key*/
int create_MPcap(unsigned char *top, uint16_t *len, uint64_t key_loc_n, uint64_t key_rem_n) 
{

	unsigned char tpcap_len = (key_rem_n == 0)? MPTCP_SUB_LEN_CAPABLE_SYN:MPTCP_SUB_LEN_CAPABLE_ACK;

	if((*len) + tpcap_len > TCP_OPTION_MAX_LEN) return 0;

	unsigned char *start = top + (*len);


	*(start) = 30;
	*(start+1) = tpcap_len;
	*(start+2) = ( ((unsigned char) MPTCP_SUB_CAPABLE)<<4) & 0xf0;
	*(start+3) = 0x81;//checksum on
	*((uint64_t*) (start+4)) = key_loc_n;
	if(key_rem_n != 0) {
		*((uint64_t*) (start+12)) = key_rem_n;//only used for ACK
	}
	*(len) += tpcap_len;
	return 1;
}




int create_MPadd_addr(unsigned char *top, uint16_t *len, unsigned char addr_id_loc, uint32_t ip_loc_n) {

	uint16_t new_len = MPTCP_SUB_LEN_ADD_ADDR4;
	
	if((*len) + new_len > TCP_OPTION_MAX_LEN) return 0;

	unsigned char *start = top + (*len);
	
	*(start) = 30;
	*(start+1) = new_len;
	*(start+2) = 0x34u;
	*(start+3) = addr_id_loc;
	*((uint32_t*) (start+4)) = ip_loc_n;
	(*len) += new_len;
	return 1;
}

int create_MPjoin_syn(unsigned char *top, uint16_t *len, uint32_t token, unsigned char addr_id) {

	uint16_t new_len = MPTCP_SUB_LEN_JOIN_SYN;

	if((*len) + new_len > TCP_OPTION_MAX_LEN) return 0;

	unsigned char *start = top + (*len);

	*(start) = 30;
	*(start+1) = new_len;
	*(start+2) = 0x10u;
	*(start+3) = addr_id;
	*((uint32_t*) (start+4)) = token;
	*((uint32_t*) (start+8)) = get_rand();
	(*len) += new_len;
	return 1;
}

int create_MPjoin_ack(unsigned char *top, uint16_t *len, uint32_t *mac_n) {

	if((*len) + 24 > 40) return 0;

	unsigned char *start = top + (*len);
	*(start) = 30;
	*(start+1) = 24;
	*(start+2) = ( ((unsigned char) MPTCP_SUB_JOIN)<<4) ;
	*(start+3) = 0;

	memcpy(start+4, (unsigned char*) mac_n, 20);
	(*len) += 24;
	return 1;
}

int create_mpdss_ack(unsigned char *top, uint16_t *len, uint32_t ack_num_h){

	uint16_t new_len = MPTCP_SUB_LEN_DSS + MPTCP_SUB_LEN_ACK;
	
	if((*len) + new_len > TCP_OPTION_MAX_LEN) return 0;

	unsigned char *start = top + (*len);
	
	*(start) = 30;
	*(start+1) = new_len;
	*(start+2) = 0x20u;
	*(start+3) = 0x01;
	*((uint32_t*) (start+4)) = htonl(ack_num_h);
	(*len) += new_len;
	return 1;
}

//consideration: combine mpcap and mpjoin in here? 
int analyze_MPjoin_synack(uint8_t * const start, uint64_t *mac_n, uint32_t *rand_nmb_h, unsigned char *address_id) {

	if(*(start) != 30){
		perror("analyze_MPjoin_synack: wrong mptcp pointer");
		exit(EXIT_FAILURE);
	}

	//get token and find session
	*address_id = *(start+3);
	*mac_n = *( (uint64_t *) (start+4)) ;
	*rand_nmb_h = ntohl(*(uint32_t *) (start+8));

	return 1;
}

uint16_t get_unused_port_number() {

	int sd;
	struct sockaddr_in skaddr;
	int length;
	
	if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("Problem creating socket\n");
		exit(EXIT_FAILURE);
	}
	
	skaddr.sin_family = AF_INET;
	skaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	skaddr.sin_port = htons(0);

	if (bind(sd, (struct sockaddr *) &skaddr, sizeof(skaddr))<0) {
	  perror("Problem binding\n");
	  exit(EXIT_FAILURE);
	}

	length = sizeof(skaddr);
	if (getsockname(sd, (struct sockaddr *) &skaddr, &length)<0) {
	  perror("Error getsockname\n");
	  exit(EXIT_FAILURE);
	}

	close(sd);

	return ntohs(skaddr.sin_port);

}


struct  ip *
get_iphdr_from_ip_frame(uint8_t* ip_frame)
{
	return (struct ip *) (ip_frame);
}

struct tcphdr *
get_tcphdr_from_ip_frame(uint8_t* ip_frame)
{
	return (struct tcphdr *) (ip_frame + IP4_HDRLEN);
}


struct  ip *
get_iphdr_from_ether_frame(uint8_t* ether_frame)
{
	return (struct ip *) (ether_frame + ETH_HDRLEN);
}

struct tcphdr *
get_tcphdr_from_ether_frame(uint8_t* ether_frame)
{
	return (struct tcphdr *) (ether_frame + ETH_HDRLEN + IP4_HDRLEN);
}

void mptcp_key_sha1(uint64_t key, uint32_t *token, uint64_t *idsn)
{
	uint32_t workspace[SHA_WORKSPACE_WORDS];
	uint32_t mptcp_hashed_key[SHA_DIGEST_WORDS];
	uint8_t input[64];
	int i;

	memset(workspace, 0, sizeof(workspace));

	/* Initialize input with appropriate padding */
	memset(&input[9], 0, sizeof(input) - 10); /* -10, because the last byte
						   * is explicitly set too
						   */
	memcpy(input, &key, sizeof(key)); /* Copy key to the msg beginning */
	input[8] = 0x80; /* Padding: First bit after message = 1 */
	input[63] = 0x40; /* Padding: Length of the message = 64 bits */

	sha_init(mptcp_hashed_key);
	sha_transform(mptcp_hashed_key, input, workspace);

	for (i = 0; i < 5; i++)
		mptcp_hashed_key[i] = cpu_to_be32(mptcp_hashed_key[i]);

	if (token)
		*token = mptcp_hashed_key[0];
	if (idsn)
		*idsn = *((uint64_t *)&mptcp_hashed_key[3]);
}

void mptcp_hmac_sha1(uint8_t *key_1, uint8_t *key_2, uint32_t *hash_out, int arg_num, ...)
{
	uint32_t workspace[SHA_WORKSPACE_WORDS];
	uint8_t input[128]; /* 2 512-bit blocks */
	int i;
	int index;
	int length;
	uint8_t *msg;
	va_list list;

	memset(workspace, 0, sizeof(workspace));

	/* Generate key xored with ipad */
	memset(input, 0x36, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	va_start(list, arg_num);
	index = 64;
	for (i = 0; i < arg_num; i++) {
		length = va_arg(list, int);
		msg = va_arg(list, uint8_t *);
		if(index + length > 125); /* Message is too long */
			perror("mptcp_hmac_sha1():Message is too long");
		memcpy(&input[index], msg, length);
		index += length;
	}
	va_end(list);

	input[index] = 0x80; /* Padding: First bit after message = 1 */
	memset(&input[index + 1], 0, (126 - index));

	/* Padding: Length of the message = 512 + message length (bits) */
	input[126] = 0x02;
	input[127] = ((index - 64) * 8); /* Message length (bits) */

	sha_init(hash_out);
	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, &input[64], workspace);
	memset(workspace, 0, sizeof(workspace));

	for (i = 0; i < 5; i++)
		hash_out[i] = cpu_to_be32(hash_out[i]);

	/* Prepare second part of hmac */
	memset(input, 0x5C, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	memcpy(&input[64], hash_out, 20);
	input[84] = 0x80;
	memset(&input[85], 0, 41);

	/* Padding: Length of the message = 512 + 160 bits */
	input[126] = 0x02;
	input[127] = 0xA0;

	sha_init(hash_out);
	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, &input[64], workspace);

	for (i = 0; i < 5; i++)
		hash_out[i] = cpu_to_be32(hash_out[i]);
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
tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr, uint8_t *options, int opt_len,const uint8_t *payload, int payload_len)
{
	uint16_t svalue;
	char buf[IP_MAXPACKET], cvalue;
	char *ptr;
	int chksumlen = 0;

  if (payload == NULL)
    payload_len = 0;

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
  svalue = htons (sizeof (tcphdr) + opt_len + payload_len);
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

  // Copy TCP payload to buf
  if (payload && payload_len) {
    printf("has payload.\n");
    memcpy(ptr, payload, payload_len);
    ptr += payload_len;
    chksumlen += payload_len;
  }

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


