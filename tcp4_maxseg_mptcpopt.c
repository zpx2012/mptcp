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
#include "sha1.h"
#include <errno.h>            // errno, perror()
#include "little_endian.h"
#include "my_checksum.h"

//××××××××××××××
//Variables need to be setted
#define src_ip "192.168.1.133"
#define dst_ip "130.104.230.45"
#define src_port 30126
#define dst_port 80
#define sender_key_str 0x5f6257d35e39d48a 
#define http_frame_str "474554202f66616c6f6e67676f6e6720485454502f312e310d0a486f73743a206d756c7469706174682d7463702e6f72670d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a557067726164652d496e7365637572652d52657175657374733a20310d0a557365722d4167656e743a204d6f7a696c6c612f352e3020285831313b204c696e7578207838365f363429204170706c655765624b69742f3533372e333620284b48544d4c2c206c696b65204765636b6f29205562756e7475204368726f6d69756d2f36312e302e333136332e313030204368726f6d652f36312e302e333136332e313030205361666172692f3533372e33360d0a4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f776562702c696d6167652f61706e672c2a2f2a3b713d302e380d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a4163636570742d4c616e67756167653a207a682d434e2c7a683b713d302e380d0a0d0a"

#define src_ip2 "10.11.12.13"
#define src_port2 30125
#define ADDR_ID 3


// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define TCP_HDRLEN 20  // TCP header length, excludes options data
#define KEY_LEN 8

#define FIN 0
#define SYN 1
#define RST 2
#define PSH 3
#define ACK 4
#define URG 5
#define ECE 6
#define CWR 7



struct mp_dss {
	__u8	kind;
	__u8	len;
	__u8	sub;
	__u8	flags;
	__u32	data_ack;
	__u32	data_seq;
	__u32	sub_seq;
	__u16	data_len;
	__u16	dss_csum;
};

struct  mp_cap {
	__u8 kind;
	__u8 len;
	__u8 subtype_version;
	__u8 flags;
	uint64_t key;
}__attribute__((__packed__));

struct psu_dss
{
	__u64 data_seq;
	__u32 sub_seq;
	__u16 data_len;
	__u16 dss_csum;
	
};__attribute__((__packed__));


uint64_t key_rem_n=0,key_loc_n=0;//network order
uint64_t idsn_rem_n=0,idsn_loc_n=0;
uint32_t token_rem_n=0,token_loc_n=0;
uint32_t data_seq_h=0,data_ack_h=0;
uint32_t sub_seq_h=1;

// Function prototypes
uint16_t checksum (uint16_t *, int);
uint16_t tcp4_checksum (struct ip, struct tcphdr, uint8_t *, int, uint8_t *, int);
char *allocate_strmem (int);
char **allocate_strmemp (int);
uint8_t *allocate_ustrmem (int);
uint8_t **allocate_ustrmemp (int);
int *allocate_intmem (int);
struct ip *get_iphdr(uint8_t*);
struct tcphdr *get_tcphdr(uint8_t*);
int send_ether_frame(uint8_t* ether_frame,int frame_length);
void mptcp_key_sha1(uint64_t key, uint32_t *token, uint64_t *idsn);
int strhextobytehex(const char* strhex,int8_t* bytehexbuf,int len);
uint32_t get_rand();

uint32_t get_data_seq_h_32(uint64_t idsn_n);
int create_mpdss_ack (unsigned char *top, uint16_t *len, uint32_t ack_num_n);
int create_MPadd_addr(unsigned char *top, uint16_t *len, unsigned char addr_id_loc, const char* sfl_ip_loc);
int create_MPjoin_syn(unsigned char *top, uint16_t *len, uint32_t token, unsigned char addr_id);

int send_mpcap_syn_ether_frame(uint8_t *ether_frame,int *frame_length);
int recv_mpcap_synack_ether_frame(uint8_t *recv_ether_frame);
int send_mpcap_ack_ether_frame(uint8_t* mpcap_syn_ether_frame,int mpcap_syn_frame_length,uint8_t* mpcap_synack_ether_frame);
int send_mpjoin_syn_ether_frame(uint8_t *ether_frame,int *frame_length);

int
main (int argc, char **argv)
{

	int mpcap_syn_frame_length;
	uint8_t *mpcap_syn_ether_frame,*mpcap_synack_ether_frame;


	mpcap_syn_ether_frame = allocate_ustrmem (IP_MAXPACKET);
	mpcap_synack_ether_frame = allocate_ustrmem (IP_MAXPACKET);

	char* cmd = "iptables -A OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP";
    system(cmd);

	//MP_CAP
	//first handshake
	send_mpcap_syn_ether_frame(mpcap_syn_ether_frame,&mpcap_syn_frame_length);

  	//second handshake
	recv_mpcap_synack_ether_frame(mpcap_synack_ether_frame);

  	//third handshake
	send_mpcap_ack_ether_frame(mpcap_syn_ether_frame,mpcap_syn_frame_length,mpcap_synack_ether_frame);

	//MP_JOIN
	//first handshake
	memset(mpcap_syn_ether_frame,0,IP_MAXPACKET);
	mpcap_syn_frame_length = 0;
	send_mpjoin_syn_ether_frame(mpcap_syn_ether_frame,&mpcap_syn_frame_length);

//	free(mpcap_syn_ether_frame);
//	free(mpcap_synack_ether_frame);

	return (EXIT_SUCCESS);


}

int send_mpjoin_syn_ether_frame(uint8_t *ether_frame,int *frame_length)
{
	int i, c, status, sd, bytes, *ip_flags, *tcp_flags, nopt, buf_len;
	struct ip iphdr;
	struct tcphdr tcphdr;
	uint8_t *opt_buffer;
	void *tmp;

	// Allocate memory for various arrays.
	ip_flags = allocate_intmem (4);
	tcp_flags = allocate_intmem (8);
	opt_buffer = allocate_ustrmem (40);
	
	// Copy all options into single options buffer.
	buf_len = 0;
	create_MPjoin_syn(opt_buffer,&buf_len,token_rem_n,ADDR_ID);	
	
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
	if ((status = inet_pton (AF_INET, src_ip2, &(iphdr.ip_src))) != 1) {
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
	tcphdr.th_sport = htons (src_port+100);
	
	// Destination port number (16 bits)
	tcphdr.th_dport = htons (dst_port);
	
	// Sequence number (32 bits)
	tcphdr.th_seq = htonl (random() % 65535);

	
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
	tcphdr.th_win = htons (29200);
	
	// Urgent pointer (16 bits): 0 (only valid if URG flag is set)
	tcphdr.th_urp = htons (0);
	
	// TCP checksum (16 bits)
	tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, opt_buffer, buf_len, NULL, 0);
	
	// Fill out ethernet frame header.
	
	// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header + TCP options)
	*frame_length = IP4_HDRLEN + TCP_HDRLEN + buf_len;
	
	// IPv4 header
	memcpy (ether_frame, &iphdr, IP4_HDRLEN * sizeof (uint8_t));
	
	// TCP header
	memcpy (ether_frame + IP4_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
	
	// TCP Options
	memcpy (ether_frame + IP4_HDRLEN + TCP_HDRLEN, opt_buffer, buf_len * sizeof (uint8_t));

	send_ether_frame(ether_frame,*frame_length);

	// Free allocated memory.
	free (ip_flags);
	free (tcp_flags);
	free (opt_buffer);

	return 1;
}



int send_mpcap_ack_ether_frame(uint8_t* mpcap_syn_ether_frame,int mpcap_syn_frame_length,uint8_t* mpcap_synack_ether_frame)
{
	uint8_t *opt_ack_buff;
	struct ip *syn_iphdr;
	struct tcphdr *syn_tcphdr,*synack_tcphdr;
	int *tcp_flags;
	int i,opt_syn_len = 12,opt_ack_len;

	struct mp_dss mp_dss;
	uint64_t key,idsn,*p_rcv_key;
	
	int http_len = 0;
	uint8_t* http_frame_buf;

	tcp_flags = allocate_intmem (8);
	opt_ack_buff = allocate_ustrmem (opt_syn_len + KEY_LEN + 12);
	http_len = strlen(http_frame_str)/2;
	http_frame_buf = allocate_ustrmem(http_len);

	syn_iphdr = get_iphdr(mpcap_syn_ether_frame);
	syn_tcphdr = get_tcphdr(mpcap_syn_ether_frame);
	synack_tcphdr = get_tcphdr(mpcap_synack_ether_frame + ETH_HDRLEN);

	// Cast rcv_key


	//Modify syn frame to ack frame

	//IP level
	//Total length of IP datagram (16 bits)	
	syn_iphdr->ip_sum = checksum ((uint16_t *) &syn_iphdr, IP4_HDRLEN);

	//TCP level
	// Data offset (4 bits): size of TCP header + length of options, in 32-bit words
	syn_tcphdr->th_ack = htonl(ntohl(synack_tcphdr->th_seq) + 1);
	syn_tcphdr->th_seq = synack_tcphdr->th_ack;

	// Window size (16 bits)
	syn_tcphdr->th_win = htons (29312);



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

	//Create opt_ack_buff
	memcpy(opt_ack_buff,mpcap_syn_ether_frame + IP4_HDRLEN + TCP_HDRLEN, opt_syn_len * sizeof(uint8_t));
	memcpy(opt_ack_buff + opt_syn_len, &key_rem_n, KEY_LEN * sizeof(uint8_t));
	opt_ack_buff[1] = 20u;

	opt_ack_len = opt_syn_len + KEY_LEN;
	create_mpdss_ack(opt_ack_buff,&opt_ack_len,data_ack_n);

	//Patch opt_ack_buff
	memcpy (mpcap_syn_ether_frame + IP4_HDRLEN + TCP_HDRLEN, opt_ack_buff, opt_ack_len * sizeof (uint8_t));

	syn_iphdr->ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + opt_ack_len);
	syn_tcphdr->th_off = (TCP_HDRLEN + opt_ack_len) / 4;

	syn_tcphdr->th_sum = tcp4_checksum (*syn_iphdr, *syn_tcphdr, opt_ack_buff, opt_ack_len, NULL, 0);


	//send MPCAP ack
	send_ether_frame(mpcap_syn_ether_frame,mpcap_syn_frame_length - opt_syn_len + opt_ack_len);


	//send ADD ADDR
	memset(opt_ack_buff,0,opt_ack_len);
	opt_ack_len = 0;
	create_MPadd_addr(opt_ack_buff,&opt_ack_len,ADDR_ID,src_ip2);
	create_mpdss_ack(opt_ack_buff,&opt_ack_len,data_ack_n);
	memcpy (mpcap_syn_ether_frame + IP4_HDRLEN + TCP_HDRLEN, opt_ack_buff, opt_ack_len * sizeof (uint8_t));

	//length
	syn_iphdr->ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + opt_ack_len);
	syn_tcphdr->th_off = (TCP_HDRLEN + opt_ack_len) / 4;

	//checksum
	syn_tcphdr->th_sum = tcp4_checksum (*syn_iphdr, *syn_tcphdr, opt_ack_buff, opt_ack_len, NULL, 0);

	send_ether_frame(mpcap_syn_ether_frame, IP4_HDRLEN + TCP_HDRLEN + opt_ack_len);

/*	
	//HTTP request
	strhextobytehex(http_frame_str,http_frame_buf,http_len);

	mp_dss.len = 20;
	mp_dss.flags = 0x05u;
//	sscanf(sender_key_str,"%16lx",&key);
	key = sender_key_str;
	idsn = 0;
	mptcp_key_sha1(ntohll(key),NULL,&idsn);
	idsn = ntohll(idsn) + 1;
	__u32 hdseq =  idsn >> 32;
//	idsn = (__u32)idsn;
	mp_dss.data_seq = htonl((__u32)idsn);
	printf("mp_dss.data_seq%16lx\n", mp_dss.data_seq);
	mp_dss.sub_seq = htonl(1);
	mp_dss.data_len = htons(http_len);
	mp_dss.dss_csum = 0;

	struct psu_dss psu_dss;
	printf("psu_dss size%d\n", sizeof(psu_dss));
	psu_dss.data_seq = ntohll(idsn);
	psu_dss.sub_seq = mp_dss.sub_seq;
	psu_dss.data_len = mp_dss.data_len;
	psu_dss.dss_csum = 0;

	__wsum csum = 0;
	csum = csum_partial(http_frame_buf,http_len,csum);
	mp_dss.dss_csum = csum_fold(csum_partial(&psu_dss, sizeof(psu_dss), csum));

	memset(opt_ack_buff,0,opt_syn_len + KEY_LEN);
	memcpy(opt_ack_buff,&mp_dss,mp_dss.len * sizeof(uint8_t));

	// PSH flag (1 bit)
	tcp_flags[3] = 1;
	syn_tcphdr->th_flags = 0;
	for (i=0; i<8; i++) {
		syn_tcphdr->th_flags += (tcp_flags[i] << i);
	}


	opt_ack_len = 20;
	syn_iphdr->ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + opt_ack_len + http_len);
	syn_tcphdr->th_off = (TCP_HDRLEN + opt_ack_len) / 4;
	syn_tcphdr->th_sum = tcp4_checksum (*syn_iphdr, *syn_tcphdr, opt_ack_buff, opt_ack_len, http_frame_buf, http_len);
	printf("TCP CSUM: %02X %02X\n", syn_tcphdr->th_sum & 0xff, (syn_tcphdr->th_sum >> 8) & 0xff);

	memcpy (mpcap_syn_ether_frame + IP4_HDRLEN + TCP_HDRLEN, opt_ack_buff, opt_ack_len * sizeof (uint8_t));
	memcpy(mpcap_syn_ether_frame + IP4_HDRLEN + TCP_HDRLEN + opt_ack_len, http_frame_buf,http_len * sizeof(uint8_t));

	send_ether_frame(mpcap_syn_ether_frame,IP4_HDRLEN + TCP_HDRLEN + opt_ack_len + http_len);
*/
//	free(tcp_flags);
//	free(opt_ack_buff);
//	free(http_frame_buf);

	return 1;
}

int update_packet(){


}



//seq = idsn+1
uint32_t get_data_seq_h_32(uint64_t idsn_n){
	uint64_t idsn_h = ntohll(idsn_n);
	uint32_t data_seq_h = (uint32_t)(idsn_h+1);
	return data_seq_h;
}

int create_MPadd_addr(unsigned char *top, uint16_t *len, unsigned char addr_id_loc, const char* sfl_ip_loc) {

	uint16_t new_len = 8;
	
	if((*len) + new_len > 40) return 0;

	unsigned char *start = top + (*len);
	
	*(start) = 30;
	*(start+1) = new_len;
	*(start+2) = 0x34u;
	*(start+3) = addr_id_loc;
	*((uint32_t*) (start+4)) = inet_addr(sfl_ip_loc);
	(*len) += new_len;
	return 1;
}

int create_MPjoin_syn(unsigned char *top, uint16_t *len, uint32_t token, unsigned char addr_id) {

	uint16_t new_len = 12;

	if((*len) + new_len > 40) return 0;

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

uint32_t get_rand() {
	uint32_t nmb;
	nmb = rand();
	nmb += ( (rand()%2) <<31);
	return nmb;
}


int create_mpdss_ack(unsigned char *top, uint16_t *len, uint32_t ack_num_n){

	uint16_t new_len = 8;
	
	if((*len) + new_len > 40) return 0;

	unsigned char *start = top + (*len);
	
	*(start) = 30;
	*(start+1) = new_len;
	*(start+2) = 0x20u;
	*(start+3) = 0x01;
	*((uint32_t*) (start+4)) = ack_num_n;
	(*len) += new_len;
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
        	} 
        	else if (status == EINTR) {  // EINTR = 4
          		continue;  // Something weird happened, but let's keep listening.
      		} 
      		else {
      			perror ("recvfrom() failed ");
      			exit (EXIT_FAILURE);
      		}
      	}  // End of error handling conditionals.

      	// Check for an IP ethernet frame. If not, ignore and keep listening.
      	if ((recv_iphdr->ip_p == IPPROTO_TCP) && (inet_addr(dst_ip) == recv_iphdr->ip_src.s_addr) && 
      	    (htons(dst_port) == recv_tcphdr->th_sport) && (htons(src_port) == recv_tcphdr->th_dport)){
      			//printf("th_ack:%x\n", recv_tcphdr->th_ack);
      		p_rcv_key = (uint64_t*)(recv_ether_frame + ETH_HDRLEN + mpcap_syn_frame_length + 4 - KEY_LEN);
      		key_rem_n = *p_rcv_key;
      		mptcp_key_sha1(key_rem_n,&token_rem_n,&idsn_rem_n);
      		data_ack_h = get_data_seq_h_32(idsn_rem_n);

      			break;
       	} 
    }  // End of Receive loop.
    return 1;
}


int send_ether_frame(uint8_t* ether_frame,int frame_length)
{
	int sd,bytes;
	struct sockaddr_in dst_addr;

 // Submit request for a raw socket descriptor.
	if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("socket() failed ");
		exit (EXIT_FAILURE);
	}

	// Fill out sockaddr_ll.
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(dst_port);
	dst_addr.sin_addr.s_addr = inet_addr(dst_ip);

  // Send ethernet frame to socket.
	if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &dst_addr, sizeof(dst_addr))) <= 0) {
		perror ("sendto() failed");
		exit (EXIT_FAILURE);
	}
	printf("sent%d\n",bytes);
  // Close socket descriptor.
	close (sd);

	return 1;

}


int send_mpcap_syn_ether_frame(uint8_t *ether_frame,int *frame_length)
{
	int i, c, status, sd, bytes, *ip_flags, *tcp_flags, nopt, buf_len;
	struct ip iphdr;
	struct tcphdr tcphdr;
	uint8_t *opt_buffer;
	void *tmp;

	// Allocate memory for various arrays.
	ip_flags = allocate_intmem (4);
	tcp_flags = allocate_intmem (8);
	opt_buffer = allocate_ustrmem (40);
	
	struct mp_cap mp_cap;
	mp_cap.kind = 30;
	mp_cap.len = 12;
	mp_cap.subtype_version = 0;
	mp_cap.flags = 0x81u;
	mp_cap.key = htonll(sender_key_str);
//	printf("%d\n", sizeof(mp_cap));

	// Copy all options into single options buffer.
	buf_len = mp_cap.len;
	memcpy (opt_buffer, &mp_cap, buf_len * sizeof (uint8_t));
	
	
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
	tcphdr.th_win = htons (29200);
	
	// Urgent pointer (16 bits): 0 (only valid if URG flag is set)
	tcphdr.th_urp = htons (0);
	
	// TCP checksum (16 bits)
	tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, opt_buffer, buf_len, NULL, 0);
	
	// Fill out ethernet frame header.
	
	// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header + TCP options)
	*frame_length = IP4_HDRLEN + TCP_HDRLEN + buf_len;
	
	// IPv4 header
	memcpy (ether_frame, &iphdr, IP4_HDRLEN * sizeof (uint8_t));
	
	// TCP header
	memcpy (ether_frame + IP4_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
	
	// TCP Options
	memcpy (ether_frame + IP4_HDRLEN + TCP_HDRLEN, opt_buffer, buf_len * sizeof (uint8_t));

	send_ether_frame(ether_frame,*frame_length);

	// Free allocated memory.
	free (ip_flags);
	free (tcp_flags);
	free (opt_buffer);

	return 1;
}

int strhextobytehex(const char* strhex,int8_t* bytehexbuf,int len){

	char* strhex_ptr = strhex;
	int8_t* bytehexbuf_ptr = bytehexbuf;
	for(;bytehexbuf_ptr<bytehexbuf+len;bytehexbuf_ptr++){
		sscanf(strhex_ptr,"%02hx",bytehexbuf_ptr);
//		printf("%c%c %02x\n", strhex_ptr[0],strhex_ptr[1],bytehexbuf_ptr[0]);
		strhex_ptr +=2;
	}
	return 1;
}


struct tcphdr *
get_tcphdr(uint8_t* ether_frame)
{
	return (struct tcphdr *) (ether_frame + IP4_HDRLEN);
}

struct  ip *
get_iphdr(uint8_t* ether_frame)
{
	return (struct ip *) (ether_frame);
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
tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr, uint8_t *options, int opt_len, uint8_t *payload, int payload_len)
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

