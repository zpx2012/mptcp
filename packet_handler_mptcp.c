#include "packet_handler_mptcp.h"

//××××××××××××××
//Variables need to be setted
#define IP_LOC1_STR "169.235.31.237"
#define IP_LOC2_STR "10.25.12.228"
#define IP_REM_STR "130.104.230.45"
#define PORT_REM 80
#define SUBFLOW_ADDR_ID 3

#define KEY_LOC_N 0x5f6257d35e39d488 

#define HTTP_FRAME1_STR "474554202f20485454502f312e310d0a486f73743a206d756c7469706174682d7463702e6f72670d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a557067726164652d496e7365637572652d52657175657374733a20310d0a557365722d4167656e743a204d6f7a696c6c612f352e3020285831313b204c696e7578207838365f363429204170706c655765624b69742f3533372e333620284b48544d4c2c206c696b65204765636b6f29205562756e7475204368726f6d69756d2f36322e302e333230322e3735204368726f6d652f36322e302e333230322e3735205361666172692f3533372e33360d0a4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f776562702c696d6167652f61706e672c2a2f2a3b713d302e380d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a4163636570742d4c616e67756167653a20656e2c7a682d434e3b713d302e392c7a683b713d302e380d0a0d0a"

#define HTTP_FRAME2_STR "202f66616c6f6e67676f6e6720485454502f312e310d0a486f73743a206d756c7469706174682d7463702e6f72670d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a557067726164652d496e7365637572652d52657175657374733a20310d0a557365722d4167656e743a204d6f7a696c6c612f352e3020285831313b204c696e7578207838365f363429204170706c655765624b69742f3533372e333620284b48544d4c2c206c696b65204765636b6f29205562756e7475204368726f6d69756d2f36312e302e333136332e313030204368726f6d652f36312e302e333136332e313030205361666172692f3533372e33360d0a4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f776562702c696d6167652f61706e672c2a2f2a3b713d302e380d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a4163636570742d4c616e67756167653a207a682d434e2c7a683b713d302e380d0a0d0a"


//Consideration:
//1.should master sf_cb be global?
//2.is it ok to update ack in find_subflow_cb?

struct mpcb mpc_global;


int init_subflow_cb(
	struct subflow_cb* p_sf_cb, 
	const char* ip_loc_str,
	const char* ip_rem_str, 
	uint16_t port_loc_h,
	uint16_t port_rem_h,
	uint8_t addr_id_loc,
	uint8_t is_master,
	struct subflow_cb *p_slave_sf_cb)
{
	int status;

	if ((status = inet_pton (AF_INET, ip_loc_str, &(p_sf_cb->ip_loc_n))) != 1) {
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		return -1;
	}

	// Destination IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, ip_rem_str, &(p_sf_cb->ip_rem_n))) != 1) {
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		return -1;
	}

	p_sf_cb->port_loc_h = port_loc_h;
	p_sf_cb->port_rem_h = port_rem_h;
	p_sf_cb->tcp_ack_h = 0;
	p_sf_cb->tcp_seq_next_h = random() % 65535;
	p_sf_cb->sub_seq_next_h = 1;

	p_sf_cb->rand_loc_n = get_rand();
	p_sf_cb->rand_rem_n = 0;
	p_sf_cb->addr_id_loc = addr_id_loc;
	p_sf_cb->addr_id_rem = 0;
	p_sf_cb->is_master = is_master;
	if(is_master == SUBFLOW_MASTER)		
		p_sf_cb->p_slave_sf_cb = p_slave_sf_cb;
	else
		p_sf_cb->p_slave_sf_cb = NULL;
	return 1;

}


int init_mpcb(struct mpcb* p_mpcb, uint64_t key_loc_n){

	p_mpcb->key_loc_n = key_loc_n;
	mptcp_key_sha1(p_mpcb->key_loc_n,&(p_mpcb->token_loc_n),&(p_mpcb->idsn_loc_n));
	
	p_mpcb->key_rem_n = 0;
	p_mpcb->idsn_rem_n = 0;
	p_mpcb->token_rem_n = 0;

	p_mpcb->data_ack_h = 0;
	p_mpcb->data_seq_next_h = get_data_seq_h_32(p_mpcb->idsn_loc_n);

	return 1;
}


void do_iptable(){

	char* cmd = "iptables -A OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP";
    system(cmd);

}

int send_packet(uint8_t* buf_pkg,int len_pkg)
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
	dst_addr.sin_port = get_tcphdr_from_ip_frame(buf_pkg)->th_dport;
	dst_addr.sin_addr.s_addr = ((struct ip*)buf_pkg)->ip_dst.s_addr;

	// Send ethernet frame to socket.
	if ((bytes = sendto (sd, buf_pkg, len_pkg, 0, (struct sockaddr *) &dst_addr, sizeof(dst_addr))) <= 0) {
		perror ("sendto() failed");
		exit (EXIT_FAILURE);
	}

	close (sd);

	return 1;
}

int send_mptcp_packet(struct subflow_cb* p_sf_cb, uint8_t mptcp_sub_type, uint8_t tcp_flag, unsigned char* payload, unsigned int payload_len)
{
	uint8_t *opt_buffer= NULL,*packet_buffer = NULL;
	uint16_t opt_len = 0,packet_len = 0, win = 29200;
	uint8_t hash_mac[20];


	// Allocate memory for various arrays.
	opt_buffer = allocate_ustrmem (TCP_OPTION_MAX_LEN);
	packet_buffer = allocate_ustrmem (IP_MAXPACKET);

	// Copy all options into single options buffer.
	switch(mptcp_sub_type){
		case MPTCP_SUB_CAPABLE:
			create_MPcap(opt_buffer,&opt_len,mpc_global.key_loc_n,mpc_global.key_rem_n);
			if(tcp_flag == ACK){
				create_MPdss_ack(opt_buffer,&opt_len,mpc_global.data_ack_h);
				win += 112;
			}
			break;

		case MPTCP_SUB_JOIN:
			if(tcp_flag == SYN){
				create_MPjoin_syn(opt_buffer,&opt_len,mpc_global.token_rem_n,p_sf_cb->rand_loc_n);
			}
			else if(tcp_flag == ACK){
				if(p_sf_cb->rand_rem_n == 0){
					perror("send_mptcp_packet():NULL rand_rem_n\n");
				}
				mptcp_hmac_sha1((uint8_t *)&mpc_global.key_loc_n,  //order of ley_loc and key_rem matters
								(uint8_t *)&mpc_global.key_rem_n,
								(uint32_t *)hash_mac, 2,
								4, (uint8_t *)&p_sf_cb->rand_loc_n,
								4, (uint8_t *)&p_sf_cb->rand_rem_n);
				create_MPjoin_ack(opt_buffer, &opt_len, (uint32_t *)hash_mac);
			}
			else
				perror ("send_mptcp_packet():unexpected flag of MPTCP_SUB_JOIN");
			break;

		case MPTCP_SUB_ADD_ADDR:
			create_MPadd_addr(opt_buffer,&opt_len,p_sf_cb->p_slave_sf_cb->addr_id_loc,p_sf_cb->p_slave_sf_cb->ip_loc_n);
			create_MPdss_ack(opt_buffer,&opt_len,mpc_global.data_ack_h);
			break;

		case MPTCP_SUB_DSS:
			create_complete_MPdss(opt_buffer,&opt_len,mpc_global.data_ack_h,mpc_global.data_seq_next_h,p_sf_cb->sub_seq_next_h,(uint32_t)((mpc_global.idsn_loc_n)),payload,payload_len);
			printf("idsn_n:%llx idsn_high_n:%x\n", ntohll(mpc_global.idsn_loc_n),ntohl((uint32_t)mpc_global.idsn_loc_n));
			break;

		case MPTCP_SUB_FCLOSE:
			create_MPfclose(opt_buffer,&opt_len,&(mpc_global.key_rem_n));
			break;

		case NO_MPTCP_OPTION:
			break;

		default:
			perror ("send_mptcp_packet():unexpected mptcp_sub_type");
			break;
	}

	printf("create packet:seq %x, tcp_flag %d\n", p_sf_cb->tcp_seq_next_h,tcp_flag);
	create_packet(packet_buffer,&packet_len,p_sf_cb,tcp_flag,win,opt_buffer,opt_len,payload,payload_len);	

	send_packet(packet_buffer,packet_len);

	printf("%s\n", opt_buffer);
	free(opt_buffer);
	printf("free packet_buffer:seq %x, tcp_flag %d\n", p_sf_cb->tcp_seq_next_h, tcp_flag);
	printf("%s\n", packet_buffer);
	free(packet_buffer);

	return 1;
}

int parse_mptcp_option(uint8_t* p_mptcp_option, struct subflow_cb* p_sf_cb)
{
	uint8_t mptcp_sub_type = 0;
	uint64_t mac_n = 0;

	mptcp_sub_type = *(p_mptcp_option+2)>>4;
	switch(mptcp_sub_type){

		case MPTCP_SUB_CAPABLE:
			if(p_sf_cb->is_master != SUBFLOW_MASTER){
				perror("recv_mptcp_packet: MPTCP_SUB_CAPABLE is not master subflow");
				exit(EXIT_FAILURE);
			}
			printf("recv MPTCP_CAPABLE\n");
			mpc_global.key_rem_n = *((uint64_t*) (p_mptcp_option+4));
			mptcp_key_sha1(mpc_global.key_rem_n,&(mpc_global.token_rem_n),&(mpc_global.idsn_rem_n));
			mpc_global.data_ack_h = get_data_seq_h_32(mpc_global.idsn_rem_n);
			return 1;

		case MPTCP_SUB_JOIN:
			if(p_sf_cb->is_master == SUBFLOW_MASTER){
				perror("recv_mptcp_packet: MPTCP_SUB_JOIN is master subflow");
				exit(EXIT_FAILURE);
			}
			printf("recv MPTCP_JOIN\n");
			analyze_MPjoin_synack(p_mptcp_option,&mac_n,&(p_sf_cb->rand_rem_n),&(p_sf_cb->addr_id_rem));
      		//check man_n
			return 1;

		case MPTCP_SUB_FAIL:
			//send FCOLSE to reset
			printf("recv MPTCP_FAIL\n");
			send_mptcp_packet(p_sf_cb,MPTCP_SUB_FCLOSE,ACK,NULL,0);

		default:
			perror("recv_mptcp_packet:unexpected mptcp_sub_type");
	}

}

int parse_tcp_options(unsigned char *opt_buf, uint16_t opt_len,struct subflow_cb* p_sf_cb){

	size_t curs = 0;
	while(curs < opt_len) {
		if( *(opt_buf+curs) <= 1) 
			curs++;//those are the one-byte option with kind =0 or kind =1
		else{				
			if( *(opt_buf+curs+1) == 0 )
				break;

			if( *(opt_buf+curs) == 30) {//MPTCP_KIND
				parse_mptcp_option(opt_buf+curs,p_sf_cb);
				return 1;
			}
		}
		curs+= (*(opt_buf+curs+1));
	}
	printf("No mptcp option found\n");
	return -1;
}


//find subflow_cb by 4turple in recv ether frame
int handle_recv_mptcp_packet(uint8_t* recv_ether_frame, int len_recv_ether_frame,struct subflow_cb* p_mastr_sf_cb)
{
	int i;
	struct ip *recv_iphdr = NULL;
	struct tcphdr* recv_tcphdr = NULL;
	struct subflow_cb *p_index_sf_cb = NULL;

	recv_iphdr = get_iphdr_from_ether_frame(recv_ether_frame);
	recv_tcphdr = get_tcphdr_from_ether_frame(recv_ether_frame);

	if (recv_iphdr->ip_p != IPPROTO_TCP)
		return -1;

	p_index_sf_cb = p_mastr_sf_cb;
	for(i = 0; i < 2;i++){
		if( (recv_iphdr->ip_src.s_addr == p_index_sf_cb->ip_rem_n) &&
			(recv_iphdr->ip_dst.s_addr == p_index_sf_cb->ip_loc_n) &&  
			(recv_tcphdr->th_sport     == htons(p_index_sf_cb->port_rem_h)) && 
			(recv_tcphdr->th_dport     == htons(p_index_sf_cb->port_loc_h))
		){
			//check seq and update ack in mpc
  			if(p_index_sf_cb->tcp_seq_next_h != ntohl(recv_tcphdr->th_ack)){
				fprintf(stderr,"seq check in recv_mpcap_synack failed:tcp_seq_next_h %x,th_ack %x\n",p_index_sf_cb->tcp_seq_next_h,ntohl(recv_tcphdr->th_ack));
				printf("\n");
				return -1;
			}
			p_index_sf_cb->tcp_ack_h = ntohl(recv_tcphdr->th_seq) + 1;

			//found, return
			parse_tcp_options((uint8_t*)(recv_tcphdr) + TCP_HDRLEN,ntohs(recv_tcphdr->th_off)*4 - TCP_HDRLEN,p_index_sf_cb);
			return 1;
		}
		p_index_sf_cb = p_mastr_sf_cb->p_slave_sf_cb;
	}
	return -1;

}


int recv_mptcp_packet(struct subflow_cb* p_sf_cb)
{
	int recvsd,bytes;
	uint8_t *buf_recv_ether_frame;

	buf_recv_ether_frame = allocate_ustrmem (IP_MAXPACKET);

	// Submit request for a raw socket descriptor to receive packets.
	if ((recvsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
		perror ("socket() failed ");
		exit (EXIT_FAILURE);
	}

	// RECEIVE LOOP
	for (;;) {

		memset (buf_recv_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
		if ((bytes = recv(recvsd, buf_recv_ether_frame, IP_MAXPACKET, 0)) < 0) {
        	// Deal with error conditions first.
        	if (errno == EAGAIN) {  // EAGAIN = 11
        		perror ("recv_mptcp_packet() failed ");
        		exit (EXIT_FAILURE);
        	} 
        	else if (errno == EINTR) {  // EINTR = 4
          		continue;  // Something weird happened, but let's keep listening.
      		} 
      		else {
      			perror ("recv_mptcp_packet() failed ");
      			exit (EXIT_FAILURE);
      		}
      	}  // End of error handling conditionals.

      	if(handle_recv_mptcp_packet(buf_recv_ether_frame,bytes,p_sf_cb) == 1)
      		return 1;
    }  // End of Receive loop.

    free(buf_recv_ether_frame);

    return 1;
}



int
main (int argc, char **argv)
{
	struct subflow_cb sf_master,sf_slave;

	init_mpcb(&mpc_global,KEY_LOC_N);

	init_subflow_cb(&sf_master,IP_LOC1_STR,IP_REM_STR,get_rand()+2,PORT_REM,0,SUBFLOW_MASTER,&sf_slave);
	init_subflow_cb(&sf_slave ,IP_LOC2_STR,IP_REM_STR,get_unused_port_number(IP_LOC2_STR),PORT_REM,SUBFLOW_ADDR_ID,SUBFLOW_MASTER+1,NULL);

	do_iptable();

	//MP_CAP
	//first handshake
	send_mptcp_packet(&sf_master,MPTCP_SUB_CAPABLE,SYN,NULL,0);

  	//second handshake
	recv_mptcp_packet(&sf_master);

  	//third handshake
	send_mptcp_packet(&sf_master,MPTCP_SUB_CAPABLE,ACK,NULL,0);

	//ADD ADDR
//	send_mptcp_packet(&sf_master,MPTCP_SUB_ADD_ADDR,ACK,NULL,0);

	//Send first data packet
	uint16_t len_payload = strlen(HTTP_FRAME1_STR)/2;
	uint8_t *payload = allocate_ustrmem(len_payload);
	strhex_to_bytehex(HTTP_FRAME1_STR,payload,len_payload);
//	payload[len_payload] = 0;
	send_mptcp_packet(&sf_master,MPTCP_SUB_DSS,ACK|PSH,payload,len_payload);
	free(payload);

	//MP_JOIN
//	send_mptcp_packet(&sf_slave,MPTCP_SUB_JOIN,SYN,NULL,0);

//	recv_mptcp_packet(&sf_master);

//	send_mptcp_packet(&sf_slave,MPTCP_SUB_JOIN,ACK,NULL,0);
	
	//send second data packet
//	send_mptcp_packet(&sf_slave,MPTCP_SUB_DSS,ACK|PSH,HTTP_FRAME2_STR,strlen(HTTP_FRAME2_STR));

	//FCLOSE
//	send_mptcp_packet(&sf_master,MPTCP_SUB_FCLOSE,ACK,NULL,0);
//	send_mptcp_packet(&sf_slave ,NO_MPTCP_OPTION,RST,NULL,0);
	return (EXIT_SUCCESS);


}