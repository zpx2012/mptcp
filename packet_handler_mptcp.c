#include "packet_handler_mptcp.h"

//××××××××××××××
//Variables need to be setted
#define INTERF_1 "eth0"
#define INTERF_2 "wlp3s0"
#define IP_LOC1_STR "202.112.50.150"
#define IP_LOC2_STR "10.25.17.144"
#define IP_REM_STR "130.104.230.45"
#define PORT_REM 80
#define PORT 3805
#define SUBFLOW_ADDR_ID 3

#define KEY_LOC_N 0x5f6257d35e39d488 

#define HTTP_FRAME1_STR "474554202f20485454502f312e310d0a486f73743a206d756c7469706174682d7463702e6f72670d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a557067726164652d496e7365637572652d52657175657374733a20310d0a557365722d4167656e743a204d6f7a696c6c612f352e3020285831313b204c696e7578207838365f363429204170706c655765624b69742f3533372e333620284b48544d4c2c206c696b65204765636b6f29205562756e7475204368726f6d69756d2f36322e302e333230322e3735204368726f6d652f36322e302e333230322e3735205361666172692f3533372e33360d0a4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f776562702c696d6167652f61706e672c2a2f2a3b713d302e380d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a4163636570742d4c616e67756167653a20656e2c7a682d434e3b713d302e392c7a683b713d302e380d0a0d0a"
#define HTTP_FRAME11_STR "474554"
#define HTTP_FRAME12_STR "202f20485454502f312e310d0a486f73743a206d756c7469706174682d7463702e6f72672f756c747261737572660d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a557067726164652d496e7365637572652d52657175657374733a20310d0a557365722d4167656e743a204d6f7a696c6c612f352e3020285831313b204c696e7578207838365f363429204170706c655765624b69742f3533372e333620284b48544d4c2c206c696b65204765636b6f29205562756e7475204368726f6d69756d2f36322e302e333230322e3735204368726f6d652f36322e302e333230322e3735205361666172692f3533372e33360d0a4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f776562702c696d6167652f61706e672c2a2f2a3b713d302e380d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a4163636570742d4c616e67756167653a20656e2c7a682d434e3b713d302e392c7a683b713d302e380d0a0d0a"

#define HTTP_FRAME2_STR "202f66616c6f6e67676f6e6720485454502f312e310d0a486f73743a206d756c7469706174682d7463702e6f72670d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a557067726164652d496e7365637572652d52657175657374733a20310d0a557365722d4167656e743a204d6f7a696c6c612f352e3020285831313b204c696e7578207838365f363429204170706c655765624b69742f3533372e333620284b48544d4c2c206c696b65204765636b6f29205562756e7475204368726f6d69756d2f36312e302e333136332e313030204368726f6d652f36312e302e333136332e313030205361666172692f3533372e33360d0a4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f776562702c696d6167652f61706e672c2a2f2a3b713d302e380d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a4163636570742d4c616e67756167653a207a682d434e2c7a683b713d302e380d0a0d0a"


//Consideration:
//1.should master sf_cb be global?
//2.is it ok to update ack in find_subflow_cb?

int init_subflow_cb(
	struct subflow_cb* p_sf_cb,
	const char* interface_str, 
	const char* ip_loc_str,
	const char* ip_rem_str, 
	uint16_t port_loc_h,
	uint16_t port_rem_h,
	uint8_t addr_id_loc,
	uint8_t is_master,
	struct subflow_cb *p_slave_sf_cb)
{
	int sd,status,length;
	struct sockaddr_in skaddr;

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


	if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("socket() failed ");
		exit (EXIT_FAILURE);
	}

	if(setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, interface_str, strlen(interface_str)) < 0)
		perror("bind interface error");
	
	skaddr.sin_family = AF_INET;
	skaddr.sin_addr.s_addr = p_sf_cb->ip_loc_n;;
	skaddr.sin_port = htons(port_loc_h);

	if (bind(sd, (struct sockaddr *) &skaddr, sizeof(skaddr))<0) {
	  perror("Problem binding\n");
	  exit(EXIT_FAILURE);
	}

//	length = sizeof(skaddr);
//	if (getsockname(sd, (struct sockaddr *) &skaddr, &length)<0) {
//	  perror("Error getsockname\n");
//	  exit(EXIT_FAILURE);
//	}

	p_sf_cb->socket_d = sd;
//	p_sf_cb->port_loc_h = skaddr.sin_port;
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

int send_packet(int sd,uint8_t* buf_pkg,int len_pkg)
{
	int bytes;
	struct sockaddr_in dst_addr;

	// Fill out sockaddr_ll.
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = get_tcphdr_from_ip_frame(buf_pkg)->th_dport;
	dst_addr.sin_addr.s_addr = ((struct ip*)buf_pkg)->ip_dst.s_addr;

	printf("sd:%d\n", sd);

	// Send ethernet frame to socket.
	if ((bytes = sendto (sd, buf_pkg, len_pkg, 0, (struct sockaddr *) &dst_addr, sizeof(dst_addr))) <= 0) {
		perror ("sendto() failed");
		exit (EXIT_FAILURE);
	}

	return 1;
}

int send_mptcp_packet(struct subflow_cb* p_sf_cb, uint8_t mptcp_sub_type, uint8_t tcp_flag, unsigned char* payload_str, unsigned int payload_str_len)
{
	uint8_t *opt_buffer= NULL,*packet_buffer = NULL,*payload = NULL;
	uint16_t opt_len = 0,packet_len = 0, payload_len = 0,win = 29200;
	uint8_t hash_mac[20];
	int i;


	// Allocate memory for various arrays.
	opt_buffer = allocate_ustrmem (TCP_OPTION_MAX_LEN);
	packet_buffer = allocate_ustrmem (IP_MAXPACKET);

	// Copy all options into single options buffer.
	switch(mptcp_sub_type){

		case MPTCP_SUB_CAPABLE:
			create_MPcap(opt_buffer,&opt_len,mpc_global.key_loc_n,mpc_global.key_rem_n);
			if(tcp_flag == ACK){
				printf("send MPTCP_CAPABLE ack\n");
				create_MPdss_ack(opt_buffer,&opt_len,mpc_global.data_ack_h);
				win += 112;
				break;
			}
			printf("send MPTCP_CAPABLE syn\n");
			break;

		case MPTCP_SUB_JOIN:
			if(tcp_flag == SYN){
				printf("send MPTCP_JOIN syn\n");
				create_MPjoin_syn(opt_buffer,&opt_len,mpc_global.token_rem_n,p_sf_cb->rand_loc_n,p_sf_cb->addr_id_loc);
			}
			else if(tcp_flag == ACK){
				if(p_sf_cb->rand_rem_n == 0){
					perror("send_mptcp_packet():NULL rand_rem_n\n");
				}
				printf("key_loc_n %lx,key_rem_n %lx,rand_loc_n %x,rand_rem_n %x\n", 
					    mpc_global.key_loc_n,mpc_global.key_rem_n,p_sf_cb->rand_loc_n,p_sf_cb->rand_rem_n);
				mptcp_hmac_sha1((uint8_t *)&mpc_global.key_loc_n,  //order of ley_loc and key_rem matters
								(uint8_t *)&mpc_global.key_rem_n,
								(uint32_t *)hash_mac, 2,
								4, (uint8_t *)&p_sf_cb->rand_loc_n,
								4, (uint8_t *)&p_sf_cb->rand_rem_n);
				for (i = 0; i < 20; ++i)
					printf("%02hhx", hash_mac[i]);
				printf("\n");
				printf("send MPTCP_JOIN ack\n");
				create_MPjoin_ack(opt_buffer, &opt_len, (uint32_t *)hash_mac);
			}
			else
				perror ("send_mptcp_packet():unexpected flag of MPTCP_SUB_JOIN");
			break;

		case MPTCP_SUB_ADD_ADDR:
			printf("send MPTCP_ADD_ADDR\n");
			win += 112;
			create_MPadd_addr(opt_buffer,&opt_len,p_sf_cb->p_slave_sf_cb->addr_id_loc,p_sf_cb->p_slave_sf_cb->ip_loc_n);
			create_MPdss_ack(opt_buffer,&opt_len,mpc_global.data_ack_h);
			break;

		case MPTCP_SUB_DSS:
			if(tcp_flag == ACK){
				printf("send MPTCP_DSS_ACK\n");
				create_MPdss_ack(opt_buffer,&opt_len,mpc_global.data_ack_h);
				break;
			}
			printf("send MPTCP_COMPLETE_DSS\n");
			payload_len = payload_str_len/2;
			payload = allocate_ustrmem(payload_len);
			strhex_to_bytehex(payload_str,payload,payload_len);
			create_complete_MPdss(opt_buffer,&opt_len,mpc_global.data_ack_h,mpc_global.data_seq_next_h,p_sf_cb->sub_seq_next_h,(uint32_t)((mpc_global.idsn_loc_n)),payload,payload_len);
			break;

		case MPTCP_SUB_FCLOSE:
			printf("send MPTCP_FCLOSE\n");
			create_MPfclose(opt_buffer,&opt_len,mpc_global.key_rem_n);
			break;

		case NO_MPTCP_OPTION:
			break;

		default:
			perror ("send_mptcp_packet():unexpected mptcp_sub_type");
			break;
	}

//	printf("create packet:seq %x, tcp_flag %d\n", p_sf_cb->tcp_seq_next_h,tcp_flag);
	create_packet(packet_buffer,&packet_len,p_sf_cb,tcp_flag,win,opt_buffer,opt_len,payload,payload_len);	

	send_packet(p_sf_cb->socket_d,packet_buffer,packet_len);

	free(opt_buffer);
	free(packet_buffer);
	if(payload)
		free(payload);

	return 1;
}

int parse_mptcp_option(struct subflow_cb* p_sf_cb, uint8_t* p_mptcp_option, uint8_t tcp_flag)
{
	uint8_t mptcp_sub_type = 0;
	uint64_t mac_n = 0;

	mptcp_sub_type = *(p_mptcp_option+2)>>4;
	printf("mptcp_sub_type:%d\n", mptcp_sub_type);
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

			send_mptcp_packet(p_sf_cb,MPTCP_SUB_CAPABLE,ACK,NULL,0);
			send_mptcp_packet(p_sf_cb,MPTCP_SUB_ADD_ADDR,ACK,NULL,0);
			send_mptcp_packet(p_sf_cb,MPTCP_SUB_DSS,ACK|PSH,HTTP_FRAME11_STR,strlen(HTTP_FRAME11_STR));
			send_mptcp_packet(p_sf_cb->p_slave_sf_cb,MPTCP_SUB_JOIN,SYN,NULL,0);
			break;

		case MPTCP_SUB_JOIN:
			if(p_sf_cb->is_master == SUBFLOW_MASTER){
				perror("recv_mptcp_packet: MPTCP_SUB_JOIN is master subflow");
				exit(EXIT_FAILURE);
			}
			printf("recv MPTCP_JOIN\n");
			analyze_MPjoin_synack(p_mptcp_option,&mac_n,&(p_sf_cb->rand_rem_n),&(p_sf_cb->addr_id_rem));
			send_mptcp_packet(p_sf_cb,MPTCP_SUB_JOIN,ACK,NULL,0);
			send_mptcp_packet(p_sf_cb,MPTCP_SUB_DSS,ACK|PSH,HTTP_FRAME12_STR,strlen(HTTP_FRAME12_STR));
      		//check man_n
			break;

		case MPTCP_SUB_DSS:
			if(analyze_complete_MPdss(p_mptcp_option,&(mpc_global.data_ack_h)) == 1){
				printf("recv MPTCP_COMPLETE_DSS\n");
				send_mptcp_packet(p_sf_cb,MPTCP_SUB_DSS,ACK,NULL,0);
				break;
			}
			if((tcp_flag&FIN) != 0){
				printf("recv MPTCP_DSS FIN ACK:%d %d\n",tcp_flag,FIN);
				send_mptcp_packet(p_sf_cb,MPTCP_SUB_DSS,ACK,NULL,0);
				send_mptcp_packet(p_sf_cb,MPTCP_SUB_FCLOSE,ACK,NULL,0);	
			}
			printf("recv MPTCP_DSS_ACK\n");
			break;

		case MPTCP_SUB_FAIL:
			//send FCOLSE to reset
			printf("recv MPTCP_FAIL\n");
			send_mptcp_packet(p_sf_cb,MPTCP_SUB_FCLOSE,ACK,NULL,0);
			break;

		case MPTCP_SUB_ADD_ADDR:
			printf("recv MPTCP_ADD_ADDR\n");
			if(p_sf_cb->p_slave_sf_cb)
				send_mptcp_packet(p_sf_cb->p_slave_sf_cb,MPTCP_SUB_JOIN,SYN,NULL,0);
			break;

		default:
			printf("recv_mptcp_packet:unexpected mptcp_sub_type:%d\n",mptcp_sub_type);
	}
	return 1;

}

uint8_t* find_mptcp_options(unsigned char *opt_buf, uint16_t opt_len){

	size_t curs = 0;
	while(curs < opt_len) {
		if( *(opt_buf+curs) <= 1) 
			curs++;//those are the one-byte option with kind =0 or kind =1
		else{				
			if( *(opt_buf+curs+1) == 0 )
				break;

			if( *(opt_buf+curs) == 30) {//MPTCP_KIND
				return opt_buf+curs;
			}
		}
		curs+= (*(opt_buf+curs+1));
	}
	printf("No mptcp option found\n");
	return NULL;
}


//find subflow_cb by 4turple in recv ether frame
int handle_recv_mptcp_packet(uint8_t* recv_ether_frame, int len_recv_ether_frame,struct subflow_cb* p_mastr_sf_cb)
{
	int i;
	uint16_t ip_len = 0, tcp_off = 0, payload_len = 0;
	uint8_t *p_mptcp_option = NULL;
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
			printf("master sf:%d\n", p_index_sf_cb->is_master);
			//check seq 
  			if(p_index_sf_cb->tcp_seq_next_h != ntohl(recv_tcphdr->th_ack)){
				fprintf(stderr,"seq check failed:tcp_seq_next_h %d,th_ack %d\n",p_index_sf_cb->tcp_seq_next_h,ntohl(recv_tcphdr->th_ack));
				return -1;
			}
			if(p_index_sf_cb->tcp_ack_h != ntohl(recv_tcphdr->th_seq)){
				fprintf(stderr,"ack check failed:tcp_ack_h %d,th_seq %d\n",p_index_sf_cb->tcp_ack_h,ntohl(recv_tcphdr->th_seq));
			}

			//update tcp ack
			//? make a funtion?
			printf("tcp flag:%hhd\n", recv_tcphdr->th_flags);
			if((recv_tcphdr->th_flags&SYN) !=0 || (recv_tcphdr->th_flags&FIN) != 0){
				printf("recv SYN or FIN:th_flags&SYN %d,th_flags&FIN %d, SYN %d\n",recv_tcphdr->th_flags&SYN,recv_tcphdr->th_flags&FIN,SYN);
				p_index_sf_cb->tcp_ack_h = ntohl(recv_tcphdr->th_seq) + 1;
			}
			else if((recv_tcphdr->th_flags&ACK) !=0){
				printf("recv ACK\n");
				ip_len = ntohs(recv_iphdr->ip_len);   // IP4_HDRLEN + TCP_HDRLEN + opt_len + payload_len
				tcp_off= recv_tcphdr->th_off*4;// TCP_HDRLEN + opt_len
				payload_len = ip_len - tcp_off - IP4_HDRLEN;
				p_index_sf_cb->tcp_ack_h = ntohl(recv_tcphdr->th_seq) + payload_len;
				printf("ip_len:%d, tcp_off:%d, payload_len:%d, tcp_ack:%d\n", ip_len,tcp_off,payload_len,p_index_sf_cb->tcp_ack_h);				
			}
			else
				printf("unexpected tcp flag:%d\n", recv_tcphdr->th_flags); 				


			//found, handle
			p_mptcp_option = find_mptcp_options((uint8_t*)(recv_tcphdr) + TCP_HDRLEN,tcp_off - TCP_HDRLEN);
			if(p_mptcp_option)
				parse_mptcp_option(p_index_sf_cb,p_mptcp_option,recv_tcphdr->th_flags);
			printf("\n");
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

      	handle_recv_mptcp_packet(buf_recv_ether_frame,bytes,p_sf_cb);
    }  // End of Receive loop.

    free(buf_recv_ether_frame);

    return 1;
}



int
main (int argc, char **argv)
{
	struct subflow_cb sf_master,sf_slave;

	init_mpcb(&mpc_global,KEY_LOC_N);

	init_subflow_cb(&sf_master,INTERF_1,IP_LOC1_STR,IP_REM_STR,PORT+2,PORT_REM,0,SUBFLOW_MASTER,&sf_slave);
	init_subflow_cb(&sf_slave ,INTERF_1,IP_LOC1_STR,IP_REM_STR,PORT,PORT_REM,SUBFLOW_ADDR_ID,SUBFLOW_MASTER+1,NULL);

	do_iptable();

	//MP_CAP
	//first handshake
	send_mptcp_packet(&sf_master,MPTCP_SUB_CAPABLE,SYN,NULL,0);

  	//second handshake
	recv_mptcp_packet(&sf_master);

  	//third handshake


	//ADD ADDR


	//Send first data packet

	//MP_JOIN


//	
	
	//send second data packet
//	

	//FCLOSE
	send_mptcp_packet(&sf_master,MPTCP_SUB_FCLOSE,ACK,NULL,0);
//	send_mptcp_packet(&sf_slave ,NO_MPTCP_OPTION,RST,NULL,0);
	return (EXIT_SUCCESS);


}
