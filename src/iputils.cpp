#include "../iputils.h"

#if defined(__WXMSW__)
	//Winsock library
	#pragma comment(lib , "ws2_32.lib")
#endif

/**
    Checksums - IP and TCP
 */
unsigned short iputils::csum(unsigned short *ptr,int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1)
	{
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;

	return(answer);
}

/**
	Get ip from domain name
*/
char* iputils::hostname_to_ip(char * hostname)
{
	struct hostent *he;
	struct in_addr **addr_list;
	int i;

	if ( (he = gethostbyname( hostname ) ) == NULL)
	{
		// get the host info
		//herror("gethostbyname");
		return NULL;
	}

	addr_list = (struct in_addr **) he->h_addr_list;

	for(i = 0; addr_list[i] != NULL; i++)
	{
		//Return the first one;
		return inet_ntoa(*addr_list[i]) ;
	}

	return NULL;
}

/**
	@brief
	Get hostname from ip address , reverse dns lookup
*/
/*
char* iputils::ip_to_hostname(char *ip_address)
{
	struct hostent *he;
    struct in_addr addr;

    inet_pton(AF_INET , ip_address , &addr);
    he = gethostbyaddr( &addr , sizeof addr , AF_INET);

    if(he != NULL)
    {
        return he->h_name;
    }

    return "";
}
*/


char* iputils::ip_to_hostname(char *ip_address , char *hostname)
{
	struct sockaddr_in sa; // could be IPv4 if you want
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(ip_address);

	char host[1024];
	char service[20];

	if(getnameinfo((struct sockaddr*)&sa , sizeof sa , host, sizeof host , service , sizeof service, 0) == 0)
	{
		//printf("   host: %s\n", host);    // e.g. "www.example.com"
		//printf("service: %s\n", service); // e.g. "http"
		strcpy(hostname , host);
	}
	else
	{
#if defined(_WIN32)
		//sprintf(hostname , "Error Code : %d", WSAGetLastError());
#else
		//strcpy(hostname , "Error");
#endif
	}

	return hostname;
}

/**
	@brief
	Get source IP of system , like 192.168.0.6 or 192.168.1.2
*/

void iputils::get_local_ip ( char * buffer)
{

#if defined(__WXMSW__)
	WSADATA wsaData;
	if( WSAStartup(MAKEWORD(2, 2), &wsaData)!=0 )
	{
		return;
	}
#endif

	//UDP socket please
	int sock = socket ( AF_INET , SOCK_DGRAM , 0);

	const char *google_dns = "8.8.8.8";
	int dns_port = 53;

	struct sockaddr_in serv;

	memset( &serv , 0 , sizeof(serv) );
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr( google_dns );
	serv.sin_port = htons( dns_port );

	int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname( sock , (struct sockaddr*) &name, &namelen );

#if defined(__UNIX__)
	inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

	close(sock);

#elif defined(__WXMSW__)
	//inet_ntop is not available on windowx xp and below , only vista and above have it
	strcpy(buffer , inet_ntoa(name.sin_addr));

	closesocket(sock);
#endif

}

/**
    @brief
	Check if an ip is private or not

	@details
    RFC 1918

	The following ip ranges are private :

    10.0.0.0 – 10.255.255.255
    172.16.0.0 – 172.31.255.255
    192.168.0.0 – 192.168.255.255
*/
bool iputils::check_private_ip(char *ip_address)
{
    long ipnum = htonl(inet_addr(ip_address));

    if( ipnum > htonl(inet_addr("192.168.0.0")) && ipnum < htonl(inet_addr("192.168.255.255")) )
    {
        return true;
    }

    if( ipnum > htonl(inet_addr("172.16.0.0")) && ipnum < htonl(inet_addr("172.31.255.255")) )
    {
        return true;
    }

    if( ipnum > htonl(inet_addr("10.0.0.0")) && ipnum < htonl(inet_addr("10.255.255.255")) )
    {
        return true;
    }

    //By default not private
    return false;
}

/**
    @brief
    Get ip whois information
*/
bool iputils::get_ip_whois(char *ip , char *whois_data)
{
    char *data = NULL;
    iputils::get_whois(ip , &data);

    strcpy(whois_data , data);

    free(data);

	return true;
}

/**
	@brief
	Get the whois content of an ip by selecting the correct server
*/
void iputils::get_whois(char *ip , char **data)
{
	char *wch = NULL, *pch , *response = NULL;

	if(iputils::whois_query("whois.iana.org" , ip , &response))
	{
		printf("Whois query failed");
	}

	pch = strtok(response , "\n");

	while(pch != NULL)
	{
		//Check if whois line
		wch = strstr(pch , "whois.");
		if(wch != NULL)
		{
			break;
		}

		//Next line please
		pch = strtok(NULL , "\n");
	}

    if(wch != NULL)
    {
        printf("\nWhois server is : %s" , wch);
        iputils::whois_query(wch , ip , data);
    }
    else
    {
        printf("No whois data found");

        //malloc is necessary since we do a free in the calling function
        *data = (char*)malloc(100);
        strcpy(*data , "No whois data");
    }

    free(response);

	return;
}

/**
    @brief
    Perform a whois query to a server and record the response
*/
int iputils::whois_query(char *server , char *query , char **response)
{
	char *ip , message[100] , buffer[1500];
	int sock , read_size , total_size = 0;
	struct sockaddr_in dest;

	sock = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);

    //Prepare connection structures :)
    memset( &dest , 0 , sizeof(dest) );
    dest.sin_family = AF_INET;

	printf("\nResolving %s..." , server);

	if( (ip = iputils::hostname_to_ip(server)) == NULL )
	{
		printf("Failed");
		return 1;
	}

	printf("%s" , ip);
	dest.sin_addr.s_addr = inet_addr( ip );
	dest.sin_port = htons( 43 );

	//Now connect to remote server
	if(connect( sock , (const struct sockaddr*) &dest , sizeof(dest) ) < 0)
	{
		perror("connect failed");
	}

	//Now send some data or message
	printf("\nQuerying for ... %s ..." , query);
	sprintf(message , "%s\r\n" , query);
	if( send(sock , message , strlen(message) , 0) < 0)
	{
		perror("send failed");
	}

	//Now receive the response
	while( (read_size = recv(sock , buffer , sizeof(buffer) , 0) ) )
	{
		*response = (char *)realloc(*response , read_size + total_size);
		if(*response == NULL)
		{
			printf("realloc failed");
		}
		memcpy(*response + total_size , buffer , read_size);
		total_size += read_size;
	}
	printf("Done");
	fflush(stdout);

	*response = (char *)realloc(*response , total_size + 1);
	*(*response + total_size) = '\0';

#if defined(_WIN32)
	closesocket(sock);
#else
	close(sock);
#endif
	return 0;
}

void iputils::ip_ntop(in_addr sin_addr , char *ip_address)
{
    //inet_ntoa is deprecated!! and most importantly it returns static char pointers which is not threadsafe
#if defined(__UNIX__)
    inet_ntop(AF_INET, &(sin_addr), ip_address , 32);
#elif defined(__WXMSW__)
    strcpy(ip_address , inet_ntoa(sin_addr));
#endif

}
