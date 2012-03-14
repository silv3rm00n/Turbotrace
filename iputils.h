#if defined(_WIN32)
	#include "include/arch/win/win.h"
#endif

#include<wx/wx.h>

#include<string.h>
#include<stdlib.h> //u_char

#if defined(__UNIX__)
	#include<netdb.h>	//hostent
	#include<arpa/inet.h>	//inet_ntoa and ntohs etc
	#include<unistd.h>
	#include<netinet/tcp.h>	//Provides declarations for tcp header

//header files for windows
#elif defined(__WXMSW__)

    #include<winsock2.h>    //winsock functionality
    #include<Ws2tcpip.h>	//inet_ntop

	#include "include/arch/win/tcp.h"

//unknown platoform
#else
    #error "Unknown Platform"
#endif

class iputils
{
    public:

    //Checksum calculator for IP and TCP headers
    static unsigned short csum(unsigned short *, int);

    //Convert hostname into IP address
    static char* hostname_to_ip(char *);

    //Get the local ip for use as source ip in IP header
    static void get_local_ip ( char *);

    //Convert IP into a hostname
    static char* ip_to_hostname(char * , char *);

    //Check if ip is in private range
    static bool check_private_ip(char *);

    static bool get_ip_whois(char * , char *);

    static int whois_query(char *, char * , char **);

    static void get_whois(char * , char **);

    static void ip_ntop(in_addr , char *);
};

struct pseudo_header    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};
