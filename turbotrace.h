#ifndef TURBOTRACE_H
#define TURBOTRACE_H

//header files for windows
#if defined(_WIN32)
	#include "include/arch/win/win.h"
#endif

//wxwidgets
#include <wx/wx.h>
#include <wx/event.h>

//header includes for Linux system
#if defined(__UNIX__)

    #include<stdio.h> //printf
    #include<string.h> //memset
    #include<stdlib.h> //for exit(0);
    #include<sys/socket.h> //you know what is this for
    #include<errno.h> //For errno - the error number
    //#include<pthread.h> //for threading , link with lpthread
    #include<netdb.h>	//hostent
    #include<arpa/inet.h>	//inet_ntoa and ntohs etc
    #include<netinet/tcp.h>	//Provides declarations for tcp header
    #include<netinet/ip_icmp.h>	//Provides declarations for icmp header
    #include<netinet/ip.h>	//Provides declarations for ip header
    #include<netinet/if_ether.h>	//For ETH_P_ALL
    #include<net/ethernet.h>	//For ether_header
    //#include<unistd.h>	//For sleep

//header files for windows
#elif defined(__WXMSW__)

	#define strdup _strdup
	#define close _close

	#include<winsock2.h>

	#define HAVE_REMOTE
	#include "pcap.h"	//Winpcap :)

	#pragma comment(lib , "ws2_32.lib") //For winsock
	#pragma comment(lib , "wpcap.lib") //For winpcap

    #include "include/arch/win/ethernet.h"
	#include "include/arch/win/ip.h"
	#include "include/arch/win/tcp.h"
	#include "include/arch/win/icmp.h"

//unknown platoform
#else
    #error "Unknown Platform"

#endif

#include "iputils.h"
#include "tcptraceMain.h"

class turbotrace : public wxThreadHelper
{
    public :
        turbotrace(tcptraceFrame *);


        bool trace(wxString host);
        void stop_sniffer();
        void set_log_function( void (*functocall)(wxString) );

        void shutdown();

        void process_packet(unsigned char*, int);

        void set_comm_sock(int s);

    private :
        void inform_parent(node *);

//Winpcap variables for windows
#if defined(__WXMSW__)
        bool send_packet_pcap(char *, int);
        //winpcap device to sniff
        pcap_t *adapter;
        pcap_if_t adapter_info;
        bool select_pcap_adapter();
#endif

        //unsigned char s_mac[6],d_mac[6];

        int comm_sock;

        wxString thread_message;
        void log(wxString msg);
        void tlog(wxString msg);

        bool send_syn();
        bool resolve_host(wxString);
        int start_sniffer_thread();
        bool start_sniffer();
        int sniff_more;
        bool sniffer_ready;
        int sniffer_socket;

        void sniff_packet(unsigned char *);

        char source_ip[20];
        wxString host;
        struct in_addr dest_ip;

        int initial_seq;
        int ip_id;
        int initial_port;
        bool ack_done;
        //Upto 100 network nodes
        char nodes[100][32];
        //Current node count - number of nodes discovered
        int node_count;

        //response time of each node , ttl indexed
        int response_times[100];
        //struct timeval time_send[100] , time_reply[100];
        wxLongLong time_send[100];

        tcptraceFrame *parent_frame;

    protected:
        virtual wxThread::ExitCode Entry();
};

#endif
