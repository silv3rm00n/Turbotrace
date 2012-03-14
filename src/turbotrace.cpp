#include "../turbotrace.h"

/**
    @brief
    Constructor

    @details
    Initialiase some values
*/
turbotrace::turbotrace(tcptraceFrame *p):wxThreadHelper()
{
    ip_id = 50000;
    initial_port = 40000;
    initial_seq = 1105024978;

    node_count = 0;

	this->parent_frame = p;

	//get the source ip
	iputils::get_local_ip( source_ip );
	log( wxT("Local IP address : ") + wxString(source_ip , wxConvUTF8));


#if defined(_WIN32)
	//Select a winpcap adapter intelligently
	if(!select_pcap_adapter())
	{

	}
#endif
}
/**
    @brief
    Sets the interprocess communication socket. Used only on Linux
*/
void turbotrace::set_comm_sock(int s)
{
    comm_sock = s;
}

#if defined(__WXMSW__)
/**
    @brief
    Packet processing function for libpcap/winpcap

	@details
	Currently used only on windows+winpcap
*/
void process_packet2(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	turbotrace *t = (turbotrace *)args;
	int size = header->len;
	t->process_packet((unsigned char*)buffer , size);
}
#endif

/**
    @brief
    Log messages
*/
void turbotrace::log(wxString msg)
{
    tlog(msg);
}

void turbotrace::tlog(wxString msg)
{
    wxString *p = new wxString();
    *p = msg;

    wxCommandEvent evt( update_log ); // Still keeping it simple, don't give a specific event ID
    evt.SetClientData((void*) p);
    ::wxPostEvent(parent_frame , evt); // This posts to ourselves: it'll be caught and sent to a different method
}

/**
    @brief
    Trace a domain
*/
bool turbotrace::trace( wxString h )
{
    //No hostname specified
	if( !h.Trim().size() )
	{
		::wxMessageBox(wxT("Hostname not specified") , wxT("Error"));
		log(_("Please specify a hostname"));
		return false;
	}

    //Store the host as wxString
    host = h.Trim();

	//things to set on every trace
	sniff_more = 1;

	//set the ack done to 0
    ack_done = false;

    //Start the sniffer thread
    start_sniffer_thread();

    return true;
}

/**
    @brief
    Function Resolve the hostname to ip
*/
bool turbotrace::resolve_host(wxString host)
{
    //Get hostname as a char pointer
    char *target = strdup( (char*) host.ToAscii().data());

    log( _("Will now resolve : ") + wxString(target , wxConvUTF8) );

    //Is it just a simple IP
	if( inet_addr( target ) != INADDR_NONE)
	{
		dest_ip.s_addr = inet_addr( target );
		tlog(_("Valid IP provided"));
	}
	//Domain name , resolve it
	else
	{
		char *ip = iputils::hostname_to_ip( (char*) target );

		if(ip != NULL)
		{
			tlog( wxString(target , wxConvUTF8) + _(" resolved to ") + wxString(ip , wxConvUTF8));

			//Convert domain name to IP
			dest_ip.s_addr = inet_addr( ip );
		}
		else
		{
			tlog( _("Unable to resolve hostname : ") + wxString(target , wxConvUTF8) );
			return false;
		}
	}
	return true;
}

/**
    @brief
    Function to send the syn packets

    @details
    Make sure syn packets are send only when sniffer is MOST READY , either the loop should begin immediately after the syn
    packets are released. Otherwise due to thread races , syn packets might go out even before the sniffer is ready , and response packets would
    be lost
*/
bool turbotrace::send_syn()
{
    //Now prepare to send syn packets
    int i;

	//Create a raw socket
	int s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);

    if(s < 0)
	{
		log( _("Error creating socket") );
		return false;
	}

    //Datagram to represent the packet
	char datagram[4096];

	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;

	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));

	struct sockaddr_in  dest;
	struct pseudo_header psh;

	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr;

	//First node is source ip :D

    //Send event to parent frame to update gui
    node *new_node =  new node;
    new_node->node_number = 0;

    new_node->ip_address = wxString(source_ip , wxConvUTF8 );
    new_node->ttl = 0;
    new_node->type = 1;

    wxCommandEvent evt( update_node_event ); // Still keeping it simple, don't give a specific event ID
    evt.SetClientData((void*) new_node);
    ::wxPostEvent(parent_frame , evt); // This posts to ourselves: it'll be caught and sent to a different method

	memset (datagram, 0, 4096);	/* zero out the buffer */

	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;

	//Total length in bytes
	iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr));
	iph->frag_off = htons(16384);
	iph->protocol = IPPROTO_TCP;
	iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph->daddr = dest_ip.s_addr;

	//TCP Header
	tcph->dest = htons (80);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;		//Size of tcp header
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons ( 0 );	// maximum allowed window size
	tcph->urg_ptr = 0;

	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;

    //Use IP_HDRINCL on unix/linux , as they have raw socket support
#if defined(__UNIX__)
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		log( wxString::Format(wxT("Error setting IP_HDRINCL. Error number : %d. Error Message") , errno ) + wxString(strerror(errno) , wxConvUTF8) );
        return false;
	}
#endif

	log( _("Starting to send syn packets\n") );

    /*
		Increment the IP header ID , TCP sequence
		Keep constant the TCP source port
	*/
    for(i = 1 ; i < 30 ; i++)
	{
		//Set ttl of ip packet
		iph->ttl = i;
		iph->id = htons (ip_id + i);	//Id of this packet
		iph->check = 0;
		iph->check = iputils::csum ((unsigned short *) datagram, sizeof (struct iphdr) );

		tcph->source = htons ( initial_port  );
		tcph->check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
		tcph->seq = htonl( initial_seq + i );

		psh.source_address = inet_addr( source_ip );
		psh.dest_address = dest.sin_addr.s_addr;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons( sizeof(struct tcphdr) );

		memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

		tcph->check = iputils::csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

#if defined(__UNIX__)
		//Send the packet
		if ( sendto (s, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
		{
			log( wxString::Format( wxT("sendto failed. Error number : %d. Error Message") , errno ) + wxString(strerror(errno) , wxConvUTF8) );
            return false;
		}

#elif defined(__WXMSW__)
		if(!send_packet_pcap(datagram , sizeof(struct iphdr) + sizeof(struct tcphdr)))
		{
			log(wxT("pcap_sendpacket failed"));
		}
#endif

        time_send[ i ] = wxGetUTCTimeUSec(); //wxGetLocalTimeMillis();

	}

    //How about sending ICMP packets now :D
    struct icmphdr *icmph = (struct icmphdr *) (datagram + sizeof (struct iphdr));

    iph->protocol = IPPROTO_ICMP;
	iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct icmphdr));

    icmph->type = 8;
    icmph->code = 0;

    for(i = 1 ; i < 30 ; i++)
	{
		//Set ttl of ip packet
		iph->ttl = i;
		iph->id = htons (ip_id + i);	//Id of this packet
		//checksum
		iph->check = 0;
		iph->check = iputils::csum ((unsigned short *) datagram, sizeof (struct iphdr) );

        //icmp header checksum
		icmph->un.echo.id = htons (ip_id + i);	//Id of this packet
		icmph->checksum = 0;
        icmph->checksum = iputils::csum ((unsigned short *) icmph , sizeof(struct icmphdr) );

#if defined(__UNIX__)
		//Send the packet
		if ( sendto (s, datagram , sizeof(struct iphdr) + sizeof(struct icmphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
		{
			log( wxString::Format( wxT("sendto failed. Error number : %d. Error Message") , errno ) + wxString(strerror(errno) , wxConvUTF8) );
            return false;
		}
#elif defined(__WXMSW__)
		if(!send_packet_pcap(datagram , sizeof(struct iphdr) + sizeof(struct icmphdr)))
		{
			log(wxT("pcap_sendpacket failed"));
		}
#endif
	}

	/*
        Close the socket man
        if we dont close , and do start-stop very fast , sendto might fail
    */
#if defined(__UNIX__)
	close(s);
#elif defined(__WXMSW__)
	closesocket(s);
#endif

	return true;
}

#if defined(__WXMSW__)

/**
    @brief
    Send packets using winpcap packet library on windows
*/
bool turbotrace::send_packet_pcap(char *buffer , int size)
{
	//packet to be transmitted
	char packet[4096];

	//source and destination mac address please!
	static u_char s_mac[6],d_mac[6];
	in_addr srcip , destip;

	static int eth_ready = 0;
	struct ethhdr *ehdr;

	char sgatewayip[16] , errbuf[PCAP_ERRBUF_SIZE+1];
	int gatewayip;

	if(!eth_ready)
	{
		srcip.s_addr = inet_addr(source_ip);

		log(wxT("Selected device has ip : ") + wxString(inet_ntoa(srcip) , wxConvUTF8) );

		utils::get_mac_from_ip(s_mac , srcip);
		log(wxString::Format("Selected device has mac address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",s_mac[0],s_mac[1],s_mac[2],s_mac[3],s_mac[4],s_mac[5]));

		//Get the gateway ip - destination
		utils::get_gateway(srcip , sgatewayip , &gatewayip);
		log(wxT("Selected device has gateway : ") + wxString (sgatewayip , wxConvUTF8) );
		destip.s_addr = gatewayip;

		//get the gateway mac - destination
		utils::get_mac_from_ip(d_mac , destip);
		log(wxString::Format("Gateway Mac : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X " , d_mac[0],d_mac[1],d_mac[2],d_mac[3],d_mac[4],d_mac[5]));

		if ( (adapter = pcap_open( adapter_info.name , 100 , PCAP_OPENFLAG_PROMISCUOUS , 1000 , NULL , errbuf) ) == NULL)
		{
			log("Unable to open adapter");
			return false;
		}
		log(wxT("Opened interface for sending packets : ") + wxString(adapter_info.name , wxConvUTF8));

		eth_ready = 1;
	}

	//construct the ethernet header
	ehdr = (struct ethhdr*) packet;

	memcpy(ehdr->h_source , s_mac , 6);	//Source Mac address
	memcpy(ehdr->h_dest , d_mac , 6);	//Destination MAC address
	ehdr->h_proto = 8; //IP Frames

	memcpy( packet + sizeof(ethhdr) , buffer , size );

	int send = pcap_sendpacket( adapter , (u_char*)packet , sizeof(ethhdr) + size );

	//send the packet via the winpcap function , zoooooooooom
	if( send == -1)
	{
		log( pcap_geterr( adapter ) );
		return false;
	}

	return true;
}

/**
	@brief
	Select the winpcap adapter to sniff and send packets over :D

	@details
	It does the selection by matching the source ip with each adapters ip
	This function still needs improvement
*/
bool turbotrace::select_pcap_adapter()
{
	pcap_if_t *alldevs , *d;
	char errbuf[PCAP_ERRBUF_SIZE+1];
	pcap_addr_t *a;
	int selected = 0;

	/* The user didn't provide a packet source: Retrieve the local device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		log( wxT("Error in pcap_findalldevs_ex: \n") +  wxString(errbuf , wxConvUTF8) );
		return false;
	}

	//Jump to required device/adapter
	for (d = alldevs ; d ;d = d->next)
	{
		//First address
		a = d->addresses;

		//Compare the ip address of the adapter and system source ip
		if( ((struct sockaddr_in *)a->addr)->sin_addr.s_addr = inet_addr(source_ip))
		{
			adapter_info = *d;
			log("Selected device : " + wxString(d->name , wxConvUTF8));
			selected = 1;
		}
	}

	//free the list , this will crash the application
	//pcap_freealldevs(alldevs);

	if(selected)
	{
		return true;
	}

	log("No pcap device selected");
	return false;

}
#endif

/**
    @brief
    Setup the sniffer thread
*/
int turbotrace::start_sniffer_thread()
{
    log( _("Starting sniffer thread...\n") );

    if ( CreateThread(wxTHREAD_JOINABLE) != wxTHREAD_NO_ERROR)
    {
        wxLogError("Could not create the worker thread!");
        return 1;
    }

    wxThread *a = GetThread();
    if(a != NULL)
    {
        //a->SetPriority(WXTHREAD_MAX_PRIORITY );
        if (a->Run() != wxTHREAD_NO_ERROR)
        {
            log( _("Could not run the worker thread!") );
            return 1;
        }
    }

    return 0;
}

void turbotrace::shutdown()
{
	log("Shutting Down ...");

	//Wait for thread to complete :D
    if(GetThread())
    {
        if(GetThread()->IsRunning())
		{
#if defined(__WXMSW__)
			//Stop the winpcap sniffer
			pcap_breakloop(adapter);
#endif
			//Call delete on the thread
			//GetThread()->Delete();
			GetThread()->Wait();
		}
    }

	log("Done");
}

wxThread::ExitCode turbotrace::Entry()
{
    tlog(_("Thread starting\n"));

    //Resolve the hostname , get the ip address
    if(!resolve_host(host))
    {
        return false;
    }

    wxMutexGuiEnter();
    parent_frame->set_ip( wxString( inet_ntoa(dest_ip) , wxConvUTF8) );
    wxMutexGuiLeave();

    //Call the outer class function start_sniffer
    start_sniffer();

    return (wxThread::ExitCode)0;
}

#if defined(__UNIX__)
/**
    @brief
    This will sniff incoming packets and send them to processor
*/
bool turbotrace::start_sniffer()
{
	int sock_raw;

	int saddr_size , data_size;
	struct sockaddr saddr;

	unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!

	tlog( _("Sniffer initialising...\n") );

    //Create a raw socket that shall sniff all packets
	sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;

	if(sock_raw < 0)
	{
		tlog( _("Socket Error\n") );
		return false;
	}

	saddr_size = sizeof saddr;

    sniffer_ready = true;

    //set of socket descriptors
    fd_set readfds;

    int activity;
    int k = sock_raw > comm_sock ? sock_raw : comm_sock;

    /*
        It is important to send syn packets here to ensure , they are being send when sniffer is most ready
        Because if due to thread races , the syn packets are released before sniffer is ready then icmp replies would be lost ,
        resulting into incorrect output.
    */
    if( !send_syn() )
    {
        return false;
    }

	while( ! GetThread()->TestDestroy() )
	{

		//clear the socket set
        FD_ZERO(&readfds);

        //add master socket to set
        FD_SET(sock_raw , &readfds);
        FD_SET(comm_sock , &readfds);

        //wait for an activity on one of the sockets , timeout is NULL , so wait indefinitely
        activity = select( k + 1 , &readfds , NULL , NULL , NULL);

        if ((activity < 0) && (errno!=EINTR))
        {
            tlog(_("select error\n"));
            break;
        }

        //If something happened on the master socket , then its an incoming connection
        if (FD_ISSET(sock_raw , &readfds))
        {
            //Receive a packet
            data_size = recvfrom(sock_raw ,(char*) buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size );
            if(data_size < 0 )
            {
                tlog(_("Recvfrom error , failed to get packets\n"));
                break;
            }
            //Now process the packet
            process_packet(buffer , data_size);
        }

        //Something happened on communication socket , a TERMINATE signal ?
        if (FD_ISSET(comm_sock , &readfds))
        {
            if(read(comm_sock , buffer , 1024) > 0)
            {
                tlog(_("Terminate signal. \n") + wxString(buffer , wxConvUTF8));
                break;
            }
        }
	}

	close(sock_raw);

	free(buffer);

	tlog(_("Sniffer finished. \n"));

	return true;
}

#elif defined(__WXMSW__)
/**
    @brief
    This will sniff incoming packets for an ICMP ECHO reply
    libpcap version
*/
bool turbotrace::start_sniffer()
{
	log("Sniffer initialising...\n");

    char errbuf[1000];
	//Open the device
    adapter = pcap_open(adapter_info.name , 65536 , PCAP_OPENFLAG_PROMISCUOUS , 20 , NULL ,errbuf);

    if (adapter == NULL)
	{
		log(_("pcap_open_live failed") + wxString(errbuf , wxConvUTF8));
		return false;
	}

	log(_("pcap_open successful"));

    sniffer_ready = true;

	//Send the syn packets
    send_syn();

    //Put the device in sniff loop
	pcap_loop(adapter , -1 , process_packet2 , (u_char*)this);

	return true;
}
#endif //WXMSW

/**
    @brief
    Analyse the captured packets and see if any replies came or not
*/
void turbotrace::process_packet(unsigned char* buffer, int size)
{
	//Jump the buffer to IP header straight away
	buffer = (buffer + sizeof(struct ethhdr));

	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr*)buffer;
	struct sockaddr_in source,dest;
	unsigned short iphdrlen;

	struct iphdr *old_iph;
	struct tcphdr *old_tcph;

    char ip_address[32];

    int ttl;


    wxLongLong t_reply = wxGetUTCTimeUSec(); //wxGetLocalTimeMillis();

	//ICMP replies , type == 11 , code 0 , TTL expired
	if(iph->protocol == IPPROTO_ICMP)
	{
		//struct iphdr *iph = (struct iphdr *)buffer;
		iphdrlen = iph->ihl*4;

		struct icmphdr *icmph = (struct icmphdr*)(buffer + iphdrlen);

		old_iph = (struct iphdr*)(buffer + iphdrlen + sizeof (struct icmphdr));
		old_tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof (struct icmphdr) + old_iph->ihl*4);

		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;

		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->daddr;


        //ICMP TTL EXPIRED
		if(icmph->type == 11 && icmph->code == 0)
		{
		    //Reply is a reply to a TCP packet
		    if(old_iph->protocol == IPPROTO_TCP)
		    {
                //CHECK PACKET credentials :D
                if( dest.sin_addr.s_addr == inet_addr(source_ip) && ntohl(old_tcph->seq) >= initial_seq && source.sin_addr.s_addr != dest_ip.s_addr)
                {
                    ttl = (ntohs(old_iph->id) - ip_id);

                    iputils::ip_ntop(source.sin_addr , ip_address);
					strcpy(nodes[ ttl ] , ip_address);
                    node_count = (ttl > node_count) ? ttl : node_count;

                    //Send event to parent frame to update gui
                    node *p =  new node;
                    p->node_number = ttl;

                    p->ip_address = ip_address;
                    p->ttl = ttl;

                    p->type = 1;
                    p->tcp_reply = true;

                    p->response_time = (t_reply - time_send[ttl]).ToDouble() / 1000;

                    tlog( wxString::Format( wxT("TCP Reply TTL : %d , IP : %s , Time : %.2f") , ttl , ip_address , p->response_time ));

                    inform_parent(p);
                }
		    }

		    //Reply is a reply to a ICMP , and is a TTL expired reply
		    if(old_iph->protocol == IPPROTO_ICMP)
		    {
				//CHECK PACKET credentials :D
                if( dest.sin_addr.s_addr == inet_addr(source_ip) && ntohl(old_iph->id) >= ip_id && source.sin_addr.s_addr != dest_ip.s_addr)
                {
                    //Get ip header id difference to evaluate the TTL
                    int node_number = (ntohs(old_iph->id) - ip_id);


                    iputils::ip_ntop(source.sin_addr , ip_address);
                    strcpy(nodes[node_number] , ip_address);

                    node_count = (node_number > node_count) ? node_number : node_count;

                    //Send event to parent frame to update gui
                    node *p =  new node;
                    p->node_number = node_number;

                    p->ip_address = ip_address;

                    p->type = 1;
                    p->icmp_reply = true;
                    p->ttl = node_number;


                    p->response_time = (t_reply - time_send[node_number]).ToDouble() / 1000;

                    tlog( wxString::Format( wxT("ICMP Reply TTL : %d , IP : %s , Time : %.2f") , node_number , ip_address , p->response_time ));

                    inform_parent(p);
                }
		    }
		}

        /*
            ICMP Ping ECHO Reply
			This comes from the final node who replies to ping requests
        */
        else if(icmph->type == 0 && icmph->code == 0)
        {
            //CHECK PACKET credentials :D
            if( dest.sin_addr.s_addr == inet_addr(source_ip) && ntohl(old_iph->id) >= ip_id && source.sin_addr.s_addr != dest_ip.s_addr)
            {
                //Get ip header id difference to evaluate the TTL
                int node_number = (ntohs(old_iph->id) - ip_id);


				iputils::ip_ntop(source.sin_addr , ip_address);
				strcpy(nodes[node_number] , ip_address);
				node_count = (node_number > node_count) ? node_number : node_count;

                //What is wrong with this ?
                tlog( wxString::Format( wxT("ICMP Reply TTL : %d , IP : ") , node_number) + wxString(ip_address , wxConvUTF8 ) );

                //Send event to parent frame to update gui
                node *p =  new node;
                p->node_number = node_number;
				p->ip_address = ip_address;
                p->type = 1;
                p->icmp_reply = true;

                inform_parent(p);
            }
        }
	}

    /*
        The final node will reply with syn + ack on port 80
        what if not port 80 ?
    */
	else if(iph->protocol == IPPROTO_TCP && !ack_done )
	{
		//struct iphdr *iph = (struct iphdr *)buffer;
		iphdrlen = iph->ihl*4;

		struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);

		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;

		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->daddr;

        /*
            Theory :
            If port open then syn would be set , if port closed then rst would be set
        */
		if( (tcph->syn == 1 || tcph->rst == 1) && tcph->ack == 1 && source.sin_addr.s_addr == dest_ip.s_addr )
		{
			//ack - 1 = the seq it replied to , that minus initial seq will tell the packet number
			int pos = (ntohl(tcph->ack_seq) - 1) - initial_seq;


			iputils::ip_ntop(source.sin_addr , ip_address);

			strcpy( nodes[ pos ] , ip_address );
			if(pos > node_count)
			{
				node_count = pos;
			}

			//Send event to parent frame to update gui
            node *new_node =  new node;
            new_node->node_number = pos;

            new_node->ip_address = nodes[pos];

            new_node->type = 1;
            new_node->tcp_reply = true;

            new_node->response_time = (t_reply - time_send[pos]).ToDouble() / 1000;

            inform_parent(new_node);

            tlog( wxString::Format(wxT("TCP Reply TTL : %d with ack ") , pos )  + wxString(nodes[pos] , wxConvUTF8));

			//We have received 1 ack TCP packet , dont want anymore
			ack_done = true;
		}
	}
}

/**
    @brief
    Sends the parent frame a new node object which has fresh details of a reply
*/
void turbotrace::inform_parent(node *new_node)
{
    wxCommandEvent evt( update_node_event ); // Still keeping it simple, don't give a specific event ID
    evt.SetClientData((void*) new_node);
    ::wxPostEvent(parent_frame , evt); // This posts to ourselves: it'll be caught and sent to a different method
}
