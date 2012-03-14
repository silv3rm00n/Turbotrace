#include "../include/reverse_dns.h"
#include "../iputils.h"

extern const wxEventType update_node_event;

reverse_dns::reverse_dns(tcptraceFrame *parent)
{
    parent_frame = parent;
}

void reverse_dns::set_ip(wxString ip , int nu)
{
    ip_address = ip;
    n = nu;
}

wxThread::ExitCode reverse_dns::Entry()
{
    char hostname[100];
    char whois_data[65536];
    char *ip = strdup((char*)ip_address.ToAscii().data());
    whois_analysis who;

    if(iputils::check_private_ip(ip))
    {
        strcpy(hostname , "Private Network");
    }
    else
    {
        //get hostname
        iputils::ip_to_hostname(ip , hostname);

        //get whois data
        iputils::get_ip_whois(ip , whois_data);

        wxString whois_data2 = whois_data;
        //analyse also man

        who = utils::analyse_whois(whois_data2);
    }

    //wxString cc = utils::get_url( wxT("http://api.wipmania.com/") + ip_address);

    //if(strcmp(hostname , ip))
    {
        node *new_node =  new node;

        new_node->node_number = n;
        new_node->host_name = wxString(hostname , wxConvUTF8 );
        new_node->ip_address = ip_address;
        new_node->type = 2;
        new_node->whois_data = whois_data;
        new_node->who = who;

        //Now send an event
        wxCommandEvent evt( update_node_event );
        evt.SetClientData((void*) new_node);
        ::wxPostEvent(parent_frame , evt);
    }

    free(ip);

    return (wxThread::ExitCode)0;
}
