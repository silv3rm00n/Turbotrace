/***************************************************************
 * Name:      tcptraceMain.h
 * Purpose:   Defines Application Frame
 * Author:    Silver Moon (m00n.silv3r@gmail.com)
 * Created:   2011-12-26
 * Copyright: Silver Moon (http://www.binarytides.com/blog/)
 * License:
 **************************************************************/

#ifndef TCPTRACEMAIN_H
#define TCPTRACEMAIN_H

//header files for windows
#if defined(_WIN32)
	#include "include/arch/win/win.h"
#endif

#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include<wx/listctrl.h>
#include<wx/stdpaths.h>
#include<wx/html/htmlpars.h>
#include<wx/notebook.h>
#include<wx/webview.h>
#include<wx/filedlg.h>
#include<wx/wfstream.h>
#include<wx/textfile.h>

#include "tcptraceApp.h"
#include "include/reverse_dns.h"
#include "include/logger.h"
#include "include/about_box.h"
#include "include/utils.h"
#include "include/info_box.h"

//header files for windows
#if defined(__WXMSW__)
	#define write _write

	#define strdup _strdup
	#define close _close

	#include<winsock2.h>

	#define HAVE_REMOTE
	#include "pcap.h"	//Winpcap :)

	#pragma comment(lib , "ws2_32.lib") //For winsock
	#pragma comment(lib , "wpcap.lib") //For winpcap

	#include "include/arch/win/raw.h"
#endif

extern const wxEventType update_node_event;
extern const wxEventType update_log;

//Forward declaration trick
class turbotrace;

#define MAX_HOPS 30

struct node
{
    //Position number of this node , same as ttl
    int node_number;

    //Ip address of this node
    wxString ip_address;
    wxString host_name;

    //The TTL of this Node
    unsigned int ttl;

    int type;

    double response_time;

    /*
        Optional , may not be filled
    */
    //Does this node reply to ICMP echo messages
    bool icmp_reply;
    bool tcp_reply;

    iplocation loc;

    /*
        The ip address which is used to get the location of this particular ip
        For example LAN ip 192.168.0.1 should have same ip as that of public ip
        etc.
    */
    wxString location_ip;

    //Indicates if the location if found or not
    bool location_found;

    wxString whois_data;
    //wxString isp;
    //wxString ip_range;
    whois_analysis who;
};

class tcptraceFrame : public wxFrame
{
    public:
        tcptraceFrame(wxFrame *frame, const wxString& title);

        void log(wxString);

        int update_results(char * , int );
        void set_ip(wxString ip);

        bool set_hostname(char *, int );

        bool set_node_property(int , int , char *);

        logger *log_window;

    private:

        wxString public_ip;
        wxTextCtrl *txt_host , *txt_ip , *txt_log;
        wxListCtrl *result;
        wxButton  *btn_trace;
        turbotrace *t;

        wxWebView* m_browser;

        int comm_socks[2];

        node trace_nodes[MAX_HOPS];

        void init_ui();

        //Handler for close option in Menu
        void OnClose(wxCloseEvent&);

        //Handler for Quit option in Menu
        void OnQuit(wxCommandEvent&);

        //Handler for About option in Menu
        void OnAbout(wxCommandEvent&);

        //Handler for About option in Menu
        void on_trace(wxCommandEvent&);

        //Handler for About option in Menu
        void stop_trace(wxKeyEvent&);

        void _stop_trace();

        void check_root();

        void update_node_data(wxCommandEvent &);
        void update_log_data(wxCommandEvent &);
        void on_save(wxCommandEvent &);

        void plot_node(node n);

        void clear_map();

        void revise_locations();

        void on_node_dblclick(wxListEvent& );
        void list_menu(wxListEvent &);

        void list_menu_info(wxCommandEvent &);
        void list_menu_whois(wxCommandEvent &);

        void show_info_box(node);
        void show_whois_box(node n);
};


#endif // TCPTRACEMAIN_H
