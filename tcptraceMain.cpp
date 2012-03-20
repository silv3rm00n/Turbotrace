/***************************************************************
 * Name:      tcptraceMain.cpp
 * Purpose:   Code for Application Frame
 * Author:    Silver Moon (m00n.silv3r@gmail.com)
 * Created:   2011-12-26
 * Copyright: Silver Moon (http://www.binarytides.com/blog/)
 * License:
 **************************************************************/

#ifdef WX_PRECOMP
#include "wx_pch.h"
#endif

#ifdef __BORLANDC__
#pragma hdrstop
#endif //__BORLANDC__

#include "tcptraceMain.h"
#include "turbotrace.h"

const wxEventType update_node_event = wxNewEventType(); // You get to choose the name yourself
const wxEventType update_log = wxNewEventType(); // You get to choose the name yourself

/**
    @details
    Constructor for the Frame , does a couple of things
    Create menu , statusbar etc
*/
tcptraceFrame::tcptraceFrame(wxFrame *frame, const wxString& title) : wxFrame(frame, -1, title , wxDefaultPosition , wxSize(800 , 600))
{
	t = NULL;

#if defined(__UNIX__)
	//Check if we are root
    check_root();
#endif

	//Initialise the User Interface
    init_ui();

	//Communication socket
#if defined(__UNIX__)
    if(socketpair(AF_UNIX , SOCK_STREAM, 0, comm_socks) == -1)
    {
        exit(0);
    }
#endif

    //Get the public ip
    public_ip = utils::get_url("http://www.icanhazip.com/");
    log(wxT("Public IP is : ") + public_ip);

    log(wxStandardPaths::Get().GetExecutablePath());
    log(wxFileName(wxStandardPaths::Get().GetExecutablePath()).GetPath());
}

#if defined(__UNIX__)
/**
    @brief
    Method to check if the user has superuser/root privileges on the system. For Linux/Unix

    @details
    Checks root privileges by creating a raw socket :D
    If root privileges available then raw socket would be created , otherwise not. Simple!!
*/
void tcptraceFrame::check_root()
{
    //Create a raw socket
	int s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);

    //Not root , then relaunch with root gksudo
    if(s < 0)
	{
        //wxExecute does not work with sudo , and with gksudo it asks for password everytime :D
        wxString a = wxT("gksudo ") + wxStandardPaths::Get().GetExecutablePath();
        ::wxExecute(a);

        //stop current instance
        exit(0);
	}
}
#endif

void tcptraceFrame::init_ui()
{
    #if wxUSE_MENUS
    // create a menu bar
    wxMenuBar* mbar = new wxMenuBar();

    //First file menu
    wxMenu* menu = new wxMenu( _T("") );
    //Add items to file menu
    wxMenuItem *mi = new wxMenuItem( menu , ::wxNewId() , _("&Quit\tAlt-F4") , _("Quit the application"));
    menu->Append(mi);
    this->Connect( mi->GetId() , wxEVT_COMMAND_MENU_SELECTED , (wxObjectEventFunction) &tcptraceFrame::OnQuit );
    //ADd the File menu to menubar
    mbar->Append(menu, _("&File"));

    //Now the Help Menu
    menu = new wxMenu(_T(""));
    //About option in Help Menu
    mi = new wxMenuItem(menu , ::wxNewId() , _("&About\tF1") , _("Show info about this application") );
    menu->Append(mi);
    this->Connect( mi->GetId() , wxEVT_COMMAND_MENU_SELECTED , (wxObjectEventFunction) &tcptraceFrame::OnAbout );
    //Add to menubar
    mbar->Append(menu , _("&Help"));

    //Set the main menu bar
    SetMenuBar(mbar);
    #endif // wxUSE_MENUS

    #if wxUSE_STATUSBAR
    // create a status bar with some information about the used wxWidgets version
    CreateStatusBar(2);
    SetStatusText( _("Tcp Traceroute version 1.0") , 0 );
    //SetStatusText( wxbuildinfo(short_f), 1);
    #endif // wxUSE_STATUSBAR

    wxNotebook *nb = new wxNotebook(this  , -1);

    //Now create panel
    wxPanel *panel = new wxPanel( nb , ::wxNewId() );
    wxFlexGridSizer *fgs = new wxFlexGridSizer( 3 , 2 , 9 , 25 );

    //Create some static text controls
    wxStaticText *server = new wxStaticText(panel , -1 , _("Enter Hostname/IP"));

    //Create some text boxes and buttons , remember they all belong to the panel
    txt_host = new wxTextCtrl(panel, -1 , wxT("") , wxDefaultPosition , wxDefaultSize , wxTE_PROCESS_ENTER);
    txt_host->SetToolTip(_("Enter the domain/host name or an IPv4 address"));

    //Handler enter button for the text control
    Connect( txt_host->GetId() , wxEVT_COMMAND_TEXT_ENTER , (wxObjectEventFunction) &tcptraceFrame::on_trace);

    //Create some text boxes and buttons , remember they all belong to the panel

    txt_ip = new wxTextCtrl(panel, -1 , wxT(""), wxDefaultPosition , wxSize(150,-1));
    txt_ip->Disable();

    btn_trace = new wxButton(panel ,  20 , _("Trace"));

    //Event handler call connect on this
    Connect( btn_trace->GetId() , wxEVT_COMMAND_BUTTON_CLICKED , (wxObjectEventFunction) &tcptraceFrame::on_trace);

    Connect(GetId() , wxEVT_KEY_UP , (wxObjectEventFunction) &tcptraceFrame::stop_trace );

    Connect(wxID_ANY , update_node_event ,  wxCommandEventHandler(tcptraceFrame::update_node_data) );
    Connect(wxID_ANY , update_log ,  wxCommandEventHandler(tcptraceFrame::update_log_data) );

    //Add the input field and submit button to a Box Sizer since the must stay together
    wxBoxSizer *space = new wxBoxSizer(wxHORIZONTAL);

    //Expandable with right border
    space->Add( txt_host , 1 , wxRIGHT , 10 );

    //No resizing
    space->Add( txt_ip , 0 , wxRIGHT , 10 );

    //Non expandable and align to right
    space->Add( btn_trace , 0 , wxALIGN_RIGHT);

    //Add the things to flexgridsizer
    fgs->Add(server);
    fgs->Add(space , 1 , wxEXPAND);

    fgs->Add(new wxStaticText(panel , -1 , _("Results")));

    result = new wxListCtrl(panel , -1 , wxDefaultPosition , wxDefaultSize , wxLC_REPORT | wxBORDER_SIMPLE | wxLC_EDIT_LABELS |wxLC_HRULES | wxLC_VRULES);

    result->InsertColumn(0 , wxT("No.") , wxLIST_FORMAT_LEFT , 30);
    result->InsertColumn(1 , wxT("IP") , wxLIST_FORMAT_LEFT , 150);
    result->InsertColumn(2 , wxT("HostName") , wxLIST_FORMAT_LEFT, 300);
    result->InsertColumn(3 , wxT("Location") , wxLIST_FORMAT_LEFT , 100);
    result->InsertColumn(4 , wxT("ICMP Reply") , wxLIST_FORMAT_LEFT , 100);
    result->InsertColumn(5 , wxT("TCP Reply") , wxLIST_FORMAT_LEFT , 100);
    result->InsertColumn(6 , wxT("ISP") , wxLIST_FORMAT_LEFT , 100);
    result->InsertColumn(7 , wxT("Time") , wxLIST_FORMAT_LEFT , 100);

    Connect(result->GetId() , wxEVT_COMMAND_LIST_ITEM_ACTIVATED , (wxObjectEventFunction) &tcptraceFrame::on_node_dblclick);
    Connect(result->GetId() , wxEVT_COMMAND_LIST_ITEM_RIGHT_CLICK , (wxObjectEventFunction) &tcptraceFrame::list_menu);


    fgs->Add( result , 1 , wxEXPAND );

    fgs->Add( new wxBoxSizer(wxHORIZONTAL) , 1 , wxEXPAND );

    wxButton *btn_export = new wxButton(panel , -1 , _("Export"));
    Connect( btn_export->GetId() , wxEVT_COMMAND_BUTTON_CLICKED , (wxObjectEventFunction) &tcptraceFrame::on_save);

    //Add the input field and submit button to a Box Sizer since the must stay together
    space = new wxBoxSizer(wxHORIZONTAL);

    //Expandable with right border
    space->Add( btn_export , 0 , wxRIGHT , 10 );

    fgs->Add( space , 1 , wxEXPAND );

    //Make growable cols
    fgs->AddGrowableRow(1, 1);
    fgs->AddGrowableCol(1, 1);

    wxBoxSizer *box = new wxBoxSizer(wxHORIZONTAL);
    box->Add(fgs, 1 , wxEXPAND | wxALL , 20);
    panel->SetSizer(box);

    nb->AddPage(panel , wxT("Trace"));

    //Next tab - Visual Plot Tab
    //Now create panel
    panel = new wxPanel( nb , ::wxNewId() );

    //The browser control
    m_browser = wxWebView::New(panel , wxID_ANY);

    //Load the google maps file
    m_browser->LoadURL(wxT("file://") + wxFileName(wxStandardPaths::Get().GetExecutablePath()).GetPath() + wxT("/google_map.html"));

    box = new wxBoxSizer(wxHORIZONTAL);
    box->Add(m_browser , 1 , wxEXPAND | wxALL , 20);

    //if panel is resized , it will resize the box sizer too , which will in turn resize the flexgridsizer
    panel->SetSizer(box);
    nb->AddPage(panel , wxT("Visual Plot"));


    //Next tab - Visual Plot Tab
    //Now create panel
    panel = new wxPanel( nb , ::wxNewId() );

    //The browser control
    txt_log = new wxTextCtrl(panel , -1 , wxT("") , wxDefaultPosition , wxDefaultSize , wxTE_MULTILINE);

    box = new wxBoxSizer(wxHORIZONTAL);
    box->Add(txt_log , 1 , wxEXPAND | wxALL , 20);

    //if panel is resized , it will resize the box sizer too , which will in turn resize the flexgridsizer
    panel->SetSizer(box);
    nb->AddPage(panel , wxT("Log"));

    txt_host->SetFocus();

    //Create a log window
    log_window = new logger(this,wxT("Log Data"));

    #ifdef _DEBUG_MODE_
    //log_window->Show();
    #endif
}

/**
    @brief
    Frame cross button handler
*/
void tcptraceFrame::OnClose(wxCloseEvent &event)
{
    _stop_trace();
    Destroy();
}

/**
    @brief
    File > Quit Handler
*/
void tcptraceFrame::OnQuit(wxCommandEvent &event)
{
    _stop_trace();
    Destroy();
}

/**
    @brief
    Help > About Handler
*/
void tcptraceFrame::OnAbout(wxCommandEvent &event)
{
    //wxString msg = wxbuildinfo(long_f);

    about_box dlg(-1);
    if ( dlg.ShowModal() == wxID_OK )
    {

    }
}

/**
    @brief
    Trace button handler
*/
void tcptraceFrame::on_trace(wxCommandEvent &event)
{
	if(txt_host->IsEnabled())
    {
        //Remove all result listcontrol rows
		result->DeleteAllItems();

        //Create 30 rows
        for(int i = 0; i < MAX_HOPS ; i++)
        {
            result->InsertItem(i , wxT(""));
            result->SetItemBackgroundColour(i, wxColour(252,255,232));
        }

        if( t != NULL )
        {
            log(wxT("Stopping any previous traces"));
            _stop_trace();
        }
        else
        {
            //Create a turbotrace object
            t = new turbotrace(this);

#if defined(__UNIX__)
			t->set_comm_sock(comm_socks[1]);
#endif
        }
        if(txt_host != NULL)
        {
           clear_map();

		   if(t->trace(txt_host->GetValue()))
           {
               txt_host->Disable();
               btn_trace->SetLabel(wxT("Stop Trace"));

               //Need to focus something so that Esc key works on frame
               btn_trace->SetFocus();
           }
           else
           {
               txt_host->SetFocus();
           }
        }
    }
    else
    {
		_stop_trace();
    }
}

/**
    @brief
    Keyevent handler on main frame
*/
void tcptraceFrame::stop_trace(wxKeyEvent &event)
{
    //If escape key has been pressed then stop any running traces
    if(event.GetKeyCode() == WXK_ESCAPE)
    {
        _stop_trace();
    }
}

/**
    @brief
    Event handler for update_node_data
*/
void tcptraceFrame::update_node_data(wxCommandEvent &event)
{
    //Get the data object
    struct node* n = (struct node*)event.GetClientData();
    int i = n->node_number;

    //Take a reference of the original
    node& tn  = trace_nodes[i];

    //Change gui only if thread is running , otherwise passout
    if(t->GetThread()->IsRunning())
    {
        switch(n->type)
        {
            case 1 :
            {
                //First column for host
                result->SetItem(i , 0 , wxString::Format(wxT("%i") , i+1) );
                result->SetItem(i , 1 , n->ip_address );

                tn.ip_address = n->ip_address;
                tn.node_number = i;
                tn.ttl = n->ttl;

                //Mark final node as a different color
                if(txt_ip->GetValue().CmpNoCase( n->ip_address  ) == 0)
                {
                    result->SetItemBackgroundColour(i , wxColour(0,100,0));
                    result->SetItemTextColour(i , wxColour(255,255,255));
                }

                //ICMP reply packet
                if(n->icmp_reply == true)
                {
                    result->SetItem(i , 4 , wxT("Yes"));
                    tn.icmp_reply = true;
                }

                //TCP reply packet
                if(n->tcp_reply == true)
                {
                    result->SetItem(i , 5 , wxT("Yes"));
                    tn.tcp_reply = true;
                }

                //Reply from some server
                if(i > 0)
                {
                    //Start a thread to resolve the hostname , reverse address lookup :D
                    reverse_dns *d = new reverse_dns(this);

                    d->set_ip( n->ip_address , i );
                    d->Create();
                    d->Run();
                }

                //Local machine IP :D
                else
                {
                    //Put data object in GUI
                    result->SetItem(i , 2 , wxT("Local Machine"));
                    result->SetItem(i , 3 , wxT("-") );
                    result->SetItemBackgroundColour(i , wxColour(255,250,205));
                }

                iplocation a;
                wxString b;

                //If ip is a private ip , then get the location of previous ip if there is any
                if(iputils::check_private_ip( strdup(n->ip_address.ToAscii().data()) ))
                {
                    //First node , your computer , No previous for first node
                    if(i == 0)
                    {
                        a = utils::get_iplocation( public_ip );
                        tn.location_ip = public_ip;
                    }

                    //Non first nodes
                    else
                    {
                        node p = trace_nodes[i-1];

                        if(p.ip_address.length() > 0 && !iputils::check_private_ip( strdup( p.ip_address.ToAscii().data() ) ) )
                        {
                            a = utils::get_iplocation( p.ip_address );
                            tn.location_ip = p.ip_address;
                        }

                        /*
                            For example 192.168.0.1 is your LAN router , then it will take the location ip of your computer's ip (192.168.0.6)
                            And then 192.168.0.1 will have location ip same as location ip of 192.168.0.6
                        */
                        else if(p.ip_address.length() > 0 && iputils::check_private_ip( strdup( p.ip_address.ToAscii().data() ) ) )
                        {
                            a = utils::get_iplocation( p.location_ip );
                            tn.location_ip = p.location_ip;
                        }
                    }
                }
                else
                {
                    a = utils::get_iplocation( n->ip_address );
                }

                //Set current nodes location
				tn.loc = a;

				//revise all location and apply intelligence
                revise_locations();

                if(tn.location_ip.length() > 0 && tn.ip_address.CmpNoCase(tn.location_ip) != 0)
                {
                    b = a.country_code + wxT("/") + a.city + wxT(" [ ") + tn.location_ip + wxT(" ]");
                }
                else
                {
                    b = tn.loc.country_code + wxT("/") + tn.loc.city;
                }
                result->SetItem(i , 3 , b);

                result->SetItem(i , 7 , wxString::Format("%.2lf ms" , n->response_time ) );

                result->SetItemPtrData(i , (wxUIntPtr) &tn);

                //Plot node on the map
                plot_node(tn);

                break;
            }

            //Reverse DNS reply
            case 2 :
            {
                //Put data object in GUI
                result->SetItem(i , 2 , n->host_name );
                tn.host_name = n->host_name;

                tn.whois_data = n->whois_data;
                result->SetItem(i , 6 , n->who.isp );

                break;
            }
        }
    }

    //free the node item;
    delete n;
}

/**
    @brief
    Stop any running trace processes
*/
void tcptraceFrame::_stop_trace()
{
    if(t != NULL)
    {
		//Close communication sockets on Linux
#if defined(__UNIX__)
		if(t->GetThread() != NULL)
        {
            if(t->GetThread()->IsRunning())
            {
                //Send terminate signal to thread please to stop recvfrom
                write(comm_socks[0] , "TERMINATE" , 9);
            }
        }
#endif
        t->shutdown();

        if(!txt_host->IsEnabled())
        {
            txt_host->Enable();
            btn_trace->SetLabel(wxT("Trace"));
            txt_host->SetFocus();
        }
    }
}

/**
    @brief
    Function to clear the google map
*/
void tcptraceFrame::clear_map()
{
    //Clear the map
    wxString js_code = wxT("clear_map();");

    //Run the javacsript
    m_browser->RunScript(js_code);

    //Log it too!
    log(js_code);
}

/**
    @brief
	Log messages in the log box.
*/
void tcptraceFrame::log(wxString msg)
{
    (*txt_log)<<wxT("\n")<<msg<<wxT("\n");
}

/**
    @brief
    update_log_data event handler

    @details
    Manages log messages coming as events to this frame
*/
void tcptraceFrame::update_log_data(wxCommandEvent &event)
{
    log(*(wxString*) event.GetClientData());
}

/**
    @brief
    Ip node is doubleclicked then show its information
*/
void tcptraceFrame::on_node_dblclick(wxListEvent& event)
{
    int i = event.GetIndex();

    if(result->GetItemData(i) == NULL)
    {
        return;
    }

    node n = *((node*)result->GetItemData(i));

    show_info_box(n);
}

/**
    @brief
    Show the information related to a particular node
*/
void tcptraceFrame::show_info_box(node n)
{
    info_box info;

    //prepare the information text
    wxString info_text = _("IP Address : ") + n.ip_address + wxT("\n") +
    _("TTL : ") + wxString::Format("%d" , n.ttl) + wxT("\n") +
    _("Hostname : ") + n.host_name + wxT("\n") +
    _("\n\nLocation Information #### \n\n") +
    _("Country Code : ") + n.loc.country_code + wxT("\n") +
    _("City : ") + n.loc.city + wxT("\n") +
    _("Latitude : ") + wxString::Format("%f" , n.loc.latitude) + wxT("\n") +
    wxT("Longitude : ") + wxString::Format("%f" , n.loc.longitude) + wxT("\n") +
    wxT("\n");

    info.set_text(info_text);

    //Show it
    if ( info.ShowModal() == wxID_OK )
    {
        //When showing is done , destroy it
        info.Destroy();
    }
}

/**
    @brief
    Set the IP of the host
*/
void tcptraceFrame::set_ip( wxString ip )
{
    txt_ip->SetValue(ip);
}

/**
    1 - IP address
    2 - Hostname
*/
bool tcptraceFrame::set_node_property(int n , int prop , char *value)
{
    /*
    if(n < 30)
    {
        switch(prop)
        {
            case 1 :
            strcpy(trace_nodes[n].ip_address , value);
            break;
            case 2 :
            strcpy(trace_nodes[n].host_name , value);
            break;
            default:
            break;
        }
    }
*/
    return true;
}

/**
    @brief
    Plot a node on the Google Map

    @details
    latitude and longitude must be in C locale otherwise in other locales 9.3 may become 9,3 and will not work

*/
void tcptraceFrame::plot_node(node n)
{
    //Force C locale for latitude and longitude numbers
    std::ostringstream latitude , longitude;

    latitude.imbue( std::locale("C") );
    latitude<<n.loc.latitude;
    //wxString str(ss.str());

    longitude.imbue( std::locale("C") );
    longitude<<n.loc.longitude;

    //Plot on map
    wxString js_command = "plot({ip_address : '" + n.ip_address +
        "' , node_number : '" + wxString::Format("%d" , n.node_number + 1) +
        "' , country_code : '" + n.loc.country_code +
        "' , city : '" + n.loc.city +
        //"' , latitude : '" + wxString::Format("%f" , n.loc.latitude) +
        "' , latitude : '" + latitude.str() +
        "' , longitude : '" + longitude.str() +  wxT("'});");

    //Run the javacsript
    m_browser->RunScript(js_command);

    //Log it too!
    log( _("Javascript command : ") + js_command);

    //Doesnt work
    //m_browser->Execute(js_command);
    //m_browser->OpenURI(  js_command );
}

/**
    @brief
    Revise the locations intelligently and remap them
*/
void tcptraceFrame::revise_locations()
{
    for(int j = 0; j < MAX_HOPS ; j++)
    {
		for(int i = 0; i < MAX_HOPS ; i++)
		{
			iplocation& a = trace_nodes[i].loc;

			//If this node does not have a city , then try getting it from previous or next node , subject to conditions
			if( a.country_code.length() )
			{
				//country found but not city
				if(a.city.length() == 0)
				{
					//Check the previous node
					if( (i-1) >= 0 )
					{

						iplocation p = trace_nodes[i-1].loc;

						//Previous node
						if(p.city.length() > 0 && p.country_code.CmpNoCase(a.country_code) == 0)
						{
							//map as same location
							trace_nodes[i].loc = p;
							log(trace_nodes[i].ip_address + wxT(" takes the location of : ") + trace_nodes[i-1].ip_address);
							continue;
						}
					}

					//Check the next node
					if( (i+1) < MAX_HOPS )
					{
						//Next node
						iplocation n = trace_nodes[i+1].loc;

						if(n.city.length() > 0 && n.country_code.CmpNoCase(a.country_code) == 0)
						{
							a = n;
							continue;
						}
					}
				}
			}
		}
    }
}

/**
    @brief
    Save the results to a csv file
*/
void tcptraceFrame::on_save(wxCommandEvent &event)
{
    wxFileDialog saveFileDialog(this , _("Save Results") , "" , "" , "CSV files (*.csv)|*.csv", wxFD_SAVE|wxFD_OVERWRITE_PROMPT);

    //user changed idea and clicked cancel
    if (saveFileDialog.ShowModal() == wxID_CANCEL)
    {
        return;
    }

    wxString path = saveFileDialog.GetPath();

    //Prepare the csv
    wxString csv = "";
    node n;
    for(int i = 0 ; i < MAX_HOPS ; i++)
    {
        n = trace_nodes[i];
        csv += wxString::Format("%d" , n.node_number) +

        //ip address
        "," + n.ip_address +

        //reverse dns host name
        "," + n.host_name +

        //location information
        "," + n.loc.country_code +
        "," + n.loc.city +

        //isp , internet service provider
        "," + n.who.isp +

        //response time
        "," + wxString::Format("%.2f" , n.response_time) +

        "\r\n";
    }

    wxTextFile f(path);

    if(!f.Exists())
    {
        f.Create();
    }

    f.Open();
    f.Clear();

    f.AddLine(csv);
    f.Write();
    f.Close();

    // save the current contents in the file;
    // this can be done with e.g. wxWidgets output streams:
    //wxFileOutputStream output_stream( path );
    /*
    if ( !output_stream.IsOk() )
    {
        wxLogError("Cannot save current contents in file '%s'." , path );
        return;
    }*/
}

/**
    @brief
    Generate the right click context menu for each node

    @details
    Options are :

    1. View more information
    2. View whois data
*/
void tcptraceFrame::list_menu(wxListEvent &evt)
{
	//Get the data of the particular row selected ?
	void *data = reinterpret_cast<void *>(evt.GetItem().GetData());

	wxMenu menu;
	wxMenuItem *mi;

	menu.SetClientData( data );

    mi = new wxMenuItem(&menu , -1 , _("More Information") , _("View more information about this node") );
    menu.Append(mi);
    menu.Connect( mi->GetId() , wxEVT_COMMAND_MENU_SELECTED , (wxObjectEventFunction) &tcptraceFrame::list_menu_info , NULL , this );

    mi = new wxMenuItem(&menu , -1 , _("Whois") , _("View whois information about this node") );
    menu.Connect( mi->GetId() , wxEVT_COMMAND_MENU_SELECTED , (wxObjectEventFunction) &tcptraceFrame::list_menu_whois , NULL , this );
    menu.Append(mi);

    //pop the menu
	PopupMenu(&menu);
}

/**
    @brief
    Info button of list context menu
*/
void tcptraceFrame::list_menu_info(wxCommandEvent &evt)
{
    //node n = *((node*)result->GetItemData(i));
    node n = *( (node*)(static_cast<wxMenu *>(evt.GetEventObject())->GetClientData()) );

    show_info_box(n);
}

/**
    @brief
    context menu whois click event handler
*/
void tcptraceFrame::list_menu_whois(wxCommandEvent &evt)
{
    node n = *( (node*)(static_cast<wxMenu *>(evt.GetEventObject())->GetClientData()) );
    show_whois_box(n);
}

/**
    @brief
    show whois information box
*/
void tcptraceFrame::show_whois_box(node n)
{
    wxString ip_address = n.ip_address;
    info_box info;
    char whois_data[65536];

    //iputils::get_ip_whois(strdup(ip_address.ToAscii().data()) , whois_data);

    wxString info_text = "Whois Data for " + ip_address + "\n" + n.whois_data;
    info.set_text(info_text);

    if ( info.ShowModal() == wxID_OK )
    {
        info.Destroy();
    }
}
