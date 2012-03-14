#include "../include/utils.h"

/**
    @brief
    Simple function to fetch a url

    @details
    http://wiki.wxwidgets.org/Download_a_file_from_internet
*/
wxString utils::get_url(wxString u)
{
    wxURL url( u );

    if(url.GetError()==wxURL_NOERR)
    {
        wxString htmldata;
        wxInputStream *in = url.GetInputStream();

        if(in && in->IsOk())
        {
            wxStringOutputStream html_stream(&htmldata);
            in->Read(html_stream);
        }

        delete in;

        return htmldata;
    }

    return wxT("");
}

double utils::time_diff(struct timeval x , struct timeval y)
{
	double x_ms , y_ms , diff;

	x_ms = (double)x.tv_sec*1000 + (double)x.tv_usec/1000;
	y_ms = (double)y.tv_sec*1000 + (double)y.tv_usec/1000;

	diff = (double)y_ms - (double)x_ms;

	return diff;
}


/**
    @brief
    Analyse the raw whois data to find out useful things like isp , ip range etc.
*/
whois_analysis utils::analyse_whois(wxString whois_data)
{
    whois_analysis who;

    //Apnic format analysis
    if(whois_data.Find("whois.apnic.net") != wxNOT_FOUND)
    {
        who.rir = "APNIC";

        wxStringTokenizer tkz(whois_data, wxT("\n"));

        while ( tkz.HasMoreTokens() )
        {
            wxString token = tkz.GetNextToken();

            // process token here
            if(token.Find("netname") != wxNOT_FOUND)
            {
                wxStringTokenizer tkz2(token , wxT(":"));
                while ( tkz2.HasMoreTokens() )
                {
                    wxString isp = tkz2.GetNextToken();
                    isp.Trim(false).Trim();
                    who.isp = isp;

                    wxPrintf("ISP is : %s" , isp);
                }

            }
        }
    }

    //ARIN format analysis
    else if(whois_data.Find("whois.arin.net") != wxNOT_FOUND)
    {
        who.rir = "ARIN";

        wxStringTokenizer tkz(whois_data, wxT("\n"));

        while ( tkz.HasMoreTokens() )
        {
            wxString token = tkz.GetNextToken();

            // process token here
            if(token.Find("NetName") != wxNOT_FOUND)
            {
                wxStringTokenizer tkz2(token , wxT(":"));
                while ( tkz2.HasMoreTokens() )
                {
                    wxString isp = tkz2.GetNextToken();
                    isp.Trim(false).Trim();
                    who.isp = isp;

                    wxPrintf("ISP is : %s" , isp);
                }
            }
        }
    }

    //RIPE format
    else if(whois_data.Find("ripe.net") != wxNOT_FOUND)
    {
        who.rir = "RIPE";

        wxStringTokenizer tkz(whois_data, wxT("\n"));

        while ( tkz.HasMoreTokens() )
        {
            wxString token = tkz.GetNextToken();

            // process token here
            if(token.Find("netname") != wxNOT_FOUND)
            {
                wxStringTokenizer tkz2(token , wxT(":"));
                while ( tkz2.HasMoreTokens() )
                {
                    wxString isp = tkz2.GetNextToken();
                    isp.Trim(false).Trim();
                    who.isp = isp;

                    wxPrintf("ISP is : %s" , isp);
                }
            }
        }
    }

    //LACNIC Format ??



    return who;
}

iplocation utils::get_iplocation( wxString ip )
{
	iplocation a;
	//Check if dat file already opened or not
	//static bool db_opened = false;
//#if defined(__UNIX__)
	GeoIP *gi;

    GeoIPRecord*  gir;

	wxString dat_path = wxFileName(wxStandardPaths::Get().GetExecutablePath()).GetPath() + wxT("/GeoLiteCity.dat");

	uint32_t ipnum;
	char *_ip = strdup( ip.ToAscii().data() );

	//Ip number first
	ipnum = _GeoIP_lookupaddress(_ip);

    //Open location data file if it exists
    if( ::wxFileExists(dat_path) )
    {
        char *path = strdup ( dat_path.ToAscii().data());
        gi = GeoIP_open(path , GEOIP_STANDARD);
        //db_opened = true;
        free(path);
    }

    //If dat file doesnt exist return
    else
    {
        return a;
    }

	if (gi == NULL)
	{
		//printf("%s not available, skipping...\n" , path);
	}
	else
	{
		gir = GeoIP_record_by_ipnum(gi , ipnum);

		GeoIP_delete(gi);

		if (gir == NULL)
		{
			//printf("%s: IP Address not found\n", GeoIPDBDescription[i]);
		}
		else
		{
			//printf("%s, %s, %s, %s, %f, %f\n",  gir->country_code, _mk_NA(gir->region) , _mk_NA(gir->city), _mk_NA(gir->postal_code), gir->latitude, gir->longitude);

			a.country_code = wxString(gir->country_code , wxConvUTF8);
			a.city = wxString(gir->city , wxConvUTF8);

			a.latitude = gir->latitude;
			a.longitude = gir->longitude;

			GeoIPRecord_delete(gir);
		}
	}

//#endif
	return a;
}

#if defined(__WXMSW__)
/**
	@brief
	Get the gateway of a given ip. Only for windows

	@details
	For example for ip 192.168.1.10 the gateway is 192.168.1.1
*/
bool utils :: get_gateway(struct in_addr ip , char *sgatewayip , int *gatewayip)
{
	char pAdapterInfo[5000];

	PIP_ADAPTER_INFO  AdapterInfo;

	ULONG OutBufLen = sizeof(pAdapterInfo) ;

	GetAdaptersInfo((PIP_ADAPTER_INFO) pAdapterInfo, &OutBufLen);
	for(AdapterInfo = (PIP_ADAPTER_INFO)pAdapterInfo; AdapterInfo ; AdapterInfo = AdapterInfo->Next)
	{
		if(ip.s_addr == inet_addr(AdapterInfo->IpAddressList.IpAddress.String))
		{
			strcpy(sgatewayip , AdapterInfo->GatewayList.IpAddress.String);
		}
	}

	*gatewayip = inet_addr(sgatewayip);

	return true;
}

/**
	@brief
	Get the mac address of a given ip
*/
bool utils::get_mac_from_ip(unsigned char *mac , struct in_addr destip)
{
	DWORD ret;
	IPAddr srcip;
	ULONG MacAddr[2];
	ULONG PhyAddrLen = 6;  /* default to length of six bytes */
	int i;

	srcip = 0;

	//Send an arp packet
	ret = SendARP((IPAddr) destip.S_un.S_addr , srcip , MacAddr , &PhyAddrLen);

	//Prepare the mac address
	if(PhyAddrLen)
	{
		BYTE *bMacAddr = (BYTE *) & MacAddr;
		for (i = 0; i < (int) PhyAddrLen; i++)
		{
			mac[i] = (char)bMacAddr[i];
		}
	}

	return true;
}

#endif
