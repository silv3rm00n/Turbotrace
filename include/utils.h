#ifndef UTILS_H
#define UTILS_H

//header files for windows
#if defined(_WIN32)
	#include "arch/win/win.h"
#endif

#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

//header files for windows
#if defined(_WIN32)
	#include<winsock2.h>
	#include<iphlpapi.h>	//For SendARP
	#pragma comment(lib , "iphlpapi.lib") //For iphlpapi

	#include <stdint.h>

	typedef uint8_t u_int8_t;
	typedef uint16_t u_int16_t;
	typedef uint32_t u_int32_t;
#endif

#include<wx/url.h>
#include<wx/sstream.h>
#include<wx/stdpaths.h>
#include<wx/filename.h>
#include<wx/tokenzr.h>

#include "../libGeoIP/GeoIP.h"
#include "../libGeoIP/GeoIPCity.h"
#include "../libGeoIP/GeoIPUpdate.h"

#include<sys/time.h>

//The header file of this function is not available :(
extern "C" unsigned long _GeoIP_lookupaddress (const char *host);

struct iplocation
{
    wxString country_code;
    wxString city;

    float latitude;
    float longitude;
};

struct whois_analysis
{
    wxString isp;
    wxString rir;
    //etc.
};

/**
    @brief
    Utilities Class
*/
class utils
{
    public:

        static wxString get_url(wxString);
        static iplocation get_iplocation(wxString);
        static whois_analysis analyse_whois(wxString);
        static double time_diff(struct timeval , struct timeval);

#if defined(__WXMSW__)
		static bool get_gateway(struct in_addr ip , char *sgatewayip , int *gatewayip) ;
		static bool get_mac_from_ip(unsigned char * , struct in_addr);
#endif
    protected:

    private:
};

#endif // UTILS_H
