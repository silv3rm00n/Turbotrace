#ifndef REVERSE_DNS_H
#define REVERSE_DNS_H

//header files for windows
#if defined(_WIN32)
	#include "arch/win/win.h"	
	#define strdup _strdup
#endif

#include <wx/wx.h>
#include "../tcptraceMain.h"
#include "../include/utils.h"

class reverse_dns : public wxThread
{
    public:
        reverse_dns(class tcptraceFrame *);
        void set_ip(wxString , int);

    protected:
        virtual wxThread::ExitCode Entry();

    private:
        wxString ip_address;
        int n;
        tcptraceFrame *parent_frame;
};

#endif // REVERSE_DNS_H
