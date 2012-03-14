/***************************************************************
 * Name:      tcptraceApp.h
 * Purpose:   Defines Application Class
 * Author:    Silver Moon (m00n.silv3r@gmail.com)
 * Created:   2011-12-26
 * Copyright: Silver Moon (http://www.binarytides.com/blog/)
 * License:
 **************************************************************/

#ifndef TCPTRACEAPP_H
#define TCPTRACEAPP_H

//header files for windows
#if defined(_WIN32)
#include "include/arch/win/win.h"	
#endif

#define _DEBUG_MODE_

#include <wx/app.h>
#include <wx/dir.h>

/**
    @details
    The wxApp class instance
*/
class tcptraceApp : public wxApp
{
    private:
        wxString executable_path;

    public:
        virtual bool OnInit();

        wxString find_xul_runner(const wxString&);

        wxString get_executable_path();
};

#endif // TCPTRACEAPP_H
