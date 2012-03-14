/***************************************************************
 * Name:      tcptraceApp.cpp
 * Purpose:   Code for Application Class
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

#include "tcptraceApp.h"
#include "tcptraceMain.h"

IMPLEMENT_APP(tcptraceApp);

//Application initialisation here
bool tcptraceApp::OnInit()
{
    //Create an object of the main frame window
    tcptraceFrame* frame = new tcptraceFrame(0L , _("TurboTrace") );

    //executable_path = wxStandardPaths::Get().GetExecutablePath();

    //Application Name
    SetAppName("TurboTrace");

    //Show the frame
    frame->Show();

    return true;
}

wxString tcptraceApp::get_executable_path()
{
    return executable_path;
}
