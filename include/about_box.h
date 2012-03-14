#ifndef ABOUT_BOX_H
#define ABOUT_BOX_H

#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include <wx/bitmap.h>
#include<wx/stdpaths.h>
#include <wx/statline.h>
#include <wx/mstream.h>
#include <wx/html/htmlwin.h>

//helper functions
enum wxbuildinfoformat
{
    short_f, long_f
};

class about_box : public wxDialog
{
    public:
        about_box(wxWindowID id,  bool bRegistering = false, bool bEasterEgg = false);

    private:
        //DECLARE_EVENT_TABLE();
        bool bIsRegistered;
        wxString wsRegisterMessage;

        wxString wxbuildinfo(wxbuildinfoformat format);

        void on_close( wxCommandEvent& event );
        void on_ok( wxCommandEvent& event );
        void on_esc( wxKeyEvent& event );

        void link_click(  wxHtmlLinkEvent& event);
};


#endif // ABOUT_BOX_H
