#ifndef INFO_BOX_H
#define INFO_BOX_H

#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif
#include <wx/statline.h>

class info_box : public wxDialog
{
    public:
        info_box();
        void set_text(wxString);
    protected:
    private:
        //Variables
        wxString info;
        wxTextCtrl *txt_info;

        //Functions
        void on_esc( wxKeyEvent& event );
        void on_ok( wxCommandEvent& event );
};

#endif // INFO_BOX_H
