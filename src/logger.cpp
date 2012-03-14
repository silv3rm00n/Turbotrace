#include "../include/logger.h"

logger::logger(wxFrame *frame, const wxString& title):wxMiniFrame(frame, -1, title , wxDefaultPosition , wxSize(600 , 300) , wxCLOSE_BOX |wxCAPTION | wxRESIZE_BORDER)
{
    //ctor
    init_ui();
}

logger::~logger()
{
    //dtor
}

void logger::init_ui()
{
    //Now create panel
    wxPanel *panel = new wxPanel( this , ::wxNewId() );

    //btn_trace->SetToolTipString(_("Click to get whois information for the domain name."));
    txt_log = new wxTextCtrl(panel , -1 , _("") , wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE);

    //Add the input field and submit button to a Box Sizer since the must stay together
    wxBoxSizer *space = new wxBoxSizer(wxHORIZONTAL);

    //Non expandable and align to right
    space->Add( txt_log , 1 , wxEXPAND);

    panel->SetSizer(space);
}

void logger::log(wxString msg)
{
    (*txt_log) << msg << wxT("\n");
}
