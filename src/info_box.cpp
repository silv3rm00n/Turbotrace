#include "../include/info_box.h"

info_box::info_box():wxDialog(NULL , -1 , _("Information"))
{
    //Close on Esc button press
    Connect(GetId() , wxEVT_KEY_UP , (wxObjectEventFunction) &info_box::on_esc );

    wxFlexGridSizer *fgs = new wxFlexGridSizer( 3 , 1 , 10 , 25 );
    wxPanel *panel = new wxPanel( this , ::wxNewId() );

    txt_info = new wxTextCtrl(panel , -1 , wxT("") , wxDefaultPosition , wxSize(330 , 250) , wxTE_MULTILINE);

    fgs->Add(txt_info , 1 , wxEXPAND | wxALL , 10);

    wxStaticLine *b = new wxStaticLine(panel);
    fgs->Add(b , 1 , wxEXPAND );

    wxButton *button_ok = new wxButton(panel, -1 , _("&OK"));
    fgs->Add(button_ok , 0 , wxALIGN_RIGHT | wxALL , 10);

    Connect( button_ok->GetId() , wxEVT_COMMAND_BUTTON_CLICKED , (wxObjectEventFunction) &info_box::on_ok );

    //Make growable cols
    fgs->AddGrowableCol(0, 1);
    panel->SetSizer(fgs);

    //Make the dialog box only as big as the flexgridsizer needs
    fgs->Fit(this);

    //put button in focus otherwise esc key will not work
    button_ok->SetFocus();
}

/**
    @brief
    When esc button is pressed , close the box
*/
void info_box::on_esc(wxKeyEvent& event)
{
    //If escape key has been pressed then stop any running traces
    if(event.GetKeyCode() == WXK_ESCAPE)
    {
        Close(true);
    }
}

/**
    @brief
    OK button pressed
*/
void info_box::on_ok( wxCommandEvent& WXUNUSED(event) )
{
   Close(true);
}

/**
    @brief
    Set the text of this information box
*/
void info_box::set_text(wxString info)
{
    this->info = info;
    (*txt_info)<<info;
}
