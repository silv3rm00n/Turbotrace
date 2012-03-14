#include "../include/about_box.h"

//wxString wsAppName = wxT("Mascott");
wxString wsAppMaker = _("TurboTrace");
wxString wsAppCopyDate = _("2012");

/*inline fonction*/
inline wxBitmap _wxGetBitmapFromMemory( const unsigned char *data, int length)
{
    wxMemoryInputStream is( data, length);
    return wxBitmap( wxImage( is, wxBITMAP_TYPE_ANY, -1), -1);
}

/**
    @details
    Function to provide the build information
*/
wxString about_box::wxbuildinfo(wxbuildinfoformat format)
{
    wxString wxbuild(wxVERSION_STRING);

    if (format == long_f )
    {
        #if defined(__WXMSW__)
        wxbuild << _T("-Windows");

        #elif defined(__WXMAC__)
        wxbuild << _T("-Mac");

        #elif defined(__UNIX__)
        wxbuild << _T("-Linux");
        #endif

        #if wxUSE_UNICODE
        wxbuild << _T("-Unicode build");
        #else
        wxbuild << _T("-ANSI build");
        #endif // wxUSE_UNICODE
    }

    return wxbuild;
}


about_box::about_box(wxWindowID id , bool bRegistering , bool bEasterEgg):wxDialog(NULL , id , _("About AppName") , wxDefaultPosition)
{
    Connect(GetId() , wxEVT_KEY_UP , (wxObjectEventFunction) &about_box::on_esc );

    //Your product is registered?
    bIsRegistered = true;

    //Init all image handlers...
    wxInitAllImageHandlers();

    wxFlexGridSizer *fgs = new wxFlexGridSizer( 5 , 1 , 10 , 25 );
    wxPanel *panel = new wxPanel( this , ::wxNewId() );
    panel->SetBackgroundColour(wxColour(240,240,240));
    //Load white bg
    //wxStaticBitmap *mySBBlank = new wxStaticBitmap(this, -1, wxGetBitmapFromMemory( blank ), wxPoint(0,-8));

    //Load bg picture
    //wxStaticBitmap *mySBBackGround = new wxStaticBitmap(this, -1, (bEasterEgg) ? wxGetBitmapFromMemory( img_cachee2 ) : wxGetBitmapFromMemory( backgr ), wxPoint(0,-20));

    //Write the application name
    wxStaticText *a = new wxStaticText(panel , -1 , _( wxTheApp->GetAppName() ) );
    //a->SetBackgroundColour( wxColour(255,255,255) );
    a->SetForegroundColour( wxColour( 220, 0, 0 ) );




    a->SetFont( wxFont(24, wxFONTFAMILY_SWISS , wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD) );


    fgs->Add(a , 1 , wxEXPAND | wxALL , 10);

    wxHtmlWindow *b = new wxHtmlWindow(panel , -1 , wxDefaultPosition , wxSize(330 , 250) , wxHW_SCROLLBAR_NEVER);
    b->LoadPage(  wxFileName(wxStandardPaths::Get().GetExecutablePath()).GetPath() + wxT("/about.html") );

    Connect(b->GetId() , wxEVT_COMMAND_HTML_LINK_CLICKED , (wxObjectEventFunction) &about_box::link_click );


    //a->Wrap((int)(this->GetSize().x-2*15));
    //a->SetBackgroundColour( wxT("WHITE") );


    fgs->Add(b , 1 , wxEXPAND | wxALL , 10);

    wxString wsAppInfo = "2.0";
    //wsAppInfo.Printf(_("Build %d"), AutoVersion::BUILDS_COUNT);

    //Write build info
    a = new wxStaticText(panel, -1, wxbuildinfo(long_f));
    a->Wrap((int)(this->GetSize().x-2*15));
    a->SetBackgroundColour( wxT("WHITE") );
    a->SetForegroundColour( wxColour( 0, 0, 0 ) );

    fgs->Add(a , 1 , wxEXPAND | wxALL , 10);

    //Static line
    wxStaticLine *myStaticLine = new wxStaticLine(panel, -1);
    fgs->Add(myStaticLine , 1 , wxEXPAND );

    wxButton *button_ok = new wxButton(panel, -1 , _("&OK"));
    fgs->Add(button_ok , 0 , wxALIGN_RIGHT | wxALL , 10);

    Connect( button_ok->GetId() , wxEVT_COMMAND_BUTTON_CLICKED , (wxObjectEventFunction) &about_box::on_ok );

    //Make growable cols
    fgs->AddGrowableCol(0, 1);
    panel->SetSizer(fgs);

    //Make the dialog box only as big as the flexgridsizer needs
    fgs->Fit(this);

    //put button in focus otherwise esc key will not work
    button_ok->SetFocus();




/*
    //You wish to register your product
    if( bRegistering )
    {
        //Button 'Enregistrer'=>'Register'
        wxButton *myButtonRegister = new wxButton(this, -1 , _("&Enregistrer..."), wxPoint(10,this->GetSize().y-50-15), wxSize(80,23), 0, wxDefaultValidator, wxT("myBREGISTER"));

        //myButtonRegister->SetFont(wxFont(8, wxSWISS, wxNORMAL,wxNORMAL, false, wxT("Tahoma")));

        //Si le produit est immatriculé on affiche la clef/If the product is registered we display its key
        //(bIsRegistered) ? myButtonRegister->Disable() : myButtonRegister->Enable();

        if( bIsRegistered )
        {
            wsRegisterMessage = _("3O30-P399-TYR8-xxxx");
            myButtonRegister->Disable();
        }
        else //Sinon on demande de l'enregistrer
        {
            wsRegisterMessage = _("PLEASE REGISTER!");
            myButtonRegister->Enable();
        }

        //Write user info
        wxStaticText *myAppUser = new wxStaticText(this, -1, _("UserID: Wixy Jets - Key: ") + wsRegisterMessage, wxPoint(myAppInfo->GetPosition().x,myStaticLine->GetPosition().y-14), wxSize(20,100), 0, wxT("myAppUser"));

        //myAppUser->SetFont(wxFont(7, wxSWISS, wxNORMAL,wxFONTFLAG_ANTIALIASED, false, wxT("Courier New")));

        //myAppUser->Wrap((int)(this->GetSize().x-2*15));
        myAppUser->SetBackgroundColour( wxT("WHITE") );
        myAppUser->SetForegroundColour( wxColour( 0, 0, 0 ) );
    }
    */


}

void about_box::on_close( wxCommandEvent& WXUNUSED(event) )
{
   Close(true);
}

void about_box::on_ok( wxCommandEvent& WXUNUSED(event) )
{
   Close(true);
}

void about_box::link_click(  wxHtmlLinkEvent& event)
{
    ::wxLaunchDefaultBrowser(event.GetLinkInfo().GetHref());
}

void about_box::on_esc(wxKeyEvent& event)
{
    //::wxMessageBox(_("asd") , _("asd"));
    //If escape key has been pressed then stop any running traces
    if(event.GetKeyCode() == WXK_ESCAPE)
    {
        Close(true);
    }
}
