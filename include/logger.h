#ifndef LOGGER_H
#define LOGGER_H

#include<wx/wx.h>
#include<wx/minifram.h>

class logger : public wxMiniFrame
{
    public:
        logger(wxFrame *frame, const wxString& title);
        virtual ~logger();
        void log(wxString);

    protected:

    private:
        wxTextCtrl *txt_log;
        void init_ui();
};

#endif // LOGGER_H
