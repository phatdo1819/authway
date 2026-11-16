// The window of the details of a VPN: everything the app knows of it, as text to read and copy, with Copy all and
// Close. It follows the tunnel every second; the selection stays while the bytes count.

use super::gtk::{self, Widget};
use super::{on_click, on_close, window_id, Target};
use crate::client::details::Details;
use crate::client::DetailsView;
use crate::strings;

pub struct DetailsWindow {
    window: Widget,
    tunnel: String,
    text: Widget,
    shown: Details,
}

impl DetailsWindow {
    pub fn open(tunnel: &str, details: Details) -> DetailsWindow {
        let window = gtk::window(&strings::details_title(tunnel), 480, 560);
        let content = gtk::vbox(10);
        gtk::margins(content, 16, 16, 16);
        let heading = gtk::label(tunnel);
        gtk::add_class(heading, "authway-big");
        gtk::pack(content, heading, false);
        let text = gtk::label("");
        unsafe {
            (gtk::g().gtk_label_set_selectable)(text, 1);
            (gtk::g().gtk_label_set_line_wrap)(text, 1);
        }
        gtk::valign(text, gtk::ALIGN_START);
        gtk::margins(text, 8, 10, 8);
        gtk::pack(content, gtk::scrolled(text), true);
        let buttons = gtk::hbox(8);
        gtk::halign(buttons, gtk::ALIGN_END);
        let copy = gtk::button(strings::DETAILS_COPY);
        let close = gtk::button(strings::DETAILS_CLOSE);
        gtk::pack(buttons, copy, false);
        gtk::pack(buttons, close, false);
        gtk::pack(content, buttons, false);
        gtk::add(window, content);
        on_click(copy, Target::DetailsCopy);
        on_click(close, Target::DetailsClose);
        on_close(window);
        let mut details_window = DetailsWindow { window, tunnel: tunnel.to_string(), text, shown: Details::default() };
        details_window.update(details);
        unsafe { (gtk::g().gtk_widget_show)(window) };
        gtk::present(window);
        details_window
    }

    pub fn copy_all(&self) {
        gtk::copy_to_clipboard(&self.shown.text(&strings::details_title(&self.tunnel)));
    }
}

impl DetailsView for DetailsWindow {
    // only when something changed, with the selection as it was
    fn update(&mut self, details: Details) {
        if details == self.shown {
            return;
        }
        let (mut start, mut end) = (0, 0);
        let selected = unsafe { (gtk::g().gtk_label_get_selection_bounds)(self.text, &mut start, &mut end) } != 0;
        gtk::set_text(self.text, &details.text(&strings::details_title(&self.tunnel)));
        if selected {
            unsafe { (gtk::g().gtk_label_select_region)(self.text, start, end) };
        }
        self.shown = details;
    }

    fn activate(&self) {
        gtk::present(self.window);
    }

    fn id(&self) -> usize {
        window_id(self.window)
    }
}

impl Drop for DetailsWindow {
    fn drop(&mut self) {
        gtk::destroy(self.window);
    }
}
