// The login window of a VPN, as on Windows and macOS: the username, the password and the code of the authenticator
// app; Return or Connect logs in, Cancel or closing the window disconnects. While the app connects, the window shows
// only that, with Cancel. A sixth digit in the code logs in by itself.

use super::gtk::{self, Widget};
use super::{on_activate, on_change, on_click, on_close, window_id, Target};
use crate::client::{LoginForm, LoginValues, LoginView, OTP_LENGTH};
use crate::names::PRODUCT;
use crate::strings;

pub struct LoginWindow {
    window: Widget,
    heading: Widget,
    hint: Widget,
    notice: Widget,
    error: Widget,
    fields: Widget,
    username: Widget,
    password: Widget,
    remember: Option<Widget>,
    code_label: Widget,
    code: Widget,
    ok: Widget,
    otp_required: bool,
    checking: bool,
    busy: bool,
}

impl LoginWindow {
    pub fn open(form: LoginForm) -> LoginWindow {
        let window = gtk::window(&format!("{}: {}", PRODUCT, form.heading), 380, -1);
        unsafe { (gtk::g().gtk_window_set_resizable)(window, 0) };
        let content = gtk::vbox(10);
        gtk::margins(content, 18, 18, 18);
        let heading = gtk::wrapping(form.heading);
        gtk::add_class(heading, "authway-big");
        gtk::pack(content, heading, false);
        let hint = gtk::wrapping(form.hint);
        gtk::add_class(hint, "authway-dim");
        gtk::pack(content, hint, false);
        let notice = gtk::wrapping("");
        gtk::add_class(notice, "authway-busy");
        gtk::pack(content, notice, false);

        let fields = gtk::grid();
        let field_label = |text: &str, row: i32| {
            let label = gtk::label(text);
            gtk::attach(fields, label, 0, row);
        };
        field_label(strings::LOGIN_USERNAME, 0);
        let username = gtk::entry(&form.saved.username);
        gtk::hexpand(username);
        gtk::attach(fields, username, 1, 0);
        field_label(strings::LOGIN_PASSWORD, 1);
        let password = gtk::entry("");
        unsafe {
            (gtk::g().gtk_entry_set_visibility)(password, 0);
            (gtk::g().gtk_entry_set_input_purpose)(password, gtk::PURPOSE_PASSWORD);
        }
        if form.can_remember {
            if let Some(saved) = &form.saved.password {
                gtk::set_entry_text(password, saved);
            }
        }
        gtk::attach(fields, password, 1, 1);
        let remember = form.can_remember.then(|| {
            let remember = gtk::check_button(strings::LOGIN_REMEMBER);
            // checked the first time, then as the user left it
            gtk::set_checked(remember, form.saved.password.is_some() || form.saved.username.is_empty());
            gtk::attach(fields, remember, 1, 2);
            remember
        });
        let code_label = gtk::label(strings::LOGIN_OTP);
        gtk::attach(fields, code_label, 0, 3);
        let code = gtk::entry("");
        unsafe {
            (gtk::g().gtk_entry_set_input_purpose)(code, gtk::PURPOSE_DIGITS);
            // a pasted code can have spaces, which go away
            (gtk::g().gtk_entry_set_max_length)(code, 16);
            (gtk::g().gtk_entry_set_placeholder_text)(code, gtk::c(strings::LOGIN_OTP_CUE).as_ptr());
        }
        gtk::attach(fields, code, 1, 3);
        gtk::pack(content, fields, false);

        let error = gtk::wrapping("");
        gtk::add_class(error, "authway-bad");
        gtk::pack(content, error, false);
        let buttons = gtk::hbox(8);
        gtk::halign(buttons, gtk::ALIGN_END);
        let cancel = gtk::button(strings::CANCEL);
        let ok = gtk::button(strings::LOGIN_CONNECT);
        gtk::add_class(ok, "suggested-action");
        gtk::pack(buttons, cancel, false);
        gtk::pack(buttons, ok, false);
        gtk::pack(content, buttons, false);
        gtk::add(window, content);

        on_click(ok, Target::LoginConnect);
        on_click(cancel, Target::LoginCancel);
        // Return in any field logs in
        for entry in [username, password, code] {
            on_activate(entry, Target::LoginConnect);
        }
        on_change(code, Target::LoginCode);
        on_close(window);

        let mut login = LoginWindow {
            window,
            heading,
            hint,
            notice,
            error,
            fields,
            username,
            password,
            remember,
            code_label,
            code,
            ok,
            otp_required: form.otp_required,
            checking: form.checking,
            busy: false,
        };
        login.set_notice(form.notice);
        login.layout();
        unsafe { (gtk::g().gtk_widget_show)(window) };
        gtk::present(window);
        login.focus_first_empty();
        login
    }

    // what shows: the fields once the login page said what it asks, the code when it asks one
    fn layout(&self) {
        gtk::set_visible(self.fields, !self.checking);
        gtk::set_visible(self.ok, !self.checking);
        gtk::set_visible(self.code_label, self.otp_required);
        gtk::set_visible(self.code, self.otp_required);
        gtk::set_visible(self.notice, !gtk::text_of(unsafe { (gtk::g().gtk_label_get_text)(self.notice) }).is_empty());
        gtk::set_visible(self.error, !gtk::text_of(unsafe { (gtk::g().gtk_label_get_text)(self.error) }).is_empty());
    }

    fn focus_first_empty(&self) {
        // nothing to type yet
        if self.checking {
            return;
        }
        let values = self.values();
        if values.username.is_empty() {
            gtk::focus(self.username);
        } else if values.password.is_empty() {
            gtk::focus(self.password);
        } else if self.otp_required {
            gtk::focus(self.code);
        } else {
            gtk::focus(self.ok);
        }
    }
}

impl LoginView for LoginWindow {
    fn set_heading(&mut self, text: &str) {
        gtk::set_text(self.heading, text);
        gtk::set_title(self.window, &format!("{}: {}", PRODUCT, text));
    }

    fn set_hint(&mut self, text: &str) {
        gtk::set_text(self.hint, text);
    }

    fn set_notice(&mut self, text: Option<&str>) {
        gtk::set_text(self.notice, text.unwrap_or(""));
        self.layout();
    }

    fn set_error(&mut self, text: Option<&str>) {
        gtk::set_text(self.error, text.unwrap_or(""));
        self.layout();
    }

    fn set_otp_required(&mut self, required: bool) {
        if self.otp_required != required {
            self.otp_required = required;
            self.layout();
        }
    }

    fn set_checking(&mut self, checking: bool) {
        if self.checking != checking {
            self.checking = checking;
            self.layout();
            if !checking {
                self.focus_first_empty();
            }
        }
    }

    fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
        for widget in [self.username, self.password, self.code, self.ok] {
            gtk::set_sensitive(widget, !busy);
        }
        if let Some(remember) = self.remember {
            gtk::set_sensitive(remember, !busy);
        }
        gtk::set_button_text(self.ok, if busy { strings::LOGIN_BUSY } else { strings::LOGIN_CONNECT });
        if !busy {
            self.focus_first_empty();
        }
    }

    fn values(&self) -> LoginValues {
        LoginValues {
            username: gtk::entry_text(self.username).trim().to_string(),
            password: gtk::entry_text(self.password).into(),
            code: gtk::entry_text(self.code),
            remember: self.remember.is_some_and(gtk::is_checked),
        }
    }

    fn clear_code(&self) {
        gtk::set_entry_text(self.code, "");
        gtk::focus(if self.otp_required { self.code } else { self.password });
    }

    // only the digits stay; the code is complete at the sixth one
    fn code_changed(&self) -> bool {
        let text = gtk::entry_text(self.code);
        let digits: String = text.chars().filter(char::is_ascii_digit).take(OTP_LENGTH).collect();
        if digits != text {
            gtk::set_entry_text(self.code, &digits);
        }
        let values = self.values();
        !self.busy && digits.len() == OTP_LENGTH && !values.username.is_empty() && !values.password.is_empty()
    }

    fn activate(&self) {
        gtk::present(self.window);
    }

    fn id(&self) -> usize {
        window_id(self.window)
    }
}

impl Drop for LoginWindow {
    fn drop(&mut self) {
        gtk::destroy(self.window);
    }
}
