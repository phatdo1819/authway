// The window that connects a VPN whose server requires a login: username, password and the code of the
// authenticator app. It opens as the tunnel comes up, so the user types while it connects.

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{sel, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSBackingStoreType, NSButton, NSColor, NSControlStateValueOff, NSControlStateValueOn, NSFont, NSResponder,
    NSSecureTextField, NSTextField, NSView, NSWindow, NSWindowCollectionBehavior, NSWindowStyleMask,
};
use objc2_foundation::{NSPoint, NSRect, NSSize};

use super::{activate, ns, window_id, FlippedView, Target};
use crate::client::{LoginForm, LoginValues, LoginView, OTP_LENGTH};
use crate::names::PRODUCT;
use crate::strings;

const MARGIN: f64 = 20.0;
const WIDTH: f64 = 360.0;
const GAP: f64 = 10.0;
const FIELD_HEIGHT: f64 = 22.0;
const CODE_HEIGHT: f64 = 28.0;
const BUTTON_HEIGHT: f64 = 32.0;

pub struct LoginWindow {
    mtm: MainThreadMarker,
    window: Retained<NSWindow>,
    heading: Retained<NSTextField>,
    hint: Retained<NSTextField>,
    notice: Retained<NSTextField>,
    username_label: Retained<NSTextField>,
    username: Retained<NSTextField>,
    password_label: Retained<NSTextField>,
    password: Retained<NSSecureTextField>,
    remember: Retained<NSButton>,
    code_label: Retained<NSTextField>,
    code: Retained<NSTextField>,
    error: Retained<NSTextField>,
    ok: Retained<NSButton>,
    cancel: Retained<NSButton>,
    otp_required: bool,
    can_remember: bool,
    busy: bool,
}

fn rect(x: f64, y: f64, width: f64, height: f64) -> NSRect {
    NSRect::new(NSPoint::new(x, y), NSSize::new(width, height))
}

// the height of a text that wraps at the width
fn text_height(field: &NSTextField, width: f64) -> f64 {
    field.cell().map_or(17.0, |cell| cell.cellSizeForBounds(rect(0.0, 0.0, width, 10_000.0)).height.ceil())
}

fn text_width(field: &NSTextField) -> f64 {
    field.cell().map_or(80.0, |cell| cell.cellSizeForBounds(rect(0.0, 0.0, 10_000.0, 100.0)).width.ceil())
}

fn wrapping(mtm: MainThreadMarker, text: &str) -> Retained<NSTextField> {
    let field = NSTextField::wrappingLabelWithString(&ns(text), mtm);
    field.setSelectable(false);
    field
}

fn focus(window: &NSWindow, view: &NSView) {
    let responder: &NSResponder = view;
    window.makeFirstResponder(Some(responder));
}

impl LoginWindow {
    pub fn open(mtm: MainThreadMarker, target: &Target, form: LoginForm) -> Option<LoginWindow> {
        let style = NSWindowStyleMask::Titled | NSWindowStyleMask::Closable | NSWindowStyleMask::Miniaturizable;
        let window = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                NSWindow::alloc(mtm),
                rect(0.0, 0.0, WIDTH + MARGIN * 2.0, 300.0),
                style,
                NSBackingStoreType::Buffered,
                false,
            )
        };
        // the Retained owns it
        unsafe { window.setReleasedWhenClosed(false) };
        window.setTitle(&ns(PRODUCT));
        window.setCollectionBehavior(NSWindowCollectionBehavior::MoveToActiveSpace);
        window.setDelegate(Some(ProtocolObject::from_ref(target)));
        let content = FlippedView::new(mtm);
        window.setContentView(Some(&content));

        let label = |text: &str| NSTextField::labelWithString(&ns(text), mtm);
        let button = |text: &str, action| unsafe {
            NSButton::buttonWithTitle_target_action(&ns(text), Some(target.object()), Some(action), mtm)
        };
        let heading = wrapping(mtm, form.heading);
        heading.setFont(Some(&NSFont::boldSystemFontOfSize(16.0)));
        let notice = wrapping(mtm, "");
        notice.setTextColor(Some(&NSColor::systemOrangeColor()));
        let error = wrapping(mtm, "");
        error.setTextColor(Some(&NSColor::systemRedColor()));
        let username = NSTextField::textFieldWithString(&ns(&form.saved.username), mtm);
        let password = NSSecureTextField::new(mtm);
        let remember = unsafe { NSButton::checkboxWithTitle_target_action(&ns(strings::LOGIN_REMEMBER), None, None, mtm) };
        let code = NSTextField::textFieldWithString(&ns(""), mtm);
        code.setFont(Some(&NSFont::systemFontOfSize(18.0)));
        code.setPlaceholderString(Some(&ns(strings::LOGIN_OTP_CUE)));
        unsafe { code.setDelegate(Some(ProtocolObject::from_ref(target))) };
        let ok = button(strings::LOGIN_CONNECT, sel!(connectPressed:));
        ok.setKeyEquivalent(&ns("\r"));
        let cancel = button(strings::CANCEL, sel!(cancelPressed:));
        cancel.setKeyEquivalent(&ns("\u{1b}"));

        let mut login = LoginWindow {
            mtm,
            window,
            heading,
            hint: wrapping(mtm, form.hint),
            notice,
            username_label: label(strings::LOGIN_USERNAME),
            username,
            password_label: label(strings::LOGIN_PASSWORD),
            password,
            remember,
            code_label: label(strings::LOGIN_OTP),
            code,
            error,
            ok,
            cancel,
            otp_required: form.otp_required,
            can_remember: form.can_remember,
            busy: false,
        };
        for view in login.views() {
            content.addSubview(view);
        }
        if form.can_remember {
            if let Some(password) = &form.saved.password {
                login.password.setStringValue(&ns(password));
            }
        }
        // checked the first time, then as the user left it
        let checked = form.can_remember && (form.saved.password.is_some() || form.saved.username.is_empty());
        login.remember.setState(if checked { NSControlStateValueOn } else { NSControlStateValueOff });
        login.remember.setHidden(!form.can_remember);
        login.set_notice(form.notice);
        login.layout();
        login.window.setAutorecalculatesKeyViewLoop(true);
        login.window.center();
        activate(mtm);
        login.window.makeKeyAndOrderFront(None);
        login.focus_first_empty();
        Some(login)
    }

    fn views(&self) -> [&NSView; 13] {
        [
            &self.heading,
            &self.hint,
            &self.notice,
            &self.username_label,
            &self.username,
            &self.password_label,
            &self.password,
            &self.remember,
            &self.code_label,
            &self.code,
            &self.error,
            &self.ok,
            &self.cancel,
        ]
    }

    // from the top, the height of each text as it wraps
    fn layout(&self) {
        let labels = [&self.username_label, &self.password_label, &self.code_label];
        let label_width = labels.iter().map(|label| text_width(label)).fold(0.0, f64::max);
        let field_x = MARGIN + label_width + 12.0;
        let field_width = MARGIN + WIDTH - field_x;
        let line = text_height(&self.username_label, WIDTH);
        let mut y = MARGIN;

        let height = text_height(&self.heading, WIDTH);
        self.heading.setFrame(rect(MARGIN, y, WIDTH, height));
        y += height + 6.0;
        let height = text_height(&self.hint, WIDTH);
        self.hint.setFrame(rect(MARGIN, y, WIDTH, height));
        y += height + 14.0;
        let has_notice = self.notice.stringValue().length() > 0;
        self.notice.setHidden(!has_notice);
        if has_notice {
            let height = text_height(&self.notice, WIDTH);
            self.notice.setFrame(rect(MARGIN, y, WIDTH, height));
            y += height + 12.0;
        }
        let fields: [(&NSTextField, &NSView); 2] =
            [(&self.username_label, &self.username), (&self.password_label, &self.password)];
        for (label, field) in fields {
            label.setFrame(rect(MARGIN, y + (FIELD_HEIGHT - line) / 2.0, label_width, line));
            field.setFrame(rect(field_x, y, field_width, FIELD_HEIGHT));
            y += FIELD_HEIGHT + GAP;
        }
        if self.can_remember {
            self.remember.setFrame(rect(field_x - 2.0, y - 2.0, field_width, 20.0));
            y += 20.0 + GAP;
        }
        self.code_label.setHidden(!self.otp_required);
        self.code.setHidden(!self.otp_required);
        if self.otp_required {
            self.code_label.setFrame(rect(MARGIN, y + (CODE_HEIGHT - line) / 2.0, label_width, line));
            self.code.setFrame(rect(field_x, y, 120.0, CODE_HEIGHT));
            y += CODE_HEIGHT + GAP;
        }
        let has_error = self.error.stringValue().length() > 0;
        self.error.setHidden(!has_error);
        if has_error {
            let height = text_height(&self.error, WIDTH);
            self.error.setFrame(rect(MARGIN, y + 2.0, WIDTH, height));
            y += height + GAP + 2.0;
        }
        y += 8.0;
        let button_width = [strings::LOGIN_CONNECT, strings::LOGIN_BUSY, strings::CANCEL]
            .iter()
            .map(|text| text.chars().count() as f64 * 7.5 + 32.0)
            .fold(96.0, f64::max);
        let cancel_x = MARGIN + WIDTH - button_width;
        self.cancel.setFrame(rect(cancel_x, y, button_width, BUTTON_HEIGHT));
        self.ok.setFrame(rect(cancel_x - 8.0 - button_width, y, button_width, BUTTON_HEIGHT));
        y += BUTTON_HEIGHT + MARGIN;

        // the top of the window stays where it is
        let before = self.window.frame();
        self.window.setContentSize(NSSize::new(WIDTH + MARGIN * 2.0, y));
        let top = before.origin.y + before.size.height;
        self.window.setFrameTopLeftPoint(NSPoint::new(before.origin.x, top));
    }

    fn focus_first_empty(&self) {
        let values = self.values();
        if values.username.is_empty() {
            focus(&self.window, &self.username);
        } else if values.password.is_empty() {
            focus(&self.window, &self.password);
        } else if self.otp_required {
            focus(&self.window, &self.code);
        } else {
            focus(&self.window, &self.ok);
        }
    }
}

impl LoginView for LoginWindow {
    fn set_heading(&mut self, text: &str) {
        if self.heading.stringValue().to_string() != text {
            self.heading.setStringValue(&ns(text));
            self.layout();
        }
    }

    fn set_hint(&mut self, text: &str) {
        if self.hint.stringValue().to_string() != text {
            self.hint.setStringValue(&ns(text));
            self.layout();
        }
    }

    fn set_notice(&mut self, text: Option<&str>) {
        self.notice.setStringValue(&ns(text.unwrap_or("")));
        self.layout();
    }

    fn set_error(&mut self, text: Option<&str>) {
        let text = text.unwrap_or("");
        if self.error.stringValue().to_string() == text {
            return;
        }
        self.error.setStringValue(&ns(text));
        self.layout();
    }

    fn set_otp_required(&mut self, required: bool) {
        if self.otp_required != required {
            self.otp_required = required;
            self.layout();
        }
    }

    fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
        self.username.setEnabled(!busy);
        self.password.setEnabled(!busy);
        self.remember.setEnabled(!busy);
        self.code.setEnabled(!busy);
        self.ok.setEnabled(!busy);
        self.ok.setTitle(&ns(if busy { strings::LOGIN_BUSY } else { strings::LOGIN_CONNECT }));
        if !busy {
            self.focus_first_empty();
        }
    }

    fn values(&self) -> LoginValues {
        LoginValues {
            username: self.username.stringValue().to_string().trim().to_string(),
            password: self.password.stringValue().to_string(),
            code: self.code.stringValue().to_string(),
            remember: self.can_remember && self.remember.state() == NSControlStateValueOn,
        }
    }

    fn clear_code(&self) {
        self.code.setStringValue(&ns(""));
        if self.otp_required {
            focus(&self.window, &self.code);
        } else {
            focus(&self.window, &self.password);
        }
    }

    fn code_changed(&self) -> bool {
        let text = self.code.stringValue().to_string();
        let digits: String = text.chars().filter(char::is_ascii_digit).take(OTP_LENGTH).collect();
        if digits != text {
            self.code.setStringValue(&ns(&digits));
        }
        let values = self.values();
        !self.busy && digits.len() == OTP_LENGTH && !values.username.is_empty() && !values.password.is_empty()
    }

    fn activate(&self) {
        if self.window.isMiniaturized() {
            self.window.deminiaturize(None);
        }
        activate(self.mtm);
        self.window.makeKeyAndOrderFront(None);
    }

    fn id(&self) -> usize {
        window_id(&self.window)
    }
}

impl Drop for LoginWindow {
    fn drop(&mut self) {
        self.window.setDelegate(None);
        self.window.close();
    }
}
