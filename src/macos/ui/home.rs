// The main window, the face of the app on the Mac, as on Windows: a card for each VPN with its switch, its state and,
// while it's on, its traffic; "Add VPN", or a .conf dropped on the window, adds one. A card opens the page of its VPN:
// its traffic over the last minutes, its name and its login to change, all its details and the way to remove it.
// Closing the window leaves the app in the menu bar; the app is in the Dock while the window is open.
//
// It's a view of the App, which it asks for an overview every second; its controls do what the menu of the icon
// does. They are controls of AppKit, so the keyboard and VoiceOver know them. The window lives apart from the App,
// in HOME: the App is busy while its calls open windows, and the window lays out meanwhile.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::ptr;
use std::time::Instant;

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{sel, MainThreadMarker, MainThreadOnly, Message};
use objc2_app_kit::{
    NSAccessibility, NSApplication, NSApplicationActivationPolicy, NSBackingStoreType, NSButton, NSColor,
    NSControlStateValueOff, NSControlStateValueOn, NSFont, NSFontWeightMedium, NSFontWeightRegular,
    NSFontWeightSemibold, NSImage, NSImageSymbolConfiguration, NSImageView, NSLineBreakMode, NSMenu, NSMenuItem,
    NSScrollView, NSSwitch, NSTextAlignment, NSTextField, NSView, NSWindow, NSWindowCollectionBehavior,
    NSWindowStyleMask, NSWindowTitleVisibility,
};
use objc2_foundation::{NSPoint, NSRect, NSSize};

use super::views::{rect, BoxView, ContentView, GraphView, Style};
use super::{activate, error_alert, flows, menu_item, ns, window_id, with_app, FlippedView, Target};
use crate::api::Page as LoginPage;
use crate::client::details::handshake_text;
use crate::client::overview::{Card, History, Overview, Tone, Traffic};
use crate::client::{ServiceState, Shell};
use crate::conf::MAX_NAME_LENGTH;
use crate::creds;
use crate::log;
use crate::names::{PRODUCT, VERSION};
use crate::settings;
use crate::setup::{self, CANCELLED};
use crate::strings;
use crate::time::unix_now;

// in points
const WIDTH: f64 = 420.0;
const HEIGHT: f64 = 640.0;
const MIN_WIDTH: f64 = 360.0;
const MIN_HEIGHT: f64 = 440.0;
const HEADER: f64 = 52.0;
const BANNER: f64 = 44.0;
const MARGIN: f64 = 16.0;
const GAP: f64 = 10.0;
const PAD: f64 = 16.0;
const ICON_BUTTON: f64 = 30.0;
const GRAPH_HEIGHT: f64 = 76.0;
// where macOS keeps the place of the window
const AUTOSAVE: &str = "Authway main window";

// the menu of "More", by the tags of its items
const MENU_ADD: isize = 1;
const MENU_SIGN_IN: isize = 2;
const MENU_APP_LOG: isize = 3;
const MENU_SERVICE_LOG: isize = 4;
const MENU_START_SERVICE: isize = 5;
const MENU_QUIT: isize = 6;

#[derive(Clone, PartialEq, Eq, Debug)]
enum View {
    List,
    // the page of a VPN, by its name
    Vpn(String),
}

pub enum Action {
    // the menu, under its button
    More,
    Back,
    Add,
    StartService,
    Open(String),
    // the name, and whether it's on
    Toggle(String, bool),
    LogIn(String),
    Forget,
    Save,
    Details(String),
    Remove(String),
}

#[derive(Clone, Copy)]
enum Font {
    Title,
    Name,
    Strong,
    Body,
    Small,
    Value,
}

fn font(font: Font) -> Retained<NSFont> {
    let (semibold, medium) = unsafe { (NSFontWeightSemibold, NSFontWeightMedium) };
    match font {
        Font::Title => NSFont::boldSystemFontOfSize(17.0),
        Font::Name => NSFont::systemFontOfSize_weight(14.0, semibold),
        Font::Strong => NSFont::systemFontOfSize_weight(13.0, semibold),
        Font::Body => NSFont::systemFontOfSize(13.0),
        Font::Small => NSFont::systemFontOfSize(11.0),
        Font::Value => NSFont::monospacedDigitSystemFontOfSize_weight(15.0, medium),
    }
}

// a text on one line, cut with an ellipsis
fn label(mtm: MainThreadMarker, size: Font, color: &NSColor) -> Retained<NSTextField> {
    let field = NSTextField::labelWithString(&ns(""), mtm);
    field.setFont(Some(&font(size)));
    field.setTextColor(Some(color));
    field.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
    field
}

// a text on as many lines as it takes
fn wrapping(mtm: MainThreadMarker, size: Font, color: &NSColor) -> Retained<NSTextField> {
    let field = NSTextField::wrappingLabelWithString(&ns(""), mtm);
    field.setFont(Some(&font(size)));
    field.setTextColor(Some(color));
    field.setSelectable(false);
    field
}

fn set_text(field: &NSTextField, text: &str) {
    if field.stringValue().to_string() != text {
        field.setStringValue(&ns(text));
    }
}

// the height of a text that wraps at the width
fn height(field: &NSTextField, width: f64) -> f64 {
    field.cell().map_or(17.0, |cell| cell.cellSizeForBounds(rect(0.0, 0.0, width, 10_000.0)).height.ceil())
}

fn place(view: &NSView, frame: NSRect) {
    if view.frame() != frame {
        view.setFrame(frame);
    }
}

// the size of a control as it shows, without the room that AppKit leaves around it
fn control_size(view: &NSView) -> NSSize {
    let (size, insets) = (view.fittingSize(), view.alignmentRectInsets());
    NSSize::new(size.width - insets.left - insets.right, size.height - insets.top - insets.bottom)
}

// a control with what shows of it at x and y; its size as it shows
fn place_control(view: &NSView, x: f64, y: f64) -> NSSize {
    let (size, insets) = (view.fittingSize(), view.alignmentRectInsets());
    place(view, rect(x - insets.left, y - insets.top, size.width, size.height));
    control_size(view)
}

fn set_hidden(view: &NSView, hidden: bool) {
    if view.isHidden() != hidden {
        view.setHidden(hidden);
    }
}

fn symbol(name: &str, size: f64) -> Option<Retained<NSImage>> {
    let image = NSImage::imageWithSystemSymbolName_accessibilityDescription(&ns(name), None)?;
    let configuration = NSImageSymbolConfiguration::configurationWithPointSize_weight(size, unsafe { NSFontWeightRegular });
    image.imageWithSymbolConfiguration(&configuration)
}

fn button(mtm: MainThreadMarker, target: &Target, title: &str) -> Retained<NSButton> {
    unsafe { NSButton::buttonWithTitle_target_action(&ns(title), Some(target.object()), Some(sel!(homePressed:)), mtm) }
}

// in the accent, as the default button
fn primary(mtm: MainThreadMarker, target: &Target, title: &str, image: Option<&str>) -> Retained<NSButton> {
    let button = match image.and_then(|name| symbol(name, 13.0)) {
        Some(image) => unsafe {
            NSButton::buttonWithTitle_image_target_action(&ns(title), &image, Some(target.object()), Some(sel!(homePressed:)), mtm)
        },
        None => button(mtm, target, title),
    };
    button.setBezelColor(Some(&NSColor::controlAccentColor()));
    button
}

// an icon without a frame; its text for the tooltip and VoiceOver, and in place of the icon if there's none
fn icon_button(mtm: MainThreadMarker, target: &Target, name: &str, size: f64, text: &str) -> Retained<NSButton> {
    let button = match symbol(name, size) {
        Some(image) => unsafe { NSButton::buttonWithImage_target_action(&image, Some(target.object()), Some(sel!(homePressed:)), mtm) },
        None => button(mtm, target, text),
    };
    button.setBordered(false);
    button.setToolTip(Some(&ns(text)));
    button.setAccessibilityLabel(Some(&ns(text)));
    button
}

fn switch(mtm: MainThreadMarker, target: &Target) -> Retained<NSSwitch> {
    let switch = NSSwitch::new(mtm);
    unsafe {
        switch.setTarget(Some(target.object()));
        switch.setAction(Some(sel!(homePressed:)));
    }
    switch
}

fn set_switch(switch: &NSSwitch, card: &Card) {
    let state = if card.on { NSControlStateValueOn } else { NSControlStateValueOff };
    if switch.state() != state {
        switch.setState(state);
    }
    if switch.isEnabled() != card.can_switch {
        switch.setEnabled(card.can_switch);
    }
    switch.setAccessibilityLabel(Some(&ns(&card.name)));
}

fn tone_color(tone: Tone) -> Retained<NSColor> {
    match tone {
        Tone::Off => NSColor::tertiaryLabelColor(),
        Tone::Busy => NSColor::controlAccentColor(),
        Tone::Good => NSColor::systemGreenColor(),
        Tone::Warning => NSColor::systemOrangeColor(),
        Tone::Bad => NSColor::systemRedColor(),
    }
}

fn state_color(tone: Tone) -> Retained<NSColor> {
    match tone {
        Tone::Warning => NSColor::systemOrangeColor(),
        Tone::Bad => NSColor::systemRedColor(),
        _ => NSColor::labelColor(),
    }
}

fn duration_text(traffic: &Traffic) -> String {
    if traffic.since == 0 {
        String::new()
    } else {
        strings::value_duration(unix_now().saturating_sub(traffic.since))
    }
}

// the heights of the lines of each font
struct Lines {
    title: f64,
    name: f64,
    strong: f64,
    body: f64,
    small: f64,
    value: f64,
}

impl Lines {
    fn new(mtm: MainThreadMarker) -> Lines {
        let line = |size: Font| {
            let field = label(mtm, size, &NSColor::labelColor());
            field.setStringValue(&ns("Xy"));
            height(&field, 10_000.0)
        };
        Lines {
            title: line(Font::Title),
            name: line(Font::Name),
            strong: line(Font::Strong),
            body: line(Font::Body),
            small: line(Font::Small),
            value: line(Font::Value),
        }
    }
}

// a VPN of the list
struct CardViews {
    name: String,
    card: Retained<BoxView>,
    title: Retained<NSTextField>,
    sub: Retained<NSTextField>,
    dot: Retained<NSTextField>,
    state: Retained<NSTextField>,
    traffic: Retained<NSTextField>,
    hint: Retained<NSTextField>,
    log_in: Retained<NSButton>,
    switch: Retained<NSSwitch>,
    // the chevron, which opens the page also from the keyboard
    open: Retained<NSButton>,
}

impl CardViews {
    fn new(mtm: MainThreadMarker, target: &Target, document: &NSView, name: &str) -> CardViews {
        let card = BoxView::new(mtm, Style::Card);
        card.set_name(name);
        let (muted, text) = (NSColor::secondaryLabelColor(), NSColor::labelColor());
        let views = CardViews {
            name: name.to_string(),
            title: label(mtm, Font::Name, &text),
            sub: label(mtm, Font::Small, &muted),
            dot: label(mtm, Font::Small, &muted),
            state: label(mtm, Font::Body, &text),
            traffic: label(mtm, Font::Small, &muted),
            hint: wrapping(mtm, Font::Small, &muted),
            log_in: primary(mtm, target, strings::HOME_LOG_IN, None),
            switch: switch(mtm, target),
            open: icon_button(mtm, target, "chevron.right", 13.0, name),
            card,
        };
        views.dot.setStringValue(&ns("\u{25CF}"));
        views.open.setContentTintColor(Some(&NSColor::tertiaryLabelColor()));
        let children: [&NSView; 9] =
            [&views.title, &views.sub, &views.dot, &views.state, &views.traffic, &views.hint, &views.log_in, &views.switch, &views.open];
        for child in children {
            views.card.addSubview(child);
        }
        document.addSubview(&views.card);
        views
    }

    fn fill(&self, card: &Card, history: Option<&History>) {
        set_text(&self.title, &card.name);
        set_text(&self.sub, &card.subtitle());
        self.dot.setTextColor(Some(&tone_color(card.tone)));
        set_text(&self.state, &card.state);
        self.state.setTextColor(Some(&state_color(card.tone)));
        set_hidden(&self.traffic, card.traffic.is_none());
        if let Some(traffic) = &card.traffic {
            let (down, up) = history.map(History::now).unwrap_or((0.0, 0.0));
            let text = format!("\u{2193} {}    \u{2191} {}    {}", strings::value_rate(down), strings::value_rate(up), duration_text(traffic));
            set_text(&self.traffic, &text);
        }
        set_hidden(&self.hint, card.hint.is_none());
        if let Some(hint) = &card.hint {
            set_text(&self.hint, hint);
            self.hint.setTextColor(Some(&state_color(card.tone)));
        }
        set_hidden(&self.log_in, !card.needs_login);
        set_switch(&self.switch, card);
        self.open.setAccessibilityLabel(Some(&ns(&format!("{}: {}", card.name, card.state))));
    }

    // its height, at its width
    fn layout(&self, width: f64, lines: &Lines, card: &Card) -> f64 {
        let switch = control_size(&self.switch);
        let open_width = 14.0;
        let switch_x = width - PAD - open_width - 10.0 - switch.width;
        let text_right = switch_x - 12.0;
        let mut y = PAD;
        let name_top = y;
        place(&self.title, rect(PAD, y, text_right - PAD, lines.name));
        y += lines.name + 2.0;
        place(&self.sub, rect(PAD, y, text_right - PAD, lines.small));
        y += lines.small + 8.0;
        place(&self.dot, rect(PAD - 1.0, y + (lines.body - lines.small) / 2.0, 14.0, lines.small));
        place(&self.state, rect(PAD + 14.0, y, text_right - PAD - 14.0, lines.body));
        y += lines.body;
        let middle = (name_top + y) / 2.0;
        place_control(&self.switch, switch_x, middle - switch.height / 2.0);
        place(&self.open, rect(width - PAD - open_width, middle - 10.0, open_width, 20.0));
        if card.traffic.is_some() {
            y += 4.0;
            place(&self.traffic, rect(PAD, y, text_right - PAD, lines.small));
            y += lines.small;
        }
        if card.hint.is_some() {
            y += 8.0;
            let text_height = height(&self.hint, width - PAD * 2.0);
            place(&self.hint, rect(PAD, y, width - PAD * 2.0, text_height));
            y += text_height;
        }
        if card.needs_login {
            y += 12.0;
            y += place_control(&self.log_in, PAD, y).height;
        }
        y + PAD
    }
}

// the list without VPNs
struct EmptyViews {
    circle: Retained<BoxView>,
    title: Retained<NSTextField>,
    text: Retained<NSTextField>,
    add: Retained<NSButton>,
}

impl EmptyViews {
    fn new(mtm: MainThreadMarker, target: &Target, document: &NSView) -> EmptyViews {
        let circle = BoxView::new(mtm, Style::Circle);
        if let Some(image) = symbol("lock.shield", 36.0) {
            let icon = NSImageView::imageViewWithImage(&image, mtm);
            icon.setContentTintColor(Some(&NSColor::controlAccentColor()));
            icon.setFrame(rect(0.0, 0.0, 88.0, 88.0));
            circle.addSubview(&icon);
        }
        let views = EmptyViews {
            circle,
            title: label(mtm, Font::Title, &NSColor::labelColor()),
            text: wrapping(mtm, Font::Body, &NSColor::secondaryLabelColor()),
            add: primary(mtm, target, strings::HOME_EMPTY_ADD, Some("plus")),
        };
        views.title.setStringValue(&ns(strings::HOME_EMPTY_TITLE));
        views.text.setStringValue(&ns(strings::HOME_EMPTY_TEXT));
        for field in [&views.title, &views.text] {
            field.setAlignment(NSTextAlignment::Center);
        }
        for view in views.views() {
            document.addSubview(view);
        }
        views
    }

    fn views(&self) -> [&NSView; 4] {
        [&self.circle, &self.title, &self.text, &self.add]
    }

    fn set_hidden(&self, hidden: bool) {
        for view in self.views() {
            set_hidden(view, hidden);
        }
    }

    // in the middle: a circle with the icon, a title, what to do and its button
    fn layout(&self, width: f64, lines: &Lines) -> f64 {
        let center = width / 2.0;
        let mut y = 56.0;
        place(&self.circle, rect(center - 44.0, y, 88.0, 88.0));
        y += 88.0 + 20.0;
        place(&self.title, rect(MARGIN, y, width - MARGIN * 2.0, lines.title));
        y += lines.title + 8.0;
        let text_width = (width - MARGIN * 2.0).min(320.0);
        let text_height = height(&self.text, text_width);
        place(&self.text, rect(center - text_width / 2.0, y, text_width, text_height));
        y += text_height + 20.0;
        let size = control_size(&self.add);
        y += place_control(&self.add, center - size.width / 2.0, y).height;
        y + MARGIN + GAP
    }
}

// a label and its value, on the page
struct Pair {
    label: Retained<NSTextField>,
    value: Retained<NSTextField>,
}

// the page of a VPN: its fields stay while the overview changes under them
struct PageViews {
    name: String,
    login: Option<LoginPage>,
    saved_user: String,
    saved_password: bool,
    // the state, the switch and the login
    state_box: Retained<BoxView>,
    dot: Retained<NSTextField>,
    state: Retained<NSTextField>,
    sub: Retained<NSTextField>,
    hint: Retained<NSTextField>,
    switch: Retained<NSSwitch>,
    log_in: Retained<NSButton>,
    // the traffic
    traffic_box: Retained<BoxView>,
    traffic_title: Retained<NSTextField>,
    graph: Retained<GraphView>,
    scale: Retained<NSTextField>,
    // received and sent: their dot, their name, their speed
    speeds: [(Retained<NSTextField>, Retained<NSTextField>, Retained<NSTextField>); 2],
    // duration, handshake, received, sent, address, server
    cells: [Pair; 6],
    off: Retained<NSTextField>,
    routing_label: Retained<NSTextField>,
    routing: Retained<NSTextField>,
    // the settings: the name, the login
    settings_box: Retained<BoxView>,
    settings_title: Retained<NSTextField>,
    name_label: Retained<NSTextField>,
    name_edit: Retained<NSTextField>,
    rename_off: Retained<NSTextField>,
    user_label: Retained<NSTextField>,
    // None without a login page
    user_edit: Option<Retained<NSTextField>>,
    password: Retained<NSTextField>,
    forget: Retained<NSButton>,
    changed: Retained<NSTextField>,
    no_login: Retained<NSTextField>,
    save: Retained<NSButton>,
    // under them
    details: Retained<NSButton>,
    remove: Retained<NSButton>,
}

// an editable field; Return in it saves
fn field(mtm: MainThreadMarker, target: &Target, text: &str) -> Retained<NSTextField> {
    let field = NSTextField::textFieldWithString(&ns(text), mtm);
    field.setFont(Some(&font(Font::Body)));
    unsafe {
        field.setTarget(Some(target.object()));
        field.setAction(Some(sel!(homePressed:)));
        field.setDelegate(Some(ProtocolObject::from_ref(target)));
    }
    if let Some(cell) = field.cell() {
        cell.setSendsActionOnEndEditing(false);
        cell.setScrollable(true);
    }
    field
}

impl PageViews {
    fn new(mtm: MainThreadMarker, target: &Target, document: &NSView, card: &Card) -> PageViews {
        let (muted, text) = (NSColor::secondaryLabelColor(), NSColor::labelColor());
        let titled = |size: Font, title: &str| {
            let field = label(mtm, size, if matches!(size, Font::Small) { &muted } else { &text });
            field.setStringValue(&ns(title));
            field
        };
        let pair = |title: &str| Pair { label: titled(Font::Small, title), value: label(mtm, Font::Strong, &text) };
        let speed = |title: &str, color: Retained<NSColor>| {
            let dot = titled(Font::Small, "\u{25CF}");
            dot.setTextColor(Some(&color));
            (dot, titled(Font::Small, title), label(mtm, Font::Value, &text))
        };
        let saved = card.page.as_ref().map(creds::read);
        let forget = button(mtm, target, strings::HOME_FORGET);
        forget.setBordered(false);
        forget.setContentTintColor(Some(&NSColor::linkColor()));
        let remove = button(mtm, target, strings::HOME_REMOVE);
        remove.setContentTintColor(Some(&NSColor::systemRedColor()));
        let changed = wrapping(mtm, Font::Small, &NSColor::systemOrangeColor());
        let page = PageViews {
            name: card.name.clone(),
            login: card.page,
            saved_user: saved.as_ref().map(|saved| saved.username.clone()).unwrap_or_default(),
            saved_password: saved.as_ref().is_some_and(|saved| saved.password.is_some()),
            state_box: BoxView::new(mtm, Style::Panel),
            dot: titled(Font::Body, "\u{25CF}"),
            state: label(mtm, Font::Name, &text),
            sub: label(mtm, Font::Small, &muted),
            hint: wrapping(mtm, Font::Small, &muted),
            switch: switch(mtm, target),
            log_in: primary(mtm, target, strings::HOME_LOG_IN, None),
            traffic_box: BoxView::new(mtm, Style::Panel),
            traffic_title: titled(Font::Strong, strings::HOME_TRAFFIC),
            graph: GraphView::new(mtm),
            scale: label(mtm, Font::Small, &muted),
            speeds: [speed(strings::HOME_DOWNLOAD, NSColor::controlAccentColor()), speed(strings::HOME_UPLOAD, NSColor::systemTealColor())],
            cells: [
                pair(strings::HOME_DURATION),
                pair(strings::DETAIL_HANDSHAKE),
                pair(strings::DETAIL_RECEIVED),
                pair(strings::DETAIL_SENT),
                pair(strings::HOME_ADDRESS),
                pair(strings::HOME_SERVER),
            ],
            off: wrapping(mtm, Font::Body, &muted),
            routing_label: titled(Font::Small, strings::HOME_ROUTING),
            routing: wrapping(mtm, Font::Body, &text),
            settings_box: BoxView::new(mtm, Style::Panel),
            settings_title: titled(Font::Strong, strings::HOME_SETTINGS),
            name_label: titled(Font::Small, strings::HOME_NAME),
            name_edit: field(mtm, target, &card.name),
            rename_off: titled(Font::Small, strings::HOME_RENAME_OFF),
            user_label: titled(Font::Small, strings::HOME_USERNAME),
            user_edit: saved.as_ref().map(|saved| field(mtm, target, &saved.username)),
            password: wrapping(mtm, Font::Small, &muted),
            forget,
            changed,
            no_login: wrapping(mtm, Font::Small, &muted),
            save: primary(mtm, target, strings::HOME_SAVE, None),
            details: button(mtm, target, strings::HOME_ALL_DETAILS),
            remove,
        };
        page.scale.setAlignment(NSTextAlignment::Right);
        page.off.setStringValue(&ns(strings::HOME_TRAFFIC_OFF));
        page.no_login.setStringValue(&ns(strings::HOME_NO_LOGIN));
        let state: [&NSView; 6] = [&page.dot, &page.state, &page.sub, &page.hint, &page.switch, &page.log_in];
        for view in state {
            page.state_box.addSubview(view);
        }
        let traffic: [&NSView; 6] = [&page.traffic_title, &page.graph, &page.scale, &page.off, &page.routing_label, &page.routing];
        for view in traffic {
            page.traffic_box.addSubview(view);
        }
        for (dot, name, value) in &page.speeds {
            let views: [&NSView; 3] = [dot, name, value];
            for view in views {
                page.traffic_box.addSubview(view);
            }
        }
        for pair in &page.cells {
            page.traffic_box.addSubview(&pair.label);
            page.traffic_box.addSubview(&pair.value);
        }
        let settings: [&NSView; 10] = [
            &page.settings_title,
            &page.name_label,
            &page.name_edit,
            &page.rename_off,
            &page.user_label,
            &page.password,
            &page.forget,
            &page.changed,
            &page.no_login,
            &page.save,
        ];
        for view in settings {
            page.settings_box.addSubview(view);
        }
        if let Some(edit) = &page.user_edit {
            page.settings_box.addSubview(edit);
        }
        for view in page.views() {
            document.addSubview(view);
        }
        page
    }

    // the ones in the document
    fn views(&self) -> [&NSView; 5] {
        [&self.state_box, &self.traffic_box, &self.settings_box, &self.details, &self.remove]
    }

    fn locked(card: &Card) -> bool {
        card.on || !card.can_switch
    }

    fn username(&self) -> Option<String> {
        self.user_edit.as_ref().map(|edit| edit.stringValue().to_string().trim().to_string())
    }

    // a change of username leaves the password of the other one behind
    fn username_changed(&self) -> bool {
        self.saved_password && self.username().is_some_and(|username| username != self.saved_user)
    }

    fn fill(&self, card: &Card, history: Option<&History>) {
        self.dot.setTextColor(Some(&tone_color(card.tone)));
        set_text(&self.state, &card.state);
        self.state.setTextColor(Some(&state_color(card.tone)));
        set_text(&self.sub, &card.subtitle());
        set_hidden(&self.hint, card.hint.is_none());
        if let Some(hint) = &card.hint {
            set_text(&self.hint, hint);
            self.hint.setTextColor(Some(&state_color(card.tone)));
        }
        set_hidden(&self.log_in, !card.needs_login);
        set_switch(&self.switch, card);

        let on = card.traffic.is_some();
        let mut shown: Vec<&NSView> = vec![&self.graph, &self.scale];
        for (dot, name, value) in &self.speeds {
            shown.extend([&**dot as &NSView, name, value]);
        }
        for pair in &self.cells {
            shown.extend([&*pair.label as &NSView, &pair.value]);
        }
        for view in shown {
            set_hidden(view, !on);
        }
        set_hidden(&self.off, on);
        if let Some(traffic) = &card.traffic {
            let (down, up) = history.map(History::now).unwrap_or((0.0, 0.0));
            let top = history.map_or(1024.0, History::top);
            self.graph.set(history.map(|history| history.rates.iter().copied().collect()).unwrap_or_default(), top);
            set_text(&self.scale, &strings::value_rate(top));
            set_text(&self.speeds[0].2, &strings::value_rate(down));
            set_text(&self.speeds[1].2, &strings::value_rate(up));
            let duration = if traffic.since == 0 { strings::VALUE_NOT_YET.to_string() } else { duration_text(traffic) };
            let values = [
                duration,
                handshake_text(traffic.handshake),
                strings::value_bytes(traffic.rx_bytes),
                strings::value_bytes(traffic.tx_bytes),
                if traffic.address.is_empty() { strings::VALUE_NONE.to_string() } else { traffic.address.clone() },
                if traffic.server.is_empty() { card.host.clone() } else { traffic.server.clone() },
            ];
            for (pair, value) in self.cells.iter().zip(values) {
                set_text(&pair.value, &value);
            }
        }
        set_text(&self.routing, &card.routing);

        let locked = Self::locked(card);
        if self.name_edit.isEnabled() == locked {
            self.name_edit.setEnabled(!locked);
        }
        set_hidden(&self.rename_off, !locked);
        let has_login = self.user_edit.is_some();
        set_hidden(&self.user_label, !has_login);
        set_hidden(&self.password, !has_login);
        set_hidden(&self.no_login, has_login);
        set_text(&self.password, if self.saved_password { strings::HOME_PASSWORD_SAVED } else { strings::HOME_PASSWORD_NOT_SAVED });
        set_hidden(&self.forget, !(has_login && self.saved_password));
        set_hidden(&self.changed, !self.username_changed());
        if self.username_changed() {
            set_text(&self.changed, &strings::home_username_changed(&self.saved_user));
        }
    }

    // from the top of the document; where it ends
    fn layout(&self, width: f64, lines: &Lines, card: &Card) -> f64 {
        let box_width = width - MARGIN * 2.0;
        let inner = box_width - PAD * 2.0;
        let mut y = MARGIN;

        // the state, the switch and the login
        let mut top = PAD;
        let switch = control_size(&self.switch);
        let switch_x = box_width - PAD - switch.width;
        place_control(&self.switch, switch_x, top + (lines.name - switch.height) / 2.0);
        place(&self.dot, rect(PAD - 1.0, top, 16.0, lines.name));
        place(&self.state, rect(PAD + 18.0, top, switch_x - 12.0 - PAD - 18.0, lines.name));
        top += lines.name + 4.0;
        if !card.subtitle().is_empty() {
            place(&self.sub, rect(PAD, top, switch_x - 12.0 - PAD, lines.small));
            top += lines.small;
        }
        if card.hint.is_some() {
            top += 10.0;
            let text_height = height(&self.hint, inner);
            place(&self.hint, rect(PAD, top, inner, text_height));
            top += text_height;
        }
        if card.needs_login {
            top += 14.0;
            top += place_control(&self.log_in, PAD, top).height;
        }
        top += PAD;
        place(&self.state_box, rect(MARGIN, y, box_width, top));
        y += top + GAP;

        // the traffic
        let mut top = PAD;
        place(&self.traffic_title, rect(PAD, top, inner, lines.strong));
        top += lines.strong + 12.0;
        let column = PAD + inner / 2.0 + 6.0;
        if card.traffic.is_some() {
            place(&self.graph, rect(PAD, top, inner, GRAPH_HEIGHT));
            place(&self.scale, rect(PAD + 8.0, top + 3.0, inner - 16.0, lines.small));
            top += GRAPH_HEIGHT + 12.0;
            for (index, (dot, name, value)) in self.speeds.iter().enumerate() {
                let x = if index == 0 { PAD } else { column };
                place(dot, rect(x - 1.0, top, 14.0, lines.small));
                place(name, rect(x + 13.0, top, column - PAD - 25.0, lines.small));
                place(value, rect(x, top + lines.small + 2.0, column - PAD - 12.0, lines.value));
            }
            top += lines.small + 2.0 + lines.value + 16.0;
            for row in self.cells.chunks(2) {
                for (index, pair) in row.iter().enumerate() {
                    let (x, end) = if index == 0 { (PAD, column - 12.0) } else { (column, PAD + inner) };
                    place(&pair.label, rect(x, top, end - x, lines.small));
                    place(&pair.value, rect(x, top + lines.small + 2.0, end - x, lines.strong));
                }
                top += lines.small + 2.0 + lines.strong + 14.0;
            }
        } else {
            let text_height = height(&self.off, inner);
            place(&self.off, rect(PAD, top, inner, text_height));
            top += text_height + 14.0;
        }
        place(&self.routing_label, rect(PAD, top, inner, lines.small));
        top += lines.small + 2.0;
        let text_height = height(&self.routing, inner);
        place(&self.routing, rect(PAD, top, inner, text_height));
        top += text_height + PAD;
        place(&self.traffic_box, rect(MARGIN, y, box_width, top));
        y += top + GAP;

        // the settings: the name, the login
        let mut top = PAD;
        place(&self.settings_title, rect(PAD, top, inner, lines.strong));
        top += lines.strong + 14.0;
        place(&self.name_label, rect(PAD, top, inner, lines.small));
        top += lines.small + 6.0;
        let field_height = self.name_edit.fittingSize().height;
        place(&self.name_edit, rect(PAD, top, inner, field_height));
        top += field_height;
        if Self::locked(card) {
            top += 6.0;
            place(&self.rename_off, rect(PAD, top, inner, lines.small));
            top += lines.small;
        }
        top += 16.0;
        match &self.user_edit {
            Some(edit) => {
                place(&self.user_label, rect(PAD, top, inner, lines.small));
                top += lines.small + 6.0;
                place(edit, rect(PAD, top, inner, field_height));
                top += field_height + 10.0;
                let mut text_right = PAD + inner;
                if self.saved_password {
                    let size = control_size(&self.forget);
                    place_control(&self.forget, PAD + inner - size.width, top + (lines.small - size.height) / 2.0);
                    text_right -= size.width + 8.0;
                }
                let text_height = height(&self.password, text_right - PAD);
                place(&self.password, rect(PAD, top, text_right - PAD, text_height));
                top += text_height;
                if self.username_changed() {
                    top += 6.0;
                    let text_height = height(&self.changed, inner);
                    place(&self.changed, rect(PAD, top, inner, text_height));
                    top += text_height;
                }
                top += 16.0;
            }
            None => {
                let text_height = height(&self.no_login, inner);
                place(&self.no_login, rect(PAD, top, inner, text_height));
                top += text_height + 16.0;
            }
        }
        let size = control_size(&self.save);
        top += place_control(&self.save, PAD + inner - size.width, top).height;
        top += PAD;
        place(&self.settings_box, rect(MARGIN, y, box_width, top));
        y += top + GAP + 4.0;

        // all the details, and the removal
        let mut x = MARGIN;
        let mut tallest: f64 = 0.0;
        for button in [&self.details, &self.remove] {
            let size = place_control(button, x, y);
            x += size.width + 10.0;
            tallest = tallest.max(size.height);
        }
        y + tallest + MARGIN
    }

    fn remove_views(&self) {
        for view in self.views() {
            view.removeFromSuperview();
        }
    }
}

struct Changes {
    name: String,
    new_name: Option<String>,
    username: Option<(LoginPage, String)>,
}

pub struct Home {
    mtm: MainThreadMarker,
    target: Retained<Target>,
    window: Retained<NSWindow>,
    content: Retained<ContentView>,
    // the header
    icon: Retained<NSImageView>,
    title: Retained<NSTextField>,
    back: Retained<NSButton>,
    add: Retained<NSButton>,
    more: Retained<NSButton>,
    // the banner, when the service is down
    banner_icon: Retained<NSImageView>,
    banner_text: Retained<NSTextField>,
    start: Retained<NSButton>,
    scroll: Retained<NSScrollView>,
    document: Retained<FlippedView>,
    // over the list while a file is dragged on the window
    drop: Retained<BoxView>,
    drop_text: Retained<NSTextField>,
    lines: Lines,
    overview: Overview,
    view: View,
    cards: Vec<CardViews>,
    empty: EmptyViews,
    page: Option<PageViews>,
    history: HashMap<String, History>,
    // the scroll of the list, while a page is open
    list_scroll: f64,
}

thread_local! {
    static HOME: RefCell<Option<Home>> = const { RefCell::new(None) };
}

fn with_home<R>(action: impl FnOnce(&mut Home) -> R) -> Option<R> {
    HOME.with(|cell| {
        let mut guard = cell.try_borrow_mut().ok()?;
        Some(action(guard.as_mut()?))
    })
}

fn with_home_ref<R>(action: impl FnOnce(&Home) -> R) -> Option<R> {
    HOME.with(|cell| {
        let guard = cell.try_borrow().ok()?;
        Some(action(guard.as_ref()?))
    })
}

impl Home {
    fn open(mtm: MainThreadMarker, target: &Target, overview: Overview) -> Home {
        let style = NSWindowStyleMask::Titled
            | NSWindowStyleMask::Closable
            | NSWindowStyleMask::Miniaturizable
            | NSWindowStyleMask::Resizable;
        let window = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                NSWindow::alloc(mtm),
                rect(0.0, 0.0, WIDTH, HEIGHT),
                style,
                NSBackingStoreType::Buffered,
                false,
            )
        };
        // the Retained owns it
        unsafe { window.setReleasedWhenClosed(false) };
        window.setTitle(&ns(PRODUCT));
        // the header says it: the title bar is part of the window
        window.setTitleVisibility(NSWindowTitleVisibility::Hidden);
        window.setTitlebarAppearsTransparent(true);
        window.setCollectionBehavior(NSWindowCollectionBehavior::MoveToActiveSpace);
        window.setContentMinSize(NSSize::new(MIN_WIDTH, MIN_HEIGHT));
        window.setDelegate(Some(ProtocolObject::from_ref(target)));
        let content = ContentView::new(mtm);
        window.setContentView(Some(&content));

        let application = NSApplication::sharedApplication(mtm);
        let icon = match application.applicationIconImage() {
            Some(image) => NSImageView::imageViewWithImage(&image, mtm),
            None => NSImageView::new(mtm),
        };
        let title = label(mtm, Font::Title, &NSColor::labelColor());
        let back = icon_button(mtm, target, "chevron.left", 17.0, strings::HOME_BACK);
        let add = primary(mtm, target, strings::HOME_ADD, Some("plus"));
        let more = icon_button(mtm, target, "ellipsis.circle", 17.0, strings::HOME_MORE);
        let banner_icon = match symbol("exclamationmark.triangle.fill", 15.0) {
            Some(image) => NSImageView::imageViewWithImage(&image, mtm),
            None => NSImageView::new(mtm),
        };
        banner_icon.setContentTintColor(Some(&NSColor::systemOrangeColor()));
        let banner_text = label(mtm, Font::Body, &NSColor::labelColor());
        banner_text.setStringValue(&ns(strings::MENU_SERVICE_DOWN));
        let start = button(mtm, target, strings::HOME_START_SERVICE);

        let scroll = NSScrollView::initWithFrame(NSScrollView::alloc(mtm), rect(0.0, HEADER, WIDTH, HEIGHT - HEADER));
        scroll.setHasVerticalScroller(true);
        scroll.setAutohidesScrollers(true);
        scroll.setDrawsBackground(false);
        let document = FlippedView::new(mtm);
        scroll.setDocumentView(Some(&document));

        let drop = BoxView::new(mtm, Style::Drop);
        let drop_text = label(mtm, Font::Strong, &NSColor::controlAccentColor());
        drop_text.setStringValue(&ns(strings::HOME_DROP));
        drop_text.setAlignment(NSTextAlignment::Center);
        drop.addSubview(&drop_text);
        drop.setHidden(true);

        // the drop over the rest
        let views: [&NSView; 10] = [&icon, &title, &back, &add, &more, &banner_icon, &banner_text, &start, &scroll, &drop];
        for view in views {
            content.addSubview(view);
        }
        let empty = EmptyViews::new(mtm, target, &document);
        let mut home = Home {
            mtm,
            target: target.retain(),
            window,
            content,
            icon,
            title,
            back,
            add,
            more,
            banner_icon,
            banner_text,
            start,
            scroll,
            document,
            drop,
            drop_text,
            lines: Lines::new(mtm),
            overview,
            view: View::List,
            cards: Vec::new(),
            empty,
            page: None,
            history: HashMap::new(),
            list_scroll: 0.0,
        };
        home.window.setAutorecalculatesKeyViewLoop(true);
        // the middle of the screen the first time, then where the user left it
        home.window.center();
        home.window.setFrameAutosaveName(&ns(AUTOSAVE));
        home.sync();
        home.layout();
        home
    }

    fn visible(&self) -> bool {
        self.window.isVisible()
    }

    // the overview of the App: what changed shows
    fn update(&mut self, overview: Overview) {
        let now = Instant::now();
        for card in &overview.cards {
            match &card.traffic {
                Some(traffic) => self.history.entry(card.name.clone()).or_default().add(now, traffic.rx_bytes, traffic.tx_bytes),
                None => {
                    self.history.remove(&card.name);
                }
            }
        }
        self.history.retain(|name, _| overview.card(name).is_some());
        self.overview = overview;
        if let View::Vpn(name) = &self.view {
            if self.overview.card(name).is_none() {
                self.show_list();
                return;
            }
        }
        // the durations and the graph move every second
        if self.visible() {
            self.sync();
            self.layout();
        }
    }

    fn card(&self) -> Option<&Card> {
        match &self.view {
            View::Vpn(name) => self.overview.card(name),
            View::List => None,
        }
    }

    // The views of the overview: the cards that came, the ones that went, then what each one says
    fn sync(&mut self) {
        let on_list = self.view == View::List;
        let mut previous = std::mem::take(&mut self.cards);
        for card in &self.overview.cards {
            let views = match previous.iter().position(|views| views.name == card.name) {
                Some(index) => previous.remove(index),
                None => CardViews::new(self.mtm, &self.target, &self.document, &card.name),
            };
            self.cards.push(views);
        }
        for gone in previous {
            gone.card.removeFromSuperview();
        }
        for views in &self.cards {
            set_hidden(&views.card, !on_list);
            if let Some(card) = self.overview.card(&views.name) {
                views.fill(card, self.history.get(&card.name));
            }
        }
        let known = !matches!(self.overview.service, ServiceState::Unknown | ServiceState::Unavailable);
        self.empty.set_hidden(!(on_list && self.overview.cards.is_empty() && known));

        set_hidden(&self.icon, !on_list);
        set_hidden(&self.add, !on_list);
        set_hidden(&self.back, on_list);
        let title = match &self.view {
            View::List => PRODUCT.to_string(),
            View::Vpn(name) => name.clone(),
        };
        set_text(&self.title, &title);
        // Esc goes back to the list
        self.back.setKeyEquivalent(&ns(if on_list { "" } else { "\u{1b}" }));
        let down = self.overview.service == ServiceState::Unavailable;
        for view in [&*self.banner_icon as &NSView, &self.banner_text, &self.start] {
            set_hidden(view, !down);
        }

        let card = match &self.view {
            View::Vpn(name) => self.overview.card(name),
            View::List => None,
        };
        if let (Some(page), Some(card)) = (&self.page, card) {
            page.fill(card, self.history.get(&card.name));
        }
        let changed = self.changes().is_some();
        if let Some(page) = &self.page {
            if page.save.isEnabled() != changed {
                page.save.setEnabled(changed);
            }
        }
    }

    // the header, the banner and the list or the page under them
    fn layout(&mut self) {
        let size = self.content.bounds().size;
        let (width, height) = (size.width, size.height);
        let banner = if self.overview.service == ServiceState::Unavailable { BANNER } else { 0.0 };
        self.content.set_bands(HEADER, banner);

        let middle = HEADER / 2.0;
        let more_x = width - MARGIN - ICON_BUTTON + 6.0;
        place(&self.more, rect(more_x, middle - ICON_BUTTON / 2.0, ICON_BUTTON, ICON_BUTTON));
        place(&self.back, rect(MARGIN - 8.0, middle - ICON_BUTTON / 2.0, ICON_BUTTON, ICON_BUTTON));
        place(&self.icon, rect(MARGIN, middle - 12.0, 24.0, 24.0));
        let (title_left, title_right) = match self.view {
            View::List => {
                let add = control_size(&self.add);
                let add_x = more_x - 8.0 - add.width;
                place_control(&self.add, add_x, middle - add.height / 2.0);
                (MARGIN + 24.0 + 10.0, add_x - 8.0)
            }
            View::Vpn(_) => (MARGIN - 8.0 + ICON_BUTTON + 4.0, more_x - 8.0),
        };
        place(&self.title, rect(title_left, middle - self.lines.title / 2.0, title_right - title_left, self.lines.title));
        if banner > 0.0 {
            let middle = HEADER + banner / 2.0;
            place(&self.banner_icon, rect(MARGIN, middle - 10.0, 20.0, 20.0));
            let start = control_size(&self.start);
            let start_x = width - MARGIN - start.width;
            place_control(&self.start, start_x, middle - start.height / 2.0);
            let left = MARGIN + 20.0 + 8.0;
            place(&self.banner_text, rect(left, middle - self.lines.body / 2.0, start_x - 10.0 - left, self.lines.body));
        }
        let top = HEADER + banner;
        place(&self.scroll, rect(0.0, top, width, (height - top).max(0.0)));
        let drop = rect(MARGIN / 2.0, top + MARGIN / 2.0, width - MARGIN, (height - top - MARGIN).max(0.0));
        place(&self.drop, drop);
        place(&self.drop_text, rect(0.0, drop.size.height / 2.0 - self.lines.strong / 2.0, drop.size.width, self.lines.strong));

        // the document: as wide as the scroll view, as high as what it has, at least as the scroll view. Twice when
        // the scroll bar comes or goes, which changes the width
        for _ in 0..2 {
            let visible = self.scroll.contentSize();
            let content = match self.view {
                View::List => self.layout_list(visible.width),
                View::Vpn(_) => match (&self.page, self.card()) {
                    (Some(page), Some(card)) => page.layout(visible.width, &self.lines, card),
                    _ => 0.0,
                },
            };
            let document = NSSize::new(visible.width, content.max(visible.height));
            if self.document.frame().size != document {
                self.document.setFrameSize(document);
            }
            if self.scroll.contentSize().width == visible.width {
                break;
            }
        }
    }

    fn layout_list(&self, width: f64) -> f64 {
        let card_width = width - MARGIN * 2.0;
        let mut y = MARGIN;
        for views in &self.cards {
            let Some(card) = self.overview.card(&views.name) else { continue };
            let card_height = views.layout(card_width, &self.lines, card);
            place(&views.card, rect(MARGIN, y, card_width, card_height));
            y += card_height + GAP;
        }
        if !self.empty.title.isHidden() {
            y = self.empty.layout(width, &self.lines);
        }
        y - GAP + MARGIN / 2.0
    }

    fn scroll_position(&self) -> f64 {
        self.scroll.contentView().bounds().origin.y
    }

    fn scroll_to(&self, position: f64) {
        let most = self.document.frame().size.height - self.scroll.contentSize().height;
        self.document.scrollPoint(NSPoint::new(0.0, position.min(most).max(0.0)));
    }

    // the views

    fn show_list(&mut self) {
        self.close_page();
        self.view = View::List;
        self.sync();
        self.layout();
        self.scroll_to(self.list_scroll);
    }

    fn show_page(&mut self, name: &str) {
        let Some(card) = self.overview.card(name).cloned() else { return };
        if self.view == View::List {
            self.list_scroll = self.scroll_position();
        }
        self.close_page();
        self.page = Some(PageViews::new(self.mtm, &self.target, &self.document, &card));
        self.view = View::Vpn(card.name.clone());
        self.sync();
        self.layout();
        self.scroll_to(0.0);
        // no field takes the keys until the user clicks one
        self.window.makeFirstResponder(None);
    }

    fn close_page(&mut self) {
        if let Some(page) = self.page.take() {
            page.remove_views();
        }
    }

    // after a rename done on the page
    fn page_renamed(&mut self, new_name: &str) {
        if let Some(page) = self.page.as_mut() {
            page.name = new_name.to_string();
        }
        self.view = View::Vpn(new_name.to_string());
        self.history.clear();
    }

    // the saved login again, after a change
    fn reload_login(&mut self) {
        if let Some(page) = self.page.as_mut() {
            if let Some(login) = &page.login {
                let saved = creds::read(login);
                page.saved_password = saved.password.is_some();
                page.saved_user = saved.username;
            }
        }
        self.sync();
        self.layout();
    }

    fn changes(&self) -> Option<Changes> {
        let page = self.page.as_ref()?;
        let new_name = page.name_edit.stringValue().to_string().trim().to_string();
        let username = match (&page.login, page.username()) {
            (Some(login), Some(username)) => Some((*login, username)),
            _ => None,
        };
        let changes = Changes {
            name: page.name.clone(),
            new_name: (new_name != page.name).then_some(new_name),
            username: username.filter(|(_, username)| *username != page.saved_user),
        };
        (changes.new_name.is_some() || changes.username.is_some()).then_some(changes)
    }

    // the login of the page as saved: for "Forget it"
    fn saved_login(&self) -> Option<(LoginPage, String)> {
        let page = self.page.as_ref()?;
        Some((page.login?, page.saved_user.clone()))
    }

    // What a control does
    fn action_of(&self, sender: &NSView) -> Option<Action> {
        let is = |view: &NSView| ptr::eq(view, sender);
        let toggle = |card: &Card| card.can_switch.then(|| Action::Toggle(card.name.clone(), card.on));
        if is(&self.more) {
            return Some(Action::More);
        }
        if is(&self.back) {
            return Some(Action::Back);
        }
        if is(&self.add) || is(&self.empty.add) {
            return Some(Action::Add);
        }
        if is(&self.start) {
            return Some(Action::StartService);
        }
        for views in &self.cards {
            let Some(card) = self.overview.card(&views.name) else { continue };
            if is(&views.switch) {
                return toggle(card);
            }
            if is(&views.log_in) {
                return Some(Action::LogIn(card.name.clone()));
            }
            if is(&views.open) {
                return Some(Action::Open(card.name.clone()));
            }
        }
        let page = self.page.as_ref()?;
        let card = self.card()?;
        if is(&page.switch) {
            return toggle(card);
        }
        if is(&page.log_in) {
            return Some(Action::LogIn(card.name.clone()));
        }
        if is(&page.forget) {
            return Some(Action::Forget);
        }
        if is(&page.save) || is(&page.name_edit) || page.user_edit.as_ref().is_some_and(|edit| is(edit)) {
            return Some(Action::Save);
        }
        if is(&page.details) {
            return Some(Action::Details(card.name.clone()));
        }
        if is(&page.remove) {
            return Some(Action::Remove(card.name.clone()));
        }
        None
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        self.window.setDelegate(None);
        self.window.close();
    }
}

// what the App, the icon, the controls and the flows ask

// Opens the window, or brings it back; the app is in the Dock meanwhile
pub fn show() {
    let Some(mtm) = MainThreadMarker::new() else { return };
    let exists = HOME.with(|cell| cell.try_borrow().map(|home| home.is_some()).unwrap_or(true));
    if !exists {
        let Some((overview, target)) = with_app(|app| (app.overview(), app.shell.target.clone())) else { return };
        let home = Home::open(mtm, &target, overview);
        HOME.with(|cell| {
            if let Ok(mut slot) = cell.try_borrow_mut() {
                *slot = Some(home);
            }
        });
    }
    NSApplication::sharedApplication(mtm).setActivationPolicy(NSApplicationActivationPolicy::Regular);
    // as it is now before it shows: it doesn't lay out while it's hidden
    let overview = with_app(|app| app.overview());
    with_home(|home| {
        if let Some(overview) = overview {
            home.update(overview);
        }
        home.sync();
        home.layout();
        if home.window.isMiniaturized() {
            home.window.deminiaturize(None);
        }
        activate(mtm);
        home.window.makeKeyAndOrderFront(None);
    });
}

// the overview of the App, every second and after each change
pub fn refresh() {
    let open = HOME.with(|cell| cell.try_borrow().map(|home| home.is_some()).unwrap_or(false));
    if !open {
        return;
    }
    let Some(overview) = with_app(|app| app.overview()) else { return };
    with_home(|home| home.update(overview));
}

// at the end of the app
pub fn close() {
    let home = HOME.with(|cell| cell.try_borrow_mut().ok().and_then(|mut slot| slot.take()));
    drop(home);
}

pub fn is_home(id: usize) -> bool {
    with_home_ref(|home| window_id(&home.window) == id).unwrap_or(false)
}

// The close button and Cmd+W: the app stays in the menu bar, out of the Dock. It says so the first time.
pub fn hide() {
    let Some(mtm) = MainThreadMarker::new() else { return };
    let first = !settings::close_notice_shown();
    with_home_ref(|home| home.window.orderOut(None));
    NSApplication::sharedApplication(mtm).setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    if first {
        settings::set_close_notice_shown();
        with_app(|app| app.shell.notify(&strings::notice_still_running(), false));
    }
}

pub fn resized(id: usize) {
    with_home(|home| {
        if window_id(&home.window) == id {
            home.layout();
        }
    });
}

// a key in the name or the username
pub fn text_changed() {
    with_home(|home| {
        // as long as the service takes it
        if let Some(page) = &home.page {
            let text = page.name_edit.stringValue().to_string();
            if text.chars().count() > MAX_NAME_LENGTH {
                page.name_edit.setStringValue(&ns(&text.chars().take(MAX_NAME_LENGTH).collect::<String>()));
            }
        }
        home.sync();
        home.layout();
    });
}

pub fn action_of(sender: &NSView) -> Option<Action> {
    with_home_ref(|home| home.action_of(sender)).flatten()
}

// a click on a card
pub fn open_page(name: &str) {
    run(Action::Open(name.to_string()));
}

// a file dragged on the window, or no more
pub fn dragging(on: bool) {
    with_home_ref(|home| set_hidden(&home.drop, !on));
}

// the files dropped on the window, one after the other
pub fn dropped(files: Vec<PathBuf>) {
    let Some(mtm) = MainThreadMarker::new() else { return };
    activate(mtm);
    for path in files {
        flows::import_path(mtm, &path);
    }
    refresh();
}

pub fn run(action: Action) {
    let Some(mtm) = MainThreadMarker::new() else { return };
    match action {
        Action::More => more_menu(mtm),
        Action::Back => {
            with_home(|home| home.show_list());
        }
        Action::Add => flows::import_from_file(mtm),
        Action::StartService => {
            match setup::start_service() {
                Ok(()) => {}
                Err(error) if error == CANCELLED => {}
                Err(error) => error_alert(mtm, &error),
            }
            with_app(|app| app.list_soon());
        }
        Action::Open(name) => {
            with_home(|home| home.show_page(&name));
        }
        Action::Toggle(name, on) => {
            with_app(|app| if on { app.disconnect(&name) } else { app.connect(&name) });
        }
        Action::LogIn(name) => {
            with_app(|app| app.show_login(&name, None));
        }
        Action::Forget => {
            if let Some((page, username)) = with_home_ref(|home| home.saved_login()).flatten() {
                if !creds::save(&page, &username, None) {
                    log!("can't forget the password of {}", page);
                }
            }
            with_home(|home| home.reload_login());
        }
        Action::Save => save(mtm),
        Action::Details(name) => {
            with_app(|app| app.show_details(&name));
        }
        Action::Remove(name) => flows::remove(mtm, &name),
    }
    refresh();
}

// the username, then the name: the login doesn't depend on the name
fn save(mtm: MainThreadMarker) {
    let Some(changes) = with_home_ref(|home| home.changes()).flatten() else { return };
    if let Some((page, username)) = &changes.username {
        // the password saved was the one of the other username
        let saved = if username.is_empty() {
            creds::delete(page);
            true
        } else {
            creds::save(page, username, None)
        };
        if !saved {
            log!("can't save the username for {}", page);
        }
    }
    if let Some(new_name) = &changes.new_name {
        if flows::rename(mtm, &changes.name, new_name) {
            with_home(|home| home.page_renamed(new_name));
        }
    }
    with_home(|home| home.reload_login());
}

fn more_menu(mtm: MainThreadMarker) {
    let Some((button, target)) = with_home_ref(|home| (home.more.clone(), home.target.clone())) else { return };
    let service_down = with_app(|app| app.service_state() == ServiceState::Unavailable).unwrap_or(false);
    let item = |title: &str, tag: isize| {
        let entry = menu_item(mtm, title, Some(sel!(homeMenu:)));
        unsafe { entry.setTarget(Some(target.object())) };
        entry.setTag(tag);
        entry
    };
    let menu = NSMenu::new(mtm);
    menu.setAutoenablesItems(false);
    menu.addItem(&item(strings::MENU_IMPORT, MENU_ADD));
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    let sign_in = item(strings::MENU_OPEN_AT_SIGN_IN, MENU_SIGN_IN);
    if settings::open_at_sign_in() {
        sign_in.setState(NSControlStateValueOn);
    }
    menu.addItem(&sign_in);
    let logs = NSMenu::initWithTitle(NSMenu::alloc(mtm), &ns(strings::MENU_LOGS));
    logs.setAutoenablesItems(false);
    logs.addItem(&item(strings::MENU_APP_LOG, MENU_APP_LOG));
    logs.addItem(&item(strings::MENU_SERVICE_LOG, MENU_SERVICE_LOG));
    let logs_item = menu_item(mtm, strings::MENU_LOGS, None);
    logs_item.setSubmenu(Some(&logs));
    menu.addItem(&logs_item);
    if service_down {
        menu.addItem(&item(strings::MENU_START_SERVICE, MENU_START_SERVICE));
    }
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    let version = menu_item(mtm, &strings::menu_version(VERSION), None);
    version.setEnabled(false);
    menu.addItem(&version);
    menu.addItem(&item(strings::MENU_QUIT, MENU_QUIT));
    // under the button, its right edge on the right of the button
    let bounds = button.bounds();
    let y = if button.isFlipped() { bounds.size.height + 4.0 } else { -4.0 };
    let x = bounds.size.width - menu.size().width;
    menu.popUpMenuPositioningItem_atLocation_inView(None, NSPoint::new(x, y), Some(&button));
}

pub fn menu_chosen(tag: isize) {
    let Some(mtm) = MainThreadMarker::new() else { return };
    match tag {
        MENU_ADD => flows::import_from_file(mtm),
        MENU_SIGN_IN => settings::set_open_at_sign_in(!settings::open_at_sign_in()),
        MENU_APP_LOG => {
            if let Some(path) = log::path() {
                setup::open_log(&path);
            }
        }
        MENU_SERVICE_LOG => setup::open_log(&crate::service::log_path()),
        MENU_START_SERVICE => run(Action::StartService),
        MENU_QUIT => flows::quit(mtm, true),
        _ => {}
    }
}
