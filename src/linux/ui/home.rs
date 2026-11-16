// The main window, the face of the app on Linux as on Windows and macOS: a card for each VPN with its switch, its
// state and, while it's on, its traffic; "Add VPN" adds one. A card opens the page of its VPN: its traffic over the
// last minutes, its name and its login to change, all its details and the way to remove it. Closing the window leaves
// the app in the tray; without a tray, the app keeps running and the menu of the applications opens it again.
//
// It's a view of the App, which it asks for an overview every second; its controls do what the menu of the tray does.
// They are widgets of GTK, so the keyboard and the screen readers know them. The window lives apart from the App, in
// HOME: the App is busy while its calls open windows.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::time::Instant;

use super::gtk::{self, Widget};
use super::{flows, on_activate, on_change, on_click, on_close, on_draw, on_press, on_switch, set_switch, window_id, with_app, Target};
use crate::api::Page as LoginPage;
use crate::client::details::handshake_text;
use crate::client::overview::{Card, History, Overview, Tone, Traffic, SAMPLES};
use crate::client::{Command, ServiceState, Shell};
use crate::conf::MAX_NAME_LENGTH;
use crate::creds;
use crate::log;
use crate::names::{PRODUCT, VERSION};
use crate::settings;
use crate::strings;
use crate::time::unix_now;

const TONES: [&str; 5] = ["authway-off", "authway-busy", "authway-good", "authway-warning", "authway-bad"];

#[derive(Clone, PartialEq, Eq, Debug)]
enum View {
    List,
    // the page of a VPN, by its name
    Vpn(String),
}

#[derive(Clone)]
pub enum Action {
    More,
    Back,
    Add,
    StartService,
    Open(String),
    // the switch of a VPN: the state asked comes with the signal
    Switch(String),
    LogIn(String),
    Forget,
    Save,
    Details(String),
    Remove(String),
    // the field of the name or of the username changed
    Edited,
    // an item of the menu of "More"
    OpenAtSignIn,
    AppLog,
    ServiceLog,
    Quit,
}

fn tone_class(tone: Tone) -> &'static str {
    match tone {
        Tone::Off => "authway-off",
        Tone::Busy => "authway-busy",
        Tone::Good => "authway-good",
        Tone::Warning => "authway-warning",
        Tone::Bad => "authway-bad",
    }
}

// the color of a state in words: its tone when it asks for attention
fn state_class(tone: Tone) -> &'static str {
    match tone {
        Tone::Warning => "authway-warning",
        Tone::Bad => "authway-bad",
        _ => "authway-plain",
    }
}

fn duration_text(traffic: &Traffic) -> String {
    if traffic.since == 0 {
        String::new()
    } else {
        strings::value_duration(unix_now().saturating_sub(traffic.since))
    }
}

fn small(widget: Widget) -> Widget {
    gtk::add_class(widget, "authway-small");
    widget
}

fn dim(widget: Widget) -> Widget {
    gtk::add_class(widget, "authway-dim");
    widget
}

fn heading(text: &str) -> Widget {
    let label = gtk::label(text);
    gtk::add_class(label, "authway-heading");
    label
}

// a box with a frame, for a card or a part of a page
fn framed(class: &str, spacing: i32) -> (Widget, Widget) {
    let inner = gtk::vbox(spacing);
    gtk::margins(inner, 12, 14, 12);
    let frame = gtk::event_box(inner);
    gtk::add_class(frame, class);
    (frame, inner)
}

// a VPN of the list
struct CardViews {
    name: String,
    root: Widget,
    switch: Widget,
    title: Widget,
    sub: Widget,
    dot: Widget,
    state: Widget,
    hint: Widget,
    log_in: Widget,
    traffic: Widget,
}

impl CardViews {
    fn new(list: Widget, name: &str) -> CardViews {
        let (root, inner) = framed("authway-card", 4);
        let top = gtk::hbox(8);
        let title = gtk::ellipsized(name);
        gtk::add_class(title, "authway-name");
        gtk::pack(top, title, true);
        let switch = gtk::switch();
        gtk::pack_end(top, switch);
        gtk::pack(inner, top, false);
        let sub = dim(small(gtk::ellipsized("")));
        gtk::pack(inner, sub, false);
        let row = gtk::hbox(6);
        let dot = gtk::label("\u{25cf}");
        gtk::pack(row, dot, false);
        let state = gtk::ellipsized("");
        gtk::pack(row, state, true);
        gtk::pack(inner, row, false);
        let hint = small(gtk::wrapping(""));
        gtk::pack(inner, hint, false);
        let traffic = dim(small(gtk::label("")));
        gtk::pack(inner, traffic, false);
        let log_in = gtk::button(strings::HOME_LOG_IN);
        gtk::add_class(log_in, "suggested-action");
        gtk::halign(log_in, gtk::ALIGN_START);
        gtk::pack(inner, log_in, false);
        gtk::pack(list, root, false);
        on_press(root, Target::Home(Action::Open(name.to_string())));
        on_switch(switch, Target::Home(Action::Switch(name.to_string())));
        on_click(log_in, Target::Home(Action::LogIn(name.to_string())));
        CardViews { name: name.to_string(), root, switch, title, sub, dot, state, hint, log_in, traffic }
    }

    fn fill(&self, card: &Card, history: Option<&History>) {
        gtk::set_text(self.title, &card.name);
        let subtitle = card.subtitle();
        gtk::set_text(self.sub, &subtitle);
        gtk::set_visible(self.sub, !subtitle.is_empty());
        gtk::set_class(self.dot, &TONES, tone_class(card.tone));
        gtk::set_text(self.state, &card.state);
        gtk::set_class(self.state, &["authway-warning", "authway-bad", "authway-plain"], state_class(card.tone));
        gtk::set_visible(self.traffic, card.traffic.is_some());
        if let Some(traffic) = &card.traffic {
            let (down, up) = history.map(History::now).unwrap_or((0.0, 0.0));
            let text = format!(
                "\u{2193} {}    \u{2191} {}    {}",
                strings::value_rate(down),
                strings::value_rate(up),
                duration_text(traffic)
            );
            gtk::set_text(self.traffic, &text);
        }
        gtk::set_visible(self.hint, card.hint.is_some());
        if let Some(hint) = &card.hint {
            gtk::set_text(self.hint, hint);
            gtk::set_class(self.hint, &["authway-warning", "authway-bad", "authway-plain"], state_class(card.tone));
        }
        gtk::set_visible(self.log_in, card.needs_login);
        set_switch(self.switch, card.on);
        gtk::set_sensitive(self.switch, card.can_switch);
    }
}

// the list without VPNs
fn empty_views(list: Widget) -> Widget {
    let empty = gtk::vbox(10);
    gtk::margins(empty, 48, 24, 24);
    let icon = gtk::image(&PRODUCT.to_lowercase(), 64);
    gtk::pack(empty, icon, false);
    let title = gtk::label(strings::HOME_EMPTY_TITLE);
    gtk::add_class(title, "authway-big");
    gtk::halign(title, gtk::ALIGN_CENTER);
    gtk::pack(empty, title, false);
    let text = dim(gtk::wrapping(strings::HOME_EMPTY_TEXT));
    unsafe { (gtk::g().gtk_label_set_xalign)(text, 0.5) };
    gtk::halign(text, gtk::ALIGN_CENTER);
    gtk::pack(empty, text, false);
    let add = gtk::button(strings::HOME_EMPTY_ADD);
    gtk::add_class(add, "suggested-action");
    gtk::halign(add, gtk::ALIGN_CENTER);
    gtk::pack(empty, add, false);
    on_click(add, Target::Home(Action::Add));
    gtk::pack(list, empty, false);
    empty
}

// the page of a VPN: its fields stay while the overview changes under them
struct PageViews {
    name: String,
    login: Option<LoginPage>,
    saved_user: String,
    saved_password: bool,
    root: Widget,
    // the state, the switch and the login
    dot: Widget,
    state: Widget,
    sub: Widget,
    hint: Widget,
    switch: Widget,
    log_in: Widget,
    // the traffic, while it's on
    traffic: Widget,
    graph: Widget,
    scale: Widget,
    speeds: [Widget; 2],
    // duration, handshake, received, sent, address, server
    cells: [Widget; 6],
    off: Widget,
    routing: Widget,
    // the settings: the name, the login
    name_edit: Widget,
    rename_off: Widget,
    user_label: Widget,
    // None without a login page
    user_edit: Option<Widget>,
    password: Widget,
    forget: Widget,
    changed: Widget,
    no_login: Widget,
    save: Widget,
}

impl PageViews {
    fn new(container: Widget, card: &Card) -> PageViews {
        let root = gtk::vbox(12);
        gtk::margins(root, 16, 16, 16);
        let name = card.name.clone();
        let saved = card.page.as_ref().map(creds::read);

        // the state
        let (state_box, state_inner) = framed("authway-box", 6);
        let top = gtk::hbox(8);
        let dot = gtk::label("\u{25cf}");
        gtk::pack(top, dot, false);
        let state = gtk::ellipsized("");
        gtk::add_class(state, "authway-name");
        gtk::pack(top, state, true);
        let switch = gtk::switch();
        gtk::pack_end(top, switch);
        gtk::pack(state_inner, top, false);
        let sub = dim(small(gtk::ellipsized("")));
        gtk::pack(state_inner, sub, false);
        let hint = small(gtk::wrapping(""));
        gtk::pack(state_inner, hint, false);
        let log_in = gtk::button(strings::HOME_LOG_IN);
        gtk::add_class(log_in, "suggested-action");
        gtk::halign(log_in, gtk::ALIGN_START);
        gtk::pack(state_inner, log_in, false);
        gtk::pack(root, state_box, false);

        // the traffic
        let (traffic_box, traffic_inner) = framed("authway-box", 8);
        gtk::pack(traffic_inner, heading(strings::HOME_TRAFFIC), false);
        let traffic = gtk::vbox(8);
        let scale = dim(small(gtk::label("")));
        gtk::halign(scale, gtk::ALIGN_END);
        gtk::pack(traffic, scale, false);
        let graph = gtk::drawing_area(76);
        on_draw(graph);
        gtk::pack(traffic, graph, false);
        let speeds_row = gtk::hbox(24);
        let speed = |title: &str, class: &str| {
            let column = gtk::vbox(2);
            let line = gtk::hbox(6);
            let dot = gtk::label("\u{25cf}");
            gtk::add_class(dot, class);
            gtk::pack(line, dot, false);
            gtk::pack(line, dim(small(gtk::label(title))), false);
            gtk::pack(column, line, false);
            let value = gtk::label("");
            gtk::add_class(value, "authway-heading");
            gtk::pack(column, value, false);
            gtk::pack(speeds_row, column, false);
            value
        };
        let speeds = [speed(strings::HOME_DOWNLOAD, "authway-download"), speed(strings::HOME_UPLOAD, "authway-upload")];
        gtk::pack(traffic, speeds_row, false);
        let grid = gtk::grid();
        let titles = [
            strings::HOME_DURATION,
            strings::DETAIL_HANDSHAKE,
            strings::DETAIL_RECEIVED,
            strings::DETAIL_SENT,
            strings::HOME_ADDRESS,
            strings::HOME_SERVER,
        ];
        // a title and its value on each line of the grid
        let cells: [Widget; 6] = std::array::from_fn(|row| {
            let value = gtk::ellipsized("");
            gtk::attach(grid, dim(small(gtk::label(titles[row]))), 0, row as i32);
            gtk::attach(grid, value, 1, row as i32);
            gtk::hexpand(value);
            value
        });
        gtk::pack(traffic, grid, false);
        gtk::pack(traffic_inner, traffic, false);
        let off = dim(gtk::wrapping(strings::HOME_TRAFFIC_OFF));
        gtk::pack(traffic_inner, off, false);
        gtk::pack(traffic_inner, dim(small(gtk::label(strings::HOME_ROUTING))), false);
        let routing = gtk::wrapping("");
        gtk::pack(traffic_inner, routing, false);
        gtk::pack(root, traffic_box, false);

        // the settings
        let (settings_box, settings_inner) = framed("authway-box", 6);
        gtk::pack(settings_inner, heading(strings::HOME_SETTINGS), false);
        gtk::pack(settings_inner, dim(small(gtk::label(strings::HOME_NAME))), false);
        let name_edit = gtk::entry(&name);
        unsafe { (gtk::g().gtk_entry_set_max_length)(name_edit, MAX_NAME_LENGTH as i32) };
        on_change(name_edit, Target::Home(Action::Edited));
        on_activate(name_edit, Target::Home(Action::Save));
        gtk::pack(settings_inner, name_edit, false);
        let rename_off = dim(small(gtk::wrapping(strings::HOME_RENAME_OFF)));
        gtk::pack(settings_inner, rename_off, false);
        let user_label = dim(small(gtk::label(strings::HOME_USERNAME)));
        gtk::pack(settings_inner, user_label, false);
        let user_edit = saved.as_ref().map(|saved| {
            let edit = gtk::entry(&saved.username);
            on_change(edit, Target::Home(Action::Edited));
            on_activate(edit, Target::Home(Action::Save));
            gtk::pack(settings_inner, edit, false);
            edit
        });
        let password_row = gtk::hbox(8);
        let password = dim(small(gtk::wrapping("")));
        gtk::pack(password_row, password, true);
        let forget = gtk::button(strings::HOME_FORGET);
        on_click(forget, Target::Home(Action::Forget));
        gtk::pack_end(password_row, forget);
        gtk::pack(settings_inner, password_row, false);
        let changed = small(gtk::wrapping(""));
        gtk::add_class(changed, "authway-warning");
        gtk::pack(settings_inner, changed, false);
        let no_login = dim(small(gtk::wrapping(strings::HOME_NO_LOGIN)));
        gtk::pack(settings_inner, no_login, false);
        let save = gtk::button(strings::HOME_SAVE);
        gtk::add_class(save, "suggested-action");
        gtk::halign(save, gtk::ALIGN_END);
        on_click(save, Target::Home(Action::Save));
        gtk::pack(settings_inner, save, false);
        gtk::pack(root, settings_box, false);

        // under them
        let buttons = gtk::hbox(8);
        let details = gtk::button(strings::HOME_ALL_DETAILS);
        on_click(details, Target::Home(Action::Details(name.clone())));
        gtk::pack(buttons, details, false);
        let remove = gtk::button(strings::HOME_REMOVE);
        gtk::add_class(remove, "destructive-action");
        on_click(remove, Target::Home(Action::Remove(name.clone())));
        gtk::pack_end(buttons, remove);
        gtk::pack(root, buttons, false);

        on_switch(switch, Target::Home(Action::Switch(name.clone())));
        on_click(log_in, Target::Home(Action::LogIn(name.clone())));
        gtk::pack(container, root, false);
        PageViews {
            name,
            login: card.page,
            saved_user: saved.as_ref().map(|saved| saved.username.clone()).unwrap_or_default(),
            saved_password: saved.as_ref().is_some_and(|saved| saved.password.is_some()),
            root,
            dot,
            state,
            sub,
            hint,
            switch,
            log_in,
            traffic,
            graph,
            scale,
            speeds,
            cells,
            off,
            routing,
            name_edit,
            rename_off,
            user_label,
            user_edit,
            password,
            forget,
            changed,
            no_login,
            save,
        }
    }

    // a VPN on, or turning off, can't be renamed: the app knows the tunnels that are on by their names
    fn locked(card: &Card) -> bool {
        card.on || !card.can_switch
    }

    fn username(&self) -> Option<String> {
        self.user_edit.map(|edit| gtk::entry_text(edit).trim().to_string())
    }

    // a change of username leaves the password of the other one behind
    fn username_changed(&self) -> bool {
        self.saved_password && self.username().is_some_and(|username| username != self.saved_user)
    }

    fn fill(&self, card: &Card, history: Option<&History>) {
        gtk::set_class(self.dot, &TONES, tone_class(card.tone));
        gtk::set_text(self.state, &card.state);
        gtk::set_class(self.state, &["authway-warning", "authway-bad", "authway-plain"], state_class(card.tone));
        let subtitle = card.subtitle();
        gtk::set_text(self.sub, &subtitle);
        gtk::set_visible(self.sub, !subtitle.is_empty());
        gtk::set_visible(self.hint, card.hint.is_some());
        if let Some(hint) = &card.hint {
            gtk::set_text(self.hint, hint);
            gtk::set_class(self.hint, &["authway-warning", "authway-bad", "authway-plain"], state_class(card.tone));
        }
        gtk::set_visible(self.log_in, card.needs_login);
        set_switch(self.switch, card.on);
        gtk::set_sensitive(self.switch, card.can_switch);

        gtk::set_visible(self.traffic, card.traffic.is_some());
        gtk::set_visible(self.off, card.traffic.is_none());
        if let Some(traffic) = &card.traffic {
            let (down, up) = history.map(History::now).unwrap_or((0.0, 0.0));
            let top = history.map_or(1024.0, History::top);
            gtk::set_text(self.scale, &strings::value_rate(top));
            gtk::set_text(self.speeds[0], &strings::value_rate(down));
            gtk::set_text(self.speeds[1], &strings::value_rate(up));
            let duration = if traffic.since == 0 { strings::VALUE_NOT_YET.to_string() } else { duration_text(traffic) };
            let values = [
                duration,
                handshake_text(traffic.handshake),
                strings::value_bytes(traffic.rx_bytes),
                strings::value_bytes(traffic.tx_bytes),
                if traffic.address.is_empty() { strings::VALUE_NONE.to_string() } else { traffic.address.clone() },
                if traffic.server.is_empty() { card.host.clone() } else { traffic.server.clone() },
            ];
            for (cell, value) in self.cells.iter().zip(values) {
                gtk::set_text(*cell, &value);
            }
            gtk::redraw(self.graph);
        }
        gtk::set_text(self.routing, &card.routing);

        let locked = Self::locked(card);
        gtk::set_sensitive(self.name_edit, !locked);
        gtk::set_visible(self.rename_off, locked);
        let has_login = self.user_edit.is_some();
        gtk::set_visible(self.user_label, has_login);
        gtk::set_visible(self.password, has_login);
        gtk::set_visible(self.no_login, !has_login);
        gtk::set_text(self.password, if self.saved_password { strings::HOME_PASSWORD_SAVED } else { strings::HOME_PASSWORD_NOT_SAVED });
        gtk::set_visible(self.forget, has_login && self.saved_password);
        gtk::set_visible(self.changed, self.username_changed());
        if self.username_changed() {
            gtk::set_text(self.changed, &strings::home_username_changed(&self.saved_user));
        }
    }
}

thread_local! {
    static HOME: RefCell<Option<Home>> = const { RefCell::new(None) };
    // the notice that the desktop has no tray, once a run
    static NO_TRAY_SAID: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct Changes {
    name: String,
    new_name: Option<String>,
    username: Option<(LoginPage, String)>,
}

pub struct Home {
    window: Widget,
    header: Widget,
    back: Widget,
    add: Widget,
    more: Widget,
    banner: Widget,
    list_scroll: Widget,
    list: Widget,
    empty: Widget,
    page_scroll: Widget,
    page_box: Widget,
    // the menu of "More" that's open, made again each time
    menu: Option<Widget>,
    overview: Overview,
    view: View,
    cards: Vec<CardViews>,
    page: Option<PageViews>,
    history: HashMap<String, History>,
}

fn with_home<R>(action: impl FnOnce(&mut Home) -> R) -> Option<R> {
    HOME.with(|cell| {
        let mut guard = cell.try_borrow_mut().ok()?;
        let home = guard.as_mut()?;
        Some(action(home))
    })
}

fn with_home_ref<R>(action: impl FnOnce(&Home) -> R) -> Option<R> {
    HOME.with(|cell| {
        let guard = cell.try_borrow().ok()?;
        let home = guard.as_ref()?;
        Some(action(home))
    })
}

impl Home {
    fn open(overview: Overview) -> Home {
        let window = gtk::window(PRODUCT, 440, 660);
        unsafe { (gtk::g().gtk_widget_set_size_request)(window, 360, 440) };
        let header = unsafe { (gtk::g().gtk_header_bar_new)() };
        unsafe {
            (gtk::g().gtk_widget_show)(header);
            (gtk::g().gtk_header_bar_set_show_close_button)(header, 1);
            (gtk::g().gtk_header_bar_set_title)(header, gtk::c(PRODUCT).as_ptr());
            (gtk::g().gtk_window_set_titlebar)(window, header);
        }
        let back = gtk::icon_button("go-previous-symbolic", strings::HOME_BACK);
        let add = gtk::icon_button("list-add-symbolic", strings::HOME_ADD);
        let more = gtk::icon_button("open-menu-symbolic", strings::HOME_MORE);
        unsafe {
            (gtk::g().gtk_header_bar_pack_start)(header, back);
            (gtk::g().gtk_header_bar_pack_start)(header, add);
            (gtk::g().gtk_header_bar_pack_end)(header, more);
        }
        on_click(back, Target::Home(Action::Back));
        on_click(add, Target::Home(Action::Add));
        on_click(more, Target::Home(Action::More));

        let content = gtk::vbox(0);
        let banner_inner = gtk::hbox(10);
        gtk::margins(banner_inner, 8, 12, 8);
        gtk::pack(banner_inner, gtk::image("dialog-warning-symbolic", 16), false);
        let banner_text = gtk::wrapping(strings::MENU_SERVICE_DOWN);
        gtk::pack(banner_inner, banner_text, true);
        let start = gtk::button(strings::HOME_START_SERVICE);
        gtk::valign(start, gtk::ALIGN_CENTER);
        on_click(start, Target::Home(Action::StartService));
        gtk::pack_end(banner_inner, start);
        let banner = gtk::event_box(banner_inner);
        gtk::add_class(banner, "authway-banner");
        gtk::margins(banner, 12, 12, 0);
        gtk::pack(content, banner, false);

        let list = gtk::vbox(10);
        gtk::margins(list, 16, 16, 16);
        let empty = empty_views(list);
        let list_scroll = gtk::scrolled(list);
        gtk::pack(content, list_scroll, true);
        let page_box = gtk::vbox(0);
        let page_scroll = gtk::scrolled(page_box);
        gtk::pack(content, page_scroll, true);
        gtk::add(window, content);
        on_close(window);
        Home {
            window,
            header,
            back,
            add,
            more,
            banner,
            list_scroll,
            list,
            empty,
            page_scroll,
            page_box,
            menu: None,
            overview,
            view: View::List,
            cards: Vec::new(),
            page: None,
            history: HashMap::new(),
        }
    }

    fn visible(&self) -> bool {
        gtk::is_visible(self.window)
    }

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
        }
    }

    // The widgets of the overview: the cards that came, the ones that went, then what each one says
    fn sync(&mut self) {
        let on_list = self.view == View::List;
        let mut previous = std::mem::take(&mut self.cards);
        for card in &self.overview.cards {
            let views = match previous.iter().position(|views| views.name == card.name) {
                Some(index) => previous.remove(index),
                None => CardViews::new(self.list, &card.name),
            };
            self.cards.push(views);
        }
        for gone in previous {
            gtk::destroy(gone.root);
        }
        // in the order of the service, after the view of the empty list
        for (position, views) in self.cards.iter().enumerate() {
            unsafe { (gtk::g().gtk_box_reorder_child)(self.list, views.root, position as i32 + 1) };
            if let Some(card) = self.overview.card(&views.name) {
                views.fill(card, self.history.get(&card.name));
            }
        }
        let known = !matches!(self.overview.service, ServiceState::Unknown | ServiceState::Unavailable);
        gtk::set_visible(self.empty, self.overview.cards.is_empty() && known);
        gtk::set_visible(self.list_scroll, on_list);
        gtk::set_visible(self.page_scroll, !on_list);
        gtk::set_visible(self.add, on_list);
        gtk::set_visible(self.back, !on_list);
        let title = match &self.view {
            View::List => PRODUCT.to_string(),
            View::Vpn(name) => name.clone(),
        };
        unsafe { (gtk::g().gtk_header_bar_set_title)(self.header, gtk::c(&title).as_ptr()) };
        // the title of the window too, in the taskbar
        gtk::set_title(self.window, &title);
        gtk::set_visible(self.banner, self.overview.service == ServiceState::Unavailable);

        let card = match &self.view {
            View::Vpn(name) => self.overview.card(name),
            View::List => None,
        };
        if let (Some(page), Some(card)) = (&self.page, card) {
            page.fill(card, self.history.get(&card.name));
        }
        let changed = self.changes().is_some();
        if let Some(page) = &self.page {
            gtk::set_sensitive(page.save, changed);
        }
    }

    fn show_list(&mut self) {
        self.close_page();
        self.view = View::List;
        self.sync();
    }

    fn show_page(&mut self, name: &str) {
        let Some(card) = self.overview.card(name).cloned() else { return };
        self.close_page();
        self.page = Some(PageViews::new(self.page_box, &card));
        self.view = View::Vpn(name.to_string());
        self.sync();
    }

    fn close_page(&mut self) {
        if let Some(page) = self.page.take() {
            gtk::destroy(page.root);
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
    }

    fn changes(&self) -> Option<Changes> {
        let page = self.page.as_ref()?;
        let new_name = gtk::entry_text(page.name_edit).trim().to_string();
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
}

impl Drop for Home {
    fn drop(&mut self) {
        if let Some(menu) = self.menu.take() {
            gtk::destroy(menu);
        }
        gtk::destroy(self.window);
    }
}

// what the App, the tray, the controls and the flows ask

// Opens the window, or brings it back
pub fn show() {
    let exists = HOME.with(|cell| cell.try_borrow().map(|home| home.is_some()).unwrap_or(true));
    if !exists {
        let Some(overview) = with_app(|app| app.overview()) else { return };
        let home = Home::open(overview);
        HOME.with(|cell| {
            if let Ok(mut slot) = cell.try_borrow_mut() {
                *slot = Some(home);
            }
        });
    }
    let overview = with_app(|app| app.overview());
    with_home(|home| {
        if let Some(overview) = overview {
            home.update(overview);
        }
        unsafe { (gtk::g().gtk_widget_show)(home.window) };
        home.sync();
        gtk::present(home.window);
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

// the main window while it shows: the parent of the dialogs
pub fn parent() -> Option<Widget> {
    with_home_ref(|home| home.window).filter(|window| gtk::is_visible(*window))
}

pub fn is_home(id: usize) -> bool {
    with_home_ref(|home| window_id(home.window) == id).unwrap_or(false)
}

// The close button: the app stays in the tray, and says so the first time. Without a tray (GNOME without its
// extension), the window goes down to the taskbar instead, the way back to the app, and says why once a run.
pub fn hide() {
    let has_tray = with_app(|app| app.shell.has_tray).unwrap_or(false);
    if !has_tray {
        with_home_ref(|home| unsafe { (gtk::g().gtk_window_iconify)(home.window) });
        if !NO_TRAY_SAID.replace(true) {
            with_app(|app| app.shell.notify(&strings::notice_no_tray(), false));
        }
        return;
    }
    with_home_ref(|home| unsafe { (gtk::g().gtk_widget_hide)(home.window) });
    if !settings::close_notice_shown() {
        settings::set_close_notice_shown();
        with_app(|app| app.shell.notify(&strings::notice_still_running(), false));
    }
}

// the graph of the traffic of the page: the speeds received and sent, the last on the right
pub fn draw(widget: Widget, cairo: *mut c_void) {
    let rates = with_home_ref(|home| {
        let page = home.page.as_ref().filter(|page| page.graph == widget)?;
        let history = home.history.get(&page.name)?;
        Some((history.rates.iter().copied().collect::<Vec<_>>(), history.top()))
    });
    let Some(Some((rates, top))) = rates else { return };
    let g = gtk::g();
    let width = f64::from(unsafe { (g.gtk_widget_get_allocated_width)(widget) });
    let height = f64::from(unsafe { (g.gtk_widget_get_allocated_height)(widget) });
    let text = gtk::color_of(widget);
    let step = width / (SAMPLES.max(2) - 1) as f64;
    let first = SAMPLES.saturating_sub(rates.len());
    unsafe {
        // the base line
        (g.cairo_set_source_rgba)(cairo, text.red, text.green, text.blue, 0.2);
        (g.cairo_set_line_width)(cairo, 1.0);
        (g.cairo_move_to)(cairo, 0.0, height - 0.5);
        (g.cairo_line_to)(cairo, width, height - 0.5);
        (g.cairo_stroke)(cairo);
        let colors = [(0.21, 0.52, 0.89), (0.13, 0.56, 0.64)];
        for (series, (red, green, blue)) in colors.into_iter().enumerate() {
            (g.cairo_set_source_rgba)(cairo, red, green, blue, 1.0);
            (g.cairo_set_line_width)(cairo, 2.0);
            for (index, rate) in rates.iter().enumerate() {
                let value = if series == 0 { rate.0 } else { rate.1 };
                let x = (first + index) as f64 * step;
                let y = height - 1.0 - (value / top).min(1.0) * (height - 2.0);
                if index == 0 {
                    (g.cairo_move_to)(cairo, x, y);
                } else {
                    (g.cairo_line_to)(cairo, x, y);
                }
            }
            (g.cairo_stroke)(cairo);
        }
    }
}

// a switch of a card or of the page: the App turns it on or off, the switch follows its overview
pub fn switched(name: &str, on: bool) {
    let can = with_home_ref(|home| home.overview.card(name).is_some_and(|card| card.can_switch)).unwrap_or(true);
    if can {
        with_app(|app| if on { app.connect(name) } else { app.disconnect(name) });
    }
    refresh();
}

pub fn run(action: Action) {
    match action {
        Action::More => more_menu(),
        Action::Back => {
            with_home(|home| home.show_list());
        }
        Action::Add => flows::import_from_file(),
        Action::StartService => super::run_command(Command::StartService),
        Action::Open(name) => {
            with_home(|home| home.show_page(&name));
        }
        Action::Switch(name) => switched(&name, true),
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
        Action::Save => save(),
        Action::Details(name) => {
            with_app(|app| app.show_details(&name));
        }
        Action::Remove(name) => flows::remove(&name),
        Action::Edited => {
            with_home(|home| home.sync());
        }
        Action::OpenAtSignIn => settings::set_open_at_sign_in(!settings::open_at_sign_in()),
        Action::AppLog => super::run_command(Command::AppLog),
        Action::ServiceLog => super::run_command(Command::ServiceLog),
        Action::Quit => flows::quit(true),
    }
    refresh();
}

// the username, then the name: the login doesn't depend on the name
fn save() {
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
        if flows::rename(&changes.name, new_name) {
            with_home(|home| home.page_renamed(new_name));
        }
    }
    with_home(|home| home.reload_login());
}

// the menu of "More", under its button: made again each time, as the state of the service changes
pub fn more_menu() {
    let Some(button) = with_home_ref(|home| home.more) else { return };
    let service_down = with_app(|app| app.service_state() == ServiceState::Unavailable).unwrap_or(false);
    let menu = gtk::menu();
    let item = |text: &str, action: Action| {
        let entry = gtk::menu_item(text);
        on_activate(entry, Target::Home(action));
        gtk::append(menu, entry);
    };
    item(strings::MENU_IMPORT, Action::Add);
    gtk::append(menu, gtk::menu_separator());
    // checked before its signal, which the check would send
    let sign_in = gtk::check_menu_item(strings::MENU_OPEN_AT_SIGN_IN, settings::open_at_sign_in());
    on_activate(sign_in, Target::Home(Action::OpenAtSignIn));
    gtk::append(menu, sign_in);
    let logs = gtk::menu();
    for (text, action) in [(strings::MENU_APP_LOG, Action::AppLog), (strings::MENU_SERVICE_LOG, Action::ServiceLog)] {
        let entry = gtk::menu_item(text);
        on_activate(entry, Target::Home(action));
        gtk::append(logs, entry);
    }
    let logs_item = gtk::menu_item(strings::MENU_LOGS);
    gtk::set_submenu(logs_item, logs);
    gtk::append(menu, logs_item);
    if service_down {
        item(strings::MENU_START_SERVICE, Action::StartService);
    }
    gtk::append(menu, gtk::menu_separator());
    let version = gtk::menu_item(&strings::menu_version(VERSION));
    gtk::set_sensitive(version, false);
    gtk::append(menu, version);
    item(strings::MENU_QUIT, Action::Quit);
    let before = with_home(|home| home.menu.replace(menu)).flatten();
    if let Some(before) = before {
        gtk::destroy(before);
    }
    unsafe {
        (gtk::g().gtk_menu_popup_at_widget)(menu, button, gtk::GRAVITY_SOUTH_EAST, gtk::GRAVITY_NORTH_EAST, std::ptr::null_mut());
    }
}
