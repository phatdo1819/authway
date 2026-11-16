// GTK 3, the tray icon (AppIndicator) and the notices (libnotify), loaded when the app starts: the service and the
// commands run without them, and the build needs none of their development files. Each function of C is declared
// once here, with its signature from the headers of GTK 3.24; the rest of the app calls the small functions below.
// GTK lives on the main thread only: g_idle_add, which reaches it from the other threads, is the exception.

use std::ffi::{c_char, c_int, c_uint, c_ulong, c_void, CStr, CString};
use std::sync::OnceLock;

pub type Widget = *mut c_void;

// the colors of GTK, for the graph
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Rgba {
    pub red: f64,
    pub green: f64,
    pub blue: f64,
    pub alpha: f64,
}

macro_rules! library {
    ($kind:ident { $( fn $name:ident($($argument:ty),*) $(-> $result:ty)?; )* }) => {
        #[allow(non_snake_case)]
        pub struct $kind {
            $( pub $name: unsafe extern "C" fn($($argument),*) $(-> $result)?, )*
        }

        impl $kind {
            // SAFETY: the handle is one of dlopen; each symbol has the signature declared
            unsafe fn load(handle: *mut c_void) -> Result<$kind, String> {
                Ok($kind {
                    $( $name: {
                        let symbol = libc::dlsym(handle, concat!(stringify!($name), "\0").as_ptr() as *const c_char);
                        if symbol.is_null() {
                            return Err(format!("{} is missing", stringify!($name)));
                        }
                        std::mem::transmute::<*mut c_void, unsafe extern "C" fn($($argument),*) $(-> $result)?>(symbol)
                    }, )*
                })
            }
        }
    };
}

// GTK and what it brings: GDK, GObject, GLib, GIO and cairo, found through the handle of GTK
library!(Gtk {
    fn gtk_init_check(*mut c_int, *mut *mut *mut c_char) -> c_int;
    fn gtk_main();
    fn gtk_main_quit();
    fn gtk_window_new(c_int) -> Widget;
    fn gtk_window_set_title(Widget, *const c_char);
    fn gtk_window_set_default_size(Widget, c_int, c_int);
    fn gtk_window_present(Widget);
    fn gtk_window_set_icon_name(Widget, *const c_char);
    fn gtk_window_set_transient_for(Widget, Widget);
    fn gtk_window_set_modal(Widget, c_int);
    fn gtk_window_set_resizable(Widget, c_int);
    fn gtk_window_set_position(Widget, c_int);
    fn gtk_window_set_default(Widget, Widget);
    fn gtk_window_iconify(Widget);
    fn gtk_window_set_titlebar(Widget, Widget);
    fn gtk_widget_show(Widget);
    fn gtk_widget_hide(Widget);
    fn gtk_widget_destroy(Widget);
    fn gtk_widget_set_sensitive(Widget, c_int);
    fn gtk_widget_get_sensitive(Widget) -> c_int;
    fn gtk_widget_set_visible(Widget, c_int);
    fn gtk_widget_get_visible(Widget) -> c_int;
    fn gtk_widget_set_margin_start(Widget, c_int);
    fn gtk_widget_set_margin_end(Widget, c_int);
    fn gtk_widget_set_margin_top(Widget, c_int);
    fn gtk_widget_set_margin_bottom(Widget, c_int);
    fn gtk_widget_set_halign(Widget, c_int);
    fn gtk_widget_set_valign(Widget, c_int);
    fn gtk_widget_set_hexpand(Widget, c_int);
    fn gtk_widget_set_vexpand(Widget, c_int);
    fn gtk_widget_set_size_request(Widget, c_int, c_int);
    fn gtk_widget_grab_focus(Widget);
    fn gtk_widget_set_tooltip_text(Widget, *const c_char);
    fn gtk_widget_get_toplevel(Widget) -> Widget;
    fn gtk_widget_queue_draw(Widget);
    fn gtk_widget_get_allocated_width(Widget) -> c_int;
    fn gtk_widget_get_allocated_height(Widget) -> c_int;
    fn gtk_widget_get_style_context(Widget) -> *mut c_void;
    fn gtk_style_context_add_class(*mut c_void, *const c_char);
    fn gtk_style_context_remove_class(*mut c_void, *const c_char);
    fn gtk_style_context_get_color(*mut c_void, c_int, *mut Rgba);
    fn gtk_css_provider_new() -> *mut c_void;
    fn gtk_css_provider_load_from_data(*mut c_void, *const c_char, isize, *mut *mut c_void) -> c_int;
    fn gtk_style_context_add_provider_for_screen(*mut c_void, *mut c_void, c_uint);
    fn gdk_screen_get_default() -> *mut c_void;
    fn gtk_box_new(c_int, c_int) -> Widget;
    fn gtk_box_pack_start(Widget, Widget, c_int, c_int, c_uint);
    fn gtk_box_pack_end(Widget, Widget, c_int, c_int, c_uint);
    fn gtk_box_reorder_child(Widget, Widget, c_int);
    fn gtk_container_add(Widget, Widget);
    fn gtk_label_new(*const c_char) -> Widget;
    fn gtk_label_set_text(Widget, *const c_char);
    fn gtk_label_get_text(Widget) -> *const c_char;
    fn gtk_label_set_xalign(Widget, f32);
    fn gtk_label_set_line_wrap(Widget, c_int);
    fn gtk_label_set_ellipsize(Widget, c_int);
    fn gtk_label_set_selectable(Widget, c_int);
    fn gtk_label_set_max_width_chars(Widget, c_int);
    fn gtk_label_get_selection_bounds(Widget, *mut c_int, *mut c_int) -> c_int;
    fn gtk_label_select_region(Widget, c_int, c_int);
    fn gtk_button_new_with_label(*const c_char) -> Widget;
    fn gtk_button_set_label(Widget, *const c_char);
    fn gtk_button_new_from_icon_name(*const c_char, c_int) -> Widget;
    fn gtk_button_set_relief(Widget, c_int);
    fn gtk_image_new_from_icon_name(*const c_char, c_int) -> Widget;
    fn gtk_image_set_pixel_size(Widget, c_int);
    fn gtk_switch_new() -> Widget;
    fn gtk_switch_set_active(Widget, c_int);
    fn gtk_switch_get_active(Widget) -> c_int;
    fn gtk_switch_set_state(Widget, c_int);
    fn gtk_entry_new() -> Widget;
    fn gtk_entry_get_text(Widget) -> *const c_char;
    fn gtk_entry_set_text(Widget, *const c_char);
    fn gtk_entry_set_visibility(Widget, c_int);
    fn gtk_entry_set_max_length(Widget, c_int);
    fn gtk_entry_set_placeholder_text(Widget, *const c_char);
    fn gtk_entry_set_activates_default(Widget, c_int);
    fn gtk_entry_set_input_purpose(Widget, c_int);
    fn gtk_check_button_new_with_label(*const c_char) -> Widget;
    fn gtk_toggle_button_get_active(Widget) -> c_int;
    fn gtk_toggle_button_set_active(Widget, c_int);
    fn gtk_scrolled_window_new(*mut c_void, *mut c_void) -> Widget;
    fn gtk_scrolled_window_set_policy(Widget, c_int, c_int);
    fn gtk_grid_new() -> Widget;
    fn gtk_grid_attach(Widget, Widget, c_int, c_int, c_int, c_int);
    fn gtk_grid_set_row_spacing(Widget, c_uint);
    fn gtk_grid_set_column_spacing(Widget, c_uint);
    fn gtk_separator_new(c_int) -> Widget;
    fn gtk_header_bar_new() -> Widget;
    fn gtk_header_bar_set_title(Widget, *const c_char);
    fn gtk_header_bar_set_show_close_button(Widget, c_int);
    fn gtk_header_bar_pack_start(Widget, Widget);
    fn gtk_header_bar_pack_end(Widget, Widget);
    fn gtk_menu_new() -> Widget;
    fn gtk_menu_item_new_with_label(*const c_char) -> Widget;
    fn gtk_check_menu_item_new_with_label(*const c_char) -> Widget;
    fn gtk_check_menu_item_set_active(Widget, c_int);
    fn gtk_separator_menu_item_new() -> Widget;
    fn gtk_menu_item_set_submenu(Widget, Widget);
    fn gtk_menu_shell_append(Widget, Widget);
    fn gtk_menu_popup_at_widget(Widget, Widget, c_int, c_int, *mut c_void);
    fn gtk_dialog_new() -> Widget;
    fn gtk_dialog_add_button(Widget, *const c_char, c_int) -> Widget;
    fn gtk_dialog_run(Widget) -> c_int;
    fn gtk_dialog_get_content_area(Widget) -> Widget;
    fn gtk_dialog_set_default_response(Widget, c_int);
    fn gtk_file_chooser_native_new(*const c_char, Widget, c_int, *const c_char, *const c_char) -> *mut c_void;
    fn gtk_native_dialog_run(*mut c_void) -> c_int;
    fn gtk_file_chooser_get_filename(*mut c_void) -> *mut c_char;
    fn gtk_file_filter_new() -> *mut c_void;
    fn gtk_file_filter_add_pattern(*mut c_void, *const c_char);
    fn gtk_file_filter_set_name(*mut c_void, *const c_char);
    fn gtk_file_chooser_add_filter(*mut c_void, *mut c_void);
    fn gtk_drawing_area_new() -> Widget;
    fn gtk_event_box_new() -> Widget;
    fn gtk_clipboard_get(*mut c_void) -> *mut c_void;
    fn gtk_clipboard_set_text(*mut c_void, *const c_char, c_int);
    fn gdk_atom_intern(*const c_char, c_int) -> *mut c_void;
    fn g_signal_connect_data(*mut c_void, *const c_char, *const c_void, *mut c_void, *const c_void, c_int) -> c_ulong;
    fn g_timeout_add(c_uint, *const c_void, *mut c_void) -> c_uint;
    fn g_idle_add(*const c_void, *mut c_void) -> c_uint;
    fn g_unix_signal_add(c_int, *const c_void, *mut c_void) -> c_uint;
    fn g_free(*mut c_void);
    fn g_object_unref(*mut c_void);
    fn g_object_ref_sink(*mut c_void) -> *mut c_void;
    fn g_error_free(*mut c_void);
    fn g_bus_get_sync(c_int, *mut c_void, *mut *mut c_void) -> *mut c_void;
    fn g_dbus_connection_call_sync(
        *mut c_void,
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
        *mut c_void,
        *mut c_void,
        c_int,
        c_int,
        *mut c_void,
        *mut *mut c_void
    ) -> *mut c_void;
    fn g_variant_new_string(*const c_char) -> *mut c_void;
    fn g_variant_new_tuple(*const *mut c_void, usize) -> *mut c_void;
    fn g_variant_get_child_value(*mut c_void, usize) -> *mut c_void;
    fn g_variant_get_boolean(*mut c_void) -> c_int;
    fn g_variant_unref(*mut c_void);
    fn cairo_set_source_rgba(*mut c_void, f64, f64, f64, f64);
    fn cairo_set_line_width(*mut c_void, f64);
    fn cairo_move_to(*mut c_void, f64, f64);
    fn cairo_line_to(*mut c_void, f64, f64);
    fn cairo_stroke(*mut c_void);
});

// the tray icon: StatusNotifierItem, through Ayatana AppIndicator or the AppIndicator of Ubuntu before it
library!(Indicator {
    fn app_indicator_new(*const c_char, *const c_char, c_int) -> *mut c_void;
    fn app_indicator_set_status(*mut c_void, c_int);
    fn app_indicator_set_menu(*mut c_void, Widget);
    fn app_indicator_set_icon_full(*mut c_void, *const c_char, *const c_char);
    fn app_indicator_set_title(*mut c_void, *const c_char);
});

// the notices of the desktop
library!(Notify {
    fn notify_init(*const c_char) -> c_int;
    fn notify_notification_new(*const c_char, *const c_char, *const c_char) -> *mut c_void;
    fn notify_notification_show(*mut c_void, *mut *mut c_void) -> c_int;
    fn notify_notification_set_urgency(*mut c_void, c_int);
    fn notify_notification_add_action(*mut c_void, *const c_char, *const c_char, *const c_void, *mut c_void, *const c_void);
});

pub struct Libraries {
    pub gtk: Gtk,
    pub indicator: Option<Indicator>,
    pub notify: Option<Notify>,
}

static LIBRARIES: OnceLock<Libraries> = OnceLock::new();

fn open(names: &[&str]) -> Option<*mut c_void> {
    names.iter().find_map(|name| {
        let name = CString::new(*name).ok()?;
        let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
        (!handle.is_null()).then_some(handle)
    })
}

// Once, on the main thread, before any other function here: GTK, then what's there of the others
pub fn load() -> Result<(), String> {
    let handle = open(&["libgtk-3.so.0"]).ok_or("GTK 3 isn't installed (libgtk-3-0, or gtk3)")?;
    let gtk = unsafe { Gtk::load(handle) }.map_err(|error| format!("GTK 3 is too old: {}", error))?;
    let indicator = open(&["libayatana-appindicator3.so.1", "libappindicator3.so.1"])
        .and_then(|handle| unsafe { Indicator::load(handle) }.ok());
    let notify = open(&["libnotify.so.4"]).and_then(|handle| unsafe { Notify::load(handle) }.ok());
    let _ = LIBRARIES.set(Libraries { gtk, indicator, notify });
    Ok(())
}

pub fn libraries() -> &'static Libraries {
    LIBRARIES.get().expect("GTK loaded")
}

pub fn g() -> &'static Gtk {
    &libraries().gtk
}

// a text for C, without the NULs it can't hold
pub fn c(text: &str) -> CString {
    CString::new(text.replace('\0', "")).unwrap_or_default()
}

pub fn text_of(pointer: *const c_char) -> String {
    if pointer.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(pointer) }.to_string_lossy().to_string()
}

// the values of the enumerations of GTK 3
pub const WINDOW_TOPLEVEL: c_int = 0;
pub const POSITION_CENTER: c_int = 1;
pub const HORIZONTAL: c_int = 0;
pub const VERTICAL: c_int = 1;
pub const ALIGN_FILL: c_int = 0;
pub const ALIGN_START: c_int = 1;
pub const ALIGN_END: c_int = 2;
pub const ALIGN_CENTER: c_int = 3;
pub const ICON_SIZE_MENU: c_int = 1;
pub const ICON_SIZE_BUTTON: c_int = 4;
pub const RELIEF_NONE: c_int = 2;
pub const ELLIPSIZE_END: c_int = 3;
pub const POLICY_AUTOMATIC: c_int = 1;
pub const POLICY_NEVER: c_int = 2;
pub const PURPOSE_DIGITS: c_int = 2;
pub const PURPOSE_PASSWORD: c_int = 8;
pub const FILE_CHOOSER_OPEN: c_int = 0;
pub const RESPONSE_ACCEPT: c_int = -3;
pub const RESPONSE_DELETE_EVENT: c_int = -4;
pub const GRAVITY_NORTH_EAST: c_int = 3;
pub const GRAVITY_SOUTH_EAST: c_int = 9;
pub const STATE_FLAG_NORMAL: c_int = 0;
pub const STYLE_PRIORITY_APPLICATION: c_uint = 600;
pub const BUS_SESSION: c_int = 2;
pub const INDICATOR_APPLICATION_STATUS: c_int = 0;
pub const INDICATOR_ACTIVE: c_int = 1;
pub const URGENCY_NORMAL: c_int = 1;
pub const URGENCY_CRITICAL: c_int = 2;

fn bool(value: bool) -> c_int {
    value as c_int
}

// Each widget made here is shown: the ones to hide are hidden after, show_all is never called
fn shown(widget: Widget) -> Widget {
    unsafe { (g().gtk_widget_show)(widget) };
    widget
}

pub fn label(text: &str) -> Widget {
    let label = shown(unsafe { (g().gtk_label_new)(c(text).as_ptr()) });
    unsafe { (g().gtk_label_set_xalign)(label, 0.0) };
    label
}

// on as many lines as it takes
pub fn wrapping(text: &str) -> Widget {
    let label = label(text);
    unsafe {
        (g().gtk_label_set_line_wrap)(label, 1);
        (g().gtk_label_set_max_width_chars)(label, 40);
    }
    label
}

// on one line, cut at the end
pub fn ellipsized(text: &str) -> Widget {
    let label = label(text);
    unsafe { (g().gtk_label_set_ellipsize)(label, ELLIPSIZE_END) };
    label
}

pub fn set_text(label: Widget, text: &str) {
    if text_of(unsafe { (g().gtk_label_get_text)(label) }) != text {
        unsafe { (g().gtk_label_set_text)(label, c(text).as_ptr()) };
    }
}

pub fn button(text: &str) -> Widget {
    shown(unsafe { (g().gtk_button_new_with_label)(c(text).as_ptr()) })
}

pub fn set_button_text(button: Widget, text: &str) {
    unsafe { (g().gtk_button_set_label)(button, c(text).as_ptr()) };
}

// an icon of the theme, with its text as tooltip
pub fn icon_button(icon: &str, text: &str) -> Widget {
    let button = shown(unsafe { (g().gtk_button_new_from_icon_name)(c(icon).as_ptr(), ICON_SIZE_BUTTON) });
    unsafe { (g().gtk_widget_set_tooltip_text)(button, c(text).as_ptr()) };
    button
}

pub fn image(icon: &str, size: c_int) -> Widget {
    let image = shown(unsafe { (g().gtk_image_new_from_icon_name)(c(icon).as_ptr(), ICON_SIZE_BUTTON) });
    unsafe { (g().gtk_image_set_pixel_size)(image, size) };
    image
}

pub fn switch() -> Widget {
    let switch = shown(unsafe { (g().gtk_switch_new)() });
    unsafe { (g().gtk_widget_set_valign)(switch, ALIGN_CENTER) };
    switch
}

pub fn set_switch(switch: Widget, on: bool) {
    unsafe {
        if ((g().gtk_switch_get_active)(switch) != 0) != on {
            (g().gtk_switch_set_active)(switch, bool(on));
        }
        (g().gtk_switch_set_state)(switch, bool(on));
    }
}

pub fn entry(text: &str) -> Widget {
    let entry = shown(unsafe { (g().gtk_entry_new)() });
    unsafe { (g().gtk_entry_set_text)(entry, c(text).as_ptr()) };
    entry
}

pub fn entry_text(entry: Widget) -> String {
    text_of(unsafe { (g().gtk_entry_get_text)(entry) })
}

pub fn set_entry_text(entry: Widget, text: &str) {
    unsafe { (g().gtk_entry_set_text)(entry, c(text).as_ptr()) };
}

pub fn check_button(text: &str) -> Widget {
    shown(unsafe { (g().gtk_check_button_new_with_label)(c(text).as_ptr()) })
}

pub fn is_checked(button: Widget) -> bool {
    unsafe { (g().gtk_toggle_button_get_active)(button) != 0 }
}

pub fn set_checked(button: Widget, on: bool) {
    unsafe { (g().gtk_toggle_button_set_active)(button, bool(on)) };
}

pub fn vbox(spacing: c_int) -> Widget {
    shown(unsafe { (g().gtk_box_new)(VERTICAL, spacing) })
}

pub fn hbox(spacing: c_int) -> Widget {
    shown(unsafe { (g().gtk_box_new)(HORIZONTAL, spacing) })
}

// in a box: at the start, taking the room left when it expands
pub fn pack(container: Widget, child: Widget, expand: bool) {
    unsafe { (g().gtk_box_pack_start)(container, child, bool(expand), 1, 0) };
}

pub fn pack_end(container: Widget, child: Widget) {
    unsafe { (g().gtk_box_pack_end)(container, child, 0, 0, 0) };
}

pub fn add(container: Widget, child: Widget) {
    unsafe { (g().gtk_container_add)(container, child) };
}

pub fn grid() -> Widget {
    let grid = shown(unsafe { (g().gtk_grid_new)() });
    unsafe {
        (g().gtk_grid_set_row_spacing)(grid, 6);
        (g().gtk_grid_set_column_spacing)(grid, 12);
    }
    grid
}

pub fn attach(grid: Widget, child: Widget, column: c_int, row: c_int) {
    unsafe { (g().gtk_grid_attach)(grid, child, column, row, 1, 1) };
}

pub fn scrolled(child: Widget) -> Widget {
    let scroll = shown(unsafe { (g().gtk_scrolled_window_new)(std::ptr::null_mut(), std::ptr::null_mut()) });
    unsafe {
        (g().gtk_scrolled_window_set_policy)(scroll, POLICY_NEVER, POLICY_AUTOMATIC);
        (g().gtk_widget_set_vexpand)(scroll, 1);
    }
    add(scroll, child);
    scroll
}

pub fn separator() -> Widget {
    shown(unsafe { (g().gtk_separator_new)(HORIZONTAL) })
}

pub fn event_box(child: Widget) -> Widget {
    let event_box = shown(unsafe { (g().gtk_event_box_new)() });
    add(event_box, child);
    event_box
}

pub fn drawing_area(height: c_int) -> Widget {
    let area = shown(unsafe { (g().gtk_drawing_area_new)() });
    unsafe { (g().gtk_widget_set_size_request)(area, -1, height) };
    area
}

pub fn margins(widget: Widget, top: c_int, side: c_int, bottom: c_int) {
    unsafe {
        (g().gtk_widget_set_margin_top)(widget, top);
        (g().gtk_widget_set_margin_bottom)(widget, bottom);
        (g().gtk_widget_set_margin_start)(widget, side);
        (g().gtk_widget_set_margin_end)(widget, side);
    }
}

pub fn set_visible(widget: Widget, visible: bool) {
    unsafe {
        if ((g().gtk_widget_get_visible)(widget) != 0) != visible {
            (g().gtk_widget_set_visible)(widget, bool(visible));
        }
    }
}

pub fn is_visible(widget: Widget) -> bool {
    unsafe { (g().gtk_widget_get_visible)(widget) != 0 }
}

pub fn set_sensitive(widget: Widget, sensitive: bool) {
    unsafe {
        if ((g().gtk_widget_get_sensitive)(widget) != 0) != sensitive {
            (g().gtk_widget_set_sensitive)(widget, bool(sensitive));
        }
    }
}

pub fn halign(widget: Widget, align: c_int) {
    unsafe { (g().gtk_widget_set_halign)(widget, align) };
}

pub fn valign(widget: Widget, align: c_int) {
    unsafe { (g().gtk_widget_set_valign)(widget, align) };
}

pub fn hexpand(widget: Widget) {
    unsafe { (g().gtk_widget_set_hexpand)(widget, 1) };
}

pub fn focus(widget: Widget) {
    unsafe { (g().gtk_widget_grab_focus)(widget) };
}

pub fn destroy(widget: Widget) {
    unsafe { (g().gtk_widget_destroy)(widget) };
}

pub fn redraw(widget: Widget) {
    unsafe { (g().gtk_widget_queue_draw)(widget) };
}

pub fn toplevel(widget: Widget) -> Widget {
    unsafe { (g().gtk_widget_get_toplevel)(widget) }
}

pub fn add_class(widget: Widget, class: &str) {
    unsafe { (g().gtk_style_context_add_class)((g().gtk_widget_get_style_context)(widget), c(class).as_ptr()) };
}

pub fn remove_class(widget: Widget, class: &str) {
    unsafe { (g().gtk_style_context_remove_class)((g().gtk_widget_get_style_context)(widget), c(class).as_ptr()) };
}

// one class of the list, the others off
pub fn set_class(widget: Widget, classes: &[&str], class: &str) {
    for other in classes.iter().filter(|other| **other != class) {
        remove_class(widget, other);
    }
    add_class(widget, class);
}

pub fn color_of(widget: Widget) -> Rgba {
    let mut color = Rgba::default();
    unsafe { (g().gtk_style_context_get_color)((g().gtk_widget_get_style_context)(widget), STATE_FLAG_NORMAL, &mut color) };
    color
}

pub fn window(title: &str, width: c_int, height: c_int) -> Widget {
    let window = unsafe { (g().gtk_window_new)(WINDOW_TOPLEVEL) };
    unsafe {
        (g().gtk_window_set_title)(window, c(title).as_ptr());
        (g().gtk_window_set_default_size)(window, width, height);
        (g().gtk_window_set_icon_name)(window, c(&crate::names::PRODUCT.to_lowercase()).as_ptr());
        (g().gtk_window_set_position)(window, POSITION_CENTER);
    }
    window
}

pub fn present(window: Widget) {
    unsafe { (g().gtk_window_present)(window) };
}

pub fn set_title(window: Widget, title: &str) {
    unsafe { (g().gtk_window_set_title)(window, c(title).as_ptr()) };
}

pub fn set_default(window: Widget, button: Widget) {
    unsafe { (g().gtk_window_set_default)(window, button) };
}

pub fn menu() -> Widget {
    shown(unsafe { (g().gtk_menu_new)() })
}

pub fn menu_item(text: &str) -> Widget {
    shown(unsafe { (g().gtk_menu_item_new_with_label)(c(text).as_ptr()) })
}

pub fn check_menu_item(text: &str, on: bool) -> Widget {
    let item = shown(unsafe { (g().gtk_check_menu_item_new_with_label)(c(text).as_ptr()) });
    unsafe { (g().gtk_check_menu_item_set_active)(item, bool(on)) };
    item
}

pub fn menu_separator() -> Widget {
    shown(unsafe { (g().gtk_separator_menu_item_new)() })
}

pub fn append(menu: Widget, item: Widget) {
    unsafe { (g().gtk_menu_shell_append)(menu, item) };
}

pub fn set_submenu(item: Widget, menu: Widget) {
    unsafe { (g().gtk_menu_item_set_submenu)(item, menu) };
}

// A function of GLib on the main thread: g_idle_add is the one function here that other threads can call
pub fn idle(callback: unsafe extern "C" fn(*mut c_void) -> c_int, data: *mut c_void) {
    unsafe { (g().g_idle_add)(callback as *const c_void, data) };
}

// what a signal of a widget calls, with the data given; the signature of the callback is the one of the signal
pub fn connect(widget: Widget, signal: &str, callback: *const c_void, data: *mut c_void) {
    unsafe { (g().g_signal_connect_data)(widget, c(signal).as_ptr(), callback, data, std::ptr::null(), 0) };
}

pub fn copy_to_clipboard(text: &str) {
    unsafe {
        let clipboard = (g().gtk_clipboard_get)((g().gdk_atom_intern)(c("CLIPBOARD").as_ptr(), 0));
        (g().gtk_clipboard_set_text)(clipboard, c(text).as_ptr(), -1);
    }
}

// The rules of the look of the app, on the whole screen
pub fn load_css(css: &str) {
    unsafe {
        let provider = (g().gtk_css_provider_new)();
        let mut error: *mut c_void = std::ptr::null_mut();
        let text = c(css);
        if (g().gtk_css_provider_load_from_data)(provider, text.as_ptr(), -1, &mut error) == 0 && !error.is_null() {
            (g().g_error_free)(error);
        }
        (g().gtk_style_context_add_provider_for_screen)((g().gdk_screen_get_default)(), provider, STYLE_PRIORITY_APPLICATION);
    }
}

// Whether a tray shows the icons of StatusNotifierItem: a watcher on the session bus. GNOME has none without its
// AppIndicator extension; KDE, Xfce, Cinnamon, MATE and Ubuntu have one.
pub fn has_tray() -> bool {
    unsafe {
        let mut error: *mut c_void = std::ptr::null_mut();
        let bus = (g().g_bus_get_sync)(BUS_SESSION, std::ptr::null_mut(), &mut error);
        if bus.is_null() {
            if !error.is_null() {
                (g().g_error_free)(error);
            }
            return false;
        }
        let name = (g().g_variant_new_string)(c("org.kde.StatusNotifierWatcher").as_ptr());
        let parameters = (g().g_variant_new_tuple)(&name, 1);
        let reply = (g().g_dbus_connection_call_sync)(
            bus,
            c("org.freedesktop.DBus").as_ptr(),
            c("/org/freedesktop/DBus").as_ptr(),
            c("org.freedesktop.DBus").as_ptr(),
            c("NameHasOwner").as_ptr(),
            parameters,
            std::ptr::null_mut(),
            0,
            2000,
            std::ptr::null_mut(),
            &mut error,
        );
        let owned = if reply.is_null() {
            if !error.is_null() {
                (g().g_error_free)(error);
            }
            false
        } else {
            let value = (g().g_variant_get_child_value)(reply, 0);
            let owned = (g().g_variant_get_boolean)(value) != 0;
            (g().g_variant_unref)(value);
            (g().g_variant_unref)(reply);
            owned
        };
        (g().g_object_unref)(bus);
        owned
    }
}
