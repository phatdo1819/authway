// The views of the main window that AppKit hasn't: the boxes of the cards and of the parts of a page, drawn in the
// colors of the appearance; the graph of the traffic; the content of the window, which takes the .conf files dropped
// on it. A card opens the page of its VPN on a click anywhere but on its switch and its buttons.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{define_class, msg_send, AnyThread, ClassType, DefinedClass, MainThreadMarker, MainThreadOnly, Message};
use objc2_app_kit::{
    NSAppearanceCustomization, NSAppearanceNameAqua, NSAppearanceNameDarkAqua, NSBezierPath, NSButton, NSColor,
    NSCursor, NSDragOperation, NSDraggingDestination, NSDraggingInfo, NSEvent, NSLineJoinStyle,
    NSPasteboardTypeFileURL, NSSwitch, NSTrackingArea, NSTrackingAreaOptions, NSView,
};
use objc2_foundation::{NSArray, NSObjectProtocol, NSPoint, NSRect, NSSize, NSURL};

use super::{home, later};
use crate::client::overview::SAMPLES;

const RADIUS: f64 = 10.0;

pub fn rect(x: f64, y: f64, width: f64, height: f64) -> NSRect {
    NSRect::new(NSPoint::new(x, y), NSSize::new(width, height))
}

fn inset(area: NSRect, by: f64) -> NSRect {
    rect(area.origin.x + by, area.origin.y + by, area.size.width - by * 2.0, area.size.height - by * 2.0)
}

fn rounded(area: NSRect, radius: f64) -> Retained<NSBezierPath> {
    NSBezierPath::bezierPathWithRoundedRect_xRadius_yRadius(area, radius, radius)
}

// the dark appearance: the boxes are lighter than the window there, not white
fn is_dark(view: &NSView) -> bool {
    let (aqua, dark) = unsafe { (NSAppearanceNameAqua, NSAppearanceNameDarkAqua) };
    let names = NSArray::from_slice(&[aqua, dark]);
    view.effectiveAppearance().bestMatchFromAppearancesWithNames(&names).is_some_and(|name| name.isEqualToString(dark))
}

// the white of a card, or its light grey on the dark window
fn surface(dark: bool) -> Retained<NSColor> {
    if dark {
        NSColor::colorWithWhite_alpha(1.0, 0.07)
    } else {
        NSColor::controlBackgroundColor()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Style {
    // a part of a page
    Panel,
    // a VPN of the list
    Card,
    // where the file of a VPN drops
    Drop,
    // the round under the icon of the empty list
    Circle,
}

pub struct BoxState {
    style: Style,
    // the VPN of a card
    name: RefCell<String>,
    hovered: Cell<bool>,
    pressed: Cell<bool>,
}

define_class!(
    #[unsafe(super(NSView))]
    #[thread_kind = MainThreadOnly]
    #[name = "AuthwayBox"]
    #[ivars = BoxState]
    pub struct BoxView;

    impl BoxView {
        #[unsafe(method(isFlipped))]
        fn is_flipped(&self) -> bool {
            true
        }

        #[unsafe(method(drawRect:))]
        fn draw_rect(&self, _dirty: NSRect) {
            self.draw();
        }

        // on a card, its switch and its buttons take their clicks; the rest of it is the card
        #[unsafe(method_id(hitTest:))]
        fn hit_test(&self, point: NSPoint) -> Option<Retained<NSView>> {
            let hit: Option<Retained<NSView>> = unsafe { msg_send![super(self), hitTest: point] };
            let control = |view: &NSView| view.isKindOfClass(NSButton::class()) || view.isKindOfClass(NSSwitch::class());
            match hit {
                Some(view) if self.ivars().style == Style::Card && !control(&view) => Some(Retained::into_super(self.retain())),
                hit => hit,
            }
        }

        // a click on a card of a window in the back opens it at once
        #[unsafe(method(acceptsFirstMouse:))]
        fn accepts_first_mouse(&self, _event: Option<&NSEvent>) -> bool {
            self.ivars().style == Style::Card
        }

        #[unsafe(method(mouseDown:))]
        fn mouse_down(&self, event: &NSEvent) {
            if self.ivars().style == Style::Card {
                self.ivars().pressed.set(true);
                self.setNeedsDisplay(true);
            } else {
                let () = unsafe { msg_send![super(self), mouseDown: event] };
            }
        }

        // where the button went up: off the card, nothing
        #[unsafe(method(mouseUp:))]
        fn mouse_up(&self, event: &NSEvent) {
            if self.ivars().style == Style::Card {
                self.clicked(event);
            } else {
                let () = unsafe { msg_send![super(self), mouseUp: event] };
            }
        }

        #[unsafe(method(mouseEntered:))]
        fn mouse_entered(&self, _event: &NSEvent) {
            self.ivars().hovered.set(true);
            self.setNeedsDisplay(true);
        }

        #[unsafe(method(mouseExited:))]
        fn mouse_exited(&self, _event: &NSEvent) {
            self.ivars().hovered.set(false);
            self.ivars().pressed.set(false);
            self.setNeedsDisplay(true);
        }

        #[unsafe(method(resetCursorRects))]
        fn reset_cursor_rects(&self) {
            if self.ivars().style == Style::Card {
                self.addCursorRect_cursor(self.bounds(), &NSCursor::pointingHandCursor());
            }
        }
    }
);

impl BoxView {
    pub fn new(mtm: MainThreadMarker, style: Style) -> Retained<BoxView> {
        let state = BoxState { style, name: RefCell::new(String::new()), hovered: Cell::new(false), pressed: Cell::new(false) };
        let this = Self::alloc(mtm).set_ivars(state);
        let view: Retained<BoxView> = unsafe { msg_send![super(this), initWithFrame: rect(0.0, 0.0, 10.0, 10.0)] };
        if style == Style::Card {
            // follows the size of the card
            let options = NSTrackingAreaOptions::MouseEnteredAndExited
                | NSTrackingAreaOptions::ActiveInActiveApp
                | NSTrackingAreaOptions::InVisibleRect;
            let area = unsafe {
                NSTrackingArea::initWithRect_options_owner_userInfo(NSTrackingArea::alloc(), NSRect::ZERO, options, Some(&view), None)
            };
            view.addTrackingArea(&area);
        }
        view
    }

    // the VPN that the card opens
    pub fn set_name(&self, name: &str) {
        *self.ivars().name.borrow_mut() = name.to_string();
    }

    fn clicked(&self, event: &NSEvent) {
        let pressed = self.ivars().pressed.replace(false);
        self.setNeedsDisplay(true);
        let point = self.convertPoint_fromView(event.locationInWindow(), None);
        let bounds = self.bounds();
        let inside = point.x >= 0.0 && point.y >= 0.0 && point.x < bounds.size.width && point.y < bounds.size.height;
        if pressed && inside {
            let name = self.ivars().name.borrow().clone();
            later(move || home::open_page(&name));
        }
    }

    fn draw(&self) {
        let bounds = self.bounds();
        let state = self.ivars();
        let dark = is_dark(self);
        match state.style {
            Style::Drop => {
                let accent = NSColor::controlAccentColor();
                let path = rounded(inset(bounds, 1.0), RADIUS);
                accent.colorWithAlphaComponent(if dark { 0.25 } else { 0.12 }).setFill();
                path.fill();
                accent.setStroke();
                path.setLineWidth(2.0);
                path.stroke();
            }
            Style::Circle => {
                NSColor::controlAccentColor().colorWithAlphaComponent(0.15).setFill();
                NSBezierPath::bezierPathWithOvalInRect(bounds).fill();
            }
            Style::Panel | Style::Card => {
                let path = rounded(inset(bounds, 0.5), RADIUS);
                surface(dark).setFill();
                path.fill();
                let hovered = state.style == Style::Card && state.hovered.get();
                if hovered {
                    let amount = if state.pressed.get() { 0.08 } else { 0.04 };
                    NSColor::labelColor().colorWithAlphaComponent(amount).setFill();
                    path.fill();
                }
                let line = if hovered { NSColor::controlAccentColor().colorWithAlphaComponent(0.6) } else { NSColor::separatorColor() };
                line.setStroke();
                path.setLineWidth(1.0);
                path.stroke();
            }
        }
    }
}

pub struct GraphState {
    // bytes per second received and sent, the newest last
    rates: RefCell<Vec<(f64, f64)>>,
    top: Cell<f64>,
}

define_class!(
    // the traffic of the last minutes: received in the accent, filled under, sent in teal; the newest on the right
    #[unsafe(super(NSView))]
    #[thread_kind = MainThreadOnly]
    #[name = "AuthwayGraph"]
    #[ivars = GraphState]
    pub struct GraphView;

    impl GraphView {
        #[unsafe(method(isFlipped))]
        fn is_flipped(&self) -> bool {
            true
        }

        #[unsafe(method(drawRect:))]
        fn draw_rect(&self, _dirty: NSRect) {
            self.draw();
        }
    }
);

impl GraphView {
    pub fn new(mtm: MainThreadMarker) -> Retained<GraphView> {
        let this = Self::alloc(mtm).set_ivars(GraphState { rates: RefCell::new(Vec::new()), top: Cell::new(1024.0) });
        unsafe { msg_send![super(this), initWithFrame: rect(0.0, 0.0, 10.0, 10.0)] }
    }

    pub fn set(&self, rates: Vec<(f64, f64)>, top: f64) {
        let state = self.ivars();
        if *state.rates.borrow() == rates && state.top.get() == top {
            return;
        }
        *state.rates.borrow_mut() = rates;
        state.top.set(top);
        self.setNeedsDisplay(true);
    }

    fn draw(&self) {
        let bounds = self.bounds();
        let back = if is_dark(self) { NSColor::colorWithWhite_alpha(1.0, 0.05) } else { NSColor::windowBackgroundColor() };
        back.setFill();
        rounded(bounds, 6.0).fill();
        let rates = self.ivars().rates.borrow();
        if rates.is_empty() {
            return;
        }
        let top = self.ivars().top.get();
        let (left, right) = (2.0, bounds.size.width - 2.0);
        // room for the scale at the top
        let (upper, bottom) = (18.0, bounds.size.height - 2.0);
        let step = (right - left) / (SAMPLES - 1) as f64;
        let count = rates.len();
        let points = |value: fn(&(f64, f64)) -> f64| -> Vec<NSPoint> {
            rates
                .iter()
                .enumerate()
                .map(|(index, rate)| {
                    let x = right - (count - 1 - index) as f64 * step;
                    NSPoint::new(x, bottom - (value(rate) / top).min(1.0) * (bottom - upper))
                })
                .collect()
        };
        let line = |points: &[NSPoint]| {
            let path = NSBezierPath::bezierPath();
            path.moveToPoint(points[0]);
            for point in &points[1..] {
                path.lineToPoint(*point);
            }
            path
        };
        let accent = NSColor::controlAccentColor();
        let received = points(|rate| rate.0);
        let area = line(&received);
        area.lineToPoint(NSPoint::new(received[count - 1].x, bottom));
        area.lineToPoint(NSPoint::new(received[0].x, bottom));
        area.closePath();
        accent.colorWithAlphaComponent(0.16).setFill();
        area.fill();
        for (points, color) in [(received, accent), (points(|rate| rate.1), NSColor::systemTealColor())] {
            let path = line(&points);
            path.setLineWidth(2.0);
            path.setLineJoinStyle(NSLineJoinStyle::Round);
            color.setStroke();
            path.stroke();
        }
    }
}

pub struct ContentState {
    // the heights of the header, and of the banner under it
    header: Cell<f64>,
    banner: Cell<f64>,
}

define_class!(
    // The content of the main window: the line under the header, the banner when the service is down, and the files
    // dropped anywhere on it
    #[unsafe(super(NSView))]
    #[thread_kind = MainThreadOnly]
    #[name = "AuthwayHomeContent"]
    #[ivars = ContentState]
    pub struct ContentView;

    impl ContentView {
        #[unsafe(method(isFlipped))]
        fn is_flipped(&self) -> bool {
            true
        }

        #[unsafe(method(drawRect:))]
        fn draw_rect(&self, _dirty: NSRect) {
            let width = self.bounds().size.width;
            let (header, banner) = (self.ivars().header.get(), self.ivars().banner.get());
            if banner > 0.0 {
                NSColor::systemYellowColor().colorWithAlphaComponent(0.18).setFill();
                NSBezierPath::fillRect(rect(0.0, header, width, banner));
            }
            NSColor::separatorColor().setFill();
            NSBezierPath::fillRect(rect(0.0, header - 1.0, width, 1.0));
            if banner > 0.0 {
                NSBezierPath::fillRect(rect(0.0, header + banner - 1.0, width, 1.0));
            }
        }
    }

    unsafe impl NSObjectProtocol for ContentView {}

    unsafe impl NSDraggingDestination for ContentView {
        #[unsafe(method(draggingEntered:))]
        fn dragging_entered(&self, sender: &ProtocolObject<dyn NSDraggingInfo>) -> NSDragOperation {
            let wanted = !files(sender).is_empty();
            home::dragging(wanted);
            if wanted {
                NSDragOperation::Copy
            } else {
                NSDragOperation::None
            }
        }

        #[unsafe(method(draggingExited:))]
        fn dragging_exited(&self, _sender: Option<&ProtocolObject<dyn NSDraggingInfo>>) {
            home::dragging(false);
        }

        #[unsafe(method(performDragOperation:))]
        fn perform_drag_operation(&self, sender: &ProtocolObject<dyn NSDraggingInfo>) -> bool {
            home::dragging(false);
            let files = files(sender);
            let wanted = !files.is_empty();
            if wanted {
                // out of the drop, which the Finder waits for
                later(move || home::dropped(files));
            }
            wanted
        }
    }
);

impl ContentView {
    pub fn new(mtm: MainThreadMarker) -> Retained<ContentView> {
        let this = Self::alloc(mtm).set_ivars(ContentState { header: Cell::new(0.0), banner: Cell::new(0.0) });
        let view: Retained<ContentView> = unsafe { msg_send![super(this), initWithFrame: rect(0.0, 0.0, 10.0, 10.0)] };
        view.registerForDraggedTypes(&NSArray::from_slice(&[unsafe { NSPasteboardTypeFileURL }]));
        view
    }

    pub fn set_bands(&self, header: f64, banner: f64) {
        let state = self.ivars();
        if state.header.get() != header || state.banner.get() != banner {
            state.header.set(header);
            state.banner.set(banner);
            self.setNeedsDisplay(true);
        }
    }
}

// the files of a drop
fn files(sender: &ProtocolObject<dyn NSDraggingInfo>) -> Vec<PathBuf> {
    let Some(items) = sender.draggingPasteboard().pasteboardItems() else { return Vec::new() };
    items
        .iter()
        .filter_map(|item| item.stringForType(unsafe { NSPasteboardTypeFileURL }))
        .filter_map(|text| NSURL::URLWithString(&text))
        // the Finder gives references to the files
        .filter_map(|url| url.filePathURL())
        .filter_map(|url| url.path())
        .map(|path| PathBuf::from(path.to_string()))
        .collect()
}
