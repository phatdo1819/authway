// The window of the details of a VPN: the rows of client::details as a text with a heading per group, which the
// user can select and copy (Cmd+C), or copy all with the button. It follows the tunnel every second.

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{sel, AnyThread, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSAttributedStringNSStringDrawing, NSAutoresizingMaskOptions, NSBackingStoreType, NSBorderType, NSButton, NSColor,
    NSFont, NSFontAttributeName, NSForegroundColorAttributeName, NSMutableParagraphStyle, NSParagraphStyle,
    NSParagraphStyleAttributeName, NSPasteboard, NSPasteboardTypeString, NSScrollView, NSTextAlignment, NSTextField,
    NSTextTab, NSTextView, NSView, NSWindow, NSWindowCollectionBehavior, NSWindowStyleMask,
};
use objc2_foundation::{NSArray, NSAttributedString, NSDictionary, NSMutableAttributedString, NSPoint, NSRect, NSSize, NSString};

use super::{activate, ns, window_id, Target};
use crate::client::details::Details;
use crate::client::DetailsView;
use crate::log;
use crate::strings;

const MARGIN: f64 = 16.0;
const BUTTON_WIDTH: f64 = 110.0;
const BUTTON_HEIGHT: f64 = 32.0;

pub struct DetailsWindow {
    mtm: MainThreadMarker,
    window: Retained<NSWindow>,
    tunnel: String,
    text: Retained<NSTextView>,
    shown: Details,
}

fn rect(x: f64, y: f64, width: f64, height: f64) -> NSRect {
    NSRect::new(NSPoint::new(x, y), NSSize::new(width, height))
}

fn piece(
    text: &str,
    font: &NSFont,
    color: &NSColor,
    style: &NSParagraphStyle,
) -> Retained<NSAttributedString> {
    let keys: [&NSString; 3] = unsafe { [NSFontAttributeName, NSForegroundColorAttributeName, NSParagraphStyleAttributeName] };
    let values: [&AnyObject; 3] = [font, color, style];
    let attributes = NSDictionary::from_slices(&keys, &values);
    unsafe { NSAttributedString::initWithString_attributes(NSAttributedString::alloc(), &ns(text), Some(&attributes)) }
}

// The groups and their rows, the values in a column after the longest label
fn attributed(details: &Details) -> Retained<NSMutableAttributedString> {
    let size = NSFont::systemFontSize();
    let font = NSFont::systemFontOfSize(size);
    let bold = NSFont::boldSystemFontOfSize(size);
    let label_color = NSColor::secondaryLabelColor();
    let value_color = NSColor::labelColor();
    let plain = NSParagraphStyle::defaultParagraphStyle();
    let column = details
        .rows
        .iter()
        .map(|row| piece(&row.label, &font, &label_color, &plain).size().width)
        .fold(0.0, f64::max)
        + 20.0;
    let tab = unsafe {
        NSTextTab::initWithTextAlignment_location_options(NSTextTab::alloc(), NSTextAlignment::Left, column, &NSDictionary::new())
    };
    let row_style = NSMutableParagraphStyle::new();
    row_style.setTabStops(Some(&NSArray::from_retained_slice(&[tab])));
    // a long value wraps under itself
    row_style.setHeadIndent(column);
    row_style.setParagraphSpacing(3.0);
    let header_style = NSMutableParagraphStyle::new();
    header_style.setParagraphSpacingBefore(12.0);
    header_style.setParagraphSpacing(5.0);
    let first_style = NSMutableParagraphStyle::new();
    first_style.setParagraphSpacing(5.0);

    let result = NSMutableAttributedString::new();
    for (index, group) in details.groups.iter().enumerate() {
        let style = if index == 0 { &first_style } else { &header_style };
        result.appendAttributedString(&piece(&format!("{}\n", group.header), &bold, &value_color, style));
        for row in details.rows.iter().filter(|row| row.group == group.id) {
            result.appendAttributedString(&piece(&format!("{}\t", row.label), &font, &label_color, &row_style));
            result.appendAttributedString(&piece(&format!("{}\n", row.value), &font, &value_color, &row_style));
        }
    }
    result
}

impl DetailsWindow {
    pub fn open(mtm: MainThreadMarker, target: &Target, tunnel: &str, details: Details) -> Option<DetailsWindow> {
        let (width, height) = (520.0, 600.0);
        let style = NSWindowStyleMask::Titled
            | NSWindowStyleMask::Closable
            | NSWindowStyleMask::Miniaturizable
            | NSWindowStyleMask::Resizable;
        let window = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                NSWindow::alloc(mtm),
                rect(0.0, 0.0, width, height),
                style,
                NSBackingStoreType::Buffered,
                false,
            )
        };
        unsafe { window.setReleasedWhenClosed(false) };
        window.setTitle(&ns(&strings::details_title(tunnel)));
        window.setCollectionBehavior(NSWindowCollectionBehavior::MoveToActiveSpace);
        window.setContentMinSize(NSSize::new(380.0, 320.0));
        window.setDelegate(Some(ProtocolObject::from_ref(target)));
        let content = NSView::initWithFrame(NSView::alloc(mtm), rect(0.0, 0.0, width, height));
        window.setContentView(Some(&content));

        // from the bottom: the buttons, the text, the heading
        let button = |text: &str, action| unsafe {
            NSButton::buttonWithTitle_target_action(&ns(text), Some(target.object()), Some(action), mtm)
        };
        let pinned = NSAutoresizingMaskOptions::ViewMinXMargin | NSAutoresizingMaskOptions::ViewMaxYMargin;
        let close = button(strings::DETAILS_CLOSE, sel!(closePressed:));
        close.setKeyEquivalent(&ns("\r"));
        close.setFrame(rect(width - MARGIN - BUTTON_WIDTH, MARGIN, BUTTON_WIDTH, BUTTON_HEIGHT));
        close.setAutoresizingMask(pinned);
        let copy = button(strings::DETAILS_COPY, sel!(copyPressed:));
        copy.setFrame(rect(width - MARGIN - BUTTON_WIDTH * 2.0 - 8.0, MARGIN, BUTTON_WIDTH, BUTTON_HEIGHT));
        copy.setAutoresizingMask(pinned);

        let heading = NSTextField::labelWithString(&ns(tunnel), mtm);
        heading.setFont(Some(&NSFont::boldSystemFontOfSize(16.0)));
        let heading_height = 22.0;
        heading.setFrame(rect(MARGIN, height - MARGIN - heading_height, width - MARGIN * 2.0, heading_height));
        heading.setAutoresizingMask(
            NSAutoresizingMaskOptions::ViewWidthSizable | NSAutoresizingMaskOptions::ViewMinYMargin,
        );

        let bottom = MARGIN + BUTTON_HEIGHT + 12.0;
        let top = height - MARGIN - heading_height - 10.0;
        let scroll = NSScrollView::initWithFrame(NSScrollView::alloc(mtm), rect(MARGIN, bottom, width - MARGIN * 2.0, top - bottom));
        scroll.setHasVerticalScroller(true);
        scroll.setBorderType(NSBorderType::BezelBorder);
        scroll.setAutoresizingMask(
            NSAutoresizingMaskOptions::ViewWidthSizable | NSAutoresizingMaskOptions::ViewHeightSizable,
        );
        let inner = scroll.contentSize();
        let text = NSTextView::initWithFrame(NSTextView::alloc(mtm), rect(0.0, 0.0, inner.width, inner.height));
        text.setMinSize(NSSize::new(0.0, inner.height));
        text.setMaxSize(NSSize::new(f64::MAX, f64::MAX));
        text.setVerticallyResizable(true);
        text.setHorizontallyResizable(false);
        text.setAutoresizingMask(NSAutoresizingMaskOptions::ViewWidthSizable);
        text.setEditable(false);
        text.setSelectable(true);
        text.setTextContainerInset(NSSize::new(8.0, 10.0));
        scroll.setDocumentView(Some(&text));

        let views: [&NSView; 4] = [&heading, &scroll, &copy, &close];
        for view in views {
            content.addSubview(view);
        }
        let mut details_window = DetailsWindow { mtm, window, tunnel: tunnel.to_string(), text, shown: Details::default() };
        details_window.update(details);
        details_window.window.center();
        activate(mtm);
        details_window.window.makeKeyAndOrderFront(None);
        Some(details_window)
    }

    pub fn copy_all(&self) {
        let text = self.shown.text(&strings::details_title(&self.tunnel));
        let pasteboard = NSPasteboard::generalPasteboard();
        pasteboard.clearContents();
        if !pasteboard.setString_forType(&ns(&text), unsafe { NSPasteboardTypeString }) {
            log!("can't copy the details to the clipboard");
        }
    }
}

impl DetailsView for DetailsWindow {
    // only when something changed; the selection stays while the bytes count
    fn update(&mut self, details: Details) {
        if details == self.shown {
            return;
        }
        let Some(storage) = (unsafe { self.text.textStorage() }) else { return };
        let selected = self.text.selectedRange();
        let text = attributed(&details);
        let length = text.length();
        storage.setAttributedString(&text);
        if selected.location + selected.length <= length {
            self.text.setSelectedRange(selected);
        }
        self.shown = details;
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

impl Drop for DetailsWindow {
    fn drop(&mut self) {
        self.window.setDelegate(None);
        self.window.close();
    }
}
