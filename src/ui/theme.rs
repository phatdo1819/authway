// The look of the main window: its colors, the system ones in high contrast; its fonts, from the one of the
// dialogs of Windows, and the icons of the icon font of Windows; shapes drawn smooth with GDI+, which GDI draws
// jagged; and the drawing done out of sight, then copied, so nothing flickers. The texts are GDI's, with ClearType.

use std::mem::{size_of, zeroed};
use std::ptr;
use std::sync::Once;

use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontIndirectW, CreateSolidBrush, DeleteDC, DeleteObject,
    DrawTextW, FillRect, GetDC, GetSysColor, GetTextFaceW, ReleaseDC, SelectObject, SetBkMode, SetTextColor,
    COLOR_GRAYTEXT, COLOR_HIGHLIGHT, COLOR_HIGHLIGHTTEXT, COLOR_WINDOW, COLOR_WINDOWTEXT, DT_CALCRECT, DT_NOPREFIX,
    DT_SINGLELINE, DT_WORDBREAK, FW_NORMAL, FW_SEMIBOLD, HBITMAP, HBRUSH, HDC, HFONT, HGDIOBJ, LOGFONTW, SRCCOPY,
    TRANSPARENT,
};
use windows_sys::Win32::Graphics::GdiPlus::{
    FillModeAlternate, GdipAddPathArc, GdipClosePathFigure, GdipCreateFromHDC, GdipCreatePath, GdipCreatePen1,
    GdipCreateSolidFill, GdipDeleteBrush, GdipDeleteGraphics, GdipDeletePath, GdipDeletePen, GdipDrawLines,
    GdipDrawPath, GdipFillEllipse, GdipFillPath, GdipFillPolygon, GdipSetPenEndCap, GdipSetPenLineJoin,
    GdipSetPenStartCap, GdipSetPixelOffsetMode, GdipSetSmoothingMode, GdiplusStartup, GdiplusStartupInput, GpBrush,
    GpGraphics, GpPath, GpPen, GpSolidFill, LineCapRound, LineJoinRound, PixelOffsetModeHalf, PointF,
    SmoothingModeAntiAlias, UnitPixel,
};
use windows_sys::Win32::UI::Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW};
use windows_sys::Win32::UI::HiDpi::SystemParametersInfoForDpi;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SystemParametersInfoW, NONCLIENTMETRICSW, SPI_GETHIGHCONTRAST, SPI_GETNONCLIENTMETRICS,
};

use super::scale;

// COLORREF: 0x00bbggrr
pub const fn rgb(red: u8, green: u8, blue: u8) -> u32 {
    red as u32 | (green as u32) << 8 | (blue as u32) << 16
}

#[derive(Clone, Copy)]
pub struct Palette {
    // under the cards
    pub background: u32,
    // the cards and the header
    pub surface: u32,
    pub hover: u32,
    pub border: u32,
    pub text: u32,
    pub muted: u32,
    pub accent: u32,
    pub accent_hover: u32,
    // the switch while it turns on, the circle of the empty list
    pub accent_soft: u32,
    // on the accent
    pub on_accent: u32,
    pub good: u32,
    pub warning: u32,
    pub bad: u32,
    pub off: u32,
    // the upload, next to the download in the accent
    pub upload: u32,
    // the switch when off, a button that can't be used
    pub track: u32,
    // the service isn't running
    pub banner: u32,
    pub high_contrast: bool,
}

fn high_contrast() -> bool {
    let mut info: HIGHCONTRASTW = unsafe { zeroed() };
    info.cbSize = size_of::<HIGHCONTRASTW>() as u32;
    let ok = unsafe { SystemParametersInfoW(SPI_GETHIGHCONTRAST, info.cbSize, &mut info as *mut _ as *mut _, 0) };
    ok != 0 && info.dwFlags & HCF_HIGHCONTRASTON != 0
}

impl Palette {
    // the one of the app, or the colors of the system in high contrast
    pub fn system() -> Palette {
        if high_contrast() {
            let system = |index| unsafe { GetSysColor(index) };
            let (window, text) = (system(COLOR_WINDOW), system(COLOR_WINDOWTEXT));
            let (accent, on_accent) = (system(COLOR_HIGHLIGHT), system(COLOR_HIGHLIGHTTEXT));
            return Palette {
                background: window,
                surface: window,
                hover: window,
                border: text,
                text,
                muted: system(COLOR_GRAYTEXT),
                accent,
                accent_hover: accent,
                accent_soft: accent,
                on_accent,
                good: text,
                warning: text,
                bad: text,
                off: text,
                upload: text,
                track: system(COLOR_GRAYTEXT),
                banner: window,
                high_contrast: true,
            };
        }
        // the blue of the icon, and the slate, amber and red of its states
        Palette {
            background: rgb(0xf1, 0xf4, 0xf8),
            surface: rgb(0xff, 0xff, 0xff),
            hover: rgb(0xf8, 0xfa, 0xfc),
            border: rgb(0xdd, 0xe3, 0xea),
            text: rgb(0x0f, 0x17, 0x2a),
            muted: rgb(0x5b, 0x67, 0x7a),
            accent: rgb(0x03, 0x69, 0xa1),
            accent_hover: rgb(0x07, 0x59, 0x85),
            accent_soft: rgb(0xd6, 0xec, 0xf8),
            on_accent: rgb(0xff, 0xff, 0xff),
            good: rgb(0x15, 0x80, 0x3d),
            warning: rgb(0xb4, 0x53, 0x09),
            bad: rgb(0xb9, 0x1c, 0x1c),
            off: rgb(0x94, 0xa3, 0xb8),
            upload: rgb(0x0d, 0x94, 0x88),
            track: rgb(0xc5, 0xcf, 0xdb),
            banner: rgb(0xfe, 0xf3, 0xc7),
            high_contrast: false,
        }
    }
}

// The glyphs of Segoe Fluent Icons, or of Segoe MDL2 Assets before Windows 11: the same code points
pub const GLYPH_MORE: char = '\u{E712}';
pub const GLYPH_BACK: char = '\u{E72B}';
pub const GLYPH_ADD: char = '\u{E710}';
pub const GLYPH_CHEVRON: char = '\u{E76C}';
pub const GLYPH_VPN: char = '\u{E705}';
pub const GLYPH_DOWNLOAD: char = '\u{E896}';
pub const GLYPH_UPLOAD: char = '\u{E898}';
pub const GLYPH_WARNING: char = '\u{E7BA}';

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Font {
    // the header
    Title,
    // a card
    Name,
    Body,
    Strong,
    Small,
    // the numbers of the traffic
    Value,
    Icon,
    IconLarge,
}

pub struct Fonts {
    title: HFONT,
    name: HFONT,
    body: HFONT,
    strong: HFONT,
    small: HFONT,
    value: HFONT,
    icon: HFONT,
    icon_large: HFONT,
}

fn font(base: &LOGFONTW, tenths: i32, weight: u32) -> HFONT {
    let mut font = *base;
    font.lfHeight = base.lfHeight * tenths / 10;
    font.lfWeight = weight as i32;
    unsafe { CreateFontIndirectW(&font) }
}

fn face_font(face: &str, height: i32) -> HFONT {
    let mut font: LOGFONTW = unsafe { zeroed() };
    font.lfHeight = -height;
    font.lfWeight = FW_NORMAL as i32;
    for (target, unit) in font.lfFaceName.iter_mut().take(31).zip(face.encode_utf16()) {
        *target = unit;
    }
    unsafe { CreateFontIndirectW(&font) }
}

// the icon font of Windows 11, else the one of Windows 10
fn icon_font(height: i32) -> HFONT {
    const FLUENT: &str = "Segoe Fluent Icons";
    let fluent = face_font(FLUENT, height);
    // Windows gives another font when it doesn't have this one
    let mut name = [0u16; 64];
    let found = unsafe {
        let dc = GetDC(ptr::null_mut());
        let previous = SelectObject(dc, fluent as HGDIOBJ);
        GetTextFaceW(dc, name.len() as i32, name.as_mut_ptr());
        SelectObject(dc, previous);
        ReleaseDC(ptr::null_mut(), dc);
        let end = name.iter().position(|&unit| unit == 0).unwrap_or(name.len());
        String::from_utf16_lossy(&name[..end])
    };
    if found.eq_ignore_ascii_case(FLUENT) {
        return fluent;
    }
    unsafe { DeleteObject(fluent as HGDIOBJ) };
    face_font("Segoe MDL2 Assets", height)
}

impl Fonts {
    pub fn new(dpi: u32) -> Fonts {
        let mut metrics: NONCLIENTMETRICSW = unsafe { zeroed() };
        metrics.cbSize = size_of::<NONCLIENTMETRICSW>() as u32;
        unsafe {
            SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, metrics.cbSize, &mut metrics as *mut _ as *mut _, 0, dpi)
        };
        // 9 points at 100%, or what the user chose for the texts
        let base = metrics.lfMessageFont;
        Fonts {
            title: font(&base, 16, FW_SEMIBOLD),
            name: font(&base, 13, FW_SEMIBOLD),
            body: font(&base, 11, FW_NORMAL),
            strong: font(&base, 11, FW_SEMIBOLD),
            small: font(&base, 10, FW_NORMAL),
            value: font(&base, 12, FW_SEMIBOLD),
            icon: icon_font(scale(16, dpi)),
            icon_large: icon_font(scale(34, dpi)),
        }
    }

    pub fn get(&self, font: Font) -> HFONT {
        match font {
            Font::Title => self.title,
            Font::Name => self.name,
            Font::Body => self.body,
            Font::Strong => self.strong,
            Font::Small => self.small,
            Font::Value => self.value,
            Font::Icon => self.icon,
            Font::IconLarge => self.icon_large,
        }
    }
}

impl Drop for Fonts {
    fn drop(&mut self) {
        for font in [self.title, self.name, self.body, self.strong, self.small, self.value, self.icon, self.icon_large] {
            unsafe { DeleteObject(font as HGDIOBJ) };
        }
    }
}

// a text in a rectangle, as DrawTextW formats it; the height it took
pub fn text(dc: HDC, fonts: &Fonts, font: Font, color: u32, text: &str, rect: &RECT, format: u32) -> i32 {
    let mut rect = *rect;
    let wide: Vec<u16> = text.encode_utf16().collect();
    unsafe {
        let previous = SelectObject(dc, fonts.get(font) as HGDIOBJ);
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, color);
        let height = DrawTextW(dc, wide.as_ptr(), wide.len() as i32, &mut rect, format | DT_NOPREFIX);
        SelectObject(dc, previous);
        height
    }
}

// The size of a text: on one line, or wrapped at the width
pub fn measure(dc: HDC, fonts: &Fonts, font: Font, text: &str, width: Option<i32>) -> (i32, i32) {
    let text = if text.is_empty() { "X" } else { text };
    let wide: Vec<u16> = text.encode_utf16().collect();
    let mut rect = RECT { left: 0, top: 0, right: width.unwrap_or(100_000), bottom: 0 };
    let format = DT_CALCRECT | DT_NOPREFIX | if width.is_some() { DT_WORDBREAK } else { DT_SINGLELINE };
    unsafe {
        let previous = SelectObject(dc, fonts.get(font) as HGDIOBJ);
        DrawTextW(dc, wide.as_ptr(), wide.len() as i32, &mut rect, format);
        SelectObject(dc, previous);
    }
    (rect.right - rect.left, rect.bottom - rect.top)
}

pub fn fill(dc: HDC, rect: &RECT, color: u32) {
    unsafe {
        let brush = CreateSolidBrush(color);
        FillRect(dc, rect, brush);
        DeleteObject(brush as HGDIOBJ);
    }
}

pub fn brush(color: u32) -> HBRUSH {
    unsafe { CreateSolidBrush(color) }
}

// Drawn out of sight, copied on the DC when dropped: the rectangle starts at 0, 0, as the client area of a window
// and the item of a button do
pub struct Buffer {
    target: HDC,
    dc: HDC,
    bitmap: HBITMAP,
    previous: HGDIOBJ,
    width: i32,
    height: i32,
}

impl Buffer {
    pub fn new(target: HDC, width: i32, height: i32) -> Buffer {
        unsafe {
            let dc = CreateCompatibleDC(target);
            let bitmap = CreateCompatibleBitmap(target, width.max(1), height.max(1));
            let previous = SelectObject(dc, bitmap as HGDIOBJ);
            Buffer { target, dc, bitmap, previous, width, height }
        }
    }

    pub fn dc(&self) -> HDC {
        self.dc
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe {
            BitBlt(self.target, 0, 0, self.width, self.height, self.dc, 0, 0, SRCCOPY);
            SelectObject(self.dc, self.previous);
            DeleteObject(self.bitmap as HGDIOBJ);
            DeleteDC(self.dc);
        }
    }
}

fn start_gdiplus() {
    static START: Once = Once::new();
    START.call_once(|| {
        let input = GdiplusStartupInput { GdiplusVersion: 1, ..GdiplusStartupInput::default() };
        let mut token = 0usize;
        // for the whole life of the app
        unsafe { GdiplusStartup(&mut token, &input, ptr::null_mut()) };
    });
}

// GDI+ ARGB from a COLORREF
fn argb(color: u32, alpha: u8) -> u32 {
    let (red, green, blue) = (color & 0xff, (color >> 8) & 0xff, (color >> 16) & 0xff);
    (alpha as u32) << 24 | red << 16 | green << 8 | blue
}

// GDI+ on a DC, smooth
pub struct Canvas(*mut GpGraphics);

struct Path(*mut GpPath);

impl Drop for Path {
    fn drop(&mut self) {
        unsafe { GdipDeletePath(self.0) };
    }
}

struct Brush(*mut GpSolidFill);

impl Brush {
    fn new(color: u32, alpha: u8) -> Brush {
        let mut brush = ptr::null_mut();
        unsafe { GdipCreateSolidFill(argb(color, alpha), &mut brush) };
        Brush(brush)
    }

    fn get(&self) -> *mut GpBrush {
        self.0 as *mut GpBrush
    }
}

impl Drop for Brush {
    fn drop(&mut self) {
        unsafe { GdipDeleteBrush(self.0 as *mut GpBrush) };
    }
}

struct Pen(*mut GpPen);

impl Pen {
    fn new(color: u32, alpha: u8, width: f32) -> Pen {
        let mut pen = ptr::null_mut();
        unsafe {
            GdipCreatePen1(argb(color, alpha), width, UnitPixel, &mut pen);
            GdipSetPenStartCap(pen, LineCapRound);
            GdipSetPenEndCap(pen, LineCapRound);
            GdipSetPenLineJoin(pen, LineJoinRound);
        }
        Pen(pen)
    }
}

impl Drop for Pen {
    fn drop(&mut self) {
        unsafe { GdipDeletePen(self.0) };
    }
}

fn rounded(x: f32, y: f32, width: f32, height: f32, radius: f32) -> Path {
    let mut path = ptr::null_mut();
    let diameter = (radius * 2.0).min(width).min(height);
    unsafe {
        GdipCreatePath(FillModeAlternate, &mut path);
        if diameter <= 0.0 {
            GdipAddPathArc(path, x, y, 0.0, 0.0, 180.0, 90.0);
        } else {
            let (right, bottom) = (x + width - diameter, y + height - diameter);
            GdipAddPathArc(path, x, y, diameter, diameter, 180.0, 90.0);
            GdipAddPathArc(path, right, y, diameter, diameter, 270.0, 90.0);
            GdipAddPathArc(path, right, bottom, diameter, diameter, 0.0, 90.0);
            GdipAddPathArc(path, x, bottom, diameter, diameter, 90.0, 90.0);
        }
        GdipClosePathFigure(path);
    }
    Path(path)
}

impl Canvas {
    pub fn new(dc: HDC) -> Canvas {
        start_gdiplus();
        let mut graphics = ptr::null_mut();
        unsafe {
            GdipCreateFromHDC(dc, &mut graphics);
            GdipSetSmoothingMode(graphics, SmoothingModeAntiAlias);
            // the pixels at their place, as GDI has them
            GdipSetPixelOffsetMode(graphics, PixelOffsetModeHalf);
        }
        Canvas(graphics)
    }

    pub fn fill_round(&self, rect: &RECT, radius: f32, color: u32) {
        self.fill_round_alpha(rect, radius, color, 255);
    }

    pub fn fill_round_alpha(&self, rect: &RECT, radius: f32, color: u32, alpha: u8) {
        let (x, y, width, height) = (rect.left as f32, rect.top as f32, (rect.right - rect.left) as f32, (rect.bottom - rect.top) as f32);
        let path = rounded(x, y, width, height, radius);
        let brush = Brush::new(color, alpha);
        unsafe { GdipFillPath(self.0, brush.get(), path.0) };
    }

    // the line inside the rectangle
    pub fn stroke_round(&self, rect: &RECT, radius: f32, width: f32, color: u32) {
        let half = width / 2.0;
        let path = rounded(
            rect.left as f32 + half,
            rect.top as f32 + half,
            (rect.right - rect.left) as f32 - width,
            (rect.bottom - rect.top) as f32 - width,
            (radius - half).max(0.0),
        );
        let pen = Pen::new(color, 255, width);
        unsafe { GdipDrawPath(self.0, pen.0, path.0) };
    }

    pub fn fill_circle(&self, center_x: f32, center_y: f32, radius: f32, color: u32) {
        let brush = Brush::new(color, 255);
        unsafe { GdipFillEllipse(self.0, brush.get(), center_x - radius, center_y - radius, radius * 2.0, radius * 2.0) };
    }

    pub fn lines(&self, points: &[PointF], width: f32, color: u32) {
        if points.len() < 2 {
            return;
        }
        let pen = Pen::new(color, 255, width);
        unsafe { GdipDrawLines(self.0, pen.0, points.as_ptr(), points.len() as i32) };
    }

    pub fn fill_polygon(&self, points: &[PointF], color: u32, alpha: u8) {
        if points.len() < 3 {
            return;
        }
        let brush = Brush::new(color, alpha);
        unsafe { GdipFillPolygon(self.0, brush.get(), points.as_ptr(), points.len() as i32, FillModeAlternate) };
    }
}

impl Drop for Canvas {
    fn drop(&mut self) {
        unsafe { GdipDeleteGraphics(self.0) };
    }
}

pub fn point(x: f32, y: f32) -> PointF {
    PointF { X: x, Y: y }
}
