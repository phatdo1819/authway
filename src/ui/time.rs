// The times of the login API, in ISO 8601, shown as the user reads them

use std::mem::zeroed;
use std::ptr;

use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::Globalization::{GetDateFormatEx, GetTimeFormatEx, DATE_SHORTDATE, TIME_NOSECONDS};
use windows_sys::Win32::System::SystemInformation::GetLocalTime;
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

// "2026-10-25T18:30:00.123456+00:00" as seconds since 1970
pub fn parse_iso(text: &str) -> Option<u64> {
    let (date, time) = text.trim().split_once(['T', ' '])?;
    let mut date = date.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // the zone starts after the seconds
    let zone_start = time.char_indices().skip(5).find(|&(_, c)| c == '+' || c == '-' || c == 'Z').map(|(i, _)| i);
    let (clock, zone) = match zone_start {
        Some(start) => time.split_at(start),
        None => (time, ""),
    };
    let mut clock = clock.split(':');
    let hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let second: i64 = clock.next().unwrap_or("0").split('.').next()?.parse().ok()?;
    let offset = match zone {
        "" | "Z" => 0,
        _ => {
            let sign = if zone.starts_with('-') { -1 } else { 1 };
            let (hours, minutes) = zone[1..].split_once(':').unwrap_or((&zone[1..], "0"));
            sign * (hours.parse::<i64>().ok()? * 3600 + minutes.parse::<i64>().ok()? * 60)
        }
    };
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
    u64::try_from(seconds).ok()
}

fn local_time(unix: u64) -> Option<SYSTEMTIME> {
    let ticks = (unix + 11_644_473_600) * 10_000_000;
    let file = FILETIME { dwLowDateTime: ticks as u32, dwHighDateTime: (ticks >> 32) as u32 };
    unsafe {
        let mut utc: SYSTEMTIME = zeroed();
        let mut local: SYSTEMTIME = zeroed();
        if FileTimeToSystemTime(&file, &mut utc) == 0 || SystemTimeToTzSpecificLocalTime(ptr::null(), &utc, &mut local) == 0 {
            return None;
        }
        Some(local)
    }
}

// "18:30" today, with the date on the other days, in the format of the user
pub fn format_local(unix: u64) -> String {
    let Some(local) = local_time(unix) else { return String::new() };
    let mut buffer = [0u16; 64];
    let length = unsafe { GetTimeFormatEx(ptr::null(), TIME_NOSECONDS, &local, ptr::null(), buffer.as_mut_ptr(), buffer.len() as i32) };
    let time = String::from_utf16_lossy(&buffer[..(length.max(1) - 1) as usize]);
    let mut today: SYSTEMTIME = unsafe { zeroed() };
    unsafe { GetLocalTime(&mut today) };
    if (today.wYear, today.wMonth, today.wDay) == (local.wYear, local.wMonth, local.wDay) {
        return time;
    }
    let length = unsafe {
        GetDateFormatEx(ptr::null(), DATE_SHORTDATE, &local, ptr::null(), buffer.as_mut_ptr(), buffer.len() as i32, ptr::null())
    };
    let date = String::from_utf16_lossy(&buffer[..(length.max(1) - 1) as usize]);
    format!("{} {}", date, time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_times() {
        assert_eq!(parse_iso("2026-01-01T00:00:00+00:00"), Some(1_767_225_600));
        assert_eq!(parse_iso("2026-01-01T00:00:00.123456+00:00"), Some(1_767_225_600));
        assert_eq!(parse_iso("2026-01-01T01:30:00+01:30"), Some(1_767_225_600));
        assert_eq!(parse_iso("2025-12-31T23:00:00-01:00"), Some(1_767_225_600));
        assert_eq!(parse_iso("2026-01-01T00:00:00Z"), Some(1_767_225_600));
        assert_eq!(parse_iso("2024-02-29T12:00:00"), Some(1_709_208_000));
        assert_eq!(parse_iso("yesterday"), None);
        assert_eq!(parse_iso("2026-13-01T00:00:00"), None);
        assert!(!format_local(1_767_225_600).is_empty());
    }
}
