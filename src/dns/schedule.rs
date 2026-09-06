//! time-based access control and scheduled domain filtering.
//!
//! allows domain blocking rules to be active only during specified time windows and days of the week,
//! supporting both overnight ranges (e.g. 23:00-07:00) and daytime ranges (e.g. 09:00-18:00).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRangeStr {
    #[serde(default)]
    pub after: String,
    #[serde(default)]
    pub before: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ScheduleConfig {
    #[serde(default)]
    pub time_range: Option<String>,
    #[serde(default)]
    pub days: Vec<String>,
    #[serde(default)]
    pub sun: Vec<TimeRangeStr>,
    #[serde(default)]
    pub mon: Vec<TimeRangeStr>,
    #[serde(default)]
    pub tue: Vec<TimeRangeStr>,
    #[serde(default)]
    pub wed: Vec<TimeRangeStr>,
    #[serde(default)]
    pub thu: Vec<TimeRangeStr>,
    #[serde(default)]
    pub fri: Vec<TimeRangeStr>,
    #[serde(default)]
    pub sat: Vec<TimeRangeStr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
    pub after: u32,  // seconds from midnight (0..=86400)
    pub before: u32, // seconds from midnight (0..=86400)
}

impl TimeRange {
    pub fn new(after: u32, before: u32) -> Self {
        Self { after, before }
    }

    pub fn parse(after_str: &str, before_str: &str) -> Result<Self, String> {
        let after = parse_hhmm_to_seconds(after_str)?;
        let before = parse_hhmm_to_seconds(before_str)?;
        Ok(Self::new(after, before))
    }

    pub fn parse_range_str(range_str: &str) -> Result<Self, String> {
        let parts: Vec<&str> = range_str.split('-').collect();
        if parts.len() != 2 {
            return Err(format!("invalid time range format: '{}'", range_str));
        }
        Self::parse(parts[0].trim(), parts[1].trim())
    }

    pub fn matches(&self, now_sec: u32) -> bool {
        if self.after > self.before {
            // overnight range, e.g. 21:00 (75600) to 07:00 (25200)
            now_sec >= self.after || now_sec <= self.before
        } else if self.after < self.before {
            // daytime range, e.g. 09:00 (32400) to 18:00 (64800)
            now_sec >= self.after && now_sec <= self.before
        } else {
            // 24h all-day range (after == before)
            true
        }
    }
}

pub fn parse_hhmm_to_seconds(s: &str) -> Result<u32, String> {
    let clean = s.trim();
    let parts: Vec<&str> = clean.split(':').collect();
    if parts.len() != 2 {
        return Err(format!("time expression must be HH:MM, got '{}'", s));
    }
    let hour: u32 = parts[0]
        .trim()
        .parse()
        .map_err(|_| format!("invalid hour: '{}'", parts[0]))?;
    let min: u32 = parts[1]
        .trim()
        .parse()
        .map_err(|_| format!("invalid minute: '{}'", parts[1]))?;
    if hour > 23 || min > 59 {
        return Err(format!("time out of range 00:00-23:59, got '{}'", s));
    }
    Ok(hour * 3600 + min * 60)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WeeklyRanges {
    pub ranges: [Vec<TimeRange>; 7], // 0 = Sun, 1 = Mon, ..., 6 = Sat
}

impl WeeklyRanges {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_config(cfg: &ScheduleConfig) -> Result<Self, String> {
        let mut res = Self::new();

        // 1. check if simple time_range ("09:00-17:00") is specified
        if let Some(ref tr_str) = cfg.time_range {
            let tr = TimeRange::parse_range_str(tr_str)?;
            let days_mask = parse_days_mask(&cfg.days);
            for day in 0..7 {
                if days_mask[day] {
                    res.ranges[day].push(tr);
                }
            }
        }

        // 2. add per-day explicit ranges
        let day_cfgs = [
            &cfg.sun, &cfg.mon, &cfg.tue, &cfg.wed, &cfg.thu, &cfg.fri, &cfg.sat,
        ];
        for (day, list) in day_cfgs.iter().enumerate() {
            for item in *list {
                let tr = TimeRange::parse(&item.after, &item.before)?;
                res.ranges[day].push(tr);
            }
        }

        Ok(res)
    }

    pub fn is_active_at(&self, wday: usize, hour: u32, min: u32, sec: u32) -> bool {
        if wday >= 7 {
            return false;
        }
        let day_ranges = &self.ranges[wday];
        if day_ranges.is_empty() {
            return false;
        }
        let now_sec = hour * 3600 + min * 60 + sec;
        day_ranges.iter().any(|tr| tr.matches(now_sec))
    }

    pub fn is_active_now(&self) -> bool {
        #[cfg(unix)]
        {
            unsafe {
                let mut t: libc::time_t = 0;
                libc::time(&mut t);
                let mut tm: libc::tm = std::mem::zeroed();
                libc::localtime_r(&t, &mut tm);
                self.is_active_at(
                    tm.tm_wday as usize,
                    tm.tm_hour as u32,
                    tm.tm_min as u32,
                    tm.tm_sec as u32,
                )
            }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

// parses day strings into a boolean mask [Sun, Mon, Tue, Wed, Thu, Fri, Sat]
pub fn parse_days_mask(days: &[String]) -> [bool; 7] {
    if days.is_empty() {
        return [true; 7];
    }
    let mut mask = [false; 7];
    for d in days {
        let clean = d.trim().to_ascii_lowercase();
        match clean.as_str() {
            "all" | "*" => return [true; 7],
            "sun" | "sunday" | "0" => mask[0] = true,
            "mon" | "monday" | "1" => mask[1] = true,
            "tue" | "tues" | "tuesday" | "2" => mask[2] = true,
            "wed" | "wednesday" | "3" => mask[3] = true,
            "thu" | "thur" | "thurs" | "thursday" | "4" => mask[4] = true,
            "fri" | "friday" | "5" => mask[5] = true,
            "sat" | "saturday" | "6" => mask[6] = true,
            _ => {}
        }
    }
    mask
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRule {
    pub pattern: String,
    pub schedule_name: String,
}

impl ScheduledRule {
    pub fn new(pattern: &str, schedule_name: &str) -> Self {
        let clean_pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
        Self {
            pattern: clean_pattern,
            schedule_name: schedule_name.trim().to_string(),
        }
    }

    pub fn matches(&self, domain: &str) -> bool {
        let clean_domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if clean_domain.is_empty() {
            return false;
        }

        // Substring wildcard check, e.g. *.youtube.* or *youtube*
        if self.pattern.starts_with('*') && self.pattern.ends_with('*') {
            let core = self.pattern.trim_matches('*').trim_matches('.');
            if !core.is_empty() && clean_domain.contains(core) {
                return true;
            }
        }

        // Suffix / exact check (e.g. "youtube.com" matches "youtube.com" and "www.youtube.com")
        let target = self
            .pattern
            .trim_start_matches("*.")
            .trim_start_matches('*');
        if clean_domain == target || clean_domain.ends_with(&format!(".{}", target)) {
            return true;
        }

        false
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScheduleManager {
    pub schedules: HashMap<String, WeeklyRanges>,
    pub rules: Vec<ScheduledRule>,
}

impl ScheduleManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_config(schedules_cfg: &HashMap<String, ScheduleConfig>) -> Self {
        let mut schedules = HashMap::new();
        for (name, cfg) in schedules_cfg {
            if let Ok(wr) = WeeklyRanges::from_config(cfg) {
                schedules.insert(name.clone(), wr);
            }
        }
        Self {
            schedules,
            rules: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, pattern: &str, schedule_name: &str) {
        self.rules.push(ScheduledRule::new(pattern, schedule_name));
    }

    // parses rule line that may contain `@schedule_name`, returns true if was a scheduled rule
    pub fn add_line(&mut self, line: &str) -> bool {
        let clean = line.trim();
        if clean.is_empty() || clean.starts_with('#') || clean.starts_with("//") {
            return false;
        }
        if let Some(idx) = clean.find('@') {
            let domain_part = clean[..idx].trim();
            let schedule_name = clean[idx + 1..].trim();
            let domain = domain_part.split_whitespace().last().unwrap_or(domain_part);
            if !domain.is_empty() && !schedule_name.is_empty() {
                self.add_rule(domain, schedule_name);
                return true;
            }
        }
        false
    }

    // parses multi-line text (e.g. blocklist file) and extracts all @schedule rules
    pub fn load_rules_from_text(&mut self, text: &str) {
        for line in text.lines() {
            self.add_line(line);
        }
    }

    // checks if domain is blocked by an active schedule rule, returning schedule name if blocked
    pub fn check_blocked(&self, domain: &str) -> Option<&str> {
        if self.rules.is_empty() || self.schedules.is_empty() {
            return None;
        }
        for rule in &self.rules {
            if rule.matches(domain) {
                if let Some(schedule) = self.schedules.get(&rule.schedule_name) {
                    if schedule.is_active_now() {
                        return Some(&rule.schedule_name);
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_range_daytime_matching() {
        // 09:00 to 17:00
        let tr = TimeRange::parse_range_str("09:00-17:00").expect("range should parse");
        assert_eq!(tr.after, 9 * 3600);
        assert_eq!(tr.before, 17 * 3600);

        assert!(!tr.matches(8 * 3600 + 59 * 60)); // 08:59 -> false
        assert!(tr.matches(9 * 3600)); // 09:00 -> true
        assert!(tr.matches(12 * 3600 + 30 * 60)); // 12:30 -> true
        assert!(tr.matches(17 * 3600)); // 17:00 -> true
        assert!(!tr.matches(17 * 3600 + 1)); // 17:00:01 -> false
    }

    #[test]
    fn test_time_range_overnight_matching() {
        // 22:00 to 06:00
        let tr = TimeRange::parse("22:00", "06:00").expect("range should parse");
        assert_eq!(tr.after, 22 * 3600);
        assert_eq!(tr.before, 6 * 3600);

        assert!(tr.matches(22 * 3600)); // 22:00 -> true
        assert!(tr.matches(23 * 3600 + 59 * 60)); // 23:59 -> true
        assert!(tr.matches(0)); // 00:00 -> true
        assert!(tr.matches(3 * 3600)); // 03:00 -> true
        assert!(tr.matches(6 * 3600)); // 06:00 -> true
        assert!(!tr.matches(6 * 3600 + 1)); // 06:00:01 -> false
        assert!(!tr.matches(12 * 3600)); // 12:00 -> false
        assert!(!tr.matches(21 * 3600 + 59 * 60)); // 21:59 -> false
    }

    #[test]
    fn test_weekly_ranges_active_at() {
        let mut wr = WeeklyRanges::new();
        // Friday 09:00 - 17:00 (Friday is index 5)
        let tr = TimeRange::parse_range_str("09:00-17:00").unwrap();
        wr.ranges[5].push(tr);

        // Friday at 10:00 -> active
        assert!(wr.is_active_at(5, 10, 0, 0));
        // Friday at 18:00 -> inactive
        assert!(!wr.is_active_at(5, 18, 0, 0));
        // Thursday at 10:00 -> inactive
        assert!(!wr.is_active_at(4, 10, 0, 0));
    }

    #[test]
    fn test_scheduled_rule_matching() {
        let rule = ScheduledRule::new("*.youtube.*", "work");
        assert!(rule.matches("youtube.com"));
        assert!(rule.matches("www.youtube.com"));
        assert!(rule.matches("m.youtube.co.uk"));
        assert!(!rule.matches("vimeo.com"));

        let rule2 = ScheduledRule::new("facebook.com", "study");
        assert!(rule2.matches("facebook.com"));
        assert!(rule2.matches("m.facebook.com"));
        assert!(!rule2.matches("notfacebook.com"));
    }

    #[test]
    fn test_schedule_manager_parsing_and_checking() {
        let mut cfg = HashMap::new();
        cfg.insert(
            "work".to_string(),
            ScheduleConfig {
                time_range: Some("00:00-23:59".to_string()), // all day
                days: vec!["all".to_string()],
                ..Default::default()
            },
        );

        let mut mgr = ScheduleManager::from_config(&cfg);
        assert!(mgr.add_line("youtube.com @work"));
        assert!(mgr.add_line("0.0.0.0 *.tiktok.* @work"));
        assert!(!mgr.add_line("doubleclick.net")); // no schedule

        assert_eq!(mgr.rules.len(), 2);
        assert_eq!(mgr.check_blocked("youtube.com"), Some("work"));
        assert_eq!(mgr.check_blocked("app.tiktok.com"), Some("work"));
        assert_eq!(mgr.check_blocked("wikipedia.org"), None);
    }
}
