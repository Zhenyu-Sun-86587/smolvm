//! Linux cgroup v2 CPU bandwidth units shared by Serve and the Worker.

const DEFAULT_PERIOD_USEC: u64 = 100_000;
const MAX_PERIOD_USEC: u64 = 1_000_000;
const MIN_BANDWIDTH_USEC: u64 = 1_000;
const USEC_PER_SECOND: u64 = 1_000_000;
const USEC_PER_MILLICPU: u64 = 1_000;

/// Convert CPU time per second to the quota for the supplied period.
pub fn cpu_max_quota_us(usec_per_sec: u64, period_us: u64) -> u64 {
    (usec_per_sec.saturating_mul(period_us) / USEC_PER_SECOND).max(MIN_BANDWIDTH_USEC)
}

/// Serialize a finite limit, stretching the period for limits under 10 mCPU
/// so that the kernel's minimum quota doesn't raise the requested bandwidth.
fn cpu_max_period_us(usec_per_sec: u64) -> u64 {
    if usec_per_sec == 0
        || usec_per_sec.saturating_mul(DEFAULT_PERIOD_USEC) / USEC_PER_SECOND >= MIN_BANDWIDTH_USEC
    {
        DEFAULT_PERIOD_USEC
    } else {
        (MIN_BANDWIDTH_USEC * USEC_PER_SECOND)
            .div_ceil(usec_per_sec)
            .min(MAX_PERIOD_USEC)
    }
}

pub fn cpu_max_line(usec_per_sec: u64) -> String {
    let period = cpu_max_period_us(usec_per_sec);
    format!("{} {period}", cpu_max_quota_us(usec_per_sec, period))
}

/// Serialize a whole-millicpu limit with an exact quota at the chosen period.
pub fn cpu_max_millicpus_line(millicpus: u64) -> String {
    let usec_per_sec = millicpus * USEC_PER_MILLICPU;
    let period = cpu_max_period_us(usec_per_sec).div_ceil(USEC_PER_MILLICPU) * USEC_PER_MILLICPU;
    format!("{} {period}", cpu_max_quota_us(usec_per_sec, period))
}

/// Whether the controller reports the requested bandwidth at its actual period.
pub fn cpu_max_matches(cpu_max: &str, usec_per_sec: u64) -> bool {
    let mut fields = cpu_max.split_whitespace();
    let quota = fields.next().and_then(|field| field.parse::<u64>().ok());
    let period = fields.next().and_then(|field| field.parse::<u64>().ok());
    matches!((quota, period), (Some(quota), Some(period))
        if period > 0 && fields.next().is_none() && cpu_max_quota_us(usec_per_sec, period) == quota)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_small_millicpu_limit_is_exact_at_the_kernel_quota_floor() {
        for millicpus in 1..=10 {
            let limit = cpu_max_millicpus_line(millicpus);
            let (quota, period) = limit.split_once(' ').unwrap();
            let (quota, period): (u64, u64) = (quota.parse().unwrap(), period.parse().unwrap());
            assert!((100_000..=MAX_PERIOD_USEC).contains(&period));
            assert!(quota >= MIN_BANDWIDTH_USEC);
            assert_eq!(quota * 1_000, millicpus * period);
        }
        assert_eq!(cpu_max_millicpus_line(250), "25000 100000");
    }
}
