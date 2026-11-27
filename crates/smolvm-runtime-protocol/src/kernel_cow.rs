//! Fixed RAM layout shared by the Worker, the capture actor and libkrun.

use serde::{Deserialize, Serialize};

pub const PROFILE: &str = "kernel_cow_anon_v1";
pub const MAX_REGIONS: usize = 64;
const PAGE: u64 = 4096;
const HOST_BASE: u64 = 0x4000_0000_0000;
const HOST_LIMIT: u64 = 0x4800_0000_0000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(C)]
pub struct Region {
    pub guest_start: u64,
    pub size: u64,
}

/// Validate the ordered regions of this profile and return the packed RAM size.
pub fn packed_size(regions: &[Region]) -> Result<u64, &'static str> {
    const INVALID: &str = "invalid fixed CoW RAM layout";
    if regions.is_empty() || regions.len() > MAX_REGIONS {
        return Err(INVALID);
    }
    let mut previous_end = 0;
    let mut total = 0_u64;
    for (index, region) in regions.iter().enumerate() {
        if !region.guest_start.is_multiple_of(PAGE)
            || region.size == 0
            || !region.size.is_multiple_of(PAGE)
            || region.guest_start < previous_end
        {
            return Err(INVALID);
        }
        previous_end = region.guest_start.checked_add(region.size).ok_or(INVALID)?;
        let limit = HOST_LIMIT - HOST_BASE - index as u64 * PAGE;
        if previous_end > limit {
            return Err(INVALID);
        }
        total = total.checked_add(region.size).ok_or(INVALID)?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_layout_is_ordered_aligned_and_bounded() {
        let first = Region {
            guest_start: 0,
            size: PAGE,
        };
        let second = Region {
            guest_start: PAGE * 3,
            size: PAGE * 2,
        };
        assert_eq!(packed_size(&[first, second]), Ok(PAGE * 3));
        assert!(packed_size(&[second, first]).is_err());
        assert!(packed_size(&[first, first]).is_err());
        assert!(packed_size(&[Region {
            size: PAGE + 1,
            ..first
        }])
        .is_err());
        assert!(packed_size(&[Region {
            guest_start: HOST_LIMIT - HOST_BASE,
            ..first
        }])
        .is_err());
    }
}
