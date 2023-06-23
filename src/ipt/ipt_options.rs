#![allow(non_upper_case_globals)]
/// Code for handling the Ipt Options bitfield structure, including getters/setters for
/// each option. 
/// 
/// Above attribute is to allow a find/replace macro to generate the these methods automatically 
/// while using lowercase method names, and the constants themselves are private anyway.
use std::{fmt, arch::asm};
use paste::paste;

/// u64 bitfield representing the user configurable features of the IPT.SYS driver
#[derive(Clone, Copy)]
pub struct IptOptions {
    inner: u64,
}

/// Pretty print all options with hex values
impl fmt::Debug for IptOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IptOptions")
        .field("Raw value", &format_args!("{:#x}", &self.inner))
        .field("OptionVersion", &format_args!("{:#x}", &self.get_version()))
        .field("TimingSettings", &format_args!("{:#x}", &self.get_timing()))
        .field("MtcFrequency ", &format_args!("{:#x}", &self.get_mtc()))
        .field("CycThreshold ", &format_args!("{:#x}", &self.get_cyc()))
        .field("TopaPagesPow2", &format_args!("{:#x}", &self.get_topa()))
        .field("MatchSettings", &format_args!("{:#x}", &self.get_matchs()))
        .field("Inherit", &format_args!("{:#x}", &self.get_inherit()))
        .field("ModeSettings ", &format_args!("{:#x}", &self.get_mode()))
        .finish()
    }
}

/// Always starts with version set to `1`
impl Default for IptOptions {
    fn default() -> Self {
        Self {
            inner: 1,
        }
    }
}

/// Macro to generate setters for the various option fields
macro_rules! set_option {
    ($option:ident) => {
    paste! {
            pub fn [<set_ $option>](&mut self, value: u64) -> () {
                // shift the new value up to the bit position it occupies in IptOptions
                let new_value: u64 = value << [<$option _SHIFT>];
                // capture the current value of the overall IptOptions
                let old_options = self.inner;
                // mask the current bits for the specified value to 0 the OR in the new value
                self.inner = (old_options & ![<$option _MASK>]) | new_value;
            }
        }
    }
}

/// Macro to generate getters for the various option fields
macro_rules! get_option {
    ($option:ident) => {
    paste! {
            pub fn [<get_ $option>](&self) -> u64 {
                // mask off the option's bits then shift them down to LSB
                return (self.inner & [<$option _MASK>]) >> [<$option _SHIFT>]
            }
        }
    }
}

/// Constants which allow for masking and shifting to LSB the option fields,
/// used with the above macros to generate methods
const version_MASK: u64 = 0xf;
const version_SHIFT: u64 = 0;

const timing_MASK: u64 = 0xf0;
const timing_SHIFT: u64 = 4;

const mtc_MASK: u64 = 0xf00;
const mtc_SHIFT: u64 = 8;

const cyc_MASK: u64 = 0xf000;
const cyc_SHIFT: u64 = 12;

const topa_MASK: u64 = 0xf_0000;
const topa_SHIFT: u64 = 16;

const matchs_MASK: u64 = 0x70_0000;
const matchs_SHIFT: u64 = 20;

const inherit_MASK: u64 = 0x80_0000;
const inherit_SHIFT: u64 = 23;

const mode_MASK: u64 = 0xF00_0000;
const mode_SHIFT: u64 = 24;

impl IptOptions {
    /// Get options field as a byte array
    pub fn to_le_bytes(&self) -> [u8; 8] {
        self.inner.to_le_bytes()
    }

    /// Create a new IptOptions with desired trace size. Performs checks on the size and will silently
    /// modify them to be within min/max allowed bounds. Can use `get_size_in_bytes`to check if
    /// modification has occurred.
    pub fn new(buffer_size: usize) -> Self {
        let mut options = IptOptions::default();
        let size;

        // Sanity check for the allowable sizes
        if buffer_size < 0x1000 {
            size = 0x1000;
        } else if buffer_size > 0x800_0000 {
            size = 0x800_0000;
        } else {
            size = buffer_size;
        }

        let mut size_bit_index;
        unsafe {
            // SAFETY: size cannot be zero 
            size_bit_index = bit_scan_reverse(size as u64);
        }

        // The minimum size is 0x1000 or b1_0000_0000_0000 (12th bit index) so we shift
        // the "size index" back by 12 to get the `TOPA` offset used by the IPT driver.
        size_bit_index -= 12;
        
        options.set_topa(size_bit_index);

        options
    }

    /// Get the configured trace size in number of bytes
    pub fn get_size_in_bytes(&self) -> usize {
        let topa = self.get_topa() as usize;
        
        // Add the `TOPA` offset back to the value to get the real bit index
        let bit_index: usize = topa + 12;

        // Shift by the index to get the trace size value in bytes
        return 1 << bit_index;
    }

    set_option!(version);
    get_option!(version);

    set_option!(timing);
    get_option!(timing);

    set_option!(mtc);
    get_option!(mtc);

    set_option!(cyc);
    get_option!(cyc);

    set_option!(topa);
    get_option!(topa);
    
    set_option!(matchs);
    get_option!(matchs);

    set_option!(inherit);
    get_option!(inherit);

    set_option!(mode);
    get_option!(mode);
}

/// Helper ASM function, we know the arch will always be x86 ;)
/// 
/// SAFETY: `src` should be checked by the caller to ensure it is > 0, 
/// and note this will clear the ZF.
/// 
/// See also: https://www.felixcloutier.com/x86/bsr
#[inline]
unsafe fn bit_scan_reverse(src: u64) -> u64 {
    let mut s = src;
    asm!(
        "bsr {s}, {s}",
        s = inout(reg) s,
    );

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version() {
        let mut opt = IptOptions::default();
        opt.set_version(0xf);
        assert_eq!(0xf, opt.get_version());
    }

    #[test]
    fn timing() {
        let mut opt = IptOptions::default();
        opt.set_timing(0xf);
        assert_eq!(0xf, opt.get_timing());
    }

    #[test]
    fn mtc() {
        let mut opt = IptOptions::default();
        opt.set_mtc(0xf);
        assert_eq!(0xf, opt.get_mtc());
    }

    #[test]
    fn cyc() {
        let mut opt = IptOptions::default();
        opt.set_cyc(0xf);
        assert_eq!(0xf, opt.get_cyc());
    }

    #[test]
    fn topa() {
        let mut opt = IptOptions::default();
        opt.set_topa(0xf);
        assert_eq!(0xf, opt.get_topa());
    }

    #[test]
    fn matchs() {
        let mut opt = IptOptions::default();
        opt.set_matchs(0xf);
        assert_eq!(0x7, opt.get_matchs());
    }

    #[test]
    fn inherit() {
        let mut opt = IptOptions::default();
        opt.set_inherit(0xf);
        assert_eq!(1, opt.get_inherit());
    }

    #[test]
    fn mode() {
        let mut opt = IptOptions::default();
        opt.set_mode(0xf);
        assert_eq!(0xf, opt.get_mode());
    }

    #[test]
    fn debug() {
        let mut opt = IptOptions::default();
        opt.set_version(0x1);
        opt.set_timing(0x1);
        opt.set_mtc(0x1);
        opt.set_cyc(0x1);
        opt.set_topa(0x1);
        opt.set_matchs(0x1);
        opt.set_inherit(0x1);
        opt.set_mode(0x1);
        // pretty print to check that none of the values have overflowed
        println!("{:#?}", opt);
    }

    #[test]
    fn bsr() {
        unsafe {
            let bits = 0x10u64;
            let msb = bit_scan_reverse(bits);
            assert_eq!(4, msb);
        }
    }

    #[test]
    fn topa_to_size() {
        let opt = IptOptions::new(0x1000);
        let size = opt.get_size_in_bytes();
        assert_eq!(size, 0x1000);
    }

}