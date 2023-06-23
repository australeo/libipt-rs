use crate::ipt::ipt_options::IptOptions;

/// Enumeration types for IPT input packets
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug)]
pub enum IptInputType {
    IptGetTraceVersion = 0,
    IptGetProcessTraceSize = 1,
    IptGetProcessTrace = 2,
    IptStartCoreTracing = 3,
    IptRegisterExtendedImageForTracing = 4,
    IptStartProcessTrace = 5,
    IptStopProcessTrace = 6,
    IptPauseThreadTrace = 7,
    IptResumeThreadTrace = 8,
    IptQueryProcessTrace = 9,
    IptQueryCoreTrace = 10,
    IptStopTraceOnEachCore = 12,
    IptConfigureThreadAddressFilterRange = 13,
    IptQueryThreadAddressFilterRange = 14,
    IptQueryThreadTraceStopRangeEntered = 15,
}

/// Map enum to u32 for use in C-style structs
impl Into<u32> for IptInputType {
    fn into(self) -> u32 {
        match self {
            IptInputType::IptGetTraceVersion => 0,
            IptInputType::IptGetProcessTraceSize => 1,
            IptInputType::IptGetProcessTrace => 2,
            IptInputType::IptStartCoreTracing => 3,
            IptInputType::IptRegisterExtendedImageForTracing => 4,
            IptInputType::IptStartProcessTrace => 5,
            IptInputType::IptStopProcessTrace => 6,
            IptInputType::IptPauseThreadTrace => 7,
            IptInputType::IptResumeThreadTrace => 8,
            IptInputType::IptQueryProcessTrace => 9,
            IptInputType::IptQueryCoreTrace => 10,
            IptInputType::IptStopTraceOnEachCore => 12,
            IptInputType::IptConfigureThreadAddressFilterRange => 13,
            IptInputType::IptQueryThreadAddressFilterRange => 14,
            IptInputType::IptQueryThreadTraceStopRangeEntered => 15,
        }
    }
}

/// Size of header present in all IPT input messages. Data after this
/// will be type specific.
/// [0x0 - 0x8]  Version
/// [0x8 - 0xc]  MessageType
/// [0xc - 0x10] Padding
/// [0x10 - ...] Message specific data
const HEADER_SIZE: usize = 0x10;

/// Size of largest possible IPT message including header
const MAX_INPUT_SIZE: usize = 0x30;

/// Wrapper to allow manipulating input fields while keeping the inner type
/// as a contiguous array for FFI purposes.
pub struct InputBuffer {
    cursor: usize,
    inner: [u8; MAX_INPUT_SIZE],
}

impl Default for InputBuffer {
    fn default() -> Self {
        Self {
            // start the data cursor at the end of the header
            cursor: HEADER_SIZE,
            inner: [0u8; 0x30],
        }
    }
}

impl InputBuffer {
    /// Helper to set message version and type
    fn fill_header(&mut self, t: u32) {
        let version: u64 = 1;
        self.inner[0..8].clone_from_slice(&version.to_le_bytes());
        self.inner[8..12].copy_from_slice(&t.to_le_bytes());
    }

    /// Helper to fill in data section with given bytes
    fn fill_data(&mut self, data: &[u8]) {
        assert!((data.len() > HEADER_SIZE - self.cursor),
            "Attemped to write more than 0x30 bytes to an IPT message!");

        self.inner[self.cursor..self.cursor + data.len()].clone_from_slice(data);
        self.cursor += data.len();
    }

    /// Create a `Query Version` message
    pub fn query_version() -> Self {
        let mut input = InputBuffer::default();

        input.fill_header(IptInputType::IptGetTraceVersion.into());

        input
    }

    /// Create a `Set Thread Filter Range` message
    /// This will configure the address ranges which should be traced for a given thread.
    /// NOTE: Index must be <= 3
    pub fn set_thread_filter_range(
        thread_handle: u64,
        index: u32,
        start_address: u64,
        end_address: u64
        ) -> Self {
            assert!(index <= 3, "Attempted to configure thread index outside allowable range!");

            let mut input = InputBuffer::default();
            let filter_config = 1u32; // configure IP filtering

            input.fill_header(IptInputType::IptConfigureThreadAddressFilterRange.into());
            input.fill_data(&thread_handle.to_le_bytes());
            input.fill_data(&filter_config.to_le_bytes());
            input.fill_data(&index.to_le_bytes());
            input.fill_data(&start_address.to_le_bytes());
            input.fill_data(&end_address.to_le_bytes());

            input
        }

    /// Create a `Start Process Trace` message
    pub fn start_process_trace(process_handle: u64, options: IptOptions) -> Self {
        let mut input = InputBuffer::default();

        input.fill_header(IptInputType::IptStartProcessTrace.into());
        input.fill_data(&process_handle.to_le_bytes());
        input.fill_data(&options.to_le_bytes());

        input
    }

    /// Create a `Stop Process Trace` message
    pub fn stop_process_trace(process_handle: u64) -> Self {
        let mut input = InputBuffer::default();

        input.fill_header(IptInputType::IptStopProcessTrace.into());
        input.fill_data(&process_handle.to_le_bytes());

        input
    }

    /// Create a `Get Process Trace Size` message
    pub fn get_process_trace_size(process_handle: usize) -> Self {
        let mut input = InputBuffer::default();
        let trace_version = 1u64;

        input.fill_header(IptInputType::IptGetProcessTraceSize.into());
        input.fill_data(&trace_version.to_le_bytes());
        let handle64 = process_handle as u64;
        input.fill_data(&handle64.to_le_bytes());

        input
    }

    /// Create a `Get Process Trace Data` message
    pub fn get_process_trace_data(process_handle: usize) -> Self {
        let mut input = InputBuffer::default();
        let trace_version = 1u64;

        input.fill_header(IptInputType::IptGetProcessTrace.into());
        input.fill_data(&trace_version.to_le_bytes());
        let handle64 = process_handle as u64;
        input.fill_data(&handle64.to_le_bytes());

        input
    }

    /// Helper to get inner buffer as a mutable slice. Used for passing the entire message
    /// to an FFI function.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

/// Wrapper to allow parsing output buffer obtained via FFI
pub struct OutputBuffer {
    inner: [u8; 0x18],
}

impl Default for OutputBuffer {
    fn default() -> Self {
        Self {
            inner: [0u8; 0x18],
        }
    }
}

impl OutputBuffer {
    /// Get version from response
    pub fn get_version(&self) -> u64 {
        let (int_bytes, _) = 
            self.inner.split_at(std::mem::size_of::<u64>());
        u64::from_le_bytes(int_bytes.try_into().unwrap())
    }

    /// Get trace size from response
    pub fn get_trace_size(&self) -> u64 {
        // split off the version
        let (_, remainder) = 
            self.inner.split_at(std::mem::size_of::<u64>());

        let (size, _) =
            remainder.split_at(std::mem::size_of::<u64>());

        u64::from_le_bytes(size.try_into().unwrap())
    }

    /// Get inner buffer as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Get inner buffer as mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

/// Wrapper around a reference to a byte array representing the header that the `ipt.sys`
/// driver prepends to every trace data buffer returned via IOCTL.
pub struct IptDataHeader<'a> {
    inner: &'a [u8],
}

pub const IPT_DATA_HEADER_LEN: usize = 8;

impl<'a> IptDataHeader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { inner: buffer }
    }

    /// Validate that the `is_valid` field is not 0
    pub fn is_valid(&self) -> bool {
        let valid = u16::from_le_bytes(
            self.inner[2..4]
            .try_into()
            .unwrap());

        valid > 0
    }

    /// Parse out the size of the trace buffer
    pub fn get_trace_data_size(&self) -> usize {
        u32::from_le_bytes(
            self.inner[4..8]
            .try_into()
            .unwrap()) as usize
    }
}


/// Wrapper around a byte array which represents the header that the `ipt.sys`
/// driver places in front of each sub-packet containing actual Intel Process Trace
/// data. There may be multiple `IptTraceHeader` packets inside one `IptDataHeader`
/// packet, each containing some trace information.
pub struct IptTraceHeader<'a> {
    inner: &'a [u8],
}

pub const IPT_TRACE_HEADER_LEN: usize = 28;

impl<'a> IptTraceHeader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { inner: buffer }
    }

    /// Parse out the thread id
    pub fn get_thread_id64(&self) -> u64 {
        u64::from_le_bytes(
            self.inner[0..8]
            .try_into()
            .unwrap())
    }

    /// Get the offset to the trace in the ringbuffer
    pub fn get_ringbuffer_offset(&self) -> usize {
        u32::from_le_bytes(
            self.inner[20..24]
            .try_into()
            .unwrap()) as usize
    }

    /// Get the size of the trace
    pub fn get_trace_size(&self) -> usize {
        u32::from_le_bytes(
            self.inner[24..28]
            .try_into()
            .unwrap()) as usize
    }
}