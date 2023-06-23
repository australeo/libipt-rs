use crate::ipt::ipt_buffers::{OutputBuffer, InputBuffer, IPT_DATA_HEADER_LEN, IptDataHeader, IPT_TRACE_HEADER_LEN};
use crate::ipt::ipt_options::IptOptions;
use crate::ffi::filesystem::{close_handle, create_file_read, device_io_control};
use windows::Win32::Foundation::HANDLE;

use super::ipt_buffers::IptTraceHeader;

type Result<T> = std::result::Result<T, &'static str>;

/// IOCTL for control messages
pub const IPT_IOCTL_REQUEST: u32 = 0x220004;
/// IOTCL for `read trace` messages
pub const IPT_IOCTL_READ_TRACE: u32 = 0x220006;
/// Path for IPT device
pub const IPT_DEVICE_PATH: &'static str = "\\??\\IPT";

fn print_ipt_service_message() {
    println!(
    "################################################
     # Failed to obtain a handle to the IPT device! #
     # This may mean the IPT service is not running.#
     # Run the following from an administrative cmd #
     # prompt to enable it:                         #
     #      `sc start ipt`                          #
     ################################################
    ")
}

/// Controller object for interacting with the IPT driver
pub struct IptController {
    /// Handle to the IPT device
    device_handle: HANDLE,
    /// Options for IPT tracing
    options: IptOptions,
    /// Maximum size of the trace buffer
    trace_buffer_max: usize,
    /// Buffer for storing trace data
    trace_buffer: Vec<u8>,
}

/// Close the device handle on drop
impl Drop for IptController {
    fn drop(&mut self) {
        if self.device_handle != HANDLE(0) {
            let temp = self.device_handle;
            self.device_handle = HANDLE(0);
            close_handle(temp);
        }
    }
}

impl IptController {
    /// Create a new controller object, can fail if obtaining a handle to the windows 
    /// IPT device fails.
    pub fn create_controller(options: IptOptions) -> Result<Self> {
        let device_handle;

        // SAFETY: Opening the device handle requires an FFI call
        unsafe {
            match create_file_read(IPT_DEVICE_PATH) {
                Ok(handle) => device_handle = handle,
                Err(e) => {
                    print_ipt_service_message();
                    return Err(e);
                },
            }
    
            Ok(
                Self {
                    device_handle,
                    options,
                    trace_buffer_max: options.get_size_in_bytes(),
                    trace_buffer: Vec::<u8>::with_capacity(options.get_size_in_bytes() + 8),
                }
            )
        }
    }

    /// Get the IPT protocol version in use by the windows driver
    pub fn get_ipt_version(&self) -> Result<u64> {
        let mut in_buffer = InputBuffer::query_version();
        let mut out_buffer = OutputBuffer::default();

        unsafe {
            let _ = device_io_control(
                self.device_handle,
                IPT_IOCTL_REQUEST,
                &mut in_buffer.as_mut_slice(),
                &mut out_buffer.as_mut_slice()
            )?;
        }

        Ok(out_buffer.get_version())
    }

    /// Set the range of instruction pointer addresses to be trace.
    /// Up to four pairs of start/end addresses can be provided.
    pub fn set_ip_filter_range(
        &mut self, 
        thread_handle: usize,
        index: u32,
        start_address: u64,
        end_address: u64,
    ) -> Result<()> {
        if index > 3 {
            return Err("Index is outside of range 0-3!");
        }

        let mut in_buffer = InputBuffer::set_thread_filter_range(
            thread_handle as u64,
            index,
            start_address,
            end_address
        );
        let mut out_buffer = OutputBuffer::default();

        unsafe {
            let _ = device_io_control(
                self.device_handle,
                IPT_IOCTL_REQUEST,
                &mut in_buffer.as_mut_slice(),
                &mut out_buffer.as_mut_slice()
            )?;
        }

        Ok(())
    }

    /// Start IPT tracing on a target process
    pub fn start_tracing_on_process(&mut self, process_handle: u64) -> Result<()> {
        let mut in_buffer = InputBuffer::start_process_trace(
            process_handle, self.options);
        let mut out_buffer = OutputBuffer::default();

        unsafe {
            let _ = device_io_control(
                self.device_handle,
                IPT_IOCTL_REQUEST,
                &mut in_buffer.as_mut_slice(),
                &mut out_buffer.as_mut_slice()
            )?;
        }

        Ok(())
    }

    /// Stop IPT tracing on a target process
    pub fn stop_tracing_on_process(&mut self, process_handle: u64) -> Result<()> {
        let mut in_buffer = InputBuffer::stop_process_trace(process_handle);
        let mut out_buffer = OutputBuffer::default();

        unsafe {
            let _ = device_io_control(
                self.device_handle,
                IPT_IOCTL_REQUEST,
                &mut in_buffer.as_mut_slice(),
                &mut out_buffer.as_mut_slice()
            )?;
        }

        println!("Stopped tracing on process {:#x}", process_handle);

        Ok(())
    }

    /// Get the trace data for a target thread
    pub fn get_trace_data_for_process(
        &mut self, 
        process_handle: usize, 
        thread_id: u32
    ) -> Result<&[u8]> {
        // setup to get trace size
        let mut in_size_buffer = InputBuffer::get_process_trace_size(process_handle);
        let mut out_buffer = OutputBuffer::default();

        unsafe {
            let _ = device_io_control(
                self.device_handle,
                IPT_IOCTL_REQUEST,
                &mut in_size_buffer.as_mut_slice(),
                &mut out_buffer.as_mut_slice()
            )?;
        }

        let trace_size = out_buffer.get_trace_size() as usize;

        println!("Got trace size of {:#x} for process {:#x}", trace_size, process_handle);

        // setup to get ipt trace data
        let mut in_trace_buffer = InputBuffer::get_process_trace_data(process_handle);
        let mut ipt_trace_data = vec![0u8; trace_size];
        unsafe {
            let _ = device_io_control(
                self.device_handle,
                IPT_IOCTL_READ_TRACE,
                &mut in_trace_buffer.as_mut_slice(),
                &mut ipt_trace_data.as_mut_slice()
            )?;
        }

        println!("Got trace data for process {:#x}", process_handle);

        // parse trace data will read the IPT headers to find the actual size
        // of the trace packets
        self.parse_ipt_header(&ipt_trace_data, thread_id)?;

        // tag end of trace
        self.trace_buffer.push(0x55);
        Ok(&self.trace_buffer[..])
    }

    /// for debugging
    pub fn get_handle(&self) -> HANDLE {
        self.device_handle
    }

    /// Extract Intel PT data from Window ipt.sys metadata
    fn parse_ipt_header(
        &mut self, 
        header: &[u8], 
        thread_id: u32
    ) -> Result<()> {
        assert!(header.len() >= IPT_DATA_HEADER_LEN);

        // get the header for the overall packet
        let data_header = IptDataHeader::new(&header[0..8]);
        if data_header.is_valid() == false {
            return Err("Trace is invalid!");
        }

        // get the size of the remaining data
        let trace_buffer_size = data_header.get_trace_data_size();
        println!("IptDataHeader size: {:#x}", data_header.get_trace_data_size());

        let mut trace_header;
        let mut cursor = IPT_DATA_HEADER_LEN;

        while cursor <= (trace_buffer_size - IPT_TRACE_HEADER_LEN) {
            // get the header for the next trace
            trace_header = IptTraceHeader::new(
                &header[cursor..]);

            cursor += IPT_TRACE_HEADER_LEN;
            let data_offset = cursor;
            cursor += trace_header.get_trace_size();
            println!("IptTraceHeader size: {:#x}", trace_header.get_trace_size());

            println!("Got thread id {:#x}, target: {:#x}", trace_header.get_thread_id64(), thread_id);
            if trace_header.get_thread_id64() == thread_id as u64 {
                // extract the trace data and add it to the buffer
                self.extract_ipt_trace_data(
                    &trace_header, 
                    &header[data_offset..cursor]
                )?;
            }

            cursor += trace_header.get_trace_size();
        }

        Ok(())
    }

    fn extract_ipt_trace_data(
        &mut self, 
        header: &IptTraceHeader, 
        trace: &[u8]
    ) -> Result<()> {
        // trace has not overflowed
        if header.get_ringbuffer_offset() > self.trace_buffer.len() {
            self.append_trace_data(trace);
            Ok(())
        } else {
            Err("Trace overflowed!")
        }
    }

    fn append_trace_data(
        &mut self,
        data: &[u8]
    ) {
        // if there is space remaining, push the trace data onto the buffer
        if self.trace_buffer.len() + data.len() < self.trace_buffer_max {
            self.trace_buffer.extend_from_slice(data);
        } else {
            let remaining = self.trace_buffer_max - self.trace_buffer.len();
            // only take what we can fit
            self.trace_buffer.extend_from_slice(&data[..remaining]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_version() {
        let opt = IptOptions::default();
        let controller = IptController::create_controller(opt).unwrap();
        let version = controller.get_ipt_version().unwrap();
        println!("VERSION: {:x}", version);
        assert_eq!(1, version);
    }
}
