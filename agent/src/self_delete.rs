use std::time::Duration;
use std::env;
use std::io::Write;
use std::fs::File;
use std::thread;
use std::process::Command;
use std::error::Error;

pub fn self_delete() -> Result<(), Box<dyn Error>> {
    let exe_path = env::current_exe()?.display().to_string();

    let batch_content = format!(
        "@echo off\n\
        timeout /t 3 /nobreak > NUL\n\
        del \"{}\"",
       exe_path
    );

    let batch_file = "sd.bat";
    let mut file = File::create(batch_file)?;
    file.write_all(batch_content.as_bytes())?;

    //execute the batch file
    Command::new("cmd")
        .args(&["/C", batch_file])
        .spawn()?;

        //give some time to execute before Rust program exits
        thread::sleep(Duration::from_secs(3));

        Ok(())
}