//execute commands using cmd.exe
use std::process::Command;
use obfstr::obfstr as m;

pub fn cmd_command(args: Vec<&str>) -> String {

    let command = args[0].to_string();
    if args.is_empty() {
        return m!("give command").to_string();
    }
    let mut ret = String::new();

    //this executes only system commands

    let output = match Command::new(command.clone()).args(&args).output() {
        Ok(output) => output,
        Err(err) => {
            log::debug!("Error executing command: {}", err);
            return ret;
        }
    };

    ret = String::from_utf8(output.stdout).unwrap();

    return ret;


}