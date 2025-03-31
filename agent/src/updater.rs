use std::fs;
use std::env;
use std::process::Command;
use reqwest::blocking::get;
use serde::Deserialize;

const UPDATE_URL: &str = "http://example.com/latest_version";
const DOWNLOAD_URL: &str = "http://example.com/download/latest_version";
const CURRENT_VERSION: &str = "0.1.0";

#[derive(Deserialize)]
struct VersionInfo {
    version: String,
}


pub fn full_update() {
   
   //check for updates
   let response = get(UPDATE_URL).unwrap().text().unwrap();
    let version_info: VersionInfo = serde_json::from_str(&response).unwrap();
    version_info.version != CURRENT_VERSION;


    //download the update
    let response = get(DOWNLOAD_URL).unwrap();
    let mut file = fs::File::create("latest_version.exe").unwrap();
    let content = response.bytes().unwrap();
    use std::io::Write;
    file.write_all(&content).unwrap();

    //replace the current executable
    let current_executable = env::current_exe().unwrap();
    fs::remove_file(&current_executable).unwrap();
    fs::rename("latest_version.exe", &current_executable).unwrap();


    //restart the agent
    let current_executable = env::current_exe().unwrap();
    Command::new(current_executable)
        .spawn()
        .unwrap();

}