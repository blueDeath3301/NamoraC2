# 🚀 NAMORA

![Namora Logo](namora.png "Namora Logo")

---

## ⚠️ Disclaimer
**Messy code ahead!**  
This project was built quickly and contains a critical bug. While the implant connects back to the teamserver and waits for commands, attempting to send a command using the client results in a **signature verification error**. Check the TODO file for more details.  
Feel free to debug it (you can use the JSON file in the `.vscode` directory) and fix it if you want to use **Namora (Naked Mole Rat)**.

---

## ❓ What is Namora?
**Namora** is a Command and Control (C2) framework written in Rust, inspired by various GitHub projects.  
The Cargo workspace consists of three components:
1. **Windows Agent (Implant)**  
2. **Server (Teamserver)**  
3. **CLI Client** (GUI planned using `egui` or `Slint`)

### 🔒 Security Features
- **End-to-End Encryption**: Communication between the server and implant is secured using **ECDH** and **XChaCha20Poly1305**.
- **Authentication**: Ensured via **ed25519-dalek** signatures. The agent authenticates its signature to the server.
- **Agent Management**: Supports up to 20 agents, registered in a **Postgres database**.

---

## 🖥️ Components

### 🌐 Server
- Requires a **Postgres database** for storing agent data.  
- You can use tools like **pgAdmin** for easier database management.  
- Configure the server port and database URL in the source code or use environment variables.  
- Run the server from the terminal.

---

### 🛠️ Client
- The client sends commands to the implant via the server.  
- The server authenticates the client's signature before relaying commands to the agent.

---

### 🕵️‍♂️ Agent
The Windows implant is designed as a stealthy, persistent backdoor with advanced post-exploitation capabilities.  
It includes several **shellcode loading techniques** and **EDR evasion mechanisms**.  

#### Key Features:
1. **Threadless Injection**  
2. **Thread Encryption**  
3. **Dynamic NTAPI Resolution**  
4. **Indirect Syscalls**:
   - Callstack Spoofing  
   - Syscall Parameter Spoofing (via VEH and breakpoints)  
   - VEH Syscalls  
5. **NTDLL.dll Unhooking**  
6. **Module Fluctuation**: Loads a fresh copy of `ntdll.dll` and hides it from EDRs.  
7. **Sleep Obfuscation**: Uses ROP chains.  
8. **PPID Spoofing**  
9. **BlockDLLs & ACG**  

#### Additional Capabilities:
- Executes staged PowerShell scripts or direct commands with **AMSI** and **ETW bypass**.  
- Loads .NET assemblies and BOFs using **CoffeeLdr**.

---

## 🙌 Credits
This project was inspired by and built upon the following amazing repositories:
1. [Dinvoke-rs, Shelter, and Unwinder](https://github.com/Kudaes)  
2. [SnapInject](https://github.com/Teach2Breach)  
3. [NovaLdr](https://github.com/BlackSnufkin/NovaLdr)  
4. [Black Hat Rust Code](https://github.com/skerkour/black-hat-rust)  
5. [Rust for Malware Development](https://github.com/Whitecat18/Rust-for-Malware-Development)  
6. [AMSI Bypass & PowerShell Execution](https://github.com/BlackSnufkin/NyxInvoke)  

---

## 💡 Final Thoughts
Yes, it might sound like overkill, but this project was a learning exercise in **malware development with Rust**.  
Feedback and constructive criticism are always welcome!
