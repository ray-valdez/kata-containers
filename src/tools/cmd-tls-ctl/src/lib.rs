#[derive(PartialEq)]
pub enum CmdKind {
    PAUSE,
    RESUME,
    LISTCONTAINERS,
}

pub struct Config {
    pub key_path: String,
    pub cmd: CmdKind,
    pub address: String,
    pub cid: String,
}

impl Config {
    pub fn new(mut args: std::env::Args) -> Result<Config, &'static str> {
        args.next(); // skip name of program

        if args.len() == 0 {
             return Err("Usage: cmd-tls-ctl <CLIENT_KEY_PATH> <listcontainers | pause | resume> [kata-agent_ip_addr] [container-id] ");
        }

        let key_path = match args.next() {
            Some(arg) => arg,
            None => return Err("Missing: [kata_agent IP address]"),
        };

        let cmd: CmdKind = match args.next() {
            Some(arg) => {
                if arg.eq("pause") {
                    CmdKind::PAUSE
                } else if arg.eq("resume") {
                    CmdKind::RESUME
                } else if arg.eq("listcontainers") {
                    CmdKind::LISTCONTAINERS
                } else {
                    return Err("Incorrect command:  listcontainers, pause, or  resume >");
                }
            }
            None => return Err("Missing: <listcontainers | pause | resume>"),
        };

        let address = match args.next() {
            Some(arg) => arg,
            None => return Err("Missing: kata_agent IP address"),
        };
        
        if cmd == CmdKind::LISTCONTAINERS {
            return Ok(Config { key_path, cmd, address, cid: "None".to_string() });            
        }

        let cid = match args.next() {
            Some(arg) => arg,
            None => return Err("Missing: container-id"),
        };

        Ok(Config { key_path, cmd, address, cid })
    }
}
