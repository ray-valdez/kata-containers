#[derive(PartialEq)]
pub enum CmdKind {
    PAUSE,
    RESUME,
    LISTCONTAINERS,
}

pub struct Config {
    pub cmd: CmdKind,
    pub address: String,
    pub cid: String,
}

impl Config {
    pub fn new(mut args: std::env::Args) -> Result<Config, &'static str> {
        args.next(); // skip name of program

        let cmd: CmdKind = match args.next() {
            Some(arg) => {
                if arg.eq("pause") {
                    CmdKind::PAUSE
                } else if arg.eq("resume") {
                    CmdKind::RESUME
                } else if arg.eq("listcontainers") {
                    CmdKind::LISTCONTAINERS
                } else {
                    return Err("Incorrect command: [listcontainers | pause | resume]");
                }
            }
            None => return Err("Missing: [listcontainers | pause | resume]"),
        };

        let address = match args.next() {
            Some(arg) => arg,
            None => return Err("Missing: [kata_agent IP address]"),
        };
        
        if cmd == CmdKind::LISTCONTAINERS {
            return Ok(Config { cmd, address, cid: "None".to_string() });            
        }

        let cid = match args.next() {
            Some(arg) => arg,
            None => return Err("Missing: [container id]"),
        };

        Ok(Config { cmd, address, cid })
    }
}
