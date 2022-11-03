pub enum PauseKind {
    PAUSE,
    RESUME,
}

pub struct Config {
    pub cmd: PauseKind,
    pub address: String,
    pub cid: String,
}

impl Config {
    pub fn new(mut args: std::env::Args) -> Result<Config, &'static str> {
        args.next(); // skip name of program

        let cmd: PauseKind = match args.next() {
            Some(arg) => {
                if arg.eq("pause") {
                    PauseKind::PAUSE
                } else if arg.eq("resume") {
                    PauseKind::RESUME
                } else {
                    return Err("Incorrect command: [pause | resume]");
                }
            }
            None => return Err("Missing: [pause | resume]"),
        };

        let address = match args.next() {
            Some(arg) => arg,
            None => return Err("Missing: [kata_agent IP address]"),
        };

        let cid = match args.next() {
            Some(arg) => arg,
            None => return Err("Missing: [container id]"),
        };

        Ok(Config { cmd, address, cid })
    }
}
