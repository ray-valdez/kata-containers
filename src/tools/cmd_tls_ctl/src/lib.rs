pub struct Config {
    pub address: String,
    pub cid: String
}

impl Config {
    pub fn new (mut args: std::env::Args) -> Result<Config, &'static str> {
        args.next(); // skip name of program
        let address = match args.next() {
            Some(arg) => arg,
            None => return Err("Missing: [kata_agent IP address]"),
        };

        let cid = match args.next() {
            Some(arg) => arg,
            None => return Err("Missing: [container id]"),
        };

        Ok(Config { address, cid })
    }
}





