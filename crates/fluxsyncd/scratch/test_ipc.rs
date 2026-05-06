use std::os::unix::net::UnixStream;
use std::io::{Write, BufRead, BufReader};
use std::path::PathBuf;

fn main() {
    let home = std::env::var("HOME").unwrap_or_default();
    let path = PathBuf::from(&home).join(".fluxsync").join("sock");
    println!("Testing connection to: {:?}", path);
    println!("HOME env: {:?}", home);

    match UnixStream::connect(&path) {
        Ok(stream) => {
            println!("✅ SUCCESS: Connected to socket!");
            let mut writer = stream;
            writer.write_all(b"{\"subscribe\":\"state\"}\n").expect("write failed");
            
            let mut reader = BufReader::new(&writer);
            let mut line = String::new();
            reader.read_line(&mut line).expect("read failed");
            println!("📥 RECEIVED: {}", line);
        }
        Err(e) => {
            println!("❌ FAILURE: Could not connect: {}", e);
            if !path.exists() {
                println!("   (File does not exist)");
            }
        }
    }
}
