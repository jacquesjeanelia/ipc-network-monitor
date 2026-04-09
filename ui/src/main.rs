use common::TrafficData;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;

fn main(){
    let stream = UnixStream::connect("/tmp/netmon.sock").unwrap(); // Connect to the Unix socket created by the Rust application
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    loop{
        line.clear(); // Clear the line buffer before reading new data
        reader.read_line(&mut line).unwrap(); 
        let received_data: TrafficData = serde_json::from_str(&line).unwrap(); // Deserialize the JSON string into a TrafficData struct
        println!("Received data: Process: {}, Bytes Downloaded: {}", received_data.process_name, received_data.bytes_downloaded);
    }
}