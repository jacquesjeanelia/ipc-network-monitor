use common::TrafficData;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;

fn main(){
    let stream = UnixStream::connect("/tmp/netmon.sock").unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    loop{
        line.clear();
        reader.read_line(&mut line).unwrap();
        let received_data: TrafficData = serde_json::from_str(&line).unwrap();
        println!("Received data: Process: {}, Bytes Downloaded: {}", received_data.process_name, received_data.bytes_downloaded);
    }
}