use common::TrafficData;
use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::Duration;

fn main(){
    let _ = std::fs::remove_file("/tmp/netmon.sock");
    let listener = UnixListener::bind("/tmp/netmon.sock").unwrap();

    for stream in listener.incoming(){
        let mut connection: UnixStream = stream.unwrap();
        loop{
            let fake_data = TrafficData{
                process_name: String::from("example_process"),
                bytes_downloaded: 1024,
            };

            let mut json_string = serde_json::to_string(&fake_data).unwrap();
            json_string.push('\n');

            connection.write_all(json_string.as_bytes()).unwrap();
            thread::sleep(Duration::from_secs(1));
        }
    }
}