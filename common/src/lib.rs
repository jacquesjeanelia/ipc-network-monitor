use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)] 
pub struct TrafficData{ // Define a struct to hold the traffic data for each process
    pub process_name: String,
    pub bytes_downloaded: u32,
}