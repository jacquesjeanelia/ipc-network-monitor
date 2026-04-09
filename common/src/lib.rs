use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TrafficData{
    pub process_name: String,
    pub bytes_downloaded: u32,
}