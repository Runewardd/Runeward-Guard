pub mod detector;
pub mod host;
pub mod observer;
pub mod wire;

use serde::de::DeserializeOwned;

pub const MAX_EVENT_BYTES: usize = 1 << 20;

pub fn parse_exact<T: DeserializeOwned>(data: &[u8]) -> Result<T, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(data);
    let value = T::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    Ok(value)
}
