use crate::core::types::ScanResult;

pub fn to_json(result: &ScanResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|e| {
        format!("{{\"error\": \"Failed to serialize: {}\"}}", e)
    })
}

pub fn print_json(result: &ScanResult) {
    println!("{}", to_json(result));
}
