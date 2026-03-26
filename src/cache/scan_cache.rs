use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::core::types::ScanResult;

const DEFAULT_TTL_SECS: u64 = 3600;
const CACHE_FILENAME: &str = ".clawfortify-cache.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheEntry {
    pub content_hash: String,
    pub timestamp: u64,
    pub result: ScanResult,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScanCache {
    pub entries: HashMap<String, CacheEntry>,
    #[serde(skip)]
    cache_path: Option<PathBuf>,
    #[serde(skip)]
    ttl: Duration,
}

impl ScanCache {
    pub fn new(ttl_secs: Option<u64>) -> Self {
        let cache_path = cache_dir().map(|d| d.join(CACHE_FILENAME));
        let ttl = Duration::from_secs(ttl_secs.unwrap_or(DEFAULT_TTL_SECS));
        let mut cache = Self {
            entries: HashMap::new(),
            cache_path: cache_path.clone(),
            ttl,
        };
        if let Some(ref path) = cache_path {
            cache.load_from_disk(path);
        }
        cache
    }

    pub fn content_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn get(&self, file_path: &str, content: &str) -> Option<&ScanResult> {
        let entry = self.entries.get(file_path)?;
        let hash = Self::content_hash(content);
        if entry.content_hash != hash {
            return None;
        }
        let now = now_secs();
        if now.saturating_sub(entry.timestamp) > self.ttl.as_secs() {
            return None;
        }
        Some(&entry.result)
    }

    pub fn put(&mut self, file_path: String, content: &str, result: ScanResult) {
        let entry = CacheEntry {
            content_hash: Self::content_hash(content),
            timestamp: now_secs(),
            result,
        };
        self.entries.insert(file_path, entry);
        self.save_to_disk();
    }

    pub fn invalidate(&mut self, file_path: &str) {
        self.entries.remove(file_path);
        self.save_to_disk();
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.save_to_disk();
    }

    pub fn prune_expired(&mut self) {
        let now = now_secs();
        let ttl = self.ttl.as_secs();
        self.entries
            .retain(|_, entry| now.saturating_sub(entry.timestamp) <= ttl);
        self.save_to_disk();
    }

    fn load_from_disk(&mut self, path: &Path) {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(loaded) = serde_json::from_str::<ScanCache>(&content) {
                self.entries = loaded.entries;
            }
        }
    }

    fn save_to_disk(&self) {
        if let Some(ref path) = self.cache_path {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(path, serde_json::to_string(self).unwrap_or_default());
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cache_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(|p| PathBuf::from(p).join("clawfortify"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .ok()
            .map(|p| PathBuf::from(p).join(".cache").join("clawfortify"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{Grade, RiskScore, ScanResult};
    use std::collections::HashMap;

    fn dummy_result() -> ScanResult {
        ScanResult {
            skill_path: "test.md".into(),
            risk_score: RiskScore {
                score: 0,
                grade: Grade::A,
                findings: vec![],
            },
            pass_summaries: HashMap::new(),
        }
    }

    #[test]
    fn cache_hit_on_same_content() {
        let mut cache = ScanCache {
            entries: HashMap::new(),
            cache_path: None,
            ttl: Duration::from_secs(3600),
        };
        let content = "# Test\n";
        cache.put("test.md".into(), content, dummy_result());
        assert!(cache.get("test.md", content).is_some());
    }

    #[test]
    fn cache_miss_on_changed_content() {
        let mut cache = ScanCache {
            entries: HashMap::new(),
            cache_path: None,
            ttl: Duration::from_secs(3600),
        };
        cache.put("test.md".into(), "# Old\n", dummy_result());
        assert!(cache.get("test.md", "# New\n").is_none());
    }

    #[test]
    fn cache_miss_after_invalidate() {
        let mut cache = ScanCache {
            entries: HashMap::new(),
            cache_path: None,
            ttl: Duration::from_secs(3600),
        };
        let content = "# Test\n";
        cache.put("test.md".into(), content, dummy_result());
        cache.invalidate("test.md");
        assert!(cache.get("test.md", content).is_none());
    }
}
