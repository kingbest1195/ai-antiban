#![cfg(any(test, feature = "test-support"))]
#![cfg_attr(not(test), allow(dead_code))]

use super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// In-memory [`PolicyStore`] for unit tests.
#[derive(Default)]
pub struct FakePolicyStore {
    inner: Mutex<FakePolicyState>,
}

#[derive(Default)]
struct FakePolicyState {
    applicable_domains: BTreeMap<String, bool>,
    values: BTreeMap<(String, String), PolicyValue>,
}

impl FakePolicyStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set_domain_applicable(&self, domain: &str, applicable: bool) {
        self.inner
            .lock()
            .unwrap()
            .applicable_domains
            .insert(domain.to_string(), applicable);
    }

    pub fn preset(&self, domain: &str, key: &str, value: PolicyValue) {
        let mut g = self.inner.lock().unwrap();
        g.applicable_domains
            .entry(domain.to_string())
            .or_insert(true);
        g.values
            .insert((domain.to_string(), key.to_string()), value);
    }

    pub fn get(&self, domain: &str, key: &str) -> Option<PolicyValue> {
        self.inner
            .lock()
            .unwrap()
            .values
            .get(&(domain.to_string(), key.to_string()))
            .cloned()
    }
}

impl PolicyStore for FakePolicyStore {
    fn is_domain_applicable(&self, domain: &str) -> bool {
        let g = self.inner.lock().unwrap();
        g.applicable_domains.get(domain).copied().unwrap_or(true)
    }

    fn read(&self, domain: &str, key: &str) -> PResult<Option<PolicyValue>> {
        let g = self.inner.lock().unwrap();
        Ok(g.values
            .get(&(domain.to_string(), key.to_string()))
            .cloned())
    }

    fn write(&self, domain: &str, key: &str, value: &PolicyValue) -> PResult<()> {
        let mut g = self.inner.lock().unwrap();
        g.values
            .insert((domain.to_string(), key.to_string()), value.clone());
        Ok(())
    }

    fn delete(&self, domain: &str, key: &str) -> PResult<()> {
        let mut g = self.inner.lock().unwrap();
        g.values.remove(&(domain.to_string(), key.to_string()));
        Ok(())
    }
}
