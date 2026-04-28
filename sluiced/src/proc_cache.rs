//! Per-process metadata cache.
//!
//! Resolving `/proc/<pid>/exe` + `cmdline` for every connection event is a
//! couple of syscalls per event — fast in absolute terms but wasteful for
//! chatty processes (a browser opening 50 connections to render one page).
//! [`ProcInfoCache`] memoizes the lookup, keyed by PID with `start_time`
//! as the freshness check: when the kernel recycles a PID, the new task
//! has a different `start_time` and the cache transparently refreshes.

use std::collections::{HashMap, VecDeque};

use crate::proc_info::{self, ProcInfo};

/// Default upper bound on cached process entries. Conservative enough for
/// a desktop (where the working set is typically a few hundred long-lived
/// processes) while bounding memory.
pub const DEFAULT_CAPACITY: usize = 1024;

pub struct ProcInfoCache {
    entries: HashMap<u32, ProcInfo>,
    /// FIFO eviction order — the oldest *insertion* is dropped when the
    /// cache reaches `capacity`. Hits do not move entries to the front,
    /// so this is FIFO rather than true LRU. Good enough for chatty,
    /// long-lived processes; refinement to LRU is a one-line change with
    /// `indexmap`.
    insertion_order: VecDeque<u32>,
    capacity: usize,
}

impl ProcInfoCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            insertion_order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }

    /// Hit-or-fetch: returns metadata for `pid`, refreshing the cached
    /// entry if the kernel has recycled the PID (detected via `start_time`).
    pub fn lookup_or_fetch(&mut self, pid: u32) -> &ProcInfo {
        let current_start_time = proc_info::read_start_time(pid).unwrap_or(0);

        let stale = self
            .entries
            .get(&pid)
            .map(|existing| existing.start_time != current_start_time)
            .unwrap_or(true);

        if stale {
            let info = ProcInfo {
                pid,
                start_time: current_start_time,
                exe: proc_info::read_exe(pid),
                cmdline: proc_info::read_cmdline(pid),
            };
            self.insert(pid, info);
        }

        self.entries
            .get(&pid)
            .expect("entry was just inserted or already present")
    }

    fn insert(&mut self, pid: u32, info: ProcInfo) {
        if !self.entries.contains_key(&pid) {
            self.insertion_order.push_back(pid);
        }
        self.entries.insert(pid, info);

        while self.entries.len() > self.capacity {
            if let Some(evict) = self.insertion_order.pop_front() {
                self.entries.remove(&evict);
            } else {
                break;
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fake_info(pid: u32, start_time: u64) -> ProcInfo {
        ProcInfo {
            pid,
            start_time,
            exe: Some(PathBuf::from(format!("/usr/bin/proc{pid}"))),
            cmdline: vec![format!("proc{pid}")],
        }
    }

    #[test]
    fn fifo_eviction_at_capacity() {
        let mut cache = ProcInfoCache::new(2);
        cache.insert(1, fake_info(1, 100));
        cache.insert(2, fake_info(2, 200));
        cache.insert(3, fake_info(3, 300));
        assert_eq!(cache.len(), 2);
        // PID 1 was inserted first → evicted first.
        assert!(!cache.entries.contains_key(&1));
        assert!(cache.entries.contains_key(&2));
        assert!(cache.entries.contains_key(&3));
    }

    #[test]
    fn duplicate_insert_does_not_grow_order() {
        let mut cache = ProcInfoCache::new(2);
        cache.insert(1, fake_info(1, 100));
        cache.insert(1, fake_info(1, 101)); // refresh
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.insertion_order.len(), 1);
        assert_eq!(cache.entries.get(&1).unwrap().start_time, 101);
    }

    #[test]
    fn default_capacity_is_set() {
        let cache = ProcInfoCache::with_default_capacity();
        assert_eq!(cache.capacity(), DEFAULT_CAPACITY);
    }
}
