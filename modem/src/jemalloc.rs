use prometheus::{GaugeVec, register_gauge_vec};
use slog::{Logger, error};
pub use tikv_jemalloc_ctl::Error;
use tikv_jemalloc_ctl::{epoch, stats};

lazy_static::lazy_static! {
    static ref JEMALLOC_ALLOCATED: GaugeVec = register_gauge_vec!(
        "jemalloc_allocated_bytes",
        "Bytes allocated by jemalloc",
        &["cluster", "server_ip"]
    ).unwrap();
    static ref JEMALLOC_ACTIVE: GaugeVec = register_gauge_vec!(
        "jemalloc_active_bytes",
        "Bytes in active arenas",
        &["cluster", "server_ip"]
    ).unwrap();
    static ref JEMALLOC_METADATA: GaugeVec = register_gauge_vec!(
        "jemalloc_metadata_bytes",
        "Bytes used for metadata",
        &["cluster", "server_ip"]
    ).unwrap();
    static ref JEMALLOC_RESIDENT: GaugeVec = register_gauge_vec!(
        "jemalloc_resident_bytes",
        "Bytes resident in RAM",
        &["cluster", "server_ip"]
    ).unwrap();
    static ref JEMALLOC_MAPPED: GaugeVec = register_gauge_vec!(
        "jemalloc_mapped_bytes",
        "Bytes mapped by jemalloc",
        &["cluster", "server_ip"]
    ).unwrap();
    static ref JEMALLOC_RETAINED: GaugeVec = register_gauge_vec!(
        "jemalloc_retained_bytes",
        "Bytes retained by jemalloc",
        &["cluster", "server_ip"]
    ).unwrap();
    static ref JEMALLOC_DIRTY: GaugeVec = register_gauge_vec!(
        "jemalloc_dirty_bytes",
        "Bytes dirty in RAM",
        &["cluster", "server_ip"]
    ).unwrap();
    static ref JEMALLOC_FRAGMENTATION: GaugeVec = register_gauge_vec!(
        "jemalloc_fragmentation_bytes",
        "Bytes fragmented in RAM",
        &["cluster", "server_ip"]
    ).unwrap();
}

pub fn spawn_allocator_metrics_loop(cluster: String, ip_addr: String, logger: Logger) {
    tokio::spawn(async move {
        loop {
            let s = match fetch_stats() {
                Ok(s) => s,
                Err(e) => {
                    error!(logger, "fetch jemalloc stats";
                        "error" => %e
                    );
                    return;
                }
            };

            // Update the metrics
            JEMALLOC_ALLOCATED
                .with_label_values(&[cluster.clone(), ip_addr.clone()])
                .set(s.allocated as f64);
            JEMALLOC_ACTIVE
                .with_label_values(&[cluster.clone(), ip_addr.clone()])
                .set(s.active as f64);
            JEMALLOC_METADATA
                .with_label_values(&[cluster.clone(), ip_addr.clone()])
                .set(s.metadata as f64);
            JEMALLOC_RESIDENT
                .with_label_values(&[cluster.clone(), ip_addr.clone()])
                .set(s.resident as f64);
            JEMALLOC_MAPPED
                .with_label_values(&[cluster.clone(), ip_addr.clone()])
                .set(s.mapped as f64);
            JEMALLOC_RETAINED
                .with_label_values(&[cluster.clone(), ip_addr.clone()])
                .set(s.retained as f64);
            JEMALLOC_DIRTY
                .with_label_values(&[cluster.clone(), ip_addr.clone()])
                .set(s.dirty as f64);
            JEMALLOC_FRAGMENTATION
                .with_label_values(&[cluster.clone(), ip_addr.clone()])
                .set(s.fragmentation as f64);

            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

fn fetch_stats() -> Result<JemallocStats, Error> {
    // Stats are cached. Need to advance epoch to refresh.
    epoch::advance()?;

    Ok(JemallocStats {
        allocated: stats::allocated::read()? as u64,
        active: stats::active::read()? as u64,
        metadata: stats::metadata::read()? as u64,
        resident: stats::resident::read()? as u64,
        mapped: stats::mapped::read()? as u64,
        retained: stats::retained::read()? as u64,
        dirty: stats::resident::read()?
            .saturating_sub(stats::active::read()?)
            .saturating_sub(stats::metadata::read()?) as u64,
        fragmentation: stats::active::read()?.saturating_sub(stats::allocated::read()?) as u64,
    })
}

pub struct JemallocStats {
    pub allocated: u64,
    pub active: u64,
    pub metadata: u64,
    pub resident: u64,
    pub mapped: u64,
    pub retained: u64,
    pub dirty: u64,
    pub fragmentation: u64,
}
