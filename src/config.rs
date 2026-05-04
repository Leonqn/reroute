use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use anyhow::Result;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub metrics_bind_addr: Option<SocketAddr>,
    pub udp_dns_upstream: SocketAddr,
    pub doh_upstreams: Option<Vec<String>>,
    pub dns_routing: Option<Vec<DnsRoute>>,
    pub reroute: Option<Reroute>,
    pub ads_block: Option<AdsBlock>,
    pub retry: Option<Retry>,
    pub cache_max_size: Option<usize>,
    pub web_bind_addr: Option<SocketAddr>,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_ecs_override_ip")]
    pub ecs_override_ip: Ipv4Addr,
    #[serde(default)]
    pub hosts: HashMap<String, Ipv4Addr>,
}

impl Config {
    pub fn init() -> Result<(Self, PathBuf)> {
        let config_name = std::env::args()
            .nth(1)
            .expect("Config file should be specified as first argument");
        let config_path = PathBuf::from(&config_name);
        let config = config::Config::builder()
            .add_source(config::File::with_name(&config_name))
            .build()?
            .try_deserialize()?;
        Ok((config, config_path))
    }
}

#[derive(Deserialize)]
pub struct DnsRoute {
    pub domains: Vec<String>,
    pub doh_upstreams: Vec<String>,
}

#[derive(Deserialize)]
pub struct Retry {
    pub attempts_count: usize,
    #[serde(with = "humantime_serde")]
    pub next_attempt_delay: Duration,
}

#[derive(Deserialize)]
pub struct AdsBlock {
    pub filter_uri: String,
    #[serde(with = "humantime_serde")]
    pub filter_update_interval: Duration,
    #[serde(default)]
    pub manual_rules: Vec<String>,
}

#[derive(Deserialize)]
pub struct Reroute {
    #[serde(default)]
    pub domain_lsts: Vec<String>,
    #[serde(with = "humantime_serde")]
    pub blacklist_update_interval: Duration,
    pub router_api_uri: String,
    pub route_interface: String,
    #[serde(default)]
    pub manual_whitelist: Vec<String>,
    pub manual_whitelist_dns: Option<Vec<String>>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub route_ttl: Option<Duration>,
    #[serde(default = "default_conntrack_poll_interval")]
    #[serde(with = "humantime_serde")]
    pub conntrack_poll_interval: Duration,
    #[serde(default = "default_auto_route_min_orig_packets")]
    pub auto_route_min_orig_packets: Option<u64>,
}

fn default_conntrack_poll_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_auto_route_min_orig_packets() -> Option<u64> {
    Some(15)
}

fn default_data_dir() -> String {
    "/tmp/reroute".to_owned()
}

fn default_ecs_override_ip() -> Ipv4Addr {
    Ipv4Addr::new(185, 76, 151, 0)
}
