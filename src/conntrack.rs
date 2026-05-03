use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use arc_swap::ArcSwapOption;
use ipnet::Ipv4Net;
use log::error;

use crate::{
    reroute::Rerouter,
    routers::{ConntrackEntry, KeeneticClient},
};

pub fn spawn_polling(
    router_client: Arc<KeeneticClient>,
    rerouter: Rerouter,
    whitelist_ips: Arc<ArcSwapOption<Vec<Ipv4Net>>>,
    poll_interval: Duration,
    auto_route_min_orig_packets: Option<u64>,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(poll_interval).await;
            if let Err(e) = poll(
                &router_client,
                &rerouter,
                &whitelist_ips,
                auto_route_min_orig_packets,
            )
            .await
            {
                error!("Connections polling error: {:#}", e);
            }
        }
    });
}

async fn poll(
    router_client: &KeeneticClient,
    rerouter: &Rerouter,
    whitelist_ips: &ArcSwapOption<Vec<Ipv4Net>>,
    auto_route_min_orig_packets: Option<u64>,
) -> Result<()> {
    let entries = router_client.get_connections().await?;
    let whitelist = whitelist_ips.load();
    let nets: &[Ipv4Net] = whitelist.as_deref().map(|v| v.as_slice()).unwrap_or(&[]);

    if !nets.is_empty() {
        let matched_ips: HashSet<Ipv4Addr> = entries
            .iter()
            .map(|e| e.orig.dst)
            .filter(|ip| nets.iter().any(|net| net.contains(ip)))
            .collect();

        if !matched_ips.is_empty() {
            let ips: Vec<Ipv4Addr> = matched_ips.into_iter().collect();
            rerouter.reroute(ips, "conntrack").await?;
        }
    }

    if let Some(min_orig) = auto_route_min_orig_packets {
        let routed_snap = rerouter.routed_snapshot().load();
        let routed_set: HashSet<Ipv4Addr> = routed_snap
            .as_deref()
            .map(|v| v.iter().map(|e| e.ip).collect())
            .unwrap_or_default();
        let to_route = auto_route_candidates(&entries, &routed_set, nets, min_orig);
        if !to_route.is_empty() {
            rerouter.reroute(to_route, "auto").await?;
        }
    }

    Ok(())
}

fn auto_route_candidates(
    entries: &[ConntrackEntry],
    routed: &HashSet<Ipv4Addr>,
    whitelist: &[Ipv4Net],
    min_orig_packets: u64,
) -> Vec<Ipv4Addr> {
    let mut per_ip: HashMap<Ipv4Addr, (u64, u64)> = HashMap::new();
    for e in entries {
        if e.orig.proto != "TCP" {
            continue;
        }
        let ip = e.orig.dst;
        if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_multicast() {
            continue;
        }
        if routed.contains(&ip) {
            continue;
        }
        if whitelist.iter().any(|n| n.contains(&ip)) {
            continue;
        }
        let s = per_ip.entry(ip).or_default();
        s.0 += e.orig.packets;
        s.1 += e.repl.packets;
    }
    per_ip
        .into_iter()
        .filter(|(_, (o, r))| *o >= min_orig_packets && *r == 0)
        .map(|(ip, _)| ip)
        .collect()
}
