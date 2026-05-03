use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use arc_swap::ArcSwapOption;
use futures_util::future::join_all;
use ipnet::Ipv4Net;
use log::error;

use crate::{
    enrichment::{EnrichInfo, Enricher},
    reroute::Rerouter,
    routers::{ConntrackEntry, KeeneticClient},
};

pub fn spawn_polling(
    router_client: Arc<KeeneticClient>,
    rerouter: Rerouter,
    whitelist_ips: Arc<ArcSwapOption<Vec<Ipv4Net>>>,
    poll_interval: Duration,
    auto_route_min_orig_packets: Option<u64>,
    enricher: Enricher,
) {
    tokio::spawn(async move {
        let mut cache: HashMap<Ipv4Addr, EnrichInfo> = HashMap::new();
        loop {
            tokio::time::sleep(poll_interval).await;
            if let Err(e) = poll(
                &router_client,
                &rerouter,
                &whitelist_ips,
                auto_route_min_orig_packets,
                &enricher,
                &mut cache,
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
    enricher: &Enricher,
    cache: &mut HashMap<Ipv4Addr, EnrichInfo>,
) -> Result<()> {
    let entries = router_client.get_connections().await?;
    let whitelist = whitelist_ips.load();
    let nets: &[Ipv4Net] = whitelist.as_deref().map(|v| v.as_slice()).unwrap_or(&[]);

    if !nets.is_empty() {
        let matched_ips: Vec<Ipv4Addr> = entries
            .iter()
            .map(|e| e.orig.dst)
            .filter(|ip| nets.iter().any(|net| net.contains(ip)))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if !matched_ips.is_empty() {
            reroute_with_enrichment(rerouter, enricher, cache, matched_ips, "conntrack").await;
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
            reroute_with_enrichment(rerouter, enricher, cache, to_route, "auto").await;
        }
    }

    Ok(())
}

async fn reroute_with_enrichment(
    rerouter: &Rerouter,
    enricher: &Enricher,
    cache: &mut HashMap<Ipv4Addr, EnrichInfo>,
    ips: Vec<Ipv4Addr>,
    prefix: &str,
) {
    let to_lookup: Vec<Ipv4Addr> = ips
        .iter()
        .filter(|ip| !cache.contains_key(ip))
        .copied()
        .collect();
    let lookups = to_lookup
        .into_iter()
        .map(|ip| async move { (ip, enricher.lookup(ip).await) });
    let results = join_all(lookups).await;
    for (ip, info) in results {
        if !info.is_empty() {
            cache.insert(ip, info);
        }
    }

    for ip in ips {
        let info = cache.get(&ip).cloned().unwrap_or_default();
        let comment = info.format_comment(prefix);
        if let Err(e) = rerouter.reroute(vec![ip], &comment).await {
            error!("Reroute failed for {ip}: {e:#}");
        }
    }
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
