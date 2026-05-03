use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use ipnet::Ipv4Net;

use crate::config::{AdsBlock, Config, DnsRoute, Reroute, Retry};
use crate::web::AppState;
use anyhow::Result;
use arc_swap::ArcSwapOption;
use blacklist::DomainHashSet;
use dns::client::{
    AdsBlockClient, CachedClient, ChoiceClient, DnsCache, DnsClient, DohClient,
    DomainRoutingClient, Either, HostsClient, RerouteClient, RetryClient, RoundRobinClient,
    StatsClient, UdpClient,
};
use domains_filter::DomainsFilter;
use futures_util::{stream, StreamExt};
use last_item::LastItem;
use log::info;
use reroute::Rerouter;
use routers::KeeneticClient;
use stats::StatsCollector;
use url::Url;

mod blacklist;
mod cache;
mod config;
mod conntrack;
mod dns;
mod domains_filter;
mod files_stream;
mod last_item;
mod reroute;
mod routers;
mod stats;
mod updater;
mod web;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::init();
    let (config, config_path) = Config::init()?;
    info!("Starting service");

    let data_dir = PathBuf::from(&config.data_dir);
    std::fs::create_dir_all(&data_dir)?;

    let router_for_stats: Option<Arc<KeeneticClient>> = config.reroute.as_ref().and_then(|u| {
        let url = u.router_api_uri.parse().ok()?;
        Some(Arc::new(KeeneticClient::new(
            url,
            u.route_interface.clone(),
        )))
    });

    let router_for_polling = router_for_stats.clone();
    let stats_collector =
        Arc::new(StatsCollector::new(data_dir.join("stats"), router_for_stats).await);

    let conntrack_poll_interval = config.reroute.as_ref().map(|r| r.conntrack_poll_interval);
    let auto_route_min_orig_packets = config
        .reroute
        .as_ref()
        .and_then(|r| r.auto_route_min_orig_packets);
    let hosts_entries: Arc<ArcSwapOption<HashMap<String, Ipv4Addr>>> = if config.hosts.is_empty() {
        Arc::new(ArcSwapOption::empty())
    } else {
        Arc::new(ArcSwapOption::from_pointee(config.hosts))
    };
    let (dns_pipeline, app_state) = create_dns_client(DnsClientConfig {
        doh_upstreams: config.doh_upstreams,
        dns_routing: config.dns_routing,
        udp_upstream: config.udp_dns_upstream,
        ads_block: config.ads_block,
        reroute_config: config.reroute,
        retry_config: config.retry,
        data_dir,
        cache_max_size: config.cache_max_size,
        ecs_override_ip: config.ecs_override_ip,
        hosts: hosts_entries.clone(),
    })
    .await?;

    let dns_pipeline = StatsClient::new(dns_pipeline, stats_collector.clone());
    let dns_pipeline: Arc<dyn DnsClient> = Arc::new(dns_pipeline);

    let rerouter_for_polling = app_state.rerouter.clone();
    let whitelist_ips_for_polling = app_state.whitelist_ips.clone();

    let app_state = Arc::new(AppState {
        routed_snapshot: app_state.routed_snapshot,
        dns_pipeline: dns_pipeline.clone(),
        stats_collector: stats_collector.clone(),
        route_ttl_secs: app_state.route_ttl_secs,
        whitelist_filter: app_state.whitelist_filter,
        whitelist_rules: app_state.whitelist_rules,
        whitelist_ips: app_state.whitelist_ips,
        whitelist_ip_rules: app_state.whitelist_ip_rules,
        hosts: hosts_entries,
        dns_cache: app_state.dns_cache,
        config_path,
    });

    let web_bind_addr = config.web_bind_addr.or(config.metrics_bind_addr);
    let web_service =
        web_bind_addr.map(|addr| tokio::spawn(web::start_web_server(addr, app_state)));

    {
        let stats = stats_collector.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                stats.save_to_disk().await;
            }
        });
    }

    if let (Some(rerouter), Some(router_client), Some(poll_interval)) = (
        rerouter_for_polling,
        router_for_polling,
        conntrack_poll_interval,
    ) {
        conntrack::spawn_polling(
            router_client,
            rerouter,
            whitelist_ips_for_polling,
            poll_interval,
            auto_route_min_orig_packets,
        );
    }

    let request_handler = move |query| {
        let dns_pipeline = dns_pipeline.clone();
        async move { dns_pipeline.send(query).await }
    };
    let udp_server =
        dns::server::create_udp_server(config.bind_addr, request_handler.clone()).await?;
    let tcp_server = dns::server::create_tcp_server(config.bind_addr, request_handler).await?;

    let main_service = tokio::spawn(async move {
        tokio::join!(udp_server, tcp_server);
    });

    tokio::select! {
        web = async { web_service.unwrap().await }, if web_service.is_some() => {
            web
        }
        main_service = main_service => {
            main_service
        }
    }?;
    Ok(())
}

struct RerouteResult<C> {
    client: C,
    routed_snapshot: RerouteStateSnapshot,
}

struct RerouteStateSnapshot {
    routed_snapshot: Arc<ArcSwapOption<Vec<reroute::RoutedEntry>>>,
    route_ttl_secs: Option<u64>,
    whitelist_filter: Arc<ArcSwapOption<DomainsFilter>>,
    whitelist_rules: Arc<ArcSwapOption<Vec<String>>>,
    whitelist_ips: Arc<ArcSwapOption<Vec<Ipv4Net>>>,
    whitelist_ip_rules: Arc<ArcSwapOption<Vec<String>>>,
    rerouter: Option<Rerouter>,
}

struct PartialAppState {
    routed_snapshot: Arc<ArcSwapOption<Vec<reroute::RoutedEntry>>>,
    route_ttl_secs: Option<u64>,
    whitelist_filter: Arc<ArcSwapOption<DomainsFilter>>,
    whitelist_rules: Arc<ArcSwapOption<Vec<String>>>,
    whitelist_ips: Arc<ArcSwapOption<Vec<Ipv4Net>>>,
    whitelist_ip_rules: Arc<ArcSwapOption<Vec<String>>>,
    rerouter: Option<Rerouter>,
    dns_cache: DnsCache,
}

struct DnsClientConfig {
    doh_upstreams: Option<Vec<String>>,
    dns_routing: Option<Vec<DnsRoute>>,
    udp_upstream: SocketAddr,
    ads_block: Option<AdsBlock>,
    reroute_config: Option<Reroute>,
    retry_config: Option<Retry>,
    data_dir: PathBuf,
    cache_max_size: Option<usize>,
    ecs_override_ip: Ipv4Addr,
    hosts: Arc<ArcSwapOption<HashMap<String, Ipv4Addr>>>,
}

async fn create_dns_client(cfg: DnsClientConfig) -> Result<(impl DnsClient, PartialAppState)> {
    let DnsClientConfig {
        doh_upstreams,
        dns_routing,
        udp_upstream,
        ads_block,
        reroute_config,
        retry_config,
        data_dir,
        cache_max_size,
        ecs_override_ip,
        hosts,
    } = cfg;
    let udp_client = UdpClient::new(udp_upstream).await?;
    let doh = create_doh_if_needed(udp_client, doh_upstreams, ecs_override_ip)?;
    let domain_routed = create_domain_routing_if_needed(doh, dns_routing, ecs_override_ip)?;
    let retry_client = match retry_config {
        Some(retry) => Either::Left(RetryClient::new(
            domain_routed,
            retry.attempts_count,
            retry.next_attempt_delay,
        )),
        None => Either::Right(domain_routed),
    };

    let RerouteResult {
        client: reroute_client,
        routed_snapshot,
    } = create_reroute_if_needed(retry_client, reroute_config, &data_dir)?;
    let (cached_client, dns_cache) = CachedClient::new(reroute_client, cache_max_size);
    let hosts_client = HostsClient::new(cached_client, hosts);
    let ads_block_client = create_ads_block_if_needed(hosts_client, ads_block)?;

    let state = PartialAppState {
        routed_snapshot: routed_snapshot.routed_snapshot,
        route_ttl_secs: routed_snapshot.route_ttl_secs,
        whitelist_filter: routed_snapshot.whitelist_filter,
        whitelist_rules: routed_snapshot.whitelist_rules,
        whitelist_ips: routed_snapshot.whitelist_ips,
        whitelist_ip_rules: routed_snapshot.whitelist_ip_rules,
        rerouter: routed_snapshot.rerouter,
        dns_cache,
    };
    Ok((ads_block_client, state))
}

fn create_ads_block_if_needed(
    client: impl DnsClient,
    config: Option<AdsBlock>,
) -> Result<impl DnsClient> {
    match config {
        Some(config) => {
            let domains_filter_stream = domains_filter::filters_stream(
                config.filter_uri.parse()?,
                config.filter_update_interval,
                config.manual_rules,
            )?;
            let last_item = LastItem::new(domains_filter_stream);
            Ok(Either::Left(AdsBlockClient::new(client, last_item)))
        }
        None => Ok(Either::Right(client)),
    }
}

fn create_reroute_if_needed(
    client: impl DnsClient,
    config: Option<Reroute>,
    data_dir: &Path,
) -> Result<RerouteResult<impl DnsClient>> {
    match config {
        Some(config) => {
            let router_client =
                KeeneticClient::new(config.router_api_uri.parse()?, config.route_interface);

            let mut blacklist_last_items: Vec<LastItem<Box<dyn blacklist::Blacklist>>> = Vec::new();

            for (i, url) in config.domain_lsts.iter().enumerate() {
                let dest = data_dir.join(format!("domain_lst_{i}.lst"));
                let stream = blacklist::download_and_parse(
                    url.parse()?,
                    config.blacklist_update_interval,
                    dest,
                )?;
                let last_item = LastItem::new(stream);
                blacklist_last_items.push(last_item);
            }
            if blacklist_last_items.is_empty() {
                let empty: Box<dyn blacklist::Blacklist> = Box::new(DomainHashSet::default());
                let stream = stream::iter([empty]).chain(stream::pending());
                blacklist_last_items.push(LastItem::new(stream));
            }

            let route_ttl = config.route_ttl;
            let rerouter = Rerouter::new(router_client, route_ttl);
            let routed_snapshot = rerouter.routed_snapshot();

            let blacklists_for_client: Vec<LastItem<Box<dyn blacklist::Blacklist>>> =
                blacklist_last_items.to_vec();

            let raw_rules = config.manual_whitelist_dns.unwrap_or_default();
            let whitelist_filter = Arc::new(ArcSwapOption::from_pointee(DomainsFilter::new(
                &raw_rules.join("\n"),
            )?));
            let whitelist_rules = Arc::new(ArcSwapOption::from_pointee(raw_rules));

            let ip_nets = parse_ip_whitelist(&config.manual_whitelist)?;
            let whitelist_ips = Arc::new(ArcSwapOption::from_pointee(ip_nets));
            let whitelist_ip_rules = Arc::new(ArcSwapOption::from_pointee(config.manual_whitelist));

            let rerouter_clone = rerouter.clone();
            let reroute_client = RerouteClient::new(
                client,
                rerouter,
                whitelist_filter.clone(),
                whitelist_ips.clone(),
                blacklists_for_client,
            );
            Ok(RerouteResult {
                client: Either::Left(reroute_client),
                routed_snapshot: RerouteStateSnapshot {
                    routed_snapshot,
                    route_ttl_secs: route_ttl.map(|d| d.as_secs()),
                    whitelist_filter,
                    whitelist_rules,
                    whitelist_ips,
                    whitelist_ip_rules,
                    rerouter: Some(rerouter_clone),
                },
            })
        }
        None => Ok(RerouteResult {
            client: Either::Right(client),
            routed_snapshot: RerouteStateSnapshot {
                routed_snapshot: Arc::new(ArcSwapOption::empty()),
                route_ttl_secs: None,
                whitelist_filter: Arc::new(ArcSwapOption::empty()),
                whitelist_rules: Arc::new(ArcSwapOption::empty()),
                whitelist_ips: Arc::new(ArcSwapOption::empty()),
                whitelist_ip_rules: Arc::new(ArcSwapOption::empty()),
                rerouter: None,
            },
        }),
    }
}

pub fn parse_ip_whitelist(rules: &[String]) -> Result<Vec<Ipv4Net>> {
    rules
        .iter()
        .map(|s| {
            if s.contains('/') {
                s.parse::<Ipv4Net>().map_err(Into::into)
            } else {
                let ip: Ipv4Addr = s.parse()?;
                Ok(Ipv4Net::new(ip, 32)?)
            }
        })
        .collect()
}

fn create_domain_routing_if_needed(
    client: impl DnsClient,
    dns_routing: Option<Vec<DnsRoute>>,
    ecs_override_ip: Ipv4Addr,
) -> Result<impl DnsClient> {
    match dns_routing {
        Some(routes) if !routes.is_empty() => {
            let routing_rules = routes
                .into_iter()
                .map(|route| {
                    let clients = route
                        .doh_upstreams
                        .into_iter()
                        .map(|u| {
                            let c = DohClient::new(u.parse()?, ecs_override_ip)?;
                            Ok(Box::new(c) as Box<dyn DnsClient>)
                        })
                        .collect::<Result<_>>()?;
                    let rr = RoundRobinClient::new(clients);
                    let mut domain_set = DomainHashSet::default();
                    for domain in route.domains {
                        let stripped = domain.strip_prefix("*.").unwrap_or(&domain);
                        domain_set.insert(stripped);
                    }
                    Ok((domain_set, Box::new(rr) as Box<dyn DnsClient>))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Either::Left(DomainRoutingClient::new(
                routing_rules,
                client,
            )))
        }
        _ => Ok(Either::Right(client)),
    }
}

fn create_doh_if_needed(
    client: impl DnsClient,
    doh_upstreams: Option<Vec<String>>,
    ecs_override_ip: Ipv4Addr,
) -> Result<impl DnsClient> {
    match doh_upstreams {
        Some(doh_upstreams) => {
            let doh_upstreams = doh_upstreams
                .iter()
                .map(|x| Ok(x.parse()?))
                .collect::<Result<Vec<Url>>>()?;
            let doh_domains = doh_upstreams
                .iter()
                .map(|x| Some(x.domain()?.to_owned()))
                .collect::<Option<HashSet<_>>>()
                .expect("Should have domains");
            let doh_clients = doh_upstreams
                .into_iter()
                .map(|url| {
                    let c = DohClient::new(url, ecs_override_ip)?;
                    Ok(Box::new(c) as Box<dyn DnsClient>)
                })
                .collect::<Result<_>>()?;
            let round_robin_doh = RoundRobinClient::new(doh_clients);
            let choice_client = ChoiceClient::new(client, round_robin_doh, doh_domains);
            Ok(Either::Left(choice_client))
        }
        None => Ok(Either::Right(client)),
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, path::PathBuf, sync::Arc, time::Duration};

    use arc_swap::ArcSwapOption;

    use anyhow::Result;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper::Response;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    use crate::{
        config::{AdsBlock, Reroute, Retry},
        create_dns_client,
        dns::{
            client::{DnsClient, UdpClient},
            message::Query,
        },
        DnsClientConfig,
    };

    async fn router_http_stub() {
        let listener = TcpListener::bind("127.0.0.1:3030").await.unwrap();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|_req| async {
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .body(Full::new(Bytes::from_static(b"{}")))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            });
        }
    }

    #[tokio::test]
    async fn should_handle_dns_request() -> Result<()> {
        tokio::spawn(router_http_stub());
        tokio::task::yield_now().await;
        let bind_addr = "0.0.0.0:3356".parse()?;
        let data_dir = PathBuf::from("/tmp/reroute-test");
        std::fs::create_dir_all(&data_dir)?;
        let (dns_pipeline, _state) = create_dns_client(DnsClientConfig {
            doh_upstreams: Some(vec![
                "https://dns.google/dns-query".to_owned(),
                "https://dns.cloudflare.com/dns-query".to_owned(),
                "https://dns.quad9.net/dns-query".to_owned(),
            ]),
            dns_routing: None,
            udp_upstream: "8.8.8.8:53".parse()?,
            ads_block: Some(AdsBlock {
                filter_uri: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
                    .to_owned(),
                filter_update_interval: Duration::from_secs(10),
                manual_rules: vec!["@||youtube.com".to_owned()],
            }),
            reroute_config: Some(Reroute {
                domain_lsts: vec![],
                blacklist_update_interval: Duration::from_secs(10),
                router_api_uri: "http://127.0.0.1:3030".to_owned(),
                route_interface: "Ads".to_owned(),
                manual_whitelist: vec![],
                route_ttl: Some(Duration::from_secs(10)),
                manual_whitelist_dns: Some(Vec::new()),
                conntrack_poll_interval: Duration::from_secs(10),
                auto_route_min_orig_packets: None,
            }),
            retry_config: Some(Retry {
                attempts_count: 3,
                next_attempt_delay: Duration::from_millis(200),
            }),
            data_dir,
            cache_max_size: None,
            ecs_override_ip: Ipv4Addr::new(185, 76, 151, 0),
            hosts: Arc::new(ArcSwapOption::empty()),
        })
        .await?;

        let dns_pipeline = std::sync::Arc::new(dns_pipeline);
        let request_handler = move |query| {
            let dns_pipeline = dns_pipeline.clone();
            async move { dns_pipeline.send(query).await }
        };
        let udp_server =
            crate::dns::server::create_udp_server(bind_addr, request_handler.clone()).await?;
        let tcp_server = crate::dns::server::create_tcp_server(bind_addr, request_handler).await?;
        tokio::spawn(async move {
            tokio::join!(udp_server, tcp_server);
        });
        let udp_client = UdpClient::new(bind_addr).await?;
        let requests = vec![
            include_bytes!("../test/dns_packets/q_api.browser.yandex.com.bin").as_ref(),
            include_bytes!("../test/dns_packets/q_www.google.com.bin").as_ref(),
            include_bytes!("../test/dns_packets/q_api.browser.yandex.com.bin").as_ref(),
            include_bytes!("../test/dns_packets/q_www.google.com.bin").as_ref(),
        ]
        .into_iter()
        .map(|request| Query::from_bytes(Bytes::from_static(request)).unwrap());

        for request in requests {
            let response = udp_client.send(request).await?;
            response.parse()?;
        }
        Ok(())
    }
}
