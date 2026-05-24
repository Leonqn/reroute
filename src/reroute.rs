use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::routers::RouterClient;

use anyhow::Result;
use arc_swap::ArcSwapOption;
use log::{error, info};
use tokio::{
    sync::{
        mpsc::UnboundedSender,
        mpsc::{unbounded_channel, UnboundedReceiver},
        oneshot,
    },
    time::Instant,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RerouteResponse {
    Rerouted(Vec<Ipv4Addr>),
    Skipped,
}

#[derive(Clone)]
pub struct Rerouter {
    router_requests: UnboundedSender<RouterRequest>,
    routed_snapshot: Arc<ArcSwapOption<Vec<RoutedEntry>>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RoutedEntry {
    pub ip: Ipv4Addr,
    pub comment: String,
    /// Unix timestamp (seconds) of the last DNS request that touched this route.
    pub last_seen_secs: u64,
}

impl Rerouter {
    pub fn new(router_client: impl RouterClient, route_ttl: Option<Duration>) -> Self {
        let routed_snapshot = Arc::new(ArcSwapOption::empty());
        let (router_requests_tx, router_requests_rx) = unbounded_channel();
        let router_handler = router_requests_handler(
            router_client,
            route_ttl,
            router_requests_rx,
            routed_snapshot.clone(),
        );
        tokio::spawn(router_handler);
        Self {
            router_requests: router_requests_tx,
            routed_snapshot,
        }
    }

    pub fn routed_snapshot(&self) -> Arc<ArcSwapOption<Vec<RoutedEntry>>> {
        self.routed_snapshot.clone()
    }

    pub async fn reroute(
        &self,
        ips: impl IntoIterator<Item = Ipv4Addr>,
        comment: &str,
    ) -> Result<RerouteResponse> {
        let ips = ips.into_iter().collect::<HashSet<_>>();
        if ips.is_empty() {
            return Ok(RerouteResponse::Skipped);
        }
        let (response_tx, response_rx) = oneshot::channel();
        self.router_requests
            .send(RouterRequest::Add(AddRoutesRequest {
                ips,
                waiter: response_tx,
                comment: comment.to_owned(),
            }))
            .expect("Receiver dropped");

        response_rx.await.expect("Should receive response")
    }

    /// Remove the given IPs from the router (only those currently rerouted).
    pub async fn unroute(&self, ips: impl IntoIterator<Item = Ipv4Addr>) -> Result<()> {
        let ips = ips.into_iter().collect::<Vec<_>>();
        if ips.is_empty() {
            return Ok(());
        }
        let (response_tx, response_rx) = oneshot::channel();
        self.router_requests
            .send(RouterRequest::Remove(RemoveRoutesRequest {
                ips,
                waiter: response_tx,
            }))
            .expect("Receiver dropped");

        response_rx.await.expect("Should receive response")
    }
}

#[derive(Debug)]
enum RouterRequest {
    Add(AddRoutesRequest),
    Remove(RemoveRoutesRequest),
}

#[derive(Debug)]
struct AddRoutesRequest {
    ips: HashSet<Ipv4Addr>,
    waiter: oneshot::Sender<Result<RerouteResponse>>,
    comment: String,
}

#[derive(Debug)]
struct RemoveRoutesRequest {
    ips: Vec<Ipv4Addr>,
    waiter: oneshot::Sender<Result<()>>,
}

pub const PERMANENT_COMMENT: &str = "permanent";

fn is_permanent(comment: &str) -> bool {
    comment == PERMANENT_COMMENT || comment.starts_with("permanent ")
}

/// Convert a tokio `Instant` (last_seen) to a unix timestamp in seconds.
/// We anchor the conversion via `SystemTime::now()` and the elapsed time
/// since `last_seen`, so we never need a global process-start offset.
fn instant_to_unix_secs(last_seen: Instant) -> u64 {
    let elapsed = last_seen.elapsed();
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_sub(elapsed)
        .as_secs()
}

async fn router_requests_handler(
    router_client: impl RouterClient,
    route_ttl: Option<Duration>,
    mut requests: UnboundedReceiver<RouterRequest>,
    routed_snapshot: Arc<ArcSwapOption<Vec<RoutedEntry>>>,
) {
    let loaded = load_routed(&router_client).await;
    info!("Loaded {} routed IPs from router", loaded.len());
    let now = Instant::now();
    let mut rerouted: HashMap<Ipv4Addr, (Instant, String)> = loaded
        .into_iter()
        .map(|(ip, comment)| (ip, (now, comment)))
        .collect();
    update_snapshot(&routed_snapshot, &rerouted);

    while let Some(request) = requests.recv().await {
        let now = Instant::now();
        let mut changed = false;
        match request {
            RouterRequest::Add(request) => {
                // Touch all requested IPs to refresh their TTL
                let force_overwrite_comment = is_permanent(&request.comment);
                for &ip in &request.ips {
                    if let Some(entry) = rerouted.get_mut(&ip) {
                        entry.0 = now;
                        if force_overwrite_comment {
                            if entry.1 != request.comment {
                                entry.1 = request.comment.clone();
                                changed = true;
                            }
                        } else if entry.1.is_empty() && !request.comment.is_empty() {
                            entry.1 = request.comment.clone();
                        }
                    }
                }
                let blocked = request
                    .ips
                    .iter()
                    .filter(|ip| !rerouted.contains_key(ip))
                    .copied()
                    .collect::<Vec<_>>();
                if !blocked.is_empty() {
                    let add_result = router_client.add_routes(&blocked, &request.comment).await;
                    match add_result {
                        Ok(_) => {
                            for &ip in &request.ips {
                                rerouted.insert(ip, (now, request.comment.clone()));
                            }
                            changed = true;
                            let _ = request.waiter.send(Ok(RerouteResponse::Rerouted(blocked)));
                        }
                        Err(err) => {
                            let _ = request.waiter.send(Err(err));
                        }
                    }
                } else {
                    let _ = request.waiter.send(Ok(RerouteResponse::Skipped));
                }
            }
            RouterRequest::Remove(request) => {
                for ip in request.ips {
                    if !rerouted.contains_key(&ip) {
                        continue;
                    }
                    match router_client.remove_route(ip).await {
                        Ok(_) => {
                            rerouted.remove(&ip);
                            changed = true;
                            info!("Unrouted {}", ip);
                        }
                        Err(err) => {
                            error!("Error unrouting {}: {:?}", ip, err);
                        }
                    }
                }
                let _ = request.waiter.send(Ok(()));
            }
        }
        // Remove up to 50 expired routes on each request
        if let Some(ttl) = route_ttl {
            let expired: Vec<Ipv4Addr> = rerouted
                .iter()
                .filter(|(_, (last_seen, comment))| {
                    !is_permanent(comment) && now.duration_since(*last_seen) > ttl
                })
                .map(|(ip, _)| *ip)
                .take(50)
                .collect();
            for ip in expired {
                match router_client.remove_route(ip).await {
                    Ok(_) => {
                        rerouted.remove(&ip);
                        changed = true;
                        info!("Removed expired route {}", ip);
                    }
                    Err(err) => {
                        error!("Error removing expired route {}: {:?}", ip, err);
                    }
                }
            }
        }
        if changed {
            update_snapshot(&routed_snapshot, &rerouted);
        }
    }
}

fn update_snapshot(
    snapshot: &ArcSwapOption<Vec<RoutedEntry>>,
    rerouted: &HashMap<Ipv4Addr, (Instant, String)>,
) {
    let entries: Vec<RoutedEntry> = rerouted
        .iter()
        .map(|(ip, (last_seen, comment))| RoutedEntry {
            ip: *ip,
            comment: comment.clone(),
            last_seen_secs: instant_to_unix_secs(*last_seen),
        })
        .collect();
    snapshot.store(Some(Arc::new(entries)));
}

async fn load_routed(router_client: &impl RouterClient) -> Vec<(Ipv4Addr, String)> {
    use fure::backoff::fixed;
    use fure::policies::{backoff, cond};
    let policy = cond(backoff(fixed(Duration::from_secs(5))), |result| {
        if let Some(Err(err)) = result {
            error!(
                "Got error while receiving routed table from router: {:#}",
                err
            );
            true
        } else {
            false
        }
    });

    fure::retry(|| router_client.get_routed(), policy)
        .await
        .expect("Must be something")
}

#[cfg(test)]
mod tests {
    use crate::routers::RouterClient;

    use super::{RerouteResponse, Rerouter};
    use anyhow::Result;
    use async_trait::async_trait;
    use futures_util::{
        future::{BoxFuture, Shared},
        FutureExt,
    };
    use pretty_assertions::assert_eq;
    use std::{
        net::Ipv4Addr,
        sync::atomic::AtomicUsize,
        sync::Arc,
        sync::{
            atomic::{AtomicBool, Ordering},
            Mutex,
        },
        time::Duration,
    };
    use tokio::{sync::oneshot, time::sleep};

    #[derive(Clone)]
    struct RouterMock {
        add_calls: Arc<AtomicUsize>,
        get_called: Arc<AtomicBool>,
        remove_called: Arc<AtomicBool>,
        add_hung: Arc<Mutex<Option<Shared<BoxFuture<'static, ()>>>>>,
    }

    impl RouterMock {
        fn new() -> Self {
            Self {
                add_calls: Arc::new(AtomicUsize::new(0)),
                get_called: Arc::new(AtomicBool::new(false)),
                add_hung: Arc::new(Mutex::new(None)),
                remove_called: Arc::new(AtomicBool::new(false)),
            }
        }

        fn hung_add_routes(&self) -> oneshot::Sender<()> {
            let (tx, rx) = oneshot::channel();
            self.add_hung.lock().unwrap().replace(
                async move {
                    rx.await.unwrap();
                }
                .boxed()
                .shared(),
            );
            tx
        }
    }

    #[async_trait]
    impl RouterClient for RouterMock {
        async fn get_routed(&self) -> Result<Vec<(Ipv4Addr, String)>> {
            self.get_called.store(true, Ordering::Relaxed);
            Ok(Vec::new())
        }

        async fn add_routes(&self, _ips: &[Ipv4Addr], _comment: &str) -> Result<()> {
            self.add_calls.fetch_add(1, Ordering::Relaxed);
            let hung = {
                let guard = self.add_hung.lock().unwrap();
                guard.as_ref().cloned()
            };
            if let Some(hung) = hung {
                hung.await
            }
            Ok(())
        }

        async fn remove_route(&self, _ip: Ipv4Addr) -> Result<()> {
            self.remove_called.store(true, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn should_add_routes_when_ips_are_not_rerouted() -> Result<()> {
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let rerouter = Rerouter::new(router_mock.clone(), Some(Duration::from_secs(1)));
        tokio::task::yield_now().await;

        let response = rerouter.reroute(vec![blacklisted_ip], "").await?;

        assert_eq!(response, RerouteResponse::Rerouted(vec![blacklisted_ip]));
        assert_eq!(router_mock.add_calls.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn should_not_add_routes_when_ips_are_rerouted() -> Result<()> {
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let rerouter = Rerouter::new(router_mock.clone(), Some(Duration::from_secs(1)));
        tokio::task::yield_now().await;
        rerouter.reroute(vec![blacklisted_ip], "").await?;

        let response = rerouter.reroute(vec![blacklisted_ip], "").await?;

        assert_eq!(response, RerouteResponse::Skipped);
        assert_eq!(router_mock.add_calls.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn should_remove_expired_routes_on_next_request() -> Result<()> {
        let expired_ip: Ipv4Addr = "64.233.162.103".parse().unwrap();
        let new_ip: Ipv4Addr = "64.233.162.104".parse().unwrap();
        let router_mock = RouterMock::new();
        let rerouter = Arc::new(Rerouter::new(
            router_mock.clone(),
            Some(Duration::from_millis(1)),
        ));
        tokio::task::yield_now().await;

        rerouter.reroute(vec![expired_ip], "").await?;
        sleep(Duration::from_millis(10)).await;
        // Next request triggers cleanup of expired routes
        rerouter.reroute(vec![new_ip], "").await?;

        assert!(router_mock.remove_called.load(Ordering::Relaxed));
        Ok(())
    }

    #[tokio::test]
    async fn should_not_add_same_router_in_parallel() -> Result<()> {
        let blacklisted_ip = "64.233.162.103".parse().unwrap();
        let router_mock = RouterMock::new();
        let rerouter = Arc::new(Rerouter::new(
            router_mock.clone(),
            Some(Duration::from_secs(1)),
        ));
        tokio::task::yield_now().await;
        let hunger = router_mock.hung_add_routes();

        let t1 = tokio::spawn({
            let rerouter = rerouter.clone();
            async move { rerouter.reroute(vec![blacklisted_ip], "").await.unwrap() }
        });
        tokio::task::yield_now().await;
        let t2 = tokio::spawn({
            let rerouter = rerouter.clone();
            async move { rerouter.reroute(vec![blacklisted_ip], "").await.unwrap() }
        });
        tokio::task::yield_now().await;
        hunger.send(()).unwrap();
        let (t1, t2) = tokio::try_join!(t1, t2)?;

        assert_eq!(router_mock.add_calls.load(Ordering::Relaxed), 1);
        assert_eq!(t1, RerouteResponse::Rerouted(vec![blacklisted_ip]));
        assert_eq!(t2, RerouteResponse::Skipped);

        Ok(())
    }
}
