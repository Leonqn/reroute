use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Method, Request};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use url::Url;

use super::RouterClient;

#[derive(Deserialize)]
struct ConntrackResponse {
    show: ConntrackShow,
}

#[derive(Deserialize)]
struct ConntrackShow {
    ip: ConntrackIp,
}

#[derive(Deserialize)]
struct ConntrackIp {
    conntrack: ConntrackData,
}

#[derive(Deserialize)]
struct ConntrackData {
    ipv4: ConntrackEntries,
}

#[derive(Deserialize)]
struct ConntrackEntries {
    #[serde(default)]
    entry: Vec<ConntrackEntry>,
}

#[derive(Deserialize)]
pub struct ConntrackEntry {
    pub orig: ConntrackEndpoint,
    pub repl: ConntrackEndpoint,
}

#[derive(Deserialize)]
pub struct ConntrackEndpoint {
    pub dst: Ipv4Addr,
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub packets: u64,
}

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn empty_body() -> BoxBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn string_body(s: String) -> BoxBody {
    Full::new(Bytes::from(s))
        .map_err(|never| match never {})
        .boxed()
}

pub struct KeeneticClient {
    http: Client<HttpConnector, BoxBody>,
    base_url: Url,
    vpn_interface: String,
}

impl KeeneticClient {
    pub fn new(base_url: Url, vpn_interface: String) -> Self {
        let http = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(1)
            .pool_idle_timeout(Duration::from_secs(60))
            .build_http();
        Self {
            http,
            base_url,
            vpn_interface,
        }
    }

    async fn remove_route(&self, addr: Ipv4Addr) -> Result<()> {
        let request_body = format!(
            r#"[{{"ip":{{"route":{{"auto":true,"reject":true,"interface":"{interface}","host":"{host}","no":true,"name":"{interface}"}}}}}},{{"system":{{"configuration":{{"save":true}}}}}}]"#,
            interface = &self.vpn_interface,
            host = addr
        );
        self.send_rci(request_body).await
    }

    async fn add_route(&self, addr: Ipv4Addr, comment: &str) -> Result<()> {
        let request_body = format!(
            r#"[{{"ip":{{"route":{{"auto":true,"reject":true,"interface":"{interface}","host":"{host}","comment":"{comment}"}}}}}},{{"system":{{"configuration":{{"save":true}}}}}}]"#,
            interface = &self.vpn_interface,
            host = addr,
            comment = comment,
        );
        self.send_rci(request_body).await
    }

    pub async fn get_hotspot(&self) -> Result<HashMap<IpAddr, String>> {
        let uri = self.base_url.join("/rci/")?.to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri(&uri)
            .body(string_body(
                r#"[{"show":{"ip":{"hotspot":{}}}}]"#.to_owned(),
            ))?;
        let res = self.http.request(req).await?;
        let body = res.into_body().collect().await?.to_bytes();
        let responses: Vec<HotspotResponse> = serde_json::from_slice(&body)?;
        let mut devices = HashMap::new();
        for resp in responses {
            let Some(show) = resp.show else {
                continue;
            };
            let Some(ip) = show.ip else { continue };
            let Some(hotspot) = ip.hotspot else {
                continue;
            };
            for host in hotspot.host {
                let Some(ip) = host.ip else { continue };
                let name = if !host.hostname.is_empty() {
                    host.hostname
                } else if !host.name.is_empty() {
                    host.name
                } else {
                    continue;
                };
                devices.insert(ip, name);
            }
        }
        Ok(devices)
    }

    pub async fn get_connections(&self) -> Result<Vec<ConntrackEntry>> {
        let uri = self.base_url.join("/rci/")?.to_string();
        let body = r#"{"show":{"ip":{"conntrack":{"format":"standard"}}}}"#;
        let req = Request::builder()
            .method(Method::POST)
            .uri(&uri)
            .body(string_body(body.to_owned()))?;
        let res = self.http.request(req).await?;
        let body = res.into_body().collect().await?.to_bytes();
        let resp: ConntrackResponse = serde_json::from_slice(&body)?;
        Ok(resp.show.ip.conntrack.ipv4.entry)
    }

    async fn send_rci(&self, request_body: String) -> Result<()> {
        let uri = self.base_url.join("/rci/")?.to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(string_body(request_body))?;
        let res = self.http.request(req).await?;
        if res.status().is_success() {
            Ok(())
        } else {
            let body = res.into_body().collect().await?.to_bytes();
            let text = String::from_utf8_lossy(&body).into_owned();
            Err(anyhow!("Got unsuccessful response from router {}", text))
        }
    }
}

#[async_trait]
impl RouterClient for KeeneticClient {
    async fn get_routed(&self) -> Result<Vec<(Ipv4Addr, String)>> {
        let uri = self.base_url.join("/rci/ip/route")?.to_string();
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(empty_body())?;
        let res = self.http.request(req).await?;
        let body = res.into_body().collect().await?.to_bytes();
        let routes: Routes = serde_json::from_slice(&body)?;
        Ok(routes
            .routes()
            .into_iter()
            .flatten()
            .filter(|r| r.interface == self.vpn_interface)
            .filter_map(|r| Some((r.host?, r.comment.unwrap_or_default())))
            .collect())
    }

    async fn add_routes(&self, ips: &[Ipv4Addr], comment: &str) -> Result<()> {
        let add_addrs_tasks = ips.iter().map(|addr| self.add_route(*addr, comment));
        futures_util::future::try_join_all(add_addrs_tasks).await?;
        Ok(())
    }

    async fn remove_route(&self, ip: Ipv4Addr) -> Result<()> {
        self.remove_route(ip).await?;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Routes {
    Routes(Vec<Route>),
    None {},
}

impl Routes {
    fn routes(self) -> Option<Vec<Route>> {
        match self {
            Routes::Routes(r) => Some(r),
            Routes::None {} => None,
        }
    }
}

#[derive(Deserialize)]
struct Route {
    host: Option<Ipv4Addr>,
    interface: String,
    comment: Option<String>,
}

#[derive(Deserialize)]
struct HotspotResponse {
    show: Option<HotspotShow>,
}

#[derive(Deserialize)]
struct HotspotShow {
    ip: Option<HotspotIp>,
}

#[derive(Deserialize)]
struct HotspotIp {
    hotspot: Option<HotspotData>,
}

#[derive(Deserialize)]
struct HotspotData {
    #[serde(default)]
    host: Vec<HotspotHost>,
}

#[derive(Deserialize)]
struct HotspotHost {
    ip: Option<IpAddr>,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    name: String,
}
