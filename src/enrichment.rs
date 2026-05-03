use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::Result;

use crate::dns::{
    client::{DnsClient, UdpClient},
    message::Query,
};

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Default)]
pub struct EnrichInfo {
    pub country: Option<String>,
    pub rdns: Option<String>,
}

impl EnrichInfo {
    pub fn format_comment(&self, prefix: &str) -> String {
        let mut parts: Vec<&str> = vec![prefix];
        if let Some(c) = self.country.as_deref() {
            parts.push(c);
        }
        if let Some(r) = self.rdns.as_deref() {
            parts.push(r);
        }
        parts.join(" | ")
    }

    pub fn is_empty(&self) -> bool {
        self.country.is_none() && self.rdns.is_none()
    }
}

pub struct Enricher {
    udp_client: UdpClient,
}

impl Enricher {
    pub async fn new(upstream: SocketAddr) -> Result<Self> {
        Ok(Self {
            udp_client: UdpClient::new(upstream).await?,
        })
    }

    pub async fn lookup(&self, ip: Ipv4Addr) -> EnrichInfo {
        let (country, rdns) = tokio::join!(
            tokio::time::timeout(LOOKUP_TIMEOUT, lookup_country(&self.udp_client, ip)),
            tokio::time::timeout(LOOKUP_TIMEOUT, lookup_rdns(&self.udp_client, ip)),
        );
        EnrichInfo {
            country: country.ok().and_then(|r| r.ok()).flatten(),
            rdns: rdns.ok().and_then(|r| r.ok()).flatten(),
        }
    }
}

async fn lookup_country(client: &UdpClient, ip: Ipv4Addr) -> Result<Option<String>> {
    let [a, b, c, d] = ip.octets();
    let domain = format!("{d}.{c}.{b}.{a}.origin.asn.cymru.com");
    let query = Query::for_domain_with_type(&domain, 16);
    let response = client.send(query).await?;
    let Some(txt) = extract_txt(response.bytes()) else {
        return Ok(None);
    };
    // Cymru TXT format: "ASN | prefix | country | registry | date"
    let country = txt
        .split('|')
        .nth(2)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Ok(country)
}

async fn lookup_rdns(client: &UdpClient, ip: Ipv4Addr) -> Result<Option<String>> {
    let [a, b, c, d] = ip.octets();
    let domain = format!("{d}.{c}.{b}.{a}.in-addr.arpa");
    let query = Query::for_domain_with_type(&domain, 12);
    let response = client.send(query).await?;
    Ok(extract_ptr(response.bytes()))
}

/// Extracts the first PTR target name from a DNS response packet.
fn extract_ptr(packet: &[u8]) -> Option<String> {
    let (mut pos, ancount) = skip_to_answers(packet)?;
    for _ in 0..ancount {
        pos = skip_name(packet, pos)?;
        if pos + 10 > packet.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        pos += 8;
        let rdlength = u16::from_be_bytes([packet[pos], packet[pos + 1]]) as usize;
        pos += 2;
        if rtype == 12 {
            return parse_dns_name(packet, pos);
        }
        pos += rdlength;
    }
    None
}

/// Extracts the first TXT record's concatenated string from a DNS response packet.
fn extract_txt(packet: &[u8]) -> Option<String> {
    let (mut pos, ancount) = skip_to_answers(packet)?;
    for _ in 0..ancount {
        pos = skip_name(packet, pos)?;
        if pos + 10 > packet.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        pos += 8;
        let rdlength = u16::from_be_bytes([packet[pos], packet[pos + 1]]) as usize;
        pos += 2;
        if rtype == 16 {
            let rdata = packet.get(pos..pos + rdlength)?;
            let mut s = String::new();
            let mut p = 0;
            while p < rdata.len() {
                let l = rdata[p] as usize;
                p += 1;
                if p + l > rdata.len() {
                    return None;
                }
                s.push_str(std::str::from_utf8(&rdata[p..p + l]).ok()?);
                p += l;
            }
            return Some(s);
        }
        pos += rdlength;
    }
    None
}

/// Returns the position right after the question section, plus the answer count.
fn skip_to_answers(packet: &[u8]) -> Option<(usize, u16)> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(packet, pos)?;
        pos += 4; // QTYPE + QCLASS
    }
    Some((pos, ancount))
}

/// Skips a (possibly compressed) DNS name and returns the position after it.
fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + len as usize;
    }
}

/// Parses a (possibly compressed) DNS name starting at `start`.
fn parse_dns_name(packet: &[u8], start: usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut iters = 0;
    loop {
        if iters > 64 {
            return None;
        }
        iters += 1;
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos];
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= packet.len() {
                return None;
            }
            let offset = (((len as usize) & 0x3F) << 8) | packet[pos + 1] as usize;
            pos = offset;
            continue;
        }
        let lstart = pos + 1;
        let lend = lstart + len as usize;
        if lend > packet.len() {
            return None;
        }
        labels.push(std::str::from_utf8(&packet[lstart..lend]).ok()?.to_string());
        pos = lend;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// Encodes a domain name as DNS labels (no compression).
    fn encode_name(name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf
    }

    /// Builds a minimal DNS response packet with one question and one answer of the given type/rdata.
    fn build_response(qname: &str, qtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header: id=1, flags=0x8180 (response, RD, RA), QD=1, AN=1, NS=0, AR=0
        buf.extend_from_slice(&[
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        let qname_bytes = encode_name(qname);
        buf.extend_from_slice(&qname_bytes);
        buf.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        buf.extend_from_slice(&[0x00, 0x01]); // QCLASS
                                              // Answer: pointer to qname (offset 12), TYPE, CLASS=IN, TTL=300, RDLENGTH, RDATA
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01]);
        buf.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(rdata);
        buf
    }

    #[test]
    fn extract_ptr_uncompressed() {
        let rdata = encode_name("dns.google");
        let packet = build_response("8.8.8.8.in-addr.arpa", 12, &rdata);
        assert_eq!(extract_ptr(&packet), Some("dns.google".to_owned()));
    }

    #[test]
    fn extract_ptr_with_compression_pointer() {
        // Build manually: the rdata uses a compression pointer to the qname
        let mut buf = Vec::new();
        buf.extend_from_slice(&[
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        let qname_bytes = encode_name("dns.google");
        let qname_offset = buf.len();
        buf.extend_from_slice(&qname_bytes);
        buf.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]); // QTYPE=PTR, QCLASS=IN
                                                          // Answer: pointer to start of qname for the answer NAME
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C]);
        // RDATA: a pointer to the qname → name = "dns.google"
        let pointer = (0xC000u16 | qname_offset as u16).to_be_bytes();
        buf.extend_from_slice(&[0x00, 0x02]); // RDLENGTH = 2
        buf.extend_from_slice(&pointer);
        assert_eq!(extract_ptr(&buf), Some("dns.google".to_owned()));
    }

    #[test]
    fn extract_txt_single_chunk() {
        let s = "15169 | 8.8.8.0/24 | US | arin | 2014-03-14";
        let mut rdata = vec![s.len() as u8];
        rdata.extend_from_slice(s.as_bytes());
        let packet = build_response("8.8.8.8.origin.asn.cymru.com", 16, &rdata);
        assert_eq!(extract_txt(&packet), Some(s.to_owned()));
    }

    #[test]
    fn extract_txt_multiple_chunks_concatenated() {
        let chunks: [&[u8]; 2] = [b"hello ", b"world"];
        let mut rdata = Vec::new();
        for c in chunks {
            rdata.push(c.len() as u8);
            rdata.extend_from_slice(c);
        }
        let packet = build_response("x.example", 16, &rdata);
        assert_eq!(extract_txt(&packet), Some("hello world".to_owned()));
    }

    #[test]
    fn extract_returns_none_when_record_type_missing() {
        let rdata = encode_name("dns.google");
        let packet = build_response("foo.example", 12, &rdata);
        assert_eq!(extract_txt(&packet), None);
    }

    #[test]
    fn lookup_country_parses_cymru_format() {
        // Verify that the third pipe-separated field is taken as the country.
        let txt = "15169 | 8.8.8.0/24 | US | arin | 2014-03-14";
        let country = txt
            .split('|')
            .nth(2)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        assert_eq!(country, Some("US".to_owned()));
    }

    #[test]
    fn format_comment_with_country_and_rdns() {
        let info = EnrichInfo {
            country: Some("RU".to_owned()),
            rdns: Some("mail.yandex.ru".to_owned()),
        };
        assert_eq!(info.format_comment("auto"), "auto | RU | mail.yandex.ru");
    }

    #[test]
    fn format_comment_with_partial_data() {
        let info = EnrichInfo {
            country: Some("US".to_owned()),
            rdns: None,
        };
        assert_eq!(info.format_comment("conntrack"), "conntrack | US");
    }

    #[test]
    fn format_comment_with_no_data() {
        let info = EnrichInfo::default();
        assert_eq!(info.format_comment("auto"), "auto");
    }

    #[tokio::test]
    async fn enrich_real_lookup_google_dns() -> Result<()> {
        let upstream = "8.8.8.8:53".parse().unwrap();
        let enricher = Enricher::new(upstream).await?;
        let ip = "8.8.8.8".parse().unwrap();
        let info = enricher.lookup(ip).await;
        assert_eq!(info.country.as_deref(), Some("US"));
        assert_eq!(info.rdns.as_deref(), Some("dns.google"));
        Ok(())
    }
}
