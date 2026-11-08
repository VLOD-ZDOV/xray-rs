#![forbid(unsafe_code)]

//! `ocspStapling`, as Xray-core's `common/ocsp`: the response the leaf's OCSP
//! server returns is stapled as it is.

use std::time::Duration;

use rustls::pki_types::CertificateDer;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer, X509Certificate};

const OCSP_OID: &str = "1.3.6.1.5.5.7.48.1";
const CA_ISSUERS_OID: &str = "1.3.6.1.5.5.7.48.2";
const MAX_BODY: usize = 1 << 20;
const TIMEOUT: Duration = Duration::from_secs(30);

fn access_url(cert: &X509Certificate<'_>, method: &str) -> Option<String> {
    cert.extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::AuthorityInfoAccess(aia) => aia.accessdescs.iter().find_map(|desc| {
                match (
                    &desc.access_location,
                    desc.access_method.to_id_string() == method,
                ) {
                    (GeneralName::URI(uri), true) => Some(uri.to_string()),
                    _ => None,
                }
            }),
            _ => None,
        })
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// Go's `ocsp.CreateRequest` with the default SHA-1 CertID and no nonce.
fn request(leaf: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> Vec<u8> {
    // AlgorithmIdentifier { sha1, NULL }
    let sha1_alg = der(
        0x30,
        &[
            &der(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a])[..],
            &[0x05, 0x00],
        ]
        .concat(),
    );
    let name_hash = Sha1::digest(issuer.tbs_certificate.subject.as_raw());
    let key_hash = Sha1::digest(&issuer.public_key().subject_public_key.data);
    let cert_id = der(
        0x30,
        &[
            sha1_alg,
            der(0x04, &name_hash),
            der(0x04, &key_hash),
            der(0x02, leaf.raw_serial()),
        ]
        .concat(),
    );
    let request_list = der(0x30, &der(0x30, &cert_id));
    der(0x30, &der(0x30, &request_list))
}

/// One plain HTTP exchange, read to the end of the body.
async fn http(url: &str, post: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("unsupported URL scheme: {url}"))?;
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let path = if path.is_empty() { "/" } else { path };
    let addr = if authority
        .rsplit_once(':')
        .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
        && !authority.ends_with(']')
    {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let exchange = async {
        let mut stream = tokio::net::TcpStream::connect(&addr)
            .await
            .map_err(|e| e.to_string())?;
        let mut head = match post {
            Some(body) => format!(
                "POST {path} HTTP/1.0\r\nHost: {authority}\r\nContent-Type: application/ocsp-request\r\nContent-Length: {}\r\n\r\n",
                body.len()
            ),
            None => format!("GET {path} HTTP/1.0\r\nHost: {authority}\r\n\r\n"),
        }
        .into_bytes();
        head.extend_from_slice(post.unwrap_or_default());
        stream.write_all(&head).await.map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        (&mut stream)
            .take(MAX_BODY as u64 + 16 * 1024)
            .read_to_end(&mut response)
            .await
            .map_err(|e| e.to_string())?;
        let split = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("malformed HTTP response")?;
        Ok::<_, String>(response[split + 4..].to_vec())
    };
    tokio::time::timeout(TIMEOUT, exchange)
        .await
        .map_err(|_| format!("{url}: timed out"))?
}

pub async fn fetch(chain: &[CertificateDer<'static>]) -> Result<Vec<u8>, String> {
    let leaf_der = chain.first().ok_or("no certificate")?;
    let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(|e| e.to_string())?;
    let server = access_url(&leaf, OCSP_OID).ok_or("no OCSP server specified in cert")?;
    let fetched_issuer;
    let issuer_der: &[u8] = match chain.get(1) {
        Some(issuer) => issuer,
        None => {
            let url = access_url(&leaf, CA_ISSUERS_OID).ok_or("no issuing certificate URL")?;
            fetched_issuer = http(&url, None).await?;
            &fetched_issuer
        }
    };
    let (_, issuer) = X509Certificate::from_der(issuer_der).map_err(|e| e.to_string())?;
    http(&server, Some(&request(&leaf, &issuer))).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_carries_the_sha1_cert_id() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let mut params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
        params.serial_number = Some(vec![0x01, 0x02, 0x03].into());
        let leaf = params
            .signed_by(&rcgen::KeyPair::generate().unwrap(), &issuer)
            .unwrap();
        let (_, leaf) = X509Certificate::from_der(leaf.der()).unwrap();
        let (_, ca) = X509Certificate::from_der(ca.der()).unwrap();
        let req = request(&leaf, &ca);
        let name_hash = Sha1::digest(ca.tbs_certificate.subject.as_raw());
        assert!(req.windows(20).any(|w| w == name_hash.as_slice()));
        assert!(req.ends_with(&[0x02, 0x03, 0x01, 0x02, 0x03]));
        assert_eq!(req[0], 0x30);
        assert_eq!(req[1] as usize, req.len() - 2);
    }
}
