#![forbid(unsafe_code)]

use std::net::SocketAddr;
use xray_config::Network;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub abs_path: String,
}

#[derive(Debug, Clone)]
pub struct ProcessMatcher {
    pub process_names: Vec<String>,
    pub abs_paths: Vec<String>,
    pub folders: Vec<String>,
    pub match_xray_self: bool,
}

impl ProcessMatcher {
    pub fn new(names: &[String]) -> Self {
        let mut process_names = Vec::new();
        let mut abs_paths = Vec::new();
        let mut folders = Vec::new();
        let mut match_xray_self = false;
        let self_exe = std::env::current_exe()
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        for raw in names {
            if raw == "self/" {
                match_xray_self = true;
                continue;
            }
            let name = if raw == "xray/" {
                if let Some(ref p) = self_exe {
                    p.clone()
                } else {
                    crate::log::warn("process rule: cannot resolve the path of \"xray/\"");
                    continue;
                }
            } else {
                raw.clone()
            };
            if name.ends_with('/') {
                folders.push(name);
            } else if name.contains('/') {
                abs_paths.push(name);
            } else {
                let clean = name.strip_suffix(".exe").unwrap_or(&name).to_string();
                process_names.push(clean);
            }
        }
        Self {
            process_names,
            abs_paths,
            folders,
            match_xray_self,
        }
    }

    pub fn matches(&self, pid: u32, name: &str, abs_path: &str) -> bool {
        if self.match_xray_self && pid == std::process::id() {
            return true;
        }
        if self.process_names.iter().any(|p| p == name) {
            return true;
        }
        if self.abs_paths.iter().any(|p| p == abs_path) {
            return true;
        }
        for f in &self.folders {
            if abs_path.starts_with(f) {
                return true;
            }
        }
        false
    }
}

#[cfg(target_os = "linux")]
pub fn find_local_process(network: Network, src: SocketAddr) -> Option<ProcessInfo> {
    let canonical_ip = src.ip().to_canonical();
    if !is_local_ip(canonical_ip) {
        return None;
    }
    let inode = find_inode_in_proc_net(network, SocketAddr::new(canonical_ip, src.port()))?;
    let pid = find_pid_by_socket_inode(&inode)?;
    let abs_path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()?
        .to_string_lossy()
        .to_string();
    let name = abs_path.rsplit('/').next()?.to_string();
    Some(ProcessInfo {
        pid,
        name,
        abs_path,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn find_local_process(_network: Network, _src: SocketAddr) -> Option<ProcessInfo> {
    None
}

#[cfg(target_os = "linux")]
fn is_local_ip(ip: std::net::IpAddr) -> bool {
    let ip = ip.to_canonical();
    if ip.is_loopback() {
        return true;
    }
    std::net::UdpSocket::bind((ip, 0)).is_ok()
}

#[cfg(target_os = "linux")]
fn find_inode_in_proc_net(network: Network, src: SocketAddr) -> Option<String> {
    use std::io::BufRead;

    let ip = src.ip().to_canonical();
    let is_tcp = network == Network::Tcp;
    let is_ipv4 = matches!(ip, std::net::IpAddr::V4(_));
    let proc_files = match (is_tcp, is_ipv4) {
        (true, true) => &["/proc/net/tcp", "/proc/net/tcp6"][..],
        (true, false) => &["/proc/net/tcp6", "/proc/net/tcp"][..],
        (false, true) => &["/proc/net/udp", "/proc/net/udp6"][..],
        (false, false) => &["/proc/net/udp6", "/proc/net/udp"][..],
    };

    let target_hex = format_proc_net_addr(ip, src.port());
    let port_fallback = if !is_tcp {
        Some(format!(":{:04X}", src.port()))
    } else {
        None
    };

    let mut only_matched_port = None;

    for &file_path in proc_files {
        let Ok(file) = std::fs::File::open(file_path) else {
            continue;
        };
        let reader = std::io::BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let local_addr = fields[1];
            if local_addr == target_hex {
                return Some(fields[9].to_string());
            }
            if let Some(ref fb) = port_fallback {
                if local_addr.ends_with(fb) {
                    let wildcard = local_addr.trim_end_matches(fb);
                    if (wildcard.len() == 8 || wildcard.len() == 32)
                        && wildcard.chars().all(|c| c == '0')
                    {
                        only_matched_port = Some(fields[9].to_string());
                    }
                }
            }
        }
    }
    only_matched_port
}

#[cfg(target_os = "linux")]
fn format_proc_net_addr(ip: std::net::IpAddr, port: u16) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(40);
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let val = u32::from_ne_bytes(ipv4.octets());
            let _ = write!(s, "{val:08X}:{port:04X}");
        }
        std::net::IpAddr::V6(ipv6) => {
            for chunk in ipv6.octets().chunks_exact(4) {
                let val = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                let _ = write!(s, "{val:08X}");
            }
            let _ = write!(s, ":{port:04X}");
        }
    }
    s
}

#[cfg(target_os = "linux")]
fn find_pid_by_socket_inode(inode: &str) -> Option<u32> {
    let target_link = format!("socket:[{inode}]");
    let proc_dir = std::fs::read_dir("/proc").ok()?;

    for entry in proc_dir.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let file_name = entry.file_name();
        let name_str = file_name.to_str()?;
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };

        let fd_dir_path = format!("/proc/{pid}/fd");
        let Ok(fd_dir) = std::fs::read_dir(&fd_dir_path) else {
            continue;
        };
        for fd_entry in fd_dir.flatten() {
            if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                if link.to_str() == Some(&target_link) {
                    return Some(pid);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_names_match_exactly() {
        let m = ProcessMatcher::new(&["foo.exe".to_owned(), "bar".to_owned()]);
        assert!(m.matches(1, "foo", ""));
        assert!(m.matches(1, "bar", ""));
        assert!(!m.matches(1, "foo.exe", ""));
        assert!(!m.matches(1, "bar.exe", ""));
    }
}
