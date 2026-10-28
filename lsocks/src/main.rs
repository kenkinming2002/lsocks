#![feature(try_blocks)]

use std::{collections::{HashMap, hash_map}, mem, net::{IpAddr, Ipv4Addr, Ipv6Addr, }, sync::{Arc, Mutex, RwLock}};

use anyhow::{Result, bail};
use argh::{FromArgValue, FromArgs};
use ipnet::{IpAddrRange, IpNet};
use log::{error, info, warn};
use tokio::{io::{self, AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt, BufReader, BufStream, BufWriter}, net::{TcpListener, TcpStream}};

#[derive(Debug, Clone, Copy)]
struct RemapPort {
    from: u16,
    to: u16,
}

impl FromArgValue for RemapPort {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        let mut components = value.split(":");

        let from = components.next().ok_or_else(|| String::from("missing from port"))?.parse().map_err(|e| format!("{e}"))?;
        let to   = components.next().ok_or_else(|| String::from("missing to port"))?  .parse().map_err(|e| format!("{e}"))?;
        let None = components.next() else { return Err(String::from("too many ports")); };

        Ok(Self{ from, to })
    }
}

/// Socks proxy for local services.
#[derive(FromArgs)]
#[derive(Debug)]
struct Args {
    /// ip network
    #[argh(option)]
    net: IpNet,

    /// prefix for local service
    #[argh(option)]
    prefix: String,

    /// remap ports
    #[argh(option)]
    remap_port: Vec<RemapPort>,

    /// port for local service registry
    #[argh(option)]
    registry: u16,

    /// port for HTTP server serving PAC file
    #[argh(option)]
    pac: u16,

    /// port for SOCKS proxy
    #[argh(option)]
    socks: u16,
}

#[derive(Debug)]
struct IpAddrAlloc {
    addr: IpAddr,
    addr_range: IpAddrRange,
}

#[derive(Debug)]
struct LSocks {
    net: IpNet,
    prefix: String,
    remap_port: HashMap<u16, u16>,

    registry: u16,
    pac: u16,
    socks: u16,

    addr_map: RwLock<HashMap<String, IpAddr>>,
    addr_alloc: Mutex<IpAddrAlloc>,
    pac_resp: String,
}

#[derive(Debug)]
enum Addr {
    Ip(IpAddr),
    DomainName(String),
}

impl IpAddrAlloc {
    fn new(net: IpNet) -> Self {
        Self {
            addr: net.addr(),
            addr_range: net.hosts(),
        }
    }

    fn alloc(&mut self) -> Option<IpAddr> {
        self.addr_range.find(|&addr| self.addr != addr)
    }
}

impl Addr {
    async fn connect(&self, port: u16) -> io::Result<TcpStream> {
        match self {
            Addr::Ip(addr) => TcpStream::connect((*addr, port)).await,
            Addr::DomainName(domain_name) => TcpStream::connect((domain_name.as_str(), port)).await,
        }
    }

    async fn read<R: AsyncRead + Unpin>(mut reader: R) -> Result<Self> {
        let atyp = reader.read_u8().await?;
        match atyp {
            0x01 /* IP V4 address */ => {
                let mut octets = [0; _];
                reader.read_exact(&mut octets).await?;
                Ok(Addr::Ip(IpAddr::V4(Ipv4Addr::from_octets(octets))))
            },
            0x03 /* DOMAINNAME */ => {
                let len = reader.read_u8().await?;
                let mut bytes = vec![0; len as usize];
                reader.read_exact(&mut bytes).await?;
                Ok(Addr::DomainName(String::from_utf8(bytes)?))
            },
            0x04 /* IP V6 address */ => {
                let mut octets = [0; _];
                reader.read_exact(&mut octets).await?;
                Ok(Addr::Ip(IpAddr::V6(Ipv6Addr::from_octets(octets))))
            },
            _ => bail!("invalid atyp {atyp}"),
        }
    }

    async fn write<W: AsyncWrite + Unpin>(&self, mut writer: W) -> Result<()> {
        match self {
            Addr::Ip(IpAddr::V4(addr)) => {
                writer.write_u8(0x01).await?;
                writer.write_all(&addr.octets()).await?;
            },
            Addr::DomainName(domain_name) => {
                writer.write_u8(0x03).await?;
                writer.write_u8(domain_name.len() as u8).await?;
                writer.write_all(domain_name.as_bytes()).await?;
            },
            Addr::Ip(IpAddr::V6(addr)) => {
                writer.write_u8(0x04).await?;
                writer.write_all(&addr.octets()).await?;
            },
        }
        Ok(())
    }
}

impl LSocks {
    fn new(Args { net, prefix, remap_port, registry, pac, socks }: Args) -> Self {
        let remap_port = remap_port.into_iter().map(|RemapPort { from, to }| (from, to)).collect();
        let addr_map = RwLock::new(HashMap::new());
        let addr_alloc = Mutex::new(IpAddrAlloc::new(net));
        let pac_resp = format!(concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: application/javascript\r\n",
            "\r\n",
            "function FindProxyForURL(url, host) {{\r\n",
            "  if (dnsDomainIs(host, \"{}\")) {{\r\n",
            "    return \"SOCKS5 {}:{}\";\r\n",
            "  }} else {{\r\n",
            "    return \"DIRECT\";\r\n",
            "  }}\r\n",
            "}}\r\n",
        ), prefix, net.addr(), socks);

        Self { net, prefix, remap_port, registry, pac, socks, addr_map, addr_alloc, pac_resp }
    }

    async fn run(self: Arc<Self>) -> Result<()> {
        let addr = self.net.addr();
        let registry = TcpListener::bind((addr, self.registry)).await?;
        let pac = TcpListener::bind((addr, self.pac)).await?;
        let socks = TcpListener::bind((addr, self.socks)).await?;
        loop {
            tokio::select! {
                conn = registry.accept() => match conn {
                    Ok((conn, _)) => { tokio::spawn({ let this = self.clone(); async move { if let Err(e) = this.handle_registry(conn).await { error!("{e}") } } });},
                    Err(e) => error!("failed to accept connection for registry: {e}"),
                },
                conn = pac.accept() => match conn {
                    Ok((conn, _)) => { tokio::spawn({ let this = self.clone(); async move { if let Err(e) = this.handle_pac(conn).await { error!("{e}") } } });},
                    Err(e) => error!("failed to accept connection for pac: {e}"),
                },
                conn = socks.accept() => match conn {
                    Ok((conn, _)) => { tokio::spawn({ let this = self.clone(); async move { if let Err(e) = this.handle_socks(conn).await { error!("{e}") } } });},
                    Err(e) => error!("failed to accept connection for socks: {e}"),
                },
            };
        }
    }

    async fn handle_registry(&self, mut stream: TcpStream) -> Result<()> {
        let (reader, writer) = stream.split();
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        let length = reader.read_u8().await?;

        let mut name = vec![0; length as usize];
        reader.read_exact(&mut name).await?;
        let name = str::from_utf8(&name)?;

        let addr = {
            let mut addr_map = self.addr_map.write().unwrap();
            let hash_map::Entry::Vacant(entry) = addr_map.entry(name.to_owned()) else { bail!("name \"{name}\" already allocated") };

            let mut addr_alloc = self.addr_alloc.lock().unwrap();
            let Some(addr) = addr_alloc.alloc() else { bail!("address exhausted")};

            entry.insert(addr);
            addr
        };

        match addr {
            IpAddr::V4(addr) => {
                writer.write_u8(mem::size_of::<Ipv4Addr>() as u8).await?;
                writer.write_all(&addr.octets()).await?;
            },
            IpAddr::V6(addr) => {
                writer.write_u8(mem::size_of::<Ipv6Addr>() as u8).await?;
                writer.write_all(&addr.octets()).await?;
            },
        }

        writer.flush().await?;
        info!("registered: {} => {}", name, addr);

        let mut c = [0; 1];
        loop {
            let n = reader.read(&mut c).await?;
            if n == 0 { break }
            warn!("excess byte {} read from registry connection", c[0]);
        }

        let mut addr_map = self.addr_map.write().unwrap();
        addr_map.remove(name);

        info!("deregistered: {} => {}", name, addr);
        Ok(())
    }

    async fn handle_pac(&self, mut stream: TcpStream) -> Result<()> {
        // Who cares about properly handling HTTP semantic anyway? Practically, HTTP request should
        // be small enough that it fits into internal buffer and there is no need to drain it, but
        // we do it anyway.
        let (reader, mut writer) = stream.split();
        let reader = BufReader::new(reader);
        let mut lines = reader.lines();
        while let Some(line) = lines.next_line().await? { if line.is_empty() { break } }
        writer.write_all(self.pac_resp.as_bytes()).await?;
        Ok(())
    }

    fn resolve(&self, addr: Addr, port: u16) -> Option<(Addr, u16)> {
        if let Addr::DomainName(domain_name) = &addr {
            if let Some(domain_name) = domain_name.strip_suffix(&self.prefix) {
                if let Some(domain_name) = domain_name.strip_suffix(".") {
                    if let Some(addr) = self.addr_map.read().unwrap().get(domain_name) {
                        let addr = Addr::Ip(*addr);
                        let port = self.remap_port.get(&port).cloned().unwrap_or(port);
                        return Some((addr, port))
                    } else {
                        return None
                    }
                }
            }
        }
        Some((addr, port))
    }

    async fn handle_socks(&self, stream: TcpStream) -> Result<()> {
        let mut stream = BufStream::new(stream);

        ////////////////////////
        // Method Negotiation //
        ////////////////////////

        let ver = stream.read_u8().await?;
        if ver != 0x05 { bail!("invalid socks version {ver}") }

        let mut has_method = false;
        let nmethods = stream.read_u8().await?;
        for _ in 0..nmethods {
            let method = stream.read_u8().await?;
            if method == 0x00 { has_method = true }
        }

        if !has_method {
            stream.write_all(&[0x05, 0xFF]).await?; // [VER=5, METHOD=NO ACCEPTABLE METHODS=X'FF']
            stream.flush().await?;
            return Ok(());
        } else {
            stream.write_all(&[0x05, 0x00]).await?; // [VER=5, METHOD=NO AUTHENTICATION REQUIRED=X'00']
            stream.flush().await?;
        }

        /////////////
        // Request //
        /////////////

        let ver = stream.read_u8().await?;
        if ver != 5 { bail!("invalid socks version {ver}") }

        let cmd = stream.read_u8().await?;
        let _rsv = stream.read_u8().await?;
        let dst_addr = Addr::read(&mut stream).await?;
        let dst_port = stream.read_u16().await?;

        //////////////
        // Response //
        //////////////

        match cmd {
            1 /* CONNECT */ => {
                let dst_stream = try {
                    let (dst_addr, dst_port) = self.resolve(dst_addr, dst_port)?;
                    let dst_stream = dst_addr.connect(dst_port).await.ok()?;
                    dst_stream
                };

                let ver = 0x05;
                let rep = dst_stream.as_ref().map(|_| 0x00 /* Succeeded */).unwrap_or(0x04 /* general socks server failure */);
                let rsv = 0x0;
                let (bnd_addr, bnd_port) = dst_stream
                    .as_ref()
                    .and_then(|dst_stream| dst_stream.local_addr().ok())
                    .map(|addr| (Addr::Ip(addr.ip()), addr.port()))
                    .unwrap_or((Addr::DomainName(Default::default()), 0));

                stream.write_u8(ver).await?;
                stream.write_u8(rep).await?;
                stream.write_u8(rsv).await?;
                bnd_addr.write(&mut stream).await?;
                stream.write_u16(bnd_port).await?;
                stream.flush().await?;

                if let Some(mut dst_stream) = dst_stream {
                    tokio::io::copy_bidirectional(&mut stream, &mut dst_stream).await?;
                }
            },
            2 /* BIND */ => {
                let ver = 0x05;
                let rep = 0x07 /* Command not supported */;
                let rsv = 0x0;
                let (bnd_addr, bnd_port) = (Addr::DomainName(Default::default()), 0);

                stream.write_u8(ver).await?;
                stream.write_u8(rep).await?;
                stream.write_u8(rsv).await?;
                bnd_addr.write(&mut stream).await?;
                stream.write_u16(bnd_port).await?;
                stream.flush().await?;
            },
            3 /* UDP ASSOCIATE */ => {
                let ver = 0x05;
                let rep = 0x07 /* Command not supported */;
                let rsv = 0x0;
                let (bnd_addr, bnd_port) = (Addr::DomainName(Default::default()), 0);

                stream.write_u8(ver).await?;
                stream.write_u8(rep).await?;
                stream.write_u8(rsv).await?;
                bnd_addr.write(&mut stream).await?;
                stream.write_u16(bnd_port).await?;
                stream.flush().await?;
            },
            _ => bail!("invalid cmd {cmd}"),
        }
        Ok(())
    }

}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
    let args = argh::from_env::<Args>();
    let lsocks = Arc::new(LSocks::new(args));
    lsocks.run().await
}
