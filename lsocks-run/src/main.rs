#![feature(exit_status_error)]

use std::{io::{BufReader, BufWriter, Read, Write}, mem, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream}, process::Command};

use anyhow::{Context as _, Result, bail};
use argh::FromArgs;

/// Run service under lsocks
#[derive(FromArgs, Debug)]
struct Args {
    /// name of service
    #[argh(option)]
    name: String,

    /// socket address for lsocks registry
    #[argh(option)]
    target: SocketAddr,

    #[argh(positional)]
    program: String,

    #[argh(positional)]
    args: Vec<String>,
}

const IPV4_LEN: u8 = mem::size_of::<Ipv4Addr>() as u8;
const IPV6_LEN: u8 = mem::size_of::<Ipv6Addr>() as u8;

fn main() -> Result<()> {
    let args = argh::from_env::<Args>();

    let mut stream = TcpStream::connect(args.target)?;
    let mut writer = BufWriter::new(&mut stream);
    writer.write_all(b"LSCK")?;
    writer.write(&[args.name.len().try_into().context("")?])?;
    writer.write(args.name.as_bytes())?;
    writer.flush()?;
    drop(writer);

    let mut reader = BufReader::new(&mut stream);
    let mut buf = [0; 1];
    reader.read_exact(&mut buf)?;
    let len = buf[0];
    let addr = match len {
        IPV4_LEN => {
            let mut octets = [0; _];
            reader.read_exact(&mut octets)?;
            IpAddr::V4(Ipv4Addr::from_octets(octets))
        },
        IPV6_LEN => {
            let mut octets = [0; _];
            reader.read_exact(&mut octets)?;
            IpAddr::V6(Ipv6Addr::from_octets(octets))
        },
        _ => bail!("Unrecognized ip address"),
    };
    let addr = addr.to_string();
    drop(reader);

    let program = args.program;
    let mut args = args.args;
    for arg in &mut args {
        if arg.contains("{}") { *arg = arg.replace("{}", &addr); }
    }

    Ok(Command::new(program)
        .args(args)
        .spawn()?
        .wait()?
        .exit_ok()?)
}
