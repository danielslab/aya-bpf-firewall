use anyhow::Context;
use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Bpf,
    maps::HashMap,
};
use aya_log::BpfLogger;
use std::net::{Ipv4Addr, Ipv6Addr};
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long, default_value = "")]
    bpfprog: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.

    let mut bpf = if opt.bpfprog != "" {
        let bpf = Bpf::load_file(&opt.bpfprog)?;
        bpf
    } else {

        #[cfg(debug_assertions)]
        let bpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/aya-bpf-firewall"
        ))?;
        #[cfg(not(debug_assertions))]
        let bpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/aya-bpf-firewall"
        ))?;
        bpf
    };


    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("aya_bpf_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

        let mut blocklist_v4: HashMap<_,u32, u32> =HashMap::try_from(bpf.map_mut("BLOCKLIST_V4").unwrap())?;
        let block_adddr_v4: u32 = Ipv4Addr::new(192,168,1,1).try_into()?;
        blocklist_v4.insert(block_adddr_v4, 0, 0)?;
    
        blocklist_v4.keys().for_each(|k| {
            info!("blocklist_v4: {:?}", k.unwrap());
        });
    
        for entry in blocklist_v4.iter() {
            match entry {
                Ok((key, value)) => {
                    let key: Ipv4Addr = key.try_into()?;
                    println!("Key: {}, Value: {}", key, value)
                },
                Err(e) => eprintln!("Error: {}", e),
            }
        }
    
        for entry in blocklist_v4.iter(){
            let (a,b)= entry.unwrap();
            println!("Key: {}, Value: {}", a, b)
        };
    
        let mut blocklist_v6: HashMap<_,u128, u32> =HashMap::try_from(bpf.map_mut("BLOCKLIST_V6").unwrap())?;
        let block_adddr_v6: u128 = Ipv6Addr::new(1,1,1,1,1,1,1,1).try_into()?;
        blocklist_v6.insert(block_adddr_v6, 0, 0)?;
    
        blocklist_v6.keys().for_each(|k| {
            info!("blocklist_v6: {:?}", k.unwrap());
        });
    
        for entry in blocklist_v6.iter() {
            match entry {
                Ok((key, value)) => {
                    let key: Ipv6Addr = key.try_into()?;
                    println!("Key: {}, Value: {}", key, value)
                },
                Err(e) => eprintln!("Error: {}", e),
            }
        }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
