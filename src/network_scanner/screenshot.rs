use super::{State, interfaces::Interface, netbios, ports, scan};
use crate::{Module, arp::Device};

impl State {
    /// Fictional completed scan for documentation, without executing discovery tasks.
    pub(crate) fn screenshot_fixture() -> Self {
        let Module::NetworkDevices(mut state) = Self::new().0 else {
            unreachable!("network constructor returns a network scanner");
        };
        let interface = Interface {
            name: "Office Ethernet".into(),
            ip: [192, 0, 2, 10].into(),
            prefix: 24,
        };
        state.loading_interfaces = None;
        state.interfaces = Ok(vec![interface.clone()]);
        state.interface = Some(interface);

        // Documentation-only addresses and locally administered MACs avoid real device data.
        let examples: &[(u8, &str, bool, &[u16])] = &[
            (1, "gateway.example", true, &[80, 443]),
            (20, "fileserver.example", true, &[22, 445]),
            (30, "workstation.example", true, &[3389]),
            (40, "printer.example", true, &[80, 631, 9100]),
            (50, "hypervisor.example", true, &[22, 8006]),
            (60, "backup.example", false, &[22, 443]),
            (70, "ups-monitor.example", true, &[3493]),
        ];
        let mut devices = Vec::new();
        for &(host, hostname, replied, open_ports) in examples {
            let ip = [192, 0, 2, host].into();
            devices.push(scan::Observation {
                ip,
                ping_reply: Some(replied),
                addresses: vec![Device {
                    ip,
                    mac: [0x02, 0, 0, 0, 0, host],
                }],
                names: match host {
                    20 | 30 => vec![netbios::Name {
                        name: if host == 20 {
                            "FILESERVER"
                        } else {
                            "OFFICE-PC"
                        }
                        .into(),
                        suffix: 0,
                    }],
                    _ => Vec::new(),
                },
                hostname: Some(hostname.into()),
            });
            state.port_results.insert(
                ip,
                ports::PORTS
                    .iter()
                    .map(|port| {
                        let outcome = if open_ports.contains(&port.number) {
                            ports::Outcome::Open
                        } else {
                            ports::Outcome::Refused
                        };
                        (port.number, outcome)
                    })
                    .collect(),
            );
        }
        state.port_completed = devices.len() * ports::PORTS.len();
        state.results = Some(scan::Report {
            devices,
            notices: Vec::new(),
        });
        state
    }
}
