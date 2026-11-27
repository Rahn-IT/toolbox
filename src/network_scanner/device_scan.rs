use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    time::Duration,
};

use futures_util::StreamExt;
use iced::{
    Alignment, Border, Element, Font, Length, Task, Theme,
    task::Handle,
    widget::{Id, button, column, container, operation, row, scrollable, space, text, text_input},
};

use super::{interfaces, name_lookup, netbios, ping, ports, scan};
use crate::{
    Module, OpenedModule,
    action::Action,
    arp::{self, Scope},
    loading,
    tab_manager::TabMessage,
};

#[derive(Clone)]
pub enum Message {
    Finished(Result<Report, String>),
    OpenWebPort(u16),
    PortChanged(String),
    ScanPort,
    RescanPorts,
    RescanPortsFinished(Vec<(u16, Result<ports::Outcome, String>)>),
    PortFinished(u16, Result<ports::Outcome, String>),
}

#[derive(Clone)]
pub struct Report {
    interface: interfaces::Interface,
    ping: String,
    mac: Result<Option<String>, String>,
    hostname: Result<Option<String>, String>,
    netbios: Result<Option<String>, String>,
    ports: Vec<(u16, ports::Outcome)>,
}

pub struct State {
    ip: Ipv4Addr,
    title: String,
    pending: Option<Handle>,
    result: Option<Result<Report, String>>,
    port_input: String,
    port_input_id: Id,
    pending_ports: BTreeMap<u16, Handle>,
    manual_ports: BTreeSet<u16>,
    pending_rescan: Option<Handle>,
    port_error: Option<String>,
}

impl State {
    pub fn new(ip: Ipv4Addr) -> OpenedModule {
        let (task, handle) = Task::perform(scan_device(ip), Message::Finished).abortable();
        let state = Self {
            ip,
            title: ip.to_string(),
            pending: Some(handle.abort_on_drop()),
            result: None,
            port_input: String::new(),
            port_input_id: Id::unique(),
            pending_ports: BTreeMap::new(),
            manual_ports: BTreeSet::new(),
            pending_rescan: None,
            port_error: None,
        };
        (Module::DeviceScan(state), task.map(TabMessage::DeviceScan))
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn update(&mut self, message: Message) -> Action<Message> {
        match message {
            Message::Finished(result) => {
                self.pending = None;
                self.result = Some(result);
            }
            Message::OpenWebPort(port) => {
                if let Some(Ok(report)) = &self.result
                    && report.ports.contains(&(port, ports::Outcome::Open))
                    && let Some(protocol) =
                        ports::definition(port).and_then(|entry| entry.web_protocol)
                {
                    let _ = open::that_in_background(format!("{protocol}://{}:{port}/", self.ip));
                }
            }
            Message::PortChanged(value) => {
                self.port_input = value;
                self.port_error = None;
            }
            Message::ScanPort => return self.scan_port(),
            Message::RescanPorts => return self.rescan_ports(),
            Message::RescanPortsFinished(results) => {
                self.pending_rescan = None;
                for (port, result) in results {
                    self.apply_port_result(port, result);
                }
            }
            Message::PortFinished(port, result) => {
                if self.pending_ports.remove(&port).is_some() {
                    self.apply_port_result(port, result);
                }
            }
        }
        Action::None
    }

    fn apply_port_result(&mut self, port: u16, result: Result<ports::Outcome, String>) {
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                self.port_error = Some(format!("Could not scan port {port}: {error}"));
                ports::Outcome::Failed
            }
        };
        if let Some(Ok(report)) = &mut self.result {
            match report
                .ports
                .binary_search_by_key(&port, |(number, _)| *number)
            {
                Ok(index) => report.ports[index].1 = outcome,
                Err(index) => report.ports.insert(index, (port, outcome)),
            }
        }
    }

    fn can_rescan_ports(&self) -> bool {
        self.pending_rescan.is_none()
            && self.pending_ports.is_empty()
            && matches!(&self.result, Some(Ok(report)) if !report.ports.is_empty())
    }

    fn rescan_ports(&mut self) -> Action<Message> {
        let Some(Ok(report)) = &self.result else {
            return Action::None;
        };
        if !self.can_rescan_ports() {
            return Action::None;
        }
        let interface = report.interface.clone();
        let ip = self.ip;
        let numbers: Vec<_> = report.ports.iter().map(|&(port, _)| port).collect();
        let (task, handle) = Task::perform(
            async move {
                futures_util::stream::iter(numbers)
                    .map(|port| {
                        let interface = interface.clone();
                        async move { (port, ports::check_single(interface, ip, port).await) }
                    })
                    .buffer_unordered(16)
                    .collect()
                    .await
            },
            Message::RescanPortsFinished,
        )
        .abortable();
        self.port_error = None;
        self.pending_rescan = Some(handle.abort_on_drop());
        Action::Task(task)
    }

    fn entered_port(&self) -> Option<u16> {
        self.port_input.trim().parse::<u16>().ok().filter(|port| {
            *port != 0 && self.pending_rescan.is_none() && !self.pending_ports.contains_key(port)
        })
    }

    fn scan_port(&mut self) -> Action<Message> {
        let (Some(port), Some(Ok(report))) = (self.entered_port(), &self.result) else {
            return Action::None;
        };
        let interface = report.interface.clone();
        let (task, handle) = Task::perform(
            ports::check_single(interface, self.ip, port),
            move |result| Message::PortFinished(port, result),
        )
        .abortable();
        self.pending_ports.insert(port, handle.abort_on_drop());
        self.manual_ports.insert(port);
        self.port_input.clear();
        self.port_error = None;
        Action::Task(Task::batch([
            task,
            operation::focus(self.port_input_id.clone()),
        ]))
    }

    pub fn view(&self) -> Element<'_, Message> {
        let details = match &self.result {
            None => container(loading::content(None, "Scanning device…"))
                .center_x(Length::Fill)
                .padding([20, 0])
                .into(),
            Some(Err(error)) => text(error).into(),
            Some(Ok(report)) => self.report_view(report),
        };
        screen(column![text(self.title()).font(Font::MONOSPACE).size(28), details,].spacing(16))
    }

    fn report_view(&self, report: &Report) -> Element<'_, Message> {
        let identity = column![
            field("Interface", report.interface.to_string()),
            field("Ping reply", report.ping.as_str()),
            field("MAC address", optional_result(&report.mac)),
            field("Hostname", optional_result(&report.hostname)),
            field("NetBIOS", optional_result(&report.netbios)),
        ]
        .spacing(10);
        let mut visible_ports = report
            .ports
            .iter()
            .copied()
            .filter(|(port, outcome)| {
                !matches!(outcome, ports::Outcome::Refused | ports::Outcome::TimedOut)
                    || self.manual_ports.contains(port)
            })
            .peekable();
        let port_rows = if visible_ports.peek().is_none() {
            column![text("—")]
        } else {
            column![
                container(
                    row![
                        text("Port").width(75),
                        text("Common service").width(210),
                        text("Status"),
                    ]
                    .spacing(14),
                )
                .padding([0, 14]),
                column(visible_ports.map(|(port, outcome)| port_row(port, outcome))).spacing(6),
            ]
            .spacing(6)
        };
        column![
            container(identity)
                .padding(18)
                .width(Length::Fill)
                .style(panel_style),
            text("TCP ports").size(20),
            row![
                text_input("Port", &self.port_input)
                    .id(self.port_input_id.clone())
                    .width(145)
                    .on_input(Message::PortChanged)
                    .on_submit_maybe(self.entered_port().is_some().then_some(Message::ScanPort)),
                button("Scan")
                    .on_press_maybe(self.entered_port().is_some().then_some(Message::ScanPort)),
                space::horizontal(),
                button("Rescan all ports")
                    .on_press_maybe(self.can_rescan_ports().then_some(Message::RescanPorts)),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            self.pending_rescan
                .as_ref()
                .map(|_| loading::content(None, "Rescanning ports…")),
            (!self.pending_ports.is_empty()).then(|| text(format!(
                "Checking {} additional port(s)…",
                self.pending_ports.len()
            ))),
            self.port_error.as_deref().map(text),
            port_rows,
        ]
        .spacing(16)
        .into()
    }
}

fn screen<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(
        scrollable(
            container(container(content).width(Length::Fill).max_width(760))
                .center_x(Length::Fill)
                .padding([22, 16]),
        )
        .height(Length::Fill),
    )
    .width(Length::Fill)
    .into()
}

const PANEL_RADIUS: f32 = 8.0;

fn panel_style(theme: &Theme) -> container::Style {
    let background = theme.extended_palette().background.weak;
    container::background(background.color)
        .color(background.text)
        .border(Border::default().rounded(PANEL_RADIUS))
}

fn port_row(port: u16, outcome: ports::Outcome) -> Element<'static, Message> {
    let definition = ports::definition(port);
    let label = match outcome {
        ports::Outcome::Open => "Open",
        ports::Outcome::Refused => "Refused",
        ports::Outcome::Failed => "Connection error",
        ports::Outcome::TimedOut => "Timed out",
    };
    let content = row![
        text(port.to_string()).font(Font::MONOSPACE).width(75),
        text(definition.map_or("—", |entry| entry.label)).width(210),
        text(label),
    ]
    .spacing(14)
    .align_y(Alignment::Center);
    if outcome == ports::Outcome::Open
        && definition.is_some_and(|entry| entry.web_protocol.is_some())
    {
        button(
            content
                .push(space::horizontal())
                .push(text("Open in browser").size(14)),
        )
        .padding([9, 14])
        .width(Length::Fill)
        .style(|theme, status| {
            let mut style = button::secondary(theme, status);
            style.border.radius = PANEL_RADIUS.into();
            style
        })
        .on_press(Message::OpenWebPort(port))
        .into()
    } else {
        container(content)
            .padding([9, 14])
            .width(Length::Fill)
            .style(panel_style)
            .into()
    }
}

fn field<'a>(label: &str, value: impl Into<String>) -> Element<'a, Message> {
    row![text(label.to_owned()).width(125), text(value.into())]
        .spacing(12)
        .into()
}

fn optional_result(result: &Result<Option<String>, String>) -> &str {
    match result {
        Ok(Some(value)) => value,
        Ok(None) => "—",
        Err(error) => error,
    }
}

async fn scan_device(ip: Ipv4Addr) -> Result<Report, String> {
    let mut interfaces = interfaces::list()
        .await
        .map_err(|error| error.to_string())?;
    interfaces.retain(|interface| scan::in_subnet(interface, ip));
    interfaces.sort_unstable_by_key(|interface| std::cmp::Reverse(interface.prefix));
    let mut interfaces = interfaces.into_iter();
    let interface = interfaces
        .next()
        .ok_or("The device is outside the available IPv4 interfaces.")?;
    if interfaces
        .next()
        .is_some_and(|other| other.prefix == interface.prefix)
    {
        return Err("More than one interface matches this device.".into());
    }
    interfaces::verify_route(&interface)
        .await
        .map_err(|error| error.to_string())?;

    let (ping, hostname, netbios, port_results) = tokio::join!(
        ping_device(&interface, ip),
        read_hostname(ip),
        read_netbios(ip),
        ports::check_addresses(interface.ip, [ip], ports::EXTRA_PORTS).collect::<Vec<_>>(),
    );
    let mac = tokio::time::timeout(
        Duration::from_secs(5),
        arp::read(Scope::Interface {
            local_ip: interface.ip,
            device: &interface.name,
        }),
    )
    .await
    .map_err(|_| "Reading the ARP cache timed out.".to_owned())
    .and_then(|result| result)
    .map(|entries| {
        entries
            .into_iter()
            .find(|entry| entry.ip == ip)
            .map(|entry| entry.mac_address())
    });
    let mut ports = port_results
        .into_iter()
        .map(|(_, port, outcome)| (port, outcome))
        .collect::<Vec<_>>();
    ports.sort_unstable_by_key(|(port, _)| *port);
    Ok(Report {
        interface,
        ping,
        mac,
        hostname,
        netbios,
        ports,
    })
}

async fn ping_device(interface: &interfaces::Interface, ip: Ipv4Addr) -> String {
    let runner = match ping::prepare().await {
        Ok(runner) => runner,
        Err(error) => return error,
    };
    let _permit = scan::PROBES
        .acquire()
        .await
        .expect("the probe semaphore stays open");
    match runner.echo(Some(&interface.name), ip.into()).await {
        ping::Outcome::Reply(_) => "Yes".into(),
        ping::Outcome::NoReply => "No".into(),
        ping::Outcome::TimedOut => "Timed out".into(),
        ping::Outcome::Failed(error) => error,
    }
}

async fn read_hostname(ip: Ipv4Addr) -> Result<Option<String>, String> {
    let resolver = name_lookup::prepare()?;
    let _permit = scan::PROBES
        .acquire()
        .await
        .expect("the probe semaphore stays open");
    resolver.reverse(ip).await
}

async fn read_netbios(ip: Ipv4Addr) -> Result<Option<String>, String> {
    let Some(runner) = netbios::prepare()? else {
        return Ok(None);
    };
    let _permit = scan::PROBES
        .acquire()
        .await
        .expect("the probe semaphore stays open");
    match runner.lookup(ip).await {
        netbios::Outcome::Found(names) => Ok(Some(
            names
                .into_iter()
                .map(|name| format!("{} <{:02X}>", name.name, name.suffix))
                .collect::<Vec<_>>()
                .join(", "),
        )),
        netbios::Outcome::NoReply => Ok(None),
        netbios::Outcome::Failed(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submitting_another_port_does_not_wait_for_the_previous_result() {
        let ip = Ipv4Addr::new(192, 0, 2, 10);
        let (module, _initial_task) = State::new(ip);
        let Module::DeviceScan(mut state) = module else {
            panic!("expected a device scan");
        };
        let _ = state.update(Message::Finished(Ok(Report {
            interface: interfaces::Interface {
                name: "test".into(),
                ip: Ipv4Addr::new(192, 0, 2, 1),
                prefix: 24,
            },
            ping: "Yes".into(),
            mac: Ok(None),
            hostname: Ok(None),
            netbios: Ok(None),
            ports: Vec::new(),
        })));

        let _ = state.update(Message::PortChanged("1433".into()));
        assert!(matches!(state.update(Message::ScanPort), Action::Task(_)));
        assert!(state.port_input.is_empty());
        let _ = state.update(Message::PortChanged("53".into()));
        assert!(matches!(state.update(Message::ScanPort), Action::Task(_)));
        assert!(state.port_input.is_empty());
        assert_eq!(state.pending_ports.len(), 2);

        let _ = state.update(Message::PortFinished(1433, Ok(ports::Outcome::Refused)));
        let _ = state.update(Message::PortFinished(53, Ok(ports::Outcome::Open)));
        let report = state.result.unwrap().unwrap();
        assert!(matches!(
            report.ports.as_slice(),
            [(53, ports::Outcome::Open), (1433, ports::Outcome::Refused)]
        ));
    }
}
