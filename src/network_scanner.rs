use std::{collections::BTreeMap, net::Ipv4Addr};

use iced::{Element, Task, task::Handle};

use crate::{Module, OpenedModule, action::Action, tab_manager::TabMessage};

pub mod device_scan;
pub mod interfaces;
pub(crate) mod name_lookup;
pub(crate) mod netbios;
pub(crate) mod ping;
pub(crate) mod ports;
mod scan;
mod view;

#[cfg(test)]
mod screenshot;

use interfaces::Interface;

#[derive(Clone)]
pub enum Message {
    InterfacesLoaded(Result<Vec<Interface>, String>),
    SelectInterface(Interface),
    FilterChanged(String),
    Rescan,
    Cancel,
    ScanUpdate(u64, scan::Update),
    ScanFinished(u64, scan::Report),
    CheckPorts,
    CancelPorts,
    PortResult(u64, Ipv4Addr, u16, ports::Outcome),
    PortsFinished(u64, Result<(), String>),
    OpenDevice(Ipv4Addr),
}

pub struct State {
    interfaces: Result<Vec<Interface>, String>,
    loading_interfaces: Option<Handle>,
    interface: Option<Interface>,
    filter: String,
    scan_request: u64,
    loading_scan: Option<Handle>,
    progress: scan::Progress,
    results: Option<scan::Report>,
    canceled: bool,
    port_request: u64,
    port_task: Option<Handle>,
    port_completed: usize,
    port_results: BTreeMap<Ipv4Addr, BTreeMap<u16, ports::Outcome>>,
    port_notice: Option<String>,
}

impl State {
    pub const TITLE: &str = "Network Scan";

    pub fn new() -> OpenedModule {
        let (task, handle) = Task::perform(interfaces::list(), |result| {
            Message::InterfacesLoaded(result.map_err(|error| error.to_string()))
        })
        .abortable();
        let state = Self {
            interfaces: Ok(Vec::new()),
            loading_interfaces: Some(handle.abort_on_drop()),
            interface: None,
            filter: String::new(),
            scan_request: 0,
            loading_scan: None,
            progress: scan::Progress::Preparing,
            results: None,
            canceled: false,
            port_request: 0,
            port_task: None,
            port_completed: 0,
            port_results: BTreeMap::new(),
            port_notice: None,
        };
        (
            Module::NetworkDevices(state),
            task.map(TabMessage::NetworkDevices),
        )
    }

    pub fn update(&mut self, message: Message) -> Action<Message> {
        match message {
            Message::FilterChanged(filter) => self.filter = filter,
            Message::OpenDevice(ip)
                if self
                    .results
                    .as_ref()
                    .is_some_and(|report| report.devices.iter().any(|device| device.ip == ip)) =>
            {
                return Action::OpenModule(device_scan::State::new(ip));
            }
            Message::InterfacesLoaded(result) => {
                self.loading_interfaces = None;
                self.interfaces = result;
                if let Ok([interface]) = self.interfaces.as_deref() {
                    self.interface = Some(interface.clone());
                    return self.start_scan();
                }
            }
            Message::SelectInterface(interface)
                if self
                    .interfaces
                    .as_ref()
                    .is_ok_and(|options| options.contains(&interface)) =>
            {
                self.interface = Some(interface);
                self.results = None;
                return self.start_scan();
            }
            Message::Rescan if self.loading_scan.is_none() => return self.start_scan(),
            Message::Cancel if self.loading_scan.is_some() => {
                self.scan_request += 1;
                self.loading_scan = None;
                self.canceled = true;
            }
            Message::ScanUpdate(request, update)
                if request == self.scan_request && self.loading_scan.is_some() =>
            {
                match update {
                    scan::Update::Progress(progress) => self.progress = progress,
                    scan::Update::Rows(rows) => {
                        let devices = &mut self.results.get_or_insert_default().devices;
                        for row in rows {
                            match devices.binary_search_by_key(&row.ip, |device| device.ip) {
                                Ok(index) => devices[index] = row,
                                Err(index) => devices.insert(index, row),
                            }
                        }
                    }
                }
            }
            Message::ScanFinished(request, result) if request == self.scan_request => {
                self.loading_scan = None;
                self.results = Some(result);
                return Action::Task(Task::done(Message::CheckPorts));
            }
            Message::CheckPorts if self.loading_scan.is_none() && self.port_task.is_none() => {
                return self.check_ports();
            }
            Message::CancelPorts if self.port_task.is_some() => {
                self.port_task = None;
                self.port_notice = Some("Port checks canceled.".into());
            }
            Message::PortResult(request, ip, port, outcome)
                if request == self.port_request && self.port_task.is_some() =>
            {
                if self
                    .port_results
                    .entry(ip)
                    .or_default()
                    .insert(port, outcome)
                    .is_none()
                {
                    self.port_completed += 1;
                }
            }
            Message::PortsFinished(request, result)
                if request == self.port_request && self.port_task.is_some() =>
            {
                self.port_task = None;
                self.port_notice = Some(match result {
                    Ok(()) => "Port checks complete.".into(),
                    Err(error) => format!("Could not check ports: {error}"),
                });
            }
            _ => {}
        }
        Action::None
    }

    fn start_scan(&mut self) -> Action<Message> {
        let Some(interface) = self.interface.clone() else {
            return Action::None;
        };
        self.scan_request += 1;
        self.port_task = None;
        self.port_results.clear();
        self.port_notice = None;
        self.results = None;
        self.canceled = false;
        self.progress = scan::Progress::Preparing;
        let request = self.scan_request;
        let (task, handle) = Task::sip(
            scan::discover(interface),
            move |update| Message::ScanUpdate(request, update),
            move |result| Message::ScanFinished(request, result),
        )
        .abortable();
        self.loading_scan = Some(handle.abort_on_drop());
        Action::Task(task)
    }

    fn check_ports(&mut self) -> Action<Message> {
        let (Some(interface), Some(report)) = (&self.interface, &self.results) else {
            return Action::None;
        };
        if report.devices.is_empty() {
            return Action::None;
        }
        if report.devices.len() > scan::MAX_HOSTS as usize {
            self.port_notice = Some("This list exceeds the device limit for port checks.".into());
            return Action::None;
        }
        self.port_request += 1;
        let request = self.port_request;
        self.port_completed = 0;
        self.port_results.clear();
        self.port_notice = None;
        let addresses = report.devices.iter().map(|device| device.ip).collect();
        let (task, handle) = Task::sip(
            ports::check(interface.clone(), addresses),
            move |(ip, port, outcome)| Message::PortResult(request, ip, port, outcome),
            move |result| Message::PortsFinished(request, result),
        )
        .abortable();
        self.port_task = Some(handle.abort_on_drop());
        Action::Task(task)
    }

    pub fn view(&self) -> Element<'_, Message> {
        view::render(self)
    }
}
