use std::net::Ipv4Addr;

use iced::{Element, Task, task::Handle};

use crate::{Module, OpenedModule, action::Action, tab_manager::TabMessage};

pub mod interfaces;
mod netbios;
mod ping;
mod scan;
mod view;

use interfaces::Interface;

#[derive(Clone)]
pub enum Message {
    InterfacesLoaded(Result<Vec<Interface>, String>),
    SelectInterface(Interface),
    Rescan,
    Cancel,
    ScanProgress(u64, scan::Progress),
    ScanFinished(u64, scan::Report),
    SelectDevice(Ipv4Addr),
}

pub struct State {
    interfaces: Result<Vec<Interface>, String>,
    loading_interfaces: Option<Handle>,
    interface: Option<Interface>,
    scan_request: u64,
    loading_scan: Option<Handle>,
    progress: scan::Progress,
    results: Option<scan::Report>,
    canceled: bool,
    device: Option<Ipv4Addr>,
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
            scan_request: 0,
            loading_scan: None,
            progress: scan::Progress::Preparing,
            results: None,
            canceled: false,
            device: None,
        };
        (
            Module::NetworkDevices(state),
            task.map(TabMessage::NetworkDevices),
        )
    }

    pub fn update(&mut self, message: Message) -> Action<Message> {
        match message {
            Message::InterfacesLoaded(result) => {
                self.loading_interfaces = None;
                self.interfaces = result;
            }
            Message::SelectInterface(interface)
                if self
                    .interfaces
                    .as_ref()
                    .is_ok_and(|options| options.contains(&interface)) =>
            {
                self.interface = Some(interface);
                self.results = None;
                self.device = None;
                return self.start_scan();
            }
            Message::Rescan if self.loading_scan.is_none() => return self.start_scan(),
            Message::Cancel if self.loading_scan.is_some() => {
                self.scan_request += 1;
                self.loading_scan = None;
                self.canceled = true;
            }
            Message::ScanProgress(request, progress)
                if request == self.scan_request && self.loading_scan.is_some() =>
            {
                self.progress = progress;
            }
            Message::ScanFinished(request, result) if request == self.scan_request => {
                self.loading_scan = None;
                self.device = self
                    .device
                    .filter(|ip| result.devices.iter().any(|row| row.ip == *ip));
                self.results = Some(result);
            }
            Message::SelectDevice(ip)
                if self
                    .results
                    .as_ref()
                    .is_some_and(|report| report.devices.iter().any(|row| row.ip == ip)) =>
            {
                self.device = Some(ip);
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
        self.canceled = false;
        self.progress = scan::Progress::Preparing;
        let request = self.scan_request;
        let (task, handle) = Task::sip(
            scan::discover(interface),
            move |progress| Message::ScanProgress(request, progress),
            move |result| Message::ScanFinished(request, result),
        )
        .abortable();
        self.loading_scan = Some(handle.abort_on_drop());
        Action::Task(task)
    }

    pub fn view(&self) -> Element<'_, Message> {
        view::render(self)
    }
}
