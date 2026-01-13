use std::{mem, ops::Not, path::PathBuf, sync::Arc, time::Duration};

use iced::{Length, Task, alignment::Vertical, task::sipper};
use rfd::{AsyncFileDialog, FileHandle};
use tokio::{fs, io::AsyncWriteExt, time::Instant};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub enum Message {
    SelectFolder,
    SelectedFolder(Option<Arc<FileHandle>>),
    AbortScan,
    ScanComplete,
    Error(String),
    LimitChanged(String),
    StartScan,
    ScanUpdate {
        now_scanned: u64,
        new_paths_over_limit: Vec<OverLimit>,
    },
    ExportCsv,
    CsvExportComplete(Result<String, String>),
}

pub struct PathLengthChecker {
    selecting: bool,
    selected: Option<PathBuf>,
    scan_status: ScanStatus,
    paths_over_limit: Vec<OverLimit>,
    scanned: u64,
    limit_input: String,
    limit: usize,
    scan_limit: usize,
    errors: Vec<String>,
    exporting: bool,
    export_message: Option<String>,
    export_success: bool,
}

enum ScanStatus {
    WaitingForStart,
    Scanning(CancellationToken),
    Done,
}

impl ScanStatus {
    fn is_idle(&self) -> bool {
        match self {
            ScanStatus::WaitingForStart => true,
            ScanStatus::Scanning(_) => false,
            ScanStatus::Done => true,
        }
    }

    fn is_scanning(&self) -> bool {
        match self {
            ScanStatus::WaitingForStart => false,
            ScanStatus::Scanning(_) => true,
            ScanStatus::Done => false,
        }
    }

    fn is_done(&self) -> bool {
        match self {
            ScanStatus::WaitingForStart => false,
            ScanStatus::Scanning(_) => false,
            ScanStatus::Done => true,
        }
    }

    fn cancel(&mut self) {
        match self {
            ScanStatus::WaitingForStart => (),
            ScanStatus::Scanning(cancellation_token) => {
                cancellation_token.cancel();
                *self = Self::Done;
            }
            ScanStatus::Done => (),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OverLimit {
    path: String,
    size: u64,
}

impl PathLengthChecker {
    pub fn new() -> Self {
        Self {
            selecting: false,
            selected: None,
            scan_status: ScanStatus::WaitingForStart,
            paths_over_limit: Vec::new(),
            scanned: 0,
            limit_input: "240".to_string(),
            limit: 240,
            scan_limit: 240,
            errors: Vec::new(),
            exporting: false,
            export_message: None,
            export_success: false,
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::SelectFolder => {
                self.selecting = true;
                Task::future(async {
                    let folder = AsyncFileDialog::new().pick_folder().await;
                    Message::SelectedFolder(folder.map(Arc::new))
                })
            }
            Message::SelectedFolder(selected) => {
                self.selecting = false;
                if let Some(selected) = selected {
                    if let Some(selected) = Arc::into_inner(selected) {
                        let selected: PathBuf = selected.path().into();
                        self.selected = Some(selected.clone());
                        self.scan_status = ScanStatus::WaitingForStart;
                    }
                }
                Task::none()
            }
            Message::AbortScan | Message::ScanComplete => {
                self.cancel_scan();
                Task::none()
            }
            Message::Error(err) => {
                self.errors.push(err);
                Task::none()
            }
            Message::LimitChanged(limit) => {
                self.limit_input = limit.clone();
                if let Ok(parsed) = limit.parse::<usize>() {
                    self.limit = parsed;
                }
                Task::none()
            }
            Message::StartScan => {
                if let Some(ref folder) = self.selected {
                    self.scan_status.cancel();
                    self.paths_over_limit.clear();
                    self.errors.clear();
                    self.scanned = 0;
                    self.export_message = None;
                    let token = CancellationToken::new();
                    self.scan_status = ScanStatus::Scanning(token.clone());
                    self.scan_limit = self.limit;
                    self.start_scan(folder.clone(), self.limit, token)
                } else {
                    Task::none()
                }
            }
            Message::ScanUpdate {
                now_scanned,
                new_paths_over_limit,
            } => {
                self.scanned = now_scanned;
                self.paths_over_limit.extend(new_paths_over_limit);
                Task::none()
            }
            Message::ExportCsv => {
                if self.paths_over_limit.is_empty() {
                    Task::none()
                } else {
                    self.exporting = true;
                    self.export_message = None;
                    let paths_to_export = self.paths_over_limit.clone();
                    Task::future(async move {
                        let file_handle = AsyncFileDialog::new()
                            .set_file_name("path_length_report.csv")
                            .add_filter("CSV", &["csv"])
                            .save_file()
                            .await;

                        if let Some(file_handle) = file_handle {
                            let export_count = paths_to_export.len();
                            let file_path = file_handle.path().to_path_buf();

                            match tokio::fs::File::create(&file_path).await {
                                Ok(mut file) => {
                                    // Write CSV header
                                    if let Err(e) = file.write_all(b"Length;Path\n").await {
                                        return Message::CsvExportComplete(Err(format!(
                                            "Failed to write CSV header: {}",
                                            e
                                        )));
                                    }

                                    // Write in chunks of 1000 lines
                                    for chunk in paths_to_export.chunks(1000) {
                                        let mut chunk_content = String::new();
                                        for path in chunk {
                                            chunk_content.push_str(&format!(
                                                "{};\"{}\"\n",
                                                path.size,
                                                path.path
                                                    .replace("\\", "\\\\")
                                                    .replace("\"", "\"\""),
                                            ));
                                        }

                                        if let Err(e) =
                                            file.write_all(chunk_content.as_bytes()).await
                                        {
                                            return Message::CsvExportComplete(Err(format!(
                                                "Failed to write CSV chunk: {}",
                                                e
                                            )));
                                        }
                                    }

                                    if let Err(e) = file.flush().await {
                                        return Message::CsvExportComplete(Err(format!(
                                            "Failed to flush CSV file: {}",
                                            e
                                        )));
                                    }

                                    Message::CsvExportComplete(Ok(format!(
                                        "Exported {} paths to {}",
                                        export_count,
                                        file_path.display()
                                    )))
                                }
                                Err(e) => Message::CsvExportComplete(Err(format!(
                                    "Failed to create CSV file: {}",
                                    e
                                ))),
                            }
                        } else {
                            Message::CsvExportComplete(Err("Export cancelled".to_string()))
                        }
                    })
                }
            }
            Message::CsvExportComplete(result) => {
                self.exporting = false;
                match result {
                    Ok(success_msg) => {
                        self.export_message = Some(success_msg);
                        self.export_success = true;
                        Task::none()
                    }
                    Err(error_msg) => {
                        self.export_message = Some(error_msg);
                        self.export_success = false;
                        Task::none()
                    }
                }
            }
        }
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        use iced::widget::{column, *};

        let main_controls = column![
            row![
                button(text("Select Folder")).on_press_maybe(if self.selecting {
                    None
                } else {
                    Some(Message::SelectFolder)
                }),
                if let Some(selected) = &self.selected {
                    text(selected.to_string_lossy())
                } else {
                    text("")
                }
            ]
            .spacing(10)
            .align_y(Vertical::Center),
            row![
                text("Path Length Limit:"),
                text_input("", &self.limit_input)
                    .on_input(Message::LimitChanged)
                    .on_submit(Message::StartScan)
                    .width(Length::Fixed(100.0)),
            ]
            .spacing(10)
            .align_y(Vertical::Center),
            row![
                button(text("Start Scan")).on_press_maybe(
                    if self.selected.is_some() && !self.scan_status.is_scanning() {
                        Some(Message::StartScan)
                    } else {
                        None
                    }
                ),
                button(text("Abort")).on_press_maybe(if self.scan_status.is_scanning() {
                    Some(Message::AbortScan)
                } else {
                    None
                }),
                button(text("Export CSV")).on_press_maybe(
                    if !self.paths_over_limit.is_empty()
                        && !self.exporting
                        && self.scan_status.is_done()
                    {
                        Some(Message::ExportCsv)
                    } else {
                        None
                    }
                ),
            ]
            .spacing(10),
        ]
        .spacing(10);

        column![
            main_controls,
            match &self.scan_status {
                ScanStatus::Scanning(_) => {
                    Some(text(format!("Scanning... {} paths checked", self.scanned)).size(16))
                }
                ScanStatus::Done => {
                    Some(text(format!("Scan Finished! {} paths checked", self.scanned)).size(16))
                }
                ScanStatus::WaitingForStart => None,
            },
            if self.scan_status.is_idle() {
                None
            } else if self.paths_over_limit.is_empty() {
                Some(text("No paths over limit found"))
            } else {
                Some(
                    text(format!(
                        "Found {} paths over limit ({})",
                        self.paths_over_limit.len(),
                        self.scan_limit
                    ))
                    .size(18),
                )
            },
            self.exporting.then(|| text("Exporting to CSV...").size(16)),
            self.export_message.as_ref().map(|message| {
                if self.export_success {
                    text(message)
                        .size(16)
                        .color(iced::Color::from_rgb(0.0, 0.6, 0.0))
                } else {
                    text(message)
                        .size(16)
                        .color(iced::Color::from_rgb(0.8, 0.2, 0.2))
                }
            }),
            self.errors.is_empty().not().then(|| {
                column![
                    text(format!("Errors ({})", self.errors.len()))
                        .size(18)
                        .color(iced::Color::from_rgb(0.8, 0.2, 0.2)),
                    scrollable(column(self.errors.iter().map(|error| text(error).into())))
                        .height(Length::Fill)
                        .width(Length::Fill)
                ]
            }),
        ]
        .spacing(20)
        .padding(20)
        .into()
    }

    fn start_scan(
        &mut self,
        root: PathBuf,
        limit: usize,
        token: CancellationToken,
    ) -> Task<Message> {
        let sipper = sipper(move |mut sender| async move {
            let mut stack = vec![root];

            let mut scanned: u64 = 0;
            let mut over_limit: Vec<OverLimit> = Vec::new();
            let mut last_update = Instant::now();

            token
                .run_until_cancelled(async move {
                    while let Some(path) = stack.pop() {
                        match fs::read_dir(&path).await {
                            Ok(mut entries) => {
                                while let Ok(Some(entry)) = entries.next_entry().await {
                                    let entry_path = entry.path();
                                    let path_length = entry_path.as_os_str().len();

                                    if path_length > limit {
                                        over_limit.push(OverLimit {
                                            path: entry_path
                                                .as_os_str()
                                                .to_string_lossy()
                                                .to_string(),
                                            size: path_length as u64,
                                        });
                                    }

                                    match entry.metadata().await {
                                        Ok(metadata) => {
                                            if metadata.is_dir() {
                                                stack.push(entry_path);
                                            }
                                        }
                                        Err(err) => {
                                            sender
                                                .send(Message::Error(format!(
                                                    "Error reading metadata for {}: {}",
                                                    entry_path.display(),
                                                    err
                                                )))
                                                .await;
                                        }
                                    }

                                    scanned += 1;

                                    let now = Instant::now();
                                    if now - last_update > Duration::from_millis(100) {
                                        sender
                                            .send(Message::ScanUpdate {
                                                now_scanned: scanned,
                                                new_paths_over_limit: mem::take(&mut over_limit),
                                            })
                                            .await;
                                        last_update = now;
                                    }
                                }
                            }
                            Err(err) => {
                                sender
                                    .send(Message::Error(format!(
                                        "Error reading directory {}: {}",
                                        path.display(),
                                        err
                                    )))
                                    .await;
                            }
                        }
                    }

                    sender
                        .send(Message::ScanUpdate {
                            now_scanned: scanned,
                            new_paths_over_limit: mem::take(&mut over_limit),
                        })
                        .await;
                })
                .await;
        });

        Task::sip(sipper, |value| value, |_| Message::ScanComplete)
    }

    pub(crate) fn cancel_scan(&mut self) {
        self.scan_status.cancel();
    }
}
