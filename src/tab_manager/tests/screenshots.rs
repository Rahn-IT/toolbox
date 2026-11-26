use std::{fs, path::Path, sync::Arc};

use iced::{Settings, Theme, widget::text_editor};

use super::super::TabManager;
use crate::{
    Module, encoder, mailbox_scanner, network_scanner, nut, path_length_checker, wake_on_lan,
};

#[test]
#[ignore = "Generates README screenshots; run with just screenshots"]
fn generate_readme_screenshots() -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = root.join("screenshots");
    let staging = root
        .join("target/readme-screenshots")
        .join(std::process::id().to_string());
    fs::create_dir_all(&output)?;
    fs::create_dir_all(&staging)?;

    let mut screens = vec![
        ("search", Module::Search(String::new())),
        (
            "mailbox-scanner",
            Module::MailboxScanner(mailbox_scanner::App::screenshot_fixture()),
        ),
        (
            "path-length-checker",
            Module::PathLengthChecker(path_length_checker::PathLengthChecker::screenshot_fixture()),
        ),
        ("nut-client", Module::Nut(nut::Nut::screenshot_fixture())),
    ];

    let Module::Encoder(mut state) = encoder::Encoder::new(encoder::Encoding::Base64).0 else {
        unreachable!("encoder constructor returns an encoder");
    };
    let _ = state.update(encoder::Message::DecodedChanged(text_editor::Action::Edit(
        text_editor::Edit::Paste(Arc::new("Hello from Rahn-IT Toolbox!".into())),
    )));
    let _ = state.update(encoder::Message::Encode);
    screens.push(("encoder-base64", Module::Encoder(state)));

    // Use fixed state and discard tasks so capturing never accesses the network or ARP cache.
    let mut wake = wake_on_lan::State::default();
    let _ = wake.update(wake_on_lan::Message::MacChanged("02:00:00:00:00:01".into()));
    let _ = wake.update(wake_on_lan::Message::DevicesLoaded(Ok([1, 20, 30, 40, 50]
        .into_iter()
        .map(|host| wake_on_lan::Device {
            ip: [192, 0, 2, host].into(),
            mac: [2, 0, 0, 0, 0, host],
        })
        .collect())));
    let _ = wake.update(wake_on_lan::Message::Sent(Ok(())));
    screens.push(("wake-on-lan", Module::WakeOnLan(wake)));

    screens.push((
        "network-scan",
        Module::NetworkDevices(network_scanner::State::screenshot_fixture()),
    ));

    #[cfg(windows)]
    {
        let Module::QuickInstall(mut install) = crate::quick_install::QuickInstall::new().0 else {
            unreachable!("quick install constructor returns quick install");
        };
        for id in ["firefox", "7zip", "windirstat"] {
            let _ = install.update(crate::quick_install::Message::Toggled(id, true));
        }
        screens.push(("quick-install", Module::QuickInstall(install)));
    }

    for (name, module) in screens {
        let mut app = TabManager::default();
        app.tabs.insert(0, module);
        let mut simulator =
            iced_test::Simulator::with_size(Settings::default(), (1400.0, 850.0), app.view());

        // iced adds a renderer suffix and only writes missing images. An empty staging
        // directory lets every run regenerate images while keeping published names stable.
        let frame = staging.join(name);
        fs::create_dir_all(&frame)?;
        for entry in fs::read_dir(&frame)? {
            fs::remove_file(entry?.path())?;
        }
        assert!(
            simulator
                .snapshot(&Theme::Dark)?
                .matches_image(frame.join(name))?
        );
        let files = fs::read_dir(&frame)?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(files.len(), 1, "expected one PNG for {name}");
        let destination = output.join(format!("{name}.png"));
        fs::copy(files[0].path(), &destination)?;
        println!("Generated {}", destination.display());
        fs::remove_dir_all(frame)?;
    }
    fs::remove_dir(staging)?;
    Ok(())
}
