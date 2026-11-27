use std::net::IpAddr;

use iced::{
    Alignment, Color, Element, Length,
    widget::{button, column, container, opaque, row, scrollable, space, text},
};
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::{extensions::GeneralName, time::ASN1Time, x509::X509Name};

use super::{Message, check_view::badge};

#[derive(Default)]
pub(super) struct ViewState {
    pub open: bool,
}

pub(super) fn view(certificates: &[CertificateDer<'_>]) -> Element<'static, Message> {
    let now = ASN1Time::now();
    let entries = column(
        certificates
            .iter()
            .enumerate()
            .map(|(index, certificate)| certificate_view(index, certificate.as_ref(), now)),
    )
    .spacing(12);
    let panel = container(
        column![
            row![
                text("Certificate chain").size(24),
                space::horizontal(),
                button("Close").on_press(Message::CloseCertificates),
            ]
            .align_y(Alignment::Center)
            .spacing(12),
            scrollable(entries).height(Length::Fill),
        ]
        .spacing(16),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .max_width(760)
    .max_height(540)
    .padding(24)
    .style(|theme: &iced::Theme| {
        container::rounded_box(theme).background(theme.extended_palette().background.base.color)
    });

    opaque(
        container(panel)
            .center(Length::Fill)
            .padding(24)
            .style(|_| container::background(Color::BLACK.scale_alpha(0.55))),
    )
}

fn certificate_view(index: usize, der: &[u8], now: ASN1Time) -> Element<'static, Message> {
    let role = if index == 0 {
        "Server certificate".into()
    } else {
        format!("Chain certificate {}", index + 1)
    };
    let details = match x509_parser::parse_x509_certificate(der) {
        Ok((_, certificate)) => {
            let validity = certificate.validity();
            let warning = if now < validity.not_before {
                Some("Not yet valid")
            } else if now > validity.not_after {
                Some("Expired")
            } else {
                None
            };
            let names = if index == 0 {
                certificate
                    .subject_alternative_name()
                    .ok()
                    .flatten()
                    .map(|extension| {
                        extension
                            .value
                            .general_names
                            .iter()
                            .filter_map(|name| match name {
                                GeneralName::DNSName(name) => Some((*name).to_owned()),
                                GeneralName::IPAddress(address) => {
                                    ip_name(address).map(|ip| ip.to_string())
                                }
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .filter(|names| !names.is_empty())
            } else {
                None
            };
            column![
                row![
                    text(role).size(18),
                    space::horizontal(),
                    warning.map(|label| badge(label, false)),
                    super::tls::is_self_signed(&certificate).then(|| badge("Self-signed", false)),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
                field("Subject", common_name(certificate.subject())),
                field("Issuer", common_name(certificate.issuer())),
                field(
                    "Valid from",
                    validity.not_before.to_datetime().date().to_string()
                ),
                field(
                    "Expires",
                    validity.not_after.to_datetime().date().to_string()
                ),
                names.map(|names| field("Names", names)),
            ]
            .spacing(6)
        }
        Err(_) => column![text(role).size(18), badge("Unreadable certificate", false),].spacing(6),
    };
    container(details)
        .width(Length::Fill)
        .padding(12)
        .style(container::rounded_box)
        .into()
}

fn field(label: &'static str, value: String) -> Element<'static, Message> {
    row![
        text(label).width(88),
        text(value)
            .width(Length::Fill)
            .wrapping(text::Wrapping::WordOrGlyph),
    ]
    .spacing(8)
    .into()
}

fn common_name(name: &X509Name<'_>) -> String {
    name.iter_common_name()
        .find_map(|attribute| attribute.as_str().ok())
        .filter(|name| !name.is_empty())
        .map_or_else(|| name.to_string(), str::to_owned)
}

fn ip_name(address: &[u8]) -> Option<IpAddr> {
    if let Ok(bytes) = <[u8; 4]>::try_from(address) {
        Some(bytes.into())
    } else {
        <[u8; 16]>::try_from(address).ok().map(IpAddr::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_keeps_its_close_button_when_a_certificate_cannot_be_parsed() {
        let chain = [CertificateDer::from(vec![1, 2, 3])];
        let mut ui = iced_test::Simulator::with_size(
            iced::Settings::default(),
            (1150.0, 650.0),
            view(&chain),
        );
        assert!(ui.find("Unreadable certificate").is_ok());
        ui.click("Close").unwrap();
        assert!(
            ui.into_messages()
                .any(|message| matches!(message, Message::CloseCertificates))
        );
    }
}
