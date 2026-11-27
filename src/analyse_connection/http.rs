use std::{net::SocketAddr, time::Duration};

use iced::{
    Element, Task,
    widget::{column, text},
};
use reqwest::{Client, StatusCode, Url, Version, redirect};
use tokio::time::Instant;

use super::{check_view, tls};

const BODY_LIMIT: usize = 128 * 1024;
const MAX_REDIRECTS: usize = 5;
const HEADERS: &[(&str, &str)] = &[
    ("Server", "server"),
    ("Content-Type", "content-type"),
    ("Location", "location"),
    ("Via", "via"),
    ("X-Powered-By", "x-powered-by"),
    ("Cache-Control", "cache-control"),
    ("WWW-Authenticate", "www-authenticate"),
];

#[derive(Clone)]
pub struct Report {
    status: StatusCode,
    version: Version,
    title: Option<String>,
    headers: Vec<(&'static str, String)>,
    redirects: Vec<Redirect>,
    redirect_stop: Option<&'static str>,
}

#[derive(Clone)]
struct Redirect {
    status: StatusCode,
    from: Url,
    to: Url,
}

#[derive(Default)]
pub(super) enum State {
    #[default]
    Skipped,
    Checking,
    Complete(Result<Report, String>),
}

impl State {
    pub fn start(&mut self, host: &str, endpoint: SocketAddr, https: bool) -> Task<super::Message> {
        if !matches!(self, Self::Skipped) {
            return Task::none();
        }
        *self = Self::Checking;
        Task::perform(
            inspect(host.to_owned(), endpoint, https),
            super::Message::HttpFinished,
        )
    }

    pub fn is_running(&self) -> bool {
        matches!(self, Self::Checking)
    }

    pub fn view(&self) -> Option<Element<'_, super::Message>> {
        let status = match self {
            Self::Skipped => return None,
            Self::Checking => check_view::checking(),
            Self::Complete(Err(error)) => check_view::error_badge("HTTP request failed", error),
            Self::Complete(Ok(report)) => status_view(report.status),
        };
        let mut rows = vec![("Status", Some(status))];
        if let Self::Complete(Ok(report)) = self {
            rows.push((
                "HTTP version",
                Some(result_text(format!("{:?}", report.version))),
            ));
            rows.push((
                "Page title",
                Some(result_text(report.title.as_deref().unwrap_or("—"))),
            ));
            rows.extend(
                report
                    .headers
                    .iter()
                    .map(|(name, value)| (*name, Some(result_text(value)))),
            );
            if !report.redirects.is_empty() {
                let hops = report.redirects.iter().map(|hop| {
                    iced::widget::row![
                        status_view(hop.status),
                        result_text(format!("{} → {}", hop.from, hop.to)),
                    ]
                    .spacing(8)
                    .align_y(iced::Alignment::Center)
                    .into()
                });
                rows.push(("Redirect chain", Some(column(hops).spacing(6).into())));
            }
            rows.extend(
                report
                    .redirect_stop
                    .map(|reason| ("Redirect stopped", Some(check_view::badge(reason, false)))),
            );
        }
        check_view::table("HTTP", None, rows)
    }
}

fn status_view(status: StatusCode) -> Element<'static, super::Message> {
    let label = status.to_string();
    if status.is_redirection() {
        check_view::warning_badge(label)
    } else if status.is_informational() {
        result_text(label)
    } else {
        check_view::badge(label, status.is_success())
    }
}

fn result_text<'a>(value: impl text::IntoFragment<'a>) -> Element<'a, super::Message> {
    text(value).wrapping(text::Wrapping::WordOrGlyph).into()
}

async fn inspect(host: String, endpoint: SocketAddr, https: bool) -> Result<Report, String> {
    let name = tls::server_name(&host)?;
    let host = name.to_str();
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let scheme = if https { "https" } else { "http" };
    let url = Url::parse(&format!("{scheme}://{authority}:{}/", endpoint.port()))
        .map_err(|error| error.to_string())?;
    let url_host = url
        .host_str()
        .ok_or("Missing HTTP hostname")?
        .trim_matches(['[', ']']);
    if let Ok(ip) = url_host.parse::<std::net::IpAddr>()
        && ip != endpoint.ip()
    {
        return Err("HTTP URL does not match the analysed address".into());
    }
    let client = Client::builder()
        .no_proxy()
        .redirect(redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .resolve(url_host, SocketAddr::new(endpoint.ip(), 0))
        .build()
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut visited = vec![url.clone()];
    let mut redirects = Vec::new();
    let mut last_response = None;
    let mut url = url;
    let (mut response, redirect_stop) = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero()
            && let Some(previous) = last_response.take()
        {
            break (previous, Some("Redirect timed out"));
        }
        let response = match client.get(url.clone()).timeout(remaining).send().await {
            Ok(response) => response,
            Err(error) => match last_response.take() {
                Some(previous) if error.is_timeout() => {
                    break (previous, Some("Redirect timed out"));
                }
                Some(previous) => break (previous, Some("Redirect request failed")),
                None => return Err(error.to_string()),
            },
        };
        let status = response.status();
        if !matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
            break (response, None);
        }
        let Some(location) = response.headers().get("location") else {
            break (response, Some("Redirect missing Location"));
        };
        let Some(mut next) = location
            .to_str()
            .ok()
            .and_then(|location| url.join(location).ok())
        else {
            break (response, Some("Invalid redirect destination"));
        };
        next.set_fragment(None);
        redirects.push(Redirect {
            status,
            from: url.clone(),
            to: next.clone(),
        });
        let stop = redirect_stop_reason(&url, &next, &visited);
        if let Some(reason) = stop {
            break (response, Some(reason));
        }
        if redirects.len() > MAX_REDIRECTS {
            break (response, Some("Redirect limit reached"));
        }
        last_response = Some(response);
        visited.push(next.clone());
        url = next;
    };
    let status = response.status();
    let version = response.version();
    let headers: Vec<_> = HEADERS
        .iter()
        .filter_map(|&(label, name)| {
            let value = response.headers().get(name)?.to_str().ok()?;
            Some((label, value.chars().take(512).collect()))
        })
        .collect();
    let is_html = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| {
            let media_type = value.split(';').next().unwrap_or_default().trim();
            media_type.eq_ignore_ascii_case("text/html")
                || media_type.eq_ignore_ascii_case("application/xhtml+xml")
        });
    let mut title = None;
    if is_html {
        let mut body = Vec::new();
        while body.len() < BODY_LIMIT {
            let Ok(Some(chunk)) = response.chunk().await else {
                break;
            };
            body.extend_from_slice(&chunk[..chunk.len().min(BODY_LIMIT - body.len())]);
        }
        title = page_title(&String::from_utf8_lossy(&body));
    }
    Ok(Report {
        status,
        version,
        headers,
        title,
        redirects,
        redirect_stop,
    })
}

fn redirect_stop_reason(from: &Url, to: &Url, visited: &[Url]) -> Option<&'static str> {
    if !matches!(to.scheme(), "http" | "https") || to.host().is_none() {
        Some("Unsupported redirect destination")
    } else if !to.username().is_empty() || to.password().is_some() {
        Some("Redirect contains credentials")
    } else if from.host() != to.host() {
        Some("Redirect leaves the analysed hostname")
    } else if from.scheme() == "https" && to.scheme() == "http" {
        Some("HTTPS to HTTP downgrade")
    } else if visited.contains(to) {
        Some("Redirect loop")
    } else {
        None
    }
}

fn page_title(html: &str) -> Option<String> {
    let lowercase = html.to_ascii_lowercase();
    let mut position = 0;
    let raw_title = loop {
        let start = position + lowercase[position..].find('<')?;
        let tag = &lowercase[start..];
        if tag.starts_with("<!--") {
            position = start + 4 + tag[4..].find("-->")? + 3;
            continue;
        }
        let end = tag.find('>')?;
        let name = tag[1..end].split_ascii_whitespace().next();
        position = start + end + 1;
        if matches!(name, Some("title" | "script" | "style" | "textarea")) {
            let name = name?;
            let closing = format!("</{name}");
            let close = lowercase[position..]
                .match_indices(&closing)
                .find_map(|(index, _)| {
                    let next = lowercase.as_bytes().get(position + index + closing.len())?;
                    (next.is_ascii_whitespace() || *next == b'>').then_some(position + index)
                })?;
            if name == "title" {
                break &html[position..close];
            }
            position = close + lowercase[close..].find('>')? + 1;
        }
    };
    let mut decoded = String::new();
    let mut remainder = raw_title;
    while let Some((prefix, entity)) = remainder.split_once('&') {
        decoded.push_str(prefix);
        if let Some((value, suffix)) = entity.split_once(';')
            && value.len() <= 12
            && let Some(character) = title_entity(value)
        {
            decoded.push(character);
            remainder = suffix;
        } else {
            decoded.push('&');
            remainder = entity;
        }
    }
    decoded.push_str(remainder);
    let title = decoded
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(256)
        .collect::<String>();
    (!title.is_empty()).then_some(title)
}

fn title_entity(value: &str) -> Option<char> {
    match value {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => {
            let digits = value.strip_prefix('#')?;
            let code = if let Some(hex) = digits.strip_prefix(['x', 'X']) {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                digits.parse().ok()?
            };
            char::from_u32(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn reads_title_from_markup_and_ignores_comments_and_scripts() {
        let html = "<!-- <title>wrong</title> --><script>let title = '<title>wrong</title>';</script><TITLE lang=en> Café &amp; &#x1F310; </TITLE >";
        assert_eq!(page_title(html).as_deref(), Some("Café & 🌐"));
        assert_eq!(page_title("<title>unfinished"), None);
    }

    #[tokio::test]
    async fn follows_a_relative_redirect_and_keeps_the_host_header_and_chain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for (path, response) in [
                (
                    "/",
                    "HTTP/1.1 302 Found\r\nLocation: /next\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                ),
                (
                    "/next",
                    "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<title>Example</title>",
                ),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    assert!(request.len() < 2048);
                    request.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(request.starts_with(&format!("get {path} http/1.1\r\n")));
                assert!(request.contains(&format!("host: server.invalid:{}\r\n", endpoint.port())));
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        let report = inspect("server.invalid".into(), endpoint, false)
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(report.status, StatusCode::OK);
        assert_eq!(report.version, Version::HTTP_11);
        assert_eq!(report.title.as_deref(), Some("Example"));
        assert!(report.headers.contains(&("Server", "nginx".into())));
        assert_eq!(report.redirects.len(), 1);
        assert_eq!(report.redirects[0].status, 302);
        assert_eq!(report.redirects[0].from.path(), "/");
        assert_eq!(report.redirects[0].to.path(), "/next");
        assert_eq!(report.redirect_stop, None);
    }

    #[test]
    fn permits_same_host_upgrades_and_stops_cross_host_downgrades_and_loops() {
        let http = Url::parse("http://server.invalid:8080/").unwrap();
        let https = Url::parse("https://server.invalid/").unwrap();
        let other = Url::parse("https://other.invalid/").unwrap();
        assert_eq!(redirect_stop_reason(&http, &https, &[]), None);
        assert_eq!(
            redirect_stop_reason(&https, &http, &[]),
            Some("HTTPS to HTTP downgrade")
        );
        assert_eq!(
            redirect_stop_reason(&https, &other, &[]),
            Some("Redirect leaves the analysed hostname")
        );
        assert_eq!(
            redirect_stop_reason(&http, &http, std::slice::from_ref(&http)),
            Some("Redirect loop")
        );
    }
}
