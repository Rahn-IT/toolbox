use std::{net::Ipv4Addr, time::Duration};

pub(crate) fn adapters() -> ipconfig::error::Result<Vec<ipconfig::Adapter>> {
    ipconfig::get_adapters()
}

pub(crate) async fn default_adapter() -> Result<Option<ipconfig::Adapter>, String> {
    let path = crate::quick_tools::system::executable("route.exe")?;
    let mut command = tokio::process::Command::new(path);
    command
        .arg("print")
        .kill_on_drop(true)
        .creation_flags(0x0800_0000);
    let output = tokio::time::timeout(Duration::from_secs(3), command.output())
        .await
        .map_err(|_| "Reading the default route timed out.".to_owned())?
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "Could not read the default route ({})",
            output.status
        ));
    }
    let routes = String::from_utf8_lossy(&output.stdout);
    let (ipv4, ipv6) = default_routes(&routes);
    let active = adapters()
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|adapter| adapter.oper_status() == ipconfig::OperStatus::IfOperStatusUp);
    Ok(active
        .filter_map(|adapter| {
            if ipv4.is_some_and(|ip| adapter.ip_addresses().contains(&ip.into())) {
                Some((0, adapter))
            } else if ipv6 == Some(adapter.ipv6_if_index()) {
                Some((1, adapter))
            } else {
                None
            }
        })
        .min_by_key(|(priority, _)| *priority)
        .map(|(_, adapter)| adapter))
}

fn default_routes(output: &str) -> (Option<Ipv4Addr>, Option<u32>) {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for line in output.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        match fields.as_slice() {
            ["0.0.0.0", "0.0.0.0", gateway @ .., address, metric] if !gateway.is_empty() => {
                if let (Ok(address), Ok(metric)) = (address.parse(), metric.parse::<u32>()) {
                    ipv4.push((metric, address));
                }
            }
            [index, metric, "::/0", gateway @ ..] if !gateway.is_empty() => {
                if let (Ok(index), Ok(metric)) = (index.parse(), metric.parse::<u32>()) {
                    ipv6.push((metric, index));
                }
            }
            _ => {}
        }
    }
    (
        ipv4.into_iter()
            .min_by_key(|(metric, _)| *metric)
            .map(|(_, address)| address),
        ipv6.into_iter()
            .min_by_key(|(metric, _)| *metric)
            .map(|(_, index)| index),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_the_lowest_metric_default_route_for_each_family() {
        let routes = "
            0.0.0.0  0.0.0.0  192.0.2.1  192.0.2.10    30
            0.0.0.0  0.0.0.0  198.51.100.1  198.51.100.7    20
            0.0.0.0  0.0.0.0  203.0.113.1    1
            7  30  ::/0    fe80::1
            8  20  ::/0    fe80::2
            9   1  fe80::/64    On-link
        ";
        assert_eq!(
            default_routes(routes),
            (Some(Ipv4Addr::new(198, 51, 100, 7)), Some(8))
        );
    }
}
