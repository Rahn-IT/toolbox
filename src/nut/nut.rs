use std::collections::HashMap;
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// High-level view of a UPS' most common values.
///
/// All fields are `Option<String>` because not every UPS exposes everything.
#[derive(Debug, Clone)]
pub struct UpsInfo {
    pub ups_name: String,

    // Common UPS fields
    pub status: Option<String>,       // ups.status
    pub model: Option<String>,        // ups.model
    pub manufacturer: Option<String>, // ups.mfr
    pub serial: Option<String>,       // ups.serial
    pub ups_type: Option<String>,     // ups.type

    // Load / power
    pub load_percent: Option<String>,    // ups.load
    pub realpower_watts: Option<String>, // ups.realpower

    // Battery
    pub battery_charge_percent: Option<String>, // battery.charge
    pub battery_runtime_seconds: Option<String>, // battery.runtime
    pub battery_voltage: Option<String>,        // battery.voltage

    // Input / output electrical info
    pub input_voltage: Option<String>,       // input.voltage
    pub output_voltage: Option<String>,      // output.voltage
    pub input_frequency_hz: Option<String>,  // input.frequency
    pub output_frequency_hz: Option<String>, // output.frequency

    /// Any additional variables go here, by NUT variable name.
    /// e.g. "ambient.temperature", "ups.delay.shutdown", ...
    pub extra: Vec<(String, String)>,
}

impl UpsInfo {
    fn from_var_map(ups_name: &str, mut vars: HashMap<String, String>) -> Self {
        // Helper to pull a key out of the map and return it
        let mut take = |key: &str| vars.remove(key);

        let status = take("ups.status");
        let model = take("ups.model");
        let manufacturer = take("ups.mfr");
        let serial = take("ups.serial");
        let ups_type = take("ups.type");

        let load_percent = take("ups.load");
        let realpower_watts = take("ups.realpower");

        let battery_charge_percent = take("battery.charge");
        let battery_runtime_seconds = take("battery.runtime");
        let battery_voltage = take("battery.voltage");

        let input_voltage = take("input.voltage");
        let output_voltage = take("output.voltage");
        let input_frequency_hz = take("input.frequency");
        let output_frequency_hz = take("output.frequency");

        let mut extra: Vec<(String, String)> = vars.into_iter().collect();
        extra.sort();

        UpsInfo {
            ups_name: ups_name.to_string(),
            status,
            model,
            manufacturer,
            serial,
            ups_type,
            load_percent,
            realpower_watts,
            battery_charge_percent,
            battery_runtime_seconds,
            battery_voltage,
            input_voltage,
            output_voltage,
            input_frequency_hz,
            output_frequency_hz,
            // whatever is left in `vars` is "extra"
            extra,
        }
    }
}

#[derive(Debug)]
pub struct NutClient {
    username: String,
    password: String,
    stream: BufReader<TcpStream>,
}

impl NutClient {
    /// Connect to a NUT upsd instance and optionally authenticate.
    ///
    /// If `username` is empty, no USERNAME/PASSWORD commands are sent.
    pub async fn connect(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> io::Result<Self> {
        let host_str = host.into();
        let username = username.into();
        let password = password.into();

        let addr = format!("{}:{}", &host_str, port);
        let stream = TcpStream::connect(addr).await?;

        let mut client = NutClient {
            username,
            password,
            stream: BufReader::new(stream),
        };

        if !client.username.is_empty() {
            client.authenticate().await?;
        }

        Ok(client)
    }

    /// List all UPSes known to the server.
    ///
    /// Returns Vec<(ups_name, description)>
    pub async fn list_ups(&mut self) -> io::Result<Vec<(String, String)>> {
        self.send_command("LIST UPS").await?;

        let first = self.read_line().await?;
        if !first.starts_with("BEGIN LIST UPS") {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unexpected response: {}", first),
            ));
        }

        let mut result = Vec::new();

        loop {
            let line = self.read_line().await?;
            if line.starts_with("END LIST UPS") {
                break;
            }

            // Expected: UPS <upsname> "<description>"
            if line.starts_with("UPS ") {
                let mut parts = line.splitn(3, ' ');
                let _ups = parts.next(); // "UPS"
                let name = parts
                    .next()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Missing UPS name"))?;
                let desc_raw = parts
                    .next()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Missing UPS desc"))?;
                let desc = strip_quotes(desc_raw);
                result.push((name.to_string(), desc));
            }
        }

        Ok(result)
    }

    /// High-level helper: fetch all variables for a UPS and map them into `UpsInfo`.
    pub async fn get_ups_info(&mut self, ups_name: &str) -> io::Result<UpsInfo> {
        let vars = self.list_vars_raw(ups_name).await?;
        Ok(UpsInfo::from_var_map(ups_name, vars))
    }

    /// Optional: gracefully log out.
    pub async fn logout(&mut self) -> io::Result<()> {
        self.send_command("LOGOUT").await?;
        let _ = self.read_line().await?;
        Ok(())
    }

    // ---------- internal helpers ----------

    /// Send USERNAME / PASSWORD to the server.
    async fn authenticate(&mut self) -> io::Result<()> {
        self.send_command(&format!("USERNAME {}", self.username))
            .await?;
        self.expect_ok().await?;

        if !self.password.is_empty() {
            self.send_command(&format!("PASSWORD {}", self.password))
                .await?;
            self.expect_ok().await?;
        }

        Ok(())
    }

    /// Low-level: LIST VAR <upsname>, returned as a map from NUT var name -> value string.
    pub async fn list_vars_raw(&mut self, ups_name: &str) -> io::Result<HashMap<String, String>> {
        self.send_command(&format!("LIST VAR {}", ups_name)).await?;

        let first = self.read_line().await?;
        if !first.starts_with("BEGIN LIST VAR") {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unexpected response: {}", first),
            ));
        }

        let mut result = HashMap::new();

        loop {
            let line = self.read_line().await?;
            if line.starts_with("END LIST VAR") {
                break;
            }

            // Expected: VAR <upsname> <varname> "<value>"
            if line.starts_with("VAR ") {
                let mut parts = line.splitn(4, ' ');
                let _var = parts.next(); // "VAR"
                let ups = parts
                    .next()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Missing UPS name"))?;
                if ups != ups_name {
                    continue;
                }

                let var_name = parts
                    .next()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Missing var name"))?;
                let value_raw = parts
                    .next()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Missing var value"))?;
                let value = strip_quotes(value_raw);

                result.insert(var_name.to_string(), value);
            }
        }

        Ok(result)
    }

    async fn send_command(&mut self, cmd: &str) -> io::Result<()> {
        let stream = self.stream.get_mut();
        stream.write_all(cmd.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await
    }

    async fn read_line(&mut self) -> io::Result<String> {
        let mut line = String::new();
        let bytes = self.stream.read_line(&mut line).await?;
        if bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Connection closed by server",
            ));
        }

        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }

        Ok(line)
    }

    async fn expect_ok(&mut self) -> io::Result<()> {
        let line = self.read_line().await?;
        if line.starts_with("OK") {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Expected OK, got: {}", line),
            ))
        }
    }
}

/// Strip leading and trailing quotes and unescape \" and \\ inside.
fn strip_quotes(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('\"') && s.ends_with('\"') {
        let inner = &s[1..s.len() - 1];
        inner.replace("\\\"", "\"").replace("\\\\", "\\")
    } else {
        s.to_string()
    }
}
