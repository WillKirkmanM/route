use clap::Parser;
use std::cmp::Reverse;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    version,
    about = "Explain IPv4 route selection from a saved Windows routing table"
)]
struct Args {
    #[arg(
        value_name = "INPUT",
        help = "Report file; omit or use - for standard input"
    )]
    input: Option<PathBuf>,

    #[arg(
        long,
        value_name = "IPV4",
        help = "Destination to look up; may be repeated"
    )]
    destination: Vec<Ipv4Addr>,

    #[arg(long, help = "Write deterministic JSON")]
    json: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct Route {
    network: Ipv4Addr,
    prefix: u32,
    gateway: Option<Ipv4Addr>,
    interface: Ipv4Addr,
    metric: u64,
}

impl Route {
    fn matches(&self, destination: Ipv4Addr) -> bool {
        u32::from(destination) & prefix_mask(self.prefix) == u32::from(self.network)
    }

    fn json(&self) -> String {
        let next_hop = self
            .gateway
            .map_or_else(|| "null".to_owned(), |gateway| format!("\"{gateway}\""));
        format!(
            "{{\"network\":\"{}/{}\",\"next_hop\":{},\"direct_delivery\":{},\"interface\":\"{}\",\"metric\":{}}}",
            self.network,
            self.prefix,
            next_hop,
            self.gateway.is_none(),
            self.interface,
            self.metric
        )
    }
}

impl fmt::Display for Route {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{} ", self.network, self.prefix)?;
        match self.gateway {
            Some(gateway) => write!(formatter, "via {gateway}")?,
            None => write!(formatter, "direct delivery")?,
        }
        write!(
            formatter,
            " interface {} metric {}",
            self.interface, self.metric
        )
    }
}

fn prefix_mask(prefix: u32) -> u32 {
    u32::MAX.checked_shl(32 - prefix).unwrap_or(0)
}

fn parse_address(value: &str, field: &str, line: usize) -> Result<Ipv4Addr, String> {
    value
        .parse()
        .map_err(|_| format!("line {line}: invalid {field} IPv4 address '{value}'"))
}

fn parse_route(line: &str, number: usize) -> Result<Route, String> {
    let fields: Vec<_> = line.split_whitespace().collect();
    let [destination, netmask, gateway, interface, metric] = fields.as_slice() else {
        return Err(format!(
            "line {number}: expected 5 route columns, found {}",
            fields.len()
        ));
    };
    let destination = parse_address(destination, "network destination", number)?;
    let mask = u32::from(parse_address(netmask, "netmask", number)?);
    let prefix = mask.leading_ones();
    if mask != prefix_mask(prefix) {
        return Err(format!("line {number}: non-contiguous netmask '{netmask}'"));
    }
    let gateway = if *gateway == "On-link" {
        None
    } else {
        Some(parse_address(gateway, "gateway", number)?)
    };
    let interface = parse_address(interface, "interface", number)?;
    let metric = metric
        .chars()
        .all(|character| character.is_ascii_digit())
        .then(|| metric.parse::<u64>().ok())
        .flatten()
        .ok_or_else(|| {
            format!(
                "line {number}: invalid metric '{metric}': expected a non-negative 64-bit integer"
            )
        })?;
    Ok(Route {
        network: Ipv4Addr::from(u32::from(destination) & mask),
        prefix,
        gateway,
        interface,
        metric,
    })
}

fn parse_routes(input: impl BufRead) -> Result<Vec<Route>, String> {
    let mut routes = Vec::new();
    let mut active_line = None;
    let mut header_seen = false;
    let mut empty = false;
    for (index, line) in input.lines().enumerate() {
        let number = index + 1;
        let line = line.map_err(|error| format!("line {number}: could not read input: {error}"))?;
        let line = line.trim_start_matches('\u{feff}').trim();
        if active_line.is_none() {
            if line == "Active Routes:" {
                active_line = Some(number);
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if line.chars().all(|character| character == '=') || line == "Persistent Routes:" {
            break;
        }
        if line == "None" && !empty && routes.is_empty() {
            header_seen = true;
            empty = true;
            continue;
        }
        if empty {
            return Err(format!(
                "line {number}: unexpected content after an empty Active Routes section"
            ));
        }
        if !header_seen {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields
                != [
                    "Network",
                    "Destination",
                    "Netmask",
                    "Gateway",
                    "Interface",
                    "Metric",
                ]
            {
                return Err(format!(
                    "line {number}: expected the Active Routes column heading"
                ));
            }
            header_seen = true;
            continue;
        }
        routes.push(parse_route(line, number)?);
    }
    let active_line = active_line.ok_or_else(|| "no Active Routes section found".to_owned())?;
    if !header_seen {
        return Err(format!(
            "line {active_line}: Active Routes section is missing its column heading"
        ));
    }
    Ok(routes)
}

fn select_routes(routes: &[Route], destination: Ipv4Addr) -> Vec<&Route> {
    let Some(best) = routes
        .iter()
        .filter(|route| route.matches(destination))
        .max_by_key(|route| (route.prefix, Reverse(route.metric)))
    else {
        return Vec::new();
    };
    routes
        .iter()
        .filter(|route| {
            route.prefix == best.prefix && route.metric == best.metric && route.matches(destination)
        })
        .collect()
}

fn render(routes: &[Route], destinations: &[Ipv4Addr], json: bool) -> (String, bool) {
    if destinations.is_empty() {
        let output = if json {
            format!(
                "{{\"routes\":[{}]}}\n",
                routes.iter().map(Route::json).collect::<Vec<_>>().join(",")
            )
        } else if routes.is_empty() {
            "No active routes\n".to_owned()
        } else {
            routes.iter().map(|route| format!("{route}\n")).collect()
        };
        return (output, false);
    }
    let mut unmatched = false;
    let mut results = Vec::new();
    for &destination in destinations {
        let selected = select_routes(routes, destination);
        let matched = !selected.is_empty();
        unmatched |= !matched;
        let result = if json {
            format!(
                "{{\"destination\":\"{destination}\",\"matched\":{matched},\"routes\":[{}]}}",
                selected
                    .iter()
                    .map(|route| route.json())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else if matched {
            format!(
                "{destination}:\n{}",
                selected
                    .iter()
                    .map(|route| format!("  {route}\n"))
                    .collect::<String>()
            )
        } else {
            format!("{destination}: no matching route\n")
        };
        results.push(result);
    }
    let output = if json {
        format!("{{\"destinations\":[{}]}}\n", results.join(","))
    } else {
        results.concat()
    };
    (output, unmatched)
}

fn run(args: Args) -> Result<ExitCode, String> {
    let routes = match args.input {
        Some(path) if path.as_os_str() != "-" => {
            let file = File::open(&path)
                .map_err(|error| format!("could not open '{}': {error}", path.display()))?;
            parse_routes(BufReader::new(file))?
        }
        _ => parse_routes(io::stdin().lock())?,
    };
    let (output, unmatched) = render(&routes, &args.destination, args.json);
    io::stdout()
        .lock()
        .write_all(output.as_bytes())
        .map_err(|error| format!("could not write output: {error}"))?;
    Ok(if unmatched {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(rows: &str) -> String {
        format!(
            "Interface List\nignored adapter details\nIPv4 Route Table\nActive Routes:\nNetwork Destination Netmask Gateway Interface Metric\n{rows}===========================================================================\nPersistent Routes:\ninvalid persistent data\n"
        )
    }

    #[test]
    fn normalises_networks_and_ignores_other_sections() {
        let routes =
            parse_routes(table("192.0.2.123 255.255.255.0 On-link 192.0.2.10 0\n").as_bytes())
                .unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].network, Ipv4Addr::new(192, 0, 2, 0));
        assert_eq!(routes[0].prefix, 24);
        assert_eq!(routes[0].gateway, None);
        assert_eq!(routes[0].metric, 0);
        assert_eq!(
            routes[0].to_string(),
            "192.0.2.0/24 direct delivery interface 192.0.2.10 metric 0"
        );
    }

    #[test]
    fn prioritises_prefix_then_metric_and_retains_ties() {
        let routes = parse_routes(
            table(concat!(
                "0.0.0.0 0.0.0.0 192.0.2.1 192.0.2.10 0\n",
                "203.0.113.0 255.255.255.0 192.0.2.254 192.0.2.10 40\n",
                "203.0.113.0 255.255.255.0 192.0.2.253 192.0.2.10 60\n",
                "203.0.113.0 255.255.255.0 192.0.2.252 192.0.2.10 40\n"
            ))
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            select_routes(&routes, Ipv4Addr::new(203, 0, 113, 42)),
            vec![&routes[1], &routes[3]]
        );
        assert_eq!(
            select_routes(&routes, Ipv4Addr::new(198, 51, 100, 42)),
            vec![&routes[0]]
        );
    }

    #[test]
    fn supports_host_routes_and_prefix_boundaries() {
        let routes = parse_routes(
            table(concat!(
                "203.0.113.42 255.255.255.255 On-link 192.0.2.10 900\n",
                "203.0.113.127 255.255.255.128 On-link 192.0.2.10 0\n"
            ))
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            select_routes(&routes, Ipv4Addr::new(203, 0, 113, 42)),
            vec![&routes[0]]
        );
        assert_eq!(
            select_routes(&routes, Ipv4Addr::new(203, 0, 113, 127)),
            vec![&routes[1]]
        );
        assert!(select_routes(&routes, Ipv4Addr::new(203, 0, 113, 128)).is_empty());
    }

    #[test]
    fn rejects_non_contiguous_masks_with_line_numbers() {
        let error =
            parse_routes(table("203.0.113.0 255.0.255.0 192.0.2.254 192.0.2.10 40\n").as_bytes())
                .unwrap_err();
        assert_eq!(error, "line 6: non-contiguous netmask '255.0.255.0'");
    }

    #[test]
    fn rejects_malformed_route_fields() {
        for row in [
            "203.0.113.0 255.255.255.0 192.0.2.1 192.0.2.10",
            "203.0.113.0 255.255.255.0 192.0.2.1 192.0.2.10 5 extra",
            "999.0.113.0 255.255.255.0 192.0.2.1 192.0.2.10 5",
            "203.0.113.0 invalid 192.0.2.1 192.0.2.10 5",
            "203.0.113.0 255.255.255.0 invalid 192.0.2.10 5",
            "203.0.113.0 255.255.255.0 On-link invalid 5",
            "203.0.113.0 255.255.255.0 On-link 192.0.2.10 -1",
            "203.0.113.0 255.255.255.0 On-link 192.0.2.10 +1",
            "203.0.113.0 255.255.255.0 On-link 192.0.2.10 1.5",
            "203.0.113.0 255.255.255.0 On-link 192.0.2.10 18446744073709551616",
        ] {
            let input = table(&format!("{row}\n"));
            let error = parse_routes(input.as_bytes()).unwrap_err();
            assert!(error.starts_with("line 6:"), "{error}");
        }
    }

    #[test]
    fn requires_an_active_section_and_heading() {
        assert_eq!(
            parse_routes("Persistent Routes:\nNone\n".as_bytes()).unwrap_err(),
            "no Active Routes section found"
        );
        assert_eq!(
            parse_routes("Active Routes:\n".as_bytes()).unwrap_err(),
            "line 1: Active Routes section is missing its column heading"
        );
        assert_eq!(
            parse_routes("Active Routes:\ninvalid heading\n".as_bytes()).unwrap_err(),
            "line 2: expected the Active Routes column heading"
        );
    }

    #[test]
    fn accepts_empty_tables_crlf_bom_and_end_of_file() {
        assert!(parse_routes(table("").as_bytes()).unwrap().is_empty());
        assert!(
            parse_routes("\u{feff}Active Routes:\r\n  None\r\n".as_bytes())
                .unwrap()
                .is_empty()
        );
        let routes = parse_routes(
            "Active Routes:\r\nNetwork Destination Netmask Gateway Interface Metric\r\n0.0.0.0 0.0.0.0 192.0.2.1 192.0.2.10 5"
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, 0);
    }

    #[test]
    fn renders_deterministic_json_and_reports_unmatched_destinations() {
        let routes =
            parse_routes(table("192.0.2.0 255.255.255.0 On-link 192.0.2.10 25\n").as_bytes())
                .unwrap();
        let route_json = "{\"network\":\"192.0.2.0/24\",\"next_hop\":null,\"direct_delivery\":true,\"interface\":\"192.0.2.10\",\"metric\":25}";
        assert_eq!(
            render(&routes, &[], true),
            (format!("{{\"routes\":[{route_json}]}}\n"), false)
        );
        let destinations = [Ipv4Addr::new(192, 0, 2, 42), Ipv4Addr::new(203, 0, 113, 42)];
        assert_eq!(
            render(&routes, &destinations, true),
            (
                format!(
                    "{{\"destinations\":[{{\"destination\":\"192.0.2.42\",\"matched\":true,\"routes\":[{route_json}]}},{{\"destination\":\"203.0.113.42\",\"matched\":false,\"routes\":[]}}]}}\n"
                ),
                true
            )
        );
        assert_eq!(
            render(&routes, &[destinations[1]], false),
            ("203.0.113.42: no matching route\n".to_owned(), true)
        );
    }

    #[test]
    fn parses_repeatable_destinations_and_standard_input_arguments() {
        let args = Args::try_parse_from([
            "route",
            "-",
            "--destination",
            "192.0.2.42",
            "--destination",
            "203.0.113.42",
            "--json",
        ])
        .unwrap();
        assert_eq!(args.input, Some(PathBuf::from("-")));
        assert_eq!(args.destination.len(), 2);
        assert!(args.json);
        assert!(Args::try_parse_from(["route", "--destination", "::1"]).is_err());
        assert!(Args::try_parse_from(["route", "--destination", "999.0.0.1"]).is_err());
    }
}
