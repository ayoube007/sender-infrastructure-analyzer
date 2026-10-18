# Sender Infrastructure Analyzer

An open-source PHP tool that checks the health of an email sending setup in one place.

Enter a domain or sending IP and get a full report on the DNS and reputation signals that decide whether your mail reaches the inbox.

## Features

- **PTR** (reverse DNS) lookup and forward-confirmation
- **MX** record check
- **SPF** record parsing and validation
- **DKIM** selector probing
- **DMARC** policy check
- **DNSBL** blacklist lookups against major blocklists (real DNS queries)
- **IP geolocation**
- **Reputation score** summarizing the results

## Why

Most deliverability tools check one thing at a time or sit behind paid plans. This project puts the essential checks in a single free, self-hostable tool.

## Requirements

- PHP 8.0 or newer
- Outbound DNS access (port 53)

## Installation

```bash
git clone https://github.com/ayoube007/sender-infrastructure-analyzer.git
cd sender-infrastructure-analyzer
php -S localhost:8000
```

Then open http://localhost:8000 in your browser.

## Roadmap

- [ ] BIMI check
- [ ] MTA-STS and TLS-RPT checks
- [ ] Exportable reports (JSON/CSV)
- [ ] Automated tests

## Contributing

Issues and pull requests are welcome.

## License

MIT. See [LICENSE](LICENSE).
