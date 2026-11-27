# Rahn-IT toolbox

This is my personal toolbox written in rust.

It provides a lot of helpers and shortcuts for my daily work and can help with network os OS diagnostics.

## ⚠️WARNING⚠️

> [!WARNING]
> **This repository is heavily vibe coded.**
>
> These are mostly internal tools. They are made public for your convinience and inspiration.
>
> These tools were mostly built because we need them. They are not as polished as a public app probably should be.
> Nevertheless, they might be useful to you, so I'm keeping this public.
>
> Feel free to check out the code if you're unsure

# tools

![Tool search](screenshots/search.png)

## Analyze Connection Problems

Enter a hostname or ip and an optional port and this tool will check everything from DNS to the ARP-Table and give you anything you need to diagnose a connection issue.

![Connection analysis showing encrypted DNS lookups, DNS overrides, and a refused TCP connection](screenshots/connection-analyzer-dns.png)

![Connection analysis showing an untrusted TLS issuer and an HTTP redirect ending in 403 Forbidden](screenshots/connection-analyzer-https.png)

## DNS Cache

Search and refresh cached DNS records, or flush the cache where supported.

![DNS Cache showing filtered A, AAAA, and CNAME records](screenshots/dns-cache.png)

## Mailbox scanner

This simple tool connects to an IMAP mailbox, downloads all mails as `.eml` files temporarily and lets either Avast or Windows Defender check them. Infected mails can be downloaded into a local quarantine folder and purged from the mail server.

![Mailbox scanner](screenshots/mailbox-scanner.png)

## quick install (windows only)

The quick install is basically the same as ninite or other quick install tools.
It just downloads the installers and runs them for you. It will still ask for admin rights if needed though.
This is just a small list of applications I need from time to time. PRs are welcome though.

![Quick Install with selected applications](screenshots/quick-install.png)

## Quick tools (Windows only)

Some simpler helpers for some configurations I commonly need

- Run AdwCleaner
- Clear Browser Default Extensions and Policies for Chrome, Firefox, and Edge
- Disable Hibernation
- Set Power Config
- Delete Old Temporary Files

## Encode / Decoder

The encoder and decoder supports the following formats:

- Eml & SMTP quoted-printable
- Base64
- Unicode codepoints

![Base64 encoder](screenshots/encoder-base64.png)

## Path Length Checker

This is a simple application to find paths which are over the windows path limit of 260 characters or close to it.

You can Scan a path and then export the found paths into a CSV file.

![grafik](screenshots/path-length-checker.png)

## Wake on LAN

Enter a MAC address to send a magic packet to wake up a device.
In case you don't know the MAC address it reads the ARP table in the hopes that the MAC is still cached.

![Wake on LAN](screenshots/wake-on-lan.png)

## Network Scan

A relatively simple network scan based on just calling `ping` and checking the ARP-Table.

Afterwards, Additional Info is collected for netbios and reverse dns name as well as ports.

Not as sophisticated as nmap, but enough for a rough overview.

![Network Scan](screenshots/network-scan.png)

## Device Scan

Type in the IP of a device to perform a simple scan on only that device instead of the whole network

## Simple NUT client

I integrated a very simple client which displays the raw numbers from a Network UPS Tools server for debugging.

![NUT client](screenshots/nut-client.png)

# Attribution

This project is licensed under the [MIT License](LICENSE).

Developed by [Rahn IT](https://it-rahn.de/).

<a href="https://github.com/iced-rs/iced">
  <img src="https://gist.githubusercontent.com/hecrj/ad7ecd38f6e47ff3688a38c79fd108f0/raw/74384875ecbad02ae2a926425e9bcafd0695bade/color.svg" width="130px">
</a>
