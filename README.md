# Rahn-IT toolbox

This is a small collection of useful tools as a simple to download and run executable written in Rust.

## ⚠️WARNING⚠️

> [!WARNING]
> **This repository is partially vibe coded.**
>
> While I built most of the code myself, I used an agent to build the more boring parts. It does still struggle a bit with iced, so I do still need to do a few refactors here and there.
>
> It's a very simple app and we use it ourselves, but I still feel like it should be openly disclosed,
> as it will always influence code quality.
>
> Feel free to check out the code if you're unsure

# tools

## Mailbox scanner

This simple tool connects to an IMAP mailbox, downloads all mails as `.eml` files temporarily and lets either Avast or Windows Defender check them. Infected mails can be downloaded into a local quarantine folder and purged from the mail server.

## quick install (windows only)

The quick install is basically the same as ninite or other quick install tools.
It just downloads the installers and runs them for you. It will still ask for admin rights if needed though.
This is just a small list of applications I need from time to time. PRs are welcome though.

<img width="804" height="724" alt="quick_install" src="https://github.com/user-attachments/assets/bfb833c1-49f7-4a61-8fbc-68a6aa5eb05e" />

## Quick tools (Windows only)

Search lists each maintenance tool separately. Selecting one starts it right away and opens a tab that shows progress and the result.

On Windows, Toolbox requests administrator access at startup. If the request is canceled or fails, Toolbox still opens and marks tools that require administrator access as unavailable.

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

## Path Length Checker

This is a simple application to find paths which are over the windows path limit of 260 characters or close to it.

You can Scan a path and then export the found paths into a CSV file.

### Screenshots

![grafik](https://github.com/user-attachments/assets/468261dd-6224-419b-95f0-b94cdfb53894)

### Usage

- [Download the latest version](https://github.com/Rahn-IT/path-length-checker/releases/latest/download/path-length-checker.exe)
- Open the program and select the folder you'd like to scan
- Optionally change the limit from the default of 240 (windows causes problems once over 260)
- Click "Start Scan"
- Wait for the scan to finish
- Click on "Export CSV" and select a location to save your report

## Wake on LAN

Open Wake on LAN from Search, enter the device's MAC address, and select **Wake** to send a magic packet on the local network.

On Windows and Linux, select an entry from the local ARP cache to fill in its MAC address. **Refresh** rereads the cache.

## Network Scan

On Windows and Linux, open Network Scan from Search and select an IPv4 interface to start discovery. Toolbox sends ping requests and reads the interface's ARP cache, so devices can appear even without a ping reply. Select a row for its addresses and available NetBIOS names, or use **Rescan** to repeat discovery. Linux uses the installed `ip` and `ping` utilities and skips NetBIOS if Samba's `nmblookup` is absent.

## Simple NUT client

I integrated a very simple client which displays the raw numbers from a Network UPS Tools server for debugging.

# Attribution

This project is licensed under the [MIT License](LICENSE).

Developed by [Rahn IT](https://it-rahn.de/).

<a href="https://github.com/iced-rs/iced">
  <img src="https://gist.githubusercontent.com/hecrj/ad7ecd38f6e47ff3688a38c79fd108f0/raw/74384875ecbad02ae2a926425e9bcafd0695bade/color.svg" width="130px">
</a>
