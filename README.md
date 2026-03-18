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

## quick install (windows only)

The quick install is basically the same as ninite or other quick install tools.
It just downloads the installers and runs them for you. It will still ask for admin rights if needed though.
This is just a small list of applications I need from time to time. PRs are welcome though.

<img width="804" height="724" alt="quick_install" src="https://github.com/user-attachments/assets/bfb833c1-49f7-4a61-8fbc-68a6aa5eb05e" />

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

## Simple NUT client

I integrated a very simple client which displays the raw numbers from a Network UPS Tools server for debugging.

# Attribution

This project is licensed under the [MIT License](LICENSE).

Developed by [Rahn IT](https://it-rahn.de/).

<a href="https://github.com/iced-rs/iced">
  <img src="https://gist.githubusercontent.com/hecrj/ad7ecd38f6e47ff3688a38c79fd108f0/raw/74384875ecbad02ae2a926425e9bcafd0695bade/color.svg" width="130px">
</a>
