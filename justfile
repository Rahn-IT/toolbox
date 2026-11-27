set windows-shell := ["cmd.exe", "/C"]

# Regenerate README images in screenshots/ for screens available on this platform.
screenshots:
    cargo test --locked tab_manager::tests::screenshots::generate_readme_screenshots -- --ignored --exact --nocapture
