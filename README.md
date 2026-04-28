# LNK Tool v4.0 - Advanced Red Team Suite

Professional forensic and LNK generation utility for Red Team operations.

## Directory Structure

- `bin/`: Compiled Windows binaries (run via Wine on Linux).
- `core/`: C++ source code for the generation engine + Rust modules.
- `server/`: Rust-based web server (Actix-web) + vanilla frontend.
  - `src/main.rs`: Backend API (replaces Node.js/Express).
  - `static/`: HTML/CSS/JS frontend (replaces React/Vite).
- `artifacts/`: Default output directory for generated LNK files.

## Quick Start

1. **Compilation (C++ Core)**:
   `x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -o bin/lnk_tool.exe core/lnk_tool_unified_v4.cpp -lole32 -lshell32 -luser32 -ladvapi32 -liphlpapi -luuid`

2. **Build Server**:
   `cd server && cargo build`

3. **Run Interface**:
   `cd server && cargo run`

4. **Access**:
   Open `http://localhost:3001` in your browser.

## Tech Stack

| Component | Technology |
|---|---|
| Backend API | **Rust** (Actix-web 4) |
| Frontend | **Vanilla HTML/CSS/JS** |
| LNK Engine | **C++17** (cross-compiled for Windows, runs via Wine) |
| Analysis | **Rust** (BenX86-Forensic emulator) |

## Features

- **7 Generation Techniques**: From simple property spoofing to LOLBin chaining and file smuggling.
- **Forensic Verification**: Analyze existing LNK files for discrepancies.
- **OPSEC Oriented**: Supports anti-sandbox delays and stealthy execution.
- **Full Rust Stack**: Zero Node.js dependencies — single binary server.

---
© 2026 Red Team Suite
