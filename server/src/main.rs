//! LNK Tool v4.0 — Actix-web Backend Server
//!
//! Replaces the Node.js/Express backend. Serves the vanilla HTML/CSS/JS
//! frontend and exposes the same REST API endpoints for LNK generation,
//! verification, file listing, and download.

use actix_files as afs;
use actix_multipart::Multipart;
use actix_web::{web, App, HttpServer, HttpResponse, HttpRequest};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

// ─── Configuration ───

const BIND_ADDR: &str = "0.0.0.0";
const PORT: u16 = 3001;

/// Resolve project-relative paths from the server binary location.
fn project_root() -> PathBuf {
    // server/ lives one level below the project root
    let exe_dir = std::env::current_exe()
        .unwrap_or_default()
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();

    // During development with `cargo run`, CWD is typically `server/`
    // so we go one level up to reach the project root.
    let cwd = std::env::current_dir().unwrap_or_default();
    if cwd.ends_with("server") {
        cwd.parent().unwrap_or(&cwd).to_path_buf()
    } else if exe_dir.ends_with("debug") || exe_dir.ends_with("release") {
        // target/debug or target/release → go up to server/, then up to project root
        cwd.clone()
    } else {
        cwd
    }
}

fn artifacts_dir() -> PathBuf {
    project_root().join("artifacts")
}

fn bin_dir() -> PathBuf {
    project_root().join("bin")
}

fn uploads_dir() -> PathBuf {
    let p = project_root().join("server").join("uploads");
    std::fs::create_dir_all(&p).ok();
    p
}

fn static_dir() -> PathBuf {
    // When run from `server/`, statics are at `server/static/`
    let cwd = std::env::current_dir().unwrap_or_default();
    if cwd.ends_with("server") {
        cwd.join("static")
    } else {
        cwd.join("server").join("static")
    }
}

// ─── Data Structures ───

#[derive(Deserialize)]
struct GenerateRequest {
    technique: String,
    target: String,
    fake: String,
    #[serde(default)]
    args: String,
    out: String,
    #[serde(default)]
    delay: u32,
    #[serde(default)]
    url: String,
    #[serde(default)]
    obfuscation: bool,
}

#[derive(Serialize)]
struct GenerateResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crc32: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

#[derive(Serialize)]
struct FileEntry {
    name: String,
    size: u64,
    mtime: String,
}

#[derive(Serialize)]
struct FilesResponse {
    success: bool,
    files: Vec<FileEntry>,
}

#[derive(Serialize)]
struct VerifyResponse {
    success: bool,
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ─── Route: GET / — Serve index.html ───

async fn index_page() -> HttpResponse {
    let path = static_dir().join("index.html");
    match std::fs::read_to_string(&path) {
        Ok(html) => HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html),
        Err(e) => {
            eprintln!("[!] Failed to read index.html from {:?}: {}", path, e);
            HttpResponse::InternalServerError().body("Failed to load frontend")
        }
    }
}

// ─── Route: GET /api/files — List generated .lnk files ───

async fn api_list_files() -> HttpResponse {
    let dir = artifacts_dir();
    let mut files: Vec<FileEntry> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".lnk") {
                if let Ok(meta) = entry.metadata() {
                    let mtime = meta.modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs().to_string())
                        .unwrap_or_default();
                    files.push(FileEntry {
                        name,
                        size: meta.len(),
                        mtime,
                    });
                }
            }
        }
    }

    // Sort newest first
    files.sort_by(|a, b| b.mtime.cmp(&a.mtime));

    HttpResponse::Ok().json(FilesResponse { success: true, files })
}

// ─── Route: GET /api/download/{filename} — Download a .lnk file ───

async fn api_download(req: HttpRequest) -> HttpResponse {
    let filename = req.match_info().get("filename").unwrap_or("");

    // Security: only allow .lnk files, no path traversal
    if !filename.ends_with(".lnk") || filename.contains("..") || filename.contains('/') {
        return HttpResponse::NotFound().json(serde_json::json!({
            "success": false,
            "error": "File not found"
        }));
    }

    let path = artifacts_dir().join(filename);
    if path.exists() {
        match std::fs::read(&path) {
            Ok(data) => HttpResponse::Ok()
                .content_type("application/octet-stream")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .body(data),
            Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": "Failed to read file"
            })),
        }
    } else {
        HttpResponse::NotFound().json(serde_json::json!({
            "success": false,
            "error": "File not found"
        }))
    }
}

// ─── Route: POST /api/verify — Upload and verify a .lnk file ───

async fn api_verify(mut payload: Multipart) -> HttpResponse {
    let uploads = uploads_dir();
    let mut file_path: Option<PathBuf> = None;

    // Extract uploaded file
    while let Some(Ok(mut field)) = payload.next().await {
        let original_name = field.content_disposition()
            .and_then(|cd| cd.get_filename().map(|s| s.to_string()))
            .unwrap_or_else(|| "upload.lnk".to_string());

        let unique_name = format!("{}_{}", Uuid::new_v4(), original_name);
        let dest = uploads.join(&unique_name);

        let mut data = Vec::new();
        while let Some(Ok(chunk)) = field.next().await {
            data.extend_from_slice(&chunk);
        }

        if let Err(e) = std::fs::write(&dest, &data) {
            eprintln!("[!] Failed to write uploaded file: {}", e);
            return HttpResponse::InternalServerError().json(VerifyResponse {
                success: false,
                verified: false,
                output: None,
                details: Some(format!("Write error: {}", e)),
                error: Some("Failed to save uploaded file".to_string()),
            });
        }

        file_path = Some(dest);
        break; // Only process first file
    }

    let file_path = match file_path {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(VerifyResponse {
                success: false,
                verified: false,
                output: None,
                details: None,
                error: Some("No file uploaded".to_string()),
            });
        }
    };

    // Execute wine verify
    let tool_path = bin_dir().join("lnk_tool.exe");
    let cmd_str = format!(
        "wine \"{}\" verify \"{}\"",
        tool_path.display(),
        file_path.display()
    );
    eprintln!("[*] Verificando: {}", cmd_str);

    let output = Command::new("wine")
        .arg(tool_path.to_str().unwrap_or(""))
        .arg("verify")
        .arg(file_path.to_str().unwrap_or(""))
        .output();

    // Clean up temp file
    let _ = std::fs::remove_file(&file_path);

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout).to_string();
            let stderr = String::from_utf8_lossy(&result.stderr).to_string();
            let verified = result.status.success();

            HttpResponse::Ok().json(VerifyResponse {
                success: true,
                verified,
                output: Some(if stdout.is_empty() { stderr } else { stdout }),
                details: if verified { None } else { Some("Analysis completed with findings or errors.".to_string()) },
                error: None,
            })
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(VerifyResponse {
                success: false,
                verified: false,
                output: None,
                details: Some(format!("Execution error: {}", e)),
                error: Some("Failed to execute verification tool".to_string()),
            })
        }
    }
}

// ─── Route: POST /api/generate — Generate a LNK file ───

async fn api_generate(body: web::Json<GenerateRequest>) -> HttpResponse {
    let tool_path = bin_dir().join("lnk_tool.exe");
    let out_path = artifacts_dir().join(&body.out);

    // Build command arguments
    let mut args: Vec<String> = vec![
        tool_path.to_string_lossy().to_string(),
        "generate".to_string(),
        body.technique.clone(),
        "--target".to_string(),
        body.target.clone(),
        "--fake".to_string(),
        body.fake.clone(),
        "--out".to_string(),
        out_path.to_string_lossy().to_string(),
    ];

    if !body.args.is_empty() {
        args.push("--args".to_string());
        args.push(body.args.clone());
    }

    if body.delay > 0 {
        args.push("--delay".to_string());
        args.push(body.delay.to_string());
    }

    if !body.url.is_empty() {
        args.push("--url".to_string());
        args.push(body.url.clone());
    }

    if body.obfuscation {
        args.push("--obfuscate".to_string());
        args.push("2".to_string());
    }

    eprintln!("[*] Ejecutando: wine {}", args.join(" "));

    let output = Command::new("wine")
        .args(&args)
        .output();

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout).to_string();
            let stderr = String::from_utf8_lossy(&result.stderr).to_string();

            if !result.status.success() {
                return HttpResponse::InternalServerError().json(GenerateResponse {
                    success: false,
                    file: None,
                    size: None,
                    crc32: None,
                    output: None,
                    error: Some(stderr.clone()),
                    details: Some(stderr),
                });
            }

            // Parse output for CRC32 and size
            let size_re = regex::Regex::new(r"\[\+\] Size: (\d+) bytes").unwrap();
            let crc_re = regex::Regex::new(r"\[\+\] CRC32: (0x[0-9a-fA-F]+)").unwrap();

            let size = size_re.captures(&stdout).map(|c| c[1].to_string()).unwrap_or_else(|| "Unknown".to_string());
            let crc32 = crc_re.captures(&stdout).map(|c| c[1].to_string()).unwrap_or_else(|| "Unknown".to_string());

            HttpResponse::Ok().json(GenerateResponse {
                success: true,
                file: Some(body.out.clone()),
                size: Some(size),
                crc32: Some(crc32),
                output: Some(stdout),
                error: None,
                details: None,
            })
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(GenerateResponse {
                success: false,
                file: None,
                size: None,
                crc32: None,
                output: None,
                error: Some(format!("Failed to execute: {}", e)),
                details: None,
            })
        }
    }
}

// ─── Main ───

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Ensure required directories exist
    std::fs::create_dir_all(artifacts_dir()).ok();
    std::fs::create_dir_all(uploads_dir()).ok();

    println!("╔══════════════════════════════════════════╗");
    println!("║   LNK TOOL v4.0 — Rust Backend Server   ║");
    println!("╠══════════════════════════════════════════╣");
    println!("║  http://{}:{}                  ║", BIND_ADDR, PORT);
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("[*] Static dir:    {:?}", static_dir());
    println!("[*] Artifacts dir: {:?}", artifacts_dir());
    println!("[*] Bin dir:       {:?}", bin_dir());

    HttpServer::new(move || {
        App::new()
            // API routes
            .route("/api/files", web::get().to(api_list_files))
            .route("/api/download/{filename}", web::get().to(api_download))
            .route("/api/verify", web::post().to(api_verify))
            .route("/api/generate", web::post().to(api_generate))
            // Static assets (CSS, JS)
            .service(afs::Files::new("/static", static_dir()).show_files_listing())
            // Serve generated artifacts for direct access
            .service(afs::Files::new("/output", artifacts_dir()))
            // Index page (catch-all)
            .default_service(web::get().to(index_page))
    })
    .bind((BIND_ADDR, PORT))?
    .run()
    .await
}
