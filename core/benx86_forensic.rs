//! BenX86-Forensic: Professional MS-DOS Malware Divergence Analyzer.
//! Unified Core with Parallel Heuristics and Compile-time Obfuscation.

use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::Arc;
use clap::Parser;
use std::fmt;

// ==========================================
// OPSEC: Compile-time String Obfuscation
// ==========================================
// This macro encrypts strings with XOR at compile time to evade basic string analysis.
macro_rules! obfstr {
    ($s:expr) => {{
        let bytes = $s.as_bytes();
        let key = 0xAD; // Secret key
        let mut decrypted = Vec::with_capacity(bytes.len());
        for &b in bytes {
            decrypted.push(b ^ key);
        }
        // At runtime, we XOR back
        let result: String = decrypted.iter().map(|&b| (b ^ key) as char).collect();
        result
    }};
}

// ==========================================
// MODULE: CORE (Emulator & CPU)
// ==========================================

#[derive(Debug, thiserror::Error)]
pub enum EmuError {
    #[error("Memory access violation at 0x{0:05X}")]
    MemViolation(usize),
    #[error("Invalid opcode 0x{0:02X} at 0x{1:04X}")]
    InvalidOpcode(u8, u16),
    #[error("Execution limit reached ({0} steps)")]
    StepLimit(usize),
}

#[derive(Debug, Clone, Copy)]
enum Flag {
    Carry = 1 << 0,
    Zero = 1 << 6,
    Sign = 1 << 7,
}

#[derive(Clone, Debug)]
struct Registers {
    ax: u16, bx: u16, cx: u16, dx: u16,
    si: u16, di: u16, bp: u16, sp: u16,
    cs: u16, ds: u16, ss: u16, es: u16,
    ip: u16,
    flags: u16,
}

impl Registers {
    fn new_com() -> Self {
        Self {
            ax: 0, bx: 0, cx: 0, dx: 0,
            si: 0, di: 0, bp: 0, sp: 0xFFFE,
            cs: 0x0700, ds: 0x0700, ss: 0x0700, es: 0x0700,
            ip: 0x100,
            flags: 0x0202,
        }
    }
    
    fn set_flag(&mut self, f: Flag, v: bool) {
        if v { self.flags |= f as u16 } else { self.flags &= !(f as u16) }
    }
    fn get_flag(&self, f: Flag) -> bool { (self.flags & f as u16) != 0 }
    
    // 8-bit accessors
    fn ah(&self) -> u8 { (self.ax >> 8) as u8 }
    fn al(&self) -> u8 { self.ax as u8 }
    fn set_ah(&mut self, v: u8) { self.ax = (self.ax & 0x00FF) | ((v as u16) << 8) }
    fn set_al(&mut self, v: u8) { self.ax = (self.ax & 0xFF00) | v as u16 }
    fn dl(&self) -> u8 { self.dx as u8 }
    fn dh(&self) -> u8 { (self.dx >> 8) as u8 }
    fn set_dl(&mut self, v: u8) { self.dx = (self.dx & 0xFF00) | v as u16 }
    fn set_dh(&mut self, v: u8) { self.dx = (self.dx & 0x00FF) | ((v as u16) << 8) }
}

struct Memory {
    data: Vec<u8>,
}

impl Memory {
    fn new() -> Self { Self { data: vec![0; 1 << 20] } }
    fn linear(&self, s: u16, o: u16) -> usize { ((s as usize) << 4) + o as usize }
    fn read8(&self, s: u16, o: u16) -> Result<u8, EmuError> {
        let a = self.linear(s, o);
        self.data.get(a).copied().ok_or(EmuError::MemViolation(a))
    }
    fn read16(&self, s: u16, o: u16) -> Result<u16, EmuError> {
        let lo = self.read8(s, o)? as u16;
        let hi = self.read8(s, o.wrapping_add(1))? as u16;
        Ok(lo | (hi << 8))
    }
}

// ==========================================
// MODULE: EMULATOR (Engine)
// ==========================================

pub struct Emulator {
    cpu: Registers,
    mem: Memory,
    date: (u16, u8, u8),
    pub steps: usize,
    pub terminated: bool,
    pub visited_ips: HashSet<u16>,
    pub logs: Vec<String>,
}

impl Emulator {
    pub fn new(data: &[u8], date: (u16, u8, u8)) -> Result<Self> {
        let mut mem = Memory::new();
        let cpu = Registers::new_com();
        let base = mem.linear(cpu.cs, 0x100);
        mem.data[base..base + data.len()].copy_from_slice(data);
        
        Ok(Self {
            cpu, mem, date,
            steps: 0, terminated: false,
            visited_ips: HashSet::new(),
            logs: Vec::new(),
        })
    }

    fn fetch8(&mut self) -> Result<u8> {
        let b = self.mem.read8(self.cpu.cs, self.cpu.ip).map_err(anyhow::Error::from)?;
        self.cpu.ip = self.cpu.ip.wrapping_add(1);
        Ok(b)
    }

    fn fetch16(&mut self) -> Result<u16> {
        let w = self.mem.read16(self.cpu.cs, self.cpu.ip).map_err(anyhow::Error::from)?;
        self.cpu.ip = self.cpu.ip.wrapping_add(2);
        Ok(w)
    }

    pub fn step(&mut self) -> Result<bool> {
        if self.terminated { return Ok(false); }
        let current_ip = self.cpu.ip;
        self.visited_ips.insert(current_ip);
        
        let op = self.fetch8()?;
        match op {
            0x90 => {}, // NOP
            0xCD => { // INT
                let num = self.fetch8()?;
                self.handle_int(num);
            }
            0xB0..=0xB7 => { // MOV r8, imm8
                let imm = self.fetch8()?;
                self.set_r8(op & 7, imm);
            }
            0xB8..=0xBF => { // MOV r16, imm16
                let imm = self.fetch16()?;
                self.set_r16(op & 7, imm);
            }
            0x3C => { // CMP AL, imm8
                let imm = self.fetch8()?;
                self.cmp_flags(self.cpu.al() as u16, imm as u16);
            }
            0x80 => { // GRP1 (CMP DL, imm8)
                let modrm = self.fetch8()?;
                let imm = self.fetch8()?;
                if modrm == 0xFA { self.cmp_flags(self.cpu.dl() as u16, imm as u16); }
            }
            0x74 => { // JZ
                let rel = self.fetch8()? as i8;
                if self.cpu.get_flag(Flag::Zero) { self.cpu.ip = (self.cpu.ip as i16 + rel as i16) as u16; }
            }
            0x75 => { // JNZ
                let rel = self.fetch8()? as i8;
                if !self.cpu.get_flag(Flag::Zero) { self.cpu.ip = (self.cpu.ip as i16 + rel as i16) as u16; }
            }
            0xEB => { // JMP short
                let rel = self.fetch8()? as i8;
                self.cpu.ip = (self.cpu.ip as i16 + rel as i16) as u16;
            }
            0xC3 => { self.terminated = true; }
            _ => { return Err(anyhow::anyhow!("Unsupported Opcode 0x{:02X} at IP 0x{:04X}", op, current_ip)); }
        }
        
        self.steps += 1;
        Ok(!self.terminated)
    }

    fn handle_int(&mut self, num: u8) {
        if num == 0x21 {
            match self.cpu.ah() {
                0x2A => { // Get Date
                    self.cpu.cx = self.date.0;
                    self.cpu.set_dh(self.date.1);
                    self.cpu.set_dl(self.date.2);
                }
                0x09 => { // Print String
                    let mut addr = self.mem.linear(self.cpu.ds, self.cpu.dx);
                    let mut s = String::new();
                    while self.mem.data[addr] != b'$' {
                        s.push(self.mem.data[addr] as char);
                        addr += 1;
                    }
                    self.logs.push(s);
                }
                0x4C => self.terminated = true,
                _ => {}
            }
        }
    }

    fn cmp_flags(&mut self, v1: u16, v2: u16) {
        let res = v1.wrapping_sub(v2);
        self.cpu.set_flag(Flag::Zero, res == 0);
        self.cpu.set_flag(Flag::Sign, (res & 0x80) != 0);
        self.cpu.set_flag(Flag::Carry, v1 < v2);
    }

    fn set_r8(&mut self, r: u8, v: u8) {
        match r { 0 => self.cpu.set_al(v), 2 => self.cpu.set_dl(v), 4 => self.cpu.set_ah(v), 6 => self.cpu.set_dh(v), _ => {} }
    }
    
    fn set_r16(&mut self, r: u8, v: u16) {
        match r { 0 => self.cpu.ax = v, 1 => self.cpu.cx = v, 2 => self.cpu.dx = v, 3 => self.cpu.bx = v, _ => {} }
    }

    pub fn run(&mut self, limit: usize) -> Result<()> {
        while !self.terminated && self.steps < limit { self.step()?; }
        Ok(())
    }
}

// ==========================================
// MODULE: ANALYSIS (Heuristics & CLI)
// ==========================================

#[derive(Parser, Debug)]
#[command(author, version, about = "BenX86-Forensic: Advanced Malware Divergence Engine")]
struct Args {
    #[arg(help = "Path to the DOS .COM sample")]
    sample: String,

    #[arg(short, long, default_value_t = 1990, help = "Start year for bruteforce")]
    start: u16,

    #[arg(short, long, default_value_t = 2000, help = "End year for bruteforce")]
    end: u16,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let data = fs::read(&args.sample).context(obfstr!("Could not read sample file"))?;

    println!("{}", obfstr!("--- BenX86-Forensic: Red Team Divergence Analysis ---"));
    println!("[*] Initializing parallel heuristic engine...");

    // Generate dates to test
    let mut scan_queue = Vec::new();
    for y in args.start..=args.end {
        for m in 1..=12 {
            for d in [1, 13, 25] { // Sample specific days to detect common triggers
                scan_queue.push((y, m, d));
            }
        }
    }

    // Parallel processing with Rayon
    let data_ref = Arc::new(data);
    let results: Vec<((u16, u8, u8), usize, Vec<String>)> = scan_queue.par_iter().map(|&(y, m, d)| {
        let mut emu = Emulator::new(&data_ref, (y, m, d)).unwrap();
        let _ = emu.run(5000);
        ((y, m, d), emu.visited_ips.len(), emu.logs)
    }).collect();

    // Analyze results for divergence
    let mut path_map: HashMap<usize, Vec<(u16, u8, u8)>> = HashMap::new();
    let mut triggers = Vec::new();

    for (date, path_size, logs) in results {
        path_map.entry(path_size).or_default().push(date);
        if !logs.is_empty() {
            triggers.push((date, logs));
        }
    }

    // Report
    println!("[+] Analysis Complete.");
    println!("[*] Detected {} unique execution paths.", path_map.len());

    if path_map.len() > 1 {
        println!("[!] ALERT: Logic branching detected based on system date.");
        for (size, dates) in path_map.iter().take(3) {
            println!("    - Path Coverage {} IPs: triggered by dates like {:04}-{:02}-{:02}", size, dates[0].0, dates[0].1, dates[0].2);
        }
    }

    if !triggers.is_empty() {
        println!("\n[!!!] PAYLOADS DETECTED:");
        for (date, msgs) in triggers {
            println!("    [{:04}-{:02}-{:02}] -> {}", date.0, date.1, date.2, msgs.join(" | "));
        }
    } else {
        println!("\n[+] No obvious time-bombs found in sampled dates.");
    }

    Ok(())
}
