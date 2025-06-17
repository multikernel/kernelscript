// Kprobe builtin definitions
// This file defines the standard kprobe context and types

// Kprobe context structure (read-only)
struct KprobeContext {
    regs: u64[21],       // CPU registers (pt_regs)
    ip: u64,             // Instruction pointer
    cs: u64,             // Code segment
    flags: u64,          // CPU flags
    sp: u64,             // Stack pointer
    ss: u64              // Stack segment
}

// Common kprobe return values
enum KprobeAction {
    KPROBE_CONTINUE = 0,
    KPROBE_FAULT = 1
} 