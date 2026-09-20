/*
 * refuse.h: make Hex-Rays refuse to decompile your functions.
 *
 * Named after the companion article ("Refusing the Decompiler"). These
 * macros make the decompiler refuse or degrade the protected function.
 * IDA itself, the disassembly, and runtime behavior are unaffected.
 *
 * Three measured methods (IDA Pro 9.3, x64; see README.md for the full
 * write-up and reproduction steps):
 *
 *   Method 1: REFUSE_BIG()
 *     Inline macro-generated junk that pushes the containing function past
 *     Hex-Rays' function-size limit: the decompiler refuses any function
 *     whose body accumulates more than MAX_FUNCSIZE × 1024 = 64 KiB
 *     (MAX_FUNCSIZE = 64 in cfg/hexrays.cfg), failing F5 with "too big
 *     function" (code -29). Measured brackets on 9.3: 63,019-byte function
 *     decompiles, 94,519-byte function refuses. Pure C, portable
 *     (GCC/Clang/MSVC, any arch). Costs ~6 MB of code per protected
 *     function with the default macro (102,400 junk statements, 12
 *     instructions each at -O0); the default macro emits ~100× more than
 *     the wall, so it can be trimmed if bloat matters. Works with or
 *     without a symbol table.
 *
 *   Method 2: REFUSE_SP_THUNK()
 *     Emits a 2-byte `push rax; ret` thunk. On IDA 9.3 the decompiler
 *     absorbs the unbalanced stack with its tail-call recovery and
 *     degrades the thunk to a hollow `__asm { retn }` stub (warning:
 *     "unbalanced stack, ignored a potential tail call"), so no pseudocode
 *     is produced. The hard refusal ("positive sp value has been found",
 *     code -5, MERR_BADSP) is raised by the convert_pushes microcode pass
 *     when a push/pop maps below the frame floor, but the minimal thunk
 *     never reaches it on 9.3. Never call the thunk; its existence in the
 *     binary is enough. GCC/Clang x64 (naked + inline asm; MSVC x64 has no
 *     inline asm; use the .asm note below or rely on Method 1).
 *
 *   Method 3: REFUSE_SELFMOD()
 *     Writes one byte into a read-only (.rdata/.text) page at runtime.
 *     Hex-Rays' memory model flags the store: "write access to const
 *     memory has been detected, the output may be wrong!", and the
 *     surrounding pseudocode comes out mis-modeled (measured: a
 *     self-relocating entry region decompiled with a `memset(nullptr,
 *     ...)` call that never exists). ~10 instructions, no bloat, executes
 *     safely (the page is flipped RW for the write and back).
 *
 * Usage:
 *     #include "refuse.h"
 *     int secret_fn(int x) { REFUSE_BIG(); return x ^ 0x5A5A; }
 *     REFUSE_SP_THUNK(thunk_name);
 *     int guarded(int x)  { REFUSE_SELFMOD(); return x * 3; }
 *
 * All three methods leave runtime behavior unchanged when used as
 * documented. License: public domain / CC0. Do whatever you want with it.
 */
#ifndef REFUSE_H
#define REFUSE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Method 2: the positive-sp thunk (2 bytes, degrades F5 to a stub)    */
/* ------------------------------------------------------------------ */

#if (defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)

/*
 * NOTE: this macro DEFINES a function. It expands to a complete naked
 * function definition, so it goes at file scope, not inside another
 * function body:
 *
 *     REFUSE_SP_THUNK(thunk_name);   // file scope: defines the thunk
 *
 * The trailing semicolon is optional (it becomes an empty declaration).
 * Never call the thunk: it runs `ret`, which jumps to whatever was in `rax`.
 */
#define REFUSE_SP_THUNK(name)                                            \
    __attribute__((naked, noinline, used)) void name(void) {              \
        __asm__ volatile("push %rax\n\t" /* push value onto the stack */  \
                         "ret");        /* ret pops it -> +sp at entry */ \
    }

/*
 * MSVC x64 has no inline asm. Add this to a .asm file assembled with MASM
 * and link it in instead:
 *
 *   .code
 *   name PROC
 *       push rax
 *       ret
 *   name ENDP
 *   END
 *
 * ...and declare:  extern void name(void);
 */

#elif defined(_MSC_VER) && defined(_M_X64)
/* MSVC x64 has no inline asm; the thunk cannot be emitted here. The macro
 * degrades to a no-op — see the MASM note above to get a real one. */
#pragma message("refuse.h: REFUSE_SP_THUNK is unavailable on MSVC x64; " \
                "link the MASM thunk from the note above instead")
#define REFUSE_SP_THUNK(name) static void name(void) { }
#else
/* Other platforms: Method 2 is unavailable; no-op. */
#define REFUSE_SP_THUNK(name) static void name(void) { }
#endif

/* ------------------------------------------------------------------ */
/* Method 1: the 64 KiB decompiler wall (MAX_FUNCSIZE, measured)       */
/* ------------------------------------------------------------------ */

/*
 * One sink per translation unit; volatile so the compiler cannot fold or
 * delete the junk. The expression mixes multiply/xor/shift/add so each
 * statement lowers to several real, non-foldable instructions.
 */
static volatile uint64_t refuse_sink = 0x9E3779B97F4A7C15ULL;

#define REFUSE_STMT()                                                      \
    ((void)(refuse_sink =                                                   \
        (refuse_sink * 0x9E3779B97F4A7C15ULL)                              \
        ^ ((refuse_sink >> 7) + (uint64_t)(uintptr_t)&refuse_sink          \
           + 0xDEADBEEFu)))

#define REFUSE_REP4(x)    x; x; x; x
#define REFUSE_REP16(x)   REFUSE_REP4(REFUSE_REP4(x))
#define REFUSE_REP64(x)   REFUSE_REP16(REFUSE_REP4(x))
#define REFUSE_REP256(x)  REFUSE_REP64(REFUSE_REP4(x))
#define REFUSE_REP1024(x) REFUSE_REP256(REFUSE_REP4(x))
#define REFUSE_REP4096(x) REFUSE_REP1024(REFUSE_REP4(x))
#define REFUSE_REP5(x)    x; x; x; x; x
#define REFUSE_REP10(x)   REFUSE_REP5(REFUSE_REP5(x))

/* REP10(x) = REP5(REP5(x)) = 25 blocks; 25 * 4096 = 102,400 statements,
 * 12 instructions each at -O0 (measured) = 1,228,800 junk instructions
 * (the demo's 1,228,807 total adds the function's 7 prologue/return/
 * epilogue instructions), ~6.4 MB of code: ~100× past the 64 KiB "too big
 * function" wall. The
 * measured wall is ~1,000-1,500 statements of this mix; shrink the
 * repetition chain if you want bloat closer to the edge. */
#define REFUSE_BLOCK() REFUSE_REP4096(REFUSE_STMT())

/* Drop this inside the function you want Hex-Rays to refuse. */
#define REFUSE_BIG()                                                       \
    do {                                                                    \
        REFUSE_REP10(REFUSE_BLOCK());                                     \
    } while (0)

/* ------------------------------------------------------------------ */
/* Method 3: the const-memory self-write (~10 instructions, no bloat)  */
/* ------------------------------------------------------------------ */

#if defined(_WIN32)
#include <windows.h>

/*
 * A byte in a read-only section. The macro flips its page writable, writes,
 * and flips it back. Hex-Rays sees a store into "const memory" and flags
 * the whole function's output as possibly wrong. Call it once in a cold
 * path (the two VirtualProtect calls are cheap).
 */
static const volatile unsigned char refuse_canary = 0;

#define REFUSE_SELFMOD()                                                 \
    do {                                                                  \
        DWORD refuse_old = 0;                                            \
        VirtualProtect((void *)&refuse_canary, 1, PAGE_READWRITE,        \
                       &refuse_old);                                     \
        *((volatile unsigned char *)&refuse_canary) = 1;                 \
        VirtualProtect((void *)&refuse_canary, 1, refuse_old,            \
                       &refuse_old);                                     \
    } while (0)

#elif defined(__GNUC__) || defined(__clang__)
#include <sys/mman.h>
#include <unistd.h>

static const volatile unsigned char refuse_canary = 0;

#define REFUSE_SELFMOD()                                                 \
    do {                                                                  \
        void *refuse_pg =                                                \
            (void *)((uintptr_t)&refuse_canary & ~(uintptr_t)(4096 - 1)); \
        mprotect(refuse_pg, 4096, PROT_READ | PROT_WRITE);               \
        *((volatile unsigned char *)&refuse_canary) = 1;                 \
        mprotect(refuse_pg, 4096, PROT_READ);                            \
    } while (0)

#else
/* Unsupported platform: Method 3 degrades to a no-op. */
#define REFUSE_SELFMOD() ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* REFUSE_H */
