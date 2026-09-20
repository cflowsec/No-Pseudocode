/*
 * hello_world.c: demo for refuse.h
 *
 * Build:   gcc -O0 -s hello_world.c -o hello_world.exe
 *
 * Load hello_world.exe in IDA Pro 9.3 and look at:
 *   - hello_world()           -> decompiles instantly, clean pseudocode
 *   - secret_function()       -> Method 1: F5 refuses with
 *                                "too big function" (-29)
 *   - thunk_refuses_ida()     -> Method 2: F5 yields a hollow
 *                                "__asm { retn }" stub with an
 *                                "unbalanced stack" warning
 *   - guarded_selfmod()       -> Method 3: F5 shows the
 *                                "write access to const memory has been
 *                                detected, the output may be wrong!"
 *                                banner with mis-modeled pseudocode
 */
#include <stdio.h>
#include "refuse.h"

/* the unprotected control: prints and returns, decompiles cleanly */
int hello_world(void)
{
    printf("hello world\n");
    return 42;
}

/* Method 2: the thunk is never called; its mere presence guts F5 */
REFUSE_SP_THUNK(thunk_refuses_ida);

/* Method 1: the junk pushes this function past the 64 KiB "too big" wall */
int secret_function(int seed)
{
    REFUSE_BIG();
    return seed ^ 0x5A5A5A5A;
}

/* Method 3: one byte into a read-only page poisons the memory model */
int guarded_selfmod(int x)
{
    REFUSE_SELFMOD();
    return x * 3 + 1;
}

int main(void)
{
    printf("control: %d\n", hello_world());
    printf("secret: %d\n", secret_function(7));
    printf("guarded: %d\n", guarded_selfmod(5));

    /* keep the thunk referenced so the linker cannot discard it */
    if (refuse_sink == 0xFFFFFFFFFFFFFFFFULL)
        ((void (*)(void))&thunk_refuses_ida)(); /* never taken */
    return 0;
}
