/* CFF positive control: real indirect dispatch via computed goto.

   This is the shape cff_deflatten.find_dispatchers exists to catch -- a
   dispatcher block whose successors are case arms and back edges -- built by
   hand so the detector can be tested against ground truth rather than against
   an argument about what flattening looks like.

   Measured behaviour (matrix run 2026-10-03, VM, detector at its shipped
   defaults unless stated):

     cff_goto -O0  -> 1 candidate: cff_goto_demo, outdeg=5, back=4  (fires)
     cff_goto -O2  -> silent, at BOTH the default and --min-case-targets 1:
                      GCC devirtualises the computed goto into direct branches
                      at -O2 regardless of the volatile state, so the -O2
                      build is NOT a valid positive control. Do not treat its
                      silence as a detector miss.
     cff_orig      -> silent at -O0 and -O2 (negative control holds)

   The "needs --min-case-targets 1" note in the plan refers to the while-switch
   fixture (cff_flat.c) at -O2, whose state machine GCC inlines into main and
   collapses to a single returning arm -- precisely the signal the default of
   2 exists to reject (see tests/test_cff_detector.py::test_case_target_floor_
   is_respected). The default must NOT be lowered to make that weak shape pass.

   Build: gcc -O0/-O2 (ELF is fine; the detector analyses blocks, not format).
*/
#include <stdio.h>

int cff_goto_demo(int x) {
    static void *tbl[] = { &&S0, &&S1, &&S2, &&S3, &&S4, &&S5, &&S99 };
    volatile int state = 0;
    int result = 0;
    goto *tbl[state];
S0:
    if (x < 0) { state = 4; goto *tbl[state]; }
    if (x < 100) { state = 1; goto *tbl[state]; }
    state = 2; goto *tbl[state];
S1:
    result = x * 2; state = 99; goto *tbl[state];
S2:
    if (x < 1000) { state = 3; goto *tbl[state]; }
    state = 5; goto *tbl[state];
S3:
    result = x + 100; state = 99; goto *tbl[state];
S4:
    result = -1; state = 99; goto *tbl[state];
S5:
    result = x - 50; state = 99; goto *tbl[state];
S99:
    return result;
}

int main(void) {
    int xs[] = { -50, 0, 50, 500, 5000 };
    int n = sizeof(xs) / sizeof(int);
    for (int i = 0; i < n; i++)
        printf("cff_goto_demo(%d)=%d\n", xs[i], cff_goto_demo(xs[i]));
    return 0;
}
