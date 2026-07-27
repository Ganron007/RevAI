/* cff_flat.c - Manually flattened version of cff_demo.
 * Same outcome as cff_orig.c but with explicit dispatcher loop.
 * The "while + switch on state" idiom is exactly what VMProtect /
 * Themida / Obfuscator-LLVM / ConfuserEx generate.
 *
 * Expected behavior of the deflatten:
 *   1. Find the dispatcher block (the switch on `state`).
 *   2. Identify `state` as the discriminator variable.
 *   3. Trace each case's terminator: it sets `state = X` then breaks.
 *   4. Recover the original directed edges:
 *      case 0 -> case 1 (when x<0)
 *      case 0 -> case 2 (when x>=0)
 *      case 1 -> case 99 (terminal)
 *      case 2 -> case 3 (when x<100)
 *      case 2 -> case 4 (when x>=100)
 *      case 3 -> case 99 (terminal)
 *      case 4 -> case 5 (when x<1000)
 *      case 4 -> case 6 (when x>=1000)
 *      case 5 -> case 99 (terminal)
 *      case 6 -> case 99 (terminal)
 *      case 99 -> function exit
 */
#include <stdio.h>
#include <stdlib.h>

int cff_demo_flat(int x) {
    int state = 0;
    int result = 0;
    while (1) {
        switch (state) {
            case 0:
                if (x < 0)      state = 1;       /* -> case 1 */
                else            state = 2;       /* -> case 2 */
                break;
            case 1:
                result = -1;                     /* terminal */
                state = 99;
                break;
            case 2:
                if (x < 100)    state = 3;       /* -> case 3 */
                else            state = 4;       /* -> case 4 */
                break;
            case 3:
                result = x * 2;                  /* terminal */
                state = 99;
                break;
            case 4:
                if (x < 1000)   state = 5;       /* -> case 5 */
                else            state = 6;       /* -> case 6 */
                break;
            case 5:
                result = x + 100;                /* terminal */
                state = 99;
                break;
            case 6:
                result = x - 50;                 /* terminal */
                state = 99;
                break;
            case 99:
                return result;
        }
    }
}

int main(int argc, char **argv) {
    int xs[] = { -50, -1, 0, 50, 99, 100, 500, 999, 1000, 5000 };
    int n = sizeof(xs) / sizeof(xs[0]);
    for (int i = 0; i < n; i++) {
        int r = cff_demo_flat(xs[i]);
        printf("cff_demo_flat(%d) = %d\n", xs[i], r);
    }
    return 0;
}
