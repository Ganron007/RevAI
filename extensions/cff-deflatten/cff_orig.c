/* cff_orig.c - Original (non-flattened) C control flow.
 * This is the "ground truth" for verifying the GhidraScript deflatten.
 * Five basic blocks: branch, branch, branch, terminal, terminal.
 * Original CFG (for x in Z):
 *   block0: if x < 0    -> block1 else block2
 *   block1: ret -1
 *   block2: if x < 100  -> block3 else block4
 *   block3: ret x*2
 *   block4: if x < 1000 -> block5 else block6
 *   block5: ret x+100
 *   block6: ret x-50
 */
#include <stdio.h>
#include <stdlib.h>

int cff_demo(int x) {
    if (x < 0)         return -1;
    if (x < 100)       return x * 2;
    if (x < 1000)      return x + 100;
    return x - 50;
}

int main(int argc, char **argv) {
    int xs[] = { -50, -1, 0, 50, 99, 100, 500, 999, 1000, 5000 };
    int n = sizeof(xs) / sizeof(xs[0]);
    for (int i = 0; i < n; i++) {
        int r = cff_demo(xs[i]);
        printf("cff_demo(%d) = %d\n", xs[i], r);
    }
    return 0;
}
