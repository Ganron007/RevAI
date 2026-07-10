#!/bin/bash
set +e
mkdir -p /tmp/cff-test
cat > /tmp/cff-test/cff_orig.c << 'EOC'
#include <stdio.h>
int cff_demo(int x) {
    if (x < 0)         return -1;
    if (x < 100)       return x * 2;
    if (x < 1000)      return x + 100;
    return x - 50;
}
int main(void) {
    int xs[] = { -50, -1, 0, 50, 99, 100, 500, 999, 1000, 5000 };
    int n = sizeof(xs)/sizeof(int);
    for (int i=0;i<n;i++) printf("cff_demo(%d)=%d\n", xs[i], cff_demo(xs[i]));
    return 0;
}
EOC
cat > /tmp/cff-test/cff_flat.c << 'EOC'
#include <stdio.h>
int cff_demo_flat(int x) {
    volatile int state = 0;
    int result = 0;
    while (1) {
        switch (state) {
            case 0:  if (x<0) state=1; else state=2; break;
            case 1:  result=-1; state=99; break;
            case 2:  if (x<100) state=3; else state=4; break;
            case 3:  result=x*2; state=99; break;
            case 4:  if (x<1000) state=5; else state=6; break;
            case 5:  result=x+100; state=99; break;
            case 6:  result=x-50; state=99; break;
            case 99: return result;
        }
    }
}
int main(void) {
    int xs[] = { -50, -1, 0, 50, 99, 100, 500, 999, 1000, 5000 };
    int n = sizeof(xs)/sizeof(int);
    for (int i=0;i<n;i++) printf("cff_demo_flat(%d)=%d\n", xs[i], cff_demo_flat(xs[i]));
    return 0;
}
EOC
x86_64-w64-mingw32-gcc -O0 -o /tmp/cff-test/cff_orig.exe /tmp/cff-test/cff_orig.c
x86_64-w64-mingw32-gcc -O0 -o /tmp/cff-test/cff_flat.exe /tmp/cff-test/cff_flat.c
ls -la /tmp/cff-test/
file /tmp/cff-test/cff_flat.exe