// varargs call sites (JNI style) must be skipped cleanly, not produce
// verifier-failing IR.  If VMP still virtualizes this function, the pass
// either emitted broken IR (verify failed + restore) or corrupted the call.
#include <stdarg.h>
#include <stdio.h>

__attribute__((annotate("vmp")))
static int sum_varargs(int count, ...) {
  va_list ap;
  va_start(ap, count);
  int total = 0;
  for (int i = 0; i < count; ++i)
    total += va_arg(ap, int);
  va_end(ap);
  return total;
}

__attribute__((annotate("vmp")))
static int caller(void) {
  // Non-varargs call of a varargs function through a casted pointer would be
  // UB; instead just exercise normal calls so the function has real body.
  return sum_varargs(0) + 7;
}

int main(void) {
  printf("%d\n", caller());
  return 0;
}
