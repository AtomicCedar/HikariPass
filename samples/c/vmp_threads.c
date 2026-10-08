// VMP multi-thread stress: the VM keeps all state on the caller's stack, so
// concurrent invocations of the same virtualized function (and recursion) must
// produce identical results to a clean build.
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((annotate("vmp")))
static long vmp_fib(long n) {
  if (n < 2)
    return n;
  return vmp_fib(n - 1) + vmp_fib(n - 2);
}

__attribute__((annotate("vmp")))
static long vmp_mix(int a, int b, int c) {
  long acc = 0;
  for (int i = 0; i < a; ++i) {
    acc += (long)(b ^ (i * c));
    acc = acc * 31 + i;
  }
  return acc;
}

struct Job {
  long n;
  long out;
};

static void *worker(void *p) {
  struct Job *J = (struct Job *)p;
  long a = vmp_fib(J->n % 14);
  long b = vmp_mix((int)(J->n % 20) + 1, 7, 3);
  J->out = a * 1000003L + b;
  return NULL;
}

int main(void) {
  enum { NT = 8, IT = 50 };
  pthread_t th[NT];
  struct Job jobs[NT];
  long total = 0;
  for (int it = 0; it < IT; ++it) {
    for (int t = 0; t < NT; ++t) {
      jobs[t].n = (long)(it * NT + t);
      jobs[t].out = -1;
      if (pthread_create(&th[t], NULL, worker, &jobs[t]) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 2;
      }
    }
    for (int t = 0; t < NT; ++t)
      pthread_join(th[t], NULL);
    for (int t = 0; t < NT; ++t)
      total += jobs[t].out;
  }
  printf("%ld\n", total);
  return 0;
}
