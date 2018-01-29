"""
Downloaded from https://code.google.com/p/benchrun/

Fibonacci numbers test benchmark
"""

from benchrun import Benchmark, clock

def fib1(n):
    if n < 2:
        return n
    return fib1(n-1) + fib1(n-2)

def fib2(n):
    if n < 2:
        return n
    a, b = 1, 0
    for i in xrange(n-1):
        a, b = a+b, a
    return a

class FibonacciBenchmark(Benchmark):
    """Compare time to compute the nth Fibonacci number recursively
    (fib1) and iteratively (fib2)."""

    # Execute for all combinations of these parameters
    parameters = ['version', 'n']
    version = ['fib1', 'fib2']
    n = range(0, 60, 5)

    # Compare timings against this parameter value
    reference = ('version', 'fib1')

    def run(self, n, version):
        f = globals()[version]
        # Don't repeat when slow
        if version == 'fib1' and n > 10:
            # Skip altogether
            if n > 30:
                return None
            t1 = clock()
            f(n)
            t2 = clock()
            return t2-t1
        # Need to repeat many times to get accurate timings for small n
        else:
            t1 = clock()
            f(n); f(n); f(n); f(n); f(n); f(n); f(n)
            f(n); f(n); f(n); f(n); f(n); f(n); f(n)
            t2 = clock()
            return (t2 - t1) / 14

if __name__ == '__main__':
    FibonacciBenchmark().print_result()
