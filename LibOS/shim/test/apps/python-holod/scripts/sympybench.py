"""
Downloaded from https://code.google.com/p/benchrun/

Test code for benchrun: sympy performance benchmark.
"""

from benchrun import Benchmark, clock

import sympycore
import sympy

class SympyBenchmark(Benchmark):
    version = ['sympy', 'sympycore']
    reference = ('version', 'sympy')


class DirectSymbolicAddition(SympyBenchmark):
    """Add small polynomials with rational coefficients"""
    parameters = ['version']
    def run(self, version):
        module = __import__(version)
        x, y, z = map(module.Symbol, 'xyz')
        a = 3*x + 2*x*y - module.Rational(1,2)*z + 2
        b = 2*x + module.Rational(3,2)*x*y + 4*z - 2
        n = N = 100
        t1 = clock()
        while n:
            a + n*b
            n -= 1
        t2 = clock()
        return (t2-t1)/N

class PowerExpansion(SympyBenchmark):
    """Expand (x+y+z)**n * (y+x)**(n-1)"""
    parameters = ['version', 'n']
    n = [5, 10, 20]
    def run(self, version, n):
        module = __import__(version)
        if version == 'sympy' and n > 10:
            return None
        x, y, z = map(module.Symbol, 'xyz')
        t1 = clock()
        e = ((x+y+z)**n * (y+x)**(n-1)).expand()
        t2 = clock()
        return t2-t1

class LegendreRecurrence(SympyBenchmark):
    """Calculate the nth Legendre polynomial by recurrence."""
    parameters = ['version', 'n']
    n = [3, 10, 30, 100]
    def run(self, version, n):
        module = __import__(version)
        x = module.Symbol('x')
        if version == 'sympy' and n > 30:
            return None
        b, a = x, 1
        t1 = clock()
        for n in range(1, n):
            b, a = (((2*n+1)*x*b - n*a)/(n+1)).expand(), b
        t2 = clock()
        return t2-t1

all_benchmarks = [
  DirectSymbolicAddition(),
  PowerExpansion(),
  LegendreRecurrence(),
]

for bench in all_benchmarks:
    bench.print_result()
