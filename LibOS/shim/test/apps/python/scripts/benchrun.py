"""
Downloaded from https://code.google.com/p/benchrun/

A benchmark is defined by creating a subclass of Benchmark.
The subclass should define a method run() that executes the code
to be timed and returns the elapsed time in seconds (as a float),
or None if the benchmark should be skipped.

See fibonacci.py for example.
"""

import sys
if sys.platform=='win32':
    from time import clock
else:
    from time import time as clock

# http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/302478
def combinations(*seqin):
    def rloop(seqin,comb):
        if seqin:
            for item in seqin[0]:
                newcomb = comb + [item]
                for item in rloop(seqin[1:],newcomb):   
                    yield item
        else:
            yield comb
    return rloop(seqin,[])


class Benchmark:
    sort_by = []
    reference = None

    def __init__(self):
        self.pnames = []
        self.pvalues = []
        self.results = []
        self.results_dict = {}
        for pname in self.parameters:
            value = getattr(self, pname)
            self.pnames.append(pname)
            self.pvalues.append(value)
        self.pcombos = list(combinations(*self.pvalues))
        if self.reference:
            self.reference_param = self.reference[0]
            self.reference_value = self.reference[1]

    def time_all(self):
        """Run benchmark for all versions and parameters."""
        for params in self.pcombos:
            args = dict(zip(self.pnames, params))
            t = self.run(**args)
            self.results.append(tuple(params) + (t,))
            self.results_dict[tuple(params)] = t

    def sort_results(self):
        sort_keys = []
        for name in self.sort_by:
            sort_keys += [self.pnames.index(name)]
        for i, name in enumerate(self.pnames):
            if i not in sort_keys:
                sort_keys += [i]
        def key(v):
            return list(v[i] for i in sort_keys)
        self.results.sort(key=key)

    def get_factor(self, pvalues, time):
        if not self.reference or not time:
            return None
        pvalues = list(pvalues)
        i = self.pnames.index(self.reference_param)
        if pvalues[i] == self.reference_value:
            return None
        else:
            pvalues[i] = self.reference_value
        ref = self.results_dict[tuple(pvalues)]
        if ref == None:
            return None
        return ref / time

    def print_result(self):
        """Run benchmark for all versions and parameters and print results
        in tabular form to the standard output."""
        self.time_all()
        self.sort_results()

        print "=" * 78
        print
        print self.__class__.__name__
        print self.__doc__, "\n"

        colwidth = 15
        reftimes = {}

        ts = "seconds"
        if self.reference:
            ts += " (x faster than " + (str(self.reference_value)) + ")"
        print "  ", "   ".join([str(r).ljust(colwidth) for r in self.pnames + [ts]])
        print "-"*79

        rows = []
        for vals in self.results:
            pvalues =  vals[:-1]
            time = vals[-1]
            if time == None:
                stime = "(n/a)"
            else:
                stime = "%.8f" % time
                factor = self.get_factor(pvalues, time)
                if factor != None:
                    stime += ("  (%.2f)" % factor)
            vals = pvalues + (stime,)
            row = [str(val).ljust(colwidth) for val in vals]
            print "  ", "   ".join(row)
        print
