Benchmarking
============

We have some `Airspeed Velocity <https://asv.readthedocs.io/>`__ benchmarks
available.

After :doc:`building graphene <../building>`:

.. code-block:: sh

   make -C benchmarks
   asv run

The first time you run the benchmark, you will be asked some questions about
your current machine. See ASV documentation for more info.
