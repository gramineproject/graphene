Benchmarking
============

We have some `Airspeed Velocity <https://asv.readthedocs.io/>`__ benchmarks
available.

After :doc:`building graphene <../building>`:

.. code-block:: sh

   cd tests
   make -C benchmarks
   ISGX_DRIVER_PATH=/opt/intel/SGXDataCenterAttestationPrimitives/driver/linux asv run -ve $SOME_OLD_COMMIT^..HEAD

The first time you run the benchmark, you will be asked some questions about
your current machine. See ASV documentation for more info.
