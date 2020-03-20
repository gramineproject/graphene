Coding Style Guidelines
=======================

This document describes coding conventions and formatting styles we use in
Graphene. All newly commited code must conform to them to pass a |~| review.

.. note:: Old code is temporarily excluded from these rules until reformatted.

Automatic Reformatting
----------------------

To make formatting easier we've added an integration with
:program:`clang-format` (currently only for C |~| code). You must install
appropriate package from your distribution to use it. For Ubuntu 18.04 you can
setup it this way:

.. code-block:: sh

   sudo apt-get install clang-format

Usage: (assuming you're in the project's top directory)

.. code-block:: sh

   make format

This :command:`make` target **reformats all source files in-place**, so we
recommend you first commit them (or add to `git index
<https://hackernoon.com/understanding-git-index-4821a0765cf>`__ with
:command:`git add -A`), reformat and then verify reformatting results using
:command:`git diff` (or :command:`git diff --cached` if you used :command:`git
add`).

C
-

We use a style derived (and slightly modified) from `Google C++ Styleguide
<https://google.github.io/styleguide/cppguide.html>`__.

Code formatting
^^^^^^^^^^^^^^^

.. note::

   See our :file:`.clang-format` config for precise rules.

1. Indentation: 4 spaces per level.

2. Maximal line length: 100 characters.

3. Brace placement::

      void f() {
          if (a && b) {
              something();
          }
      }

4. ``if-else`` formatting::

      if (x == y) {
          ...
      } else if (x > y) {
          ...
      } else {
          ...
      }

5. Asterisks (``*``) should be placed on the left, with the type. Multiple
   pointer declarations in one line are disallowed. Example::

      int* pointer;
      int* another_pointer;
      int non_pointer_a, non_pointer_b, non_pointer_c;

6. Function call/declaration folding: aligned to a matching parenthesis.
   Required only if the one-line version would exceed the line length limit.
   Examples::

      int many_args(int something_looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong,
                    int also_looooooong,
                    int c);
      ...
      many_args(some_looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong_calculations,
                many_args(123,
                          also_looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong,
                          789),
                many_args(1, 2, 3));

7. ``if``, ``else``, ``do``, ``for``, ``while``, ``switch`` and ``union`` should
   be followed by a space.

8. Includes should be grouped and then sorted lexicographically. Groups should
   be separated using a |~| single empty line.

   Groups:

   1. Matching :file:`.h` header for :file:`.c` files.
   2. Standard library headers.
   3. Non-standard headers not included in Graphene's repository (e.g. from
      external dependencies, like :file:`curl.h`).
   4. Graphene's headers.

Conventions and High-level Style
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
1. Variable and function names should be sane and easy to understand (example:
   ``nofpts`` is bad, ``points_cnt`` is ok).

2. All non-static function interfaces should be documented in comments
   (especially pointer ownerships). Same for public macros.

3. Prefer readable code and meaningful variable/function names to explaining
   implementation details in comments within a |~| function. Only tricky or
   unintuitive code should be commented.

4. Magic numbers (e.g. buffer sizes) shouldn’t be hardcoded in the
   implementation. Use ``#define``.

5. Naming:

   1. Macros and global constants should be ``NAMED_THIS_WAY``.
   2. Functions, structures and variables should be ``named_this_way``.
   3. Global variables should be prefixed with ``g_`` (e.g. ``g_thread_list``).

6. Types:

    1. All in-memory sizes and array indexes should be stored using ``size_t``.
    2. All file offsets and sizes should be stored using ``uint64_t``.
    3. In general, C99 types should be used where possible (although some code
       is "grandfathered" in, it should also be changed as time allows).

7. ``goto`` may be used only for error handling.

8. `Yoda conditions <https://en.wikipedia.org/wiki/Yoda_conditions>`__
   (e.g. ``if (42 == x)``) or any other similar constructions are not allowed.

9. Prefer ``sizeof(instance)`` to ``sizeof(type)``, it’s less error-prone.

Python
------

.. todo:: TBD
