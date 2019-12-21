.. _howto-doc:

How to write documentation
==========================

.. highlight:: rst

Documentation is generally written as `reStructuredText`_ files and processed
using `Sphinx`_. See `Sphinx' reST primer`_ for short introduction into syntax.
Documentation of C |nbsp| language API should be written as Doxygen comments
(see `Doxygen manual`_) and then included in one of the ``.rst`` files (with
appropriate description) using one of the `Breathe directives`_, like
``.. doxygenfunction::`` or ``.. doxygenstruct::``. See `Breathe`_ documentation
for more info..

:ref:`Old Wiki <old-wiki>` is imported as it was, in Markdown, but new
documentation should be written in reST.

The documentation targets ``html`` output of Sphinx. The :file:`manpages/`
subdirectory also targets ``manpage`` builder. Other formats (like ``latex``)
may be considered in the future, but for now their output is neither published
not cared for.

Preferred reST style
--------------------

(This is adapted from `Python's style guide`_).

- In ``.rst`` files use 3-space tab. This is an uncommon value, but good value
  because intended blocks usually follow explicit markup, which begins with
  ``..``.

- Wrap the paragraphs at 80th character. But don't wrap verbatim text like logs
  and use applicable style when wrapping code examples.

- For headers, use Python convention for header hierarchy:

   1. ``#`` with overline,
   2. ``*`` with overline,
   3. ``=``,
   4. ``-``,
   5. ``^``,
   6. ``"``.

   Example::

      ###################################
      Very top level header (in TOC etc.)
      ###################################

      *******************
      Less than top level
      *******************

      Per-file header
      ===============

      Section header
      --------------

      Subsection header
      ^^^^^^^^^^^^^^^^^

      Subsubsection header
      """"""""""""""""""""

  This means most documents use only ``=`` and ``-`` underlines. Those
  underlines are easy to enter in :command:`vim` using the combination
  ``yypVr-``.

- Use ``|nbsp|`` to insert non-breaking space. This should be added after
  one-letter words and where otherwise appropriate::

      This is a |nbsp| function.

  This substitution is added to all documents processed by Sphinx. For files
  processed also by other software (like ``README.rst``, which is both rendered
  by GitHub and included in ``index.rst``), use ``|_|`` after adding this
  substitution yourself::

      .. |_| unicode:: 0xa0
         :trim:

      This is a |_| README.

Documentation of the code should be organized into files by logical concepts,
as they fit into programmers mind. Ideally, this should match the source files,
if those files were organised correctly in the first place, but the reality may
be different. In case of doubt, place them as they fit the narration of the
document, not as they are placed in the source files.

Documents should be grouped by general areas and presented using
``.. toctree::`` directive in :file:`index.rst` file. This causes them to be
included in TOC in the main document and also in sidebar on RTD.

Preferred Doxygen style
-----------------------

1. Prefer Qt-style ``/*!`` and ``\param``:

   .. code-block:: c

      /*! \brief An example function
       *
       * This function returns a number augmented by the Answer to the Ultimate
       * Question of Life, the Universe, and Everything.
       *
       * \param n The number to be added
       * \return A number 42 greater
       */
      int foo(int n)
      {
          return n + 42;
      }

   ::

      There is a |nbsp| very special function :c:func:`foo`:

      .. doxygenfunction:: foo

      It's an example function, but is documented!


2. Do not use ``autodoxygen`` directives, and especially do not use
   ``.. doxygenfile::``, because documentation should be written as prose, not
   a |nbsp| coredump.

.. _reStructuredText: https://en.wikipedia.org/wiki/ReStructuredText
.. _Sphinx: https://www.sphinx-doc.org/
.. _Sphinx' reST primer: https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html
.. _Doxygen manual: http://www.doxygen.nl/manual/docblocks.html
.. _Breathe: https://breathe.readthedocs.io/en/latest/
.. _Breathe directives: https://breathe.readthedocs.io/en/latest/directives.html
.. _Python's style guide: https://devguide.python.org/documenting/#style-guide
