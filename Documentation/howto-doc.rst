.. _doc-howto:

How to write documentation
==========================

Documentation is generally written as `reStructuredText`_ files and processed
using `Sphinx`_. See `Sphinx' reST primer`_ for short introduction into syntax.
:ref:`Old Wiki <old-wiki>` is imported as it was, in Markdown, but new
documentation should be written in reST.

API documentation of C |nbsp| language should be written as Doxygen comments
(prefer Qt-style ``/*!`` and ``\param``) and then included in one of the
``.rst`` files (with appropriate description) using one of the `Breathe
directives`_, like :rst:dir:`doxygenfunction` or :rst:dir:`doxygenstruct`. See
`Breathe`_ documentation for more info. Do not use ``autodoxygen`` directives,
and especially do not use ``.. doxygenfile::``, because documentation should be
written as prose, not a |nbsp| coredump.

In ``.rst`` files use 3-space tab. This is an uncommon value, but good value
because intended blocks usually follow explicit markup, which begins with
``..``). Wrap the paragraphs at 80th character, but don't wrap verbatim text
like logs and use applicable style when wrapping code examples. Use Python
convention for header hierarchy: ``#`` with overline, ``*`` with overline,
``=``, ``-``, ``^``, ``"``. This means most documents use only ``=`` and ``-``
underlines. Those underlines are easy to enter in :command:`vim` using the
combination ``yypVr-``.

Documentation of the code should be organized into files by logical concepts,
as they fit into programmers mind. Ideally, this should match the source files,
if those files were organised correctly in the first place, but the reality may
be different. In case of doubt, place them as they fit the narration of the
document, not as they are placed in the source files.

Documents should be grouped by general areas and presented using
:rst:dir:`toctree` directive in :file:`index.rst` file. This causes them to be
included in TOC in the main document and also in sidebar on RTD.

The documentation targets ``html`` output of Sphinx. The :file:`manpages/`
subdirectory also targets ``manpage`` builder. Other formats (like ``latex``)
may be considered in the future, but for now their output is neither published
not cared for.

.. _reStructuredText: https://en.wikipedia.org/wiki/ReStructuredText
.. _Sphinx: https://www.sphinx-doc.org/
.. _Sphinx' reST primer: https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html
.. _Breathe: https://breathe.readthedocs.io/en/latest/
.. _Breathe directives: https://breathe.readthedocs.io/en/latest/directives.html
