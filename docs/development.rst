#################
Development Guide
#################

***************
Threading Model
***************

Pillar aims to be highly multi-threaded, treating Plugins like Automata
that interact with resources relevant to them to accomplish goals by
communicating with different parts of Pillar. To this end, Pillar has a
standard abstraction for workers based off of ``multiprocess.Process``. The
idea behind this, is that any process or plugin within pillar will inherit
a mix-in interface specific to the worker class it needs to interface with.

As an example, the ``KeyManager`` class inherits the ``PillarDBMixIn`` class
to allow for KeyManager to load and save keys to the database.

The most complete example of this can be found in the unit tests,
``pillar/tests/test_multiproc.py``:


.. literalinclude:: ../pillar/tests/test_multiproc.py
   :language: python
   :lines: 7-53

As you can see in the below testcase, ``return_hi()`` is callable on the
test interface attribute of TestClassMixIn, however the actual method is run
on the worker transparently.


.. literalinclude:: ../pillar/tests/test_multiproc.py
   :language: python
   :lines: 58-62,74-77


By adding MixIn interfaces that inherit the above classes to Plugins as well
as other Pillar internal classes, threading can be accomplished in a consistent
and transparent manner.