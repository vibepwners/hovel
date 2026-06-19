Hovel Python SDK API
====================

This reference is generated with Sphinx autodoc from the importable
``hovel_sdk`` package. The module-author guide explains lifecycle rules and
operator-facing behavior; this page is the callable API surface.

Module Lifecycle
----------------

.. autoclass:: hovel_sdk.HovelModule
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.Context
   :members:
   :undoc-members:
   :show-inheritance:

.. autofunction:: hovel_sdk.serve

Configuration
-------------

.. autoclass:: hovel_sdk.Requirement
   :members:
   :undoc-members:
   :show-inheritance:

Results
-------

.. autoclass:: hovel_sdk.Result
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.Finding
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.Artifact
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.InstalledPayload
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.PayloadProviderRecord
   :members:
   :undoc-members:
   :show-inheritance:

Sessions
--------

.. autoclass:: hovel_sdk.SessionRef
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.LineShellSession
   :members:
   :undoc-members:
   :show-inheritance:

Testing
-------

.. autoclass:: hovel_sdk.ModuleRPC
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.RPCError
   :members:
   :undoc-members:
   :show-inheritance:

.. autofunction:: hovel_sdk.drive_module

Logging
-------

.. autofunction:: hovel_sdk.setup_logging
