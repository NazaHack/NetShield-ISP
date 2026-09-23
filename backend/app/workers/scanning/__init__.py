"""The asynchronous scanning engine.

The pipeline is deliberately split into four independently testable pieces:

* :mod:`app.workers.scanning.command` decides what may be scanned and builds the
  argument vector.
* :mod:`app.workers.scanning.runner` executes Nmap and bounds its resource use.
* :mod:`app.workers.scanning.parser` turns Nmap's XML into validated findings.
* :mod:`app.workers.scanning.diff` compares a scan against its predecessor.

:mod:`app.workers.scanning.repository` holds every database access the engine
performs, so that the tenant filter appears in one auditable place.
"""
