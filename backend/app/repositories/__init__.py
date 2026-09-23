"""Tenant-scoped data access for the HTTP API.

Every function that touches tenant-owned data takes the tenant identifier as a
required keyword argument and applies it to the statement. Collecting them here
means the isolation rule can be reviewed by reading one package rather than by
auditing every endpoint.

The scanning engine keeps its own synchronous repository under
``app.workers.scanning``. These are the asynchronous counterparts used by
FastAPI.
"""
