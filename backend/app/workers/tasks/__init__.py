"""Celery task modules.

Modules here are registered through ``TASK_MODULES`` in
``app.workers.celery_app`` and imported by Celery when the application is
finalised. They are deliberately not imported from this package's
``__init__``: doing so would create a circular import with the Celery app
that every task module depends on.
"""
