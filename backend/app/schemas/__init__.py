"""Pydantic request and response schemas exposed by the HTTP API.

Schemas are separate from the ORM models on purpose. A response model decides
what leaves the server, so adding a column to a table never silently starts
exposing it over HTTP.
"""
