"""Shared error-handling helper for authwarden routers.

Every flow function raises typed AuthError subclasses (never raw
HTTPException, per the library's design rule). This decorator is the
single place that bridges flow-level exceptions into FastAPI's expected
HTTPException, so every route gets correct status codes automatically
without repeating try/except in every handler.
"""
from __future__ import annotations

import functools
from typing import Awaitable, Callable, TypeVar

from fastapi import HTTPException

from authwarden.exceptions import AuthError

T = TypeVar("T")


def handle_auth_errors(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
  """Decorator that converts AuthError into HTTPException with matching status code.

  Apply to every route handler that calls into authwarden flow functions.
  """
  @functools.wraps(func)
  async def wrapper(*args, **kwargs) -> T:
    try:
      return await func(*args, **kwargs)
    except AuthError as e:
      raise HTTPException(status_code=e.status_code, detail=e.detail)
  
  return wrapper