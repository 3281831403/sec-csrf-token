"""Pytest bootstrap for the offline CSRF exercise.

The test command is always run from the repository root, so the local ``csrf``
package is importable without installation or network access. No fixture is
defined here on purpose: a broken fixture must not turn red tests into errors.
"""
