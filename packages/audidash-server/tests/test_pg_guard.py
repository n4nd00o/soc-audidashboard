"""The PostgreSQL fixture drops the `public` schema: it must refuse non-test databases."""

import pytest
from conftest import ensure_disposable_test_database


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://u:p@localhost:5432/audidash_test",
        "postgresql+psycopg://u:p@db.internal:5432/audidash_test",
        "postgresql+psycopg://u:p@localhost/testdb",
        "postgresql+psycopg://u:p@127.0.0.1/my-test-db",
    ],
)
def test_disposable_databases_are_accepted(url: str) -> None:
    ensure_disposable_test_database(url)


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://u:p@localhost:5432/audidash",
        "postgresql+psycopg://u:p@db.internal:5432/testdb",  # remote: needs the _test suffix
        "postgresql+psycopg://u:p@prod.example.com/audidash_test_backup",
        "postgresql+psycopg://u:p@localhost/",
    ],
)
def test_other_databases_are_refused(url: str) -> None:
    with pytest.raises(pytest.UsageError, match="_test"):
        ensure_disposable_test_database(url)
