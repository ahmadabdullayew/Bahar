"""Bounded tenant-scoped paginated record queries, with no external DB required."""
from types import SimpleNamespace
from contextlib import contextmanager
from unittest.mock import MagicMock
import pytest
from bahar.operations import OperationsService, OperationsError


class Result:
    def __init__(self, rows):
        self.rows = rows
    def mappings(self):
        return self
    def all(self):
        return self.rows


class FakeStore:
    def __init__(self, rows):
        self.context = SimpleNamespace(organization_id='org-scope', principal_id='user-scope')
        self.connection = MagicMock()
        self.connection.execute.return_value = Result(rows)

    @contextmanager
    def transaction(self):
        yield self.connection


def test_search_pagination_uses_organization_boundary_and_parameters():
    store = FakeStore([
        {'supplier_id': 'id-1', 'supplier_code': 'SUP-1'},
        {'supplier_id': 'id-2', 'supplier_code': 'SUP-2'},
        {'supplier_id': 'id-3', 'supplier_code': 'SUP-3'},
    ])
    page = OperationsService(store).list_records_page('suppliers', limit=2, offset=20,
        search="john%_\\' OR 1=1 --")
    assert page['has_more'] is True
    assert len(page['records']) == 2
    assert page['offset'] == 20
    query, parameters = store.connection.execute.call_args.args
    sql = str(query)
    assert 'WHERE organization_id = :org' in sql
    assert "john%_\\' OR 1=1 --" not in sql
    assert parameters['org'] == 'org-scope'
    assert parameters['fetch_limit'] == 3
    assert parameters['offset'] == 20
    assert '\\%' in parameters['pattern'] and '\\_' in parameters['pattern']


@pytest.mark.parametrize('limit,offset', [(0,0), (201,0), (10,-1), (10,1000001)])
def test_invalid_page_is_rejected(limit,offset):
    with pytest.raises(OperationsError):
        OperationsService(FakeStore([])).list_records_page('suppliers',limit=limit,offset=offset)


def test_unknown_resource_rejected():
    with pytest.raises(OperationsError):
        OperationsService(FakeStore([])).list_records_page('arbitrary_user_table')


def test_no_more_when_limited_page_has_no_overflow():
    page = OperationsService(FakeStore([{'supplier_id': 's'}])).list_records_page('suppliers',limit=5)
    assert page['has_more'] is False
