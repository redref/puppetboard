import pytest
import json
import os
from datetime import datetime
from puppetboard import app
from pypuppetdb.types import Node, Report
from puppetboard import default_settings

from bs4 import BeautifulSoup


class MockDbQuery(object):
    def __init__(self, responses):
        self.responses = responses

    def get(self, method, **kws):
        resp = None
        if method in self.responses:
            resp = self.responses[method].pop(0)

            if 'validate' in resp:
                checks = resp['validate']['checks']
                resp = resp['validate']['data']
                for check in checks:
                    assert check in kws
                    expected_value = checks[check]
                    assert expected_value == kws[check]
        return resp


@pytest.fixture
def mock_puppetdb_environments(mocker):
    environemnts = [
        {'name': 'production'},
        {'name': 'staging'}
    ]
    return mocker.patch.object(app.puppetdb, 'environments',
                               return_value=environemnts)


@pytest.fixture
def mock_puppetdb_default_nodes(mocker):
    node_list = [
        Node('_', 'node-unreported',
             report_timestamp='2013-08-01T09:57:00.000Z',
             latest_report_hash='1234567',
             catalog_timestamp='2013-08-01T09:57:00.000Z',
             facts_timestamp='2013-08-01T09:57:00.000Z',
             status_report='unreported'),
        Node('_', 'node-changed',
             report_timestamp='2013-08-01T09:57:00.000Z',
             latest_report_hash='1234567',
             catalog_timestamp='2013-08-01T09:57:00.000Z',
             facts_timestamp='2013-08-01T09:57:00.000Z',
             status_report='changed'),
        Node('_', 'node-failed',
             report_timestamp='2013-08-01T09:57:00.000Z',
             latest_report_hash='1234567',
             catalog_timestamp='2013-08-01T09:57:00.000Z',
             facts_timestamp='2013-08-01T09:57:00.000Z',
             status_report='failed'),
        Node('_', 'node-noop',
             report_timestamp='2013-08-01T09:57:00.000Z',
             latest_report_hash='1234567',
             catalog_timestamp='2013-08-01T09:57:00.000Z',
             facts_timestamp='2013-08-01T09:57:00.000Z',
             status_report='noop'),
        Node('_', 'node-unchanged',
             report_timestamp='2013-08-01T09:57:00.000Z',
             latest_report_hash='1234567',
             catalog_timestamp='2013-08-01T09:57:00.000Z',
             facts_timestamp='2013-08-01T09:57:00.000Z',
             status_report='unchanged'),
    ]
    return mocker.patch.object(app.puppetdb, 'nodes',
                               return_value=iter(node_list))


@pytest.fixture
def input_data(request):
    data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             'data')
    data = None
    with open('%s/%s' % (data_path, request.function.__name__), "r") as fp:
        data = fp.read()
    return data


@pytest.fixture
def client():
    client = app.app.test_client()
    return client


def test_first_test():
    assert app is not None, ("%s" % reg.app)


def test_no_env(client, mock_puppetdb_environments):
    rv = client.get('/nonexsistenv/')

    assert rv.status_code == 404


def test_get_index(client, mocker,
                   mock_puppetdb_environments,
                   mock_puppetdb_default_nodes):
    query_data = {
        'nodes': [[{'count': 10}]],
        'resources': [[{'count': 40}]],
    }

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)
    rv = client.get('/')
    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'
    assert rv.status_code == 200


def test_index_all(client, mocker,
                   mock_puppetdb_environments,
                   mock_puppetdb_default_nodes):

    base_str = 'puppetlabs.puppetdb.population:'
    query_data = {
        'version': [{'version': '4.2.0'}],
        'mbean': [
            {
                'validate': {
                    'data': {'Value': '50'},
                    'checks': {
                        'path': '%sname=num-nodes' % base_str
                    }
                }
            },
            {
                'validate': {
                    'data': {'Value': '60'},
                    'checks': {
                        'path': '%sname=num-resources' % base_str
                    }
                }
            },
            {
                'validate': {
                    'data': {'Value': 60.3},
                    'checks': {
                        'path': '%sname=avg-resources-per-node' % base_str
                    }
                }
            }
        ]
    }
    dbquery = MockDbQuery(query_data)
    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)
    rv = client.get('/%2A/')

    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'
    vals = soup.find_all('h1',
                         {"class": "ui header darkblue no-margin-bottom"})

    assert len(vals) == 3
    assert vals[0].string == '50'
    assert vals[1].string == '60'
    assert vals[2].string == '        60'

    assert rv.status_code == 200


def test_index_all_older_puppetdb(client, mocker,
                                  mock_puppetdb_environments,
                                  mock_puppetdb_default_nodes):

    base_str = 'puppetlabs.puppetdb.population:type=default,'
    query_data = {
        'version': [{'version': '3.2.0'}],
        'mbean': [
            {
                'validate': {
                    'data': {'Value': '50'},
                    'checks': {
                        'path': '%sname=num-nodes' % base_str
                    }
                }
            },
            {
                'validate': {
                    'data': {'Value': '60'},
                    'checks': {
                        'path': '%sname=num-resources' % base_str
                    }
                }
            },
            {
                'validate': {
                    'data': {'Value': 60.3},
                    'checks': {
                        'path': '%sname=avg-resources-per-node' % base_str
                    }
                }
            }
        ]
    }
    dbquery = MockDbQuery(query_data)
    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)
    rv = client.get('/%2A/')

    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'
    vals = soup.find_all('h1',
                         {"class": "ui header darkblue no-margin-bottom"})

    assert len(vals) == 3
    assert vals[0].string == '50'
    assert vals[1].string == '60'
    assert vals[2].string == '        60'

    assert rv.status_code == 200


def test_index_division_by_zero(client, mocker):
    mock_puppetdb_environments(mocker)
    mock_puppetdb_default_nodes(mocker)

    query_data = {
        'nodes': [[{'count': 0}]],
        'resources': [[{'count': 40}]],
    }

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/')

    assert rv.status_code == 200

    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'

    vals = soup.find_all('h1',
                         {"class": "ui header darkblue no-margin-bottom"})
    assert len(vals) == 3
    assert vals[2].string == '0'


def test_offline_mode(client, mocker):
    app.app.config['OFFLINE_MODE'] = True

    mock_puppetdb_environments(mocker)
    mock_puppetdb_default_nodes(mocker)

    query_data = {
        'nodes': [[{'count': 10}]],
        'resources': [[{'count': 40}]],
    }

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)
    rv = client.get('/')
    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'
    for link in soup.find_all('link'):
        assert "//" not in link['href']

    for script in soup.find_all('script'):
        if "src" in script.attrs:
            assert "//" not in script['src']

    assert rv.status_code == 200


def test_default_node_view(client, mocker,
                           mock_puppetdb_environments,
                           mock_puppetdb_default_nodes):

    rv = client.get('/nodes')
    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'

    for label in ['failed', 'changed', 'unreported', 'noop']:
        vals = soup.find_all('a',
                             {"class": "ui %s label status" % label})
        assert len(vals) == 1
        assert 'node-%s' % (label) in vals[0].attrs['href']

    assert rv.status_code == 200


def test_radiator_view(client, mocker,
                       mock_puppetdb_environments,
                       mock_puppetdb_default_nodes):
    query_data = {
        'nodes': [[{'count': 10}]],
        'resources': [[{'count': 40}]],
    }

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/radiator')

    assert rv.status_code == 200

    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'
    assert soup.h1 != 'Not Found'
    total = soup.find(class_='total')

    assert '10' in total.text


def test_radiator_view_all(client, mocker,
                           mock_puppetdb_environments,
                           mock_puppetdb_default_nodes):
    base_str = 'puppetlabs.puppetdb.population:'
    query_data = {
        'version': [{'version': '4.2.0'}],
        'mbean': [
            {
                'validate': {
                    'data': {'Value': '50'},
                    'checks': {
                        'path': '%sname=num-nodes' % base_str
                    }
                }
            },
            {
                'validate': {
                    'data': {'Value': '60'},
                    'checks': {
                        'path': '%sname=num-resources' % base_str
                    }
                }
            },
            {
                'validate': {
                    'data': {'Value': 60.3},
                    'checks': {
                        'path': '%sname=avg-resources-per-node' % base_str
                    }
                }
            }
        ]
    }

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/%2A/radiator')

    assert rv.status_code == 200

    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'
    assert soup.h1 != 'Not Found'
    total = soup.find(class_='total')

    assert '50' in total.text


def test_radiator_view_all_old_version(client, mocker,
                                       mock_puppetdb_environments,
                                       mock_puppetdb_default_nodes):
    base_str = 'puppetlabs.puppetdb.population:type=default,'
    query_data = {
        'version': [{'version': '3.2.0'}],
        'mbean': [
            {
                'validate': {
                    'data': {'Value': '50'},
                    'checks': {
                        'path': '%sname=num-nodes' % base_str
                    }
                }
            },
            {
                'validate': {
                    'data': {'Value': '60'},
                    'checks': {
                        'path': '%sname=num-resources' % base_str
                    }
                }
            },
            {
                'validate': {
                    'data': {'Value': 60.3},
                    'checks': {
                        'path': '%sname=avg-resources-per-node' % base_str
                    }
                }
            }
        ]
    }

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/%2A/radiator')

    assert rv.status_code == 200

    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'
    assert soup.h1 != 'Not Found'
    total = soup.find(class_='total')

    assert '50' in total.text


def test_radiator_view_json(client, mocker,
                            mock_puppetdb_environments,
                            mock_puppetdb_default_nodes):
    query_data = {
        'nodes': [[{'count': 10}]],
        'resources': [[{'count': 40}]],
    }

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/radiator', headers={'Accept': 'application/json'})

    assert rv.status_code == 200
    json_data = json.loads(rv.data.decode('utf-8'))

    assert json_data['unreported'] == 1
    assert json_data['noop'] == 1
    assert json_data['failed'] == 1
    assert json_data['changed'] == 1
    assert json_data['unchanged'] == 1


def test_radiator_view_bad_env(client, mocker):
    mock_puppetdb_environments(mocker)
    mock_puppetdb_default_nodes(mocker)

    query_data = {
        'nodes': [[{'count': 10}]],
        'resources': [[{'count': 40}]],
    }

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/nothere/radiator')

    assert rv.status_code == 404
    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'
    assert soup.h1.text == 'Not Found'


def test_radiator_view_division_by_zero(client, mocker):
    mock_puppetdb_environments(mocker)
    mock_puppetdb_default_nodes(mocker)

    query_data = {
        'nodes': [[{'count': 0}]],
        'resources': [[{'count': 40}]],
    }

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/radiator')

    assert rv.status_code == 200

    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'

    total = soup.find(class_='total')
    assert '0' in total.text


def test_json_report_ok(client, mocker, input_data):
    mock_puppetdb_environments(mocker)
    mock_puppetdb_default_nodes(mocker)

    query_response = json.loads(input_data)

    query_data = {
        'reports': [
            {
                'validate': {
                    'data': query_response[:100],
                    'checks': {
                        'limit': 100,
                        'offset': 0
                    }
                }
            }
        ]
    }

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)
    app.puppetdb.last_total = 499

    rv = client.get('/reports/json')

    assert rv.status_code == 200
    result_json = json.loads(rv.data.decode('utf-8'))

    assert 'data' in result_json
    assert len(result_json['data']) == 100


def test_json_daily_reports_chart_ok(client, mocker):
    mock_puppetdb_environments(mocker)
    mock_puppetdb_default_nodes(mocker)

    query_data = {
        'reports': [
            [{'status': 'changed', 'count': 1}]
            for i in range(app.app.config['DAILY_REPORTS_CHART_DAYS'])
        ]
    }

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/daily_reports_chart.json')
    result_json = json.loads(rv.data.decode('utf-8'))

    assert 'result' in result_json
    assert (len(result_json['result']) ==
            app.app.config['DAILY_REPORTS_CHART_DAYS'])
    day_format = '%Y-%m-%d'
    cur_day = datetime.strptime(result_json['result'][0]['day'], day_format)
    for day in result_json['result'][1:]:
        next_day = datetime.strptime(day['day'], day_format)
        assert cur_day < next_day
        cur_day = next_day

    assert rv.status_code == 200


def test_catalogs_disabled(client, mocker,
                           mock_puppetdb_environments,
                           mock_puppetdb_default_nodes):
    app.app.config['ENABLE_CATALOG'] = False
    rv = client.get('/catalogs')
    assert rv.status_code == 403


def test_catalogs_view(client, mocker,
                       mock_puppetdb_environments,
                       mock_puppetdb_default_nodes):
    app.app.config['ENABLE_CATALOG'] = True
    rv = client.get('/catalogs')
    assert rv.status_code == 200
    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'


def test_catalogs_json(client, mocker,
                       mock_puppetdb_environments,
                       mock_puppetdb_default_nodes):
    app.app.config['ENABLE_CATALOG'] = True
    rv = client.get('/catalogs/json')
    assert rv.status_code == 200

    result_json = json.loads(rv.data.decode('utf-8'))
    assert 'data' in result_json

    for line in result_json['data']:
        assert len(line) == 3
        found_status = None
        for status in ['failed', 'changed', 'unchanged', 'noop', 'unreported']:
            val = BeautifulSoup(line[0], 'html.parser').find_all(
                'a', {"href": "/node/node-%s" % status})
            if len(val) == 1:
                found_status = status
                break
        assert found_status, 'Line does not match any known status'

        val = BeautifulSoup(line[2], 'html.parser').find_all(
            'form', {"method": "GET",
                     "action": "/catalogs/compare/node-%s" % found_status})
        assert len(val) == 1


def test_catalogs_json_compare(client, mocker,
                               mock_puppetdb_environments,
                               mock_puppetdb_default_nodes):
    app.app.config['ENABLE_CATALOG'] = True
    rv = client.get('/catalogs/compare/node-unreported/json')
    assert rv.status_code == 200

    result_json = json.loads(rv.data.decode('utf-8'))
    assert 'data' in result_json

    for line in result_json['data']:
        assert len(line) == 3
        found_status = None
        for status in ['failed', 'changed', 'unchanged', 'noop', 'unreported']:
            val = BeautifulSoup(line[0], 'html.parser').find_all(
                'a', {"href": "/node/node-%s" % status})
            if len(val) == 1:
                found_status = status
                break
        assert found_status, 'Line does not match any known status'

        val = BeautifulSoup(line[2], 'html.parser').find_all(
            'form', {"method": "GET",
                     "action": "/catalogs/compare/node-unreported...node-%s" %
                     found_status})
        assert len(val) == 1


def test_inventory_view(client, mocker, mock_puppetdb_environments):
    rv = client.get('/inventory')
    assert rv.status_code == 200
    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'


def test_inventory_json(client, mocker, mock_puppetdb_environments):
    facts = ['fqdn', 'ipaddress', 'lsbdistdescription', 'hardwaremodel',
             'kernelrelease', 'puppetversion']
    values = [
        ['node-1', 'X.X.X.X', 'os7', 'server', '4.3', 'X.X.X'],
        ['node-2', 'X.X.X.X', 'os5', 'server', '4.1', 'X.X.X'],
        ['node-3', 'X.X.X.X', 'os6', 'server', '4.2', 'X.X.X'],
        ['node-4', 'X.X.X.X', 'os4', 'server', '4.3', 'X.X.X'],
    ]
    query_data = {'facts': []}
    query_data['facts'].append([])

    for i, value in enumerate(values):
        for idx, column in enumerate(facts):
            query_data['facts'][0].append({
                'certname': value[0],
                'name': column,
                'value': value[idx],
                'environment': 'production'
            })

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/inventory/json')
    assert rv.status_code == 200
    result_json = json.loads(rv.data.decode('utf-8'))
    assert 'data' in result_json

    for value in values:
        for line in result_json['data']:
            if value[0] in line[0]:
                assert line[1:] == value[1:]
                break
        else:
            raise Exception("Input %s not found" % value)


def test_facts_view(client, mocker, mock_puppetdb_environments):
    query_data = {
        'fact-names': [[chr(i) for i in range(ord('a'), ord('z') + 1)]]
    }

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/facts')
    assert rv.status_code == 200
    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'

    searchable = soup.find('div', {'class': 'searchable'})
    vals = searchable.find_all('div', {'class': 'column'})
    assert len(vals) == 4


def test_fact_view_with_graph(client, mocker,
                              mock_puppetdb_environments,
                              mock_puppetdb_default_nodes):
    rv = client.get('/fact/architecture')
    assert rv.status_code == 200

    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'

    vals = soup.find_all('div', {"id": "factChart"})
    assert len(vals) == 1


def test_fact_view_without_graph(client, mocker,
                                 mock_puppetdb_environments,
                                 mock_puppetdb_default_nodes):
    rv = client.get('/%2A/fact/augeas')
    assert rv.status_code == 200

    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'

    vals = soup.find_all('div', {"id": "factChart"})
    assert len(vals) == 0


def test_fact_value_view(client, mocker,
                         mock_puppetdb_environments,
                         mock_puppetdb_default_nodes):
    rv = client.get('/fact/architecture/amd64')
    assert rv.status_code == 200

    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'

    vals = soup.find_all('div', {"id": "factChart"})
    assert len(vals) == 0


def test_node_view(client, mocker,
                   mock_puppetdb_environments,
                   mock_puppetdb_default_nodes):
    rv = client.get('/node/node-failed')
    assert rv.status_code == 200

    soup = BeautifulSoup(rv.data, 'html.parser')
    assert soup.title.contents[0] == 'Puppetboard'

    vals = soup.find_all('table', {"id": "facts_table"})
    assert len(vals) == 1

    vals = soup.find_all('table', {"id": "reports_table"})
    assert len(vals) == 1


def test_fact_json_with_graph(client, mocker,
                              mock_puppetdb_environments,
                              mock_puppetdb_default_nodes):
    values = ['a', 'b', 'b', 'd', True, 'a\nb']
    query_data = {'facts': []}
    query_data['facts'].append([])
    for i, value in enumerate(values):
        query_data['facts'][0].append({
            'certname': 'node-%s' % i,
            'name': 'architecture',
            'value': value,
            'environment': 'production'
        })

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/fact/architecture/json')
    assert rv.status_code == 200

    result_json = json.loads(rv.data.decode('utf-8'))

    assert 'data' in result_json
    assert len(result_json['data']) == 6
    for line in result_json['data']:
        assert len(line) == 2

    assert 'chart' in result_json
    assert len(result_json['chart']) == 5
    # Test group_by
    assert result_json['chart'][0]['value'] == 2


def test_fact_json_without_graph(client, mocker,
                                 mock_puppetdb_environments,
                                 mock_puppetdb_default_nodes):
    values = ['a', 'b', 'b', 'd']
    query_data = {'facts': []}
    query_data['facts'].append([])
    for i, value in enumerate(values):
        query_data['facts'][0].append({
            'certname': 'node-%s' % i,
            'name': 'architecture',
            'value': value,
            'environment': 'production'
        })

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/%2A/fact/augeas/json')
    assert rv.status_code == 200

    result_json = json.loads(rv.data.decode('utf-8'))

    assert 'data' in result_json
    assert len(result_json['data']) == 4
    for line in result_json['data']:
        assert len(line) == 2

    assert 'chart' not in result_json


def test_fact_value_json(client, mocker,
                         mock_puppetdb_environments,
                         mock_puppetdb_default_nodes):
    values = ['a', 'b', 'b', 'd']
    query_data = {'facts': []}
    query_data['facts'].append([])
    for i, value in enumerate(values):
        query_data['facts'][0].append({
            'certname': 'node-%s' % i,
            'name': 'architecture',
            'value': value,
            'environment': 'production'
        })

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/fact/architecture/amd64/json')
    assert rv.status_code == 200

    result_json = json.loads(rv.data.decode('utf-8'))

    assert 'data' in result_json
    assert len(result_json['data']) == 4
    for line in result_json['data']:
        assert len(line) == 1

    assert 'chart' not in result_json


def test_node_facts_json(client, mocker,
                         mock_puppetdb_environments,
                         mock_puppetdb_default_nodes):
    values = ['a', 'b', 'b', 'd']
    query_data = {'facts': []}
    query_data['facts'].append([])
    for i, value in enumerate(values):
        query_data['facts'][0].append({
            'certname': 'node-failed',
            'name': 'fact-%s' % i,
            'value': value,
            'environment': 'production'
        })

    dbquery = MockDbQuery(query_data)

    mocker.patch.object(app.puppetdb, '_query', side_effect=dbquery.get)

    rv = client.get('/node/node-failed/facts/json')
    assert rv.status_code == 200

    result_json = json.loads(rv.data.decode('utf-8'))

    assert 'data' in result_json
    assert len(result_json['data']) == 4
    for line in result_json['data']:
        assert len(line) == 2

    assert 'chart' not in result_json
