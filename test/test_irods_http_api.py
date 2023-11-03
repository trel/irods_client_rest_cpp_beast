import config

import json
import os
import requests
import socket
import sys
import time
import unittest
import http.client
import concurrent.futures

def setup_class(cls, opts):
    '''Initializes shared state needed by all test cases.

    This function is designed to be called in setUpClass().

    Arguments:
    cls -- The class to attach state to.
    opts -- A dict containing options for controlling the behavior of the function.
    '''

    # Used as a signal for determining whether setUpClass() succeeded or not.
    # If this results in being True, no tests should be allowed to run.
    cls._class_init_error = False
    cls._remove_rodsuser = False

    if config.test_config.get('host', None) == None:
        #print('Missing configuration property: host') # Debug
        cls._class_init_error = True
        return

    if config.test_config.get('port', None) == None:
        #print('Missing configuration property: port') # Debug
        cls._class_init_error = True
        return

    if config.test_config.get('url_base', None) == None:
        #print('Missing configuration property: url_base') # Debug
        cls._class_init_error = True
        return

    cls.url_base = f"http://{config.test_config['host']}:{config.test_config['port']}{config.test_config['url_base']}"
    cls.url_endpoint = f'{cls.url_base}/{opts["endpoint_name"]}'

    cls.zone_name = config.test_config['irods_zone']
    cls.server_hostname = config.test_config['irods_server_hostname']

    # create_rodsuser cannot be honored if init_rodsadmin is set to False.
    # Therefore, return immediately.
    if not opts.get('init_rodsadmin', True):
        #print('init_rodsadmin is False. Class setup complete.') # Debug
        return

    # Authenticate as a rodsadmin and store the bearer token.
    cls.rodsadmin_username = config.test_config['rodsadmin']['username']
    r = requests.post(f'{cls.url_base}/authenticate', auth=(cls.rodsadmin_username, config.test_config['rodsadmin']['password']))
    #print(r.content) # Debug
    if r.status_code != 200:
        cls._class_init_error = True
        #print(f'Failed to authenticate as rodsadmin [{cls.rodsadmin_username}].') # Debug
        return
    cls.rodsadmin_bearer_token = r.text

    # Create a rodsuser for testing.
    if not opts.get('create_rodsuser', True):
        #print('create_rodsuser is False. Class setup complete.') # Debug
        return

    cls.rodsuser_username = config.test_config['rodsuser']['username']
    headers = {'Authorization': f'Bearer {cls.rodsadmin_bearer_token}'}
    r = requests.post(f'{cls.url_base}/users-groups', headers=headers, data={
        'op': 'create_user',
        'name': cls.rodsuser_username,
        'zone': cls.zone_name
    })
    #print(r.content) # Debug
    if r.status_code != 200:
        cls._class_init_error = True
        #print(f'Failed to create rodsuser [{cls.rodsuser_username}].') # Debug
        return
    cls._remove_rodsuser = True

    # Set the rodsuser's password.
    r = requests.post(f'{cls.url_base}/users-groups', headers=headers, data={
        'op': 'set_password',
        'name': cls.rodsuser_username,
        'zone': cls.zone_name,
        'new-password': config.test_config['rodsuser']['password']
    })
    #print(r.content) # Debug
    if r.status_code != 200:
        cls._class_init_error = True
        #print(f'Failed to set password for rodsuser [{cls.rodsuser_username}].') # Debug
        return

    # Authenticate as the rodsuser and store the bearer token.
    r = requests.post(f'{cls.url_base}/authenticate', auth=(cls.rodsuser_username, config.test_config['rodsuser']['password']))
    #print(r.content) # Debug
    if r.status_code != 200:
        cls._class_init_error = True
        #print(f'Failed to authenticate as rodsuser [{cls.rodsuser_username}].') # Debug
        return
    cls.rodsuser_bearer_token = r.text

    #print('Class setup complete.') # Debug

def tear_down_class(cls):
    if cls._class_init_error:
        return

    if not cls._remove_rodsuser:
        return

    headers = {'Authorization': f'Bearer {cls.rodsadmin_bearer_token}'}
    r = requests.post(f'{cls.url_base}/users-groups', headers=headers, data={
        'op': 'remove_user',
        'name': cls.rodsuser_username,
        'zone': cls.zone_name
    })
    #print(r.content) # Debug
    if r.status_code != 200:
        #print(f'Failed to remove rodsuser [{cls.rodsuser_username}].') # Debug
        return

class test_collections_endpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_class(cls, {'endpoint_name': 'collections'})

    @classmethod
    def tearDownClass(cls):
        tear_down_class(cls)

    def setUp(self):
        self.assertFalse(self._class_init_error, 'Class initialization failed. Cannot continue.')

    def test_common_operations(self):
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}
        collection_path = os.path.join('/', self.zone_name, 'home', self.rodsuser_username, 'common_ops')

        # Create a new collection.
        data = {'op': 'create', 'lpath': collection_path}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        stat_info = r.json()
        self.assertEqual(stat_info['irods_response']['status_code'], 0)

        # Stat the collection to show that it exists.
        params = {'op': 'stat', 'lpath': collection_path}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        stat_info = r.json()
        self.assertEqual(stat_info['irods_response']['status_code'], 0)

        # Rename the collection.
        new_collection_path = collection_path + '.renamed'
        data = {'op': 'rename', 'old-lpath': collection_path, 'new-lpath': new_collection_path}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        # Stat the original collection to show that it does not exist.
        params = {'op': 'stat', 'lpath': collection_path}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        self.assertEqual(r.status_code, 400)

        # Stat the new collection to show that it does exist.
        params = {'op': 'stat', 'lpath': new_collection_path}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        self.assertEqual(r.status_code, 200)

        # Give another user permission to read the object.
        data = {
            'op': 'set_permission',
            'lpath': new_collection_path,
            'entity-name': self.rodsadmin_username,
            'permission': 'read_object'
        }
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        # Show that the rodsadmin user now has read permission on the collection.
        params = {'op': 'stat', 'lpath': new_collection_path}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        stat_info = r.json()
        self.assertEqual(stat_info['irods_response']['status_code'], 0)
        self.assertEqual(len(stat_info['permissions']), 2)

        perms = stat_info['permissions']
        perm = perms[0] if perms[0]['name'] == self.rodsadmin_username else perms[1]
        self.assertEqual(perm['name'], self.rodsadmin_username)
        self.assertEqual(perm['zone'], self.zone_name)
        self.assertEqual(perm['type'], 'rodsadmin')
        self.assertEqual(perm['perm'], 'read_object')

        # Remove the collection.
        data = {'op': 'remove', 'lpath': new_collection_path}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        # Stat the collection to show that it does not exist.
        params = {'op': 'stat', 'lpath': new_collection_path}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 400)

        stat_info = r.json()
        self.assertEqual(stat_info['irods_response']['status_code'], -170000)

    def test_stat_operation_returns_expected_json_structure(self):
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}
        params = {'op': 'stat', 'lpath': os.path.join('/', self.zone_name, 'home', self.rodsuser_username)}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        stat_info = r.json()
        self.assertEqual(stat_info['irods_response']['status_code'], 0)
        self.assertEqual(stat_info['type'], 'collection')
        self.assertEqual(stat_info['inheritance_enabled'], False)
        self.assertEqual(stat_info['registered'], True)
        self.assertGreater(int(stat_info['modified_at']), 0)
        self.assertGreater(len(stat_info['permissions']), 0)
        self.assertEqual(stat_info['permissions'][0]['name'], self.rodsuser_username)
        self.assertEqual(stat_info['permissions'][0]['zone'], self.zone_name)
        self.assertEqual(stat_info['permissions'][0]['type'], 'rodsuser')
        self.assertEqual(stat_info['permissions'][0]['perm'], 'own')

    def test_stat_operation_returns_error_when_executed_on_object_that_does_not_exist(self):
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}

        # Stat a non-existent collection.
        r = requests.get(self.url_endpoint, headers=headers, params={
            'op': 'stat',
            'lpath': os.path.join('/', self.zone_name, 'home', self.rodsuser_username, 'does_not_exist')
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()['irods_response']['status_code'], -170000)

    def test_list_operation(self):
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}
        home_collection = os.path.join('/', self.zone_name, 'home', self.rodsuser_username)

        # Create nested collections.
        collection = os.path.join(home_collection, 'c0', 'c1', 'c2')
        r = requests.post(self.url_endpoint, headers=headers, data={'op': 'create', 'lpath': collection})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Create one data object in each collection.
        data_objects = [
            os.path.join(home_collection, 'c0', 'd0'),
            os.path.join(home_collection, 'c0', 'c1', 'd1'),
            os.path.join(home_collection, 'c0', 'c1', 'c2', 'd2')
        ]

        for name in data_objects:
            data_object = os.path.join('/', self.zone_name, 'home', self.rodsuser_username, name)
            r = requests.post(f'{self.url_base}/data-objects', headers=headers, data={'op': 'touch', 'lpath': data_object})
            #print(r.content) # Debug
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # List only the contents of the home collection.
        r = requests.get(self.url_endpoint, headers=headers, params={'op': 'list', 'lpath': home_collection})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(result['entries'], [os.path.dirname(data_objects[0])])

        # List the home collection recursively.
        r = requests.get(self.url_endpoint, headers=headers, params={'op': 'list', 'lpath': home_collection, 'recurse': 1})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        result['entries'].sort()
        expected_result = [
            os.path.dirname(data_objects[0]),
            os.path.dirname(data_objects[1]),
            os.path.dirname(data_objects[2]),
            data_objects[0],
            data_objects[1],
            data_objects[2]
        ]
        expected_result.sort()
        self.assertEqual(result['entries'], expected_result)

        # Remove collections.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'remove',
            'lpath': os.path.dirname(data_objects[0]),
            'recurse': 1,
            'no-trash': 1
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

    def test_modifying_metadata_atomically(self):
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}
        collection = os.path.join('/', self.zone_name, 'home', self.rodsuser_username)

        # Add metadata to the collection.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'modify_metadata',
            'lpath': collection,
            'operations': json.dumps([
                {
                    'operation': 'add',
                    'attribute': 'a1',
                    'value': 'v1',
                    'units': 'u1'
                }
            ])
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the metadata exists on the collection.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': "select COLL_NAME where META_COLL_ATTR_NAME = 'a1' and META_COLL_ATTR_VALUE = 'v1' and META_COLL_ATTR_UNITS = 'u1'"
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(result['rows'][0][0], collection)

        # Remove the metadata from the collection.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'modify_metadata',
            'lpath': collection,
            'operations': json.dumps([
                {
                    'operation': 'remove',
                    'attribute': 'a1',
                    'value': 'v1',
                    'units': 'u1'
                }
            ])
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the metadata no longer exists on the collection.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': "select COLL_NAME where META_COLL_ATTR_NAME = 'a1' and META_COLL_ATTR_VALUE = 'v1' and META_COLL_ATTR_UNITS = 'u1'"
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['rows']), 0)

    def test_modifying_permissions_atomically(self):
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}
        collection = os.path.join('/', self.zone_name, 'home', self.rodsuser_username)

        # Give the rodsadmin read permission on the rodsuser's home collection.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'modify_permissions',
            'lpath': collection,
            'operations': json.dumps([
                {
                    'entity_name': self.rodsadmin_username,
                    'acl': 'read'
                }
            ])
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the rodsadmin now has permission to read the collection.
        r = requests.get(self.url_endpoint, headers=headers, params={
            'op': 'stat',
            'lpath': collection
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['permissions']), 2)
        #self.assertEqual(result['permissions'][0]['name'], self.rodsuser_username)
        #self.assertEqual(result['permissions'][0]['zone'], self.zone_name)
        #self.assertEqual(result['permissions'][0]['type'], 'rodsuser')
        #self.assertEqual(result['permissions'][0]['perm'], 'own')

        # Remove rodsadmin's permission on the collection.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'modify_permissions',
            'lpath': collection,
            'operations': json.dumps([
                {
                    'entity_name': self.rodsadmin_username,
                    'acl': 'null'
                }
            ])
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the permissions have been removed.
        r = requests.get(self.url_endpoint, headers=headers, params={
            'op': 'stat',
            'lpath': collection
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['permissions']), 1)
        #self.assertEqual(result['permissions'][0]['name'], self.rodsuser_username)
        #self.assertEqual(result['permissions'][0]['zone'], self.zone_name)
        #self.assertEqual(result['permissions'][0]['type'], 'rodsuser')
        #self.assertEqual(result['permissions'][0]['perm'], 'own')

    @unittest.skip('Test needs to be implemented.')
    def test_return_error_on_missing_parameters(self):
        pass

class test_data_objects_endpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_class(cls, {'endpoint_name': 'data-objects'})

    @classmethod
    def tearDownClass(cls):
        tear_down_class(cls)

    def setUp(self):
        self.assertFalse(self._class_init_error, 'Class initialization failed. Cannot continue.')

    def test_common_operations(self):
        rodsadmin_headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}
        rodsuser_headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}

        # Create a unixfilesystem resource.
        resc_name = 'test_ufs_common_ops_resc'
        r = requests.post(f'{self.url_base}/resources', headers=rodsadmin_headers, data={
            'op': 'create',
            'name': resc_name,
            'type': 'unixfilesystem',
            'host': self.server_hostname,
            'vault-path': os.path.join('/tmp', f'{resc_name}_vault')
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Create a non-empty data object.
        data_object = os.path.join('/', self.zone_name, 'home', self.rodsuser_username, 'common_ops.txt')
        content = 'hello, this message was written via the iRODS HTTP API!'
        r = requests.post(self.url_endpoint, headers=rodsuser_headers, data={
            'op': 'write',
            'lpath': data_object,
            'bytes': content,
            'count': len(content)
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Replicate the data object.
        r = requests.post(self.url_endpoint, headers=rodsuser_headers, data={
            'op': 'replicate',
            'lpath': data_object,
            'dst-resource': resc_name
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show there are two replicas.
        coll_name = os.path.dirname(data_object)
        data_name = os.path.basename(data_object)
        r = requests.get(f'{self.url_base}/query', headers=rodsuser_headers, params={
            'op': 'execute_genquery',
            'query': f"select DATA_NAME, RESC_NAME where COLL_NAME = '{coll_name}' and DATA_NAME = '{data_name}'"
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['rows']), 2)

        # Trim the first replica.
        r = requests.post(self.url_endpoint, headers=rodsuser_headers, data={
            'op': 'trim',
            'lpath': data_object,
            'replica-number': 0
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Rename the data object.
        data_object_renamed = f'{data_object}.renamed'
        r = requests.post(self.url_endpoint, headers=rodsuser_headers, data={
            'op': 'rename',
            'old-lpath': data_object,
            'new-lpath': data_object_renamed,
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Copy the data object.
        data_object_copied = f'{data_object}.copied'
        r = requests.post(self.url_endpoint, headers=rodsuser_headers, data={
            'op': 'copy',
            'src-lpath': data_object_renamed,
            'dst-lpath': data_object_copied,
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Modify permissions on the data object.
        r = requests.post(self.url_endpoint, headers=rodsuser_headers, data={
            'op': 'set_permission',
            'lpath': data_object_copied,
            'entity-name': self.rodsadmin_username,
            'permission': 'read_object'
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the permissions were updated.
        r = requests.get(self.url_endpoint, headers=rodsuser_headers, params={'op': 'stat', 'lpath': data_object_copied})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertIn({
            'name': self.rodsadmin_username,
            'zone': self.zone_name,
            'type': 'rodsadmin',
            'perm': 'read_object'
        }, result['permissions'])

        # Remove the data objects.
        for data_object in [data_object_renamed, data_object_copied]:
            with self.subTest(f'Removing [{data_object}]'):
                r = requests.post(self.url_endpoint, headers=rodsuser_headers, data={'op': 'remove', 'lpath': data_object, 'no-trash': 1})
                #print(r.content) # Debug
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Remove the resource.
        r = requests.post(f'{self.url_base}/resources', headers=rodsadmin_headers, data={'op': 'remove', 'name': resc_name})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

    def test_registering_a_new_data_object(self):
        rodsadmin_headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}

        # Create a local file.
        filename = 'newly_registered_file.txt'
        physical_path = f'/tmp/{filename}'
        with open(physical_path, 'w') as f:
            f.write('data')

        try:
            # Show the data object we want to create via registration does not exist.
            data_object = f'/{self.zone_name}/home/{self.rodsadmin_username}/{filename}'
            r = requests.get(self.url_endpoint, headers=rodsadmin_headers, params={
                'op': 'stat',
                'lpath': data_object
            })
            #print(r.content) # Debug
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.json()['irods_response']['status_code'], -171000)

            # Register the local file into the catalog as a new data object.
            # We know we're registering a new data object because the "as-additional-replica"
            # parameter isn't set to 1.
            resource = 'demoResc'
            r = requests.post(self.url_endpoint, headers=rodsadmin_headers, data={
                'op': 'register',
                'lpath': data_object,
                'ppath': physical_path,
                'resource': resource
            })
            #print(r.content) # Debug
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()['irods_response']['status_code'], 0)

            # Show a new data object exists with the expected replica information.
            r = requests.get(f'{self.url_base}/query', headers=rodsadmin_headers, params={
                'op': 'execute_genquery',
                'query': f"select COLL_NAME, DATA_NAME, DATA_PATH, RESC_NAME where COLL_NAME = '{os.path.dirname(data_object)}' and DATA_NAME = '{filename}'"
            })
            #print(r.content) # Debug
            self.assertEqual(r.status_code, 200)
            result = r.json()
            self.assertEqual(result['irods_response']['status_code'], 0)
            self.assertEqual(len(result['rows']), 1)
            self.assertEqual(result['rows'][0][0], os.path.dirname(data_object))
            self.assertEqual(result['rows'][0][1], filename)
            self.assertEqual(result['rows'][0][2], physical_path)
            self.assertEqual(result['rows'][0][3], resource)

        finally:
            # Remove the data object by unregistering it.
            r = requests.post(self.url_endpoint, headers=rodsadmin_headers, data={
                'op': 'remove',
                'lpath': data_object,
                'unregister': 1
            })
            #print(r.content) # Debug

    def test_registering_an_additional_replica_for_an_existing_data_object(self):
        rodsadmin_headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}

        # The name of the resource we'll use to register an additional replica under.
        other_resource = 'test_registration_resc'

        try:
            # Create a non-empty data object.
            filename = 'newly_registered_replica.txt'
            data_object = f'/{self.zone_name}/home/{self.rodsadmin_username}/{filename}'
            content = 'hello, this message was written via the iRODS HTTP API!'
            r = requests.post(self.url_endpoint, headers=rodsadmin_headers, data={
                'op': 'write',
                'lpath': data_object,
                'bytes': content,
                'count': len(content)
            })
            #print(r.content) # Debug
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()['irods_response']['status_code'], 0)

            # Create a new unixfilesystem resource.
            r = requests.post(f'{self.url_base}/resources', headers=rodsadmin_headers, data={
                'op': 'create',
                'name': other_resource,
                'type': 'unixfilesystem',
                'host': self.server_hostname,
                'vault-path': os.path.join('/tmp', f'{other_resource}_vault')
            })
            #print(r.content) # Debug
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()['irods_response']['status_code'], 0)

            # Create a local file.
            physical_path = f'/tmp/{filename}'
            with open(physical_path, 'w') as f:
                f.write('some data')

            # Register the local file into the catalog as a new replica of the data object.
            r = requests.post(self.url_endpoint, headers=rodsadmin_headers, data={
                'op': 'register',
                'lpath': data_object,
                'ppath': physical_path,
                'resource': other_resource,
                'as-additional-replica': 1
            })
            #print(r.content) # Debug
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()['irods_response']['status_code'], 0)

            # Show a new replica exists with the expected replica information.
            r = requests.get(f'{self.url_base}/query', headers=rodsadmin_headers, params={
                'op': 'execute_genquery',
                'query': 'select COLL_NAME, DATA_NAME, DATA_PATH, RESC_NAME ' +
                         f"where COLL_NAME = '{os.path.dirname(data_object)}' and DATA_NAME = '{filename}' and DATA_REPL_NUM = '1'"
            })
            #print(r.content) # Debug
            self.assertEqual(r.status_code, 200)
            result = r.json()
            self.assertEqual(result['irods_response']['status_code'], 0)
            self.assertEqual(len(result['rows']), 1)
            self.assertEqual(result['rows'][0][0], os.path.dirname(data_object))
            self.assertEqual(result['rows'][0][1], filename)
            self.assertEqual(result['rows'][0][2], physical_path)
            self.assertEqual(result['rows'][0][3], other_resource)

        finally:
            # Remove the data object by unregistering it.
            r = requests.post(self.url_endpoint, headers=rodsadmin_headers, data={
                'op': 'remove',
                'lpath': data_object,
                'no-trash': 1
            })
            #print(r.content) # Debug

            # Remove the unixfilesystem resource.
            r = requests.post(f'{self.url_base}/resources', headers=rodsadmin_headers, data={
                'op': 'remove',
                'name': other_resource
            })
            #print(r.content) # Debug

    def test_touch_operation_reports_error_when_given_a_path_to_a_collection(self):
        rodsuser_headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}
        r = requests.post(self.url_endpoint, headers=rodsuser_headers, data={
            'op': 'touch',
            'lpath': f'/{self.zone_name}/home/{self.rodsuser_username}'
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()['irods_response']['status_code'], -171000)

    def multipart_form_data_upload(self, **args):
        boundary = '------testing_http_api------'

        body = ''

        for fname, fvalue in args['fields'].items():
            body += f'--{boundary}\r\n'
            body += f'Content-Disposition: form-data; name={fname}\r\n\r\n'
            body += f'{fvalue}\r\n'

        body += f'--{boundary}\r\n'
        body += f'Content-Disposition: form-data; name=bytes\r\n'
        body += f'Content-Type: application/octet-stream\r\n'
        body += f"Content-Length: {len(args['bytes'])}\r\n"
        body += '\r\n'
        body += f"{args['bytes']}\r\n"

        body += f'--{boundary}--\r\n'

        #print('body = ' + body) # Debug

        conn = http.client.HTTPConnection(config.test_config['host'], config.test_config['port'])
        conn.request('POST', config.test_config['url_base'] + '/data-objects', bytes(body, 'utf-8'), {
            'Authorization': f"Bearer {args['bearer_token']}",
            'Content-Type': f'multipart/form-data; boundary={boundary}'
        })

        response = conn.getresponse()
        result = json.loads(response.read().decode('utf-8'))
        #print(result) # Debug
        conn.close()

        self.assertEqual(response.status, 200)

        return result

    def test_parallel_writes(self):
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}

        # Tell the server we're about to do a parallel write.
        data_object = os.path.join('/', self.zone_name, 'home', self.rodsuser_username, 'parallel_write.txt')
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'parallel_write_init',
            'lpath': data_object,
            'stream-count': 3
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        parallel_write_handle = result['parallel_write_handle']

        # Write to the data object using the parallel write handle.
        futures = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            for e in enumerate(['A', 'B', 'C']):
                count = 10
                futures.append(executor.submit(self.multipart_form_data_upload, **{
                    'bearer_token': self.rodsuser_bearer_token,
                    'fields': {
                        'op': 'write',
                        'parallel-write-handle': parallel_write_handle,
                        'offset': e[0] * count,
                        'count': count,
                        'stream-index': e[0]
                    },
                    'bytes': e[1] * count
                }))

            for f in concurrent.futures.as_completed(futures):
                result = f.result()
                #print(result) # Debug
                self.assertEqual(result['irods_response']['status_code'], 0)

        # End the parallel write.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'parallel_write_shutdown',
            'parallel-write-handle': parallel_write_handle
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Read the contents of the data object and show it contains exactly what we expect.
        r = requests.get(self.url_endpoint, headers=headers, params={
            'op': 'read',
            'lpath': data_object,
            'count': 30
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content.decode('utf-8'), 'A' * 10 + 'B' * 10 + 'C' * 10)

        # Remove the data object.
        r = requests.post(self.url_endpoint, headers=headers, data={'op': 'remove', 'lpath': data_object, 'no-trash': 1})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

    def test_modifying_metadata_atomically(self):
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}

        # Create a data object.
        data_object = os.path.join('/', self.zone_name, 'home', self.rodsuser_username, 'for_atomic_metadata.txt')
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'touch',
            'lpath': data_object
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Add metadata to the home data object.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'modify_metadata',
            'lpath': data_object,
            'operations': json.dumps([
                {
                    'operation': 'add',
                    'attribute': 'a1',
                    'value': 'v1',
                    'units': 'u1'
                }
            ])
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the metadata exists on the data object.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': "select COLL_NAME, DATA_NAME where META_DATA_ATTR_NAME = 'a1' and META_DATA_ATTR_VALUE = 'v1' and META_DATA_ATTR_UNITS = 'u1'"
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(result['rows'][0][0], os.path.dirname(data_object))
        self.assertEqual(result['rows'][0][1], os.path.basename(data_object))

        # Remove the metadata from the data object.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'modify_metadata',
            'lpath': data_object,
            'operations': json.dumps([
                {
                    'operation': 'remove',
                    'attribute': 'a1',
                    'value': 'v1',
                    'units': 'u1'
                }
            ])
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the metadata no longer exists on the data object.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': "select COLL_NAME, DATA_NAME where META_DATA_ATTR_NAME = 'a1' and META_DATA_ATTR_VALUE = 'v1' and META_DATA_ATTR_UNITS = 'u1'"
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['rows']), 0)

        # Remove the data object.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'remove',
            'lpath': data_object,
            'no-trash': 1
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

    def test_modifying_permissions_atomically(self):
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}

        # Create a data object.
        data_object = os.path.join('/', self.zone_name, 'home', self.rodsuser_username, 'for_atomic_acls.txt')
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'touch',
            'lpath': data_object
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Give the rodsadmin read permission on the data object.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'modify_permissions',
            'lpath': data_object,
            'operations': json.dumps([
                {
                    'entity_name': self.rodsadmin_username,
                    'acl': 'read'
                }
            ])
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the rodsadmin now has permission to read the data object.
        r = requests.get(self.url_endpoint, headers=headers, params={
            'op': 'stat',
            'lpath': data_object
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['permissions']), 2)
        #self.assertEqual(result['permissions'][0]['name'], self.rodsuser_username)
        #self.assertEqual(result['permissions'][0]['zone'], self.zone_name)
        #self.assertEqual(result['permissions'][0]['type'], 'rodsuser')
        #self.assertEqual(result['permissions'][0]['perm'], 'own')

        # Remove rodsadmin's permission on the data object.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'modify_permissions',
            'lpath': data_object,
            'operations': json.dumps([
                {
                    'entity_name': self.rodsadmin_username,
                    'acl': 'null'
                }
            ])
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the permissions have been removed.
        r = requests.get(self.url_endpoint, headers=headers, params={
            'op': 'stat',
            'lpath': data_object
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['permissions']), 1)
        #self.assertEqual(result['permissions'][0]['name'], self.rodsuser_username)
        #self.assertEqual(result['permissions'][0]['zone'], self.zone_name)
        #self.assertEqual(result['permissions'][0]['type'], 'rodsuser')
        #self.assertEqual(result['permissions'][0]['perm'], 'own')

        # Remove the data object.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'remove',
            'lpath': data_object,
            'no-trash': 1
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

    def test_modifying_replica_properties(self):
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}

        # Create a data object.
        data_object = os.path.join('/', self.zone_name, 'home', self.rodsadmin_username, 'modrepl.txt')
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'touch',
            'lpath': data_object
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the replica is currently marked as good and has a size of 0.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': f"select DATA_REPL_STATUS, DATA_SIZE where COLL_NAME = '{os.path.dirname(data_object)}' and DATA_NAME = '{os.path.basename(data_object)}'"
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(result['rows'][0][0], '1')
        self.assertEqual(result['rows'][0][1], '0')

        # Change the replica's status and data size using the modify_replica operation.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'modify_replica',
            'lpath': data_object,
            'replica-number': 0,
            'new-data-replica-status': 0,
            'new-data-size': 15
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the replica's status and size has changed in the catalog.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': f"select DATA_REPL_STATUS, DATA_SIZE where COLL_NAME = '{os.path.dirname(data_object)}' and DATA_NAME = '{os.path.basename(data_object)}'"
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(result['rows'][0][0], '0')
        self.assertEqual(result['rows'][0][1], '15')

        # Remove the data object.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'remove',
            'lpath': data_object,
            'no-trash': 1
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

    @unittest.skip('Test needs to be implemented.')
    def test_return_error_on_missing_parameters(self):
        pass

class test_information_endpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_class(cls, {'endpoint_name': 'info', 'init_rodsadmin': False})

    def setUp(self):
        self.assertFalse(self._class_init_error, 'Class initialization failed. Cannot continue.')

    def test_expected_properties_exist_in_json_structure(self):
        r = requests.get(self.url_endpoint)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        info = r.json()
        self.assertIn('api_version', info)
        self.assertIn('build', info)
        self.assertIn('irods_zone', info)
        self.assertIn('genquery2_enabled', info)
        self.assertIn('max_http_request_size_in_bytes', info)
        self.assertIn('max_number_of_parallel_write_streams', info)
        self.assertIn('max_number_of_rows_per_catalog_query', info)

class test_query_endpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_class(cls, {'endpoint_name': 'query'})

    @classmethod
    def tearDownClass(cls):
        tear_down_class(cls)

    def setUp(self):
        self.assertFalse(self._class_init_error, 'Class initialization failed. Cannot continue.')

    def test_support_for_genquery1(self):
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}
        params = {'op': 'execute_genquery', 'parser': 'genquery1', 'query': 'select COLL_NAME'}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertGreater(len(result['rows']), 0)

    def test_genquery2_query(self):
        if not config.test_config.get('run_genquery2_tests', False):
            self.skipTest('GenQuery2 tests not enabled. Check [run_genquery2_tests] in test configuration file.')

        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}
        r = requests.get(self.url_endpoint, headers=headers, params={
            'op': 'execute_genquery',
            'parser': 'genquery2',
            'query': 'select COLL_NAME'
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertGreater(len(result['rows']), 0)
        self.assertIn(['/tempZone/home/http_api'], result['rows'])
        self.assertIn(['/tempZone/trash/home/http_api'], result['rows'])

    def test_genquery2_sql_only_option(self):
        if not config.test_config.get('run_genquery2_tests', False):
            self.skipTest('GenQuery2 tests not enabled. Check [run_genquery2_tests] in test configuration file.')

        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}
        r = requests.get(self.url_endpoint, headers=headers, params={
            'op': 'execute_genquery',
            'parser': 'genquery2',
            'query': 'select COLL_NAME',
            'sql-only': 1
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertGreater(len(result['sql']), 0)

    def test_support_for_specific_queries(self):
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}
        collection_path = os.path.join('/', self.zone_name, 'home', self.rodsuser_username, 'common_ops')
        r = requests.get(self.url_endpoint, headers=headers, params={
            'op': 'execute_specific_query',
            'name': 'ShowCollAcls',
            'args': collection_path,
            'count': 100
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertGreaterEqual(len(result['rows']), 0)

class test_resources_endpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_class(cls, {'endpoint_name': 'resources', 'create_rodsuser': False})

    @classmethod
    def tearDownClass(cls):
        tear_down_class(cls)

    def setUp(self):
        self.assertFalse(self._class_init_error, 'Class initialization failed. Cannot continue.')

    def test_common_operations(self):
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}

        hostname = self.server_hostname
        resc_repl = 'test_repl'
        resc_ufs0 = 'test_ufs0'
        resc_ufs1 = 'test_ufs1'

        # Create three resources (replication w/ two unixfilesystem resources).
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'create',
            'name': resc_repl,
            'type': 'replication'
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)

        # Show the replication resource was created.
        r = requests.get(self.url_endpoint, headers=headers, params={'op': 'stat', 'name': resc_repl})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(result['exists'], True)
        self.assertIn('id', result['info'])
        self.assertEqual(result['info']['name'], resc_repl)
        self.assertEqual(result['info']['type'], 'replication')
        self.assertEqual(result['info']['zone'], self.zone_name)
        self.assertEqual(result['info']['host'], 'EMPTY_RESC_HOST')
        self.assertEqual(result['info']['vault_path'], 'EMPTY_RESC_PATH')
        self.assertIn('status', result['info'])
        self.assertIn('context', result['info'])
        self.assertIn('comments', result['info'])
        self.assertIn('information', result['info'])
        self.assertIn('free_space', result['info'])
        self.assertIn('free_space_last_modified', result['info'])
        self.assertEqual(result['info']['parent_id'], '')
        self.assertIn('created', result['info'])
        self.assertIn('last_modified', result['info'])
        self.assertIn('last_modified_millis', result['info'])

        # Capture the replication resource's id.
        # This resource is going to be the parent of the unixfilesystem resources.
        # This value is needed to verify the relationship.
        resc_repl_id = result['info']['id']

        for resc_name in [resc_ufs0, resc_ufs1]:
            with self.subTest(f'Create and attach resource [{resc_name}] to [{resc_repl}]'):
                vault_path = os.path.join('/tmp', f'{resc_name}_vault')

                # Create a unixfilesystem resource.
                r = requests.post(self.url_endpoint, headers=headers, data={
                    'op': 'create',
                    'name': resc_name,
                    'type': 'unixfilesystem',
                    'host': hostname,
                    'vault-path': vault_path
                })
                #print(r.content) # Debug
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.json()['irods_response']['status_code'], 0)

                # Add the unixfilesystem resource as a child of the replication resource.
                r = requests.post(self.url_endpoint, headers=headers, data={
                    'op': 'add_child',
                    'parent-name': resc_repl,
                    'child-name': resc_name
                })
                #print(r.content) # Debug
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.json()['irods_response']['status_code'], 0)

                # Show that the resource was created and configured successfully.
                r = requests.get(self.url_endpoint, headers=headers, params={'op': 'stat', 'name': resc_name})
                #print(r.content) # Debug
                self.assertEqual(r.status_code, 200)

                result = r.json()
                self.assertEqual(result['irods_response']['status_code'], 0)
                self.assertEqual(result['exists'], True)
                self.assertIn('id', result['info'])
                self.assertEqual(result['info']['name'], resc_name)
                self.assertEqual(result['info']['type'], 'unixfilesystem')
                self.assertEqual(result['info']['zone'], self.zone_name)
                self.assertEqual(result['info']['host'], hostname)
                self.assertEqual(result['info']['vault_path'], vault_path)
                self.assertIn('status', result['info'])
                self.assertIn('context', result['info'])
                self.assertIn('comments', result['info'])
                self.assertIn('information', result['info'])
                self.assertIn('free_space', result['info'])
                self.assertIn('free_space_last_modified', result['info'])
                self.assertEqual(result['info']['parent_id'], resc_repl_id)
                self.assertIn('created', result['info'])
                self.assertIn('last_modified', result['info'])

        # Create a data object targeting the replication resource.
        data_object = os.path.join('/', self.zone_name, 'home', self.rodsadmin_username, 'test_object_for_resources')
        contents = 'hello, iRODS HTTP API!'
        r = requests.post(f'{self.url_base}/data-objects', headers=headers, data={
            'op': 'write',
            'lpath': data_object,
            'resource': resc_repl,
            'bytes': contents,
            'offset': 0,
            'count': len(contents)
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show there are two replicas under the replication resource hierarchy.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': f"select DATA_NAME, RESC_NAME where DATA_NAME = '{os.path.basename(data_object)}'"
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['rows']), 2)

        resc_tuple = (result['rows'][0][1], result['rows'][1][1])
        self.assertIn(resc_tuple, [(resc_ufs0, resc_ufs1), (resc_ufs1, resc_ufs0)])

        # Trim a replica.
        r = requests.post(f'{self.url_base}/data-objects', headers=headers, data={
            'op': 'trim',
            'lpath': data_object,
            'replica-number': 0
            #'resource': resc_ufs0 # TODO Why does this result in a DIRECT_CHILD_ACCESS error? Is that correct?
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)

        # Show there is only one replica under the replication resource hierarchy.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': f"select DATA_NAME, RESC_NAME where DATA_NAME = '{os.path.basename(data_object)}'"
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['rows']), 1)

        # Launch rebalance.
        r = requests.post(self.url_endpoint, headers=headers, data={'op': 'rebalance', 'name': resc_repl})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)

        # Give the rebalance operation time to complete!
        time.sleep(3)

        #
        # Clean-up
        #

        # Remove data object.
        r = requests.post(f'{self.url_base}/data-objects', headers=headers, data={
            'op': 'remove',
            'lpath': data_object,
            'no-trash': 1
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)

        # Remove resources.
        for resc_name in [resc_ufs0, resc_ufs1]:
            with self.subTest(f'Detach and remove resource [{resc_name}] from [{resc_repl}]'):
                # Detach ufs resource from the replication resource.
                r = requests.post(self.url_endpoint, headers=headers, data={
                    'op': 'remove_child',
                    'parent-name': resc_repl,
                    'child-name': resc_name
                })
                #print(r.content) # Debug
                self.assertEqual(r.status_code, 200)

                result = r.json()
                self.assertEqual(result['irods_response']['status_code'], 0)

                # Remove ufs resource.
                r = requests.post(self.url_endpoint, headers=headers, data={'op': 'remove', 'name': resc_name})
                #print(r.content) # Debug
                self.assertEqual(r.status_code, 200)

                result = r.json()
                self.assertEqual(result['irods_response']['status_code'], 0)

                # Show that the resource no longer exists.
                r = requests.get(self.url_endpoint, headers=headers, params={'op': 'stat', 'name': resc_name})
                #print(r.content) # Debug
                self.assertEqual(r.status_code, 200)

                result = r.json()
                self.assertEqual(result['irods_response']['status_code'], 0)
                self.assertEqual(result['exists'], False)

        # Remove replication resource.
        r = requests.post(self.url_endpoint, headers=headers, data={'op': 'remove', 'name': resc_repl})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)

        # Show that the resource no longer exists.
        r = requests.get(self.url_endpoint, headers=headers, params={'op': 'stat', 'name': resc_repl})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(result['exists'], False)

    def test_modifying_metadata_atomically(self):
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}
        resource = 'demoResc'

        # Add metadata to the resource.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'modify_metadata',
            'name': resource,
            'operations': json.dumps([
                {
                    'operation': 'add',
                    'attribute': 'a1',
                    'value': 'v1',
                    'units': 'u1'
                }
            ])
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the metadata exists on the resource.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': "select RESC_NAME where META_RESC_ATTR_NAME = 'a1' and META_RESC_ATTR_VALUE = 'v1' and META_RESC_ATTR_UNITS = 'u1'"
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(result['rows'][0][0], resource)

        # Remove the metadata from the resource.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'modify_metadata',
            'name': resource,
            'operations': json.dumps([
                {
                    'operation': 'remove',
                    'attribute': 'a1',
                    'value': 'v1',
                    'units': 'u1'
                }
            ])
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the metadata no longer exists on the resource.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': "select RESC_NAME where META_RESC_ATTR_NAME = 'a1' and META_RESC_ATTR_VALUE = 'v1' and META_RESC_ATTR_UNITS = 'u1'"
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['rows']), 0)

class test_rules_endpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_class(cls, {'endpoint_name': 'rules'})

    @classmethod
    def tearDownClass(cls):
        tear_down_class(cls)

    def setUp(self):
        self.assertFalse(self._class_init_error, 'Class initialization failed. Cannot continue.')

    def test_list_all_rule_engine_plugins(self):
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}
        r = requests.get(self.url_endpoint, headers=headers, params={'op': 'list_rule_engines'})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertGreater(len(result['rule_engine_plugin_instances']), 0)

    def test_execute_rule(self):
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}
        test_msg = 'This was run by the iRODS HTTP API test suite!'

        # Execute rule text against the iRODS rule language.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'execute',
            'rep-instance': 'irods_rule_engine_plugin-irods_rule_language-instance',
            'rule-text': f'writeLine("stdout", "{test_msg}")'
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
 
        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(result['stderr'], None)

        # The REP always appends a newline character to the result. While we could trim the result,
        # it is better to append a newline character to the expected result to guarantee things align.
        self.assertEqual(result['stdout'], test_msg + '\n')

    def test_remove_delay_rule(self):
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}
        rep_instance = 'irods_rule_engine_plugin-irods_rule_language-instance'

        # Schedule a delay rule to execute in the distant future.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'execute',
            'rep-instance': rep_instance,
            'rule-text': f'delay("<INST_NAME>{rep_instance}</INST_NAME><PLUSET>1h</PLUSET>") {{ writeLine("serverLog", "iRODS HTTP API"); }}'
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
 
        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)

        # Find the delay rule we just created.
        # This query assumes the test suite is running on a system where no other delay
        # rules are being created.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': 'select max(RULE_EXEC_ID)'
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
 
        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['rows']), 1)

        # Remove the delay rule.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'remove_delay_rule',
            'rule-id': str(result['rows'][0][0])
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
 
        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)

class test_tickets_endpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_class(cls, {'endpoint_name': 'tickets'})

    @classmethod
    def tearDownClass(cls):
        tear_down_class(cls)

    def setUp(self):
        self.assertFalse(self._class_init_error, 'Class initialization failed. Cannot continue.')

    def test_create_and_remove_ticket_for_data_object(self):
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}
        data_object = os.path.join('/', self.zone_name, 'home', self.rodsuser_username, 'test_object')

        # Create a data object.
        r = requests.post(f'{self.url_base}/data-objects', headers=headers, data={'op': 'touch', 'lpath': data_object})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)

        # Create a ticket.
        ticket_type = 'read'
        ticket_use_count = 1000
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'create',
            'lpath': data_object,
            'type': ticket_type,
            'use-count': ticket_use_count
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        ticket_string = result['ticket']
        self.assertGreater(len(ticket_string), 0)

        # TODO Show the ticket exists and has the properties we defined during creation.
        # We can use GenQuery for this, but it does seem better to provide a convenience operation
        # for this.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': 'select TICKET_STRING, TICKET_TYPE, TICKET_DATA_NAME, TICKET_USES_LIMIT'
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(result['rows'][0][0], ticket_string)
        self.assertEqual(result['rows'][0][1], ticket_type)
        self.assertEqual(result['rows'][0][2], os.path.basename(data_object))
        self.assertEqual(result['rows'][0][3], str(ticket_use_count))

        # Remove the ticket.
        r = requests.post(self.url_endpoint, headers=headers, data={'op': 'remove', 'name': ticket_string})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)

        # Show the ticket no longer exists.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': 'select TICKET_STRING'
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['rows']), 0)

        # Remove the data object.
        r = requests.post(f'{self.url_base}/data-objects', headers=headers, data={
            'op': 'remove',
            'lpath': data_object,
            'no-trash': 1
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)

    def test_create_and_remove_ticket_for_collection(self):
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}

        # Create a write ticket.
        ticket_type = 'write'
        ticket_path = os.path.join('/', self.zone_name, 'home', self.rodsuser_username) 
        ticket_use_count = 2000
        ticket_groups = 'public'
        ticket_hosts = self.server_hostname
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'create',
            'lpath': ticket_path,
            'type': ticket_type,
            'use-count': ticket_use_count,
            'seconds-until-expiration': '3600',
            'users': f'{self.rodsadmin_username},{self.rodsuser_username}',
            'groups': ticket_groups,
            'hosts': ticket_hosts
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        ticket_string = result['ticket']
        self.assertGreater(len(ticket_string), 0)

        # TODO Show the ticket exists and has the properties we defined during creation.
        # We can use GenQuery for this, but it does seem better to provide a convenience operation
        # for this.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': 'select TICKET_STRING, TICKET_TYPE, TICKET_COLL_NAME, TICKET_USES_LIMIT, TICKET_ALLOWED_USER_NAME, TICKET_ALLOWED_GROUP_NAME, TICKET_ALLOWED_HOST'
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(result['rows'][0][0], ticket_string)
        self.assertEqual(result['rows'][0][1], ticket_type)
        self.assertEqual(result['rows'][0][2], ticket_path)
        self.assertEqual(result['rows'][0][3], str(ticket_use_count))
        self.assertIn(result['rows'][0][4], [self.rodsadmin_username, self.rodsuser_username])
        self.assertEqual(result['rows'][0][5], ticket_groups)
        self.assertGreater(len(result['rows'][0][6]), 0)

        # Remove the ticket.
        r = requests.post(self.url_endpoint, headers=headers, data={'op': 'remove', 'name': ticket_string})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)

        # Show the ticket no longer exists.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': 'select TICKET_STRING'
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['rows']), 0)

    @unittest.skip('Test and HTTP API operation need to be implemented.')
    def test_modification_of_ticket_properties(self):
        pass

class test_users_groups_endpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_class(cls, {'endpoint_name': 'users-groups'})

    @classmethod
    def tearDownClass(cls):
        tear_down_class(cls)

    def setUp(self):
        self.assertFalse(self._class_init_error, 'Class initialization failed. Cannot continue.')

    def test_create_stat_and_remove_rodsuser(self):
        new_username = 'test_user_rodsuser'
        user_type = 'rodsuser'
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}

        # Create a new user.
        data = {'op': 'create_user', 'name': new_username, 'zone': self.zone_name, 'user-type': user_type}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
 
        # Stat the user.
        params = {'op': 'stat', 'name': new_username, 'zone': self.zone_name}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        stat_info = r.json()
        self.assertEqual(stat_info['irods_response']['status_code'], 0)
        self.assertEqual(stat_info['exists'], True)
        self.assertIn('id', stat_info)
        self.assertEqual(stat_info['local_unique_name'], f'{new_username}#{self.zone_name}')
        self.assertEqual(stat_info['type'], user_type)

        # Remove the user.
        data = {'op': 'remove_user', 'name': new_username, 'zone': self.zone_name}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

    def test_create_stat_and_remove_rodsadmin(self):
        new_username = 'test_user_rodsadmin'
        user_type = 'rodsadmin'
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}

        # Create a new user.
        data = {'op': 'create_user', 'name': new_username, 'zone': self.zone_name, 'user-type': user_type}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
 
        # Stat the user.
        params = {'op': 'stat', 'name': new_username, 'zone': self.zone_name}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        stat_info = r.json()
        self.assertEqual(stat_info['irods_response']['status_code'], 0)
        self.assertEqual(stat_info['exists'], True)
        self.assertIn('id', stat_info)
        self.assertEqual(stat_info['local_unique_name'], f'{new_username}#{self.zone_name}')
        self.assertEqual(stat_info['type'], user_type)

        # Remove the user.
        data = {'op': 'remove_user', 'name': new_username, 'zone': self.zone_name}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

    def test_create_stat_and_remove_groupadmin(self):
        new_username = 'test_user_groupadmin'
        user_type = 'groupadmin'
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}

        # Create a new user.
        data = {'op': 'create_user', 'name': new_username, 'zone': self.zone_name, 'user-type': user_type}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
 
        # Stat the user.
        params = {'op': 'stat', 'name': new_username, 'zone': self.zone_name}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        stat_info = r.json()
        self.assertEqual(stat_info['irods_response']['status_code'], 0)
        self.assertEqual(stat_info['exists'], True)
        self.assertIn('id', stat_info)
        self.assertEqual(stat_info['local_unique_name'], f'{new_username}#{self.zone_name}')
        self.assertEqual(stat_info['type'], user_type)

        # Remove the user.
        data = {'op': 'remove_user', 'name': new_username, 'zone': self.zone_name}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

    def test_add_remove_user_to_and_from_group(self):
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}

        # Create a new group.
        new_group = 'test_group'
        data = {'op': 'create_group', 'name': new_group}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Stat the group.
        params = {'op': 'stat', 'name': new_group}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        stat_info = r.json()
        self.assertEqual(stat_info['irods_response']['status_code'], 0)
        self.assertEqual(stat_info['exists'], True)
        self.assertIn('id', stat_info)
        self.assertEqual(stat_info['type'], 'rodsgroup')

        # Create a new user.
        new_username = 'test_user_rodsuser'
        user_type = 'rodsuser'
        data = {'op': 'create_user', 'name': new_username, 'zone': self.zone_name, 'user-type': user_type}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)
 
        # Add user to group.
        data = {'op': 'add_to_group', 'group': new_group, 'user': new_username, 'zone': self.zone_name}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show that the user is a member of the group.
        params = {'op': 'is_member_of_group', 'group': new_group, 'user': new_username, 'zone': self.zone_name}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(result['is_member'], True)

        # Remove user from group.
        data = {'op': 'remove_from_group', 'group': new_group, 'user': new_username, 'zone': self.zone_name}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Remove the user.
        data = {'op': 'remove_user', 'name': new_username, 'zone': self.zone_name}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Remove group.
        data = {'op': 'remove_group', 'name': new_group}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show that the group no longer exists.
        params = {'op': 'stat', 'name': new_group}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        stat_info = r.json()
        self.assertEqual(stat_info['irods_response']['status_code'], 0)
        self.assertEqual(stat_info['exists'], False)

    def test_only_a_rodsadmin_can_change_the_type_of_a_user(self):
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}

        # Create a new user.
        new_username = 'test_user_rodsuser'
        user_type = 'rodsuser'
        data = {'op': 'create_user', 'name': new_username, 'zone': self.zone_name, 'user-type': user_type}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show that a rodsadmin can change the type of the new user.
        new_user_type = 'groupadmin'
        data = {'op': 'set_user_type', 'name': new_username, 'zone': self.zone_name, 'new-user-type': new_user_type}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show that a non-admin cannot change the new user's password.
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}
        data = {'op': 'set_user_type', 'name': new_username, 'zone': self.zone_name, 'new-user-type': 'rodsuser'}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 400)
        self.assertNotEqual(r.json()['irods_response']['status_code'], 0)

        # Show that the user type matches the type set by the rodsadmin.
        params = {'op': 'stat', 'name': new_username, 'zone': self.zone_name}
        r = requests.get(self.url_endpoint, headers=headers, params=params)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        stat_info = r.json()
        self.assertEqual(stat_info['irods_response']['status_code'], 0)
        self.assertEqual(stat_info['exists'], True)
        self.assertEqual(stat_info['local_unique_name'], f'{new_username}#{self.zone_name}')
        self.assertEqual(stat_info['type'], new_user_type)

        # Remove the user.
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}
        data = {'op': 'remove_user', 'name': new_username, 'zone': self.zone_name}
        r = requests.post(self.url_endpoint, headers=headers, data=data)
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

    def test_rodsusers_cannot_change_passwords(self):
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}

        # Show that a non-admin cannot change the new user's password.
        headers = {'Authorization': 'Bearer ' + self.rodsuser_bearer_token}
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'set_password',
            'name': self.rodsuser_username,
            'zone': self.zone_name,
            'new-password': 'not_going_to_work'
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 400)
        self.assertNotEqual(r.json()['irods_response']['status_code'], 0)

        # Authenticate as the user to prove the first password modification was successful.
        r = requests.post(f'{self.url_base}/authenticate', auth=(self.rodsuser_username, config.test_config['rodsuser']['password']))
        self.assertEqual(r.status_code, 200)
        self.assertGreater(len(r.text), 0)

    def test_listing_all_users_in_zone(self):
        r = requests.get(self.url_endpoint, headers={'Authorization': f'Bearer {self.rodsuser_bearer_token}'}, params={'op': 'users'})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertIn({'name': self.rodsadmin_username, 'zone': self.zone_name}, result['users'])
        self.assertIn({'name': self.rodsuser_username, 'zone': self.zone_name}, result['users'])

    def test_listing_all_grops_in_zone(self):
        headers = {'Authorization': f'Bearer {self.rodsadmin_bearer_token}'}

        # Create a new group.
        new_group = 'test_group'
        r = requests.post(self.url_endpoint, headers=headers, data={'op': 'create_group', 'name': new_group})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Get all groups.
        r = requests.get(self.url_endpoint, headers={'Authorization': f'Bearer {self.rodsuser_bearer_token}'}, params={'op': 'groups'})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertIn('public', result['groups'])
        self.assertIn(new_group, result['groups'])

        # Remove the new group.
        r = requests.post(self.url_endpoint, headers=headers, data={'op': 'remove_group', 'name': new_group})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

    def test_modifying_metadata_atomically(self):
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}
        username = self.rodsuser_username

        # Add metadata to the user.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'modify_metadata',
            'name': username,
            'operations': json.dumps([
                {
                    'operation': 'add',
                    'attribute': 'a1',
                    'value': 'v1',
                    'units': 'u1'
                }
            ])
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the metadata exists on the user.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': "select USER_NAME where META_USER_ATTR_NAME = 'a1' and META_USER_ATTR_VALUE = 'v1' and META_USER_ATTR_UNITS = 'u1'"
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(result['rows'][0][0], username)

        # Remove the metadata from the user.
        r = requests.post(self.url_endpoint, headers=headers, data={
            'op': 'modify_metadata',
            'name': username,
            'operations': json.dumps([
                {
                    'operation': 'remove',
                    'attribute': 'a1',
                    'value': 'v1',
                    'units': 'u1'
                }
            ])
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['irods_response']['status_code'], 0)

        # Show the metadata no longer exists on the user.
        r = requests.get(f'{self.url_base}/query', headers=headers, params={
            'op': 'execute_genquery',
            'query': "select USER_NAME where META_USER_ATTR_NAME = 'a1' and META_USER_ATTR_VALUE = 'v1' and META_USER_ATTR_UNITS = 'u1'"
        })
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)
        self.assertEqual(len(result['rows']), 0)

    @unittest.skip('Test needs to be implemented.')
    def test_create_user_returns_error_when_missing_required_parameters(self):
        pass

    @unittest.skip('Test needs to be implemented.')
    def test_remove_user_returns_error_when_missing_required_parameters(self):
        pass

    @unittest.skip('Test needs to be implemented.')
    def test_create_group_returns_error_when_missing_required_parameters(self):
        pass

    @unittest.skip('Test needs to be implemented.')
    def test_remove_group_returns_error_when_missing_required_parameters(self):
        pass

    @unittest.skip('Test needs to be implemented.')
    def test_add_to_group_returns_error_when_missing_required_parameters(self):
        pass

    @unittest.skip('Test needs to be implemented.')
    def test_remove_from_group_returns_error_when_missing_required_parameters(self):
        pass

    @unittest.skip('Test needs to be implemented.')
    def test_listing_users_returns_error_when_missing_required_parameters(self):
        pass

    @unittest.skip('Test needs to be implemented.')
    def test_listing_groups_returns_error_when_missing_required_parameters(self):
        pass

    @unittest.skip('Test needs to be implemented.')
    def test_listing_members_of_group_returns_error_when_missing_required_parameters(self):
        pass

    @unittest.skip('Test needs to be implemented.')
    def test_is_member_of_group_returns_error_when_missing_required_parameters(self):
        pass

    @unittest.skip('Test needs to be implemented.')
    def test_stat_returns_error_when_missing_required_parameters(self):
        pass

class test_zones_endpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_class(cls, {'endpoint_name': 'zones', 'create_rodsuser': False})

    def setUp(self):
        self.assertFalse(self._class_init_error, 'Class initialization failed. Cannot continue.')

    def test_report_operation(self):
        headers = {'Authorization': 'Bearer ' + self.rodsadmin_bearer_token}
        r = requests.get(self.url_endpoint, headers=headers, params={'op': 'report'})
        #print(r.content) # Debug
        self.assertEqual(r.status_code, 200)

        result = r.json()
        self.assertEqual(result['irods_response']['status_code'], 0)

        zone_report = result['zone_report']
        self.assertIn('schema_version', zone_report)
        self.assertIn('zones', zone_report)
        self.assertGreaterEqual(len(zone_report['zones']), 1)

if __name__ == '__main__':
    unittest.main()
