import logging

test_config = {
    'log_level': logging.INFO,

    'host': 'localhost',
    'port': 9000,
    'url_base': '/irods-http-api/0.1.0',

    'rodsadmin': {
        'username': 'rods',
        'password': 'rods'
    },

    'rodsuser': {
        'username': 'http_api',
        'password': 'http_api'
    },

    'irods_zone': 'tempZone',
    'irods_server_hostname': 'localhost',

    "run_genquery2_tests": False
}
