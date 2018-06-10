from asynctest import TestCase

import asyncio

from async_hvac import Client, exceptions
from async_hvac.tests import util

loop = asyncio.get_event_loop()


def create_client(sync=False, **kwargs):
    return Client(url='https://127.0.0.1:8200',
                  cert=('test/client-cert.pem', 'test/client-key.pem'),
                  verify='test/server-cert.pem',
                  loop=IntegrationTest.loop,
                  sync=sync,
                  **kwargs)


class IntegrationTest(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.manager = util.ServerManager(
            config_path='test/vault-tls.hcl',
            client=create_client(sync=True))
        cls.manager.start()
        cls.manager.initialize()
        cls.manager.unseal()

    @classmethod
    def tearDownClass(cls):
        cls.manager.stop()

    def root_token(self):
        cls = type(self)
        return cls.manager.root_token

    async def setUp(self):
        self.client = create_client(token=self.root_token())

    async def tearDown(self):
        await self.client.close()

    async def test_unseal_multi(self):
        cls = type(self)

        await self.client.seal()

        keys = cls.manager.keys

        result = await self.client.unseal_multi(keys[0:2])

        assert result['sealed']
        assert result['progress'] == 2

        result = await self.client.unseal_reset()
        assert result['progress'] == 0
        result = await self.client.unseal_multi(keys[1:3])
        assert result['sealed']
        assert result['progress'] == 2
        result = await self.client.unseal_multi(keys[0:1])
        result = await self.client.unseal_multi(keys[2:3])
        assert not result['sealed']

    async def test_seal_unseal(self):
        cls = type(self)

        assert not (await self.client.is_sealed())

        await self.client.seal()

        assert (await self.client.is_sealed())

        cls.manager.unseal()

        assert not (await self.client.is_sealed())

    async def test_ha_status(self):
        assert 'ha_enabled' in (await self.client.ha_status)

    async def test_generic_secret_backend(self):
        await self.client.write('secret/foo', zap='zip')
        result = await self.client.read('secret/foo')

        assert result['data']['zap'] == 'zip'

        await self.client.delete('secret/foo')

    async def test_list_directory(self):
        await self.client.write('secret/test-list/bar/foo', value='bar')
        await self.client.write('secret/test-list/foo', value='bar')
        result = await self.client.list('secret/test-list')

        assert result['data']['keys'] == ['bar/', 'foo']

        await self.client.delete('secret/test-list/bar/foo')
        await self.client.delete('secret/test-list/foo')

    async def test_write_with_response(self):
        if 'transit/' in (await self.client.list_secret_backends()):
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        plaintext = 'test'

        await self.client.write('transit/keys/foo')

        result = await self.client.write('transit/encrypt/foo', plaintext=plaintext)
        ciphertext = result['data']['ciphertext']

        result = await self.client.write('transit/decrypt/foo', ciphertext=ciphertext)
        assert result['data']['plaintext'] == plaintext

    async def test_wrap_write(self):
        if 'approle/' not in (await self.client.list_auth_backends()):
            await self.client.enable_auth_backend("approle")

        await self.client.write("auth/approle/role/testrole")
        result = await self.client.write('auth/approle/role/testrole/secret-id', wrap_ttl="10s")
        assert 'token' in result['wrap_info']
        await self.client.unwrap(result['wrap_info']['token'])
        await self.client.disable_auth_backend("approle")

    async def test_read_nonexistent_key(self):
        assert not (await self.client.read('secret/I/dont/exist'))

    async def test_auth_backend_manipulation(self):
        assert 'github/' not in (await self.client.list_auth_backends())

        await self.client.enable_auth_backend('github')
        assert 'github/' in (await self.client.list_auth_backends())

        self.client.token = self.root_token()
        await self.client.disable_auth_backend('github')
        assert 'github/' not in (await self.client.list_auth_backends())

    async def test_secret_backend_manipulation(self):
        assert 'test/' not in (await self.client.list_secret_backends())

        await self.client.enable_secret_backend('generic', mount_point='test')
        assert 'test/' in (await self.client.list_secret_backends())

        await self.client.tune_secret_backend('generic', mount_point='test', default_lease_ttl='3600s', max_lease_ttl='8600s')
        assert 'max_lease_ttl' in (await self.client.get_secret_backend_tuning('generic', mount_point='test'))
        assert 'default_lease_ttl' in (await self.client.get_secret_backend_tuning('generic', mount_point='test'))

        await self.client.remount_secret_backend('test', 'foobar')
        assert 'test/' not in (await self.client.list_secret_backends())
        assert 'foobar/' in (await self.client.list_secret_backends())

        self.client.token = self.root_token()
        await self.client.disable_secret_backend('foobar')
        assert 'foobar/' not in (await self.client.list_secret_backends())

    async def test_audit_backend_manipulation(self):
        assert 'tmpfile/' not in (await self.client.list_audit_backends())

        options = {
            'path': '/tmp/vault.audit.log'
        }

        await self.client.enable_audit_backend('file', options=options, name='tmpfile')
        assert 'tmpfile/' in (await self.client.list_audit_backends())

        self.client.token = self.root_token()
        await self.client.disable_audit_backend('tmpfile')
        assert 'tmpfile/' not in (await self.client.list_audit_backends())

    async def prep_policy(self, name):
        text = """
        path "sys" {
            policy = "deny"
        }
        path "secret" {
            policy = "write"
        }
        """
        obj = {
            'path': {
                'sys': {
                    'policy': 'deny'},
                'secret': {
                    'policy': 'write'}
            }
        }
        await self.client.set_policy(name, text)
        return text, obj

    async def test_policy_manipulation(self):
        assert 'root' in (await self.client.list_policies())
        assert (await self.client.get_policy('test')) is None
        policy, parsed_policy = await self.prep_policy('test')
        assert 'test' in (await self.client.list_policies())
        assert policy == (await self.client.get_policy('test'))
        assert parsed_policy == (await self.client.get_policy('test', parse=True))

        await self.client.delete_policy('test')
        assert 'test' not in (await self.client.list_policies())

    async def test_json_policy_manipulation(self):
        assert 'root' in (await self.client.list_policies())

        policy = {
            "path": {
                "sys": {
                    "policy": "deny"
                },
                "secret": {
                    "policy": "write"
                }
            }
        }

        await self.client.set_policy('test', policy)
        assert 'test' in (await self.client.list_policies())

        await self.client.delete_policy('test')
        assert 'test' not in (await self.client.list_policies())

    async def test_auth_token_manipulation(self):
        result = await self.client.create_token(lease='1h', renewable=True)
        assert result['auth']['client_token']

        lookup = await self.client.lookup_token(result['auth']['client_token'])
        assert result['auth']['client_token'] == lookup['data']['id']

        renew = await self.client.renew_token(lookup['data']['id'])
        assert result['auth']['client_token'] == renew['auth']['client_token']

        await self.client.revoke_token(lookup['data']['id'])

        try:
            lookup = await self.client.lookup_token(result['auth']['client_token'])
            assert False
        except exceptions.Forbidden:
            assert True
        except exceptions.InvalidPath:
            assert True
        except exceptions.InvalidRequest:
            assert True

    async def test_userpass_auth(self):
        if 'userpass/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('userpass')

        await self.client.enable_auth_backend('userpass')

        await self.client.write('auth/userpass/users/testuser', password='testpass', policies='not_root')

        result = await self.client.auth_userpass('testuser', 'testpass')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())

        self.client.token = self.root_token()
        await self.client.disable_auth_backend('userpass')

    async def test_create_userpass(self):
        if 'userpass/' not in (await self.client.list_auth_backends()):
            await self.client.enable_auth_backend('userpass')

        await self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root')

        result = await self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())

        # Test ttl:
        self.client.token = self.root_token()
        await self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root', ttl='10s')
        self.client.token = result['auth']['client_token']

        result = await self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert result['auth']['lease_duration'] == 10

        self.client.token = self.root_token()
        await self.client.disable_auth_backend('userpass')

    async def test_delete_userpass(self):
        if 'userpass/' not in (await self.client.list_auth_backends()):
            await self.client.enable_auth_backend('userpass')

        await self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root')

        result = await self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())

        self.client.token = self.root_token()
        await self.client.delete_userpass('testcreateuser')
        with self.assertRaises(exceptions.InvalidRequest):
            await self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

    async def test_app_id_auth(self):
        if 'app-id/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('app-id')

        await self.client.enable_auth_backend('app-id')

        await self.client.write('auth/app-id/map/app-id/foo', value='not_root')
        await self.client.write('auth/app-id/map/user-id/bar', value='foo')

        result = await self.client.auth_app_id('foo', 'bar')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())

        self.client.token = self.root_token()
        await self.client.disable_auth_backend('app-id')

    async def test_create_app_id(self):
        if 'app-id/' not in (await self.client.list_auth_backends()):
            await self.client.enable_auth_backend('app-id')

        await self.client.create_app_id('testappid', policies='not_root', display_name='displayname')

        result = await self.client.read('auth/app-id/map/app-id/testappid')
        lib_result = await self.client.get_app_id('testappid')
        del result['request_id']
        del lib_result['request_id']
        assert result == lib_result

        assert result['data']['key'] == 'testappid'
        assert result['data']['display_name'] == 'displayname'
        assert result['data']['value'] == 'not_root'
        await self.client.delete_app_id('testappid')
        assert (await self.client.get_app_id('testappid'))['data'] is None

        self.client.token = self.root_token()
        await self.client.disable_auth_backend('app-id')

    async def test_create_user_id(self):
        if 'app-id/' not in (await self.client.list_auth_backends()):
            await self.client.enable_auth_backend('app-id')

        await self.client.create_app_id('testappid', policies='not_root', display_name='displayname')
        await self.client.create_user_id('testuserid', app_id='testappid')

        result = await self.client.read('auth/app-id/map/user-id/testuserid')
        lib_result = await self.client.get_user_id('testuserid')
        del result['request_id']
        del lib_result['request_id']
        assert result == lib_result

        assert result['data']['key'] == 'testuserid'
        assert result['data']['value'] == 'testappid'

        result = await self.client.auth_app_id('testappid', 'testuserid')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())
        self.client.token = self.root_token()
        await self.client.delete_user_id('testuserid')
        assert (await self.client.get_user_id('testuserid'))['data'] is None

        self.client.token = self.root_token()
        await self.client.disable_auth_backend('app-id')

    async def test_create_role(self):
        if 'approle/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('approle')
        await self.client.enable_auth_backend('approle')

        await self.client.create_role('testrole')

        result = await self.client.read('auth/approle/role/testrole')
        lib_result = await self.client.get_role('testrole')
        del result['request_id']
        del lib_result['request_id']

        assert result == lib_result
        self.client.token = self.root_token()
        await self.client.disable_auth_backend('approle')

    async def test_create_delete_role_secret_id(self):
        if 'approle/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('approle')
        await self.client.enable_auth_backend('approle')

        await self.client.create_role('testrole')
        create_result = await self.client.create_role_secret_id('testrole', {'foo':'bar'})
        secret_id = create_result['data']['secret_id']
        result = await self.client.get_role_secret_id('testrole', secret_id)
        assert result['data']['metadata']['foo'] == 'bar'
        await self.client.delete_role_secret_id('testrole', secret_id)
        assert (await self.client.get_role_secret_id('testrole', secret_id)) is None
        self.client.token = self.root_token()
        await self.client.disable_auth_backend('approle')

    async def test_auth_approle(self):
        if 'approle/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('approle')
        await self.client.enable_auth_backend('approle')

        await self.client.create_role('testrole')
        create_result = await self.client.create_role_secret_id('testrole', {'foo': 'bar'})
        secret_id = create_result['data']['secret_id']
        role_id = await self.client.get_role_id('testrole')
        result = await self.client.auth_approle(role_id, secret_id)
        assert result['auth']['metadata']['foo'] == 'bar'
        assert self.client.token == result['auth']['client_token']
        assert await self.client.is_authenticated()
        self.client.token = self.root_token()
        await self.client.disable_auth_backend('approle')

    async def test_auth_approle_dont_use_token(self):
        if 'approle/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('approle')
        await self.client.enable_auth_backend('approle')

        await self.client.create_role('testrole')
        create_result = await self.client.create_role_secret_id('testrole', {'foo':'bar'})
        secret_id = create_result['data']['secret_id']
        role_id = await self.client.get_role_id('testrole')
        result = await self.client.auth_approle(role_id, secret_id, use_token=False)
        assert result['auth']['metadata']['foo'] == 'bar'
        assert self.client.token != result['auth']['client_token']
        self.client.token = self.root_token()
        await self.client.disable_auth_backend('approle')

    async def test_transit_read_write(self):
        if 'transit/' in (await self.client.list_secret_backends()):
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')
        result = await self.client.transit_read_key('foo')
        assert not result['data']['exportable']

        await self.client.transit_create_key('foo_export', exportable=True, key_type="ed25519")
        result = await self.client.transit_read_key('foo_export')
        assert result['data']['exportable']
        assert result['data']['type'] == 'ed25519'

        await self.client.enable_secret_backend('transit', mount_point='bar')
        await self.client.transit_create_key('foo', mount_point='bar')
        result = await self.client.transit_read_key('foo', mount_point='bar')
        assert not result['data']['exportable']

    async def test_transit_list_keys(self):
        if 'transit/' in (await self.client.list_secret_backends()):
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo1')
        await self.client.transit_create_key('foo2')
        await self.client.transit_create_key('foo3')

        result = await self.client.transit_list_keys()
        assert result['data']['keys'] == ["foo1", "foo2", "foo3"]

    async def test_transit_update_delete_keys(self):
        if 'transit/' in (await self.client.list_secret_backends()):
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')
        await self.client.transit_update_key('foo', deletion_allowed=True)
        result = await self.client.transit_read_key('foo')
        assert result['data']['deletion_allowed']

        await self.client.transit_delete_key('foo')

        try:
            await self.client.transit_read_key('foo')
        except exceptions.InvalidPath:
            assert True
        else:
            assert False

    async def test_transit_rotate_key(self):
        if 'transit/' in (await self.client.list_secret_backends()):
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')

        await self.client.transit_rotate_key('foo')
        response = await self.client.transit_read_key('foo')
        assert '2' in response['data']['keys']

        await self.client.transit_rotate_key('foo')
        response = await self.client.transit_read_key('foo')
        assert '3' in response['data']['keys']

    async def test_transit_export_key(self):
        if 'transit/' in (await self.client.list_secret_backends()):
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo', exportable=True)
        response = await self.client.transit_export_key('foo', key_type='encryption-key')
        assert response is not None

    async def test_transit_encrypt_data(self):
        if 'transit/' in (await self.client.list_secret_backends()):
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')
        ciphertext_resp = (await self.client.transit_encrypt_data('foo', 'abbaabba'))['data']['ciphertext']
        plaintext_resp = (await self.client.transit_decrypt_data('foo', ciphertext_resp))['data']['plaintext']
        assert plaintext_resp == 'abbaabba'

    async def test_transit_rewrap_data(self):
        if 'transit/' in (await self.client.list_secret_backends()):
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')
        ciphertext_resp = (await self.client.transit_encrypt_data('foo', 'abbaabba'))['data']['ciphertext']

        await self.client.transit_rotate_key('foo')
        response_wrap = (await self.client.transit_rewrap_data('foo', ciphertext=ciphertext_resp))['data']['ciphertext']
        plaintext_resp = (await self.client.transit_decrypt_data('foo', response_wrap))['data']['plaintext']
        assert plaintext_resp == 'abbaabba'

    async def test_transit_generate_data_key(self):
        if 'transit/' in (await self.client.list_secret_backends()):
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')

        response_plaintext = (await self.client.transit_generate_data_key('foo', key_type='plaintext'))['data']['plaintext']
        assert response_plaintext

        response_ciphertext = (await self.client.transit_generate_data_key('foo', key_type='wrapped'))['data']
        assert 'ciphertext' in response_ciphertext
        assert 'plaintext' not in response_ciphertext

    async def test_transit_generate_rand_bytes(self):
        if 'transit/' in (await self.client.list_secret_backends()):
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        response_data = (await self.client.transit_generate_rand_bytes(data_bytes=4))['data']['random_bytes']
        assert response_data

    async def test_transit_hash_data(self):
        if 'transit/' in (await self.client.list_secret_backends()):
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        response_hash = (await self.client.transit_hash_data('abbaabba'))['data']['sum']
        assert len(response_hash) == 64

        response_hash = (await self.client.transit_hash_data('abbaabba', algorithm="sha2-512"))['data']['sum']
        assert len(response_hash) == 128

    async def test_transit_generate_verify_hmac(self):
        if 'transit/' in (await self.client.list_secret_backends()):
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')

        response_hmac = (await self.client.transit_generate_hmac('foo', 'abbaabba'))['data']['hmac']
        assert response_hmac
        verify_resp = (await self.client.transit_verify_signed_data('foo', 'abbaabba', hmac=response_hmac))['data']['valid']
        assert verify_resp

        response_hmac = (await self.client.transit_generate_hmac('foo', 'abbaabba', algorithm='sha2-512'))['data']['hmac']
        assert response_hmac
        verify_resp = (await self.client.transit_verify_signed_data(
            'foo', 'abbaabba', algorithm='sha2-512', hmac=response_hmac))['data']['valid']
        assert verify_resp

    async def test_transit_sign_verify_signature_data(self):
        if 'transit/' in (await self.client.list_secret_backends()):
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo', key_type='ed25519')

        signed_resp = (await self.client.transit_sign_data('foo', 'abbaabba'))['data']['signature']
        assert signed_resp
        verify_resp = (await self.client.transit_verify_signed_data('foo', 'abbaabba', signature=signed_resp))['data']['valid']
        assert verify_resp

        signed_resp = (await self.client.transit_sign_data('foo', 'abbaabba', algorithm='sha2-512'))['data']['signature']
        assert signed_resp
        verify_resp = (await self.client.transit_verify_signed_data('foo', 'abbaabba',
                                                             algorithm='sha2-512',
                                                             signature=signed_resp))['data']['valid']
        assert verify_resp

    async def test_missing_token(self):
        client = create_client()
        assert not (await client.is_authenticated())
        await client.close()

    async def test_invalid_token(self):
        client = create_client(token='not-a-real-token')
        assert not (await client.is_authenticated())
        await client.close()

    async def test_illegal_token(self):
        client = create_client(token='token-with-new-line\n')
        try:
            await client.is_authenticated()
        except ValueError as e:
            assert 'Invalid header value' in str(e)
        await client.close()

    async def test_broken_token(self):
        client = create_client(token='\x1b')
        try:
            await client.is_authenticated()
        except exceptions.InvalidRequest as e:
            assert "invalid header value" in str(e)
        await client.close()

    async def test_client_authenticated(self):
        assert (await self.client.is_authenticated())

    async def test_client_logout(self):
        self.client.logout()
        assert not (await self.client.is_authenticated())

    async def test_revoke_self_token(self):
        if 'userpass/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('userpass')

        await self.client.enable_auth_backend('userpass')

        await self.client.write('auth/userpass/users/testuser', password='testpass', policies='not_root')

        result = await self.client.auth_userpass('testuser', 'testpass')

        await self.client.revoke_self_token()
        assert not (await self.client.is_authenticated())

    async def test_rekey_multi(self):
        cls = type(self)

        assert not (await self.client.rekey_status)['started']

        await self.client.start_rekey()
        assert (await self.client.rekey_status)['started']

        await self.client.cancel_rekey()
        assert not (await self.client.rekey_status)['started']

        result = await self.client.start_rekey()

        keys = cls.manager.keys

        result = await self.client.rekey_multi(keys, nonce=result['nonce'])
        assert result['complete']

        cls.manager.keys = result['keys']
        cls.manager.unseal()

    async def test_rotate(self):
        status = await self.client.key_status

        await self.client.rotate()

        assert (await self.client.key_status)['term'] > status['term']

    async def test_tls_auth(self):
        await self.client.enable_auth_backend('cert')

        with open('test/client-cert.pem') as fp:
            certificate = fp.read()

        await self.client.write('auth/cert/certs/test', display_name='test',
                                     policies='not_root', certificate=certificate)

        result = await self.client.auth_tls()

    async def test_gh51(self):
        key = 'secret/http://test.com'

        await self.client.write(key, foo='bar')

        result = await self.client.read(key)

        assert result['data']['foo'] == 'bar'

    async def test_token_accessor(self):
        # Create token, check accessor is provided
        result = await self.client.create_token(lease='1h')
        token_accessor = result['auth'].get('accessor', None)
        assert token_accessor

        # Look up token by accessor, make sure token is excluded from results
        lookup = await self.client.lookup_token(token_accessor, accessor=True)
        assert lookup['data']['accessor'] == token_accessor
        assert not lookup['data']['id']

        # Revoke token using the accessor
        await self.client.revoke_token(token_accessor, accessor=True)

        # Look up by accessor should fail
        with self.assertRaises(exceptions.InvalidRequest):
            lookup = await self.client.lookup_token(token_accessor, accessor=True)

        # As should regular lookup
        with self.assertRaises(exceptions.Forbidden):
            lookup = await self.client.lookup_token(result['auth']['client_token'])

    async def test_wrapped_token_success(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        # Unwrap token
        result = await self.client.unwrap(wrap['wrap_info']['token'])
        assert result['auth']['client_token']

        # Validate token
        lookup = await self.client.lookup_token(result['auth']['client_token'])
        assert result['auth']['client_token'] == lookup['data']['id']

    async def test_wrapped_token_intercept(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        # Intercept wrapped token
        _ = await self.client.unwrap(wrap['wrap_info']['token'])

        # Attempt to retrieve the token after it's been intercepted
        with self.assertRaises(exceptions.Forbidden):
            result = await self.client.unwrap(wrap['wrap_info']['token'])

    async def test_wrapped_token_cleanup(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        _token = self.client.token
        _ = await self.client.unwrap(wrap['wrap_info']['token'])
        assert self.client.token == _token

    async def test_wrapped_token_revoke(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        # Revoke token before it's unwrapped
        await self.client.revoke_token(wrap['wrap_info']['wrapped_accessor'], accessor=True)

        # Unwrap token anyway
        result = await self.client.unwrap(wrap['wrap_info']['token'])
        assert result['auth']['client_token']

        # Attempt to validate token
        with self.assertRaises(exceptions.Forbidden):
            lookup = await self.client.lookup_token(result['auth']['client_token'])

    async def test_create_token_explicit_max_ttl(self):

        token = await self.client.create_token(ttl='30m', explicit_max_ttl='5m')

        assert token['auth']['client_token']

        assert token['auth']['lease_duration'] == 300

        # Validate token
        lookup = await self.client.lookup_token(token['auth']['client_token'])
        assert token['auth']['client_token'] == lookup['data']['id']

    async def test_create_token_max_ttl(self):

        token = await self.client.create_token(ttl='5m')

        assert token['auth']['client_token']

        assert token['auth']['lease_duration'] == 300

        # Validate token
        lookup = await self.client.lookup_token(token['auth']['client_token'])
        assert token['auth']['client_token'] == lookup['data']['id']

    async def test_create_token_periodic(self):

        token = await self.client.create_token(period='30m')

        assert token['auth']['client_token']

        assert token['auth']['lease_duration'] == 1800

        # Validate token
        lookup = await self.client.lookup_token(token['auth']['client_token'])
        assert token['auth']['client_token'] == lookup['data']['id']
        assert lookup['data']['period'] == 1800

    async def test_token_roles(self):
        # No roles, list_token_roles == None
        before = await self.client.list_token_roles()
        assert not before

        # Create token role
        assert (await self.client.create_token_role('testrole')).status == 204

        # List token roles
        during = (await self.client.list_token_roles())['data']['keys']
        assert len(during) == 1
        assert during[0] == 'testrole'

        # Delete token role
        await self.client.delete_token_role('testrole')

        # No roles, list_token_roles == None
        after = await self.client.list_token_roles()
        assert not after

    async def test_create_token_w_role(self):
        # Create policy
        await self.prep_policy('testpolicy')

        # Create token role w/ policy
        assert (await self.client.create_token_role('testrole',
                                                         allowed_policies='testpolicy')).status == 204

        # Create token against role
        token = await self.client.create_token(lease='1h', role='testrole')
        assert token['auth']['client_token']
        assert token['auth']['policies'] == ['default', 'testpolicy']

        # Cleanup
        await self.client.delete_token_role('testrole')
        await self.client.delete_policy('testpolicy')

    async def test_ec2_role_crud(self):
        if 'aws-ec2/' in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend('aws-ec2')
        await self.client.enable_auth_backend('aws-ec2')

        # create a policy to associate with the role
        await self.prep_policy('ec2rolepolicy')

        # attempt to get a list of roles before any exist
        no_roles = await self.client.list_ec2_roles()
        # doing so should succeed and return None
        assert (no_roles is None)

        # test binding by AMI ID (the old way, to ensure backward compatibility)
        await self.client.create_ec2_role('foo',
                                          'ami-notarealami',
                                           policies='ec2rolepolicy')

        # test binding by Account ID
        await self.client.create_ec2_role('bar',
                                          bound_account_id='123456789012',
                                          policies='ec2rolepolicy')

        # test binding by IAM Role ARN
        await self.client.create_ec2_role('baz',
                                          bound_iam_role_arn='arn:aws:iam::123456789012:role/mockec2role',
                                          policies='ec2rolepolicy')

        # test binding by instance profile ARN
        await self.client.create_ec2_role('qux',
                                          bound_iam_instance_profile_arn='arn:aws:iam::123456789012:instance-profile/mockprofile',
                                          policies='ec2rolepolicy')

        roles = await self.client.list_ec2_roles()

        assert ('foo' in roles['data']['keys'])
        assert ('bar' in roles['data']['keys'])
        assert ('baz' in roles['data']['keys'])
        assert ('qux' in roles['data']['keys'])

        foo_role = await self.client.get_ec2_role('foo')
        assert (foo_role['data']['bound_ami_id'] == 'ami-notarealami')
        assert ('ec2rolepolicy' in foo_role['data']['policies'])

        bar_role = await self.client.get_ec2_role('bar')
        assert (bar_role['data']['bound_account_id'] == '123456789012')
        assert ('ec2rolepolicy' in bar_role['data']['policies'])

        baz_role = await self.client.get_ec2_role('baz')
        assert (baz_role['data']['bound_iam_role_arn'] == 'arn:aws:iam::123456789012:role/mockec2role')
        assert ('ec2rolepolicy' in baz_role['data']['policies'])

        qux_role = await self.client.get_ec2_role('qux')

        assert (
                qux_role['data']['bound_iam_instance_profile_arn'] == 'arn:aws:iam::123456789012:instance-profile/mockprofile')
        assert ('ec2rolepolicy' in qux_role['data']['policies'])

        # teardown
        await self.client.delete_ec2_role('foo')
        await self.client.delete_ec2_role('bar')
        await self.client.delete_ec2_role('baz')
        await self.client.delete_ec2_role('qux')

        await self.client.delete_policy('ec2rolepolicy')

        await self.client.disable_auth_backend('aws-ec2')
