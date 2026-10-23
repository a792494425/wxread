import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from http.cookiejar import Cookie
from session_state import EncryptedCookieState


def cookie(name, value, expires=None):
    return Cookie(
        version=0, name=name, value=value, port=None, port_specified=False,
        domain='weread.qq.com', domain_specified=True, domain_initial_dot=False,
        path='/', path_specified=True, secure=True, expires=expires,
        discard=expires is None, comment=None, comment_url=None, rest={},
        rfc2109=False
    )

class CookieStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'cache' / 'session.enc'

    def state(self, source='curl secret v1'):
        return EncryptedCookieState(source, str(self.path))

    def test_disabled_without_curl_or_path(self):
        self.assertFalse(EncryptedCookieState('', str(self.path)).save({'wr_skey': 'token'}))
        self.assertFalse(EncryptedCookieState('curl').restore({}))
        self.assertFalse(self.path.exists())

    def test_round_trip_encrypted_does_not_expose_secrets(self):
        st = self.state()
        cookies={'wr_skey': 'sensitive_token_a', 'wr_rt': 'rotating_refresh_a'}
        self.assertTrue(st.save(cookies))
        raw=self.path.read_bytes()
        self.assertNotIn(b'sensitive_token_a', raw)
        self.assertNotIn(b'rotating_refresh_a', raw)
        self.assertNotIn(b'curl secret v1', raw)
        restored={'old': 'kept'}
        self.assertTrue(st.restore(restored))
        self.assertEqual(restored['wr_skey'], 'sensitive_token_a')
        self.assertEqual(restored['wr_rt'], 'rotating_refresh_a')
        self.assertEqual(restored['old'], 'kept')

    def test_new_login_secret_disables_old_cache(self):
        self.state().save({'wr_skey': 'old'})
        initial={'wr_skey': 'new'}
        self.assertFalse(self.state('new curl secret').restore(initial))
        self.assertEqual(initial['wr_skey'],'new')
        self.assertTrue(self.state('new curl secret').save(initial))
        restored={}
        self.assertTrue(self.state('new curl secret').restore(restored))
        self.assertEqual(restored['wr_skey'],'new')

    def test_invalid_file_falls_back_without_overwriting(self):
        self.path.parent.mkdir()
        self.path.write_text('not encrypted', encoding='utf-8')
        initial={'wr_skey': 'live-from-secret'}
        self.assertFalse(self.state().restore(initial))
        self.assertEqual(initial,{'wr_skey':'live-from-secret'})

    def test_response_cookie_rotation_and_deletion(self):
        old={'wr_skey':'old', 'wr_rt':'original', 'wr_pf':'unused'}
        response=SimpleNamespace(cookies=[cookie('wr_skey','new'), cookie('wr_rt','next'), cookie('wr_pf', '', 1)])
        self.assertTrue(EncryptedCookieState.absorb_response(old,response))
        self.assertEqual(old, {'wr_skey':'new','wr_rt':'next'})
        self.assertFalse(EncryptedCookieState.absorb_response(old, SimpleNamespace(cookies=[])))

    def test_unexpired_cookie_survives_process_restart(self):
        previous={'wr_skey':'initial8','wr_rt':'original-long-token'}
        response=SimpleNamespace(cookies=[cookie('wr_skey','the-full-skey-has-more-than-eight'),cookie('wr_rt','rolled')])
        EncryptedCookieState.absorb_response(previous,response)
        self.assertTrue(self.state().save(previous))
        loaded={'wr_skey':'initial8','wr_rt':'original-long-token'}
        self.assertTrue(self.state().restore(loaded))
        self.assertEqual(loaded['wr_skey'],'the-full-skey-has-more-than-eight')
        self.assertEqual(loaded['wr_rt'],'rolled')

    def test_save_atomic_fallback_on_directory_error(self):
        file_not_dir=Path(self.tmp.name)/'notdir'
        file_not_dir.write_text('file')
        st=EncryptedCookieState('curl',str(file_not_dir/'session.enc'))
        self.assertFalse(st.save({'wr_skey': 'one'}))
        self.assertEqual(file_not_dir.read_text(),'file')

if __name__ == '__main__':
    unittest.main()
