#!/usr/bin/env python3
"""Offline retirement regressions; no services, network, coordinates or host files."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'deploy/bot'))
if os.name == 'nt':
    def forbidden_lock(*args):
        raise AssertionError('retirement must not acquire a configuration lock')
    sys.modules.setdefault('fcntl', types.SimpleNamespace(flock=forbidden_lock, LOCK_EX=2, LOCK_NB=4, LOCK_UN=8))
spec = importlib.util.spec_from_file_location('retired_bot', ROOT / 'deploy/bot/pdg-bot.py')
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)
import checks
import mitm_server
import sb2mihomo

class Retirement(unittest.TestCase):
    def test_all_mutators_refuse_before_io_and_keep_legacy_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'mitm.json'
            legacy = b'{"wloc":{"enabled":true,"locations":[{"name":"synthetic","lat":1,"lon":2}]},"other":{"keep":true}}'
            path.write_bytes(legacy)
            with patch.object(bot, 'MITM_CONFIG', str(path)), patch.object(bot, '_pdgtx', side_effect=AssertionError('transaction')), patch.object(bot, 'sh', side_effect=AssertionError('shell')):
                for platform in ('ios', 'android'):
                    with patch.object(bot, '_platform', return_value=platform):
                        for fn, args in [(bot.wloc_add, ('synthetic', 1, 2)), (bot.wloc_del, ('synthetic',)), (bot.wloc_switch, ('synthetic',)), (bot.wloc_enable, (True,)), (bot.wloc_enable, (False,)), (bot.set_wloc, (True, 1, 2)), (bot._mitm_transact, ({'enabled': True},))]:
                            self.assertFalse(fn(*args)[0])
                        self.assertEqual(bot._mitm_enabled_domains(), [])
                        self.assertEqual(bot._mitm_domains_from(legacy), [])
                self.assertEqual(path.read_bytes(), legacy)

    def test_stale_callbacks_refuse_and_menu_has_no_entry(self):
        messages=[]
        with patch.object(bot, '_platform', return_value='ios'), patch.object(bot, '_dot_host', return_value='example.invalid'), patch.object(bot, 'edit', side_effect=lambda c,m,t,k=None: messages.append(t)):
            for action in ('wloc','wloc:menu','wloc:on','wloc:off','wloc:add','wloc:sw:0','wloc:rm:0'):
                bot.state[1]='wloc_add'
                bot.handle_cb(1,2,action)
                self.assertNotIn(1,bot.state)
                self.assertEqual(messages[-1], '此功能已移除，请返回当前菜单。')
            _, kb=bot._nav('ops')
            self.assertFalse(any(str(b.get('callback_data','')).startswith('wloc') for row in kb['inline_keyboard'] for b in row))

    def test_restored_enabled_config_registers_no_plugin_and_is_not_read(self):
        with patch('builtins.open',side_effect=AssertionError('legacy config should remain unread')):
            self.assertEqual(mitm_server.load_from_config('/fixture/mitm.json'),[])
        self.assertEqual(mitm_server.PLUGIN_DOMAINS,{})

    def test_renderer_excludes_retired_domains_and_preserves_other_plugin(self):
        model={'inbounds': [], 'outbounds':[{'type':'direct','tag':'JP'}], 'route':{'final':'JP','rules':[]}}
        rendered,_=sb2mihomo.singbox_to_mihomo(model,mitm_domains=['gs-loc.apple.com','GS-LOC-CN.APPLE.COM.','retained.example'])
        self.assertIn('DOMAIN-SUFFIX,retained.example,MITM-OUT',rendered['rules'])
        self.assertFalse(any('gs-loc' in rule.lower() for rule in rendered['rules']))
        rendered,_=sb2mihomo.singbox_to_mihomo(model,mitm_domains=['gs-loc.apple.com'])
        self.assertFalse(any(p.get('name')=='MITM-OUT' for p in rendered['proxies']))

    def test_legacy_hijack_does_not_reenter_bot_renderer(self):
        with patch.object(bot,'_platform',return_value='ios'), patch('builtins.open',return_value=io.StringIO('domain:gs-loc.apple.com\ndomain:GS-LOC-CN.APPLE.COM.\ndomain:retained.example\n')):
            self.assertEqual(bot._mitm_domains(),['retained.example'])

    def check_state(self, config='{}', hijack='', core='rules: []\n', unreadable=False):
        files={'/etc/privdns-gateway/mitm.json':config,'/etc/mosdns/rules/mitm_hijack.txt':hijack,'/etc/mihomo/config.yaml':core}
        def fixture(path,*args,**kwargs):
            if unreadable: raise PermissionError('synthetic')
            return io.StringIO(files[path])
        with patch('builtins.open',side_effect=fixture): return checks.check_mitm()

    def test_doctor_detects_each_restore_residue_without_echoing_locations(self):
        for result in [self.check_state(config='{"wloc":{"enabled":true,"private":"DO_NOT_ECHO"}}'),self.check_state(hijack='domain:gs-loc.apple.com\n'),self.check_state(core='rules: ["DOMAIN-SUFFIX,gs-loc-cn.apple.com,MITM-OUT"]')]:
            self.assertEqual(result[0],'fail')
            self.assertNotIn('DO_NOT_ECHO',str(result))
            self.assertEqual(result[1], '配置残留')
            self.assertNotIn('WLOC', str(result))
        self.assertIsNone(self.check_state(config='{"wloc":{"enabled":false,"locations":[{"name":"synthetic"}]}}',hijack='domain:retained.example\n'))

    def test_current_checks_and_menus_do_not_advertise_removed_feature(self):
        self.assertIsNone(self.check_state())
        with patch('builtins.open', side_effect=FileNotFoundError):
            self.assertIsNone(checks.check_mitm())
        for name in ('WLOC_BACK', '_wloc_watch_async', '_wloc_state', 'wloc_add_reply'):
            self.assertFalse(hasattr(bot, name), name)
        for platform in ('android', 'ios'):
            with patch.object(bot, '_platform', return_value=platform), patch.object(bot, '_dot_host', return_value='example.invalid'):
                for menu in ('client', 'ops'):
                    self.assertNotIn('wloc', str(bot._nav(menu)).lower())

    def test_doctor_fails_closed_on_malformed_or_unreadable_state(self):
        self.assertEqual(self.check_state(config='{bad')[0],'fail')
        self.assertEqual(self.check_state(unreadable=True)[0],'fail')

if __name__ == '__main__': unittest.main(verbosity=2)
