import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(HERE.name.replace("-", "_"), HERE / "tool.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)

class CommonTests(unittest.TestCase):
    def test_json_decimal_ignores_caller_traps(self):
        import decimal
        with decimal.localcontext() as caller:
            caller.prec = 2
            caller.Emax, caller.Emin = 2, -2
            caller.traps[decimal.InvalidOperation] = False
            before = dict(caller.flags)
            with self.assertRaises(tool.InputError):
                tool.parse_json('[1e99999999999999999999999999]')
            self.assertEqual(tool.parse_json('[1.2345]')[0], decimal.Decimal('1.2345'))
            self.assertEqual(dict(caller.flags), before)


    def cli(self, *args):
        return subprocess.run([sys.executable, str(HERE / "tool.py"), *args], cwd=HERE,
                              capture_output=True, text=True, timeout=10)
    def test_cli_pass(self):
        result = self.cli("examples/" + PASS, *ARGS)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "pass")
        self.assertEqual(result.stderr, "")
    def test_cli_fail(self):
        result = self.cli("examples/" + FAIL, *ARGS)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "fail")
    def test_cli_malformed(self):
        result = self.cli("examples/" + MALFORMED, *ARGS)
        self.assertEqual(result.returncode, MALFORMED_CODE, result.stdout + result.stderr)
        self.assertIn(json.loads(result.stdout)["status"], ("fail", "error"))
    def test_cli_missing_file(self):
        result = self.cli("nonexistent-input", *ARGS)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["error"], "unreadable_utf8_input")
    def test_cli_invalid_arguments_are_redacted(self):
        result = self.cli("--unrecognized-secret-value")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["error"], "invalid_arguments")
        self.assertNotIn("unrecognized-secret-value", result.stdout + result.stderr)
    def test_cli_help(self):
        result = self.cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout)
    def test_cli_stability(self):
        a = self.cli("examples/" + FAIL, *ARGS)
        b = self.cli("examples/" + FAIL, *ARGS)
        self.assertEqual(a.stdout, b.stdout)
    def test_file_limit_and_utf8(self):
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"x" * (tool.MAX_BYTES + 1))
            with self.assertRaises(tool.InputError):
                tool.read_text(path)
            path.write_bytes(b"\xff")
            with self.assertRaises(UnicodeDecodeError):
                tool.read_text(path)
    def test_json_parser_safety(self):
        for text in ('{"x":1,"x":2}', '[NaN]', '[' * 130 + '0' + ']' * 130):
            with self.subTest(text=text[:20]), self.assertRaises(tool.InputError):
                tool.parse_json(text)
    def test_report_cap_preserves_count(self):
        report = tool.Report("test")
        for i in range(101):
            report.add("sample", record=i)
        result = report.finish()
        self.assertEqual(len(result["findings"]), 100)
        self.assertEqual(result["summary"]["finding_count"], 101)
        self.assertTrue(result["findings_truncated"])

    def test_adversarial_cli_and_read_only_corpus(self):
        samples = ['', 'null', 'true', '0', '[]', '{}', '[null]', '[true]', '[1]',
                   '["NaN"]', '[{}]', '[[]]', '{"x":1,"x":2}',
                   '[1e99999999999999999999999999]', '[NaN]', '[Infinity]',
                   '"\\ud800"', '["\\ud800"]', '{', '[', '["a","b"]',
                   '[1e-99999999999999999999999999]']
        before = {path: path.read_bytes() for path in (HERE / 'examples').iterdir()}
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            path = Path(directory) / 'input.txt'
            for sample in samples:
                with self.subTest(sample=sample):
                    path.write_text(sample, encoding='utf-8')
                    result = self.cli(str(path), *ARGS)
                    self.assertIn(result.returncode, (0, 1, 2), result.stderr)
                    self.assertEqual(result.stderr, '')
                    self.assertIn(json.loads(result.stdout)['status'], ('pass','fail','error'))
                    self.assertEqual(path.read_text(encoding='utf-8'), sample)
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)

PASS = 'pass.json'
FAIL = 'fail.json'
MALFORMED = 'malformed.json'
MALFORMED_CODE = 2
ARGS = ['--pointers', 'examples/pointers.json']

class AuditTests(unittest.TestCase):
    def test_rfc_keys(self):
        doc={'foo':['bar','baz'],'':0,'a/b':1,'m~n':8,'~1':9,'c%d':2}
        result=tool.audit(doc,['','/foo','/foo/0','/','/a~1b','/m~0n','/~01','/c%d'])
        self.assertEqual(result['summary']['resolved'],8)
    def test_no_unicode_normalization(self):
        self.assertEqual(tool.audit({'é':1},['/e\u0301'])['status'],'fail')
    def test_bad_escape_fragment_and_no_slash(self):
        result=tool.audit({},['a','#/a','/~','/~2'])
        self.assertEqual(result['summary']['finding_count'],4)
    def test_array_indices(self):
        result=tool.audit([1],['/00','/-','/-1','/١','/1','/'+ '9'*10000])
        self.assertEqual(result['summary']['finding_count'],6)
    def test_numeric_object_members_are_not_array_indices(self):
        self.assertEqual(tool.audit({'00':1,'-':2},['/00','/-'])['status'],'pass')
    def test_scalar_traversal(self): self.assertEqual(tool.audit({'a':None},['/a/x'])['findings'][0]['code'],'scalar_traversal')
    def test_null_exists(self): self.assertEqual(tool.audit({'a':None},['/a'])['status'],'pass')
    def test_pointer_list_shape(self):
        for value in ([],{},'x'):
            with self.assertRaises(tool.InputError): tool.audit({},value)
    def test_nonstring_pointer_is_finding(self): self.assertEqual(tool.audit({},[1])['status'],'fail')
    def test_depth_limit(self): self.assertEqual(tool.audit({},['/a'*129])['findings'][0]['code'],'pointer_depth_limit')
    def test_payload_not_emitted(self): self.assertNotIn('SUPERSECRET',json.dumps(tool.audit({'secret':'SUPERSECRET'},['/secret'])))


class MaintenanceReceiptTests(unittest.TestCase):
    def test_maintenance_receipt_is_fail_closed(self):
        import copy
        import importlib.util
        root = Path(__file__).resolve().parent
        spec = importlib.util.spec_from_file_location('release_validation', root / 'scripts/validate_release.py')
        validation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validation)
        record = json.loads((root / 'docs/MIGRATION.json').read_text())
        receipt = json.loads((root / 'docs/MAINTENANCE_2026-10-21.json').read_text())
        original = {entry['path']: entry['sha256'] for entry in record['preserved_files']}
        self.assertEqual(validation.maintenance_hashes(record, None), original)
        result = validation.maintenance_hashes(record, receipt)
        for change in receipt['changes']:
            self.assertEqual(result[change['path']], change['current_sha256'])
        invalid = []
        for field, value in [('path', '../tool.py'), ('path', 'README.md'),
                             ('original_sha256', '0' * 64), ('current_sha256', 'invalid'), ('reason', '')]:
            candidate = copy.deepcopy(receipt)
            candidate['changes'][0][field] = value
            invalid.append(candidate)
        candidate = copy.deepcopy(receipt)
        candidate['changes'].append(candidate['changes'][0].copy())
        invalid.append(candidate)
        candidate = copy.deepcopy(receipt)
        candidate['repository_id'] = 0
        invalid.append(candidate)
        for candidate in invalid:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validation.maintenance_hashes(record, candidate)

if __name__ == '__main__': unittest.main()
