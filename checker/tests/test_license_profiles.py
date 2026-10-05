import importlib
import os
import sys
import tempfile
import unittest

# checker.py creates its data directories at import time; keep them out of /data.
_TMP = tempfile.mkdtemp(prefix="cib-test-")
os.environ.setdefault("SBOM_DIR", os.path.join(_TMP, "sboms"))
os.environ.setdefault("DATA_DIR", _TMP)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def load(env):
    for k in ("LICENSE_PROFILE", "LICENSE_DENY_LIST"):
        os.environ.pop(k, None)
    os.environ.update(env)
    sys.modules.pop("checker", None)
    return importlib.import_module("checker")


def sbom(*licences):
    return {"components": [{"name": f"pkg{i}", "version": "1", "licenses": [{"license": {"id": lic}}]} for i, lic in enumerate(licences)]}


class TestProfiles(unittest.TestCase):
    def test_default_is_product_and_flags_gpl(self):
        c = load({})
        self.assertEqual(c.LICENSE_PROFILE, "product")
        self.assertEqual(len(c.check_licenses("img", sbom("GPL-2.0-only", "MIT"))), 1)

    def test_internal_ignores_gpl_but_flags_agpl(self):
        c = load({"LICENSE_PROFILE": "internal"})
        v = c.check_licenses("img", sbom("GPL-2.0-only", "GPL-3.0-or-later", "AGPL-3.0-only", "MIT"))
        self.assertEqual([x["license"] for x in v], ["AGPL-3.0-only"])

    def test_none_turns_licence_checks_off(self):
        c = load({"LICENSE_PROFILE": "none"})
        self.assertEqual(c.check_licenses("img", sbom("GPL-2.0-only", "AGPL-3.0-only")), [])

    def test_explicit_deny_list_overrides_the_profile(self):
        c = load({"LICENSE_PROFILE": "internal", "LICENSE_DENY_LIST": "MIT"})
        self.assertEqual(len(c.check_licenses("img", sbom("MIT", "AGPL-3.0-only"))), 1)

    def test_blank_deny_list_does_not_disable_checking(self):
        """docker compose always passes LICENSE_DENY_LIST (blank when unset); that must fall through to the profile."""
        c = load({"LICENSE_DENY_LIST": ""})
        self.assertEqual(len(c.check_licenses("img", sbom("GPL-3.0-only"))), 1)

    def test_unknown_profile_is_a_startup_error_not_a_silent_default(self):
        with self.assertRaises(SystemExit):
            load({"LICENSE_PROFILE": "enterprise"})


if __name__ == "__main__":
    unittest.main()
