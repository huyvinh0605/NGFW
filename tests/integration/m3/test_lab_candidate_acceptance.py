"""Regress false config-null reports, silent NOT_RUN, and unsafe cleanup."""
import copy
import unittest

from lab_candidate_acceptance import CaseFailure, candidate_semantics, config_data, response_data, run_case


def envelope():
    return {"success": True, "data": {
        "running": {"max_sessions": 50000, "security_profiles": [], "policies": [
            {"id": "lan-wan", "priority": 10, "enabled": True, "action": "ALLOW",
             "source_zones": ["lan"], "destination_zones": ["wan"]}]},
        "candidate": {"max_sessions": 51000}, "version": {"version": 93},
        "candidate_valid": True, "candidate_validation": {"state": "NOT_RUN"}}}


class FakeLab:
    def __init__(self, fail_validate=False, fail_restore=False):
        self.view = envelope()["data"]
        self.initial = copy.deepcopy(self.view["candidate"])
        self.fail_validate, self.fail_restore = fail_validate, fail_restore
        self.audit, self.files = [], {}

    def connect(self): pass
    def close(self): pass
    def identity(self): pass
    def config(self): return config_data({"success": True, "data": copy.deepcopy(self.view)})
    def candidate(self): return copy.deepcopy(self.view["candidate"])
    def save(self, name, value): self.files[name] = copy.deepcopy(value)
    def snapshot(self, name): return {"activation_files": "", "kernel_hash": "constant"}

    def request(self, method, path, body=None, expected=200):
        if path.startswith("/audit"):
            data = {"items": copy.deepcopy(self.audit), "total": len(self.audit)}
        elif path == "/config/candidate" and method == "PUT":
            if self.fail_restore and body == self.initial:
                raise CaseFailure("restore refused")
            self.view["candidate"] = copy.deepcopy(body)
            self.view["candidate_validation"] = {"state": "NOT_RUN", "candidate_checksum": str(body["max_sessions"]), "checked_checksum": ""}
            self.audit.append({"id": str(len(self.audit)), "action": "UPDATE"})
            data = self.view["candidate"]
        elif path == "/policies/validate":
            if self.fail_validate:
                raise CaseFailure("validate rejected")
            state = self.view["candidate_validation"]
            state.update(state="VALID", checked_checksum=state["candidate_checksum"])
            data = {"valid": True}
        else:
            raise AssertionError((method, path))
        return {"success": True, "data": copy.deepcopy(data)}


class CandidateAcceptanceTests(unittest.TestCase):
    def test_old_selector_reproduces_false_null_on_valid_response(self):
        raw = envelope()
        self.assertIsNone(raw.get("running"))
        self.assertIsNone(raw.get("version"))
        actual = config_data(raw)
        self.assertEqual(actual["running"]["max_sessions"], 50000)
        self.assertEqual(actual["version"]["version"], 93)

    def test_real_null_or_missing_config_fields_fail_explicitly(self):
        for name in ("running", "candidate", "version", "candidate_validation"):
            for missing in (False, True):
                raw = envelope()
                if missing: del raw["data"][name]
                else: raw["data"][name] = None
                with self.subTest(name=name, missing=missing), self.assertRaisesRegex(CaseFailure, "data." + name):
                    config_data(raw)

    def test_error_envelopes_do_not_become_empty_data(self):
        for raw in ({"success": False, "data": {}}, {"success": True}, None):
            with self.subTest(raw=raw), self.assertRaises(CaseFailure):
                response_data(raw)

    def test_restore_accepts_only_equivalent_selector_normalization(self):
        original = {"policies": [{"action": "ALLOW", "priority": 10,
                                 "destination_zones": ["lan", "dmz"],
                                 "destination_addresses": ["10.20.0.10"],
                                 "services": ["TCP:0443"]}]}
        normalized = {"policies": [{"action": "ALLOW", "priority": 10,
                                   "destination_zones": ["dmz", "lan"],
                                   "destination_addresses": ["10.20.0.10/32"],
                                   "services": ["tcp:443"]}]}
        self.assertEqual(candidate_semantics(original), candidate_semantics(normalized))
        for field, value in (("action", "DROP"), ("priority", 11), ("services", ["tcp:80"]),
                             ("destination_addresses", ["10.20.0.10/24"]),
                             ("destination_zones", ["dmz"])):
            changed = copy.deepcopy(normalized)
            changed["policies"][0][field] = value
            with self.subTest(field=field):
                self.assertNotEqual(candidate_semantics(original), candidate_semantics(changed))

    def test_successful_full_workflow_reports_pass_and_restores_draft(self):
        lab = FakeLab()
        result = run_case(lab, "test-profile")
        self.assertEqual(result["status"], "PASS", result)
        self.assertTrue(result["workflow_completed"])
        self.assertEqual(result["restore"], "PASS")
        self.assertEqual(lab.candidate(), lab.initial)
        self.assertEqual(lab.view["version"]["version"], 93)
        self.assertEqual(result["assertion_counts"]["FAIL"], 0)

    def test_validation_failure_stops_workflow_and_still_restores(self):
        lab = FakeLab(fail_validate=True)
        result = run_case(lab, "test-profile")
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["workflow_completed"])
        self.assertEqual(result["restore"], "PASS")
        self.assertEqual(lab.candidate(), lab.initial)

    def test_cleanup_failure_cannot_report_pass(self):
        result = run_case(FakeLab(fail_restore=True), "test-profile")
        self.assertTrue(result["workflow_completed"])
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["restore"], "FAIL")


if __name__ == "__main__":
    unittest.main()
