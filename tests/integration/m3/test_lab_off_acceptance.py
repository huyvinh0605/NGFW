"""Catch invalid default-deny setups before they become product failures."""
import unittest

from lab_off_acceptance import DMZ, LAN, WAN, SetupError, tcp_policy, validate_policy_setup


def fixture():
    return {"default_deny": True, "policies": [
        {"id": "outbound", "priority": 10, "enabled": True, "action": "ALLOW",
         "source_zones": ["lan"], "destination_zones": ["wan"]},
        {"id": "published", "priority": 20, "enabled": True, "action": "ALLOW",
         "source_zones": ["wan"], "destination_zones": ["dmz"],
         "destination_addresses": [DMZ + "/32"], "services": ["tcp:443"]},
    ]}


class PolicySetupTests(unittest.TestCase):
    def test_scoped_allow_and_unmatched_default_drop(self):
        result = validate_policy_setup(fixture())
        self.assertEqual(result["wan-lan-default-deny"],
                         {"expected": "DROP", "actual": "DROP", "matched_rule": None})

    def test_global_allow_is_setup_invalid_even_with_default_deny_true(self):
        config = fixture()
        config["policies"].append({"id": "old-test-allow", "priority": 900,
                                   "enabled": True, "action": "ALLOW"})
        with self.assertRaisesRegex(SetupError, "old-test-allow"):
            validate_policy_setup(config)

    def test_explicit_drop_does_not_prove_default_drop(self):
        config = fixture()
        config["policies"].insert(0, {"id": "explicit-deny", "priority": 1,
                                     "enabled": True, "action": "DROP",
                                     "source_zones": ["wan"], "destination_zones": ["lan"]})
        with self.assertRaisesRegex(SetupError, "default policy"):
            validate_policy_setup(config)

    def test_service_range_and_address_or_are_respected(self):
        config = fixture()
        config["policies"][1]["destination_addresses"] = ["198.51.100.1/32", DMZ + "/32"]
        config["policies"][1]["services"] = ["udp:53", "tcp:440-445"]
        self.assertEqual(tcp_policy(config, "wan", "dmz", WAN, DMZ, 443),
                         ("ALLOW", "published"))
        self.assertEqual(tcp_policy(config, "wan", "dmz", WAN, DMZ, 446), ("DROP", None))
        self.assertEqual(tcp_policy(config, "wan", "lan", WAN, LAN, 443), ("DROP", None))

    def test_unknown_inspection_prerequisite_and_disabled_rule(self):
        config = fixture()
        config["policies"][0]["security_profile_id"] = "active-inspection"
        with self.assertRaisesRegex(SetupError, "inspection"):
            validate_policy_setup(config)
        config = fixture()
        config["policies"].append({"id": "disabled", "priority": 1, "enabled": False,
                                   "action": "ALLOW"})
        self.assertEqual(validate_policy_setup(config)["wan-lan-default-deny"]["actual"], "DROP")


if __name__ == "__main__":
    unittest.main()
