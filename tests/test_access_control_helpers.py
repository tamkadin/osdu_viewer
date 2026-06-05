import os
import sys
import unittest


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from access_control import infer_group_type, is_valid_group_email


class AccessControlHelperTests(unittest.TestCase):
    def test_infer_group_type(self):
        cases = {
            "users@osdu.group": "USER",
            "users.datalake.viewers@osdu.group": "USER",
            "data.default.viewers@osdu.group": "DATA",
            "service.search.user@osdu.group": "SERVICE",
            "notification.pubsub@osdu.group": "SYSTEM",
            "partition.pubsub@osdu.group": "SYSTEM",
            "cron.job@osdu.group": "SYSTEM",
            "other.group@osdu.group": "UNKNOWN",
        }
        for group_email, expected in cases.items():
            with self.subTest(group_email=group_email):
                self.assertEqual(infer_group_type(group_email), expected)

    def test_group_email_validation(self):
        self.assertTrue(is_valid_group_email("service.file.viewers@osdu.group"))
        self.assertFalse(is_valid_group_email(""))
        self.assertFalse(is_valid_group_email("service.file.viewers"))
        self.assertFalse(is_valid_group_email("service.file.viewers@osdu"))
        self.assertFalse(is_valid_group_email("service/file.viewers@osdu.group"))


if __name__ == "__main__":
    unittest.main()
