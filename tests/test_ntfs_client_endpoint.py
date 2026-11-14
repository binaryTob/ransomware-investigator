"""Missing broker endpoint reproducer: synthetic files only, never real IPC."""
from unittest.mock import patch

from tests.common import ProjectTest
from tests.test_ntfs_broker import request
from ransomware_investigator.ntfs import client


class MissingBrokerEndpointTests(ProjectTest):
    def test_missing_endpoint_fails_before_socket_or_privileged_fallback(self):
        endpoint = self.work / "missing-runtime" / "broker.sock"
        prepared = request("ntfs.directory", {"inode": 5, "cursor": 0, "max_entries": 256,
                           "read_budget": 512 * 1024**2, "timeout_ms": 15000})
        with patch.object(client, "SOCKET", endpoint), \
                patch.object(client.socket, "socket") as connect, \
                patch("subprocess.Popen") as spawn:
            with self.assertRaises(FileNotFoundError) as caught:
                client.execute_physical(prepared)
        self.assertEqual(caught.exception.filename, str(endpoint))
        connect.assert_not_called()
        spawn.assert_not_called()
