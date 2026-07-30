import sys
import unittest
from unittest import result
from unittest.mock import MagicMock, patch

    sys.path.append('src/redteam')
    import simulate_attacks

    class TestSimulateAttacks(unittest.TestCase):

    def test_try_login(self):
            mock_client = MagicMock()

            mock_stdout = MagicMock()
            mock_stdout.read.return_value = b"root\n"

            mock_stderr = MagicMock()
            mock_stderr.read.return_value = b""

            mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

            result = simulate_attacks.try_login(mock_client, "root")
            print(result)


    def test_ssh_exec(self):
            mock_client = MagicMock()

            mock_stdout = MagicMock()
            mock_stdout.read.return_value = b"root\n"

            mock_stderr = MagicMock()
            mock_stderr.read.return_value = b""

            mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

            result = simulate_attacks.ssh_exec(mock_client, "whoami")

            self.assertEqual(result, "root")
            mock_client.exec_command.assert_called_with("whoami", timeout=15)

    if __name__ == '__main__':
        unittest.main()