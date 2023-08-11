import unittest
import time
from model import PacketCapture

class PacketCaptureTest(unittest.TestCase):

    def setUp(self):
        """
        The setUp function initializes a PacketCapture object.
        """
        self.packet_capture = PacketCapture()

    def tearDown(self):
        """
        The tearDown function stops the packet capture and waits for 1 second.
        """
        # Ensure that the packet capture stops after each test
        self.packet_capture.stop()
        time.sleep(1)  # Allow some time for the capture to actually stop

    def test_get_protocol_name(self):
        """
        The function `test_get_protocol_name` tests the `get_protocol_name` method of the
        `packet_capture` object by asserting that the returned protocol names match the expected values
        for different protocol numbers.
        """
        self.assertEqual(self.packet_capture.get_protocol_name(1), "ICMP")
        self.assertEqual(self.packet_capture.get_protocol_name(6), "TCP")
        self.assertEqual(self.packet_capture.get_protocol_name(17), "UDP")
        self.assertEqual(self.packet_capture.get_protocol_name(123), "Unknown")

    def test_start_and_stop(self):
        """
        The function tests the start and stop methods of a packet capture object.
        """
        self.packet_capture.start()
        self.assertEqual(self.packet_capture._stop_flag, False)
        self.packet_capture.stop()
        self.assertEqual(self.packet_capture._stop_flag, True)

    def test_get_protocol_name_invalid(self):
        """
        The function `test_get_protocol_name_invalid` tests the `get_protocol_name` method of the
        `packet_capture` object by passing an invalid protocol number and asserting that the returned
        protocol name is "Unknown".
        """
        self.assertEqual(self.packet_capture.get_protocol_name(9999), "Unknown")

if __name__ == '__main__':
    unittest.main()

# Note: if the testing doesnot quit by itselt try control + x