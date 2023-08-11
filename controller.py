from model import PacketCapture
from PyQt5.QtCore import pyqtSlot, QObject, pyqtSignal, QThread
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP
from PyQt5.QtWidgets import QMessageBox


# The PacketEmitter class is a QObject that emits packets.
class PacketEmitter(QObject):
    packet_emitted = pyqtSignal(list)

    def __init__(self, capture_instance):
        super().__init__()
        self.capture_instance = capture_instance
        self.capture_instance.packet_emitted.connect(self.emit_packet)
        self.filtered_packets = []

    def emit_packet(self, packet):
        """
        The function emits a packet using a signal.


        """
        self.packet_emitted.emit(packet)


# The CaptureThread class is a subclass of QThread that is used for capturing data.
class CaptureThread(QThread):
    packet_emitted = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.capture_instance = PacketCapture()

    def run(self):
        """
        The function runs a packet emitter in a separate thread and connects its emitted packets to
        another signal.
        """
        packet_emitter = PacketEmitter(self.capture_instance)
        packet_emitter.packet_emitted.connect(self.packet_emitted.emit)
        print("I am threading")

        self.capture_instance.start()

    def stop(self):
        """
        The function "stop" stops the capture instance.
        """
        self.capture_instance.stop()

    def save_to_file(self):
        """
        The function saves captured packets to a file, either overwriting the existing file or appending
        to it based on user confirmation.
        :return: The function does not explicitly return anything.
        """
        if not self.capture_instance.captured_packets:
            msgBox = QMessageBox()
            msgBox.setIcon(QMessageBox.Information)
            msgBox.setText(
                "No packets have been captured. Please start the packet capture first.")
            msgBox.setWindowTitle("No Packets Captured")
            msgBox.exec()
            return

        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setText(
            "Do you want to overwrite the existing packets.txt file?")
        msgBox.setWindowTitle("Overwrite Confirmation")
        msgBox.setStandardButtons(QMessageBox.Yes | QMessageBox.No)

        returnValue = msgBox.exec()
        if returnValue == QMessageBox.Yes:
            # If 'Yes' is clicked, overwrite the existing file
            with open('packets.txt', 'w') as f:
                for packet in self.capture_instance.captured_packets:
                    f.write(str(packet) + '\n')
        elif returnValue == QMessageBox.No:
            # If 'No' is clicked, append to the existing file
            with open('packets.txt', 'a') as f:
                for packet in self.capture_instance.captured_packets:
                    f.write(str(packet) + '\n')
