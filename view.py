import PyQt5.QtWidgets as qtw
import PyQt5.QtGui as qtg
import datetime
import PyQt5.QtCore as qtc
from scapy.layers.inet import IP, TCP, UDP, ICMP

import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMenu, QVBoxLayout, QSizePolicy, QMessageBox, QWidget, QPushButton, QGridLayout, QLabel, QLineEdit, QTextEdit, QTableWidget
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidgetItem
from PyQt5.QtWidgets import QAction
from PyQt5.QtCore import pyqtSlot, QObject, pyqtSignal
from bisect import bisect_left
from collections import defaultdict


from controller import CaptureThread


# The Minishark class is a subclass of QMainWindow.
class Minishark(QMainWindow):
    packet_emitted = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.packet_list = []
        self.capture_thread = CaptureThread()
        self.capture_thread.packet_emitted.connect(self.packetHandler)
        self.table_widget = QTableWidget()

        self.initUI()
        self.table_widget.clicked.connect(self.show_packet_details)
        self.packet_dict = defaultdict(list)
        self.packet_list = []
        self.packet_dict = {'ip': {}, 'protocol': {}, 'time': {}}

    def initUI(self):
        """
        The `initUI` function initializes the user interface for the Minishark application, including
        the window title, size, status bar, toolbar, central widget, labels, line edit, text edit,
        button, table widget, and packet details.
        """
        self.setWindowTitle("Minishark")
        self.setGeometry(100, 100, 800, 600)

        # Create a status bar
        self.statusBar().showMessage('Ready')

        # Create a toolbar
        toolbar = self.addToolBar('Toolbar')
        captureAction = QAction(
            QIcon('icons/start.png'), 'Start Capture', self)
        stopAction = QAction(QIcon('icons/stop.png'), 'Stop Catpure', self)
        restartAction = QAction(
            QIcon('icons/reload.png'), 'Restart Capture', self)
        saveAction = QAction(QIcon('icons/save.png'), 'Save Packets', self)
        aboutAction = QAction(QIcon('icons/about.png'), 'About', self)

        # Connect actions to their respective slots/methods
        captureAction.triggered.connect(self.startCapture)
        stopAction.triggered.connect(self.stopCapture)
        restartAction.triggered.connect(self.restartCapture)
        saveAction.triggered.connect(self.savePackets)
        aboutAction.triggered.connect(self.about)

        # Add actions to the toolbar
        toolbar.addAction(captureAction)
        toolbar.addAction(stopAction)
        toolbar.addAction(restartAction)
        toolbar.addAction(saveAction)
        toolbar.addAction(aboutAction)

        # Create a central widget
        centralWidget = QWidget(self)
        self.setCentralWidget(centralWidget)

        # Create a grid layout
        gridLayout = QGridLayout()
        centralWidget.setLayout(gridLayout)

        # Create a label
        label = QLabel('Minishark', self)
        label.setAlignment(Qt.AlignCenter)
        label.setFont(qtg.QFont('Arial', 24))
        gridLayout.addWidget(label, 0, 0, 1, 4)

        # Create a line edit
        self.lineEdit = QLineEdit(self)  # assign to self.lineEdit
        self.lineEdit.setPlaceholderText('Enter a filter')
        gridLayout.addWidget(self.lineEdit, 1, 0, 1, 4)

        # Create a text edit
        self.textEdit = QTextEdit(self)
        gridLayout.addWidget(self.textEdit, 2, 0, 1, 4)

        # Create a button
        filterbutton = QPushButton('Apply', self)
        gridLayout.addWidget(filterbutton, 3, 0, 1, 4)
        filterbutton.clicked.connect(self.filterPacket)

        # Create a label
        label = QLabel('Packet List', self)
        label.setAlignment(Qt.AlignCenter)
        label.setFont(qtg.QFont('Arial', 16))
        gridLayout.addWidget(label, 4, 0, 1, 4)

        # Create a table widget
        self.table_widget = QTableWidget(self)
        self.table_widget.setColumnCount(4)
        self.table_widget.setHorizontalHeaderLabels(
            ['Time', 'Source', 'Destination', 'Protocol'])
        gridLayout.addWidget(self.table_widget)
        self.table_widget.clicked.connect(self.show_packet_details)

        # Create a label
        label = QLabel('Packet Details', self)
        label.setAlignment(Qt.AlignCenter)
        label.setFont(qtg.QFont('Arial', 16))
        gridLayout.addWidget(label, 6, 0, 1, 4)

        # Create a text edit
        self.packetDetail = QTextEdit(self)
        gridLayout.addWidget(self.packetDetail, 7, 0, 1, 4)

        # Show the window
        self.show()

    def startCapture(self):
        """
        The function "startCapture" starts a capture thread and displays a message in the status bar
        indicating that capturing is in progress.
        """
        self.capture_thread.start()
        # print("starting")
        self.statusBar().showMessage('Capturing')

    def stopCapture(self):
        """
        The function `stopCapture` stops a capture thread and displays a message in the status bar.
        """
        self.capture_thread.stop()
        self.statusBar().showMessage('Stopped')

    def savePackets(self):
        """
        The function saves captured packets to a file and prints a message indicating that the save
        operation was successful.
        """
        self.capture_thread.save_to_file()
        print("saved")

    def about(self):
        """
        The above function displays an "About" message box with information about the Minishark
        application.
        """
        msgBox = QMessageBox()
        msgBox.setWindowTitle("About Minishark")
        msgBox.setText("Minishark v1.0\nCreated by Your Avishek Dhakal")
        msgBox.exec()

    def restartCapture(self):
        """
        The function restarts the packet capture by clearing the packet list, resetting the table
        widget, showing a capturing status message, and starting the capture thread.
        """
        self.packet_list.clear()
        self.table_widget.setRowCount(0)
        self.statusBar().showMessage('Capturing')
        self.capture_thread.start()

    def show_packet_details(self, qmodelindex):
        row = qmodelindex.row()
        packet = self.capture_thread.capture_instance.captured_packets[row]
        packet_details = packet.show(dump=True)
        self.packetDetail.setText(packet_details)

    @pyqtSlot(list)
    def packetHandler(self, packet):
        """
        The function `packetHandler` appends a packet to a list, adds a new row to a table widget,
        populates the row with the packet data, and updates a dictionary with the packet.
        
        """
        self.packet_list.append(packet)
        row_count = self.table_widget.rowCount()  # Get the current row count
        self.table_widget.setRowCount(row_count + 1)  # Add one new row

        for c, column in enumerate(packet):
            item = QTableWidgetItem(column.strip())
            self.table_widget.setItem(row_count, c, item)

        if packet[-1] in self.packet_dict:
            self.packet_dict[packet[-1]].append(packet)
        else:
            self.packet_dict[packet[-1]] = [packet]

    def parseFilterText(self, filter_text):
        """
        The function `parseFilterText` takes a filter text as input and parses it into a list of
        filters, where each filter consists of a type ('and' or 'or') and a set of criteria.
        """
        # Split the filter text into individual terms
        terms = filter_text.split()

        # Initialize filters
        filters = []
        current_filter = {'type': 'and', 'criteria': {}}

        # For each term in the filter text
        for term in terms:
            # If the term is 'and' or 'or', start a new filter
            if term.lower() in ['and', 'or']:
                if current_filter['criteria']:
                    filters.append(current_filter)
                    current_filter = {'type': term.lower(), 'criteria': {}}
            else:
                # If it's not 'and' or 'or', it's a filter criterion
                # We assume that the criterion is in the format 'type:value'
                try:
                    criterion_type, criterion_value = term.split(':')
                    current_filter['criteria'][criterion_type] = criterion_value
                except ValueError:
                    raise ValueError(
                        "'{}' is not a valid filter criterion. Filter criteria should be in the 'type:value' format.".format(term))

        # Append the last filter if it's not empty
        if current_filter['criteria']:
            filters.append(current_filter)

        return filters

    def filterPacket(self):
        """
        The `filterPacket` function filters packets based on user-defined criteria and displays the
        filtered packets in a text box.
        """
        # Get the filter criteria from the line edit and parse it
        filter_text = self.lineEdit.text().lower()
        filters = self.parseFilterText(filter_text)

        # Separate 'and' and 'or' filters
        and_filters = [filter for filter in filters if filter['type'] == 'and']
        or_filters = [filter for filter in filters if filter['type'] == 'or']

        # Filter the packets based on the filters
        filtered_packets = []
        for packet in self.packet_list:
            packet_info = {key: str(item).lower() for key, item in zip(
                ['time', 'src', 'dst', 'protocol'], packet)}

            # Split the IP and port
            packet_info['src'] = packet_info['src'].split(':')[0]
            packet_info['dst'] = packet_info['dst'].split(':')[0]

            # Check 'and' filters - all criteria must match
            and_matches = []
            for filter in and_filters:
                matches = [packet_info[key] == value for key,
                           value in filter['criteria'].items()]
                and_matches.append(all(matches))

            # Check 'or' filters - at least one criterion must match
            or_matches = []
            for filter in or_filters:
                matches = [packet_info[key] == value for key,
                           value in filter['criteria'].items()]
                or_matches.append(any(matches
                                      ))

            # If there are no 'and' filters, default to True
            # If there are no 'or' filters, default to True
            # A packet is added to filtered_packets only if it matches all 'and' filters and at least one 'or' filter
            if all(and_matches) and (any(or_matches) if or_filters else True):
                filtered_packets.append(packet)

        # Clear the text box and print the filtered packets
        self.textEdit.clear()
        for packet in filtered_packets:
            packet_info = [str(item) for item in packet]
            packet_text = f"[{packet_info[0]}] {packet_info[1]} -> {packet_info[2]}: {packet_info[3]}"
            self.textEdit.append(packet_text)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Minishark()
    sys.exit(app.exec_())
