#!/usr/bin/env python2.7
#
#   Project Horus 
#   LoRa Text Messenger
#   Copyright 2015 Mark Jessop <vk5qi@rfhead.net>
#
#   Modifications by Will Anthony <willanth@gmail.com>
#

import HorusPackets as HP #changed from wildcard import as it is not good style
from threading import Thread
from PyQt4 import QtGui, QtCore
from datetime import datetime
import socket
import json
import sys
import Queue
import ConfigParser


udp_broadcast_port = HP.HORUS_UDP_PORT
udp_listener_running = False

# RX Message queue to avoid threading issues.
rxqueue = Queue.Queue(16)
txed_packets = []

# PyQt Window Setup
app = QtGui.QApplication([])

# Widgets
statusLabel = QtGui.QLabel("No updates yet..")
console = QtGui.QPlainTextEdit()
console.setReadOnly(True)
callsignBox = QtGui.QLineEdit("N0CALL")
callsignBox.setFixedWidth(100)
callsignBox.setMaxLength(8)
messageBox = QtGui.QLineEdit("")
messageBox.setMaxLength(55)

# Create and Lay-out window
win = QtGui.QWidget()
win.resize(600,200)
win.show()
win.setWindowTitle("Horus Messenger")
layout = QtGui.QGridLayout()
win.setLayout(layout)
# Add Widgets
layout.addWidget(statusLabel,0,0,1,4)
layout.addWidget(console,1,0,1,4)
layout.addWidget(callsignBox,2,0,1,1)
layout.addWidget(messageBox,2,1,1,3)

# Now attempt to read in a config file to preset various parameters.
try:
	config = ConfigParser.ConfigParser()
	config.read('defaults.cfg')
	callsign = config.get('User','callsign')
	callsignBox.setText(callsign)
except:
	print("Problems reading configuration file, skipping...")


# Send a message!
def send_message():
    
    callsign = str(callsignBox.text())
    message = str(messageBox.text())
    message_packet = HP.create_text_message_packet(callsign,message)
    HP.tx_packet(message_packet)
    messageBox.setText("")

messageBox.returnPressed.connect(send_message)
callsignBox.returnPressed.connect(send_message)


# Method to process UDP packets.
def process_udp(udp_packet):
	try:
		packet_dict = json.loads(udp_packet)

		# Start every line with a timestamp
		line = datetime.utcnow().strftime("%H:%M ")
		print packet_dict['type']
		# TX Confirmation Packet?
		if packet_dict['type'] == 'TXDONE':
			if(packet_dict['payload'][0] == HP.HORUS_PACKET_TYPES.TEXT_MESSAGE):
				(source,message) = HP.read_text_message_packet(packet_dict['payload'])
				line += "<%8s> %s" % (source,message)
				console.appendPlainText(line)
		elif packet_dict['type'] == 'RXPKT':
			if(packet_dict['payload'][0] == HP.HORUS_PACKET_TYPES.TEXT_MESSAGE):
				rssi = float(packet_dict['rssi'])
				snr = float(packet_dict['snr'])
				print packet_dict['payload']
				(source,message) = HP.read_text_message_packet(packet_dict['payload'])

				payload_flags = HP.decode_payload_flags(packet_dict['payload'])
				if payload_flags['is_repeated']:
					line += "<%8s via #%d>" % (source,payload_flags['repeater_id'])
				else:
					line += "<%8s>" % (source)

				line += " [R:%.1f S:%.1f] %s" % (rssi,snr,message)
				console.appendPlainText(line)
		elif packet_dict['type'] == 'STATUS':
			rssi = float(packet_dict['rssi'])
			timestamp = packet_dict['timestamp']
			status_text = "%s RSSI: %.1f dBm" % (timestamp,rssi)
			statusLabel.setText(status_text)
		else:
			print("Got other packet type...")
			print packet_dict['payload']
	except:
		pass

def udp_rx_thread():
	
	s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	s.settimeout(1)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(('',HP.HORUS_UDP_PORT))
	print("Started UDP Listener Thread.")
	udp_listener_running = True
	while udp_listener_running:    #FIXME this while has no bound or pre-predicted exit, sure there's a socket timeout exception but that's still not very good.
		try:
			m = s.recvfrom(HP.MAX_JSON_LEN)
		except socket.timeout:
			m = None
		
		if m != None:
			rxqueue.put_nowait(m[0])
	
	print("Closing UDP Listener")
	s.close()

t = Thread(target=udp_rx_thread)
t.start()

def read_queue():
	try:
		packet = rxqueue.get_nowait()
		process_udp(packet)
	except:
		pass

# Start a timer to attempt to read the remote station status every 5 seconds.
timer = QtCore.QTimer()
timer.timeout.connect(read_queue)
timer.start(100)

## Start Qt event loop unless running in interactive mode or using pyside.
if __name__ == '__main__':
	if (sys.flags.interactive != 1) or not hasattr(QtCore, 'PYQT_VERSION'):
		QtGui.QApplication.instance().exec_()
		udp_listener_running = False
