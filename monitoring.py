# #Copyright (C) 2013, Delft University of Technology, Faculty of Electrical Engineering, Mathematics and Computer Science, Network Architectures and Services, Niels van Adrichem
#
# This file is part of OpenNetMon.
#
# OpenNetMon is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OpenNetMon is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OpenNetMon.  If not, see <http://www.gnu.org/licenses/>.

# Special thanks go to James McCauley and all people connected to the POX project, without their work and provided samples OpenNetMon could not have been created in the way it is now.

"""
OpenNetMon.Monitoring

Requires openflow.discovery and opennetmon.forwarding
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *

import pox.lib.util as util
from pox.lib.recoco import Timer

from forwarding import ofp_match_withHash
from datetime import datetime

from collections import defaultdict
from collections import namedtuple
import pox.lib.packet as pkt
#from pox.openflow.of_json import flow_stats_to_list
import struct
from pox.lib.addresses import IPAddr,EthAddr

import time

log = core.getLogger()
switches = {}

monitored_paths = {}
monitored_pathsById = {}
monitored_pathsByMatch = {}
monitored_pathsBySwitch = {}

pathIterator = {}
barrier = {}



prev_stats = defaultdict(lambda:defaultdict(lambda:None))

Payload = namedtuple('Payload', 'pathId timeSent')

def _install_monitoring_path(prev_path, adj):
	
	match = ofp_match_withHash()
	match.dl_src = struct.pack("!Q", prev_path.src)[2:] #convert dpid to EthAddr
	match.dl_dst = struct.pack("!Q", prev_path.dst)[2:]
	match.dl_type = pkt.ethernet.IP_TYPE
	match.nw_proto = 253 # Use for experiment and testing
	match.nw_dst = IPAddr("224.0.0.255") #IANA Unassigned multicast addres 
	match.nw_src = IPAddr(prev_path.__hash__()) #path hash
	
	
	dst_sw = prev_path.dst
	cur_sw = prev_path.dst
	
	msg = of.ofp_flow_mod()
	msg.match = match
	msg.idle_timeout = 30
	#msg.flags = of.OFPFF_SEND_FLOW_REM	
	msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
	log.debug("Installing monitoring forward from switch %s to controller port", util.dpid_to_str(cur_sw))
	switches[dst_sw].connection.send(msg)
	
	next_sw = cur_sw
	cur_sw = prev_path.prev[next_sw]
	while cur_sw is not None: #for switch in path.keys():
		msg = of.ofp_flow_mod()
		msg.match = match
		msg.idle_timeout = 10
		#msg.flags = of.OFPFF_SEND_FLOW_REM
		log.debug("Installing monitoring forward from switch %s to switch %s output port %s", util.dpid_to_str(cur_sw), util.dpid_to_str(next_sw), adj[cur_sw][next_sw])
		msg.actions.append(of.ofp_action_output(port = adj[cur_sw][next_sw]))
		switches[cur_sw].connection.send(msg)
		next_sw = cur_sw
		
		cur_sw = prev_path.prev[next_sw]



class Monitoring (object):

			
	def _timer_MonitorPaths(self):
		log.debug("Monitoring paths %s", str(datetime.now()))
		
		def AdaptiveTimer():
			changed = False
			#Increase or decrease the timers based on the throughput resuts measured based on the flowstats reply		
			if(self.increaseTimer == True):
				self.t._interval /= 2
				changed = True
			elif(self.decreaseTimer == True):
				self.t._interval *= 1.125
				changed = True
			
			#maximize the interval
			if self.t._interval > 60:
				self.t._interval = 60
				
			#minimize the interval
			if self.t._interval < 1:
				self.t._interval = 1
			
			#update next timer if, and only if, the timer has changed
			if changed == True:
				self.t._next = time.time() + self.t._interval
			
			#Reset input from received flowstats
			self.increaseTimer = False
			self.decreaseTimer = True
		
		def RoundRobin():
			pathRead = {}
			for p in monitored_paths:
				pathRead[p] = False
				
			for p in monitored_paths: #Walk through all distinct paths, not even flows
				if pathRead[p] != True:
				
					if p not in pathIterator or pathIterator[p] == p.src: # Round Robin switch selection
						pathIterator[p] = p.dst
					else:
						pathIterator[p] = p.prev[pathIterator[p]]
					
					curSwitch = pathIterator[p]
					
					log.debug("Sending message to switch %s", util.dpid_to_str(curSwitch))
					msg = of.ofp_stats_request(body=of.ofp_flow_stats_request())
					switches[curSwitch].connection.send(msg)
					for pPrime in monitored_pathsBySwitch[curSwitch]: #Circumvent polling multiple switches for paths from whom the stats have already been requested
						pathRead[pPrime] = True 
		
		
		def LastSwitch():
			switchRead = {}
			for dpid in switches:
				switchRead[dpid] = False
				
			for p in monitored_paths: #Walk through all distinct paths and select both last and first switch to calculate throughput and packet loss.
				if switchRead[p.dst] == False:
					switchRead[p.dst] = True
					msg = of.ofp_stats_request(body=of.ofp_flow_stats_request())
					switches[p.dst].connection.send(msg)
				
				if switchRead[p.src] == False:
					switchRead[p.src] = True
					msg = of.ofp_stats_request(body=of.ofp_flow_stats_request())
					switches[p.src].connection.send(msg)
		
		def MeasureDelay():
			for p in monitored_paths: #Walk through all distinct paths
				
				ip_pck = pkt.ipv4(protocol=253, #use for experiment and testing
								srcip = IPAddr(p.__hash__()),
								dstip = IPAddr("224.0.0.255"))
			
				
				pl = Payload(id(p), time.time())
					
				ip_pck.set_payload(repr(pl))
						
				eth_packet = pkt.ethernet(type=pkt.ethernet.IP_TYPE) #use something that does not interfer with regular traffic
				eth_packet.src = struct.pack("!Q", p.src)[2:] #convert dpid to EthAddr
				eth_packet.dst = struct.pack("!Q", p.dst)[2:]
				eth_packet.set_payload(ip_pck)
				
				msg = of.ofp_packet_out()
				msg.actions.append(of.ofp_action_output(port = p.first_port))
				msg.data = eth_packet.pack()
				switches[p.src].connection.send(msg)
				
				#msg2 = of.ofp_barrier_request()
				#switches[p.src].connection.send(msg2)
				#barrier[msg2.xid] = (p.src, time.time())
				
				#msg3 = of.ofp_barrier_request()
				#switches[p.dst].connection.send(msg3)
				#barrier[msg3.xid] = (p.src, time.time())
				
				eth_packet = pkt.ethernet(type=pkt.ethernet.IP_TYPE)
				eth_packet.src = struct.pack("!Q", p.src)[2:]
				eth_packet.dst = struct.pack("!Q", p.src)[2:]
				eth_packet.set_payload(ip_pck)
				
				msg = of.ofp_packet_out()
				msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
				msg.data = eth_packet.pack()				
				switches[p.src].connection.send(msg)
								
				
		
		AdaptiveTimer() #use to experiment with the adaptive timer)
		
		#RoundRobin() #use to experiment with roundrobin switch selection
		LastSwitch() #use to experiment with lastswitch switch selection
		
		MeasureDelay() #sends packets for delay measurement
		
	def __init__ (self,postfix):
		log.debug("Monitoring coming up")
		
		def startup():
			
			core.openflow.addListeners(self, priority=0xfffffffe) #took 1 priority lower as the discovery module, although it should not matter
			
			core.opennetmon_forwarding.addListeners(self) #("NewPath")
			
			self.decreaseTimer = False
			self.increaseTimer = False
			self.t = Timer(1, self._timer_MonitorPaths, recurring = True)
			
			
			self.f = open("output.%s.csv"%postfix, "w")
			#self.f.write("Experiment,Switch,SRC_IP,DST_IP,SRC_PORT,DST_PORT,Packet_Count,Byte_Count,Duration_Sec,Duration_Nsec,Delta_Packet_Count,Delta_Byte_Count,Delta_Duration_Sec,Delta_Duration_Nsec\n")
			#self.f.flush()
			
			self.f2 = open("delay.%s.csv"%postfix, "w")
			self.f2.write("MeasurementType,Src/Initiator,Dst/Switch,Delay\n")
			self.f2.flush()
			
			self.experiment = postfix
				
			log.debug("Monitoring started")
	
		core.call_when_ready(startup, ('opennetmon_forwarding')) #Wait for opennetmon-forwarding to be started
		
	def __del__(self):
		
		self.f.close()
	
	def _handle_NewSwitch (self, event):
		switch = event.switch
		log.debug("New switch to Monitor %s", switch.connection)
		switches[switch.connection.dpid] = switch
		switch.addListeners(self)
		
	def _handle_NewFlow(self, event):
		match = event.match
		path = event.prev_path
		adj = event.adj
		#log.debug("New flow to monitor %s", str(match))
		#log.debug(path._tuple_me())
		
		_install_monitoring_path(path, adj)
		
		if path not in monitored_paths:
			monitored_paths[path] = set([match])
			monitored_pathsById[id(path)] = path
			sw = path.dst
			while sw is not None:
				if sw not in monitored_pathsBySwitch:
					monitored_pathsBySwitch[sw] = set([path])
				else:
					monitored_pathsBySwitch[sw].add(path)
				#pprint(monitored_pathsBySwitch[sw])
				sw = path.prev[sw]
		else:
			monitored_paths[path].add(match)
		#pprint(monitored_paths[path])
			
		monitored_pathsByMatch[match] = path
			
	def _handle_FlowRemoved(self, event):
		match = ofp_match_withHash.from_ofp_match_Superclass(event.ofp.match)
		path = monitored_pathsByMatch.pop(match, None)
		if path is not None:
			log.debug("Removing flow")
			monitored_paths[path].remove(match)
			if not monitored_paths[path]:
				del monitored_paths[path]
				del monitored_pathsById[id(path)]
				sw = path.dst
				
				while sw is not None: 
					monitored_pathsBySwitch[sw].remove(path)
					if not monitored_pathsBySwitch[sw]:
						del monitored_pathsBySwitch[sw]
					#pprint(monitored_pathsBySwitch[sw])
			
					sw = path.prev[sw]
			#pprint(monitored_paths[path])
			
	def _handle_FlowStatsReceived(self, event):
		#stats = flow_stats_to_list(event.stats)
		#log.debug("Received Flow Stats from %s: %s", util.dpid_to_str(event.connection.dpid), stats)
		
		dpid = event.connection.dpid
		for stat in event.stats:
			
			match = ofp_match_withHash.from_ofp_match_Superclass(stat.match)
			if match.dl_type != pkt.ethernet.LLDP_TYPE and not (match.dl_type == pkt.ethernet.IP_TYPE and match.nw_proto == 253 and match.nw_dst == IPAddr("224.0.0.255")):
				if match not in prev_stats or dpid not in prev_stats[match]:
					prev_stats[match][dpid] = 0, 0, 0, 0, -1.0
				prev_packet_count, prev_byte_count, prev_duration_sec, prev_duration_nsec, prev_throughput = prev_stats[match][dpid]
				
				delta_packet_count = stat.packet_count - prev_packet_count
				delta_byte_count = stat.byte_count - prev_byte_count
				delta_duration_sec = stat.duration_sec - prev_duration_sec
				delta_duration_nsec = stat.duration_nsec - prev_duration_nsec
				
				cur_throughput = delta_byte_count / (delta_duration_sec + (delta_duration_nsec / 1000000000.0))
				
				log.debug("Stat switch: %s\tnw_src: %s\tnw_dst: %s\tnw_proto: %s\tpacketcount: %d\t bytecount: %d\t duration: %d s + %d ns\t, delta_packetcount: %d, delta_bytecount: %d, delta_duration: %d s + %d ns, throughput: %f", util.dpid_to_str(dpid), match.nw_src, match.nw_dst, match.nw_proto, stat.packet_count, stat.byte_count, stat.duration_sec, stat.duration_nsec, delta_packet_count, delta_byte_count, delta_duration_sec, delta_duration_nsec, cur_throughput)
				self.f.write("%s,%s,%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%f\n"%(self.experiment, util.dpid_to_str(dpid), match.nw_src, match.nw_dst, match.nw_proto, stat.packet_count, stat.byte_count, stat.duration_sec, stat.duration_nsec, delta_packet_count, delta_byte_count, delta_duration_sec, delta_duration_nsec, cur_throughput))
			
				#influence the timer by inspecting the change in throughput 
				if abs(cur_throughput - prev_throughput) > .05 * prev_throughput:
					self.decreaseTimer = False
				if abs(cur_throughput - prev_throughput) > .20 * prev_throughput:
					self.increaseTimer = True
				
				#log.debug("Stat switch: %s\tdl_type: %d\tnw_src: %s\tnw_dst: %s\tproto: %s\tsrc_port: %s\t dst_port: %s\tpacketcount: %d\t bytecount: %d\t duration: %d s + %d ns, delta_packetcount: %d, delta_bytecount: %d, delta_duration: %d s + %d ns", util.dpid_to_str(dpid), match.dl_type, match.nw_src, match.nw_dst, match.nw_proto, match.tp_src, match.tp_dst, stat.packet_count, stat.byte_count, stat.duration_sec, stat.duration_nsec, delta_packet_count, delta_byte_count, delta_duration_sec, delta_duration_nsec)
				#self.f.write("%s,%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n"%(self.experiment, util.dpid_to_str(dpid), match.nw_src, match.nw_dst, match.tp_src, match.tp_dst, stat.packet_count, stat.byte_count, stat.duration_sec, stat.duration_nsec, delta_packet_count, delta_byte_count, delta_duration_sec, delta_duration_nsec))
				
				self.f.flush()
				prev_stats[match][dpid] = stat.packet_count, stat.byte_count, stat.duration_sec, stat.duration_nsec, cur_throughput
			
	def _handle_BarrierIn (self, event):
		timeRecv = time.time()
		dpid = event.dpid
		xid = event.xid
		if xid not in barrier:
			return
		
		(initiator, prevTime) = barrier[xid]
		log.debug("Delay from switch %s initiated by %s = %f"%(util.dpid_to_str(dpid), util.dpid_to_str(initiator), timeRecv - prevTime))
		self.f2.write("Switch,%s,%s,%f\n"%(util.dpid_to_str(initiator), util.dpid_to_str(dpid), timeRecv - prevTime))
		self.f2.flush()
		del barrier[xid]
		return EventHalt
		

	def _handle_PacketIn(self, event):
		#log.debug("Incoming packet")
		timeRecv = time.time()
		packet = event.parsed
		if packet.effective_ethertype != pkt.ethernet.IP_TYPE:
			return
		ip_pck = packet.find(pkt.ipv4)
		if ip_pck is None or not ip_pck.parsed:
			log.error("No IP packet in IP_TYPE packet")
			return EventHalt
		
		if ip_pck.protocol != 253 or ip_pck.dstip != IPAddr("224.0.0.255"):
			#log.debug("Packet is not ours, give packet back to regular packet manager")
			return
		else:
			#log.debug("Received monitoring packet, with payload %s."%(ip_pck.payload))
			payload = eval(ip_pck.payload)
			
			log.debug("Delay from switch %s to %s = %f"%(EthAddr(packet.src), EthAddr(packet.dst), timeRecv - payload.timeSent ))
			self.f2.write("Path,%s,%s,%f\n"%(EthAddr(packet.src), EthAddr(packet.dst), timeRecv - payload.timeSent) )
			self.f2.flush()
			return EventHalt
			
def launch (postfix=datetime.now().strftime("%Y%m%d%H%M%S")):
	
	"""
	Starts the component
	"""
	core.registerNew(Monitoring, postfix)
	


