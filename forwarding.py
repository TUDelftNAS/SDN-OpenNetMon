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
OpenNetMon.Forwarding

Requires openflow.discovery
"""

from pox.lib.revent.revent import EventMixin, Event
from pox.lib.addresses import IPAddr
from pox.lib.packet.vlan import vlan
from pox.lib.packet.ipv4 import ipv4

import pox.lib.util as util
from pox.core import core

import pox.openflow.libopenflow_01 as of
from collections import defaultdict
import pox.lib.packet as pkt

from collections import namedtuple

log = core.getLogger()

switches = {}
switch_ports = {}
adj = defaultdict(lambda:defaultdict(lambda:None))

mac_learning = {}

class ofp_match_withHash(of.ofp_match):
	##Our additions to enable indexing by match specifications
	@classmethod
	def from_ofp_match_Superclass(cls, other):	
		match = cls()
		
		match.wildcards = other.wildcards
		match.in_port = other.in_port
		match.dl_src = other.dl_src
		match.dl_dst = other.dl_dst
		match.dl_vlan = other.dl_vlan
		match.dl_vlan_pcp = other.dl_vlan_pcp
		match.dl_type = other.dl_type
		match.nw_tos = other.nw_tos
		match.nw_proto = other.nw_proto
		match.nw_src = other.nw_src
		match.nw_dst = other.nw_dst
		match.tp_src = other.tp_src
		match.tp_dst = other.tp_dst
		return match
		
	def __hash__(self):
		return hash((self.wildcards, self.in_port, self.dl_src, self.dl_dst, self.dl_vlan, self.dl_vlan_pcp, self.dl_type, self.nw_tos, self.nw_proto, self.nw_src, self.nw_dst, self.tp_src, self.tp_dst))

class Path(object):
	def __init__(self, src, dst, prev, first_port):
		self.src = src
		self.dst = dst
		self.prev = prev
		self.first_port = first_port
	
	def __repr__(self):
		ret = util.dpid_to_str(self.dst)
		u = self.prev[self.dst]
		while(u != None):
			ret = util.dpid_to_str(u) + "->" + ret
			u = self.prev[u]
		
		return ret			
	
	def _tuple_me(self):
		
		list = [self.dst,]
		u = self.prev[self.dst]
		while u != None:
			list.append(u)
			u = self.prev[u]
		#log.debug("List path: %s", list)
		#log.debug("Tuple path: %s", tuple(list))
		return tuple(list)
	
	def __hash__(self):
		return hash(self._tuple_me())
	
	def __eq__(self, other):
		return self._tuple_me() == other._tuple_me()
	
def _get_path(src, dst):
	#Bellman-Ford algorithm
	keys = switches.keys()
	distance = {}
	previous = {}
	
	for dpid in keys:
		distance[dpid] = float("+inf")
		previous[dpid] = None

	distance[src] = 0
	for i in range(len(keys)-1):
		for u in adj.keys(): #nested dict
			for v in adj[u].keys():
				w = 1
				if distance[u] + w < distance[v]:
					distance[v] = distance[u] + w
					previous[v] = u 

	for u in adj.keys(): #nested dict
		for v in adj[u].keys():
			w = 1
			if distance[u] + w < distance[v]:
				log.error("Graph contains a negative-weight cycle")
				return None
	
	first_port = None
	v = dst
	u = previous[v]
	while u is not None:
		if u == src:
			first_port = adj[u][v]
		
		v = u
		u = previous[v]
				
	return Path(src, dst, previous, first_port)  #path

def _install_path(prev_path, match):
	dst_sw = prev_path.dst
	cur_sw = prev_path.dst
	dst_pck = match.dl_dst
	
	msg = of.ofp_flow_mod()
	msg.match = match
	msg.idle_timeout = 10
	msg.flags = of.OFPFF_SEND_FLOW_REM	
	msg.actions.append(of.ofp_action_output(port = mac_learning[dst_pck].port))
	log.debug("Installing forward from switch %s to output port %s", util.dpid_to_str(cur_sw), mac_learning[dst_pck].port)
	switches[dst_sw].connection.send(msg)
	
	next_sw = cur_sw
	cur_sw = prev_path.prev[next_sw]
	while cur_sw is not None: #for switch in path.keys():
		msg = of.ofp_flow_mod()
		msg.match = match
		msg.idle_timeout = 10
		msg.flags = of.OFPFF_SEND_FLOW_REM
		log.debug("Installing forward from switch %s to switch %s output port %s", util.dpid_to_str(cur_sw), util.dpid_to_str(next_sw), adj[cur_sw][next_sw])
		msg.actions.append(of.ofp_action_output(port = adj[cur_sw][next_sw]))
		switches[cur_sw].connection.send(msg)
		next_sw = cur_sw
		
		cur_sw = prev_path.prev[next_sw]
		
def _print_rev_path(dst_pck, src, dst, prev_path):
	str = "Reverse path from %s to %s over: [%s->dst over port %s]" % (util.dpid_to_str(src), util.dpid_to_str(dst), util.dpid_to_str(dst), mac_learning[dst_pck].port)
	next_sw = dst
	cur_sw = prev_path[next_sw]
	while cur_sw != None: #for switch in path.keys():
		str += "[%s->%s over port %s]" % (util.dpid_to_str(cur_sw), util.dpid_to_str(next_sw), adj[cur_sw][next_sw])
		next_sw = cur_sw
		cur_sw = prev_path[next_sw]
		
	log.debug(str)
	
class NewFlow(Event):
	def __init__(self, prev_path, match, adj):
		Event.__init__(self)
		self.match = match
		self.prev_path = prev_path
		self.adj = adj
	
class Switch(EventMixin):
	_eventMixin_events = set([
							NewFlow,
							])
	def __init__(self, connection, l3_matching=False):
		self.connection = connection
		self.l3_matching = l3_matching
		connection.addListeners(self)
		for p in self.connection.ports.itervalues(): #Enable flooding on all ports until they are classified as links
			self.enable_flooding(p.port_no)
	
	def __repr__(self):
		return util.dpid_to_str(self.connection.dpid) 
	
	
	def disable_flooding(self, port):
		msg = of.ofp_port_mod(port_no = port,
						hw_addr = self.connection.ports[port].hw_addr,
						config = of.OFPPC_NO_FLOOD,
						mask = of.OFPPC_NO_FLOOD)
	
		self.connection.send(msg)
	

	def enable_flooding(self, port):
		msg = of.ofp_port_mod(port_no = port,
							hw_addr = self.connection.ports[port].hw_addr,
							config = 0, # opposite of of.OFPPC_NO_FLOOD,
							mask = of.OFPPC_NO_FLOOD)
	
		self.connection.send(msg)
	
	def _handle_PacketIn(self, event):
		def forward(port):
			"""Tell the switch to drop the packet"""
			msg = of.ofp_packet_out()
			msg.actions.append(of.ofp_action_output(port = port))	
			if event.ofp.buffer_id is not None:
				msg.buffer_id = event.ofp.buffer_id
			else:
				msg.data = event.ofp.data
			msg.in_port = event.port
			self.connection.send(msg)
				
		def flood():
			"""Tell all switches to flood the packet, remember that we disable inter-switch flooding at startup"""
			#forward(of.OFPP_FLOOD)
			for (dpid,switch) in switches.iteritems():
				msg = of.ofp_packet_out()
				if switch == self:
					if event.ofp.buffer_id is not None:
						msg.buffer_id = event.ofp.buffer_id
					else:
						msg.data = event.ofp.data
					msg.in_port = event.port
				else:
					msg.data = event.ofp.data
				ports = [p for p in switch.connection.ports if (dpid,p) not in switch_ports]
				if len(ports) > 0:
					for p in ports:
						msg.actions.append(of.ofp_action_output(port = p))
					switches[dpid].connection.send(msg)
				
				
		def drop():
			"""Tell the switch to drop the packet"""
			if event.ofp.buffer_id is not None: #nothing to drop because the packet is not in the Switch buffer
				msg = of.ofp_packet_out()
				msg.buffer_id = event.ofp.buffer_id 
				event.ofp.buffer_id = None # Mark as dead, copied from James McCauley, not sure what it does but it does not work otherwise
				msg.in_port = event.port
				self.connection.send(msg)
		
		log.debug("Received PacketIn")		
		packet = event.parsed
				
		SwitchPort = namedtuple('SwitchPoint', 'dpid port')
		
		if (event.dpid,event.port) not in switch_ports:						# only relearn locations if they arrived from non-interswitch links
			mac_learning[packet.src] = SwitchPort(event.dpid, event.port)	#relearn the location of the mac-address
		
		if packet.effective_ethertype == packet.LLDP_TYPE:
			drop()
			log.debug("Switch %s dropped LLDP packet", self)
		elif packet.dst.is_multicast:
			flood()
			log.debug("Switch %s flooded multicast 0x%0.4X type packet", self, packet.effective_ethertype)
		elif packet.dst not in mac_learning:
			flood() #Let's first learn the location of the recipient before generating and installing any rules for this. We might flood this but that leads to further complications if half way the flood through the network the path has been learned.
			log.debug("Switch %s flooded unicast 0x%0.4X type packet, due to unlearned MAC address", self, packet.effective_ethertype)
		elif packet.effective_ethertype == packet.ARP_TYPE:
			#These packets are sent so not-often that they don't deserve a flow
			#Instead of flooding them, we drop it at the current switch and have it resend by the switch to which the recipient is connected.
			#flood()
			drop()
			dst = mac_learning[packet.dst]
			msg = of.ofp_packet_out()
			msg.data = event.ofp.data
			msg.actions.append(of.ofp_action_output(port = dst.port))
			switches[dst.dpid].connection.send(msg)
			log.debug("Switch %s processed unicast ARP (0x0806) packet, send to recipient by switch %s", self, util.dpid_to_str(dst.dpid))
		else:
			log.debug("Switch %s received PacketIn of type 0x%0.4X, received from %s.%s", self, packet.effective_ethertype, util.dpid_to_str(event.dpid), event.port)
			dst = mac_learning[packet.dst]
			prev_path = _get_path(self.connection.dpid, dst.dpid)
			if prev_path is None:
				flood()
				return
			log.debug("Path from %s to %s over path %s", packet.src, packet.dst, prev_path)
			if self.l3_matching == True: #only match on l2-properties, useful when doing experiments with UDP streams as you can insert a flow using ping and then start sending udp.
				
				match = ofp_match_withHash()

				match.dl_src = packet.src
				match.dl_dst = packet.dst
				match.dl_type = packet.type
				p = packet.next
				if isinstance(p, vlan):
					match.dl_type = p.eth_type
					match.dl_vlan = p.id
					match.dl_vlan_pcp = p.pcp
					p = p.next
				if isinstance(p, ipv4):
					match.nw_src = p.srcip
					match.nw_dst = p.dstip
					match.nw_proto = p.protocol
					match.nw_tos = p.tos
					p = p.next
				else:
					match.dl_vlan = of.OFP_VLAN_NONE
					match.dl_vlan_pcp = 0
				
			else:
				match = ofp_match_withHash.from_packet(packet)
			
			_install_path(prev_path, match)
			
			#forward the packet directly from the last switch, there is no need to have the packet run through the complete network.
			drop()
			dst = mac_learning[packet.dst]
			msg = of.ofp_packet_out()
			msg.data = event.ofp.data
			msg.actions.append(of.ofp_action_output(port = dst.port))
			switches[dst.dpid].connection.send(msg)
			
			self.raiseEvent(NewFlow(prev_path, match, adj))
			log.debug("Switch %s processed unicast 0x%0.4x type packet, send to recipient by switch %s", self, packet.effective_ethertype, util.dpid_to_str(dst.dpid))
			
		
	def _handle_ConnectionDown(self, event):
		log.debug("Switch %s going down", util.dpid_to_str(self.connection.dpid))
		del switches[self.connection.dpid]
		#pprint(switches)

		
class NewSwitch(Event):
	def __init__(self, switch):
		Event.__init__(self)
		self.switch = switch

class Forwarding(EventMixin):
	_core_name = "opennetmon_forwarding" # we want to be core.opennetmon_forwarding
	_eventMixin_events = set([NewSwitch,])
	
	def __init__ (self, l3_matching):
		log.debug("Forwarding coming up")
				
		def startup():
			core.openflow.addListeners(self)
			core.openflow_discovery.addListeners(self)
			log.debug("Forwarding started")
		
		self.l3_matching = l3_matching
		core.call_when_ready(startup, 'openflow', 'openflow_discovery')
			
	def _handle_LinkEvent(self, event):
		link = event.link
		if event.added:
			log.debug("Received LinkEvent, Link Added from %s to %s over port %d", util.dpid_to_str(link.dpid1), util.dpid_to_str(link.dpid2), link.port1)
			adj[link.dpid1][link.dpid2] = link.port1
			switch_ports[link.dpid1,link.port1] = link
			#switches[link.dpid1].disable_flooding(link.port1)
			#pprint(adj)
		else:
			log.debug("Received LinkEvent, Link Removed from %s to %s over port %d", util.dpid_to_str(link.dpid1), util.dpid_to_str(link.dpid2), link.port1)
			##Disabled those two lines to prevent interference with experiment due to falsely identified disconnected links.
			#del adj[link.dpid1][link.dpid2]
			#del switch_ports[link.dpid1,link.port1]
			
			
			#switches[link.dpid1].enable_flooding(link.port1)
			
		
		self._calc_ForwardingMatrix()
		
	def _calc_ForwardingMatrix(self):
		log.debug("Calculating forwarding matrix")
		
	def _handle_ConnectionUp(self, event):
		log.debug("New switch connection: %s", event.connection)
		sw = Switch(event.connection, l3_matching=self.l3_matching)
		switches[event.dpid] = sw;
		self.raiseEvent(NewSwitch(sw))
		

		
def launch (l3_matching=False):
	
	core.registerNew(Forwarding, l3_matching)
	
