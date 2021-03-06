/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

#include <inttypes.h>

namespace simple_router
{

  static bool isMacOfInterest(const uint8_t *mac, const Interface &inputIface);

  //////////////////////////////////////////////////////////////////////////

  void
  SimpleRouter::handlePacket(const Buffer &original_packet,
                             const std::string &inIface)
  {
    // make a mutable copy.
    Buffer packet(original_packet);

    std::cerr << "Got packet of size " << packet.size() << " on interface "
              << inIface << std::endl;

    // CHECK   packet

    const Interface *iface = findIfaceByName(inIface);
    if (iface == nullptr)
    {
      fprintf(stderr, "Received packet, but interface is unknown, ignoring\n");
      return;
    }

    if (packet.size() < sizeof(ethernet_hdr))
    {
      fprintf(stderr, "Received packet, but header is truncated, ignoring\n");
      return;
    }

    uint8_t *raw_packet = packet.data();
    ethernet_hdr *eth_hdr = (ethernet_hdr *)raw_packet;

    if (!isMacOfInterest(eth_hdr->ether_dhost, *iface))
    {
      fprintf(stderr, "Received packet, but isn't addressed to router, "
                      "ignoring\n");
      return;
    }

    /* Handle the ethernet packet based on its type */

    if (eth_hdr->ether_type == htons(ethertype_arp))
    {
      handle_arp_packet(raw_packet + sizeof(ethernet_hdr), iface,
                        eth_hdr->ether_shost);
    }
    else if (eth_hdr->ether_type == htons(ethertype_ip))
    {
      handle_ip_packet(packet, iface, eth_hdr->ether_shost);
    }
    else
    {
      fprintf(stderr, "Received packet, but type is unknown, ignoring\n");
      return;
    }
  }

  void SimpleRouter::handle_arp_packet(uint8_t *arp_data, const Interface *in_iface,
                                       uint8_t *src_mac)
  {

    arp_hdr *arp_h = (arp_hdr *)arp_data;

    //  IGNORE non-ethernet requests.
    if (ntohs(arp_h->arp_hrd) != arp_hrd_ethernet)
      return;

    uint16_t arp_op_type = ntohs(arp_h->arp_op);

    if (arp_op_type == arp_op_request)
    {

      // -------Handle ARP requests-------------

      // CREATE  ether header
      ethernet_hdr reply_eth_hdr;
      memcpy(reply_eth_hdr.ether_dhost, arp_h->arp_sha, ETHER_ADDR_LEN);
      memcpy(reply_eth_hdr.ether_shost, in_iface->addr.data(), ETHER_ADDR_LEN);
      reply_eth_hdr.ether_type = htons(ethertype_arp);

      // CREATE arp header
      arp_hdr reply_arp_hdr;
      reply_arp_hdr.arp_hrd = htons(arp_hrd_ethernet);
      reply_arp_hdr.arp_pro = htons(ethertype_ip);
      reply_arp_hdr.arp_hln = ETHER_ADDR_LEN;
      reply_arp_hdr.arp_pln = 4;
      reply_arp_hdr.arp_op = htons(arp_op_reply);
      memcpy(reply_arp_hdr.arp_sha, in_iface->addr.data(), ETHER_ADDR_LEN);
      reply_arp_hdr.arp_sip = in_iface->ip;
      memcpy(reply_arp_hdr.arp_tha, arp_h->arp_sha, ETHER_ADDR_LEN);
      reply_arp_hdr.arp_tip = arp_h->arp_sip;

      // ASSEMBLE  packet
      Buffer packet(sizeof(ethernet_hdr) + sizeof(arp_hdr));
      memcpy(packet.data(), &reply_eth_hdr, sizeof(ethernet_hdr));
      memcpy(packet.data() + sizeof(ethernet_hdr), &reply_arp_hdr, sizeof(arp_hdr));

      sendPacket(packet, in_iface->name);
      return;
    }

    // --------Handle ARP replies-----------

    // GET information from the ARP header.
    uint32_t arp_source_ip = arp_h->arp_sip;
    Buffer arp_source_mac;
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
      arp_source_mac.push_back(arp_h->arp_sha[i]);

    // RECORD the information to our ARP cache, and retrieve the packets
    std::shared_ptr<ArpRequest> request = m_arp.insertArpEntry(arp_source_mac, arp_source_ip);

    // SEND  out the queued outbound packets waiting on our ARP request.
    for (auto pending_packet : request->packets)
    {
      ethernet_hdr *eth_h = (ethernet_hdr *)pending_packet.packet.data();
      memcpy(eth_h->ether_dhost, arp_source_mac.data(), ETHER_ADDR_LEN);
      sendPacket(pending_packet.packet, pending_packet.iface);
    }

    // REMOVE  ARP request from the queue.
    m_arp.removeRequest(request);
    return;
  }

  void SimpleRouter::handle_ip_packet(Buffer &packet, const Interface *in_iface,
                                      uint8_t *src_mac)
  {  
    // CREATE HEADERS 
    ethernet_hdr *eth_h = (ethernet_hdr *)packet.data();
    ip_hdr *ip_h = (ip_hdr *)(packet.data() + sizeof(ethernet_hdr));
    icmp_hdr *icmp_h = (icmp_hdr *)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

    
    // --------CHECK HEADER----------

    if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr))
    {
      fprintf(stderr, "Received IP packet, but header is truncated, ignoring\n");
      return;
    }
    //  CHECK  checksum.
    uint16_t ip_cksum = ip_h->ip_sum;
    ip_h->ip_sum = 0x0;
    if (cksum(ip_h, sizeof(ip_hdr)) != ip_cksum)
    {
      fprintf(stderr, "Received IP packet, but checksum corrupted, ignoring\n");
      return;
    }

    // ADD  source MAC address to the ARP cache.
    if (m_arp.lookup(ip_h->ip_src) == nullptr)
    {
      Buffer src_mac_vec(src_mac, src_mac + ETHER_ADDR_LEN);
      m_arp.insertArpEntry(src_mac_vec, ip_h->ip_src);
    }


      
      
    // ========== DESTINATION  IS ROUTER ============
    if (findIfaceByIp(ip_h->ip_dst) != nullptr)
    {

      // if the packet is not an ICMP echo request, send ICMP unreachable.
      if (ip_h->ip_p != ip_protocol_icmp && icmp_h->icmp_type != 8)
      {
        send_icmp_t3_packet(packet, in_iface, 3, 3);
        return;
      }
      // IF  is time exceed send ICMP time exceed 
      if (ip_h->ip_ttl <= 1)
      {
        send_icmp_t3_packet(packet, in_iface, 11, 0);
        return;
      }

      /* Assemble ICMP response */

      // CREATE HEADERS TO SEND 
      uint8_t *icmp_packet = (uint8_t *)malloc(packet.size());
      memcpy(icmp_packet, packet.data(), packet.size());
      ethernet_hdr *icmp_eth_h = (ethernet_hdr *)icmp_packet;
      ip_hdr *icmp_ip_h = (ip_hdr *)(icmp_packet + sizeof(ethernet_hdr));
      icmp_hdr *icmp_icmp_h = (icmp_hdr *)(icmp_packet + sizeof(ethernet_hdr) + sizeof(ip_hdr));

      
      //  COPY ip header 
      memcpy(icmp_eth_h->ether_shost, eth_h->ether_dhost, ETHER_ADDR_LEN);
      memcpy(icmp_eth_h->ether_dhost, eth_h->ether_shost, ETHER_ADDR_LEN);
      icmp_ip_h->ip_src = ip_h->ip_dst;
      icmp_ip_h->ip_dst = ip_h->ip_src;

      icmp_ip_h->ip_ttl = 64;
      icmp_ip_h->ip_len = ip_h->ip_len; // TODO: why? what if packet longer?
      icmp_ip_h->ip_sum = 0x0;
      icmp_ip_h->ip_sum = cksum(icmp_ip_h, sizeof(ip_hdr));

    

      //  COPY  icmp header 
      icmp_icmp_h->icmp_type = 0x0; 
      icmp_icmp_h->icmp_code = 0x0;
      icmp_icmp_h->icmp_sum = 0x0;
      icmp_icmp_h->icmp_sum = cksum(icmp_icmp_h, sizeof(icmp_hdr));

      // SEND  the packet.
      Buffer outbound(icmp_packet, icmp_packet + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr));
      print_hdrs(outbound);
      sendPacket(outbound, in_iface->name);
      free(icmp_packet);
      return;
    }

    // ========== DESTINATION  IS NOT ROUTER ,FOWARD !============
    if (ip_h->ip_ttl <= 1)
    {
      send_icmp_t3_packet(packet, in_iface, 11, 0);
      return;
    }
    // query routing table for outbound interface.
    RoutingTableEntry routing_entry;
    try
    {
      routing_entry = m_routingTable.lookup(ip_h->ip_dst);
    }
    catch (...)
    {
      fprintf(stderr, "Recieved IP packet, but no routing table entry found, "
                      "dropping\n");
      return;
    }
    const Interface *fwd_iface = findIfaceByName(routing_entry.ifName);
    if (fwd_iface == nullptr)
    {
      fprintf(stderr, "Unknown outbound interface in routing table, dropping\n");
      return;
    }

    // prepare an output buffer for the output packet.
    Buffer out_packet(packet);
    ethernet_hdr *out_eth_h = (ethernet_hdr *)out_packet.data();

    // decrement the outbound packet's TTL.
    ip_hdr *out_ip_h = (ip_hdr *)(out_packet.data() + sizeof(ethernet_hdr));
    out_ip_h->ip_ttl--;

    // recompute the IP checksum.
    out_ip_h->ip_sum = 0x0;
    out_ip_h->ip_sum = cksum(out_ip_h, sizeof(ip_hdr));

 
    //  NO entry then put in the packet in the ARP queue.
    auto arpentry = m_arp.lookup(ip_h->ip_dst);
    if (arpentry == nullptr)
    {
      m_arp.queueRequest(ip_h->ip_dst, out_packet, fwd_iface->name);
      return;
    }

    // CHANGE  MAC  then send the packet.
    memcpy(out_eth_h->ether_dhost, arpentry->mac.data(), ETHER_ADDR_LEN);
    memcpy(out_eth_h->ether_shost, fwd_iface->addr.data(), ETHER_ADDR_LEN);
    sendPacket(out_packet, fwd_iface->name);
    return;
  }
 // send icmp packet 
  void SimpleRouter::send_icmp_t3_packet(Buffer &packet,
                                         const Interface *in_iface, uint8_t icmp_type, uint8_t icmp_code)
  {
    // initialize header pointers to the original packet.
    ethernet_hdr *eth_h = (ethernet_hdr *)packet.data();
    ip_hdr *ip_h = (ip_hdr *)(packet.data() + sizeof(ethernet_hdr));

    // copy the packet to a new outbound packet.
    size_t icmp_packet_size = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
    uint8_t *icmp_packet = (uint8_t *)malloc(icmp_packet_size);
    memcpy(icmp_packet, packet.data(), icmp_packet_size);

    // initialize header pointers for the outbound packet.
    ethernet_hdr *icmp_eth_h = (ethernet_hdr *)icmp_packet;
    ip_hdr *icmp_ip_h = (ip_hdr *)(icmp_packet + sizeof(ethernet_hdr));
    icmp_t3_hdr *icmp_icmp_t3_h = (icmp_t3_hdr *)(icmp_packet + sizeof(ethernet_hdr) + sizeof(ip_hdr));

    // return to sender, address unknown, no such number, no such zone.
    //       -- elvis presley
    memcpy(icmp_eth_h->ether_shost, eth_h->ether_dhost, ETHER_ADDR_LEN);
    memcpy(icmp_eth_h->ether_dhost, eth_h->ether_shost, ETHER_ADDR_LEN);
    icmp_ip_h->ip_src = in_iface->ip;
    icmp_ip_h->ip_dst = ip_h->ip_src;

    // initialize IP header fields.
    icmp_ip_h->ip_ttl = 64;
    icmp_ip_h->ip_p = ip_protocol_icmp;
    icmp_ip_h->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr)); // TODO big hdrs
    icmp_ip_h->ip_sum = 0x0;
    icmp_ip_h->ip_sum = cksum(icmp_ip_h, sizeof(ip_hdr));

    // fill in icmp header.
    icmp_icmp_t3_h->icmp_type = icmp_type;
    icmp_icmp_t3_h->icmp_code = icmp_code;
    icmp_icmp_t3_h->unused = 0x0;
    memcpy(icmp_icmp_t3_h->data, ip_h, ICMP_DATA_SIZE);

    // compute icmp checksum.
    icmp_icmp_t3_h->icmp_sum = 0x0;
    icmp_icmp_t3_h->icmp_sum = cksum(icmp_icmp_t3_h, sizeof(icmp_t3_hdr));

    // send the packet.
    Buffer outbound(icmp_packet, icmp_packet + icmp_packet_size);
    sendPacket(outbound, in_iface->name);
    free(icmp_packet);
  }

  static bool isMacOfInterest(const uint8_t *mac, const Interface &inputIface)
  {
    uint8_t broadcast_mac[ETHER_ADDR_LEN];
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
      broadcast_mac[i] = 0xFFU;

    if (memcmp(mac, broadcast_mac, ETHER_ADDR_LEN) == 0)
      return true;

    return memcmp(mac, inputIface.addr.data(), ETHER_ADDR_LEN) == 0;
  }

  //////////////////////////////////////////////////////////////////////////

  // You should not need to touch the rest of this code.
  SimpleRouter::SimpleRouter()
      : m_arp(*this)
  {
  }

  void
  SimpleRouter::sendPacket(const Buffer &packet, const std::string &outIface)
  {
    m_pox->begin_sendPacket(packet, outIface);
  }

  bool
  SimpleRouter::loadRoutingTable(const std::string &rtConfig)
  {
    return m_routingTable.load(rtConfig);
  }

  void
  SimpleRouter::loadIfconfig(const std::string &ifconfig)
  {
    std::ifstream iff(ifconfig.c_str());
    std::string line;
    while (std::getline(iff, line))
    {
      std::istringstream ifLine(line);
      std::string iface, ip;
      ifLine >> iface >> ip;

      in_addr ip_addr;
      if (inet_aton(ip.c_str(), &ip_addr) == 0)
      {
        throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
      }

      m_ifNameToIpMap[iface] = ip_addr.s_addr;
    }
  }

  void
  SimpleRouter::printIfaces(std::ostream &os)
  {
    if (m_ifaces.empty())
    {
      os << " Interface list empty " << std::endl;
      return;
    }

    for (const auto &iface : m_ifaces)
    {
      os << iface << "\n";
    }
    os.flush();
  }

  const Interface *
  SimpleRouter::findIfaceByIp(uint32_t ip) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip](const Interface &iface) {
      return iface.ip == ip;
    });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByMac(const Buffer &mac) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac](const Interface &iface) {
      return iface.addr == mac;
    });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  void
  SimpleRouter::reset(const pox::Ifaces &ports)
  {
    std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

    m_arp.clear();
    m_ifaces.clear();

    for (const auto &iface : ports)
    {
      auto ip = m_ifNameToIpMap.find(iface.name);
      if (ip == m_ifNameToIpMap.end())
      {
        std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
        continue;
      }

      m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
    }

    printIfaces(std::cerr);
  }

  const Interface *
  SimpleRouter::findIfaceByName(const std::string &name) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name](const Interface &iface) {
      return iface.name == name;
    });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

} // namespace simple_router

/* vim:set expandtab shiftwidth=2 textwidth=79: */
