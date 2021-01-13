/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router
{

  //////////////////////////////////////////////////////////////////////////

  void
  ArpCache::periodicCheckArpRequestsAndCacheEntries()
  {
   
   

    for (auto iter = m_arpRequests.begin(); iter != m_arpRequests.end();)
    {
      auto request = *iter;

      /* Remove requests that have timed out */

      if (request->nTimesSent >= MAX_SENT_TIME)
      {

        for (auto &packet : request->packets)
        {
          uint8_t *out_Packet = packet.packet.data();
          ethernet_hdr *out_EthernetHeader = (ethernet_hdr *)out_Packet;
          Buffer outSrcMac(out_EthernetHeader->ether_dhost, out_EthernetHeader->ether_dhost + ETHER_ADDR_LEN);
          const Interface *outIface = m_router.findIfaceByMac(outSrcMac);

          uint8_t *inPacket = (uint8_t *)packet.packet.data();
          const size_t frameSize = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
          uint8_t outPacket[frameSize];
          memcpy(outPacket, inPacket, frameSize);
          // inPacket
          ethernet_hdr *inEthernetHeader = (ethernet_hdr *)inPacket;
          ip_hdr *inIpHeader = (ip_hdr *)(inPacket + sizeof(ethernet_hdr));
          // outPacket
          ethernet_hdr *outEthernetHeader = (ethernet_hdr *)outPacket;
          ip_hdr *outIpHeader = (ip_hdr *)(outPacket + sizeof(ethernet_hdr));
          icmp_t3_hdr *outIcmpHeader = (icmp_t3_hdr *)(outPacket + sizeof(ethernet_hdr) + sizeof(ip_hdr));

          // fill in ethernet header
          memcpy(outEthernetHeader->ether_shost, inEthernetHeader->ether_dhost, ETHER_ADDR_LEN);
          memcpy(outEthernetHeader->ether_dhost, inEthernetHeader->ether_shost, ETHER_ADDR_LEN);

          // fill in ip header
          outIpHeader->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
          outIpHeader->ip_ttl = 64;
          outIpHeader->ip_p = ip_protocol_icmp;
          outIpHeader->ip_dst = inIpHeader->ip_src;
          outIpHeader->ip_src = outIface->ip;
          outIpHeader->ip_sum = 0;
          outIpHeader->ip_sum = cksum(outIpHeader, sizeof(ip_hdr));

          // fill in icmp header
          outIcmpHeader->icmp_type = 3;
          outIcmpHeader->icmp_code = 1;
          outIcmpHeader->unused = 0;
          memcpy(outIcmpHeader->data, inIpHeader, ICMP_DATA_SIZE);
          outIcmpHeader->icmp_sum = 0;
          outIcmpHeader->icmp_sum = cksum(outIcmpHeader, sizeof(icmp_t3_hdr));

          Buffer outPacketBuffer(outPacket, outPacket + frameSize);
          m_router.sendPacket(outPacketBuffer, outIface->name);
        }
        iter = m_arpRequests.erase(iter);
        continue;
      }
      else
      {

        /* Construct and Send an ARP request */
        RoutingTableEntry route = m_router.getRoutingTable().lookup(request->ip);

        const Interface *iface = m_router.findIfaceByName(route.ifName);
        if (iface == nullptr)
        {
          continue;
        }

        // Prepare ethernet header for arp request
        ethernet_hdr ethHdr;
        memset(ethHdr.ether_dhost, 255, ETHER_ADDR_LEN);
        memcpy(ethHdr.ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        ethHdr.ether_type = htons(ethertype_arp);

        // Prepare arp header for arp request
        arp_hdr arpHdr;
        arpHdr.arp_hrd = htons(arp_hrd_ethernet);
        arpHdr.arp_pro = htons(ethertype_ip);
        arpHdr.arp_hln = ETHER_ADDR_LEN;
        arpHdr.arp_pln = 4;
        arpHdr.arp_op = htons(arp_op_request);
        memcpy(arpHdr.arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
        arpHdr.arp_sip = iface->ip;
        memset(arpHdr.arp_tha, 0, ETHER_ADDR_LEN);
        arpHdr.arp_tip = request->ip;

        // Load headers to packet
        Buffer packet(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        memcpy(packet.data(), &ethHdr, sizeof(ethernet_hdr));
        memcpy(packet.data() + sizeof(ethernet_hdr), &arpHdr, sizeof(arp_hdr));

        m_router.sendPacket(packet, iface->name);

        // update the queued request's data.
        request->timeSent = std::chrono::steady_clock::now();
        request->nTimesSent++;

        iter++; // only increment the iterator when we didn't delete an entry.
      }
    }

    // remove invalid cache entries.
    for (auto iter = m_cacheEntries.begin(); iter != m_cacheEntries.end();)
    {
      if (!(*iter)->isValid)
      {
        iter = m_cacheEntries.erase(iter);
        continue;
      }
      iter++;
    }
  }

  //////////////////////////////////////////////////////////////////////////

  // You should not need to touch the rest of this code.

  ArpCache::ArpCache(SimpleRouter &router)
      : m_router(router), m_shouldStop(false), m_tickerThread(std::bind(&ArpCache::ticker, this))
  {
  }

  ArpCache::~ArpCache()
  {
    m_shouldStop = true;
    m_tickerThread.join();
  }

  std::shared_ptr<ArpEntry>
  ArpCache::lookup(uint32_t ip)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto &entry : m_cacheEntries)
    {
      if (entry->isValid && entry->ip == ip)
      {
        return entry;
      }
    }

    return nullptr;
  }

  std::shared_ptr<ArpRequest>
  ArpCache::queueRequest(uint32_t ip, const Buffer &packet, const std::string &iface)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                [ip](const std::shared_ptr<ArpRequest> &request) {
                                  return (request->ip == ip);
                                });

    if (request == m_arpRequests.end())
    {
      request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
    }

    (*request)->packets.push_back({packet, iface});
    return *request;
  }

  void
  ArpCache::removeRequest(const std::shared_ptr<ArpRequest> &entry)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_arpRequests.remove(entry);
  }

  std::shared_ptr<ArpRequest>
  ArpCache::insertArpEntry(const Buffer &mac, uint32_t ip)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto entry = std::make_shared<ArpEntry>();
    entry->mac = mac;
    entry->ip = ip;
    entry->timeAdded = steady_clock::now();
    entry->isValid = true;
    m_cacheEntries.push_back(entry);

    auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                [ip](const std::shared_ptr<ArpRequest> &request) {
                                  return (request->ip == ip);
                                });
    if (request != m_arpRequests.end())
    {
      return *request;
    }
    else
    {
      return nullptr;
    }
  }

  void
  ArpCache::clear()
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_cacheEntries.clear();
    m_arpRequests.clear();
  }

  void
  ArpCache::ticker()
  {
    while (!m_shouldStop)
    {
      std::this_thread::sleep_for(std::chrono::seconds(1));

      {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto now = steady_clock::now();

        for (auto &entry : m_cacheEntries)
        {
          if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO))
          {
            entry->isValid = false;
          }
        }

        periodicCheckArpRequestsAndCacheEntries();
      }
    }
  }

  std::ostream &
  operator<<(std::ostream &os, const ArpCache &cache)
  {
    std::lock_guard<std::mutex> lock(cache.m_mutex);

    os << "\nMAC            IP         AGE                       VALID\n"
       << "-----------------------------------------------------------\n";

    auto now = steady_clock::now();
    for (const auto &entry : cache.m_cacheEntries)
    {

      os << macToString(entry->mac) << "   "
         << ipToString(entry->ip) << "   "
         << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
         << entry->isValid
         << "\n";
    }
    os << std::endl;
    return os;
  }

} // namespace simple_router

/* vim:set expandtab shiftwidth=2 textwidth=79: */
