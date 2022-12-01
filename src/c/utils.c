/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains miscellaneous helper functions.
 *
 */

/*
 * This project is based on the Simple Router assignment included in the
 * Mininet project (https://github.com/mininet/mininet/wiki/Simple-Router) which,
 * in turn, is based on a programming assignment developed at Stanford
 * (http://www.scs.stanford.edu/09au-cs144/lab/router.html)
 *
 * While most of the code for chirouter has been written from scratch, some
 * of the original Stanford code is still present in some places and, whenever
 * possible, we have tried to provide the exact attribution for such code.
 * Any omissions are not intentional and will be gladly corrected if
 * you contact us at borja@cs.uchicago.edu
 *
 */

/*
 *  Copyright (c) 2016-2018, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "protocols/ethernet.h"
#include "protocols/arp.h"
#include "chirouter.h"
#include "utils.h"

/* See utils.h */
uint16_t cksum (const void *_data, int len)
{
      const uint8_t *data = _data;
      uint32_t sum;

      for (sum = 0;len >= 2; data += 2, len -= 2)
      {
        sum += data[0] << 8 | data[1];
      }

      if (len > 0)
      {
        sum += data[0] << 8;
      }

      while (sum > 0xffff)
      {
        sum = (sum >> 16) + (sum & 0xffff);
      }

      sum = htons (~sum);

      return sum ? sum : 0xffff;
}

/* See utils.h */
bool ethernet_addr_is_equal(uint8_t *addr1, uint8_t *addr2)
{
    for (int i=0; i<ETHER_ADDR_LEN; i++)
    {
        if(addr1[i] != addr2[i])
            return false;
    }
    return true;
}

/* See utils.h */
int send_ARP(chirouter_ctx_t *ctx, chirouter_interface_t *interface, uint8_t dst_mac, uint32_t targetIP, uint16_t arp_op){
    //get the length first
    int reply_len = sizeof(ethhdr_t) + (sizeof(arp_packet_t));

    //int convert to uint8
    uint8_t Reply[reply_len];
    memset(Reply, 0, reply_len);

    //because reply message is header + reply_arp. processing these two strut individually
    //init ethhdr
    ethhdr_t *reply_ether_hdr = (ethhdr_t *) Reply;
    memcpy(reply_ether_hdr->src, interface->mac, ETHER_ADDR_LEN);
    reply_ether_hdr->type = htons(ETHERTYPE_ARP);

    //init arp packet
    arp_packet_t *reply_arp = (arp_packet_t *)ETHER_PAYLOAD_START(Reply);
    reply_arp->hrd = htons(ARP_HRD_ETHERNET);
    reply_arp->pro = htons(ETHERTYPE_IP);
    reply_arp->hln = ETHER_ADDR_LEN;
    reply_arp->pln = IPV4_ADDR_LEN;
    reply_arp->op = htons(arp_op);
    reply_arp->spa = interface->ip.s_addr;
    reply_arp->tpa = targetIP;
    memcpy(reply_arp->sha, interface->mac, ETHER_ADDR_LEN);

    //check ARP types:
    if (arp_op == ARP_OP_REQUEST)
    {
        memcpy(reply_ether_hdr->dst, "\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN);
        memcpy(reply_arp->tha, "\x00\x00\x00\x00\x00\x00", ETHER_ADDR_LEN);
    }
    else if (arp_op == ARP_OP_REPLY)
    {
        memcpy(reply_ether_hdr->dst, dst_mac, ETHER_ADDR_LEN);
        memcpy(reply_arp->tha, dst_mac, ETHER_ADDR_LEN);
    }
    else
    {
        chilog(ERROR, "INVALID CODE.");
        return 1;
    }

    //send
    //int chirouter_send_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t *msg, size_t len);
    return chirouter_send_frame(ctx, interface, Reply, reply_len);
}

int send_ICMP(chirouter_ctx_t *ctx, ethernet_frame_t *frame, uint8_t type, uint8_t code){

    //ethernet header
    ethhdr_t *frame_ethhdr = (ethhdr_t *)frame->raw;
    //ip header
    iphdr_t *frame_iphdr = (iphdr_t *)(frame->raw + sizeof(ethhdr_t));

    int payload_len;
    if (type == ICMPTYPE_ECHO_REPLY || type == ICMPTYPE_ECHO_REQUEST)
    {
        payload_len = ntohs(frame_iphdr->len) - sizeof(iphdr_t) - ICMP_HDR_SIZE;
    }
    else
    {
        payload_len = sizeof(iphdr_t) + 8;
    }

    //get the reply message length
    int reply_len = sizeof(ethhdr_t) + sizeof(iphdr_t) + ICMP_HDR_SIZE + payload_len;

    uint8_t Reply[reply_len];
    memset(Reply, 0, reply_len);

    //init the reply ethernet header
    ethhdr_t *reply_ethhdr = (ethhdr_t *) Reply;
    memcpy(reply_ethhdr->dst,frame_ethhdr->src, ETHER_ADDR_LEN);
    memcpy(reply_ethhdr->src,frame->in_interface->mac, ETHER_ADDR_LEN);
    reply_ethhdr->type = htons(ETHERTYPE_IP);

    //init the reply ip header
    iphdr_t *reply_iphdr = (iphdr_t *)(Reply + sizeof(ethhdr_t));
    int reply_iphdr_len = sizeof(iphdr_t) + ICMP_HDR_SIZE + payload_len;
    reply_iphdr->tos = 0;
    reply_iphdr->cksum = 0;
    reply_iphdr->len = htons(reply_iphdr_len);
    reply_iphdr->id = htons(0);
    reply_iphdr->off = htons(0);
    reply_iphdr->ttl = 64;
    reply_iphdr->proto = ICMP_PROTO;
    reply_iphdr->version = 4;
    reply_iphdr->ihl = 5;

    memcpy(&reply_iphdr->src, &frame->in_interface->ip.s_addr, IPV4_ADDR_LEN);
    memcpy(&reply_iphdr->dst, &frame_iphdr->src, IPV4_ADDR_LEN);
    reply_iphdr->cksum = cksum(reply_iphdr, sizeof(iphdr_t));

    //get the icmp packet
    icmp_packet_t *icmp = (icmp_packet_t *) (frame->raw + sizeof(ethhdr_t) + sizeof(iphdr_t));

    //init the reply icmp packet
    icmp_packet_t *reply_icmp = (icmp_packet_t *)(Reply + sizeof(ethhdr_t) + sizeof(iphdr_t));
    reply_icmp->code = code;
    reply_icmp->type = type;
    reply_icmp->chksum = 0;

    //based on reply types, init the payload
    if(type == ICMPTYPE_DEST_UNREACHABLE)
    {
        memcpy(reply_icmp->dest_unreachable.payload, frame_iphdr, payload_len);
    }
    else if(type == ICMPTYPE_ECHO_REQUEST || type == ICMPTYPE_ECHO_REPLY)
    {
        if(code ==0){
            reply_icmp->echo.identifier = icmp->echo.identifier;
            reply_icmp->echo.seq_num = icmp->echo.seq_num;
            memcpy(reply_icmp->echo.payload,icmp->echo.payload,payload_len);
        }
    }
    else
    {
        memcpy(reply_icmp->time_exceeded.payload,frame_iphdr,payload_len);
    }

    reply_icmp->chksum = cksum(reply_icmp ,ICMP_HDR_SIZE + payload_len);

    return chirouter_send_frame(ctx, frame->in_interface, Reply, reply_len);

}


