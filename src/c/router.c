/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains the actual functionality of the router.
 *  When a router receives an Ethernet frame, it is handled by
 *  the chirouter_process_ethernet_frame() function.
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

#include <stdio.h>
#include <assert.h>

#include <string.h>
#include <stdlib.h>

#include "chirouter.h"
#include "arp.h"
#include "utils.h"
#include "utlist.h"


int handle_arp(chirouter_ctx_t *ctx, ethernet_frame_t *frame, ethhdr_t *coming_eth_header);
int handle_icmp(chirouter_ctx_t *ctx, ethernet_frame_t *frame, ethhdr_t *coming_eth_header);
int IP_forwarding(chirouter_ctx_t *ctx, ethernet_frame_t *frame, iphdr_t *coming_ip_header, ethhdr_t *coming_eth_header);




/*
 * chirouter_process_ethernet_frame - Process a single inbound Ethernet frame
 *
 * This function will get called every time an Ethernet frame is received by
 * a router. This function receives the router context for the router that
 * received the frame, and the inbound frame (the ethernet_frame_t struct
 * contains a pointer to the interface where the frame was received).
 * Take into account that the chirouter code will free the frame after this
 * function returns so, if you need to persist a frame (e.g., because you're
 * adding it to a list of withheld frames in the pending ARP request list)
 * you must make a deep copy of the frame.
 *
 * chirouter can manage multiple routers at once, but does so in a single
 * thread. i.e., it is guaranteed that this function is always called
 * sequentially, and that there will not be concurrent calls to this
 * function. If two routers receive Ethernet frames "at the same time",
 * they will be ordered arbitrarily and processed sequentially, not
 * concurrently (and with each call receiving a different router context)
 *
 * ctx: Router context
 *
 * frame: Inbound Ethernet frame
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 *
 *   Note: In the event of a critical error, the entire router will shut down and exit.
 *         You should only return -1 for issues that would prevent the router from
 *         continuing to run normally. Return 1 to indicate that the frame could
 *         not be processed, but that subsequent frames can continue to be processed.
 */
int chirouter_process_ethernet_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    /* Your code goes here */

    //check which type comes in
    ethhdr_t *coming_eth_header = (ethhdr_t *)(frame->raw);

    if(coming_eth_header->type == ETHERTYPE_ARP){ //handle ARP
        handle_arp(ctx, frame, coming_eth_header);
    }
    else if(coming_eth_header->type == ETHERTYPE_IP){ //all ICMP has ipv4 Ethernet type
        handle_icmp(ctx, frame, coming_eth_header);
    }
    else if (coming_eth_header->type == ETHERTYPE_IPV6){
        //scilence drop
        return 0;
    }
    else{
        return 1;
    }

    return 0;
}


/* handle_arp: process arp request/reply
 *
 * ctx: Router context
 *
 * frame: Inbound Ethernet frame
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 */
int handle_arp(chirouter_ctx_t *ctx, ethernet_frame_t *frame, ethhdr_t *coming_eth_header){

    arp_packet_t *arp = (arp_packet_t *)ETHER_PAYLOAD_START(coming_eth_header);

    //Implementing ARP replies is straightforward
    if(ntohs(arp->op) == ARP_OP_REQUEST){

        bool ip_matched = false;
        //check which interface send this
        for(int i = 0; i< ctx->num_interfaces; i++){
            if(arp->tpa == ctx->interfaces[i].ip.s_addr){
                //matched!
                ip_matched = true;
                //Send back an ARP reply
                send_ARP(ctx,&ctx->interfaces[i], coming_eth_header->src, arp->tpa, ARP_OP_REPLY);
            }
        }
        // If your router receives an IP datagram directed to one of its IP addresses, but that IP address is not the IP address of the interface on which the datagram was received, send an ICMP Host Unreachable message to the host that sent the IP datagram.
        if(!ip_matched){
            send_ICMP(ctx, frame, ICMPTYPE_DEST_UNREACHABLE, ICMPCODE_DEST_HOST_UNREACHABLE);
        }
    }
    //Sending ARP requests is a bit more elaborate
    else if (ntohs(arp->op) == ARP_OP_REPLY){
        //always check whether an entry already exists for that IP address. If it does not, you will need to send an ARP request for that MAC address. The check processe is in IP_forwarding()
        struct in_addr *ip_inqueue = malloc(sizeof(struct in_addr));
        ip_inqueue->s_addr = arp->spa;

        uint8_t mac_inqueue[ETHER_ADDR_LEN];
        memcpy(mac_inqueue, arp->sha, ETHER_ADDR_LEN);

        // If an ARP reply does arrive, you must add the IP/MAC mapping to the ARP cache.
        pthread_mutex_lock(&ctx->lock_arp);
        chirouter_arp_cache_add(ctx, ip_inqueue, mac_inqueue);
        pthread_mutex_unlock(&(ctx->lock_arp));

        // You must also fetch the pending ARP request
        //- Look up a pending ARP request by IP
        pthread_mutex_lock(&ctx->lock_arp);
        chirouter_pending_arp_req_t *pending_arp = chirouter_arp_pending_req_lookup(ctx, ip_inqueue);

        /*
        *  chirouter_arp_process
        *  that is run as a separate thread, and which will wake up every second
        *  to purge stale entries in the ARP cache (entries that are more than 15 seconds
        *  old) and to traverse the list of pending ARP requests. For each pending
        *  request in the list, it will call chirouter_arp_process_pending_req,
        *  which must either re-send the pending ARP request or cancel the
        *  request and send ICMP Host Unreachable messages in reply to all
        *  the withheld frames.
        *
        */
        // hand over to chirouter_arp_process_pending_req to send ARP, we return, wait for the new request.
        if(pending_arp == NULL){
            pthread_mutex_lock(&ctx->lock_arp);
            return 0;
        }

        //forward all withheld frames (since you will now know what MAC address to send them to).
        // If you are able to obtain that MAC address using ARP (see ARP section above),
        if(pending_arp != NULL){
            withheld_frame_t *withheld_frame;
            DL_FOREACH(pending_arp->withheld_frames, withheld_frame){

                iphdr_t *ip_header = (iphdr_t *)(withheld_frame->frame->raw + sizeof(ethhdr_t));
                if(ip_header->ttl != 1){
                    //forwarding
                    ethhdr_t *withheld_eth_header = (ethhdr_t *)(withheld_frame->frame->raw);
                    memcpy(withheld_eth_header->dst, mac_inqueue, ETHER_ADDR_LEN);
                    memcpy(withheld_eth_header->src, pending_arp->out_interface->mac, ETHER_ADDR_LEN);

                    // If you are able to obtain that MAC address using ARP (see ARP section above), then you must decrement the TTL of the IP datagram by one, recompute the IP header checksum, and send the IP datagram on the appropriate interface.
                    ip_header->ttl -=1;
                    ip_header->cksum = cksum(ip_header, sizeof(iphdr_t));
                    chirouter_send_frame(ctx, pending_arp->out_interface,
                                     withheld_frame->frame->raw,
                                     withheld_frame->frame->length);

                } else{
                    // If the TTL of the datagram is 1 (which means decrementing it by one will make the TTL equal to zero), you must send an ICMP Time Exceeded reply.
                    send_ICMP(ctx, withheld_frame->frame, ICMPTYPE_TIME_EXCEEDED,0);
                }
            }
            //You must also remove the pending ARP request from the pending ARP request list.
            chirouter_arp_pending_req_free_frames(pending_arp);
            DL_DELETE(ctx->pending_arp_reqs, pending_arp);
            free(pending_arp);
        }
        pthread_mutex_unlock(&ctx->lock_arp);

    }
    else{
        return 1;
    }
    return 0;

}

/* handle_icmp: process icmp message
 *
 * ctx: Router context
 *
 * frame: Inbound Ethernet frame
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 */
int handle_icmp(chirouter_ctx_t *ctx, ethernet_frame_t *frame, ethhdr_t *coming_eth_header){

    iphdr_t *coming_ip_header = (iphdr_t *)(frame->raw + sizeof(ethhdr_t));
    icmp_packet_t *icmp;

    bool interface_exist = false;
    bool need_IP_forwarding = true;
    bool host_unreach = false;

    //check if it comes from the src or can be forwarding
    for (int i = 0; i < ctx->num_interfaces; i++){
        chirouter_interface_t *source_interface = &(ctx->interfaces[i]);

        //check if mac adress match
        if (ethernet_addr_is_equal(coming_eth_header->dst, source_interface->mac)){
            interface_exist = true;
        }

        if (coming_ip_header->dst == source_interface->ip.s_addr){

            need_IP_forwarding = false;
            //if match, check if the coming one match the frame
            if(coming_ip_header->dst != frame->in_interface->ip.s_addr){
                host_unreach = true;
            }
        }

    }

    if(!interface_exist)
        return 1;

    //check TCP/UDP?
    bool is_tcp_udp = (coming_ip_header->proto == TCP_PROTO || coming_ip_header->proto == UDP_PROTO);

    //check is Echo or not
    bool is_echo = (coming_ip_header->proto == ICMP_PROTO);
    /*no need IP forwarding checking */ //need_IP_forwarding = false;
    //If your router receives an IP datagram directed to one of its IP addresses

    if(!need_IP_forwarding){
        //case 1: Host Unreaschable because of IP address not match
        // If your router receives an IP datagram directed to one of its IP addresses, but that IP address is not the IP address of the interface on which the datagram was received, send an ICMP Host Unreachable message to the host that sent the IP datagram.
        if(host_unreach){
            send_ICMP(ctx, frame, ICMPTYPE_DEST_UNREACHABLE, ICMPCODE_DEST_HOST_UNREACHABLE);
            return 0;
        }
        //case 2: Port Unreaschable because of TCP/UDP
        // If your router receives a TCP/UDP packet directed to one of its IP addresses, you must send an ICMP Port Unreachable to the host that sent that TCP/UDP packet.
        if(is_tcp_udp){
            send_ICMP(ctx, frame, ICMPTYPE_DEST_UNREACHABLE, ICMPCODE_DEST_PORT_UNREACHABLE);
            return 0;
        }

        //case 3: Time Exceeded because of TTL is 1
        // If your router receives an IP datagram directed to one of its IP addresses, and that IP datagram’s TTL is 1, you must send a Time Exceeded message to the host that sent the IP datagram (Note: Once you implement IP forwarding, this behaviour will change slightly)
        if (coming_ip_header->ttl == 1){
            send_ICMP(ctx, frame, ICMPTYPE_TIME_EXCEEDED, 0);
            return 0;
        }

        //case 4: echo because of receving ICMP Echo
        // If your router receives an ICMP Echo Request directed to one of its IP addresses, you must send an ICMP Echo Reply to the host that sent the ICMP Echo Request.
        if(is_echo){
            //init the reply packet from frame
            icmp = (icmp_packet_t *)(frame->raw + sizeof(ethhdr_t) + sizeof(iphdr_t));
            if(icmp->type == ICMPTYPE_ECHO_REQUEST){
                send_ICMP(ctx, frame, ICMPTYPE_ECHO_REPLY, 0);
            }
            return 0;
        }

    } else {
        /* need IP forwarding checking */
        //When your routers receive an IP datagram that is not directed to one of its IP addresses
        return IP_forwarding(ctx, frame, coming_ip_header, coming_eth_header);
    }

}

/* IP_forwarding: process icmp message when need IP forwarding
 *
 * ctx: Router context
 *
 * frame: Inbound Ethernet frame
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 */
int IP_forwarding(chirouter_ctx_t *ctx, ethernet_frame_t *frame, iphdr_t *coming_ip_header, ethhdr_t *coming_eth_header){

    //You must check the routing table and see whether the destination IP address of the IP datagram matches any of the networks in the routing table. If there are multiple matching entries, you must use longest prefix match to select just one.

    //loop routing tabe
    chirouter_interface_t *out_interface = NULL;
    in_addr_t max_subnet_mask = 0;
    struct in_addr *out_dst = malloc(sizeof(struct in_addr));

    /* Loop routing table */
    for (int i = 0; i < ctx->num_rtable_entries; i++)
    {
        //calculte the result with & by mask and dest_IP
        int forwarded_ip = (ctx->routing_table[i].mask.s_addr) & (ctx->routing_table[i].dest.s_addr);
        if (forwarded_ip == ((coming_ip_header->dst) & (ctx->routing_table[i].mask.s_addr))){
            //If there are multiple matching entries, you must use longest prefix match to select just one.
            //if find one, then update the compare subnet mask and continue matching
            if (ntohs(ctx->routing_table[i].mask.s_addr) >= max_subnet_mask){

                out_interface = ctx->routing_table[i].interface;
                max_subnet_mask = ntohs(ctx->routing_table[i].mask.s_addr);

                //If there is a match, you must take into account whether the matching entry specifies a gateway or not. For gateway routes, you must obtain the MAC address of the gateway router, and for non-gateway routes you must obtain the MAC address of the destination IP address.
                out_dst->s_addr = coming_ip_header->dst;
                if(ctx->routing_table[i].gw.s_addr != 0)
                    out_dst->s_addr = ctx->routing_table[i].gw.s_addr;
            }
        }
    }
    //No matching-- If there is no match in the routing table, then you must send an ICMP Network Unreachable reply to the host that sent that IP datagram.
    if (out_interface == NULL){
        send_ICMP(ctx, frame, ICMPTYPE_DEST_UNREACHABLE, ICMPCODE_DEST_NET_UNREACHABLE);
        return 0;
    }

    //If there is a match,

    //(from ARP)always check whether an entry already exists for that IP address. look up cache, then look  up pending list
    pthread_mutex_lock(&ctx->lock_arp);
    chirouter_arpcache_entry_t *arp_entry = chirouter_arp_cache_lookup(ctx, out_dst);
    pthread_mutex_unlock(&ctx->lock_arp);

    //If it does not, you will need to send an ARP request for that MAC address and return to ARP part
    if(arp_entry == NULL){
        //send ARP request for that MAC
        send_ARP(ctx, out_interface, coming_eth_header->src, out_dst->s_addr, ARP_OP_REQUEST);

        pthread_mutex_lock(&ctx->lock_arp);
        chirouter_pending_arp_req_t *pending_arp = chirouter_arp_pending_req_lookup(ctx, out_dst);

        if (pending_arp == NULL){
            pending_arp = chirouter_arp_pending_req_add(ctx, out_dst, out_interface);
        }
        chirouter_arp_pending_req_add_frame(ctx, pending_arp, frame);

        pthread_mutex_unlock(&ctx->lock_arp);

        return 0;
    }

    // then you must decrement the TTL of the IP datagram by one, recompute the IP header checksum, and send the IP datagram on the appropriate interface. If the TTL of the datagram is 1 (which means decrementing it by one will make the TTL equal to zero), you must send an ICMP Time Exceeded reply.
    if(coming_ip_header->ttl != 1){
        memcpy(coming_eth_header->dst, out_interface->mac, ETHER_ADDR_LEN);
        memcpy(coming_eth_header->src, arp_entry->mac, ETHER_ADDR_LEN);

        coming_ip_header->ttl -=1;
        coming_ip_header->cksum = cksum(coming_ip_header, sizeof(iphdr_t));

        return chirouter_send_frame(ctx, out_interface, frame->raw, frame->length);

    } else{
        //However, take into account that you must only send the ICMP Time Exceeded reply if the IP datagram can be forwarded and you have been able to obtain a MAC address for it.
        send_ICMP(ctx, frame, ICMPTYPE_TIME_EXCEEDED,0);
        return 0;
    }
}

