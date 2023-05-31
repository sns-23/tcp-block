#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>

#include <pcap.h>

#include "checksum.h"
#include "util.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define eth_hdr(pkt) ((struct ethhdr *)(pkt))
#define eth_hdr_len(pkt) (ETH_HLEN)
#define ip_hdr(pkt) ((struct iphdr *)((char *)(pkt) + eth_hdr_len(pkt)))
#define ip_hdr_len(pkt) (ip_hdr(pkt)->ihl * 4)
#define ip_len(pkt) (ntohs(ip_hdr(pkt)->tot_len))
#define ip_data(pkt) ((char *)ip_hdr(pkt) + ip_hdr_len(pkt))
#define ip_data_len(pkt) (ip_len(pkt) - ip_hdr_len(pkt))
#define tcp_hdr(pkt) ((struct tcphdr *)((char *)ip_hdr(pkt) + ip_hdr_len(pkt)))
#define tcp_hdr_len(pkt) (tcp_hdr(pkt)->th_off * 4)
#define tcp_len(pkt) (ip_len(pkt) - ip_hdr_len(pkt))
#define tcp_data(pkt) ((char *)tcp_hdr(pkt) + tcp_hdr_len(pkt))
#define tcp_data_len(pkt) (tcp_len(pkt) - tcp_hdr_len(pkt))
#define pkt_len(pkt) (eth_hdr_len(pkt) + ip_len(pkt))

#define FINMSG "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n"

char *interface;
char *pattern;
pcap_t *handle;
struct ether_addr my_mac_addr;

void usage(void)
{
    puts("syntax : tcp-block <interface> <pattern>");
    puts("sample : tcp-block wlan0 \"Host: test.gilgil.net\"");
}

bool check_http(char *packet)
{
    /* 
     * HTTP header starts with method name or "HTTP" 
     * https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods 
     */
    const char *methods[] = {
        "HTTP",
        "CONNECT",
        "DELETE",
        "GET",
        "HEAD",
        "OPTIONS",
        "POST",
        "PUT",
        "TRACE"
    };
    
    for (int i = 0; i < ARRAY_SIZE(methods); i++) {
        if (!strncmp(methods[i], packet, strlen(methods[i])))
            return true;
    }
        
    return false;
}

int find_http_data(char *packet)
{
    char *tcp_data;
    size_t tcp_data_len;
    char *buf;

    tcp_data = tcp_data(packet);
    tcp_data_len = tcp_data_len(packet);

    /* 
     * minimun length of http request is always greater than 16 bytes
     * http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes 
     */
    if (tcp_data_len < 16)
        return -1;

    /* 
     * TODO: Attacker can bypass this check by simply adding \r\n before HTTP Header
     *       The better checker is required
     */
    if (check_http(tcp_data) == false)
        return -1;

    return 0;
}

char *find_pattern(char *http_data, size_t http_data_len)
{
    return memmem(http_data, http_data_len, pattern, strlen(pattern));
}

char *gen_forward_pkt(char *org_pkt)
{
    struct ethhdr *forward_ethhdr;
    struct iphdr *forward_iphdr;
    struct tcphdr *forward_tcphdr;
    char *forward_pkt;
    uint32_t checksum;
    
    forward_pkt = malloc(sizeof(*forward_ethhdr) + sizeof(*forward_iphdr) + sizeof(*forward_tcphdr));
    if (forward_pkt == NULL)
        return NULL;

    forward_ethhdr = forward_pkt;
    memcpy(forward_ethhdr->h_dest, eth_hdr(org_pkt)->h_dest, ETH_ALEN);
    memcpy(forward_ethhdr->h_source, &my_mac_addr, ETH_ALEN);
    forward_ethhdr->h_proto = htons(ETH_P_IP);

    forward_iphdr = (char *)forward_ethhdr + sizeof(*forward_ethhdr);
    /* There are no additional options */
    memcpy(forward_iphdr, ip_hdr(org_pkt), sizeof(*forward_iphdr));
    forward_iphdr->ihl = sizeof(*forward_iphdr) / 4;
    forward_iphdr->tot_len = htons(sizeof(*forward_iphdr) + sizeof(*forward_tcphdr));
    forward_iphdr->check = 0;
    forward_iphdr->check = ip_fast_csum(forward_iphdr, forward_iphdr->ihl);

    forward_tcphdr = (char *)forward_iphdr + sizeof(*forward_iphdr);
    memcpy(forward_tcphdr, tcp_hdr(org_pkt), sizeof(*forward_tcphdr));
    forward_tcphdr->th_seq = htonl(ntohl(tcp_hdr(org_pkt)->th_seq) + tcp_data_len(org_pkt));
    forward_tcphdr->th_off = sizeof(*forward_tcphdr) / 4;
    forward_tcphdr->th_flags = 0;
    forward_tcphdr->rst = true;
    forward_tcphdr->psh = true;
    forward_tcphdr->ack = true;
    forward_tcphdr->th_sum = 0;

    checksum = csum_partial(forward_tcphdr, ip_data_len(forward_pkt), 0);
    forward_tcphdr->th_sum = csum_tcpudp_magic(forward_iphdr->saddr, forward_iphdr->daddr, 
                                               ip_data_len(forward_pkt), forward_iphdr->protocol, checksum);
    return forward_pkt;
}

char *gen_backward_pkt(char *org_pkt)
{
    struct ethhdr *backward_ethhdr;
    struct iphdr *backward_iphdr;
    struct tcphdr *backward_tcphdr;
    char *backward_pkt;
    uint32_t checksum;
    
    backward_pkt = malloc(sizeof(*backward_ethhdr) + sizeof(*backward_iphdr) + 
                            sizeof(*backward_tcphdr) + sizeof(FINMSG));
    if (backward_pkt == NULL)
        return NULL;

    backward_ethhdr = eth_hdr(backward_pkt);
    memcpy(backward_ethhdr->h_dest, eth_hdr(org_pkt)->h_source, ETH_ALEN);
    memcpy(backward_ethhdr->h_source, &my_mac_addr, ETH_ALEN);
    backward_ethhdr->h_proto = htons(ETH_P_IP);

    backward_iphdr = ip_hdr(backward_pkt);
    /* There are no additional options */
    memcpy(backward_iphdr, ip_hdr(org_pkt), sizeof(*backward_iphdr));
    backward_iphdr->ihl = sizeof(*backward_iphdr) / 4;
    backward_iphdr->tot_len = htons(sizeof(*backward_iphdr) + sizeof(*backward_tcphdr) + sizeof(FINMSG) - 1);
    backward_iphdr->ttl = 128;
    backward_iphdr->saddr = ip_hdr(org_pkt)->daddr;
    backward_iphdr->daddr = ip_hdr(org_pkt)->saddr;
    backward_iphdr->check = 0;
    backward_iphdr->check = ip_fast_csum(backward_iphdr, backward_iphdr->ihl);

    backward_tcphdr = tcp_hdr(backward_pkt);
    memcpy(backward_tcphdr, tcp_hdr(org_pkt), sizeof(*backward_tcphdr));
    backward_tcphdr->th_seq = tcp_hdr(org_pkt)->th_ack;
    backward_tcphdr->th_ack = htonl(ntohl(tcp_hdr(org_pkt)->th_seq) + tcp_data_len(org_pkt));
    backward_tcphdr->th_sport = tcp_hdr(org_pkt)->th_dport;
    backward_tcphdr->th_dport = tcp_hdr(org_pkt)->th_sport;
    backward_tcphdr->th_off = sizeof(*backward_tcphdr) / 4;
    backward_tcphdr->th_flags = 0;
    backward_tcphdr->fin = true;
    backward_tcphdr->psh = true;
    backward_tcphdr->ack = true;
    backward_tcphdr->th_sum = 0;

    memcpy(backward_tcphdr + 1, FINMSG, sizeof(FINMSG) - 1);

    checksum = csum_partial(backward_tcphdr, ip_data_len(backward_pkt), 0);
    backward_tcphdr->th_sum = csum_tcpudp_magic(backward_iphdr->saddr, backward_iphdr->daddr, 
                                                ip_data_len(backward_pkt), backward_iphdr->protocol, checksum);

    return backward_pkt;
}

#ifdef USE_RAWSOCKET
int init_raw_sk()
{
    int sk;
    int flag = true;

    sk = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sk < 0) {
        pr_err("socket()\n");
        return -1;
    }
        
    if (setsockopt(sk, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0) {
        pr_err("setsockopt()\n");
        close(sk);
        return -1;
    }

    return sk;
}
#endif

int send_blocking_pkt(char *org_pkt)
{
    char *forward_pkt;
    char *backward_pkt;
    int ret;
    
    forward_pkt = gen_forward_pkt(org_pkt);
    if (forward_pkt == NULL)
        goto out_error;

    backward_pkt = gen_backward_pkt(org_pkt);
    if (backward_pkt == NULL) 
        goto out_error;

    ret = pcap_sendpacket(handle, forward_pkt, pkt_len(forward_pkt));
    if (ret < 0) 
        goto out_error;

#ifdef USE_RAWSOCKET
    struct sockaddr_in addr;
    int sk;

    sk = init_raw_sk();
    if (sk < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = tcp_hdr(backward_pkt)->th_dport;
    addr.sin_addr.s_addr = ip_hdr(backward_pkt)->daddr;
    ret = sendto(sk, ip_hdr(backward_pkt), ip_len(backward_pkt), 0, &addr, sizeof(addr));
    if (ret < 0) 
        goto out_error;
    
    close(sk);
#else
    ret = pcap_sendpacket(handle, backward_pkt, pkt_len(backward_pkt));
    if (ret < 0) 
        goto out_error;
#endif

    free(forward_pkt);
    free(backward_pkt);    

    return 0;

out_error:
    if (forward_pkt)
        free(forward_pkt);
    if (backward_pkt)
        free(backward_pkt);
#ifdef USE_RAWSOCKET
    close(sk);
#endif
    return -1;
}

void callback(char *useless, const struct pcap_pkthdr *pkthdr, 
                char *packet)
{
    char *host;
    int ret;

    ret = find_http_data(packet);
    if (ret < 0) 
        return;

    if (find_pattern(tcp_data(packet), tcp_data_len(packet)) == NULL) 
        return;

    pr_info("pattern detected!\n");
   
    ret = send_blocking_pkt(packet);
    if (ret < 0) {
        pr_err("Error while sending blocking packets\n");
        return;
    }

    return;    
}

pcap_t *init_pcap(const char *device)
{
    pcap_t *handle;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;
    bpf_u_int32 tmp;
    int ret;

    handle = pcap_open_live(device, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        pr_err("pcap_open_live()\n"
               "errbuf: %s\n", errbuf);
        goto out_error;
    }

    ret = pcap_lookupnet(device, &netp, &tmp, errbuf);
    if (ret < 0) {
        pr_err("pcap_lookupnet()\n"
               "errbuf: %s\n", errbuf);
        goto out_error;
    }

    ret = pcap_compile(handle, &fp, "ip and tcp", 0, netp);
    if (ret < 0) {
        pr_err("pcap_compile()\n");
        goto out_error;
    }

    ret = pcap_setfilter(handle, &fp);
    if (ret < 0) {
        pr_err("pcap_compile()\n");
        goto out_error;
    }

    return handle;

out_error:
    if (handle)
        pcap_close(handle);
    return NULL;
}

int resolve_my_mac(char *interface)
{
    struct ifreq ifr;
    int ret;
    int sk;

    sk = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&ifr, 0, sizeof(ifr)); 
    strcpy(ifr.ifr_name, interface); 

    ret = ioctl(sk, SIOCGIFHWADDR, &ifr);
    close(sk);

    if (ret < 0) 
        return -1;

    memcpy(&my_mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    return 0;
}

int main(int argc, char *argv[])
{
    int ret;

    if (argc != 3) {
        usage();
        return 0;
    }

    interface = argv[1];
    pattern = argv[2];

    if (resolve_my_mac(interface) < 0) {
        pr_err("resolve_my_mac(%s)\n", interface);
        return -1;
    }

    handle = init_pcap(interface);
    if (handle == NULL) {
        pr_err("init_pcap(%s)\n", interface);
        return -1;
    }
        
    ret = pcap_loop(handle, 0, callback, NULL);
    if (ret < 0) {
        pr_err("pcap_loop()\n");
        pcap_close(handle);
        return -1;
    }

    pcap_close(handle);

    return 0;
}