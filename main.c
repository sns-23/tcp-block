#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <pcap.h>

#include "checksum.h"
#include "util.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define FINMSG "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n"
#define pkt_len(pkt) (ntohs(((struct iphdr *)((char *)pkt + ETH_HLEN))->tot_len) + ETH_HLEN)

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

int find_http_data(char *packet, char **bufptr, size_t *n)
{
    struct ethhdr *ethhdr;
    struct iphdr *iphdr;
    struct tcphdr *tcphdr;
    char *tcp_data;
    size_t tcp_data_len;
    char *buf;

    if (*bufptr == NULL)
        buf = malloc(tcp_data_len + 1);
    else
        buf = *bufptr;

    if (buf == NULL)
        return -1;

    ethhdr = packet;

    /* ethhdr->h_proto == ETH_P_IP has already been checked by the pcap filter */
    iphdr = (char *)ethhdr + sizeof(*ethhdr);

    /* iphdr->protocol == IPPROTO_TCP has already been checked by the pcap filter */
    tcphdr = (char *)iphdr + iphdr->ihl * 4;
    tcp_data = (char *)tcphdr + tcphdr->th_off * 4;
    tcp_data_len = ntohs(iphdr->tot_len) - (iphdr->ihl + tcphdr->th_off) * 4;

    /* 
     * minimun length of http request is always greater than 16 bytes
     * http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes 
     */
    if (tcp_data_len < 16)
        return -1;

    if (check_http(tcp_data) == false)
        return -1;

    memcpy(buf, tcp_data, tcp_data_len);
    buf[tcp_data_len] = '\0';
    *bufptr = buf;
    *n = tcp_data_len;

    return 0;
}

char *find_pattern(char *http_data, size_t http_data_len)
{
    return memmem(http_data, http_data_len, pattern, strlen(pattern));
}

char *gen_forward_pkt(struct ethhdr *org_ethhdr, struct iphdr *org_iphdr, struct tcphdr *org_tcphdr)
{
    struct ethhdr *forward_ethhdr;
    struct iphdr *forward_iphdr;
    struct tcphdr *forward_tcphdr;
    char *forward_pkt;
    size_t org_tcpdata_len;

    org_tcpdata_len = ntohs(org_iphdr->tot_len) - (org_iphdr->ihl + org_tcphdr->th_off) * 4;
    
    forward_pkt = malloc(sizeof(*forward_ethhdr) + sizeof(*forward_iphdr) + sizeof(*forward_tcphdr));
    if (forward_pkt == NULL)
        return NULL;

    forward_ethhdr = forward_pkt;
    memcpy(forward_ethhdr->h_dest, org_ethhdr->h_dest, ETH_ALEN);
    memcpy(forward_ethhdr->h_source, &my_mac_addr, ETH_ALEN);
    forward_ethhdr->h_proto = htons(ETH_P_IP);

    forward_iphdr = (char *)forward_ethhdr + sizeof(*forward_ethhdr);
    /* There are no additional options */
    memcpy(forward_iphdr, org_iphdr, sizeof(*forward_iphdr));
    forward_iphdr->ihl = sizeof(*forward_iphdr) / 4;
    forward_iphdr->tot_len = htons(sizeof(*forward_iphdr) + sizeof(*forward_tcphdr));
    forward_iphdr->check = ip_fast_csum(forward_iphdr, forward_iphdr->ihl);

    forward_tcphdr = (char *)forward_iphdr + sizeof(*forward_iphdr);
    memcpy(forward_tcphdr, org_tcphdr, sizeof(*forward_tcphdr));
    forward_tcphdr->th_seq = org_tcphdr->th_seq + org_tcpdata_len;
    forward_tcphdr->th_off = sizeof(*forward_tcphdr);
    forward_tcphdr->th_flags = 0;
    forward_tcphdr->rst = true;
    forward_tcphdr->syn = false;
    forward_tcphdr->ack = true;
    forward_tcphdr->th_sum = csum_tcpudp_magic(forward_iphdr->saddr, forward_iphdr->daddr, 0, IPPROTO_TCP, 0);

    return forward_pkt;
}

char *gen_backward_pkt(struct ethhdr *org_ethhdr, struct iphdr *org_iphdr, struct tcphdr *org_tcphdr)
{
    struct ethhdr *backward_ethhdr;
    struct iphdr *backward_iphdr;
    struct tcphdr *backward_tcphdr;
    char *backward_pkt;
    size_t org_tcpdata_len;

    org_tcpdata_len = ntohs(org_iphdr->tot_len) - (org_iphdr->ihl + org_tcphdr->th_off) * 4;
    
    backward_pkt = malloc(sizeof(*backward_ethhdr) + sizeof(*backward_iphdr) + 
                            sizeof(*backward_tcphdr) + sizeof(FINMSG));
    if (backward_pkt == NULL)
        return NULL;

    backward_ethhdr = backward_pkt;
    memcpy(backward_ethhdr->h_dest, org_ethhdr->h_source, ETH_ALEN);
    memcpy(backward_ethhdr->h_source, &my_mac_addr, ETH_ALEN);
    backward_ethhdr->h_proto = htons(ETH_P_IP);

    backward_iphdr = (char *)backward_ethhdr + sizeof(*backward_ethhdr);
    /* There are no additional options */
    memcpy(backward_iphdr, org_iphdr, sizeof(*backward_iphdr));
    backward_iphdr->ihl = sizeof(*backward_iphdr) / 4;
    backward_iphdr->tot_len = htons(sizeof(*backward_iphdr) + sizeof(backward_tcphdr) + sizeof(FINMSG) - 1);
    backward_iphdr->ttl = 128;
    backward_iphdr->saddr = org_iphdr->daddr;
    backward_iphdr->daddr = org_iphdr->saddr;
    backward_iphdr->check = ip_fast_csum(backward_iphdr, backward_iphdr->ihl);

    backward_tcphdr = (char *)backward_iphdr + sizeof(*backward_iphdr);
    memcpy(backward_tcphdr, org_tcphdr, sizeof(*backward_tcphdr));
    backward_tcphdr->th_seq = org_tcphdr->th_ack;
    backward_tcphdr->th_ack = org_tcphdr->th_seq;
    backward_tcphdr->th_off = sizeof(*backward_tcphdr);
    backward_tcphdr->th_flags = 0;
    backward_tcphdr->fin = true;
    backward_tcphdr->syn = false;
    backward_tcphdr->ack = true;
    backward_tcphdr->th_sum = csum_tcpudp_magic(backward_iphdr->saddr, backward_iphdr->daddr, sizeof(FINMSG) - 1, IPPROTO_TCP, 0);

    memcpy(backward_tcphdr + 1, FINMSG, sizeof(FINMSG) - 1);

    return backward_pkt;
}

int send_blocking_pkt(char *org_pkt)
{
    struct ethhdr *org_ethhdr;
    struct iphdr *org_iphdr;
    struct tcphdr *org_tcphdr;
    char *forward_pkt;
    char *backward_pkt;
    int ret;

    org_ethhdr = org_pkt;
    org_iphdr = (char *)org_ethhdr + ETH_HLEN;
    org_tcphdr = (char *)org_iphdr + org_iphdr->ihl * 4;
    
    forward_pkt = gen_forward_pkt(org_ethhdr, org_iphdr, org_tcphdr);
    if (forward_pkt == NULL)
        goto out_error;

    backward_pkt = gen_backward_pkt(org_ethhdr, org_iphdr, org_tcphdr);
    if (backward_pkt == NULL) 
        goto out_error;
    
    pr_info("((struct iphdr *)((char *)pkt + ETH_HLEN))->tot_len: %x\n", ((struct iphdr *)((char *)forward_pkt + ETH_HLEN))->tot_len);
    pr_info("pkt_len(forward_pkt): %x\n", pkt_len(forward_pkt));
    ret = pcap_sendpacket(handle, forward_pkt, pkt_len(forward_pkt));
    if (ret < 0) 
        goto out_error;

    pr_info("pkt_len(backward_pkt): %x\n", pkt_len(backward_pkt));
    ret = pcap_sendpacket(handle, backward_pkt, pkt_len(backward_pkt));
    if (ret < 0) 
        goto out_error;

    free(forward_pkt);
    free(backward_pkt);      

    return 0;

out_error:
    if (forward_pkt)
        free(forward_pkt);
    if (backward_pkt)
        free(backward_pkt);
    return -1;
}

void *callback(char *useless, const struct pcap_pkthdr *pkthdr, 
                char *packet)
{
    char *http_data;
    size_t http_data_len;
    char *host;
    int ret;

    http_data = NULL;
    ret = find_http_data(packet, &http_data, &http_data_len);
    if (ret < 0) 
        goto pass;

    if (find_pattern(http_data, http_data_len) == NULL) 
        goto pass;

    pr_info("pattern detected!\n");
   
    ret = send_blocking_pkt(packet);
    if (ret < 0) {
        pr_err("Error while sending blocking packets\n");
        free(http_data);
        return NULL;
    }

pass:
    if (http_data)
        free(http_data);
    return NULL;
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

    return 0;
}

int main(int argc, char *argv[])
{
    char *interface;
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
        return -1;
    }

    return 0;
}