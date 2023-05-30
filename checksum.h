/* see https://github.com/torvalds/linux/blob/master/arch/x86/um/asm/checksum.h */
#include <linux/string.h>
#include <linux/types.h>

#define __force __attribute__((force))

static inline __sum16 csum_fold(__wsum sum)
{
	__asm__(
		"  addl %1,%0\n"
		"  adcl $0xffff,%0"
		: "=r" (sum)
		: "r" ((__force __u32)sum << 16),
		  "0" ((__force __u32)sum & 0xffff0000)
	);
	return (__force __sum16)(~(__force __u32)sum >> 16);
}

/**
 * csum_tcpup_nofold - Compute an IPv4 pseudo header checksum.
 * @saddr: source address
 * @daddr: destination address
 * @len: length of packet
 * @proto: ip protocol of packet
 * @sum: initial sum to be added in (32bit unfolded)
 *
 * Returns the pseudo header checksum the input data. Result is
 * 32bit unfolded.
 */
static inline __wsum
csum_tcpudp_nofold(__be32 saddr, __be32 daddr, __u32 len,
		  __u8 proto, __wsum sum)
{
	asm("  addl %1, %0\n"
	    "  adcl %2, %0\n"
	    "  adcl %3, %0\n"
	    "  adcl $0, %0\n"
		: "=r" (sum)
	    : "g" (daddr), "g" (saddr), "g" ((len + proto) << 8), "0" (sum));
	return sum;
}

/*
 * computes the checksum of the TCP/UDP pseudo-header
 * returns a 16-bit checksum, already complemented
 */
static inline __sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr,
					__u32 len, __u8 proto,
					__wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr,daddr,len,proto,sum));
}

/**
 * ip_fast_csum - Compute the IPv4 header checksum efficiently.
 * iph: ipv4 header
 * ihl: length of header / 4
 */
static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	unsigned int sum;

	asm(	"  movl (%1), %0\n"
		"  subl $4, %2\n"
		"  jbe 2f\n"
		"  addl 4(%1), %0\n"
		"  adcl 8(%1), %0\n"
		"  adcl 12(%1), %0\n"
		"1: adcl 16(%1), %0\n"
		"  lea 4(%1), %1\n"
		"  decl %2\n"
		"  jne	1b\n"
		"  adcl $0, %0\n"
		"  movl %0, %2\n"
		"  shrl $16, %0\n"
		"  addw %w2, %w0\n"
		"  adcl $0, %0\n"
		"  notl %0\n"
		"2:"
	/* Since the input registers which are loaded with iph and ipl
	   are modified, we must also specify them as outputs, or gcc
	   will assume they contain their original values. */
	: "=r" (sum), "=r" (iph), "=r" (ihl)
	: "1" (iph), "2" (ihl)
	: "memory");
	return (__force __sum16)sum;
}