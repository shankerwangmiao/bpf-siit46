#define _DEFAULT_SOURCE
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <errno.h>



// helper macros for branch prediction
#define LIKELY(x)   __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)

/* Helper macro to print out debug messages */
#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
# define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

/*struct bpf_elf_map acc_map __section("maps") = {
        .type           = BPF_MAP_TYPE_ARRAY,
        .size_key       = sizeof(uint32_t),
        .size_value     = sizeof(uint32_t),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 2,
};*/

const int MAP_MAX_LEN = 1024;

struct ipv4_lpm_key {
    __u32 prefixlen;
    struct in_addr addr;		
};

struct ipv4_nat_table_value {
	__u8 ip4_prefixlen;
	__u8 ip6_prefixlen;
	__u16 unused;
	struct in6_addr addr;
};

SEC("maps")
struct bpf_elf_map src_4to6_map = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.size_key = sizeof(struct ipv4_lpm_key),
	.size_value = sizeof(struct ipv4_nat_table_value),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = MAP_MAX_LEN,
	.flags = BPF_F_NO_PREALLOC,
};

SEC("maps")
struct bpf_elf_map dst_4to6_map = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.size_key = sizeof(struct ipv4_lpm_key),
	.size_value = sizeof(struct ipv4_nat_table_value),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = MAP_MAX_LEN,
	.flags = BPF_F_NO_PREALLOC,
};


static __always_inline long bpf_xdp_is_data_sz_gt(const struct xdp_md *pbf, size_t size){
	return (unsigned long)pbf->data + size <= (unsigned long)pbf->data_end;
}

static __always_inline long bpf_xdp_ensure_bytes(struct xdp_md *pbf, size_t size){
	if(LIKELY(bpf_xdp_is_data_sz_gt(pbf, size))){
		return 0;
	}
	return -EINVAL;
}


static __always_inline long addr_translate_4to6 (const struct in_addr *addr4, struct in6_addr *addr6, struct bpf_elf_map *map){
	struct ipv4_lpm_key key = {
		.prefixlen = 32,
		.addr = *addr4,
	};
	const struct ipv4_nat_table_value *value = bpf_map_lookup_elem(map, &key);
	if(UNLIKELY(!value)){
		return -ENOENT;
	}
	if(UNLIKELY(value->ip6_prefixlen > 128  || value->ip4_prefixlen > 32 || value->ip6_prefixlen + 32 - value->ip4_prefixlen > 128)){
		return -EINVAL;
	}
	*addr6 = value->addr;
	uint32_t masked_addr4 = bpf_ntohl(addr4->s_addr);
	masked_addr4 &= (1ull << (32 - value->ip4_prefixlen)) - 1;
	masked_addr4 <<= value->ip4_prefixlen;
	if(value->ip6_prefixlen < 128){
		int which_dword = value->ip6_prefixlen / 32;
		uint32_t this_addr32 = 0;
		switch (which_dword)
		{
			case 3:
				this_addr32 = bpf_ntohl(addr6->s6_addr32[3]);
				break;
			case 2:
				this_addr32 = bpf_ntohl(addr6->s6_addr32[2]);
				break;
			case 1:
				this_addr32 = bpf_ntohl(addr6->s6_addr32[1]);
				break;
			case 0:
				this_addr32 = bpf_ntohl(addr6->s6_addr32[0]);
				break;
		}
		this_addr32 &= ~((1ull << (32 - value->ip6_prefixlen % 32)) - 1);
		this_addr32 |= masked_addr4 >> (value->ip6_prefixlen % 32);
		masked_addr4 <<= 32 - value->ip6_prefixlen % 32;
		switch(which_dword){
			case 3:
				addr6->s6_addr32[3] = bpf_htonl(this_addr32);
				break;
			case 2:
				addr6->s6_addr32[2] = bpf_htonl(this_addr32);
				addr6->s6_addr32[3] = bpf_htonl(masked_addr4);
				break;
			case 1:
				addr6->s6_addr32[1] = bpf_htonl(this_addr32);
				addr6->s6_addr32[2] = bpf_htonl(masked_addr4);
				addr6->s6_addr32[3] = 0;
				break;
			case 0:
				addr6->s6_addr32[0] = bpf_htonl(this_addr32);
				addr6->s6_addr32[1] = bpf_htonl(masked_addr4);
				addr6->s6_addr32[2] = 0;
				addr6->s6_addr32[3] = 0;
				break;
		}
	}
	uint64_t checksum = 0;
	checksum += 0xffffffff ^ addr4->s_addr;
	#pragma unroll
	for(int i = 0; i < 4; i++){
		checksum += addr6->s6_addr32[i];
	}
	return checksum;
}

static __always_inline long icmp_send(struct xdp_md *pbf, __u8 type, __u8 code, __u32 info){
	return -ENOSYS;
}

static __always_inline int bpf_xdp_ensure_ipv4_header(struct xdp_md *pbf, size_t offset){
	int rc;
	if(UNLIKELY((rc = bpf_xdp_ensure_bytes(pbf, offset + sizeof(struct iphdr))) < 0)){
		return rc;
	}
	const struct iphdr *iph = (struct iphdr *)(pbf->data + offset);
	if(UNLIKELY(iph->version != 4)){
		return -EINVAL;
	}
	if(UNLIKELY(iph->ihl < sizeof(struct iphdr) / 4)){
		return -EINVAL;
	}
	int length = iph->ihl * 4;
	if(UNLIKELY(bpf_ntohs(iph->tot_len) < length)){
		return -EINVAL;
	}
	switch (iph->protocol){
	case IPPROTO_TCP:
		length += sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		length += sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
		length += sizeof(struct icmphdr);
		break;
	default:
		break;
	}
	if(UNLIKELY(bpf_ntohs(iph->tot_len) < length)){
		return -EINVAL;
	}
	rc = bpf_xdp_ensure_bytes(pbf, offset + length);
	if(UNLIKELY(rc < 0)){
		return rc;
	}
	return length;
}

#define bpf_xdp_valid_ptr(pbf, ptr) \
	({if(UNLIKELY((void *)((ptr) + 1) > (void *)(unsigned long)((pbf)->data_end))){ \
		return -EINVAL; \
	}})
#define bpf_xdp_valid_ptr_len(pbf, ptr, len) \
	({if(UNLIKELY(((void *)(ptr) + (unsigned long)(len)) > (void *)(unsigned long)((pbf)->data_end))){ \
		return -EINVAL; \
	}})

static __always_inline long bpf_xdp_adjust_head_at(struct xdp_md *pbf, ssize_t len_diff, size_t offset){
	if(len_diff > 0){
		long rc = bpf_xdp_adjust_head(pbf, -len_diff);
		if(UNLIKELY(rc < 0)){
			return rc;
		}
		void *dst = (void *)(unsigned long)pbf->data;
		bpf_xdp_valid_ptr_len(pbf, dst, offset);
		void *src = (void *)(unsigned long)(pbf->data + len_diff);
		bpf_xdp_valid_ptr_len(pbf, src, offset);
		memmove(dst, src, offset);
	}else if(len_diff < 0){
		void *dst = (void *)(unsigned long)(pbf->data - len_diff);
		bpf_xdp_valid_ptr_len(pbf, dst, offset);
		void *src = (void *)(unsigned long)(pbf->data);
		bpf_xdp_valid_ptr_len(pbf, src, offset);
		memmove(dst, src, offset);
		long rc = bpf_xdp_adjust_head(pbf, -len_diff);
		if(UNLIKELY(rc < 0)){
			return rc;
		}
	}
	return 0;
}

static __always_inline long ipv4_to_6(struct xdp_md *pbf, size_t offset){
	long rc;
	if(UNLIKELY((rc = bpf_xdp_ensure_ipv4_header(pbf, offset)) < 0)){
		return rc;
	}
	//size_t total_hdr_len = rc;

	struct iphdr _iph = *(struct iphdr *)(pbf->data + offset);
	struct iphdr *iph = &_iph;

	if(iph->ttl <= 1){
		return icmp_send(pbf, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
	}
	
	//int is_icmp = iph.protocol == IPPROTO_ICMP;
	int is_frag = bpf_ntohs(iph->frag_off) & IP_MF || bpf_ntohs(iph->frag_off) & IP_OFFMASK;

	struct in6_addr src, dst;

	uint64_t checksum_diff = 0;
	rc = addr_translate_4to6((const struct in_addr *)&iph->saddr, &src, &src_4to6_map);
	if(rc < 0){
		return rc;
	}
	checksum_diff += rc;
	rc = addr_translate_4to6((const struct in_addr *)&iph->daddr, &dst, &dst_4to6_map);
	if(rc < 0){
		return rc;
	}
	checksum_diff += rc;
	ssize_t len_diff = sizeof(struct ip6_hdr) - iph->ihl * 4;
	if(is_frag){
		len_diff += sizeof(struct ip6_frag);
	}
	if(len_diff){
		rc = bpf_xdp_adjust_head_at(pbf, len_diff, offset);
		if(UNLIKELY(rc < 0)){
			return rc;
		}
	}
	struct ip6_hdr *ip6h = (struct ip6_hdr *)(pbf->data + offset);
	void *transp_hdr = (void *)(ip6h + 1);
	bpf_xdp_valid_ptr(pbf, ip6h);

	ip6h->ip6_flow = bpf_htonl(6 << 28 | iph->tos << 20);
	ip6h->ip6_plen = bpf_htons(bpf_ntohs(iph->tot_len) - iph->ihl * 4 + (is_frag ? sizeof(struct ip6_frag) : 0));
	ip6h->ip6_nxt  = iph->protocol;
	ip6h->ip6_hlim = iph->ttl - 1;
	ip6h->ip6_src  = src;
	ip6h->ip6_dst  = dst;
	if(is_frag){
		struct ip6_frag *ip6f = (struct ip6_frag *)(ip6h + 1);
		transp_hdr = (void *)(ip6f + 1);
		bpf_xdp_valid_ptr(pbf, ip6f);
		ip6f->ip6f_nxt = ip6h->ip6_nxt;
		ip6h->ip6_nxt = IPPROTO_FRAGMENT;
		ip6f->ip6f_reserved = 0;
		ip6f->ip6f_offlg = bpf_htons((bpf_ntohs(iph->frag_off) & IP_OFFMASK) << 3 ) | (bpf_ntohs(iph->frag_off) & IP_MF ? IP6F_MORE_FRAG : 0);
		ip6f->ip6f_ident = bpf_htonl(bpf_ntohs(iph->id));
	}
	
	if(iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP){
		uint16_t *checksum_ptr = NULL;
		if(iph->protocol == IPPROTO_TCP){
			struct tcphdr *tcph = (struct tcphdr *)transp_hdr;
			checksum_ptr = &tcph->check;
		}else if(iph->protocol == IPPROTO_UDP){
			struct udphdr *udph = (struct udphdr *)transp_hdr;
			checksum_ptr = &udph->check;
		}
		bpf_xdp_valid_ptr(pbf, checksum_ptr);
		checksum_diff += (0xffff ^ *checksum_ptr);
		checksum_diff = (checksum_diff & 0xffffffff) + ((checksum_diff >> 32) & 0xffffffff);
		checksum_diff = (checksum_diff & 0xffff) + ((checksum_diff >> 16) & 0xffff);
		checksum_diff = (checksum_diff & 0xffff) + ((checksum_diff >> 16) & 0xffff);
		checksum_diff &= 0xffff;
		if(checksum_diff == 0xffff) checksum_diff = 0;
		*checksum_ptr = 0xffff ^ checksum_diff;
	}
	
	return 0;
}

static __always_inline long eth_ipv4_to_6(struct xdp_md *pbf){
	struct ethhdr *ethh = (struct ethhdr *)(unsigned long)pbf->data;
	bpf_xdp_valid_ptr(pbf, ethh);
	if(ethh->h_proto == bpf_htons(ETH_P_IP)){
		long rc = ipv4_to_6(pbf, sizeof(struct ethhdr));
		if(UNLIKELY(rc < 0)){
			return rc;
		}
		ethh = (struct ethhdr *)(unsigned long)pbf->data;
		bpf_xdp_valid_ptr(pbf, ethh);
		ethh->h_proto = bpf_htons(ETH_P_IPV6);
		return 0;
	}
	return -EINVAL;
}

/*static __always_inline int icmpv6_reply(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
   	void *data_end = (void *)(long)skb->data_end;

	struct ipv6hdr *ip6h = data;
	if (data + sizeof(*ip6h) > data_end){
        	return BPF_DROP;
	}
	if (ip6h->version != 6){
		return BPF_DROP;
	}
	if (ip6h->nexthdr != IPPROTO_ICMPV6){
		return BPF_DROP;
	}

	struct icmp6hdr *icmpv6h = data + sizeof(*ip6h);
	if ((void *)icmpv6h + sizeof(*icmpv6h) > data_end){
		return BPF_DROP;
	}
	if(icmpv6h->icmp6_type != ICMPV6_ECHO_REQUEST){
		return BPF_DROP;
	}
	icmpv6h->icmp6_type = ICMPV6_ECHO_REPLY;
	struct	in6_addr tmp_addr;
	tmp_addr = ip6h->saddr;
	ip6h->saddr = ip6h->daddr;
	ip6h->daddr = tmp_addr;

	bpf_l4_csum_replace(skb, sizeof(*ip6h) + offsetof(struct icmp6hdr, icmp6_cksum), ICMPV6_ECHO_REQUEST, ICMPV6_ECHO_REPLY, sizeof(icmpv6h->icmp6_cksum) | BPF_F_PSEUDO_HDR);

	return BPF_LWT_REROUTE;


        return BPF_DROP;
}*/

/*static __always_inline int dnat(struct __sk_buff *skb){
	void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;

        struct ipv6hdr *ip6h = data;
	if (data + sizeof(*ip6h) > data_end){
                return BPF_DROP;
        }
        if (ip6h->version != 6){
                return BPF_DROP;
        }
        if (ip6h->nexthdr != IPPROTO_ICMPV6){
                return BPF_DROP;
        }
	struct icmp6hdr *icmpv6h = data + sizeof(*ip6h);
        if ((void *)icmpv6h + sizeof(*icmpv6h) > data_end){
                return BPF_DROP;
        }
        if(icmpv6h->icmp6_type != ICMPV6_ECHO_REQUEST){
                return BPF_DROP;
        }
	struct  in6_addr addrs[4];
	addrs[0] = addrs[2] = ip6h->daddr;
	addrs[1] = addrs[3] = ip6h->saddr;
	addrs[2].s6_addr[15] += 1;
	addrs[3].s6_addr[15] += 1;

	ip6h->daddr = addrs[2];
	ip6h->saddr = addrs[3];

	bpf_l4_csum_replace(skb, sizeof(*ip6h) + offsetof(struct icmp6hdr, icmp6_cksum), *(uint16_t *) &addrs[0].s6_addr[14], *(uint16_t *) &addrs[2].s6_addr[14], sizeof(icmpv6h->icmp6_cksum) | BPF_F_PSEUDO_HDR);
	bpf_l4_csum_replace(skb, sizeof(*ip6h) + offsetof(struct icmp6hdr, icmp6_cksum), *(uint16_t *) &addrs[1].s6_addr[14], *(uint16_t *) &addrs[3].s6_addr[14], sizeof(icmpv6h->icmp6_cksum) | BPF_F_PSEUDO_HDR);
	return BPF_LWT_REROUTE;
}*/


/*struct tun_info{
	int handled;
};*/

SEC("xdp:4to6")
long xslat46(struct xdp_md *pbf)
{
	long rc = eth_ipv4_to_6(pbf);
	if(rc < 0){
		return XDP_DROP;
	}else{
		return XDP_PASS;
	}
}

char __license[] SEC("license") = "GPL";
