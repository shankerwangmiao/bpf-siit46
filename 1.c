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

SEC("maps")
struct bpf_elf_map icmp_err_src_addr = {
	.type = BPF_MAP_TYPE_ARRAY,
	.size_key = sizeof(uint32_t),
	.size_value = sizeof(struct in_addr),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 1,
};

static __always_inline int bpf_skb_is_data_sz_gt(const struct __sk_buff *skb, size_t size){
	return (unsigned long)skb->data + size <= (unsigned long)skb->data_end;
}

static __always_inline int bpf_skb_ensure_bytes(struct __sk_buff *skb, size_t size){
	if(UNLIKELY(skb->len < size)){
		return -EINVAL;
	}
	if(LIKELY(bpf_skb_is_data_sz_gt(skb, size))){
		return 0;
	}
	int rc;
	if(UNLIKELY((rc = bpf_skb_pull_data(skb, size)) < 0)){
		return rc;
	}
	if(LIKELY(bpf_skb_is_data_sz_gt(skb, size))){
		return 0;
	}
	return -EINVAL;
}


static __always_inline int addr_translate_4to6 (const struct in_addr *addr4, struct in6_addr *addr6, struct bpf_elf_map *map){
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
		addr6->s6_addr32[which_dword] = bpf_ntohl(addr6->s6_addr32[which_dword]);
		addr6->s6_addr32[which_dword] &= ~((1ull << (32 - value->ip6_prefixlen % 32)) - 1);
		addr6->s6_addr32[which_dword] |= masked_addr4 >> (value->ip6_prefixlen % 32);
		addr6->s6_addr32[which_dword] = bpf_htonl(addr6->s6_addr32[which_dword]);
		masked_addr4 <<= 32 - value->ip6_prefixlen % 32;
		switch(which_dword){
			case 3:
				break;
			case 2:
				addr6->s6_addr32[3] = bpf_htonl(masked_addr4);
				break;
			case 1:
				addr6->s6_addr32[2] = bpf_htonl(masked_addr4);
				addr6->s6_addr32[3] = 0;
				break;
			case 0:
				addr6->s6_addr32[1] = bpf_htonl(masked_addr4);
				addr6->s6_addr32[2] = 0;
				addr6->s6_addr32[3] = 0;
				break;
		}/*
		if(which_dword < 4){
			addr6->s6_addr32[which_dword] = bpf_htonl(masked_addr4 << (32 - value->ip6_prefixlen % 32));
			which_dword += 1;
			if(which_dword < 4){
				addr6->s6_addr32[which_dword] = 0;
			}
			which_dword += 1;
			if(which_dword < 4){
				addr6->s6_addr32[which_dword] = 0;
			}
		}*/
		/*memcpy(
			&addr6->s6_addr[left_offset], 
			&masked_addr4, 
			left_offset + 4 > 16 ? 16 - left_offset : 4
		);
		if(16 - (left_offset + 4) > 0){
			memset(&addr6->s6_addr[left_offset + 4], 0, 16 - (left_offset + 4));
		}*/
		
		/*
		#pragma unroll
		for(int i = value->ip6_prefixlen / 8 + 1; i < 16; i++){
			addr6->s6_addr[i] = (masked_addr4 & 0xff000000ull) >> 24;
			masked_addr4 <<= 8;
		}*/		
	}
	return 0;
}

static __always_inline int icmp_send(struct __sk_buff *skb, __u8 type, __u8 code, __u32 info){
	return -ENOSYS;
}

static __always_inline int bpf_skb_ensure_ipv4_header(struct __sk_buff *skb, size_t offset){
	int rc;
	if(UNLIKELY((rc = bpf_skb_ensure_bytes(skb, offset + sizeof(struct iphdr))) < 0)){
		return rc;
	}
	const struct iphdr *iph = (struct iphdr *)(skb->data + offset);
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
	rc = bpf_skb_ensure_bytes(skb, offset + length);
	if(UNLIKELY(rc < 0)){
		return rc;
	}
	return length;
}

#define bpf_skb_valid_ptr(skb, ptr) \
	({if(UNLIKELY((void *)((ptr) + 1) > (void *)(unsigned long)((skb)->data_end))){ \
		return -EINVAL; \
	}})

static __always_inline int ipv4_to_6(struct __sk_buff *skb, size_t offset){
	int rc;
	if(UNLIKELY((rc = bpf_skb_ensure_ipv4_header(skb, offset)) < 0)){
		return rc;
	}
	int total_hdr_len = rc;

	unsigned char buf[sizeof(struct ip6_hdr) + sizeof(struct ip6_frag) + 8] = {0};
	struct ip6_hdr *ip6h = (struct ip6_hdr *)buf;
	struct iphdr *iph = (struct iphdr *)(skb->data + offset);
	bpf_skb_valid_ptr(skb, iph);
	if(iph->ttl <= 1){
		return icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
	}
	
	//int is_icmp = iph.protocol == IPPROTO_ICMP;
	int is_frag = bpf_ntohs(iph->frag_off) & IP_MF || bpf_ntohs(iph->frag_off) & IP_OFFMASK;

	int additional_size_fake_opt = iph->ihl * 4 % 8 == 0 ? 0 : 8 - iph->ihl * 4 % 8;

	rc = addr_translate_4to6((const struct in_addr *)&iph->saddr, &ip6h->ip6_src, &src_4to6_map);
	if(rc != 0){
		return rc;
	}
	rc = addr_translate_4to6((const struct in_addr *)&iph->daddr, &ip6h->ip6_dst, &dst_4to6_map);
	if(rc != 0){
		return rc;
	}

	ip6h->ip6_flow = bpf_htonl(6 << 28 | iph->tos << 20);
	ip6h->ip6_plen = bpf_htons(bpf_ntohs(iph->tot_len) /*- iph->ihl * 4*/ + (is_frag ? sizeof(struct ip6_frag) : 0) + additional_size_fake_opt);
	ip6h->ip6_nxt  = iph->protocol;
	ip6h->ip6_hlim = iph->ttl;
	if(is_frag){
		struct ip6_frag *ip6f = (struct ip6_frag *)(ip6h + 1);
		ip6f->ip6f_nxt = ip6h->ip6_nxt;
		ip6h->ip6_nxt = IPPROTO_FRAGMENT;
		ip6f->ip6f_reserved = 0;
		ip6f->ip6f_offlg = bpf_htons((bpf_ntohs(iph->frag_off) & IP_OFFMASK) << 3 ) | (bpf_ntohs(iph->frag_off) & IP_MF ? IP6F_MORE_FRAG : 0);
		ip6f->ip6f_ident = bpf_htonl(bpf_ntohs(iph->id));
	}
/*
	rc = bpf_skb_change_proto(skb, ETH_P_IPV6, 0);
	if(UNLIKELY(rc < 0)){
		return rc;
	}

	//We need to add len_diff bytes
	ssize_t len_diff = sizeof(struct ip6_hdr) - iph->ihl * 4;
	if(is_frag){
		len_diff += sizeof(struct ip6_frag);
	}
	total_hdr_len += len_diff;
	//bpf_skb_change_proto has already added 20 bytes
	len_diff -= sizeof(struct ip6_hdr) - sizeof(struct iphdr);
	if(len_diff){
		rc = bpf_skb_adjust_room(skb, len_diff, BPF_ADJ_ROOM_MAC, 0);
		if(UNLIKELY(rc < 0)){
			return rc;
		}
	}
*/
	//total_hdr_len -= iph->ihl * 4;
	total_hdr_len += additional_size_fake_opt;

	struct ip6_ext *fake_ipv6_opt = (struct ip6_ext *)(ip6h + 1);
	if(is_frag){
		struct ip6_frag *ip6f = (struct ip6_frag *)(ip6h + 1);
		ip6f->ip6f_nxt = IPPROTO_DSTOPTS;
		fake_ipv6_opt = (struct ip6_ext *)(ip6f + 1);
	}else{
		ip6h->ip6_nxt = IPPROTO_DSTOPTS;
	}
	fake_ipv6_opt->ip6e_nxt = iph->protocol;
	fake_ipv6_opt->ip6e_len = ((int)iph->ihl * 4 + 7)/ 8 - 1;
	fake_ipv6_opt[1].ip6e_nxt = IP6OPT_PADN;
	fake_ipv6_opt[1].ip6e_len = iph->ihl * 4 + additional_size_fake_opt - 4;

	if(UNLIKELY(additional_size_fake_opt < 4)){
		switch (additional_size_fake_opt)
		{
			case 0:
				memcpy(iph, fake_ipv6_opt, 4);
				break;
			case 1:
				memcpy(iph, (unsigned char *)fake_ipv6_opt + 1, 3);
				break;
			case 2:
				memcpy(iph, (unsigned char *)fake_ipv6_opt + 2, 2);
				break;
			case 3:
				memcpy(iph, (unsigned char *)fake_ipv6_opt + 3, 1);
				break;
		}
	}
	/*rc = bpf_skb_adjust_room(skb, iph->ihl * 4, BPF_ADJ_ROOM_MAC, 0);
	if(UNLIKELY(rc < 0)){
		return rc;
	}*/
	size_t len_should_push = sizeof(struct ip6_hdr) + additional_size_fake_opt;
	if(is_frag){
		len_should_push += sizeof(struct ip6_frag);
	}
	total_hdr_len += len_should_push;
	rc = bpf_lwt_push_encap(skb, BPF_LWT_ENCAP_IP, buf, len_should_push);
	skb->cb[0] = skb->cb[1] = skb->cb[2] = skb->cb[3] = skb->cb[4] = 0;
	if(UNLIKELY(rc < 0)){
		return rc;
	}
	rc = bpf_skb_ensure_bytes(skb, offset + total_hdr_len);
	if(UNLIKELY(rc < 0)){
		return rc;
	}
	return 0;
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

SEC("xmit")
long lwt_xmit(struct __sk_buff *skb)
{
	long rc = ipv4_to_6(skb, 0);
	if(rc < 0){
		return rc;
	}else{
		return BPF_LWT_REROUTE;
	}
}

char __license[] SEC("license") = "GPL";
