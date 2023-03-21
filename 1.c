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
#include <linux/ipv6.h>



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


static __always_inline long addr_translate_4to6 (const struct in_addr *addr4, struct in6_addr *addr6, const struct ipv4_nat_table_value *value){
	*addr6 = value->addr;
	uint32_t masked_addr4 = bpf_ntohl(addr4->s_addr);
	masked_addr4 &= (1ull << (32 - value->ip4_prefixlen)) - 1;
	masked_addr4 <<= value->ip4_prefixlen;
	if(value->ip6_prefixlen < 128){
		int which_dword = value->ip6_prefixlen / 32;
		uint32_t this_addr32 = 0;
		/* looks silly because the verifier cannot sometimes determine addr6->s6addr[which_dword] is within the memory range */
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

static __always_inline long is_ip_following_fragment(const struct iphdr *iph){
	return !!(bpf_ntohs(iph->frag_off) & IP_OFFMASK);
}

static __always_inline long is_ip_fragment(const struct iphdr *iph){
	return bpf_ntohs(iph->frag_off) & IP_MF || bpf_ntohs(iph->frag_off) & IP_OFFMASK;
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
	if(LIKELY(!is_ip_following_fragment(iph))){
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

static __always_inline ssize_t calc_extra_space_ip4_hdr(const struct iphdr *iph){
	int is_frag = is_ip_fragment(iph);
	ssize_t len_diff = sizeof(struct ip6_hdr) - iph->ihl * 4;
	if(is_frag){
		len_diff += sizeof(struct ip6_frag);
	}
	return len_diff;
}

static __always_inline const struct ipv4_nat_table_value *ipv4_siit_table_lookup(const struct in_addr *addr4, struct bpf_elf_map *map){
	struct ipv4_lpm_key key = {
		.prefixlen = 32,
		.addr = *addr4,
	};
	const struct ipv4_nat_table_value *value = bpf_map_lookup_elem(map, &key);
	if(UNLIKELY(!value)){
		return NULL;
	}
	return value;
}

static __always_inline long is_ipv4_siit_table_entry_valid(const struct ipv4_nat_table_value *value){
	return value->ip6_prefixlen <= 128  && value->ip4_prefixlen <= 32 && value->ip6_prefixlen + 32 - value->ip4_prefixlen <= 128;
}

static __always_inline uint64_t checksum_fold(uint64_t cksum){
	cksum = (cksum & 0xffffffff) + ((cksum >> 32) & 0xffffffff);
	cksum = (cksum & 0xffffffff) + ((cksum >> 32) & 0xffffffff);
	cksum = (cksum & 0xffff) + ((cksum >> 16) & 0xffff);
	cksum = (cksum & 0xffff) + ((cksum >> 16) & 0xffff);
	cksum &= 0xffff;
	return cksum;
}

static __always_inline long checksum_fill_delta(struct xdp_md *pbf, void *transp_hdr, uint8_t proto, uint64_t checksum_diff){
	uint64_t delta_checksum = 0;
	if(proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_ICMPV6){
		uint16_t *checksum_ptr = NULL;
		if(proto == IPPROTO_TCP){
			struct tcphdr *tcph = (struct tcphdr *)transp_hdr;
			checksum_ptr = &tcph->check;
		}else if(proto == IPPROTO_UDP){
			struct udphdr *udph = (struct udphdr *)transp_hdr;
			checksum_ptr = &udph->check;
		}else if(proto == IPPROTO_ICMPV6){
			struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)transp_hdr;
			checksum_ptr = &icmp6h->icmp6_cksum;
		}
		bpf_xdp_valid_ptr(pbf, checksum_ptr);
		delta_checksum += 0xffff ^ *checksum_ptr;
		checksum_diff += (0xffff ^ *checksum_ptr);
		checksum_diff = checksum_fold(checksum_diff);
		if(checksum_diff == 0xffff && proto == IPPROTO_UDP) checksum_diff = 0;
		*checksum_ptr = 0xffff ^ checksum_diff;
		delta_checksum += *checksum_ptr;
	}
	return delta_checksum;
}

enum {
	ICMP4_XLAT_DROP = 0,
	ICMP4_XLAT_OK = 1,
	ICMP4_XLAT_PAYLOAD = 2
};

static __always_inline long icmp4_should_trans(struct xdp_md *pbf, const struct icmphdr *icmph){
	bpf_xdp_valid_ptr(pbf, icmph);
	if(icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY){
		return ICMP4_XLAT_OK;
	}else if(icmph->type == ICMP_DEST_UNREACH){
		if(
			(icmph->code >= 0 && icmph->code <= 13 && icmph->code != ICMP_UNREACH_SRCFAIL) ||
			icmph->code == ICMP_UNREACH_PRECEDENCE_CUTOFF
		){
			goto xlat_payload;
		}else{
			return ICMP4_XLAT_DROP;
		}
	}else if(icmph->type == ICMP_TIME_EXCEEDED){
		goto xlat_payload;
	}else if(icmph->type == ICMP_PARAMETERPROB){
		if(icmph->code == 0 || icmph->code == 2){
			if(
				(((struct icmp *)icmph)->icmp_pptr >= 0 && ((struct icmp *)icmph)->icmp_pptr <= 3 ) ||
				(((struct icmp *)icmph)->icmp_pptr >= 8 && ((struct icmp *)icmph)->icmp_pptr <= 9 ) ||
				(((struct icmp *)icmph)->icmp_pptr >= 12 && ((struct icmp *)icmph)->icmp_pptr <= 19 )
			){
				goto xlat_payload;
			}else{
				return ICMP4_XLAT_DROP;
			}
		}else{
			return ICMP4_XLAT_DROP;
		}
	}else{
		return ICMP4_XLAT_DROP;
	}
	xlat_payload:
	return ICMP4_XLAT_PAYLOAD;
}

static __always_inline long fill_ipv6_hdr(struct ip6_hdr *ip6h, const struct iphdr *iph, const struct ipv4_nat_table_value *dst, const struct ipv4_nat_table_value *src, void **transp_hdr, struct xdp_md *pbf){
	if(LIKELY(!!pbf)){
		bpf_xdp_valid_ptr(pbf, ip6h);
	}
	int is_frag = is_ip_fragment(iph);
	ip6h->ip6_flow = bpf_htonl(6 << 28 | iph->tos << 20);
	ip6h->ip6_plen = bpf_htons(bpf_ntohs(iph->tot_len) - iph->ihl * 4 + (is_frag ? sizeof(struct ip6_frag) : 0));
	ip6h->ip6_nxt  = iph->protocol;
	ip6h->ip6_hlim = iph->ttl;
	long checksum = 0;
	checksum += addr_translate_4to6((const struct in_addr *)&iph->saddr, &ip6h->ip6_src, src);
	checksum += addr_translate_4to6((const struct in_addr *)&iph->daddr, &ip6h->ip6_dst, dst);
	if(LIKELY(!!transp_hdr)){
		*transp_hdr = (void *)(ip6h + 1);
	}
	if(is_frag){
		struct ip6_frag *ip6f = (struct ip6_frag *)(ip6h + 1);
		if(LIKELY(!!transp_hdr)){
			*transp_hdr = ip6f + 1;
		}
		if(LIKELY(!!pbf)){
			bpf_xdp_valid_ptr(pbf, ip6f);
		}
		ip6f->ip6f_nxt = ip6h->ip6_nxt;
		ip6h->ip6_nxt = IPPROTO_FRAGMENT;
		ip6f->ip6f_reserved = 0;
		ip6f->ip6f_offlg = bpf_htons((bpf_ntohs(iph->frag_off) & IP_OFFMASK) << 3 ) | (bpf_ntohs(iph->frag_off) & IP_MF ? IP6F_MORE_FRAG : 0);
		ip6f->ip6f_ident = bpf_htonl(bpf_ntohs(iph->id));
	}
	return checksum;
}

static __always_inline long fill_icmp6_hdr(struct icmp6_hdr *icmp6h, const struct icmphdr *icmph, struct xdp_md *pbf){
	uint64_t checksum = 0;
	if(LIKELY(!!pbf)){
		bpf_xdp_valid_ptr(pbf, icmp6h);
	}
	checksum += 0xffff ^ (*(uint16_t *)icmph);
	checksum += 0xffffffff ^ (*((uint32_t *)icmph + 1));
	switch(icmph->type){
		case ICMP_ECHO:
			icmp6h->icmp6_type = ICMP6_ECHO_REQUEST;
			icmp6h->icmp6_code = icmph->code;
			icmp6h->icmp6_id   = icmph->un.echo.id;
			icmp6h->icmp6_seq  = icmph->un.echo.sequence;
			break;
		case ICMP_ECHOREPLY:
			icmp6h->icmp6_type = ICMP6_ECHO_REPLY;
			icmp6h->icmp6_code = icmph->code;
			icmp6h->icmp6_id   = icmph->un.echo.id;
			icmp6h->icmp6_seq  = icmph->un.echo.sequence;
			break;
		case ICMP_DEST_UNREACH:
			icmp6h->icmp6_type = ICMP6_DST_UNREACH;
			icmp6h->icmp6_data32[0] = 0;
			switch(icmph->code){
				case ICMP_UNREACH_NET:
				case ICMP_UNREACH_HOST:
					icmp6h->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
					break;
				case ICMP_PROT_UNREACH:
					icmp6h->icmp6_type = ICMP6_PARAM_PROB;
					icmp6h->icmp6_code = ICMP6_PARAMPROB_NEXTHEADER;
					icmp6h->icmp6_pptr = bpf_htonl(offsetof(struct ip6_hdr, ip6_nxt));
				case ICMP_PORT_UNREACH:
					icmp6h->icmp6_code = ICMP6_DST_UNREACH_NOPORT;
					break;
				case ICMP_FRAG_NEEDED:
					icmp6h->icmp6_type = ICMP6_PACKET_TOO_BIG;
					icmp6h->icmp6_code = 0;
					// Here we do not add 20 to mtu, for safety
					icmp6h->icmp6_mtu  = bpf_htonl(bpf_ntohs(icmph->un.frag.mtu) < IPV6_MIN_MTU ? IPV6_MIN_MTU : bpf_ntohs(icmph->un.frag.mtu));
					break;
				case ICMP_NET_UNKNOWN:
				case ICMP_HOST_UNKNOWN:
				case ICMP_HOST_ISOLATED:
					icmp6h->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
					break;
				case ICMP_NET_ANO:
				case ICMP_HOST_ANO:
				case ICMP_PREC_CUTOFF:
					icmp6h->icmp6_code = ICMP6_DST_UNREACH_ADMIN;
					break;
				default:
					goto out_drop;
			}
			break;
		case ICMP_TIME_EXCEEDED:
			icmp6h->icmp6_type = ICMP6_TIME_EXCEEDED;
			icmp6h->icmp6_code = icmph->code;
			icmp6h->icmp6_data32[0] = 0;
			break;
		case ICMP_PARAMETERPROB:
			icmp6h->icmp6_type = ICMP6_PARAM_PROB;
			switch (icmph->code) {
				case 0:
				case 2:
					icmp6h->icmp6_code = ICMP6_PARAMPROB_HEADER;
					int result_pptr = 0;
					switch (((struct icmp *)icmph)->icmp_pptr) {
						case 0:
							result_pptr = offsetof(struct ip6_hdr, ip6_vfc);
							break;
						case 1:
							result_pptr = 1;
							break;
						case 2: case 3:
							result_pptr = offsetof(struct ip6_hdr, ip6_plen);
							break;
						case 8:
							result_pptr = offsetof(struct ip6_hdr, ip6_hlim);
							break;
						case 9:
							result_pptr = offsetof(struct ip6_hdr, ip6_nxt);
							break;
						case 12: case 13: case 14: case 15:
							result_pptr = offsetof(struct ip6_hdr, ip6_src);
							break;
						case 16: case 17: case 18: case 19:
							result_pptr = offsetof(struct ip6_hdr, ip6_dst);
							break;
						default:
							goto out_drop;
					}
					icmp6h->icmp6_pptr = bpf_htonl(result_pptr);
					break;
				default:
					goto out_drop;
			}
			break;
	}
	checksum += *(uint16_t *)icmp6h;
	checksum += *((uint32_t *)icmp6h + 1);
	return checksum;
out_drop:
	return -EINVAL;

}

static __always_inline uint64_t calc_icmpv6_pseudo_checksum(const struct ip6_hdr *ip6h){
	uint64_t checksum = 0;
	#pragma unroll
	for(int i = 0; i < 4; i++){
		checksum += ip6h->ip6_src.s6_addr32[i];
		checksum += ip6h->ip6_dst.s6_addr32[i];
	}
	if(ip6h->ip6_nxt != IPPROTO_FRAGMENT){
		checksum += ip6h->ip6_plen;
	}else{
		checksum += bpf_htons(bpf_ntohs(ip6h->ip6_plen) - sizeof(struct ip6_frag));
	}
	checksum += ip6h->ip6_nxt << 8;
	return checksum;
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
	iph->ttl -= 1;

	if(iph->protocol == IPPROTO_ICMP && is_ip_fragment(iph)){
		return -ENOSYS;
	}

	const struct ipv4_nat_table_value *src, *dst;
	src = ipv4_siit_table_lookup((const struct in_addr *)&iph->saddr, &src_4to6_map);
	if(UNLIKELY(src == NULL)){
		return -ENOENT;
	}
	if(UNLIKELY(!is_ipv4_siit_table_entry_valid(src))){
		return -EINVAL;
	}
	dst = ipv4_siit_table_lookup((const struct in_addr *)&iph->daddr, &dst_4to6_map);
	if(UNLIKELY(dst == NULL)){
		return -ENOENT;
	}
	if(UNLIKELY(!is_ipv4_siit_table_entry_valid(dst))){
		return -EINVAL;
	}

	ssize_t len_diff = calc_extra_space_ip4_hdr(iph);

	long icmp_trans_type = 0;
	struct icmphdr _icmph;
	struct icmphdr *icmph = &_icmph;
	struct iphdr _icmp_iph;
	struct iphdr *icmp_iph = &_icmp_iph;
	const struct ipv4_nat_table_value *icmp_ip_src, *icmp_ip_dst;
	ssize_t icmp_len_diff;
	if(UNLIKELY(iph->protocol == IPPROTO_ICMP)){
		struct icmphdr *icmph = (struct icmphdr *)(pbf->data + offset + iph->ihl * 4);
		icmp_trans_type = icmp4_should_trans(pbf, icmph);
		if(icmp_trans_type == ICMP4_XLAT_DROP){
			return -EINVAL;
		}else if(icmp_trans_type == ICMP4_XLAT_PAYLOAD){
			struct iphdr *icmp_iph = (struct iphdr *)(icmph + 1);
			if(UNLIKELY((rc = bpf_xdp_ensure_ipv4_header(pbf, (void *)icmp_iph - (void *)(long)pbf->data)) < 0)){
				return rc;
			}
			if(icmp_iph->protocol == IPPROTO_ICMP && is_ip_fragment(icmp_iph)){
				return -ENOSYS;
			}
			/* In icmp error payload, we lookup src address in dst map*/
			icmp_ip_src = ipv4_siit_table_lookup((const struct in_addr *)&icmp_iph->saddr, &dst_4to6_map);
			if(UNLIKELY(icmp_ip_src == NULL)){
				return -EINVAL;
			}
			if(UNLIKELY(!is_ipv4_siit_table_entry_valid(icmp_ip_src))){
				return -EINVAL;
			}
			icmp_ip_dst = ipv4_siit_table_lookup((const struct in_addr *)&icmp_iph->daddr, &src_4to6_map);
			if(UNLIKELY(icmp_ip_dst == NULL)){
				return -EINVAL;
			}
			if(UNLIKELY(!is_ipv4_siit_table_entry_valid(icmp_ip_dst))){
				return -EINVAL;
			}
			_icmp_iph = *icmp_iph;
			icmp_len_diff = calc_extra_space_ip4_hdr(icmp_iph);
			len_diff += icmp_len_diff;
		}else{ /*Do nothing*/

		}
		bpf_xdp_valid_ptr(pbf, icmph);
		_icmph = *icmph;
		iph->protocol = IPPROTO_ICMPV6;
	}else{ // Fill uninitialized variables to make verifier happy
		icmp_len_diff = 0;
		memset(&_icmph, 0, sizeof(_icmph));
		memset(&_icmp_iph, 0, sizeof(_icmp_iph));
	}
	if(LIKELY(len_diff != 0)){
		rc = bpf_xdp_adjust_head_at(pbf, len_diff, offset);
		if(UNLIKELY(rc < 0)){
			return rc;
		}
	}
	if(UNLIKELY(icmp_trans_type == ICMP4_XLAT_PAYLOAD)){
		iph->tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + icmp_len_diff);
	}
	struct ip6_hdr *ip6h = (struct ip6_hdr *)(pbf->data + offset);
	void *transp_hdr;
	bpf_xdp_valid_ptr(pbf, ip6h);

	rc = fill_ipv6_hdr(ip6h, iph, dst, src, &transp_hdr, pbf);
	if(UNLIKELY(rc < 0)){
		return rc;
	}
	uint64_t checksum_diff = 0;
	checksum_diff += rc;

	if(iph->protocol == IPPROTO_ICMPV6){
		checksum_diff = calc_icmpv6_pseudo_checksum(ip6h);
		struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)transp_hdr;
		rc = fill_icmp6_hdr(icmp6h, icmph, pbf);
		if(UNLIKELY(rc < 0)){
			return rc;
		}
		checksum_diff += rc;
		icmp6h->icmp6_cksum = icmph->checksum;
		if(icmp_trans_type == ICMP4_XLAT_PAYLOAD){
			struct ip6_hdr *icmp6_ip6h = (struct ip6_hdr *)(icmp6h + 1);
			void *inner_transp_hdr;
			if(icmp_iph -> protocol == IPPROTO_ICMP){
				icmp_iph->protocol = IPPROTO_ICMPV6;
				checksum_diff += (IPPROTO_ICMPV6 << 8) + (0xffff ^ (IPPROTO_ICMP << 8));
			}
			rc = fill_ipv6_hdr(icmp6_ip6h, icmp_iph, icmp_ip_dst, icmp_ip_src, &inner_transp_hdr, pbf);
			if(UNLIKELY(rc < 0)){
				return rc;
			}
			uint64_t inner_checksum_diff = rc;
			checksum_diff += rc; // Include Address Diff
			checksum_diff += 0xffffffff ^ (*((uint32_t *) icmp_iph + 0)); // Cancel IPv4 Ver IHL TOS LEN
			checksum_diff += 0xffffffff ^ (*((uint32_t *) icmp_iph + 1)); // Cancel IPv4 ID, Flags, Frag Offset
			checksum_diff += 0xffffffff ^ (*((uint32_t *) icmp_iph + 2)); // Cancel IPv4 TTL, Protocol, Checksum

			checksum_diff += *((uint32_t *) icmp6_ip6h + 0); //Include IPv6 Ver TC FL
			checksum_diff += *((uint32_t *) icmp6_ip6h + 1); //Include IPv6 Payload Length, Next Header, Hop Limit

			if(icmp6_ip6h->ip6_nxt == IPPROTO_FRAGMENT){ // Include Possible Fragment Header
				struct ip6_frag *icmp6_ip6f = (struct ip6_frag *)(icmp6_ip6h + 1);
				bpf_xdp_valid_ptr(pbf, icmp6_ip6f);
				checksum_diff += *((uint32_t *) icmp6_ip6f + 0);
				checksum_diff += *((uint32_t *) icmp6_ip6f + 1);
			}

			if(LIKELY(!is_ip_following_fragment(icmp_iph))){
				if(icmp_iph->protocol == IPPROTO_ICMPV6){
					inner_checksum_diff = 0;
					struct icmp6_hdr *inner_icmp6h = (struct icmp6_hdr *)inner_transp_hdr;
					bpf_xdp_valid_ptr(pbf, inner_icmp6h); // Make the verifier happy
					if(inner_icmp6h->icmp6_type == ICMP_ECHO){
						inner_checksum_diff += (0xffff ^ ICMP_ECHO) + ICMP6_ECHO_REQUEST;
						inner_icmp6h->icmp6_type = ICMP6_ECHO_REQUEST;
					}else if(inner_icmp6h->icmp6_type == ICMP_ECHOREPLY){
						inner_checksum_diff += (0xffff ^ ICMP_ECHOREPLY) + ICMP6_ECHO_REPLY;
						inner_icmp6h->icmp6_type = ICMP6_ECHO_REPLY;
					}
					checksum_diff += inner_checksum_diff; //Include ICMPv6 Type Code Checksum
					inner_checksum_diff += calc_icmpv6_pseudo_checksum(icmp6_ip6h);
				}
				rc = checksum_fill_delta(pbf, inner_transp_hdr, icmp_iph->protocol, inner_checksum_diff);
				if(UNLIKELY(rc < 0)){
					return rc;
				}
				checksum_diff += rc;
			}
		}
	}
	if(LIKELY(!is_ip_following_fragment(iph))){
		rc = checksum_fill_delta(pbf, transp_hdr, iph->protocol, checksum_diff);
		if(UNLIKELY(rc < 0)){
			return rc;
		}
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
