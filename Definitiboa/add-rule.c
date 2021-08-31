#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stddef.h>	/* for offsetof */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/udp.h>

#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "add-rule.h"

static int add_payload(struct nftnl_rule *rRule, uint32_t base, uint32_t dreg,
            uint32_t offset, uint32_t len)
{
    struct nftnl_expr *tExpression = nftnl_expr_alloc("payload");
    if (tExpression == NULL) {
        perror("expr payload oom");
        return(EXIT_FAILURE);
    }

    nftnl_expr_set_u32(tExpression, NFTNL_EXPR_PAYLOAD_BASE, base);
    nftnl_expr_set_u32(tExpression, NFTNL_EXPR_PAYLOAD_DREG, dreg);
    nftnl_expr_set_u32(tExpression, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
    nftnl_expr_set_u32(tExpression, NFTNL_EXPR_PAYLOAD_LEN, len);

    nftnl_rule_add_expr(rRule, tExpression);
}

static int add_cmp(struct nftnl_rule *r, uint32_t sreg, uint32_t op,
		    const void *data, uint32_t data_len)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("cmp");
	if (e == NULL) {
		perror("expr cmp oom");
		return(EXIT_FAILURE);
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, sreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, op);
	nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, data, data_len);

	nftnl_rule_add_expr(r, e);
}

static int add_counter(struct nftnl_rule *r)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("counter");
	if (e == NULL) {
		perror("expr counter oom");
		return(EXIT_FAILURE);
	}

	nftnl_rule_add_expr(r, e);
}

static struct nftnl_rule *setup_rule(uint8_t family, const char *table,
                   const char *chain, const char *handle, int iof, uint8_t proto, uint16_t port, char *ip)//, uint8_t *addr)
{
    struct nftnl_rule *rule = NULL;
    uint64_t handle_num;
    int tport, ipv, e;
    uint8_t addr[sizeof(struct in_addr)];
    
    rule = nftnl_rule_alloc();
    if (rule == NULL) {
        perror("OOM");
        return NULL;
    }

    nftnl_rule_set(rule, NFTNL_RULE_TABLE, table);
    nftnl_rule_set(rule, NFTNL_RULE_CHAIN, chain);
    nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, family);
    
    /* Declaring tcp port or udp port */
    
        //printf("2");
    if(iof == 1){  
        e=add_payload(rule, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
                    offsetof(struct iphdr, protocol), sizeof(uint8_t));
        if(e==EXIT_FAILURE){
            perror("OOM");
            return NULL;
        }
        e=add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &proto, sizeof(uint8_t));
        if(e==EXIT_FAILURE){
            perror("OOM");
            return NULL;
        }
        e=add_payload(rule, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
                    offsetof(struct udphdr, dest), sizeof(uint16_t)); 
        if(e==EXIT_FAILURE){
            perror("OOM");
            return NULL;
        }
        e=add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &port, sizeof(uint16_t));
        if(e==EXIT_FAILURE){
            perror("OOM");
            return NULL;
        }
        e=add_payload(rule, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
                    offsetof(struct iphdr, saddr), sizeof(addr));
        if(e==EXIT_FAILURE){
            perror("OOM");
            return NULL;
        }
        inet_pton(AF_INET, ip, addr);
        e=add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, addr, sizeof(struct in_addr));
        if(e==EXIT_FAILURE){
            perror("OOM");
            return NULL;
        }       
        
    }else if(iof == 2){
        e=add_payload(rule, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
                    offsetof(struct iphdr, protocol), sizeof(uint8_t));
        if(e==EXIT_FAILURE){
            perror("OOM");
            return NULL;
        }
        e=add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &proto, sizeof(uint8_t)); 
        if(e==EXIT_FAILURE){
            perror("OOM");
            return NULL;
        }
        e=add_payload(rule, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
                    offsetof(struct udphdr, dest), sizeof(uint16_t));
        if(e==EXIT_FAILURE){
            perror("OOM");
            return NULL;
        }
        e=add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &port, sizeof(uint16_t));
        if(e==EXIT_FAILURE){
            perror("OOM");
            return NULL;
        }
        e=add_payload(rule, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
                    offsetof(struct iphdr, daddr), sizeof(addr));
        if(e==EXIT_FAILURE){
            perror("OOM");
            return NULL;
        }
        inet_pton(AF_INET, ip, addr);
        e=add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, addr, sizeof(struct in_addr));
        if(e==EXIT_FAILURE){
            perror("OOM");
            return NULL;
        }
    }

    e=add_counter(rule);
    if(e==EXIT_FAILURE){
            perror("OOM");
            return NULL;
        }
    
    return rule;
}

int addRul(int argc, char *argv[])
{
    struct mnl_socket *nl;
    struct nftnl_rule *r;
    struct nlmsghdr *nlh;
    struct mnl_nlmsg_batch *batch;
    uint8_t family;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = time(NULL);
    uint8_t proto;
    uint16_t port;
    int ret, batching, iof, tport;

    if (argc != 8) {
        fprintf(stderr, "Usage: %s <family> <table> <chain> <input/output> <proto> <port> <ip>\n", argv[0]);
        return(EXIT_FAILURE);
    }

    //Hace falta añadir inet!!!
    if (strcmp(argv[1], "ip") == 0)
        family = NFPROTO_IPV4;
    else if (strcmp(argv[1], "ip6") == 0)
        family = NFPROTO_IPV6;
    else if (strcmp(argv[1], "inet") == 0)
		family = NFPROTO_INET;
	else {
		fprintf(stderr, "Unknown family: ip, ip6, inet\n");
		return(EXIT_FAILURE);
	}
	
    printf("8");
    if(strcmp(argv[4], "input") == 0)
        iof=1;
    else if(strcmp(argv[4], "output") == 0)
        iof=2;
    else{
        fprintf(stderr, "Unknown input/output\n");
        return(EXIT_FAILURE);
    }
    if(strcmp(argv[5], "udp") == 0)
        proto=IPPROTO_UDP;
    else if(strcmp(argv[5], "tcp") == 0)
        proto=IPPROTO_TCP;
    else{
        fprintf(stderr, "Unknown proto: udp, tcp\n");
        return(EXIT_FAILURE);
    }
    tport = atoi(argv[6]);
    port = htons(tport);
    printf("%s\n",argv[7]);
        
    r = setup_rule(family, argv[2], argv[3], NULL, iof, proto, port, argv[7]);

    if(r==NULL){
        return(EXIT_FAILURE);        
    }
    // Now adding rule through mnl socket
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        perror("mnl_socket_open");
        return(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        return(EXIT_FAILURE);
    }

    batching = nftnl_batch_is_supported();
    if (batching < 0) {
        perror("cannot talk to nfnetlink");
        return(EXIT_FAILURE);
    }

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

    if (batching) {
        nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);
    }

    nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
            NFT_MSG_NEWRULE,
            nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
            NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);

    nftnl_rule_nlmsg_build_payload(nlh, r);
    nftnl_rule_free(r);
    mnl_nlmsg_batch_next(batch);

    if (batching) {
        nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);
    }

    ret = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                mnl_nlmsg_batch_size(batch));
    if (ret == -1) {
        perror("mnl_socket_sendto");
        return(EXIT_FAILURE);
    }

    mnl_nlmsg_batch_stop(batch);

    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    if (ret == -1) {
        perror("mnl_socket_recvfrom");
        return(EXIT_FAILURE);
    }

    ret = mnl_cb_run(buf, ret, 0, mnl_socket_get_portid(nl), NULL, NULL);
    if (ret < 0) {
        perror("mnl_cb_run");
        return(EXIT_FAILURE);
    }

    mnl_socket_close(nl);
    
    return EXIT_SUCCESS;
} 
