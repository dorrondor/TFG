static void add_payload(struct nftnl_rule *rRule, uint32_t base, uint32_t dreg, uint32_t offset, uint32_t len);
static void add_cmp(struct nftnl_rule *r, uint32_t sreg, uint32_t op, const void *data, uint32_t data_len);
static void add_counter(struct nftnl_rule *r);
static struct nftnl_rule *setup_rule(uint8_t family, const char *table, const char *chain, const char *handle, int iof, uint8_t proto, uint16_t port, uint8_t addr);
int addRul(int argc, char *argv[]);
