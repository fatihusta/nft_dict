#include <linux/version.h>
#include <linux/glob.h>
#include <linux/tcp.h>
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include "dict.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
static inline struct net *nft_net(const struct nft_pktinfo *pkt)
{
	return pkt->net;
}
#endif

/* These would be in nf_tables.h */
enum nft_dict_attributes {
	NFTA_DICT_UNSPEC,
	NFTA_DICT_SREG,
	NFTA_DICT_DREG,
	NFTA_DICT_TYPE,
	NFTA_DICT_TABLE,
	NFTA_DICT_FIELD,
	NFTA_DICT_VALUE,
	NFTA_DICT_LEN,
	NFTA_DICT_SIZE,
	NFTA_DICT_SET,
	NFTA_DICT_FLUSH,
	__NFTA_DICT_MAX,
};

#define DICT_FIELD_SIZE 128
#define DICT_VALUE_SIZE 128

struct nft_dict {
	enum nft_registers      sreg:8;
	enum nft_registers      dreg:8;
	char field[DICT_FIELD_SIZE];
	u8 field_len;
	u32 field_hash;
	char value[DICT_VALUE_SIZE];
	u8 value_len;
	u32 value_hash;
	u32 type;
	char table[DICT_VALUE_SIZE];
	char *ptable;
	u32 len;
	u32 size;
	enum nft_registers      set:8;
	u32 flush;
};

static const struct nla_policy nft_dict_policy[NFTA_DICT_MAX + 1] = {
	[NFTA_DICT_SREG]	= { .type = NLA_U32 },
	[NFTA_DICT_DREG]	= { .type = NLA_U32 },
	[NFTA_DICT_TYPE]	= { .type = NLA_U32 },
	[NFTA_DICT_LEN]		= { .type = NLA_U32 },
	[NFTA_DICT_SIZE]	= { .type = NLA_U32 },
	[NFTA_DICT_FIELD]	= { .type = NLA_STRING, .len = DICT_FIELD_SIZE },
	[NFTA_DICT_VALUE]	= { .type = NLA_STRING, .len = DICT_VALUE_SIZE },
	[NFTA_DICT_TABLE]	= { .type = NLA_STRING, .len = DICT_VALUE_SIZE },
	[NFTA_DICT_SET]		= { .type = NLA_U32 },
	[NFTA_DICT_FLUSH]	= { .type = NLA_U32 },
};

static seq_printfn_t print_func_by_type(int type)
{
	switch(type) {
		case 7:
			return &seq_print_ip;
		case 8:
			return &seq_print_ip6;
		case 9:
			return &seq_print_mac;
		case 41:
			return &seq_print_signed_integer;
		case 42:
			return &seq_print_integer64;
		case 43:
			return &seq_print_bool;
		default:
			return &seq_print_string;
	}
}

static seq_printfn_t print_func_by_table(char * table)
{
	if(0 == strcmp(table, "session")) {
		return &seq_print_integer;
	} else if(0 == strcmp(table, "device")) {
		return &seq_print_mac;
	} else if(0 == strcmp(table, "host")) {
		return &seq_print_ip;
	} else if(0 == strcmp(table, "user")) {
		return &seq_print_string;
	} else {
		return &seq_print_integer;
	}
}

static void nft_dict_get_eval(const struct nft_expr *expr, struct nft_regs *regs, const struct nft_pktinfo *pkt)
{
	struct nft_dict *priv = nft_expr_priv(expr);
	u8 *key = (u8 *)&regs->data[priv->sreg];
	void *data = &regs->data[priv->dreg];
	struct nf_conn_dict_entry_elem * value_elem;
	char *value;
	unsigned int len;

	if(priv->flush) {
		destroy_dict(nft_net(pkt), key, priv->len, priv->ptable);
		return;
	}

	if(priv->set) {
		if(priv->value[0] != '\0') {
			value = priv->value;
			len = strlen(value);
		} else {
			value = (char *)&regs->data[priv->set];
			len = priv->size;
		}

		new_dict_entry(nft_net(pkt), key, priv->len, priv->ptable, print_func_by_table(priv->table), priv->field, value, len, print_func_by_type(priv->type));
	} else {
		rcu_read_lock();
		value_elem = find_conntrack_dict_entry(nft_net(pkt), key, priv->len, priv->ptable, priv->field);
		if(!value_elem) {
			rcu_read_unlock();
			goto err;
		}

		if(priv->value[0] != '\0') {
			regs->verdict.code = NFT_BREAK;
			if(priv->value_hash != value_elem->hash) {
				if(glob_match(priv->value, value_elem->buf)) {
					regs->verdict.code = NFT_CONTINUE;
				}
			} else {
				regs->verdict.code = NFT_CONTINUE;
			}
		} else {
			memset(data, 0, priv->size);
			if(value_elem->len > priv->size) {
				memcpy(data, &value_elem->hash, sizeof(value_elem->hash));
			} else {
				memcpy(data, value_elem->buf, value_elem->len);
			}
		}
		rcu_read_unlock();
	}
	return;
err:
	regs->verdict.code = NFT_BREAK;
}

static int nft_dict_init(const struct nft_ctx *ctx, const struct nft_expr *expr, const struct nlattr * const tb[])
{
	struct nft_dict *priv = nft_expr_priv(expr);

	if (!tb[NFTA_DICT_SREG] ||
	    !tb[NFTA_DICT_LEN])
		return -EINVAL;

	memset(priv, 0, sizeof(*priv));
	priv->sreg = nft_parse_register(tb[NFTA_DICT_SREG]);

	if(tb[NFTA_DICT_DREG]) {
		priv->dreg = nft_parse_register(tb[NFTA_DICT_DREG]);
	}

	if(tb[NFTA_DICT_FIELD]) {
		nla_strlcpy(priv->field, tb[NFTA_DICT_FIELD], DICT_FIELD_SIZE);
		priv->field_len = strlen(priv->field);
		priv->field_hash = jhash(priv->field, priv->field_len, 0);
	}

	if(tb[NFTA_DICT_VALUE]) {
		nla_strlcpy(priv->value, tb[NFTA_DICT_VALUE], DICT_VALUE_SIZE);
		priv->value_len = strlen(priv->value);
		priv->value_hash = jhash(priv->value, priv->value_len, 0);
	}

	if(tb[NFTA_DICT_TABLE]) {
		nla_strlcpy(priv->table, tb[NFTA_DICT_TABLE], DICT_VALUE_SIZE);
		priv->ptable = priv->table;
	} else {
		priv->ptable = NULL;
	}

	if(tb[NFTA_DICT_TYPE]) {
		priv->type = ntohl(nla_get_be32(tb[NFTA_DICT_TYPE]));
	}
	if(tb[NFTA_DICT_SIZE]) {
		priv->size = ntohl(nla_get_be32(tb[NFTA_DICT_SIZE]));
	}
	priv->len = ntohl(nla_get_be32(tb[NFTA_DICT_LEN]));

	if(tb[NFTA_DICT_SET]) {
		priv->set = nft_parse_register(tb[NFTA_DICT_SET]);
	}

	if(tb[NFTA_DICT_FLUSH]) {
		priv->flush = ntohl(nla_get_be32(tb[NFTA_DICT_FLUSH]));
	}

	return nft_validate_register_load(priv->sreg, priv->len);
}

static int nft_dict_dump(struct sk_buff *skb, const struct nft_expr *expr)
{
	const struct nft_dict *priv = nft_expr_priv(expr);

	if (nft_dump_register(skb, NFTA_DICT_SREG, priv->sreg))
		return -1;

	if(priv->dreg != 0) {
		if (nft_dump_register(skb, NFTA_DICT_DREG, priv->dreg))
			return -1;
	}

	if(priv->type != 0) {
		if (nla_put_be32(skb, NFTA_DICT_TYPE, htonl(priv->type)))
			return -1;
	}

	if(priv->size != 0) {
		if (nla_put_be32(skb, NFTA_DICT_SIZE, htonl(priv->size)))
			return -1;
	}

	if(priv->field) {
		if(nla_put_string(skb, NFTA_DICT_FIELD, priv->field))
			return -1;
	}

	if(priv->value[0] != '\0') {
		if(nla_put_string(skb, NFTA_DICT_VALUE, priv->value))
			return -1;
	}

	if(priv->table[0] != '\0') {
		if(nla_put_string(skb, NFTA_DICT_TABLE, priv->table))
			return -1;
	}

	if(priv->set != 0) {
		if (nft_dump_register(skb, NFTA_DICT_SET, priv->set))
			return -1;
	}

	if(priv->flush != 0) {
		if (nla_put_be32(skb, NFTA_DICT_FLUSH, htonl(priv->flush)))
			return -1;
	}

	return 0;
}

static struct nft_expr_type nft_dict_type;
static const struct nft_expr_ops nft_dict_ops = {
	.eval = nft_dict_get_eval,
	.size = NFT_EXPR_SIZE(sizeof(struct nft_dict)),
	.init = nft_dict_init,
	.dump = nft_dict_dump,
	.type = &nft_dict_type,
};

static struct nft_expr_type nft_dict_type __read_mostly = {
	.name = "dict",
	.ops = &nft_dict_ops,
	.owner = THIS_MODULE,
	.policy = nft_dict_policy,
	.maxattr = NFTA_DICT_MAX,
};

/* These would be in nf_tables.h */
enum nft_ctid_attributes {
	NFTA_CTID_UNSPEC,
	NFTA_CTID_DREG,
	__NFTA_CTID_MAX,
};

struct nft_ctid {
	enum nft_registers      dreg:8;
};

static const struct nla_policy nft_ctid_policy[NFTA_CTID_MAX + 1] = {
	[NFTA_CTID_DREG]	= { .type = NLA_U32 },
};

static void nft_ctid_get_eval(const struct nft_expr *expr, struct nft_regs *regs, const struct nft_pktinfo *pkt)
{
	const struct nft_ctid *priv = nft_expr_priv(expr);
	u32 *dest = &regs->data[priv->dreg];
	enum ip_conntrack_info ctinfo;
	const struct nf_conn *ct;
	unsigned int ct_id;

	ct = nf_ct_get(pkt->skb, &ctinfo);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,131)
	if (!ct)
		ct_id = 0;
	else
		ct_id = htonl(nf_ct_get_id(ct));
#else
	ct_id = (unsigned long)ct;
#endif
	*dest = ct_id;

	return;
}

static int nft_ctid_init(const struct nft_ctx *ctx, const struct nft_expr *expr, const struct nlattr * const tb[])
{
	struct nft_ctid *priv = nft_expr_priv(expr);

	if (!tb[NFTA_CTID_DREG])
		return -EINVAL;

	memset(priv, 0, sizeof(*priv));
	priv->dreg = nft_parse_register(tb[NFTA_CTID_DREG]);

	return nft_validate_register_store(ctx, priv->dreg, NULL,
					  NFT_DATA_VALUE, sizeof(u32));
}

static int nft_ctid_dump(struct sk_buff *skb, const struct nft_expr *expr)
{
	const struct nft_ctid *priv = nft_expr_priv(expr);

	if(priv->dreg != 0) {
		if (nft_dump_register(skb, NFTA_CTID_DREG, priv->dreg))
			return -1;
	}

	return 0;
}

static struct nft_expr_type nft_ctid_type;
static const struct nft_expr_ops nft_ctid_ops = {
	.eval = nft_ctid_get_eval,
	.size = NFT_EXPR_SIZE(sizeof(struct nft_ctid)),
	.init = nft_ctid_init,
	.dump = nft_ctid_dump,
	.type = &nft_ctid_type,
};

static struct nft_expr_type nft_ctid_type __read_mostly = {
	.name = "ctid",
	.ops = &nft_ctid_ops,
	.owner = THIS_MODULE,
	.policy = nft_ctid_policy,
	.maxattr = NFTA_CTID_MAX,
};

struct nft_cmp_expr {
	struct nft_data		data;
	enum nft_registers	sreg:8;
	u8			len;
	enum nft_cmp_ops	op:8;
};

static void nft_cmp_eval(const struct nft_expr *expr,
			 struct nft_regs *regs,
			 const struct nft_pktinfo *pkt)
{
	const struct nft_cmp_expr *priv = nft_expr_priv(expr);
	int d;

	d = memcmp(&regs->data[priv->sreg], &priv->data, priv->len);
	if(d != 0) {
		if(priv->len == sizeof(int32_t)) {
			int32_t reg, data;
			reg = (int32_t)regs->data[priv->sreg];
			data = *(int32_t *)&priv->data;
			if(reg > data)
				d = 1;
			else
				d = -1;
		} else {
			int64_t reg, data;
			reg = (int64_t)regs->data[priv->sreg];
			data = *(int64_t *)&priv->data;
			if(reg > data)
				d = 1;
			else
				d = -1;
		}
	}

	switch (priv->op) {
	case NFT_CMP_EQ:
		if (d != 0)
			goto mismatch;
		break;
	case NFT_CMP_NEQ:
		if (d == 0)
			goto mismatch;
		break;
	case NFT_CMP_LT:
		if (d == 0)
			goto mismatch;
	case NFT_CMP_LTE:
		if (d > 0)
			goto mismatch;
		break;
	case NFT_CMP_GT:
		if (d == 0)
			goto mismatch;
	case NFT_CMP_GTE:
		if (d < 0)
			goto mismatch;
		break;
	}
	return;

mismatch:
	regs->verdict.code = NFT_BREAK;
}

static const struct nla_policy nft_cmp_policy[NFTA_CMP_MAX + 1] = {
	[NFTA_CMP_SREG]		= { .type = NLA_U32 },
	[NFTA_CMP_OP]		= { .type = NLA_U32 },
	[NFTA_CMP_DATA]		= { .type = NLA_NESTED },
};

static int nft_cmp_init(const struct nft_ctx *ctx, const struct nft_expr *expr,
			const struct nlattr * const tb[])
{
	struct nft_cmp_expr *priv = nft_expr_priv(expr);
	struct nft_data_desc desc;
	int err;

	err = nft_data_init(NULL, &priv->data, sizeof(priv->data), &desc,
			    tb[NFTA_CMP_DATA]);
	BUG_ON(err < 0);

	priv->sreg = nft_parse_register(tb[NFTA_CMP_SREG]);
	err = nft_validate_register_load(priv->sreg, desc.len);
	if (err < 0)
		return err;

	priv->op  = ntohl(nla_get_be32(tb[NFTA_CMP_OP]));
	priv->len = desc.len;
	return 0;
}

static int nft_cmp_dump(struct sk_buff *skb, const struct nft_expr *expr)
{
	const struct nft_cmp_expr *priv = nft_expr_priv(expr);

	if (nft_dump_register(skb, NFTA_CMP_SREG, priv->sreg))
		goto nla_put_failure;
	if (nla_put_be32(skb, NFTA_CMP_OP, htonl(priv->op)))
		goto nla_put_failure;

	if (nft_data_dump(skb, NFTA_CMP_DATA, &priv->data,
			  NFT_DATA_VALUE, priv->len) < 0)
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -1;
}

struct nft_expr_type nft_scmp_type;
static const struct nft_expr_ops nft_cmp_ops = {
	.type		= &nft_scmp_type,
	.size		= NFT_EXPR_SIZE(sizeof(struct nft_cmp_expr)),
	.eval		= nft_cmp_eval,
	.init		= nft_cmp_init,
	.dump		= nft_cmp_dump,
};

static const struct nft_expr_ops *
nft_cmp_select_ops(const struct nft_ctx *ctx, const struct nlattr * const tb[])
{
	struct nft_data_desc desc;
	struct nft_data data;
	enum nft_cmp_ops op;
	int err;


	if (tb[NFTA_CMP_SREG] == NULL ||
	    tb[NFTA_CMP_OP] == NULL ||
	    tb[NFTA_CMP_DATA] == NULL)
		return ERR_PTR(-EINVAL);

	op = ntohl(nla_get_be32(tb[NFTA_CMP_OP]));
	switch (op) {
	case NFT_CMP_EQ:
	case NFT_CMP_NEQ:
	case NFT_CMP_LT:
	case NFT_CMP_LTE:
	case NFT_CMP_GT:
	case NFT_CMP_GTE:
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	err = nft_data_init(NULL, &data, sizeof(data), &desc,
			    tb[NFTA_CMP_DATA]);
	if (err < 0)
		return ERR_PTR(err);

	if (desc.type != NFT_DATA_VALUE) {
		err = -EINVAL;
		goto err1;
	}

	return &nft_cmp_ops;
err1:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	nft_data_release(&data, desc.type);
#else
	nft_data_uninit(&data, desc.type);
#endif
	return ERR_PTR(-EINVAL);
}

struct nft_expr_type nft_scmp_type __read_mostly = {
	.name		= "scmp",
	.select_ops	= nft_cmp_select_ops,
	.policy		= nft_cmp_policy,
	.maxattr	= NFTA_CMP_MAX,
	.owner		= THIS_MODULE,
};

static int __init nft_dict_module_init(void)
{
	int ret;

	ret = nft_register_expr(&nft_dict_type);
	if(ret < 0) {
		return ret;
	}

	ret = nft_register_expr(&nft_ctid_type);
	if(ret < 0) {
		nft_unregister_expr(&nft_dict_type);
		return ret;
	}

	ret = nft_register_expr(&nft_scmp_type);
	if(ret < 0) {
		nft_unregister_expr(&nft_ctid_type);
		nft_unregister_expr(&nft_dict_type);
		return ret;
	}

	return ret;
};

static void __exit nft_dict_module_exit(void)
{
	nft_unregister_expr(&nft_scmp_type);
	nft_unregister_expr(&nft_ctid_type);
	nft_unregister_expr(&nft_dict_type);
}

module_init(nft_dict_module_init);
module_exit(nft_dict_module_exit);

MODULE_AUTHOR("Brett Mastbergen");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NFT_EXPR("dict");
MODULE_ALIAS_NFT_EXPR("ctid");
MODULE_ALIAS_NFT_EXPR("scmp");
MODULE_DESCRIPTION("Generic dictionary matching for conntrack");
