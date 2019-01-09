#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/rhashtable.h>
#include <linux/jhash.h>
#include <linux/parser.h>
#include <linux/inet.h>
#include <net/netfilter/nf_conntrack.h>
#include "dict.h"

static struct proc_dir_entry *dict_dir;
static struct rhltable hlt;

struct nf_conn_dict {
	struct rhlist_head list;
	struct nf_conn_dict_entry_elem * table;
	struct nf_conn_dict_entry_elem * key;
	struct nf_conn_dict_entry_elem * field;
	struct nf_conn_dict_entry_elem * value;
	struct rcu_head rcu_head;
};

struct dict_hash_cmp_arg {
	u8	*key;
	u32	key_len;
	char	*table;
};

static inline int dict_hash_cmp(struct rhashtable_compare_arg *arg, const void *ptr)
{
	struct nf_conn_dict *dict = (struct nf_conn_dict *)ptr;
	const struct dict_hash_cmp_arg *x = arg->key;
	u32 key_hash, table_hash;

	if(x->key_len > sizeof(u32)) {
		key_hash = jhash(x->key, x->key_len, 0);
	} else {
		key_hash = *(u32 *)x->key;
	}

	if(x->table) {
		table_hash = jhash(x->table, strlen(x->table), 0);
		key_hash = jhash_2words(table_hash, key_hash, 0);
	}

	if(key_hash != dict->key->hash) {
		return 1;
	}

	return 0;
}

static inline u32 dict_hash_obj(const void *data, u32 len, u32 seed)
{
	const struct nf_conn_dict *dict = data;

	return dict->key->hash;
}

static inline u32 dict_hash_key(const void *data, u32 len, u32 seed)
{
	const struct dict_hash_cmp_arg *x = data;
	u32 key_hash, table_hash;

	if(x->key_len > sizeof(u32)) {
		key_hash = jhash(x->key, x->key_len, 0);
	} else {
		key_hash = *(u32 *)x->key;
	}

	if(x->table) {
		table_hash = jhash(x->table, strlen(x->table), 0);
		key_hash = jhash_2words(table_hash, key_hash, 0);
	}

	return key_hash;
}

static const struct rhashtable_params dict_rhashtable_params = {
	.head_offset = offsetof(struct nf_conn_dict, list),
	.hashfn	= dict_hash_key,
	.obj_hashfn = dict_hash_obj,
	.obj_cmpfn = dict_hash_cmp,
	.automatic_shrinking = true,
};

static struct nf_conn_dict_entry_elem * alloc_dict_entry_elem(int size)
{
	struct nf_conn_dict_entry_elem * new;

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if(!new) {
		pr_err("%s: Could not allocate new dictionary entry struct\n", __func__);
		goto err;
	}

	new->buf = kzalloc(size, GFP_KERNEL);
	if(!new->buf) {
		pr_err("%s: Could not allocate new string\n", __func__);
		goto err_free_new;
	}

	return new;

err_free_new:
	kfree(new);
err:
	return NULL;
}

static void free_dict_entry_elem(struct nf_conn_dict_entry_elem * elem)
{
	kfree(elem->buf);
	kfree(elem);
}

static void __free_dict(struct nf_conn_dict * dict)
{
	if(!dict)
		return;

	if(dict->table) {
		free_dict_entry_elem(dict->table);
	}

	free_dict_entry_elem(dict->key);
	free_dict_entry_elem(dict->field);
	free_dict_entry_elem(dict->value);
	kfree(dict);
}

static void dict_context_free(struct rcu_head *head)
{
	struct nf_conn_dict *dict = container_of(head, struct nf_conn_dict, rcu_head);
	__free_dict(dict);
}

struct nf_conn_dict * new_dict_entry(u8 *key, u32 key_len, char *table, seq_printfn_t key_printfn,
				char * field, char * value, u32 len, seq_printfn_t printfn)
{
	int ret;
	struct rhlist_head * list, * tmp;
	struct nf_conn_dict * dict, * temp;
	struct dict_hash_cmp_arg arg = {
		.key = key,
		.key_len = key_len,
		.table = table,
	};

	dict = kzalloc(sizeof(*dict), GFP_KERNEL);
	if(!dict) {
		pr_err("%s: Could not allocate dict structure\n", __func__);
		return NULL;
	}

	dict->key = alloc_dict_entry_elem(key_len);
	if(!dict->key) {
		pr_err("%s: Could not allocate dict key structure\n", __func__);
		kfree(dict);
		return NULL;
	}
	memcpy(dict->key->buf, key, key_len);
	dict->key->len = key_len;
	dict->key->printfn = key_printfn;

	if(dict->key->len > sizeof(u32)) {
		dict->key->hash = jhash(dict->key->buf, dict->key->len, 0);
	} else {
		dict->key->hash = *(u32 *)dict->key->buf;
	}

	if(table) {
		dict->table = alloc_dict_entry_elem(strlen(table) + 1);
		if(!dict->table) {
			pr_err("%s: Could not allocate dict key structure\n", __func__);
			kfree(dict->key);
			kfree(dict);
			return NULL;
		}
		strcpy(dict->table->buf, table);
		dict->table->len = strlen(dict->table->buf);
		dict->table->hash = jhash(dict->table->buf, dict->table->len, 0);

		dict->key->hash = jhash_2words(dict->table->hash, dict->key->hash, 0);
	}

	dict->field = alloc_dict_entry_elem(strlen(field)+ 1);
	if(!dict->field) {
		pr_err("%s: Could not allocate dict field\n", __func__);
		free_dict_entry_elem(dict->table);
		kfree(dict->key);
		kfree(dict);
		return NULL;
	}
	strcpy(dict->field->buf, field);
	dict->field->len = strlen(dict->field->buf);
	dict->field->hash = jhash(dict->field->buf, dict->field->len, 0);


	dict->value = alloc_dict_entry_elem(len + 1);
	if(!dict->value) {
		pr_err("%s: Could not allocate dict value\n", __func__);
		free_dict_entry_elem(dict->field);
		free_dict_entry_elem(dict->table);
		kfree(dict->key);
		kfree(dict);
		return NULL;
	}
	memcpy(dict->value->buf, value, len);
	dict->value->len = len;
	dict->value->hash = jhash(dict->value->buf, dict->value->len, 0);
	dict->value->printfn = printfn;

	rcu_read_lock();
	list = rhltable_lookup(&hlt, &arg, dict_rhashtable_params);
	rhl_for_each_entry_rcu(temp, tmp, list, list) {
		if(dict->field->hash == temp->field->hash) {
			ret = rhltable_remove(&hlt, &temp->list, dict_rhashtable_params);
			if(ret == -ENOENT) {
				continue;
			}

			if(ret < 0) {
				pr_err("%s: Unable to remove entry %s from hashtable: %d\n", __func__, field, ret);
				continue;
			}
			call_rcu(&temp->rcu_head, dict_context_free);
		}
	}
	ret = rhltable_insert_key(&hlt, &arg, &dict->list, dict_rhashtable_params);
	rcu_read_unlock();
	if(ret < 0) {
		pr_err("%s: Unable to insert dict into hashtable: %d\n", __func__, ret);
		__free_dict(dict);
		return NULL;
	}

	return dict;
}
EXPORT_SYMBOL_GPL(new_dict_entry);

static void free_dict(void *ptr, void *arg)
{
	struct nf_conn_dict * dict = (struct nf_conn_dict *)ptr;

	call_rcu(&dict->rcu_head, dict_context_free);
}

struct nf_conn_dict * find_conntrack_dict(u8 *key, u32 key_len, char *table)
{
	struct nf_conn_dict * dict;
	struct rhlist_head * list;
	struct dict_hash_cmp_arg arg = {
		.key = key,
		.key_len = key_len,
		.table = table,
	};

	rcu_read_lock();
	list = rhltable_lookup(&hlt, &arg, dict_rhashtable_params);
	dict = container_of(list, struct nf_conn_dict, list);
	rcu_read_unlock();

	return dict;
}

/* called within rcu read lock */
struct nf_conn_dict_entry_elem * find_conntrack_dict_entry(u8 *key, u32 key_len, char *table, char * field)
{
	struct nf_conn_dict * temp;
	struct rhlist_head * tmp, * list;
	struct dict_hash_cmp_arg arg = {
		.key = key,
		.key_len = key_len,
		.table = table,
	};
	u32 hash = 0;

	if(field) {
		hash = jhash(field, strlen(field), 0);
	}

	list = rhltable_lookup(&hlt, &arg, dict_rhashtable_params);
	rhl_for_each_entry_rcu(temp, tmp, list, list) {
		if(hash == temp->field->hash) {
			return temp->value;
		}
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(find_conntrack_dict_entry);

void destroy_dict_entry(u8 *key, u32 key_len, char *table, char *field)
{
	struct nf_conn_dict * temp;
	struct rhlist_head * tmp, * list;
	struct dict_hash_cmp_arg arg = {
		.key = key,
		.key_len = key_len,
		.table = table,
	};
	u32 hash = 0;
	int ret;

	if(field) {
		hash = jhash(field, strlen(field), 0);
	}

	rcu_read_lock();
	list = rhltable_lookup(&hlt, &arg, dict_rhashtable_params);
	rhl_for_each_entry_rcu(temp, tmp, list, list) {
		if(hash == temp->field->hash) {
			ret = rhltable_remove(&hlt, tmp, dict_rhashtable_params);
			if(ret < 0) {
				pr_err("%s: Unable to remove entry from hashtable: %d\n", __func__, ret);
				continue;
			}
			call_rcu(&temp->rcu_head, dict_context_free);
		}
	}
	rcu_read_unlock();

	return;
}

void destroy_dict(u8 *key, u32 key_len, char *table)
{
	struct nf_conn_dict * dict;
	int ret;

	rcu_read_lock();
	while((dict = find_conntrack_dict(key, key_len, table))) {
		ret = rhltable_remove(&hlt, &dict->list, dict_rhashtable_params);
		if(ret < 0) {
			pr_err("%s: Unable to remove entry from hashtable: %d\n", __func__, ret);
			continue;
		}
		call_rcu(&dict->rcu_head, dict_context_free);
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(destroy_dict);

static int show_dict(struct seq_file *m, struct nf_conn_dict *dict)
{
	if(dict->table) {
		seq_printf(m, "table: %s ", dict->table->buf);
	} else {
		seq_printf(m, "table: None ");
	}

	if(dict->key->printfn) {
		seq_printf(m, "key_");
		(dict->key->printfn)(m, dict->key->buf);
		seq_printf(m, " ");
	}

	seq_printf(m, "field: %s ", dict->field->buf);

	if(dict->value->printfn) {
		(dict->value->printfn)(m, dict->value->buf);
		seq_printf(m, "\n");
	}
	return 0;
}

static int all_dict_show(struct seq_file *m, void *v)
{
	struct rhltable *hlt = (struct rhltable *)m->private;
	struct rhashtable_iter hti;
	struct nf_conn_dict *dict;

	rhltable_walk_enter(hlt, &hti);
	rhashtable_walk_start(&hti);

	while ((dict = rhashtable_walk_next(&hti)) && !IS_ERR(dict)) {
		show_dict(m, dict);
	}

	rhashtable_walk_stop(&hti);
	rhashtable_walk_exit(&hti);

	return 0;
}

static int all_dict_open(struct inode *inode, struct file *file)
{
	return single_open(file, all_dict_show, PDE_DATA(inode));
}

static const struct file_operations all_dict_file_ops = {
	.owner   = THIS_MODULE,
	.open    = all_dict_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int write_show(struct seq_file *m, void *v)
{
	return 0;
}

static int write_open(struct inode *inode, struct file *file)
{
	return single_open(file, write_show, PDE_DATA(inode));
}

enum {
	Opt_key_int,
	Opt_key_ip,
	Opt_key_ip6,
	Opt_key_mac,
	Opt_key_string,
	Opt_field,
	Opt_string,
	Opt_ip,
	Opt_ip6,
	Opt_mac,
	Opt_bool,
	Opt_int,
	Opt_int64,
	Opt_table,
	Opt_err,
};

static const match_table_t tokens = {
	{Opt_key_int, "key_int=%u"},
	{Opt_key_ip, "key_ip=%s"},
	{Opt_key_ip6, "key_ip6=%s"},
	{Opt_key_mac, "key_mac=%s"},
	{Opt_key_string, "key_string=%s"},
	{Opt_field, "field=%s"},
	{Opt_string, "value=%s"},
	{Opt_string, "string=%s"},
	{Opt_ip, "ip=%s"},
	{Opt_ip6, "ip6=%s"},
	{Opt_mac, "mac=%s"},
	{Opt_bool, "bool=%s"},
	{Opt_int, "int=%d"},
	{Opt_int64, "int64=%s"},
	{Opt_table, "table=%s"},
	{Opt_err, NULL},
};

static int match_u64int(substring_t *s, u64 *result)
{
	char *buf;
	int ret;
	u64 val;
	size_t len = s->to - s->from;

	buf = kmalloc(len + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memcpy(buf, s->from, len);
	buf[len] = '\0';

	ret = kstrtoull(buf, 0, &val);
	if(!ret)
		*result = val;

	kfree(buf);
	return ret;
}

static int match_uint(substring_t *s, unsigned int *result)
{
	char *buf;
	int ret;
	unsigned int val;
	size_t len = s->to - s->from;

	buf = kmalloc(len + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memcpy(buf, s->from, len);
	buf[len] = '\0';

	ret = kstrtouint(buf, 0, &val);
	if(!ret)
		*result = val;

	kfree(buf);
	return ret;
}

void seq_print_ip(struct seq_file *m, char *buf)
{
	seq_printf(m, "ip: %pI4", buf);
}
EXPORT_SYMBOL(seq_print_ip);

void seq_print_ip6(struct seq_file *m, char *buf)
{
	seq_printf(m, "ip6: %pI6", buf);
}
EXPORT_SYMBOL(seq_print_ip6);

void seq_print_mac(struct seq_file *m, char *buf)
{
	seq_printf(m, "mac: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
}
EXPORT_SYMBOL(seq_print_mac);

void seq_print_string(struct seq_file *m, char *buf)
{
	seq_printf(m, "string: %s", buf);
}
EXPORT_SYMBOL(seq_print_string);

void seq_print_bool(struct seq_file *m, char *buf)
{
	if(buf[0] == 1) {
		seq_printf(m, "bool: true");
	} else {
		seq_printf(m, "bool: false");
	}
}
EXPORT_SYMBOL(seq_print_bool);

void seq_print_integer(struct seq_file *m, char *buf)
{
	seq_printf(m, "int: %u", *(int *)buf);
}
EXPORT_SYMBOL(seq_print_integer);

void seq_print_integer64(struct seq_file *m, char *buf)
{
	seq_printf(m, "int64: %llu", *(u64 *)buf);
}
EXPORT_SYMBOL(seq_print_integer64);

static ssize_t write_dict(struct file *file, const char __user *buf, size_t size, loff_t *pos)
{
	u8 key[128];
	char *orig, *local_buf, *p, *field = NULL, *value = NULL, *ip = NULL, *table = NULL, *string_value = NULL;
	unsigned int len = 0, key_len = 0, integer = 0;
	u64 integer64 = 0;
	u8 addr[4] = {0,0,0,0};
	u8 addr6[16] = {0,0,0,0,
			0,0,0,0,
			0,0,0,0,
			0,0,0,0};
	u8 mac[6] = {0,0,0,0,0,0};
	u8 val = 0;
	substring_t args[MAX_OPT_ARGS];
	seq_printfn_t printfn = NULL;
	seq_printfn_t key_printfn = NULL;

	memset(key, 0, sizeof(key));

	orig = local_buf = kzalloc(size + 1, GFP_KERNEL);
	if(!local_buf) {
		pr_err("%s: Could not allocate local buffer!\n", __func__);
		goto err;
	}

	if (copy_from_user(local_buf, buf, size) != 0) {
		pr_err("%s: copy_from_user failed!\n", __func__);
		goto free_local_buf;
	}

	while ((p = strsep(&local_buf, ","))) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
			case Opt_key_int:
				{
					unsigned int temp, ret = 0;
					ret = match_uint(&args[0], &temp);
					if(ret) {
						pr_err("%s: Opt_key_int failed %d\n", __func__, ret);
						goto free_local_buf;
					}
					key_len = sizeof(temp);
					memcpy(key, &temp, key_len);
					key_printfn = &seq_print_integer;
					break;
				}
			case Opt_key_ip:
				{
					char *temp;
					temp = match_strdup(&args[0]);
					in4_pton(temp, -1, key, -1, NULL);
					key_len = 4;
					kfree(temp);
					key_printfn = &seq_print_ip;
					break;
				}
			case Opt_key_ip6:
				{
					char *temp;
					temp = match_strdup(&args[0]);
					in6_pton(temp, -1, key, -1, NULL);
					key_len = 16;
					kfree(temp);
					key_printfn = &seq_print_ip6;
					break;
				}
			case Opt_key_mac:
				{
					char *temp;
					temp = match_strdup(&args[0]);
					sscanf(temp, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &key[0], &key[1], &key[2], &key[3], &key[4], &key[5]);
					key_len = 6;
					kfree(temp);
					key_printfn = &seq_print_mac;
					break;
				}
			case Opt_key_string:
				{
					char *temp;
					temp = match_strdup(&args[0]);
					key_len = strlen(temp);
					memcpy(key, temp, key_len);
					kfree(temp);
					key_printfn = &seq_print_string;
					break;
				}
			case Opt_field:
				{
					field = match_strdup(&args[0]);
					break;
				}
			case Opt_string:
				{
					string_value = match_strdup(&args[0]);
					value = string_value;
					len = strlen(value);
					printfn = &seq_print_string;
					break;
				}
			case Opt_ip:
				{
					ip = match_strdup(&args[0]);
					in4_pton(ip, -1, addr, -1, NULL);
					value = addr;
					len = sizeof(addr);
					printfn = &seq_print_ip;
					kfree(ip);
					break;
				}
			case Opt_ip6:
				{
					ip = match_strdup(&args[0]);
					in6_pton(ip, -1, addr6, -1, NULL);
					value = addr6;
					len = sizeof(addr6);
					printfn = &seq_print_ip6;
					kfree(ip);
					break;
				}
			case Opt_mac:
				{
					ip = match_strdup(&args[0]);
					sscanf(ip, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
					value = mac;
					len = sizeof(mac);
					printfn = &seq_print_mac;
					kfree(ip);
					break;
				}
			case Opt_bool:
				{
					ip = match_strdup(&args[0]);
					if(!strcmp(ip, "true")) {
						val = 1;
					} else if (!strcmp(ip, "false")) {
						val = 0;
					} else {
						kfree(ip);
						pr_err("%s: Opt_true true or false required\n", __func__);
						goto free_local_buf;
					}
					value = &val;
					len = 1;
					printfn = &seq_print_bool;
					kfree(ip);
					break;
				}
			case Opt_int:
				{
					int ret = 0;
					ret = match_int(&args[0], &integer);
					if(ret) {
						pr_err("%s: Opt_int failed %d\n", __func__, ret);
						goto free_local_buf;
					}
					value = (char *)&integer;
					len = sizeof(int);
					printfn = &seq_print_integer;
					break;
				}
			case Opt_int64:
				{
					int ret = 0;
					ret = match_u64int(&args[0], &integer64);
					if(ret) {
						pr_err("%s: Opt_int64 failed %d\n", __func__, ret);
						goto free_local_buf;
					}
					value = (char *)&integer64;
					len = sizeof(u64);
					printfn = &seq_print_integer64;
					break;
				}
			case Opt_table:
				{
					table = match_strdup(&args[0]);
					break;
				}
			default:
				pr_err("unrecognized option \"%s\" "
				       "or missing value\n", p);
				break;
		}
	}

	if(key_len != 0 && field && value && len != 0) {
		new_dict_entry(key, key_len, table, key_printfn, field, value, len, printfn);
	} else {
		pr_err("%s: Insuffient input\n", __func__);
	}

	kfree(field);
	if(string_value)
		kfree(string_value);
	if(table)
		kfree(table);
free_local_buf:
	kfree(orig);
err:
	return size;
}

static const struct file_operations write_file_ops = {
	.owner   = THIS_MODULE,
	.open    = write_open,
	.read    = seq_read,
	.write   = write_dict,
	.llseek  = seq_lseek,
	.release = single_release,
};

static char read_key[128];
static int read_key_len = 0;
static char read_table[128];
static u32 read_field_hash = 0;
static int read_show(struct seq_file *m, void *v)
{
	char * field = NULL;
	struct nf_conn_dict * temp;
	struct rhlist_head * tmp, * list;
	struct dict_hash_cmp_arg arg = {
		.key = read_key,
		.key_len = read_key_len,
		.table = read_table,
	};

	rcu_read_lock();
	list = rhltable_lookup(&hlt, &arg, dict_rhashtable_params);
	rhl_for_each_entry_rcu(temp, tmp, list, list) {
		if(read_field_hash != 0 && (read_field_hash == temp->field->hash)) {
			show_dict(m, temp);
		} else if(!field) {
			show_dict(m, temp);
		}
	}
	rcu_read_unlock();

	return 0;
}

static int read_open(struct inode *inode, struct file *file)
{
	return single_open(file, read_show, PDE_DATA(inode));
}

static ssize_t read_id_write(struct file *file, const char __user *buf, size_t size, loff_t *pos)
{
	u8 key[128];
	char * orig, * local_buf, * p,* table = NULL, * field = NULL;
	substring_t args[MAX_OPT_ARGS];
	unsigned int key_len = 0;

	memset(key, 0, sizeof(key));

	orig = local_buf = kzalloc(size + 1, GFP_KERNEL);
	if(!local_buf) {
		pr_err("%s: Could not allocate local buffer!\n", __func__);
		goto err;
	}

	if (copy_from_user(local_buf, buf, size) != 0) {
		pr_err("%s: copy_from_user failed!\n", __func__);
		goto free_local_buf;
	}

	while ((p = strsep(&local_buf, ","))) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
			case Opt_key_int:
				{
					unsigned int temp, ret = 0;
					ret = match_uint(&args[0], &temp);
					if(ret) {
						pr_err("%s: Opt_key_int failed %d\n", __func__, ret);
						goto free_local_buf;
					}
					key_len = sizeof(temp);
					memcpy(key, &temp, key_len);
					break;
				}
			case Opt_key_ip:
				{
					char *temp;
					temp = match_strdup(&args[0]);
					in4_pton(temp, -1, key, -1, NULL);
					key_len = 4;
					kfree(temp);
					break;
				}
			case Opt_key_ip6:
				{
					char *temp;
					temp = match_strdup(&args[0]);
					in6_pton(temp, -1, key, -1, NULL);
					key_len = 16;
					kfree(temp);
					break;
				}
			case Opt_key_mac:
				{
					char *temp;
					temp = match_strdup(&args[0]);
					sscanf(temp, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &key[0], &key[1], &key[2], &key[3], &key[4], &key[5]);
					key_len = 6;
					kfree(temp);
					break;
				}
			case Opt_key_string:
				{
					char *temp;
					temp = match_strdup(&args[0]);
					key_len = strlen(temp);
					memcpy(key, temp, key_len);
					kfree(temp);
					break;
				}
			case Opt_table:
				{
					table = match_strdup(&args[0]);
					break;
				}
			case Opt_field:
				{
					field = match_strdup(&args[0]);
					break;
				}
			default:
				pr_err("unrecognized option \"%s\" "
				       "or missing value\n", p);
				break;
		}
	}

	memcpy(read_key, key, key_len);
	read_key_len = key_len;
	strcpy(read_table, table);
	if(field) {
		read_field_hash = jhash(field, strlen(field), 0);
		kfree(field);
	} else {
		read_field_hash = 0;
	}

	if(table)
		kfree(table);
free_local_buf:
	kfree(orig);
err:
	return size;
}

static const struct file_operations read_file_ops = {
	.owner   = THIS_MODULE,
	.open    = read_open,
	.read    = seq_read,
	.write   = read_id_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

static ssize_t delete_write(struct file *file, const char __user *buf, size_t size, loff_t *pos)
{
	u8 key[128];
	char * orig, * local_buf, * p,* table = NULL, * field = NULL;
	substring_t args[MAX_OPT_ARGS];
	unsigned int key_len = 0;

	memset(key, 0, sizeof(key));

	orig = local_buf = kzalloc(size + 1, GFP_KERNEL);
	if(!local_buf) {
		pr_err("%s: Could not allocate local buffer!\n", __func__);
		goto err;
	}

	if (copy_from_user(local_buf, buf, size) != 0) {
		pr_err("%s: copy_from_user failed!\n", __func__);
		goto free_local_buf;
	}

	while ((p = strsep(&local_buf, ","))) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
			case Opt_key_int:
				{
					unsigned int temp, ret = 0;
					ret = match_uint(&args[0], &temp);
					if(ret) {
						pr_err("%s: Opt_key_int failed %d\n", __func__, ret);
						goto free_local_buf;
					}
					key_len = sizeof(temp);
					memcpy(key, &temp, key_len);
					break;
				}
			case Opt_key_ip:
				{
					char *temp;
					temp = match_strdup(&args[0]);
					in4_pton(temp, -1, key, -1, NULL);
					key_len = 4;
					kfree(temp);
					break;
				}
			case Opt_key_ip6:
				{
					char *temp;
					temp = match_strdup(&args[0]);
					in6_pton(temp, -1, key, -1, NULL);
					key_len = 16;
					kfree(temp);
					break;
				}
			case Opt_key_mac:
				{
					char *temp;
					temp = match_strdup(&args[0]);
					sscanf(temp, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &key[0], &key[1], &key[2], &key[3], &key[4], &key[5]);
					key_len = 6;
					kfree(temp);
					break;
				}
			case Opt_key_string:
				{
					char *temp;
					temp = match_strdup(&args[0]);
					key_len = strlen(temp);
					memcpy(key, temp, key_len);
					kfree(temp);
					break;
				}
			case Opt_field:
				{
					field = match_strdup(&args[0]);
					break;
				}
			case Opt_table:
				{
					table = match_strdup(&args[0]);
					break;
				}
			default:
				pr_err("unrecognized option \"%s\" "
				       "or missing value\n", p);
				break;
		}
	}

	if(field) {
		destroy_dict_entry(key, key_len, table, field);
		kfree(field);
	} else {
		destroy_dict(key, key_len, table);
	}

	if(table)
		kfree(table);
free_local_buf:
	kfree(orig);
err:
	return size;
}

static int delete_show(struct seq_file *m, void *v)
{
	return 0;
}

static int delete_open(struct inode *inode, struct file *file)
{
	return single_open(file, delete_show, PDE_DATA(inode));
}

static const struct file_operations delete_file_ops = {
	.owner   = THIS_MODULE,
	.open    = delete_open,
	.read    = seq_read,
	.write   = delete_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int __net_init dict_net_init(struct net *net)
{
	int ret = 0;
	struct proc_dir_entry * temp;

	dict_dir = proc_net_mkdir(net, "dict", net->proc_net);
	if (!dict_dir) {
		pr_err("cannot create dict proc entry");
		return -ENOMEM;
	}

	temp = proc_create_data("all", 0440, dict_dir, &all_dict_file_ops, &hlt);
	if (!temp) {
		pr_err("cannot create all proc");
		remove_proc_entry("dict", net->proc_net);
		return -ENOMEM;
	}

	temp = proc_create_data("write", 0440, dict_dir, &write_file_ops, NULL);
	if (!temp) {
		remove_proc_entry("all", dict_dir);
		pr_err("cannot create write proc");
		return -ENOMEM;
	}

	temp = proc_create_data("read", 0440, dict_dir, &read_file_ops, NULL);
	if (!temp) {
		remove_proc_entry("write", dict_dir);
		remove_proc_entry("all", dict_dir);
		pr_err("cannot create read proc");
		return -ENOMEM;
	}

	temp = proc_create_data("delete", 0440, dict_dir, &delete_file_ops, NULL);
	if (!temp) {
		remove_proc_entry("read", dict_dir);
		remove_proc_entry("write", dict_dir);
		remove_proc_entry("all", dict_dir);
		pr_err("cannot create delete proc");
		return -ENOMEM;
	}


	return ret;
}

static void __net_exit dict_net_exit(struct net *net)
{
	remove_proc_entry("delete", dict_dir);
	remove_proc_entry("read", dict_dir);
	remove_proc_entry("write", dict_dir);
	remove_proc_entry("all", dict_dir);
	remove_proc_entry("dict", net->proc_net);
}

static struct pernet_operations dict_net_ops = {
	.init = dict_net_init,
	.exit = dict_net_exit,
};

void dict_exit(void)
{
	unregister_pernet_subsys(&dict_net_ops);
	rhltable_free_and_destroy(&hlt, free_dict, NULL);
}

int dict_init(void)
{
	int err = 0;

	err = rhltable_init(&hlt, &dict_rhashtable_params);
	if(err < 0) {
		pr_err("%s: Unable to initialize hashtable: %d\n", __func__, err);
		goto err;
	}

	err = register_pernet_subsys(&dict_net_ops);
	if (err) {
		goto err_destroy_rhashtable;
	}

	return 0;

err_destroy_rhashtable:
	rhltable_free_and_destroy(&hlt, free_dict, NULL);
err:
	return err;
}

MODULE_AUTHOR("Brett Mastbergen <bmastbergen@untangle.com>");
MODULE_DESCRIPTION("Conntrack dict support");
MODULE_LICENSE("GPL");

module_init(dict_init);
module_exit(dict_exit);
