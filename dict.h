#include <linux/types.h>
#include <linux/rhashtable.h>

#define NFTA_DICT_MAX (__NFTA_DICT_MAX - 1)

typedef void (*seq_printfn_t)(struct seq_file *m, char *buf);

struct nf_conn_dict_entry_elem {
	char * buf;
	int len;
	u32 hash;
	seq_printfn_t printfn;
};

struct nf_conn_dict * new_dict_entry(u8 *key, u32 key_len, char *table, seq_printfn_t key_printfn,
				char * field, char * value, u32 len, seq_printfn_t printfn);
void seq_print_ip(struct seq_file *m, char *buf);
void seq_print_ip6(struct seq_file *m, char *buf);
void seq_print_mac(struct seq_file *m, char *buf);
void seq_print_string(struct seq_file *m, char *buf);
void seq_print_bool(struct seq_file *m, char *buf);
void seq_print_integer(struct seq_file *m, char *buf);
void seq_print_integer64(struct seq_file *m, char *buf);
void destroy_dict(u8 *key, u32 key_len, char *table);
struct nf_conn_dict_entry_elem * find_conntrack_dict_entry(u8 *key, u32 key_len, char *table, char * field);
