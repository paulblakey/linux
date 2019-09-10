// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* -
 * net/sched/act_ct.c  Connection Tracking action
 *
 * Authors:   Paul Blakey <paulb@mellanox.com>
 *            Yossi Kuperman <yossiku@mellanox.com>
 *            Marcelo Ricardo Leitner <marcelo.leitner@gmail.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/rhashtable.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/act_api.h>
#include <net/ip.h>
#include <net/ipv6_frag.h>
#include <uapi/linux/tc_act/tc_ct.h>
#include <net/tc_act/tc_ct.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
#include <uapi/linux/netfilter/nf_nat.h>

static struct tc_action_ops act_ct_ops;
static unsigned int ct_net_id;

struct tc_ct_action_net {
	struct tc_action_net tn; /* Must be first */
	bool labels;
};

static void flow_offload_fixup_tcp(struct ip_ct_tcp *tcp)
{
	tcp->seen[0].td_maxwin = 0;
	tcp->seen[1].td_maxwin = 0;
}

static void flow_offload_fixup_ct_state(struct nf_conn *ct, bool start)
{
	const struct nf_conntrack_l4proto *l4proto;
	unsigned int timeout;
	int l4num;

	l4num = nf_ct_protonum(ct);
	if (l4num == IPPROTO_TCP) {
		if (start) {
			flow_offload_fixup_tcp(&ct->proto.tcp);
			ct->proto.tcp.state = TCP_CONNTRACK_ESTABLISHED;
		}
	}

	if (start)
		return;

	l4proto = nf_ct_l4proto_find(l4num);
	if (!l4proto)
		return;

#define NF_FLOWTABLE_TCP_PICKUP_TIMEOUT	(30 * HZ)
#define NF_FLOWTABLE_UDP_PICKUP_TIMEOUT	(30 * HZ)
	if (l4num == IPPROTO_TCP)
		timeout = NF_FLOWTABLE_TCP_PICKUP_TIMEOUT;
	else if (l4num == IPPROTO_UDP)
		timeout = NF_FLOWTABLE_UDP_PICKUP_TIMEOUT;
	else
		return;

	ct->timeout = nfct_time_stamp + timeout;
}

static int tcf_ct_setup_cb_call(struct flow_block *block, enum tc_setup_type type,
				void *type_data)
{
	struct flow_block_cb *block_cb;
	int ok_count = 0;
	int err;

	printk(KERN_ERR "%s %d %s @@ calling cbs of block: %px, \n", __FILE__, __LINE__, __func__, block);
	list_for_each_entry(block_cb, &block->cb_list, list) {
		printk(KERN_ERR "%s %d %s @@ block: %px, cb: %px\n", __FILE__, __LINE__, __func__, block, block_cb->cb);
		err = block_cb->cb(type, type_data, block_cb->cb_priv);
		printk(KERN_ERR "%s %d %s @@ block: %px, cb: %px, returned err: %d\n", __FILE__, __LINE__, __func__, block, block_cb->cb, err);
		if (err < 0)
			continue;
		ok_count++;
	}

	return ok_count;
}

struct ct_flow_table_match_key {
	struct flow_dissector_key_control control;
	struct flow_dissector_key_basic basic;
	union {
		struct flow_dissector_key_ipv4_addrs ipv4;
		struct flow_dissector_key_ipv6_addrs ipv6;
	};
	struct flow_dissector_key_ports tp;
} __aligned(BITS_PER_LONG / 8); /* Ensure that we can do comparisons as longs. */

struct ct_flow_table_match {
	struct rhash_head node;
	struct ct_flow_table_match_key key;
	enum ip_conntrack_dir dir;
};

static const struct rhashtable_params match_params = {
	.head_offset = offsetof(struct ct_flow_table_match, node),
	.key_offset = offsetof(struct ct_flow_table_match, key),
	.key_len = sizeof(((struct ct_flow_table_match *)0)->key),
	.automatic_shrinking = true,
};

struct ct_flow_table_entry {
	struct ct_flow_table_match match[IP_CT_DIR_MAX];
	struct flow_dissector dissector;
	struct ct_flow_table *ft;
	struct nf_conn *ct;
	u64 lastused;
};

static int tcf_ct_build_flow_action(struct flow_action *action,
				    struct nf_conn *ct,
				    enum ip_conntrack_dir dir)
{
	struct nf_conntrack_tuple *tuple = &ct->tuplehash[dir].tuple;
	int *num_entries = &action->num_entries;
	struct nf_conntrack_tuple target;
	struct flow_action_entry *entry;
	struct nf_conn_labels *cl;

	nf_ct_invert_tuple(&target, &ct->tuplehash[!dir].tuple);

	*num_entries = 0;

	entry = &action->entries[*num_entries];
	entry->id = FLOW_ACTION_CT_METADATA;
	entry->ct_metadata.zone = ct->zone.id;
	entry->ct_metadata.mark = ct->mark;
	cl = nf_ct_labels_find(ct);
	if (cl) {
		u32 *ct_labels = entry->ct_metadata.labels;

		memcpy(ct_labels, cl->bits, NF_CT_LABELS_MAX_SIZE);
	} else {
		u32 *ct_labels = entry->ct_metadata.labels;

		memset(ct_labels, 0, NF_CT_LABELS_MAX_SIZE);
	}

	++(*num_entries);
	entry = &action->entries[*num_entries];

	printk(KERN_ERR "%s %d %s @@ ct: %px, dir: %d, [orig: %pI4:%d %pI4:%d][reply: %pI4:%d %pI4:%d][tuple: %pI4:%d %pI4:%d][target: %pI4:%d %pI4:%d]\n",
	       __FILE__, __LINE__, __func__,
		ct, dir,
		&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
		ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port),
		&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
		ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port),

		&ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
		ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port),
		&ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
		ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port),


		&tuple->src.u3.ip,
		ntohs(tuple->src.u.tcp.port),
		&tuple->dst.u3.ip,
		ntohs(tuple->dst.u.tcp.port),

		&target.src.u3.ip,
		ntohs(target.src.u.tcp.port),
		&target.dst.u3.ip,
		ntohs(target.dst.u.tcp.port)
	);
	/* SRC NAT:
	 * orig  src=5.5.5.5 dst=5.5.5.6 sport=2001 dport=3002 (invert the other dir, target: src=5.5.5.7:8738, dst=5.5.5.6:3002)
	 * reply src=5.5.5.6 dst=5.5.5.7 sport=3002 dport=8738 (invert the other dir, target: src=5.5.5.6:3002, dst=5.5.5.5:2001)
	 */
	if (memcmp(&target.src.u3, &tuple->src.u3, sizeof(target.src.u3))) {
		printk(KERN_ERR "%s %d %s @@ ct: 5tuple: dir: %d, IPs %pI4, %pI4 ports %d, %d @ doing src nat to: [IPs %pI4, %pI4 ports %d, %d]\n",
				__FILE__, __LINE__, __func__,
				dir,
				&tuple->src.u3.ip,
				&tuple->dst.u3.ip,
				ntohs(tuple->src.u.udp.port),
				ntohs(tuple->dst.u.udp.port),
				&target.src.u3.ip,
				&target.dst.u3.ip,
				ntohs(target.src.u.udp.port),
				ntohs(target.dst.u.udp.port));

		/* Need to change src to target src */
		entry->id = FLOW_ACTION_MANGLE;
		entry->mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_IP4;
		entry->mangle.mask = ~(0xFFFFFFFF);
		entry->mangle.offset = offsetof(struct iphdr, saddr);
		entry->mangle.val = htonl(target.src.u3.ip);
		++(*num_entries);
		entry = &action->entries[*num_entries];
	} else if (memcmp(&target.dst.u3, &tuple->dst.u3, sizeof(target.dst.u3))) {
		printk(KERN_ERR "%s %d %s @@ ct: 5tuple: dir: %d, IPs %pI4, %pI4 ports %d, %d @ doing dst nat to: [IPs %pI4, %pI4 ports %d, %d]\n",
				__FILE__, __LINE__, __func__,
				dir,
				&tuple->src.u3.ip,
				&tuple->dst.u3.ip,
				ntohs(tuple->src.u.udp.port),
				ntohs(tuple->dst.u.udp.port),
				&target.src.u3.ip,
				&target.dst.u3.ip,
				ntohs(target.src.u.udp.port),
				ntohs(target.dst.u.udp.port));

		entry->id = FLOW_ACTION_MANGLE;
		entry->mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_IP4;
		entry->mangle.mask = ~(0xFFFFFFFF);
		entry->mangle.offset = offsetof(struct iphdr, daddr);
		entry->mangle.val = htonl(target.dst.u3.ip);
		++(*num_entries);
		entry = &action->entries[*num_entries];
	}

	if (target.src.u.tcp.port != tuple->src.u.tcp.port) {
		printk(KERN_ERR "%s %d %s @@ ct: 5tuple: dir: %d, IPs %pI4, %pI4 ports %d, %d @ doing src nat to: [IPs %pI4, %pI4 ports %d, %d]\n",
				__FILE__, __LINE__, __func__,
				dir,
				&tuple->src.u3.ip,
				&tuple->dst.u3.ip,
				ntohs(tuple->src.u.udp.port),
				ntohs(tuple->dst.u.udp.port),
				&target.src.u3.ip,
				&target.dst.u3.ip,
				ntohs(target.src.u.udp.port),
				ntohs(target.dst.u.udp.port));
		entry->id = FLOW_ACTION_MANGLE;
		entry->mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_TCP;
		entry->mangle.mask = ~(0xFFFF);
		entry->mangle.offset = offsetof(struct tcphdr, source);
		entry->mangle.val = htons(target.src.u.tcp.port);
		++(*num_entries);
		entry = &action->entries[*num_entries];
	} else if (target.dst.u.tcp.port != tuple->dst.u.tcp.port) {
		printk(KERN_ERR "%s %d %s @@ ct: 5tuple: dir: %d, IPs %pI4, %pI4 ports %d, %d @ doing dst nat to: [IPs %pI4, %pI4 ports %d, %d]\n",
				__FILE__, __LINE__, __func__,
				dir,
				&tuple->src.u3.ip,
				&tuple->dst.u3.ip,
				ntohs(tuple->src.u.udp.port),
				ntohs(tuple->dst.u.udp.port),
				&target.src.u3.ip,
				&target.dst.u3.ip,
				ntohs(target.src.u.udp.port),
				ntohs(target.dst.u.udp.port));
		entry->id = FLOW_ACTION_MANGLE;
		entry->mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_TCP;
		entry->mangle.mask = ~(0xFFFF);
		entry->mangle.offset = offsetof(struct tcphdr, dest);
		entry->mangle.val = htons(target.dst.u.tcp.port);
		++(*num_entries);
		entry = &action->entries[*num_entries];
	}

	printk(KERN_ERR "%s %d %s @@ ct: %px, dir: %d num entries: %d\n", __FILE__, __LINE__, __func__, ct, dir, *num_entries);

	return 0;
}

static int tcf_ct_notify_cmd_add(struct ct_flow_table *ft,
				 struct ct_flow_table_entry *entry)
{
	struct ct_flow_offload ct_flow = {};
	struct flow_action *action;
	struct flow_match *match;
	int err, ok_count;

	ct_flow.command = CT_FLOW_ADD;
	ct_flow.block = &ft->block;
	ct_flow.ct = entry->ct;
	ct_flow.ft = ft;

	match = &ct_flow.rule.match;
	match->dissector = &entry->dissector;
	action = &ct_flow.rule.action;

	ct_flow.dir = IP_CT_DIR_ORIGINAL;
	match->key = &entry->match[ct_flow.dir].key;
	ct_flow.cookie = (unsigned long) &entry->match[ct_flow.dir];
	err = tcf_ct_build_flow_action(action, ct_flow.ct, ct_flow.dir);
	if (err)
		return err;
	err = tcf_ct_setup_cb_call(&ft->block, TC_SETUP_CT, &ct_flow);
	printk(KERN_ERR "%s %d %s @@ ft: %px entry: %px, ct: %px, err orig: %d\n", __FILE__, __LINE__, __func__, ft, entry, entry->ct, err);
	if (err < 0)
		return err;
	ok_count += err;

	ct_flow.dir = IP_CT_DIR_REPLY;
	match->key = &entry->match[ct_flow.dir].key;
	ct_flow.cookie = (unsigned long) &entry->match[ct_flow.dir];
	err = tcf_ct_build_flow_action(action, ct_flow.ct, ct_flow.dir);
	if (err)
		return ok_count;
	err = tcf_ct_setup_cb_call(&ft->block, TC_SETUP_CT, &ct_flow);
	printk(KERN_ERR "%s %d %s @@ ft: %px entry: %px, ct: %px, err reply: %d\n", __FILE__, __LINE__, __func__, ft, entry, entry->ct, err);
	if (err < 0)
		return ok_count;
	ok_count += err;

	return ok_count;
}

static void tcf_ct_notify_cmd_del(struct ct_flow_table *ft,
				  struct ct_flow_table_entry *entry)
{
	struct ct_flow_offload ct_flow = {};

	printk(KERN_ERR "%s %d %s @@ ft: %px entry: %px, ct: %px\n", __FILE__, __LINE__, __func__, ft, entry, entry->ct);

	ct_flow.command = CT_FLOW_DEL;
	ct_flow.block = &ft->block;
	ct_flow.ct = entry->ct;
	ct_flow.ft = ft;

	ct_flow.dir = IP_CT_DIR_ORIGINAL;
	ct_flow.cookie = (unsigned long) &entry->match[IP_CT_DIR_ORIGINAL];
	tcf_ct_setup_cb_call(&ft->block, TC_SETUP_CT, &ct_flow);

	ct_flow.dir = IP_CT_DIR_REPLY;
	ct_flow.cookie = (unsigned long) &entry->match[IP_CT_DIR_REPLY];
	tcf_ct_setup_cb_call(&ft->block, TC_SETUP_CT, &ct_flow);
}

static int tcf_ct_notify_cmd_stats(struct ct_flow_table *ft,
				   struct ct_flow_table_entry *entry)
{
	struct ct_flow_offload ct_flow = {};
	struct nf_conn *ct = entry->ct;
	u64 lastused;
	u32 timeout;

	ct_flow.command = CT_FLOW_STATS;
	ct_flow.block = &ft->block;
	ct_flow.ct = entry->ct;
	ct_flow.ft = ft;

	ct_flow.dir = IP_CT_DIR_ORIGINAL;
	ct_flow.cookie = (unsigned long) &entry->match[IP_CT_DIR_ORIGINAL];
	tcf_ct_setup_cb_call(&ft->block, TC_SETUP_CT, &ct_flow);

	ct_flow.dir = IP_CT_DIR_REPLY;
	ct_flow.cookie = (unsigned long) &entry->match[IP_CT_DIR_REPLY];
	tcf_ct_setup_cb_call(&ft->block, TC_SETUP_CT, &ct_flow);

	printk(KERN_ERR "%s %d %s @@ ct: %px use: %d, status: %lu\n", __FILE__, __LINE__, __func__,
		       ct, ct->ct_general.use, ct->status);

	lastused = ct_flow.stats.lastused;
	if (lastused > entry->lastused) {
		printk(KERN_ERR "%s %d %s @@ ft: %px entry: %px, ct: %px, new lastuse: %lu (%d secs ago)\n", __FILE__, __LINE__, __func__, ft, entry, entry->ct, lastused, jiffies_to_msecs(lastused - jiffies)/1000);
		entry->lastused = lastused;

		timeout = lastused + (HZ * 30);
		if (timeout > ct->timeout)
			ct->timeout = timeout;
	}

	return 0;
}

static int tcf_fill_match_key(struct ct_flow_table_match_key *key,
			      struct nf_conntrack_tuple *tuple)
{
	memset(key, 0, sizeof(*key));

	if (tuple->src.l3num == NFPROTO_IPV4) {
		key->control.addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS;
		key->basic.n_proto = htons(ETH_P_IP);
		key->ipv4.src = tuple->src.u3.ip;
		key->ipv4.dst = tuple->dst.u3.ip;
	} else if (tuple->src.l3num == NFPROTO_IPV6) {
		key->control.addr_type = FLOW_DISSECTOR_KEY_IPV6_ADDRS;
		key->basic.n_proto = htons(ETH_P_IPV6);
		key->ipv6.src = tuple->src.u3.in6;
		key->ipv6.dst = tuple->dst.u3.in6;
	} else {
		return -EOPNOTSUPP;
	}

	switch (tuple->dst.protonum) {
	case IPPROTO_UDP:
		key->basic.ip_proto = IPPROTO_UDP;
		key->tp.src = tuple->src.u.udp.port;
		key->tp.dst = tuple->dst.u.udp.port;
		break;
	case IPPROTO_TCP:
		key->basic.ip_proto = IPPROTO_TCP;
		key->tp.src = tuple->src.u.tcp.port;
		key->tp.dst = tuple->dst.u.tcp.port;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
};

static int tcf_ct_flow_add_match(struct ct_flow_table_entry *entry,
				 enum ip_conntrack_dir dir)
{
	struct nf_conntrack_tuple *tuple = &entry->ct->tuplehash[dir].tuple;
	struct ct_flow_table_match_key *key = &entry->match[dir].key;
	struct ct_flow_table_match *match = &entry->match[dir];
	struct ct_flow_table *ft = entry->ft;
	int err;

	match->dir = dir;
	err = tcf_fill_match_key(key, tuple);
	if (err)
		return err;

	err = rhashtable_insert_fast(&ft->table, &match->node, match_params);
	if (err)
		return err;

	return 0;
}

static void tcf_ct_flow_remove_match(struct ct_flow_table_entry *entry,
				     enum ip_conntrack_dir dir)
{
	struct ct_flow_table_match *match = &entry->match[dir];
	struct ct_flow_table *ft = entry->ft;

	rhashtable_remove_fast(&ft->table, &match->node, match_params);
}

static void tcf_ct_flow_del(struct ct_flow_table_entry *entry);
static int tcf_ct_notify(struct ct_flow_table *ft,
			 struct nf_conn *ct,
			 bool del);
static int tcf_ct_offload_handler(struct nf_conn *ct,
				  enum offload_event offload_event,
				  void *priv)
{
	struct ct_flow_table_entry *entry = priv;
	struct ct_flow_table *ft = entry->ft;

	switch (offload_event) {
		case OFFLOAD_STATS:
			printk(KERN_ERR "%s %d %s @@ STATS: ft: %px, entry: %px ct: %px\n", __FILE__, __LINE__, __func__, ft, entry, ct);
			tcf_ct_notify_cmd_stats(ft, entry);
			return 0;
		case OFFLOAD_DEL:
			printk(KERN_ERR "%s %d %s @@ DEL: ft: %px, entry: %px ct: %px\n", __FILE__, __LINE__, __func__, ft, entry, ct);
			tcf_ct_notify(ft, entry->ct, true);
			return 0;
		default:
			return -EOPNOTSUPP;
	};

	return 0;
}

static int tcf_ct_flow_add(struct ct_flow_table *ft, struct nf_conn *ct)
{
	struct ct_flow_table_entry *entry;
	int err;

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		WARN_ON_ONCE(1);
		return -ENOMEM;
	}
	/* ft is taken for duration of add(), by tcf_ct_notify() before
	 * add work is queued.
	 */
	entry->ft = ft;
	entry->ct = ct;
	entry->lastused = jiffies;
	flow_offload_fixup_ct_state(ct, true);

	printk(KERN_ERR "%s %d %s @@ ft: %px entry: %px, ct: %px\n", __FILE__, __LINE__, __func__, ft, entry, entry->ct);

#define SET_RULE_DISSECTOR(entry, keyid, key_member) \
	entry->dissector.used_keys |= (1 << keyid); \
	entry->dissector.offset[keyid] = offsetof(struct ct_flow_table_match_key, \
						  key_member);
	SET_RULE_DISSECTOR(entry, FLOW_DISSECTOR_KEY_CONTROL, control);
	SET_RULE_DISSECTOR(entry, FLOW_DISSECTOR_KEY_BASIC, basic);
	SET_RULE_DISSECTOR(entry, FLOW_DISSECTOR_KEY_PORTS, tp);
	SET_RULE_DISSECTOR(entry, FLOW_DISSECTOR_KEY_IPV4_ADDRS, ipv4);

	err = tcf_ct_flow_add_match(entry, IP_CT_DIR_ORIGINAL);
	printk(KERN_ERR "%s %d %s @@ ft: %px entry: %px, ct: %px, err: %d\n", __FILE__, __LINE__, __func__, ft, entry, entry->ct, err);
	if (err)
		goto err_match;
	err = tcf_ct_flow_add_match(entry, IP_CT_DIR_REPLY);
	printk(KERN_ERR "%s %d %s @@ ft: %px entry: %px, ct: %px, err: %d\n", __FILE__, __LINE__, __func__, ft, entry, entry->ct, err);
	if (err)
		goto err_match_reply;

	err = tcf_ct_notify_cmd_add(entry->ft, entry);
	printk(KERN_ERR "%s %d %s @@ ft: %px entry: %px, ct: %px, err: %d\n", __FILE__, __LINE__, __func__, ft, entry, entry->ct, err);
	if (err < 0)
		goto err_notify;

	nf_conntrack_get(&entry->ct->ct_general);
	ct->offload_priv = entry;
	rcu_assign_pointer(ct->offload_handler, tcf_ct_offload_handler);
	entry->ft->ref++;

	printk(KERN_ERR "%s %d %s @@ ft: %px entry: %px, ct: %px, err: %d\n", __FILE__, __LINE__, __func__, ft, entry, entry->ct, 0);
	return 0;

err_notify:
err_match_reply:
	tcf_ct_flow_remove_match(entry, IP_CT_DIR_ORIGINAL);
err_match:
	kfree(entry);
	return err;
}

static void tcf_ct_put_flow_table(struct ct_flow_table *ft);
static void tcf_ct_flow_del(struct ct_flow_table_entry *entry)
{
	struct ct_flow_table *ft = entry->ft;
	struct nf_conn *ct = entry->ct;

	printk(KERN_ERR "%s %d %s @@ DEL: ft: %px, entry: %px ct: %px\n", __FILE__, __LINE__, __func__, ft, entry, ct);

	ct->offload_priv = NULL;
	RCU_INIT_POINTER(ct->offload_handler, NULL);
	clear_bit(IPS_OFFLOAD_BIT, &ct->status);

	tcf_ct_notify_cmd_del(ft, entry);

	tcf_ct_flow_remove_match(entry, IP_CT_DIR_REPLY);
	tcf_ct_flow_remove_match(entry, IP_CT_DIR_ORIGINAL);
	kfree(entry);

	/* This might put module */
	tcf_ct_put_flow_table(ft);
	nf_conntrack_put(&ct->ct_general);

	flow_offload_fixup_ct_state(ct, false);
}

static void tcf_ct_flow_del_by_ct(struct ct_flow_table *ft, struct nf_conn *ct)
{
	struct ct_flow_table_match_key key;
	struct ct_flow_table_match *match;
	struct ct_flow_table_entry *entry;
	struct nf_conntrack_tuple *tuple;
	enum ip_conntrack_dir dir;
	int err;

	dir = IP_CT_DIR_ORIGINAL;
	tuple = &ct->tuplehash[dir].tuple;
	err = tcf_fill_match_key(&key, tuple);
	if (err)
		return;

	match = rhashtable_lookup_fast(&ft->table, &key, match_params);
	if (!match) {
		dir = IP_CT_DIR_REPLY;
		tuple = &ct->tuplehash[dir].tuple;
		err = tcf_fill_match_key(&key, tuple);
		if (err)
			return;
		match = rhashtable_lookup_fast(&ft->table, &key, match_params);
	}

	if (!match) {
		printk(KERN_ERR "%s %d %s @@ not found ct %px in ft: %px to delete\n", __FILE__, __LINE__, __func__, ct, ft);
		return;
	}
	printk(KERN_ERR "%s %d %s @@ found match %px, dir: %d found ct %px in ft: %px to delete\n", __FILE__, __LINE__, __func__, match, match->dir, ct, ft);

	entry = container_of(match, struct ct_flow_table_entry,
			     match[match->dir]);
	tcf_ct_flow_del(entry);
}

struct act_ct_work {
	struct work_struct work;
	struct ct_flow_table *ft;
	struct nf_conn *ct;
	bool del;
};

static void _tcf_ct_work(struct act_ct_work *work)
{
	int err;

	printk(KERN_ERR "%s %d %s @@ ft: %px, ct: %px established work, del: %d\n", __FILE__, __LINE__, __func__, work->ft, work->ct, work->del);

	if (!work->del) {
		err = tcf_ct_flow_add(work->ft, work->ct);
		printk(KERN_ERR "%s %d %s @@ ft: %px, ct: %px established work, del: %d, err: %d\n", __FILE__, __LINE__, __func__, work->ft, work->ct, work->del, err);
		if (err)
			clear_bit(IPS_OFFLOAD_BIT, &work->ct->status);
		return;
	}

	/* work->del */
	tcf_ct_flow_del_by_ct(work->ft, work->ct);
}

static void tcf_ct_work(struct work_struct *works)
{
	struct act_ct_work *work = container_of(works,
						struct act_ct_work, work);

	printk(KERN_ERR "%s %d %s @@ ft: %px, ct: %px established work\n", __FILE__, __LINE__, __func__, work->ft, work->ct);
	_tcf_ct_work(work);
	nf_conntrack_put(&work->ct->ct_general);
	tcf_ct_put_flow_table(work->ft);
}


static int tcf_ct_notify(struct ct_flow_table *ft,
			 struct nf_conn *ct,
			 bool del)
{
	struct act_ct_work *work;

	if (!del) {
		/* Register our offload handler callback that will
		 * set the offload bit */
		if (test_and_set_bit(IPS_OFFLOAD_BIT, &ct->status)) {
			ct->timeout = nfct_time_stamp + (HZ * 30);
			printk(KERN_ERR "%s %d %s @@ ft: %px, ct: %px established is already offloaded\n", __FILE__, __LINE__, __func__, ft, ct);
			return -EEXIST;
		}
	} else {
		if (!test_and_clear_bit(IPS_OFFLOAD_BIT, &ct->status)) {
			printk(KERN_ERR "%s %d %s @@ ft: %px, ct: %px established, del in progress or not offloaded\n", __FILE__, __LINE__, __func__, ft, ct);
			return -EEXIST;
		}
	}

	work = kzalloc(sizeof(*work), GFP_ATOMIC);
	if (!work) {
		WARN_ON_ONCE(1);
		if (!del)
			clear_bit(IPS_OFFLOAD_BIT, &ct->status);
		else
			set_bit(IPS_OFFLOAD_BIT, &ct->status);
		return -ENOMEM;
	}

	INIT_WORK(&work->work, tcf_ct_work);
	work->del = del;
	work->ft = ft;
	work->ct = ct;
	ft->ref++;

	nf_conntrack_get(&ct->ct_general);
	if (!schedule_work(&work->work)) {
		WARN_ON_ONCE(1);
		if (!del)
			clear_bit(IPS_OFFLOAD_BIT, &ct->status);
		else
			set_bit(IPS_OFFLOAD_BIT, &ct->status);
		nf_conntrack_put(&ct->ct_general);
		kfree(work);
		ft->ref--;
	}

	printk(KERN_ERR "%s %d %s @@ ft: %px, ct: %px established, queued event: %d\n", __FILE__, __LINE__, __func__, ft, ct, del);
	return 0;
}


static int tcf_ct_notify_packet(struct ct_flow_table *ft,
				struct nf_conn *ct,
				enum ip_conntrack_info ctinfo)
{
	bool del = false;

	if (!ft)
		return 0;

	switch (ctinfo) {
		case IP_CT_ESTABLISHED:
		case IP_CT_ESTABLISHED_REPLY:
			break;
		default:
			return 0;
	}

	switch (nf_ct_protonum(ct)) {
		case IPPROTO_TCP:
			if (ct->proto.tcp.state < TCP_CONNTRACK_ESTABLISHED)
				return 0;
			if (ct->proto.tcp.state > TCP_CONNTRACK_ESTABLISHED)
				del = true;
			break;
		case IPPROTO_UDP:
			break;
		default:
			return -EOPNOTSUPP;
	}

	return tcf_ct_notify(ft, ct, del);
}

static const struct rhashtable_params zones_params = {
	.head_offset = offsetof(struct ct_flow_table, node),
	.key_offset = offsetof(struct ct_flow_table, zone),
	.key_len = sizeof(((struct ct_flow_table *)0)->zone),
	.automatic_shrinking = true,
};

static struct rhashtable zones_ht;

static int tcf_ct_create_flow_table(struct net *net, struct tcf_ct *c)
{
	struct tcf_ct_params *params;
	struct ct_flow_table *ft;
	int err;

	params = rcu_dereference_protected(c->params, 1);
	if (!params->zone)
		return 0;

	printk(KERN_ERR "%s %d %s @@ find zone %d\n", __FILE__, __LINE__, __func__, params->zone);
	ft = rhashtable_lookup_fast(&zones_ht, &params->zone, zones_params);
	printk(KERN_ERR "%s %d %s @@ find zone %d, ft: %px\n", __FILE__, __LINE__, __func__, params->zone, ft);
	if (ft)
		goto take_ref;

	ft = kzalloc(sizeof(*ft), GFP_KERNEL);
	if (!ft)
		return -ENOMEM;
	ft->zone = params->zone;

	err = rhashtable_init(&ft->table, &match_params);
	if (err)
		goto init_err;

	err = rhashtable_insert_fast(&zones_ht, &ft->node, zones_params);
	if (err)
		goto insert_err;

	printk(KERN_ERR "%s %d %s @@ ft: %px, init flow block: %px\n", __FILE__, __LINE__, __func__, ft, &ft->block);
	flow_block_init(&ft->block);
	printk(KERN_ERR "%s %d %s @@ get_module for ft: %px\n", __FILE__, __LINE__, __func__, ft);
	__module_get(THIS_MODULE);

take_ref:
	c->ft = ft;
	ft->ref++;
	printk(KERN_ERR "%s %d %s @@ act_ct: %px got ft: %px, ref after inc: %d\n", __FILE__, __LINE__, __func__, c, c->ft, c->ft->ref);

	return 0;

insert_err:
	rhashtable_destroy(&ft->table);
init_err:
	kfree(ft);
	return 0;
}

static void tcf_ct_put_flow_table_work(struct work_struct *work)
{
	struct ct_flow_table *ft = container_of(to_rcu_work(work),
						struct ct_flow_table, rwork);

	rhashtable_remove_fast(&zones_ht, &ft->node, zones_params);
	rhashtable_destroy(&ft->table);
	kfree(ft);

	printk(KERN_ERR "%s %d %s @@ put module, after ft: %px\n", __FILE__, __LINE__, __func__, ft);
	module_put(THIS_MODULE);
}

static void tcf_ct_put_flow_table(struct ct_flow_table *ft)
{
	printk(KERN_ERR "%s %d %s @@ ft: %px, ref before dec: %d\n", __FILE__, __LINE__, __func__, ft, ft ? ft->ref : -1);
	if (!ft || ft->ref == 0 || --ft->ref > 0)
		return;

	tcf_queue_work(&ft->rwork, tcf_ct_put_flow_table_work);
}

/* Determine whether skb->_nfct is equal to the result of conntrack lookup. */
static bool tcf_ct_skb_nfct_cached(struct net *net, struct sk_buff *skb,
				   u16 zone_id, bool force)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return false;
	if (!net_eq(net, read_pnet(&ct->ct_net)))
		return false;
	if (nf_ct_zone(ct)->id != zone_id)
		return false;

	/* Force conntrack entry direction. */
	if (force && CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		if (nf_ct_is_confirmed(ct))
			nf_ct_kill(ct);

		nf_conntrack_put(&ct->ct_general);
		nf_ct_set(skb, NULL, IP_CT_UNTRACKED);

		return false;
	}

	return true;
}

/* Trim the skb to the length specified by the IP/IPv6 header,
 * removing any trailing lower-layer padding. This prepares the skb
 * for higher-layer processing that assumes skb->len excludes padding
 * (such as nf_ip_checksum). The caller needs to pull the skb to the
 * network header, and ensure ip_hdr/ipv6_hdr points to valid data.
 */
static int tcf_ct_skb_network_trim(struct sk_buff *skb, int family)
{
	unsigned int len;
	int err;

	switch (family) {
	case NFPROTO_IPV4:
		len = ntohs(ip_hdr(skb)->tot_len);
		break;
	case NFPROTO_IPV6:
		len = sizeof(struct ipv6hdr)
			+ ntohs(ipv6_hdr(skb)->payload_len);
		break;
	default:
		len = skb->len;
	}

	err = pskb_trim_rcsum(skb, len);

	return err;
}

static u8 tcf_ct_skb_nf_family(struct sk_buff *skb)
{
	u8 family = NFPROTO_UNSPEC;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		family = NFPROTO_IPV4;
		break;
	case htons(ETH_P_IPV6):
		family = NFPROTO_IPV6;
		break;
	default:
		break;
	}

	return family;
}

static int tcf_ct_ipv4_is_fragment(struct sk_buff *skb, bool *frag)
{
	unsigned int len;

	len =  skb_network_offset(skb) + sizeof(struct iphdr);
	if (unlikely(skb->len < len))
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, len)))
		return -ENOMEM;

	*frag = ip_is_fragment(ip_hdr(skb));
	return 0;
}

static int tcf_ct_ipv6_is_fragment(struct sk_buff *skb, bool *frag)
{
	unsigned int flags = 0, len, payload_ofs = 0;
	unsigned short frag_off;
	int nexthdr;

	len =  skb_network_offset(skb) + sizeof(struct ipv6hdr);
	if (unlikely(skb->len < len))
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, len)))
		return -ENOMEM;

	nexthdr = ipv6_find_hdr(skb, &payload_ofs, -1, &frag_off, &flags);
	if (unlikely(nexthdr < 0))
		return -EPROTO;

	*frag = flags & IP6_FH_F_FRAG;
	return 0;
}

static int tcf_ct_handle_fragments(struct net *net, struct sk_buff *skb,
				   u8 family, u16 zone)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	int err = 0;
	bool frag;

	/* Previously seen (loopback)? Ignore. */
	ct = nf_ct_get(skb, &ctinfo);
	if ((ct && !nf_ct_is_template(ct)) || ctinfo == IP_CT_UNTRACKED)
		return 0;

	if (family == NFPROTO_IPV4)
		err = tcf_ct_ipv4_is_fragment(skb, &frag);
	else
		err = tcf_ct_ipv6_is_fragment(skb, &frag);
	if (err || !frag)
		return err;

	skb_get(skb);

	if (family == NFPROTO_IPV4) {
		enum ip_defrag_users user = IP_DEFRAG_CONNTRACK_IN + zone;

		memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
		local_bh_disable();
		err = ip_defrag(net, skb, user);
		local_bh_enable();
		if (err && err != -EINPROGRESS)
			goto out_free;
	} else { /* NFPROTO_IPV6 */
#if IS_ENABLED(CONFIG_NF_DEFRAG_IPV6)
		enum ip6_defrag_users user = IP6_DEFRAG_CONNTRACK_IN + zone;

		memset(IP6CB(skb), 0, sizeof(struct inet6_skb_parm));
		err = nf_ct_frag6_gather(net, skb, user);
		if (err && err != -EINPROGRESS)
			goto out_free;
#else
		err = -EOPNOTSUPP;
		goto out_free;
#endif
	}

	skb_clear_hash(skb);
	skb->ignore_df = 1;
	return err;

out_free:
	kfree_skb(skb);
	return err;
}

static void tcf_ct_params_free(struct rcu_head *head)
{
	struct tcf_ct_params *params = container_of(head,
						    struct tcf_ct_params, rcu);

	if (params->tmpl)
		nf_conntrack_put(&params->tmpl->ct_general);
	kfree(params);
}

#if IS_ENABLED(CONFIG_NF_NAT)
/* Modelled after nf_nat_ipv[46]_fn().
 * range is only used for new, uninitialized NAT state.
 * Returns either NF_ACCEPT or NF_DROP.
 */
static int ct_nat_execute(struct sk_buff *skb, struct nf_conn *ct,
			  enum ip_conntrack_info ctinfo,
			  const struct nf_nat_range2 *range,
			  enum nf_nat_manip_type maniptype)
{
	int hooknum, err = NF_ACCEPT;

	/* See HOOK2MANIP(). */
	if (maniptype == NF_NAT_MANIP_SRC)
		hooknum = NF_INET_LOCAL_IN; /* Source NAT */
	else
		hooknum = NF_INET_LOCAL_OUT; /* Destination NAT */

	switch (ctinfo) {
	case IP_CT_RELATED:
	case IP_CT_RELATED_REPLY:
		if (skb->protocol == htons(ETH_P_IP) &&
		    ip_hdr(skb)->protocol == IPPROTO_ICMP) {
			if (!nf_nat_icmp_reply_translation(skb, ct, ctinfo,
							   hooknum))
				err = NF_DROP;
			goto out;
		} else if (IS_ENABLED(CONFIG_IPV6) &&
			   skb->protocol == htons(ETH_P_IPV6)) {
			__be16 frag_off;
			u8 nexthdr = ipv6_hdr(skb)->nexthdr;
			int hdrlen = ipv6_skip_exthdr(skb,
						      sizeof(struct ipv6hdr),
						      &nexthdr, &frag_off);

			if (hdrlen >= 0 && nexthdr == IPPROTO_ICMPV6) {
				if (!nf_nat_icmpv6_reply_translation(skb, ct,
								     ctinfo,
								     hooknum,
								     hdrlen))
					err = NF_DROP;
				goto out;
			}
		}
		/* Non-ICMP, fall thru to initialize if needed. */
		/* fall through */
	case IP_CT_NEW:
		/* Seen it before?  This can happen for loopback, retrans,
		 * or local packets.
		 */
		if (!nf_nat_initialized(ct, maniptype)) {
			/* Initialize according to the NAT action. */
			err = (range && range->flags & NF_NAT_RANGE_MAP_IPS)
				/* Action is set up to establish a new
				 * mapping.
				 */
				? nf_nat_setup_info(ct, range, maniptype)
				: nf_nat_alloc_null_binding(ct, hooknum);
			if (err != NF_ACCEPT)
				goto out;
		}
		break;

	case IP_CT_ESTABLISHED:
	case IP_CT_ESTABLISHED_REPLY:
		break;

	default:
		err = NF_DROP;
		goto out;
	}

	err = nf_nat_packet(ct, ctinfo, hooknum, skb);
out:
	return err;
}
#endif /* CONFIG_NF_NAT */

static void tcf_ct_act_set_mark(struct nf_conn *ct, u32 mark, u32 mask)
{
#if IS_ENABLED(CONFIG_NF_CONNTRACK_MARK)
	u32 new_mark;

	if (!mask)
		return;

	new_mark = mark | (ct->mark & ~(mask));
	if (ct->mark != new_mark) {
		ct->mark = new_mark;
		if (nf_ct_is_confirmed(ct))
			nf_conntrack_event_cache(IPCT_MARK, ct);
	}
#endif
}

static void tcf_ct_act_set_labels(struct nf_conn *ct,
				  u32 *labels,
				  u32 *labels_m)
{
#if IS_ENABLED(CONFIG_NF_CONNTRACK_LABELS)
	size_t labels_sz = FIELD_SIZEOF(struct tcf_ct_params, labels);

	if (!memchr_inv(labels_m, 0, labels_sz))
		return;

	nf_connlabels_replace(ct, labels, labels_m, 4);
#endif
}

static int tcf_ct_act_nat(struct sk_buff *skb,
			  struct nf_conn *ct,
			  enum ip_conntrack_info ctinfo,
			  int ct_action,
			  struct nf_nat_range2 *range,
			  bool commit)
{
#if IS_ENABLED(CONFIG_NF_NAT)
	enum nf_nat_manip_type maniptype;

	if (!(ct_action & TCA_CT_ACT_NAT))
		return NF_ACCEPT;

	/* Add NAT extension if not confirmed yet. */
	if (!nf_ct_is_confirmed(ct) && !nf_ct_nat_ext_add(ct))
		return NF_DROP;   /* Can't NAT. */

	if (ctinfo != IP_CT_NEW && (ct->status & IPS_NAT_MASK) &&
	    (ctinfo != IP_CT_RELATED || commit)) {
		/* NAT an established or related connection like before. */
		if (CTINFO2DIR(ctinfo) == IP_CT_DIR_REPLY)
			/* This is the REPLY direction for a connection
			 * for which NAT was applied in the forward
			 * direction.  Do the reverse NAT.
			 */
			maniptype = ct->status & IPS_SRC_NAT
				? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC;
		else
			maniptype = ct->status & IPS_SRC_NAT
				? NF_NAT_MANIP_SRC : NF_NAT_MANIP_DST;
	} else if (ct_action & TCA_CT_ACT_NAT_SRC) {
		maniptype = NF_NAT_MANIP_SRC;
	} else if (ct_action & TCA_CT_ACT_NAT_DST) {
		maniptype = NF_NAT_MANIP_DST;
	} else {
		return NF_ACCEPT;
	}

	return ct_nat_execute(skb, ct, ctinfo, range, maniptype);
#else
	return NF_ACCEPT;
#endif
}

static int tcf_ct_act(struct sk_buff *skb, const struct tc_action *a,
		      struct tcf_result *res)
{
	struct net *net = dev_net(skb->dev);
	bool cached, commit, clear, force;
	enum ip_conntrack_info ctinfo;
	struct tcf_ct *c = to_ct(a);
	struct nf_conn *tmpl = NULL;
	struct nf_hook_state state;
	int nh_ofs, err, retval;
	struct tcf_ct_params *p;
	struct nf_conn *ct;
	u8 family;

	p = rcu_dereference_bh(c->params);

	retval = READ_ONCE(c->tcf_action);
	commit = p->ct_action & TCA_CT_ACT_COMMIT;
	clear = p->ct_action & TCA_CT_ACT_CLEAR;
	force = p->ct_action & TCA_CT_ACT_FORCE;
	tmpl = p->tmpl;

	if (clear) {
		ct = nf_ct_get(skb, &ctinfo);
		if (ct) {
			nf_conntrack_put(&ct->ct_general);
			nf_ct_set(skb, NULL, IP_CT_UNTRACKED);
		}

		goto out;
	}

	family = tcf_ct_skb_nf_family(skb);
	if (family == NFPROTO_UNSPEC)
		goto drop;

	/* The conntrack module expects to be working at L3.
	 * We also try to pull the IPv4/6 header to linear area
	 */
	nh_ofs = skb_network_offset(skb);
	skb_pull_rcsum(skb, nh_ofs);
	err = tcf_ct_handle_fragments(net, skb, family, p->zone);
	if (err == -EINPROGRESS) {
		retval = TC_ACT_STOLEN;
		goto out;
	}
	if (err)
		goto drop;

	err = tcf_ct_skb_network_trim(skb, family);
	if (err)
		goto drop;

	/* If we are recirculating packets to match on ct fields and
	 * committing with a separate ct action, then we don't need to
	 * actually run the packet through conntrack twice unless it's for a
	 * different zone.
	 */
	cached = tcf_ct_skb_nfct_cached(net, skb, p->zone, force);
	if (!cached) {
		/* Associate skb with specified zone. */
		if (tmpl) {
			ct = nf_ct_get(skb, &ctinfo);
			if (skb_nfct(skb))
				nf_conntrack_put(skb_nfct(skb));
			nf_conntrack_get(&tmpl->ct_general);
			nf_ct_set(skb, tmpl, IP_CT_NEW);
		}

		state.hook = NF_INET_PRE_ROUTING;
		state.net = net;
		state.pf = family;
		err = nf_conntrack_in(skb, &state);
		if (err != NF_ACCEPT)
			goto out_push;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		goto out_push;
	nf_ct_deliver_cached_events(ct);

	err = tcf_ct_act_nat(skb, ct, ctinfo, p->ct_action, &p->range, commit);
	if (err != NF_ACCEPT)
		goto drop;

	if (!test_bit(IPS_OFFLOAD_BIT, &ct->status) &&
			ct->offload_handler) {
		printk(KERN_ERR "%s %d %s @@ ct: %px, has handler %px, without bit: %lu\n", __FILE__, __LINE__, __func__, ct, ct->offload_handler, ct->status);
	}

	if (commit) {
		tcf_ct_act_set_mark(ct, p->mark, p->mark_mask);
		tcf_ct_act_set_labels(ct, p->labels, p->labels_mask);

		/* This will take care of sending queued events
		 * even if the connection is already confirmed.
		 */
		nf_conntrack_confirm(skb);

		if (ct->offload_handler) {
			printk(KERN_ERR "%s %d %s @@ commit %px, with handler %px, alreayd exists\n", __FILE__, __LINE__, __func__, ct, ct->offload_handler);
			ct->offload_handler = NULL;
		}
	}

	tcf_ct_notify_packet(c->ft, ct, ctinfo);

out_push:
	skb_push_rcsum(skb, nh_ofs);

out:
	bstats_cpu_update(this_cpu_ptr(a->cpu_bstats), skb);
	return retval;

drop:
	qstats_drop_inc(this_cpu_ptr(a->cpu_qstats));
	return TC_ACT_SHOT;
}

static const struct nla_policy ct_policy[TCA_CT_MAX + 1] = {
	[TCA_CT_UNSPEC] = { .strict_start_type = TCA_CT_UNSPEC + 1 },
	[TCA_CT_ACTION] = { .type = NLA_U16 },
	[TCA_CT_PARMS] = { .type = NLA_EXACT_LEN, .len = sizeof(struct tc_ct) },
	[TCA_CT_ZONE] = { .type = NLA_U16 },
	[TCA_CT_MARK] = { .type = NLA_U32 },
	[TCA_CT_MARK_MASK] = { .type = NLA_U32 },
	[TCA_CT_LABELS] = { .type = NLA_BINARY,
			    .len = 128 / BITS_PER_BYTE },
	[TCA_CT_LABELS_MASK] = { .type = NLA_BINARY,
				 .len = 128 / BITS_PER_BYTE },
	[TCA_CT_NAT_IPV4_MIN] = { .type = NLA_U32 },
	[TCA_CT_NAT_IPV4_MAX] = { .type = NLA_U32 },
	[TCA_CT_NAT_IPV6_MIN] = { .type = NLA_EXACT_LEN,
				  .len = sizeof(struct in6_addr) },
	[TCA_CT_NAT_IPV6_MAX] = { .type = NLA_EXACT_LEN,
				   .len = sizeof(struct in6_addr) },
	[TCA_CT_NAT_PORT_MIN] = { .type = NLA_U16 },
	[TCA_CT_NAT_PORT_MAX] = { .type = NLA_U16 },
};

static int tcf_ct_fill_params_nat(struct tcf_ct_params *p,
				  struct tc_ct *parm,
				  struct nlattr **tb,
				  struct netlink_ext_ack *extack)
{
	struct nf_nat_range2 *range;

	if (!(p->ct_action & TCA_CT_ACT_NAT))
		return 0;

	if (!IS_ENABLED(CONFIG_NF_NAT)) {
		NL_SET_ERR_MSG_MOD(extack, "Netfilter nat isn't enabled in kernel");
		return -EOPNOTSUPP;
	}

	if (!(p->ct_action & (TCA_CT_ACT_NAT_SRC | TCA_CT_ACT_NAT_DST)))
		return 0;

	if ((p->ct_action & TCA_CT_ACT_NAT_SRC) &&
	    (p->ct_action & TCA_CT_ACT_NAT_DST)) {
		NL_SET_ERR_MSG_MOD(extack, "dnat and snat can't be enabled at the same time");
		return -EOPNOTSUPP;
	}

	range = &p->range;
	if (tb[TCA_CT_NAT_IPV4_MIN]) {
		struct nlattr *max_attr = tb[TCA_CT_NAT_IPV4_MAX];

		p->ipv4_range = true;
		range->flags |= NF_NAT_RANGE_MAP_IPS;
		range->min_addr.ip =
			nla_get_in_addr(tb[TCA_CT_NAT_IPV4_MIN]);

		range->max_addr.ip = max_attr ?
				     nla_get_in_addr(max_attr) :
				     range->min_addr.ip;
	} else if (tb[TCA_CT_NAT_IPV6_MIN]) {
		struct nlattr *max_attr = tb[TCA_CT_NAT_IPV6_MAX];

		p->ipv4_range = false;
		range->flags |= NF_NAT_RANGE_MAP_IPS;
		range->min_addr.in6 =
			nla_get_in6_addr(tb[TCA_CT_NAT_IPV6_MIN]);

		range->max_addr.in6 = max_attr ?
				      nla_get_in6_addr(max_attr) :
				      range->min_addr.in6;
	}

	if (tb[TCA_CT_NAT_PORT_MIN]) {
		range->flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
		range->min_proto.all = nla_get_be16(tb[TCA_CT_NAT_PORT_MIN]);

		range->max_proto.all = tb[TCA_CT_NAT_PORT_MAX] ?
				       nla_get_be16(tb[TCA_CT_NAT_PORT_MAX]) :
				       range->min_proto.all;
	}

	return 0;
}

static void tcf_ct_set_key_val(struct nlattr **tb,
			       void *val, int val_type,
			       void *mask, int mask_type,
			       int len)
{
	if (!tb[val_type])
		return;
	nla_memcpy(val, tb[val_type], len);

	if (!mask)
		return;

	if (mask_type == TCA_CT_UNSPEC || !tb[mask_type])
		memset(mask, 0xff, len);
	else
		nla_memcpy(mask, tb[mask_type], len);
}

static int tcf_ct_fill_params(struct net *net,
			      struct tcf_ct_params *p,
			      struct tc_ct *parm,
			      struct nlattr **tb,
			      struct netlink_ext_ack *extack)
{
	struct tc_ct_action_net *tn = net_generic(net, ct_net_id);
	struct nf_conntrack_zone zone;
	struct nf_conn *tmpl;
	int err;

	p->zone = NF_CT_DEFAULT_ZONE_ID;

	tcf_ct_set_key_val(tb,
			   &p->ct_action, TCA_CT_ACTION,
			   NULL, TCA_CT_UNSPEC,
			   sizeof(p->ct_action));

	if (p->ct_action & TCA_CT_ACT_CLEAR)
		return 0;

	err = tcf_ct_fill_params_nat(p, parm, tb, extack);
	if (err)
		return err;

	if (tb[TCA_CT_MARK]) {
		if (!IS_ENABLED(CONFIG_NF_CONNTRACK_MARK)) {
			NL_SET_ERR_MSG_MOD(extack, "Conntrack mark isn't enabled.");
			return -EOPNOTSUPP;
		}
		tcf_ct_set_key_val(tb,
				   &p->mark, TCA_CT_MARK,
				   &p->mark_mask, TCA_CT_MARK_MASK,
				   sizeof(p->mark));
	}

	if (tb[TCA_CT_LABELS]) {
		if (!IS_ENABLED(CONFIG_NF_CONNTRACK_LABELS)) {
			NL_SET_ERR_MSG_MOD(extack, "Conntrack labels isn't enabled.");
			return -EOPNOTSUPP;
		}

		if (!tn->labels) {
			NL_SET_ERR_MSG_MOD(extack, "Failed to set connlabel length");
			return -EOPNOTSUPP;
		}
		tcf_ct_set_key_val(tb,
				   p->labels, TCA_CT_LABELS,
				   p->labels_mask, TCA_CT_LABELS_MASK,
				   sizeof(p->labels));
	}

	if (tb[TCA_CT_ZONE]) {
		if (!IS_ENABLED(CONFIG_NF_CONNTRACK_ZONES)) {
			NL_SET_ERR_MSG_MOD(extack, "Conntrack zones isn't enabled.");
			return -EOPNOTSUPP;
		}

		tcf_ct_set_key_val(tb,
				   &p->zone, TCA_CT_ZONE,
				   NULL, TCA_CT_UNSPEC,
				   sizeof(p->zone));
	}

	if (p->zone == NF_CT_DEFAULT_ZONE_ID)
		return 0;

	nf_ct_zone_init(&zone, p->zone, NF_CT_DEFAULT_ZONE_DIR, 0);
	tmpl = nf_ct_tmpl_alloc(net, &zone, GFP_KERNEL);
	if (!tmpl) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to allocate conntrack template");
		return -ENOMEM;
	}
	__set_bit(IPS_CONFIRMED_BIT, &tmpl->status);
	nf_conntrack_get(&tmpl->ct_general);
	p->tmpl = tmpl;

	return 0;
}

static int tcf_ct_init(struct net *net, struct nlattr *nla,
		       struct nlattr *est, struct tc_action **a,
		       int replace, int bind, bool rtnl_held,
		       struct tcf_proto *tp,
		       struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, ct_net_id);
	struct tcf_ct_params *params = NULL;
	struct nlattr *tb[TCA_CT_MAX + 1];
	struct tcf_chain *goto_ch = NULL;
	struct tc_ct *parm;
	struct tcf_ct *c;
	int err, res = 0;
	u32 index;

	if (!nla) {
		NL_SET_ERR_MSG_MOD(extack, "Ct requires attributes to be passed");
		return -EINVAL;
	}

	err = nla_parse_nested(tb, TCA_CT_MAX, nla, ct_policy, extack);
	if (err < 0)
		return err;

	if (!tb[TCA_CT_PARMS]) {
		NL_SET_ERR_MSG_MOD(extack, "Missing required ct parameters");
		return -EINVAL;
	}
	parm = nla_data(tb[TCA_CT_PARMS]);
	index = parm->index;
	err = tcf_idr_check_alloc(tn, &index, a, bind);
	if (err < 0)
		return err;

	if (!err) {
		err = tcf_idr_create(tn, index, est, a,
				     &act_ct_ops, bind, true);
		if (err) {
			tcf_idr_cleanup(tn, index);
			return err;
		}
		res = ACT_P_CREATED;
	} else {
		if (bind)
			return 0;

		if (!replace) {
			tcf_idr_release(*a, bind);
			return -EEXIST;
		}
	}
	err = tcf_action_check_ctrlact(parm->action, tp, &goto_ch, extack);
	if (err < 0)
		goto cleanup;

	c = to_ct(*a);

	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (unlikely(!params)) {
		err = -ENOMEM;
		goto cleanup;
	}

	err = tcf_ct_fill_params(net, params, parm, tb, extack);
	if (err)
		goto cleanup;

	spin_lock_bh(&c->tcf_lock);
	goto_ch = tcf_action_set_ctrlact(*a, parm->action, goto_ch);
	rcu_swap_protected(c->params, params, lockdep_is_held(&c->tcf_lock));
	spin_unlock_bh(&c->tcf_lock);

	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);
	if (params)
		kfree_rcu(params, rcu);
	if (res == ACT_P_CREATED)
		tcf_idr_insert(tn, *a);

	if (res == ACT_P_CREATED)
		tcf_ct_create_flow_table(net, c);

	return res;

cleanup:
	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);
	kfree(params);
	tcf_idr_release(*a, bind);
	return err;
}

static void tcf_ct_cleanup(struct tc_action *a)
{
	struct tcf_ct_params *params;
	struct tcf_ct *c = to_ct(a);

	params = rcu_dereference_protected(c->params, 1);
	if (params)
		call_rcu(&params->rcu, tcf_ct_params_free);

	tcf_ct_put_flow_table(c->ft);
}

static int tcf_ct_dump_key_val(struct sk_buff *skb,
			       void *val, int val_type,
			       void *mask, int mask_type,
			       int len)
{
	int err;

	if (mask && !memchr_inv(mask, 0, len))
		return 0;

	err = nla_put(skb, val_type, len, val);
	if (err)
		return err;

	if (mask_type != TCA_CT_UNSPEC) {
		err = nla_put(skb, mask_type, len, mask);
		if (err)
			return err;
	}

	return 0;
}

static int tcf_ct_dump_nat(struct sk_buff *skb, struct tcf_ct_params *p)
{
	struct nf_nat_range2 *range = &p->range;

	if (!(p->ct_action & TCA_CT_ACT_NAT))
		return 0;

	if (!(p->ct_action & (TCA_CT_ACT_NAT_SRC | TCA_CT_ACT_NAT_DST)))
		return 0;

	if (range->flags & NF_NAT_RANGE_MAP_IPS) {
		if (p->ipv4_range) {
			if (nla_put_in_addr(skb, TCA_CT_NAT_IPV4_MIN,
					    range->min_addr.ip))
				return -1;
			if (nla_put_in_addr(skb, TCA_CT_NAT_IPV4_MAX,
					    range->max_addr.ip))
				return -1;
		} else {
			if (nla_put_in6_addr(skb, TCA_CT_NAT_IPV6_MIN,
					     &range->min_addr.in6))
				return -1;
			if (nla_put_in6_addr(skb, TCA_CT_NAT_IPV6_MAX,
					     &range->max_addr.in6))
				return -1;
		}
	}

	if (range->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		if (nla_put_be16(skb, TCA_CT_NAT_PORT_MIN,
				 range->min_proto.all))
			return -1;
		if (nla_put_be16(skb, TCA_CT_NAT_PORT_MAX,
				 range->max_proto.all))
			return -1;
	}

	return 0;
}

static inline int tcf_ct_dump(struct sk_buff *skb, struct tc_action *a,
			      int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_ct *c = to_ct(a);
	struct tcf_ct_params *p;

	struct tc_ct opt = {
		.index   = c->tcf_index,
		.refcnt  = refcount_read(&c->tcf_refcnt) - ref,
		.bindcnt = atomic_read(&c->tcf_bindcnt) - bind,
	};
	struct tcf_t t;

	spin_lock_bh(&c->tcf_lock);
	p = rcu_dereference_protected(c->params,
				      lockdep_is_held(&c->tcf_lock));
	opt.action = c->tcf_action;

	if (tcf_ct_dump_key_val(skb,
				&p->ct_action, TCA_CT_ACTION,
				NULL, TCA_CT_UNSPEC,
				sizeof(p->ct_action)))
		goto nla_put_failure;

	if (p->ct_action & TCA_CT_ACT_CLEAR)
		goto skip_dump;

	if (IS_ENABLED(CONFIG_NF_CONNTRACK_MARK) &&
	    tcf_ct_dump_key_val(skb,
				&p->mark, TCA_CT_MARK,
				&p->mark_mask, TCA_CT_MARK_MASK,
				sizeof(p->mark)))
		goto nla_put_failure;

	if (IS_ENABLED(CONFIG_NF_CONNTRACK_LABELS) &&
	    tcf_ct_dump_key_val(skb,
				p->labels, TCA_CT_LABELS,
				p->labels_mask, TCA_CT_LABELS_MASK,
				sizeof(p->labels)))
		goto nla_put_failure;

	if (IS_ENABLED(CONFIG_NF_CONNTRACK_ZONES) &&
	    tcf_ct_dump_key_val(skb,
				&p->zone, TCA_CT_ZONE,
				NULL, TCA_CT_UNSPEC,
				sizeof(p->zone)))
		goto nla_put_failure;

	if (tcf_ct_dump_nat(skb, p))
		goto nla_put_failure;

skip_dump:
	if (nla_put(skb, TCA_CT_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	tcf_tm_dump(&t, &c->tcf_tm);
	if (nla_put_64bit(skb, TCA_CT_TM, sizeof(t), &t, TCA_CT_PAD))
		goto nla_put_failure;
	spin_unlock_bh(&c->tcf_lock);

	return skb->len;
nla_put_failure:
	spin_unlock_bh(&c->tcf_lock);
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_ct_walker(struct net *net, struct sk_buff *skb,
			 struct netlink_callback *cb, int type,
			 const struct tc_action_ops *ops,
			 struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, ct_net_id);

	return tcf_generic_walker(tn, skb, cb, type, ops, extack);
}

static int tcf_ct_search(struct net *net, struct tc_action **a, u32 index)
{
	struct tc_action_net *tn = net_generic(net, ct_net_id);

	return tcf_idr_search(tn, a, index);
}

static void tcf_stats_update(struct tc_action *a, u64 bytes, u32 packets,
			     u64 lastuse, bool hw)
{
	struct tcf_ct *c = to_ct(a);

	_bstats_cpu_update(this_cpu_ptr(a->cpu_bstats), bytes, packets);

	if (hw)
		_bstats_cpu_update(this_cpu_ptr(a->cpu_bstats_hw),
				   bytes, packets);
	c->tcf_tm.lastuse = max_t(u64, c->tcf_tm.lastuse, lastuse);
}

static struct tc_action_ops act_ct_ops = {
	.kind		=	"ct",
	.id		=	TCA_ID_CT,
	.owner		=	THIS_MODULE,
	.act		=	tcf_ct_act,
	.dump		=	tcf_ct_dump,
	.init		=	tcf_ct_init,
	.cleanup	=	tcf_ct_cleanup,
	.walk		=	tcf_ct_walker,
	.lookup		=	tcf_ct_search,
	.stats_update	=	tcf_stats_update,
	.size		=	sizeof(struct tcf_ct),
};

static __net_init int ct_init_net(struct net *net)
{
	unsigned int n_bits = FIELD_SIZEOF(struct tcf_ct_params, labels) * 8;
	struct tc_ct_action_net *tn = net_generic(net, ct_net_id);

	if (nf_connlabels_get(net, n_bits - 1)) {
		tn->labels = false;
		pr_err("act_ct: Failed to set connlabels length");
	} else {
		tn->labels = true;
	}

	return tc_action_net_init(net, &tn->tn, &act_ct_ops);
}

static void __net_exit ct_exit_net(struct list_head *net_list)
{
	struct net *net;

	rtnl_lock();
	list_for_each_entry(net, net_list, exit_list) {
		struct tc_ct_action_net *tn = net_generic(net, ct_net_id);

		if (tn->labels)
			nf_connlabels_put(net);
	}
	rtnl_unlock();

	tc_action_net_exit(net_list, ct_net_id);
}

static struct pernet_operations ct_net_ops = {
	.init = ct_init_net,
	.exit_batch = ct_exit_net,
	.id   = &ct_net_id,
	.size = sizeof(struct tc_ct_action_net),
};

static int __init ct_init_module(void)
{
	int err;

	err = rhashtable_init(&zones_ht, &zones_params);
	if (err)
		return err;

	err = tcf_register_action(&act_ct_ops, &ct_net_ops);
	if (err)
		goto register_err;

	return 0;

register_err:
	rhashtable_destroy(&zones_ht);
	return err;
}

static void __exit ct_cleanup_module(void)
{
	rhashtable_destroy(&zones_ht);
	tcf_unregister_action(&act_ct_ops, &ct_net_ops);
}

module_init(ct_init_module);
module_exit(ct_cleanup_module);
MODULE_AUTHOR("Paul Blakey <paulb@mellanox.com>");
MODULE_AUTHOR("Yossi Kuperman <yossiku@mellanox.com>");
MODULE_AUTHOR("Marcelo Ricardo Leitner <marcelo.leitner@gmail.com>");
MODULE_DESCRIPTION("Connection tracking action");
MODULE_LICENSE("GPL v2");

