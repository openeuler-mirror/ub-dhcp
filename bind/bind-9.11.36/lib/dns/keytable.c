/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */


/*! \file */

#include <config.h>

#include <stdbool.h>

#include <isc/mem.h>
#include <isc/print.h>
#include <isc/refcount.h>
#include <isc/rwlock.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/util.h>

#include <dns/keytable.h>
#include <dns/fixedname.h>
#include <dns/rbt.h>
#include <dns/result.h>

#define KEYTABLE_MAGIC                  ISC_MAGIC('K', 'T', 'b', 'l')
#define VALID_KEYTABLE(kt)              ISC_MAGIC_VALID(kt, KEYTABLE_MAGIC)

#define KEYNODE_MAGIC                   ISC_MAGIC('K', 'N', 'o', 'd')
#define VALID_KEYNODE(kn)               ISC_MAGIC_VALID(kn, KEYNODE_MAGIC)

struct dns_keytable {
	/* Unlocked. */
	unsigned int            magic;
	isc_mem_t               *mctx;
	isc_refcount_t          active_nodes;
	isc_refcount_t          references;
	isc_rwlock_t            rwlock;
	/* Locked by rwlock. */
	dns_rbt_t               *table;
};

struct dns_keynode {
	unsigned int            magic;
	isc_refcount_t          refcount;
	dst_key_t *             key;
	bool           managed;
	struct dns_keynode *    next;
};

static void
free_keynode(void *node, void *arg) {
	dns_keynode_t *keynode = node;
	isc_mem_t *mctx = arg;

	dns_keynode_detachall(mctx, &keynode);
}

isc_result_t
dns_keytable_create(isc_mem_t *mctx, dns_keytable_t **keytablep) {
	dns_keytable_t *keytable;
	isc_result_t result;

	/*
	 * Create a keytable.
	 */

	REQUIRE(keytablep != NULL && *keytablep == NULL);

	keytable = isc_mem_get(mctx, sizeof(*keytable));
	if (keytable == NULL) {
		return (ISC_R_NOMEMORY);
	}

	keytable->table = NULL;
	result = dns_rbt_create(mctx, free_keynode, mctx, &keytable->table);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_keytable;
	}

	result = isc_rwlock_init(&keytable->rwlock, 0, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_rbt;
	}

	result = isc_refcount_init(&keytable->active_nodes, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_rwlock;
	}

	result = isc_refcount_init(&keytable->references, 1);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_active_nodes;
	}

	keytable->mctx = NULL;
	isc_mem_attach(mctx, &keytable->mctx);
	keytable->magic = KEYTABLE_MAGIC;
	*keytablep = keytable;

	return (ISC_R_SUCCESS);

 cleanup_active_nodes:
	isc_refcount_destroy(&keytable->active_nodes);

 cleanup_rwlock:
	isc_rwlock_destroy(&keytable->rwlock);

 cleanup_rbt:
	dns_rbt_destroy(&keytable->table);

 cleanup_keytable:
	isc_mem_putanddetach(&mctx, keytable, sizeof(*keytable));

	return (result);
}

void
dns_keytable_attach(dns_keytable_t *source, dns_keytable_t **targetp) {

	/*
	 * Attach *targetp to source.
	 */

	REQUIRE(VALID_KEYTABLE(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references, NULL);

	*targetp = source;
}

void
dns_keytable_detach(dns_keytable_t **keytablep) {
	dns_keytable_t *keytable;
	unsigned int refs;

	/*
	 * Detach *keytablep from its keytable.
	 */

	REQUIRE(keytablep != NULL && VALID_KEYTABLE(*keytablep));

	keytable = *keytablep;
	*keytablep = NULL;

	isc_refcount_decrement(&keytable->references, &refs);
	if (refs == 0) {
		INSIST(isc_refcount_current(&keytable->active_nodes) == 0);
		isc_refcount_destroy(&keytable->active_nodes);
		isc_refcount_destroy(&keytable->references);
		dns_rbt_destroy(&keytable->table);
		isc_rwlock_destroy(&keytable->rwlock);
		keytable->magic = 0;
		isc_mem_putanddetach(&keytable->mctx,
				     keytable, sizeof(*keytable));
	}
}

static isc_result_t
insert(dns_keytable_t *keytable, bool managed,
       dns_name_t *keyname, dst_key_t **keyp)
{
	isc_result_t result;
	dns_keynode_t *knode = NULL;
	dns_rbtnode_t *node;

	REQUIRE(keyp == NULL || *keyp != NULL);
	REQUIRE(VALID_KEYTABLE(keytable));

	result = dns_keynode_create(keytable->mctx, &knode);
	if (result != ISC_R_SUCCESS)
		return (result);

	knode->managed = managed;

	RWLOCK(&keytable->rwlock, isc_rwlocktype_write);

	node = NULL;
	result = dns_rbt_addnode(keytable->table, keyname, &node);

	if (keyp != NULL) {
		if (result == ISC_R_EXISTS) {
			/* Key already in table? */
			dns_keynode_t *k;
			for (k = node->data; k != NULL; k = k->next) {
				if (k->key == NULL) {
					k->key = *keyp;
					*keyp = NULL; /* transfer ownership */
					break;
				}
				if (dst_key_compare(k->key, *keyp) == true)
					break;
			}

			if (k == NULL)
				result = ISC_R_SUCCESS;
			else if (*keyp != NULL)
				dst_key_free(keyp);
		}

		if (result == ISC_R_SUCCESS) {
			knode->key = *keyp;
			knode->next = node->data;
			*keyp = NULL;
		}
	}

	if (result == ISC_R_SUCCESS) {
		node->data = knode;
		knode = NULL;
	}

	/* Key was already there?  That's the same as a success */
	if (result == ISC_R_EXISTS)
		result = ISC_R_SUCCESS;

	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_write);

	if (knode != NULL)
		dns_keynode_detach(keytable->mctx, &knode);

	return (result);
}

isc_result_t
dns_keytable_add(dns_keytable_t *keytable, bool managed,
		 dst_key_t **keyp)
{
	REQUIRE(keyp != NULL && *keyp != NULL);
	return (insert(keytable, managed, dst_key_name(*keyp), keyp));
}

isc_result_t
dns_keytable_marksecure(dns_keytable_t *keytable, dns_name_t *name) {
	return (insert(keytable, true, name, NULL));
}

isc_result_t
dns_keytable_delete(dns_keytable_t *keytable, dns_name_t *keyname) {
	isc_result_t result;
	dns_rbtnode_t *node = NULL;

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(keyname != NULL);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_write);
	result = dns_rbt_findnode(keytable->table, keyname, NULL, &node, NULL,
				  DNS_RBTFIND_NOOPTIONS, NULL, NULL);
	if (result == ISC_R_SUCCESS) {
		if (node->data != NULL)
			result = dns_rbt_deletenode(keytable->table,
						    node, false);
		else
			result = ISC_R_NOTFOUND;
	} else if (result == DNS_R_PARTIALMATCH)
		result = ISC_R_NOTFOUND;
	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_write);

	return (result);
}

isc_result_t
dns_keytable_deletekeynode(dns_keytable_t *keytable, dst_key_t *dstkey) {
	isc_result_t result;
	dns_name_t *keyname;
	dns_rbtnode_t *node = NULL;
	dns_keynode_t *knode = NULL, **kprev = NULL;

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(dstkey != NULL);

	keyname = dst_key_name(dstkey);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_write);
	result = dns_rbt_findnode(keytable->table, keyname, NULL, &node, NULL,
				  DNS_RBTFIND_NOOPTIONS, NULL, NULL);

	if (result == DNS_R_PARTIALMATCH)
		result = ISC_R_NOTFOUND;
	if (result != ISC_R_SUCCESS)
		goto finish;

	if (node->data == NULL) {
		result = ISC_R_NOTFOUND;
		goto finish;
	}

	knode = node->data;
	if (knode->next == NULL && knode->key != NULL &&
	    dst_key_compare(knode->key, dstkey) == true)
	{
		result = dns_rbt_deletenode(keytable->table, node, false);
		goto finish;
	}

	kprev = (dns_keynode_t **) &node->data;
	while (knode != NULL) {
		if (knode->key != NULL &&
		    dst_key_compare(knode->key, dstkey) == true)
			break;
		kprev = &knode->next;
		knode = knode->next;
	}

	if (knode != NULL) {
		if (knode->key != NULL)
			dst_key_free(&knode->key);
		/*
		 * This is equivalent to:
		 * dns_keynode_attach(knode->next, &tmp);
		 * dns_keynode_detach(kprev);
		 * dns_keynode_attach(tmp, &kprev);
		 * dns_keynode_detach(&tmp);
		 */
		*kprev = knode->next;
		knode->next = NULL;
		dns_keynode_detach(keytable->mctx, &knode);
	} else
		result = DNS_R_PARTIALMATCH;
  finish:
	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_write);
	return (result);
}

isc_result_t
dns_keytable_find(dns_keytable_t *keytable, dns_name_t *keyname,
		  dns_keynode_t **keynodep)
{
	isc_result_t result;
	dns_rbtnode_t *node = NULL;

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(keyname != NULL);
	REQUIRE(keynodep != NULL && *keynodep == NULL);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_read);
	result = dns_rbt_findnode(keytable->table, keyname, NULL, &node, NULL,
				  DNS_RBTFIND_NOOPTIONS, NULL, NULL);
	if (result == ISC_R_SUCCESS) {
		if (node->data != NULL) {
			isc_refcount_increment0(&keytable->active_nodes, NULL);
			dns_keynode_attach(node->data, keynodep);
		} else
			result = ISC_R_NOTFOUND;
	} else if (result == DNS_R_PARTIALMATCH)
		result = ISC_R_NOTFOUND;
	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_read);

	return (result);
}

isc_result_t
dns_keytable_nextkeynode(dns_keytable_t *keytable, dns_keynode_t *keynode,
			 dns_keynode_t **nextnodep)
{
	/*
	 * Return the next key after 'keynode', regardless of
	 * properties.
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(VALID_KEYNODE(keynode));
	REQUIRE(nextnodep != NULL && *nextnodep == NULL);

	if (keynode->next == NULL)
		return (ISC_R_NOTFOUND);

	dns_keynode_attach(keynode->next, nextnodep);
	isc_refcount_increment(&keytable->active_nodes, NULL);

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_keytable_findkeynode(dns_keytable_t *keytable, dns_name_t *name,
			 dns_secalg_t algorithm, dns_keytag_t tag,
			 dns_keynode_t **keynodep)
{
	isc_result_t result;
	dns_keynode_t *knode;
	void *data;

	/*
	 * Search for a key named 'name', matching 'algorithm' and 'tag' in
	 * 'keytable'.
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(keynodep != NULL && *keynodep == NULL);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_read);

	/*
	 * Note we don't want the DNS_R_PARTIALMATCH from dns_rbt_findname()
	 * as that indicates that 'name' was not found.
	 *
	 * DNS_R_PARTIALMATCH indicates that the name was found but we
	 * didn't get a match on algorithm and key id arguments.
	 */
	knode = NULL;
	data = NULL;
	result = dns_rbt_findname(keytable->table, name, 0, NULL, &data);

	if (result == ISC_R_SUCCESS) {
		INSIST(data != NULL);
		for (knode = data; knode != NULL; knode = knode->next) {
			if (knode->key == NULL) {
				knode = NULL;
				break;
			}
			if (algorithm == dst_key_alg(knode->key)
			    && tag == dst_key_id(knode->key))
				break;
		}
		if (knode != NULL) {
			isc_refcount_increment0(&keytable->active_nodes, NULL);
			dns_keynode_attach(knode, keynodep);
		} else
			result = DNS_R_PARTIALMATCH;
	} else if (result == DNS_R_PARTIALMATCH)
		result = ISC_R_NOTFOUND;

	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_read);

	return (result);
}

isc_result_t
dns_keytable_findnextkeynode(dns_keytable_t *keytable, dns_keynode_t *keynode,
			     dns_keynode_t **nextnodep)
{
	isc_result_t result;
	dns_keynode_t *knode;

	/*
	 * Search for the next key with the same properties as 'keynode' in
	 * 'keytable'.
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(VALID_KEYNODE(keynode));
	REQUIRE(nextnodep != NULL && *nextnodep == NULL);

	for (knode = keynode->next; knode != NULL; knode = knode->next) {
		if (knode->key == NULL) {
			knode = NULL;
			break;
		}
		if (dst_key_alg(keynode->key) == dst_key_alg(knode->key) &&
		    dst_key_id(keynode->key) == dst_key_id(knode->key))
			break;
	}
	if (knode != NULL) {
		isc_refcount_increment(&keytable->active_nodes, NULL);
		result = ISC_R_SUCCESS;
		dns_keynode_attach(knode, nextnodep);
	} else
		result = ISC_R_NOTFOUND;

	return (result);
}

isc_result_t
dns_keytable_finddeepestmatch(dns_keytable_t *keytable, dns_name_t *name,
			      dns_name_t *foundname)
{
	isc_result_t result;
	void *data;

	/*
	 * Search for the deepest match in 'keytable'.
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(foundname != NULL);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_read);

	data = NULL;
	result = dns_rbt_findname(keytable->table, name, 0, foundname, &data);

	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH)
		result = ISC_R_SUCCESS;

	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_read);

	return (result);
}

void
dns_keytable_attachkeynode(dns_keytable_t *keytable, dns_keynode_t *source,
			   dns_keynode_t **target)
{
	/*
	 * Give back a keynode found via dns_keytable_findkeynode().
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(VALID_KEYNODE(source));
	REQUIRE(target != NULL && *target == NULL);

	isc_refcount_increment(&keytable->active_nodes, NULL);

	dns_keynode_attach(source, target);
}

void
dns_keytable_detachkeynode(dns_keytable_t *keytable, dns_keynode_t **keynodep)
{
	/*
	 * Give back a keynode found via dns_keytable_findkeynode().
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(keynodep != NULL && VALID_KEYNODE(*keynodep));

	isc_refcount_decrement(&keytable->active_nodes, NULL);
	dns_keynode_detach(keytable->mctx, keynodep);
}

isc_result_t
dns_keytable_issecuredomain(dns_keytable_t *keytable, dns_name_t *name,
			    dns_name_t *foundname, bool *wantdnssecp)
{
	isc_result_t result;
	dns_rbtnode_t *node = NULL;

	/*
	 * Is 'name' at or beneath a trusted key?
	 */

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(wantdnssecp != NULL);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_read);

	result = dns_rbt_findnode(keytable->table, name, foundname, &node,
				  NULL, DNS_RBTFIND_NOOPTIONS, NULL, NULL);
	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		INSIST(node->data != NULL);
		*wantdnssecp = true;
		result = ISC_R_SUCCESS;
	} else if (result == ISC_R_NOTFOUND) {
		*wantdnssecp = false;
		result = ISC_R_SUCCESS;
	}

	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_read);

	return (result);
}

static isc_result_t
putstr(isc_buffer_t **b, const char *str) {
	isc_result_t result;

	result = isc_buffer_reserve(b, strlen(str));
	if (result != ISC_R_SUCCESS)
		return (result);

	isc_buffer_putstr(*b, str);
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_keytable_dump(dns_keytable_t *keytable, FILE *fp) {
	isc_result_t result;
	isc_buffer_t *text = NULL;

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(fp != NULL);

	result = isc_buffer_allocate(keytable->mctx, &text, 4096);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = dns_keytable_totext(keytable, &text);

	if (isc_buffer_usedlength(text) != 0) {
		(void) putstr(&text, "\n");
	} else if (result == ISC_R_SUCCESS)
		(void) putstr(&text, "none");
	else {
		(void) putstr(&text, "could not dump key table: ");
		(void) putstr(&text, isc_result_totext(result));
	}

	fprintf(fp, "%.*s", (int) isc_buffer_usedlength(text),
		(char *) isc_buffer_base(text));

	isc_buffer_free(&text);
	return (result);
}

isc_result_t
dns_keytable_totext(dns_keytable_t *keytable, isc_buffer_t **text) {
	isc_result_t result;
	dns_keynode_t *knode;
	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;

	REQUIRE(VALID_KEYTABLE(keytable));
	REQUIRE(text != NULL && *text != NULL);

	RWLOCK(&keytable->rwlock, isc_rwlocktype_read);
	dns_rbtnodechain_init(&chain, keytable->mctx);
	result = dns_rbtnodechain_first(&chain, keytable->table, NULL, NULL);
	if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
		if (result == ISC_R_NOTFOUND)
			result = ISC_R_SUCCESS;
		goto cleanup;
	}
	for (;;) {
		char pbuf[DST_KEY_FORMATSIZE];

		dns_rbtnodechain_current(&chain, NULL, NULL, &node);
		for (knode = node->data; knode != NULL; knode = knode->next) {
			char obuf[DNS_NAME_FORMATSIZE + 200];
			if (knode->key == NULL)
				continue;
			dst_key_format(knode->key, pbuf, sizeof(pbuf));
			snprintf(obuf, sizeof(obuf), "%s ; %s\n", pbuf,
				knode->managed ? "managed" : "trusted");
			result = putstr(text, obuf);
			if (result != ISC_R_SUCCESS)
				break;
		}
		result = dns_rbtnodechain_next(&chain, NULL, NULL);
		if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
			if (result == ISC_R_NOMORE)
				result = ISC_R_SUCCESS;
			break;
		}
	}

   cleanup:
	dns_rbtnodechain_invalidate(&chain);
	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_read);
	return (result);
}

isc_result_t
dns_keytable_forall(dns_keytable_t *keytable,
		    void (*func)(dns_keytable_t *, dns_keynode_t *, void *),
		    void *arg)
{
	isc_result_t result;
	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;

	REQUIRE(VALID_KEYTABLE(keytable));

	RWLOCK(&keytable->rwlock, isc_rwlocktype_read);
	dns_rbtnodechain_init(&chain, keytable->mctx);
	result = dns_rbtnodechain_first(&chain, keytable->table, NULL, NULL);
	if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
		if (result == ISC_R_NOTFOUND)
			result = ISC_R_SUCCESS;
		goto cleanup;
	}
	isc_refcount_increment0(&keytable->active_nodes, NULL);
	for (;;) {
		dns_rbtnodechain_current(&chain, NULL, NULL, &node);
		if (node->data != NULL)
			(*func)(keytable, node->data, arg);
		result = dns_rbtnodechain_next(&chain, NULL, NULL);
		if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
			if (result == ISC_R_NOMORE)
				result = ISC_R_SUCCESS;
			break;
		}
	}
	isc_refcount_decrement(&keytable->active_nodes, NULL);

   cleanup:
	dns_rbtnodechain_invalidate(&chain);
	RWUNLOCK(&keytable->rwlock, isc_rwlocktype_read);
	return (result);
}

dst_key_t *
dns_keynode_key(dns_keynode_t *keynode) {

	/*
	 * Get the DST key associated with keynode.
	 */

	REQUIRE(VALID_KEYNODE(keynode));

	return (keynode->key);
}

bool
dns_keynode_managed(dns_keynode_t *keynode) {
	/*
	 * Is this a managed key?
	 */
	REQUIRE(VALID_KEYNODE(keynode));

	return (keynode->managed);
}

isc_result_t
dns_keynode_create(isc_mem_t *mctx, dns_keynode_t **target) {
	isc_result_t result;
	dns_keynode_t *knode;

	REQUIRE(target != NULL && *target == NULL);

	knode = isc_mem_get(mctx, sizeof(dns_keynode_t));
	if (knode == NULL)
		return (ISC_R_NOMEMORY);

	knode->magic = KEYNODE_MAGIC;
	knode->managed = false;
	knode->key = NULL;
	knode->next = NULL;

	result = isc_refcount_init(&knode->refcount, 1);
	if (result != ISC_R_SUCCESS)
		return (result);

	*target = knode;
	return (ISC_R_SUCCESS);
}

void
dns_keynode_attach(dns_keynode_t *source, dns_keynode_t **target) {
	REQUIRE(VALID_KEYNODE(source));
	isc_refcount_increment(&source->refcount, NULL);
	*target = source;
}

void
dns_keynode_detach(isc_mem_t *mctx, dns_keynode_t **keynode) {
	unsigned int refs;
	dns_keynode_t *node = *keynode;
	REQUIRE(VALID_KEYNODE(node));
	isc_refcount_decrement(&node->refcount, &refs);
	if (refs == 0) {
		if (node->key != NULL)
			dst_key_free(&node->key);
		isc_refcount_destroy(&node->refcount);
		isc_mem_put(mctx, node, sizeof(dns_keynode_t));
	}
	*keynode = NULL;
}

void
dns_keynode_detachall(isc_mem_t *mctx, dns_keynode_t **keynode) {
	dns_keynode_t *next = NULL, *node = *keynode;
	REQUIRE(VALID_KEYNODE(node));
	while (node != NULL) {
		next = node->next;
		dns_keynode_detach(mctx, &node);
		node = next;
	}
	*keynode = NULL;
}
