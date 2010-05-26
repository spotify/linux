/*
 * Copyright (C) 2005-2009 Junjiro R. Okajima
 *
 * This program, aufs is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * sub-routines for dentry cache
 */

#include "aufs.h"

static void au_dpage_free(struct au_dpage *dpage)
{
	int i;
	struct dentry **p;

	p = dpage->dentries;
	for (i = 0; i < dpage->ndentry; i++)
		dput(*p++);
	free_page((unsigned long)dpage->dentries);
}

int au_dpages_init(struct au_dcsub_pages *dpages, gfp_t gfp)
{
	int err;
	void *p;

	err = -ENOMEM;
	dpages->dpages = kmalloc(sizeof(*dpages->dpages), gfp);
	if (unlikely(!dpages->dpages))
		goto out;

	p = (void *)__get_free_page(gfp);
	if (unlikely(!p))
		goto out_dpages;

	dpages->dpages[0].ndentry = 0;
	dpages->dpages[0].dentries = p;
	dpages->ndpage = 1;
	return 0; /* success */

 out_dpages:
	kfree(dpages->dpages);
 out:
	return err;
}

void au_dpages_free(struct au_dcsub_pages *dpages)
{
	int i;
	struct au_dpage *p;

	p = dpages->dpages;
	for (i = 0; i < dpages->ndpage; i++)
		au_dpage_free(p++);
	kfree(dpages->dpages);
}

static int au_dpages_append(struct au_dcsub_pages *dpages,
			    struct dentry *dentry, gfp_t gfp)
{
	int err, sz;
	struct au_dpage *dpage;
	void *p;

	dpage = dpages->dpages + dpages->ndpage - 1;
	sz = PAGE_SIZE / sizeof(dentry);
	if (unlikely(dpage->ndentry >= sz)) {
		AuLabel(new dpage);
		err = -ENOMEM;
		sz = dpages->ndpage * sizeof(*dpages->dpages);
		p = au_kzrealloc(dpages->dpages, sz,
				 sz + sizeof(*dpages->dpages), gfp);
		if (unlikely(!p))
			goto out;

		dpages->dpages = p;
		dpage = dpages->dpages + dpages->ndpage;
		p = (void *)__get_free_page(gfp);
		if (unlikely(!p))
			goto out;

		dpage->ndentry = 0;
		dpage->dentries = p;
		dpages->ndpage++;
	}

	dpage->dentries[dpage->ndentry++] = dget(dentry);
	return 0; /* success */

 out:
	return err;
}

int au_dcsub_pages(struct au_dcsub_pages *dpages, struct dentry *root,
		   au_dpages_test test, void *arg)
{
	int err;
	struct dentry *this_parent = root;
	struct list_head *next;
	struct super_block *sb = root->d_sb;

	err = 0;
	spin_lock(&dcache_lock);
 repeat:
	next = this_parent->d_subdirs.next;
 resume:
	if (this_parent->d_sb == sb
	    && !IS_ROOT(this_parent)
	    && atomic_read(&this_parent->d_count)
	    && this_parent->d_inode
	    && (!test || test(this_parent, arg))) {
		err = au_dpages_append(dpages, this_parent, GFP_ATOMIC);
		if (unlikely(err))
			goto out;
	}

	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry = list_entry(tmp, struct dentry,
						   d_u.d_child);
		next = tmp->next;
		if (/*d_unhashed(dentry) || */!dentry->d_inode)
			continue;
		if (!list_empty(&dentry->d_subdirs)) {
			this_parent = dentry;
			goto repeat;
		}
		if (dentry->d_sb == sb
		    && atomic_read(&dentry->d_count)
		    && (!test || test(dentry, arg))) {
			err = au_dpages_append(dpages, dentry, GFP_ATOMIC);
			if (unlikely(err))
				goto out;
		}
	}

	if (this_parent != root) {
		next = this_parent->d_u.d_child.next;
		this_parent = this_parent->d_parent; /* dcache_lock is locked */
		goto resume;
	}
 out:
	spin_unlock(&dcache_lock);
	return err;
}

int au_dcsub_pages_rev(struct au_dcsub_pages *dpages, struct dentry *dentry,
		       int do_include, au_dpages_test test, void *arg)
{
	int err;

	err = 0;
	spin_lock(&dcache_lock);
	if (do_include && (!test || test(dentry, arg))) {
		err = au_dpages_append(dpages, dentry, GFP_ATOMIC);
		if (unlikely(err))
			goto out;
	}
	while (!IS_ROOT(dentry)) {
		dentry = dentry->d_parent; /* dcache_lock is locked */
		if (!test || test(dentry, arg)) {
			err = au_dpages_append(dpages, dentry, GFP_ATOMIC);
			if (unlikely(err))
				break;
		}
	}

 out:
	spin_unlock(&dcache_lock);

	return err;
}

struct dentry *au_test_subdir(struct dentry *d1, struct dentry *d2)
{
	struct dentry *trap, **dentries;
	int err, i, j;
	struct au_dcsub_pages dpages;
	struct au_dpage *dpage;

	trap = ERR_PTR(-ENOMEM);
	err = au_dpages_init(&dpages, GFP_NOFS);
	if (unlikely(err))
		goto out;
	err = au_dcsub_pages_rev(&dpages, d1, /*do_include*/1, NULL, NULL);
	if (unlikely(err))
		goto out_dpages;

	trap = d1;
	for (i = 0; !err && i < dpages.ndpage; i++) {
		dpage = dpages.dpages + i;
		dentries = dpage->dentries;
		for (j = 0; !err && j < dpage->ndentry; j++) {
			struct dentry *d;

			d = dentries[j];
			err = (d == d2);
			if (!err)
				trap = d;
		}
	}
	if (!err)
		trap = NULL;

 out_dpages:
	au_dpages_free(&dpages);
 out:
	return trap;
}
