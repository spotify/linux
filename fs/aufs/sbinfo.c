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
 * superblock private data
 */

#include "aufs.h"

/*
 * they are necessary regardless sysfs is disabled.
 */
void au_si_free(struct kobject *kobj)
{
	struct au_sbinfo *sbinfo;
	struct super_block *sb;

	sbinfo = container_of(kobj, struct au_sbinfo, si_kobj);
	AuDebugOn(!list_empty(&sbinfo->si_plink.head));

	sb = sbinfo->si_sb;
	si_write_lock(sb);
	au_xino_clr(sb);
	au_br_free(sbinfo);
	kfree(sbinfo->si_branch);
	mutex_destroy(&sbinfo->si_xib_mtx);
	si_write_unlock(sb);
	AuRwDestroy(&sbinfo->si_rwsem);

	kfree(sbinfo);
}

int au_si_alloc(struct super_block *sb)
{
	int err;
	struct au_sbinfo *sbinfo;

	err = -ENOMEM;
	sbinfo = kmalloc(sizeof(*sbinfo), GFP_NOFS);
	if (unlikely(!sbinfo))
		goto out;

	/* will be reallocated separately */
	sbinfo->si_branch = kzalloc(sizeof(*sbinfo->si_branch), GFP_NOFS);
	if (unlikely(!sbinfo->si_branch))
		goto out_sbinfo;

	memset(&sbinfo->si_kobj, 0, sizeof(sbinfo->si_kobj));
	err = sysaufs_si_init(sbinfo);
	if (unlikely(err))
		goto out_br;

	au_nwt_init(&sbinfo->si_nowait);
	au_rw_init_wlock(&sbinfo->si_rwsem);
	sbinfo->si_generation = 0;
	sbinfo->au_si_status = 0;
	sbinfo->si_bend = -1;
	sbinfo->si_last_br_id = 0;

	sbinfo->si_wbr_copyup = AuWbrCopyup_Def;
	sbinfo->si_wbr_create = AuWbrCreate_Def;
	sbinfo->si_wbr_copyup_ops = au_wbr_copyup_ops + AuWbrCopyup_Def;
	sbinfo->si_wbr_create_ops = au_wbr_create_ops + AuWbrCreate_Def;

	sbinfo->si_mntflags = AuOpt_Def;

	sbinfo->si_xread = NULL;
	sbinfo->si_xwrite = NULL;
	sbinfo->si_xib = NULL;
	mutex_init(&sbinfo->si_xib_mtx);
	sbinfo->si_xib_buf = NULL;
	sbinfo->si_xino_brid = -1;
	/* leave si_xib_last_pindex and si_xib_next_bit */

	sbinfo->si_rdcache = AUFS_RDCACHE_DEF * HZ;
	sbinfo->si_rdblk = AUFS_RDBLK_DEF;
	sbinfo->si_rdhash = AUFS_RDHASH_DEF;
	sbinfo->si_dirwh = AUFS_DIRWH_DEF;

	au_spl_init(&sbinfo->si_plink);
	init_waitqueue_head(&sbinfo->si_plink_wq);

	/* leave other members for sysaufs and si_mnt. */
	sbinfo->si_sb = sb;
	sb->s_fs_info = sbinfo;
	au_debug_sbinfo_init(sbinfo);
	return 0; /* success */

 out_br:
	kfree(sbinfo->si_branch);
 out_sbinfo:
	kfree(sbinfo);
 out:
	return err;
}

int au_sbr_realloc(struct au_sbinfo *sbinfo, int nbr)
{
	int err, sz;
	struct au_branch **brp;

	AuRwMustWriteLock(&sbinfo->si_rwsem);

	err = -ENOMEM;
	sz = sizeof(*brp) * (sbinfo->si_bend + 1);
	if (unlikely(!sz))
		sz = sizeof(*brp);
	brp = au_kzrealloc(sbinfo->si_branch, sz, sizeof(*brp) * nbr, GFP_NOFS);
	if (brp) {
		sbinfo->si_branch = brp;
		err = 0;
	}

	return err;
}

/* ---------------------------------------------------------------------- */

unsigned int au_sigen_inc(struct super_block *sb)
{
	unsigned int gen;

	SiMustWriteLock(sb);

	gen = ++au_sbi(sb)->si_generation;
	au_update_digen(sb->s_root);
	au_update_iigen(sb->s_root->d_inode);
	sb->s_root->d_inode->i_version++;
	return gen;
}

aufs_bindex_t au_new_br_id(struct super_block *sb)
{
	aufs_bindex_t br_id;
	int i;
	struct au_sbinfo *sbinfo;

	SiMustWriteLock(sb);

	sbinfo = au_sbi(sb);
	for (i = 0; i <= AUFS_BRANCH_MAX; i++) {
		br_id = ++sbinfo->si_last_br_id;
		if (br_id && au_br_index(sb, br_id) < 0)
			return br_id;
	}

	return -1;
}

/* ---------------------------------------------------------------------- */

/* dentry and super_block lock. call at entry point */
void aufs_read_lock(struct dentry *dentry, int flags)
{
	si_read_lock(dentry->d_sb, flags);
	if (au_ftest_lock(flags, DW))
		di_write_lock_child(dentry);
	else
		di_read_lock_child(dentry, flags);
}

void aufs_read_unlock(struct dentry *dentry, int flags)
{
	if (au_ftest_lock(flags, DW))
		di_write_unlock(dentry);
	else
		di_read_unlock(dentry, flags);
	si_read_unlock(dentry->d_sb);
}

void aufs_write_lock(struct dentry *dentry)
{
	si_write_lock(dentry->d_sb);
	di_write_lock_child(dentry);
}

void aufs_write_unlock(struct dentry *dentry)
{
	di_write_unlock(dentry);
	si_write_unlock(dentry->d_sb);
}

void aufs_read_and_write_lock2(struct dentry *d1, struct dentry *d2, int flags)
{
	si_read_lock(d1->d_sb, flags);
	di_write_lock2_child(d1, d2, au_ftest_lock(flags, DIR));
}

void aufs_read_and_write_unlock2(struct dentry *d1, struct dentry *d2)
{
	di_write_unlock2(d1, d2);
	si_read_unlock(d1->d_sb);
}
