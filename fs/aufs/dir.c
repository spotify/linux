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
 * directory operations
 */

#include <linux/file.h>
#include <linux/fs_stack.h>
#include "aufs.h"

void au_add_nlink(struct inode *dir, struct inode *h_dir)
{
	AuDebugOn(!S_ISDIR(dir->i_mode) || !S_ISDIR(h_dir->i_mode));

	dir->i_nlink += h_dir->i_nlink - 2;
	if (h_dir->i_nlink < 2)
		dir->i_nlink += 2;
}

void au_sub_nlink(struct inode *dir, struct inode *h_dir)
{
	AuDebugOn(!S_ISDIR(dir->i_mode) || !S_ISDIR(h_dir->i_mode));

	dir->i_nlink -= h_dir->i_nlink - 2;
	if (h_dir->i_nlink < 2)
		dir->i_nlink -= 2;
}

loff_t au_dir_size(struct file *file, struct dentry *dentry)
{
	loff_t sz;
	aufs_bindex_t bindex, bend;
	struct file *h_file;
	struct dentry *h_dentry;

	sz = 0;
	if (file) {
		AuDebugOn(!file->f_dentry);
		AuDebugOn(!file->f_dentry->d_inode);
		AuDebugOn(!S_ISDIR(file->f_dentry->d_inode->i_mode));

		bend = au_fbend(file);
		for (bindex = au_fbstart(file);
		     bindex <= bend && sz < KMALLOC_MAX_SIZE;
		     bindex++) {
			h_file = au_h_fptr(file, bindex);
			if (h_file
			    && h_file->f_dentry
			    && h_file->f_dentry->d_inode)
				sz += i_size_read(h_file->f_dentry->d_inode);
		}
	} else {
		AuDebugOn(!dentry);
		AuDebugOn(!dentry->d_inode);
		AuDebugOn(!S_ISDIR(dentry->d_inode->i_mode));

		bend = au_dbtaildir(dentry);
		for (bindex = au_dbstart(dentry);
		     bindex <= bend && sz < KMALLOC_MAX_SIZE;
		     bindex++) {
			h_dentry = au_h_dptr(dentry, bindex);
			if (h_dentry && h_dentry->d_inode)
				sz += i_size_read(h_dentry->d_inode);
		}
	}
	if (sz < KMALLOC_MAX_SIZE)
		sz = roundup_pow_of_two(sz);
	if (sz > KMALLOC_MAX_SIZE)
		sz = KMALLOC_MAX_SIZE;
	else if (sz < NAME_MAX) {
		BUILD_BUG_ON(AUFS_RDBLK_DEF < NAME_MAX);
		sz = AUFS_RDBLK_DEF;
	}
	return sz;
}

/* ---------------------------------------------------------------------- */

static int reopen_dir(struct file *file)
{
	int err;
	unsigned int flags;
	aufs_bindex_t bindex, btail, bstart;
	struct dentry *dentry, *h_dentry;
	struct file *h_file;

	/* open all lower dirs */
	dentry = file->f_dentry;
	bstart = au_dbstart(dentry);
	for (bindex = au_fbstart(file); bindex < bstart; bindex++)
		au_set_h_fptr(file, bindex, NULL);
	au_set_fbstart(file, bstart);

	btail = au_dbtaildir(dentry);
	for (bindex = au_fbend(file); btail < bindex; bindex--)
		au_set_h_fptr(file, bindex, NULL);
	au_set_fbend(file, btail);

	spin_lock(&file->f_lock);
	flags = file->f_flags;
	spin_unlock(&file->f_lock);
	for (bindex = bstart; bindex <= btail; bindex++) {
		h_dentry = au_h_dptr(dentry, bindex);
		if (!h_dentry)
			continue;
		h_file = au_h_fptr(file, bindex);
		if (h_file)
			continue;

		h_file = au_h_open(dentry, bindex, flags, file);
		err = PTR_ERR(h_file);
		if (IS_ERR(h_file))
			goto out; /* close all? */
		au_set_h_fptr(file, bindex, h_file);
	}
	au_update_figen(file);
	/* todo: necessary? */
	/* file->f_ra = h_file->f_ra; */
	err = 0;

 out:
	return err;
}

static int do_open_dir(struct file *file, int flags)
{
	int err;
	aufs_bindex_t bindex, btail;
	struct dentry *dentry, *h_dentry;
	struct file *h_file;

	FiMustWriteLock(file);

	err = 0;
	dentry = file->f_dentry;
	au_set_fvdir_cache(file, NULL);
	au_fi(file)->fi_maintain_plink = 0;
	file->f_version = dentry->d_inode->i_version;
	bindex = au_dbstart(dentry);
	au_set_fbstart(file, bindex);
	btail = au_dbtaildir(dentry);
	au_set_fbend(file, btail);
	for (; !err && bindex <= btail; bindex++) {
		h_dentry = au_h_dptr(dentry, bindex);
		if (!h_dentry)
			continue;

		h_file = au_h_open(dentry, bindex, flags, file);
		if (IS_ERR(h_file)) {
			err = PTR_ERR(h_file);
			break;
		}
		au_set_h_fptr(file, bindex, h_file);
	}
	au_update_figen(file);
	/* todo: necessary? */
	/* file->f_ra = h_file->f_ra; */
	if (!err)
		return 0; /* success */

	/* close all */
	for (bindex = au_fbstart(file); bindex <= btail; bindex++)
		au_set_h_fptr(file, bindex, NULL);
	au_set_fbstart(file, -1);
	au_set_fbend(file, -1);
	return err;
}

static int aufs_open_dir(struct inode *inode __maybe_unused,
			 struct file *file)
{
	return au_do_open(file, do_open_dir);
}

static int aufs_release_dir(struct inode *inode __maybe_unused,
			    struct file *file)
{
	struct au_vdir *vdir_cache;
	struct super_block *sb;
	struct au_sbinfo *sbinfo;

	sb = file->f_dentry->d_sb;
	si_noflush_read_lock(sb);
	fi_write_lock(file);
	vdir_cache = au_fvdir_cache(file);
	if (vdir_cache)
		au_vdir_free(vdir_cache);
	if (au_fi(file)->fi_maintain_plink) {
		sbinfo = au_sbi(sb);
		/* clear the flag without write-lock */
		sbinfo->au_si_status &= ~AuSi_MAINTAIN_PLINK;
		smp_mb();
		wake_up_all(&sbinfo->si_plink_wq);
	}
	fi_write_unlock(file);
	au_finfo_fin(file);
	si_read_unlock(sb);
	return 0;
}

/* ---------------------------------------------------------------------- */

static int au_do_fsync_dir_no_file(struct dentry *dentry, int datasync)
{
	int err;
	aufs_bindex_t bend, bindex;
	struct inode *inode;
	struct super_block *sb;

	err = 0;
	sb = dentry->d_sb;
	inode = dentry->d_inode;
	IMustLock(inode);
	bend = au_dbend(dentry);
	for (bindex = au_dbstart(dentry); !err && bindex <= bend; bindex++) {
		struct path h_path;
		struct inode *h_inode;

		if (au_test_ro(sb, bindex, inode))
			continue;
		h_path.dentry = au_h_dptr(dentry, bindex);
		if (!h_path.dentry)
			continue;
		h_inode = h_path.dentry->d_inode;
		if (!h_inode)
			continue;

		/* no mnt_want_write() */
		/* cf. fs/nsfd/vfs.c and fs/nfsd/nfs4recover.c */
		/* todo: inotiry fired? */
		h_path.mnt = au_sbr_mnt(sb, bindex);
		mutex_lock(&h_inode->i_mutex);
		err = filemap_fdatawrite(h_inode->i_mapping);
		AuDebugOn(!h_inode->i_fop);
		if (!err && h_inode->i_fop->fsync)
			err = h_inode->i_fop->fsync(NULL, h_path.dentry,
						    datasync);
		if (!err)
			err = filemap_fdatawrite(h_inode->i_mapping);
		if (!err)
			vfsub_update_h_iattr(&h_path, /*did*/NULL); /*ignore*/
		mutex_unlock(&h_inode->i_mutex);
	}

	return err;
}

static int au_do_fsync_dir(struct file *file, int datasync)
{
	int err;
	aufs_bindex_t bend, bindex;
	struct file *h_file;
	struct super_block *sb;
	struct inode *inode;
	struct mutex *h_mtx;

	err = au_reval_and_lock_fdi(file, reopen_dir, /*wlock*/1);
	if (unlikely(err))
		goto out;

	sb = file->f_dentry->d_sb;
	inode = file->f_dentry->d_inode;
	bend = au_fbend(file);
	for (bindex = au_fbstart(file); !err && bindex <= bend; bindex++) {
		h_file = au_h_fptr(file, bindex);
		if (!h_file || au_test_ro(sb, bindex, inode))
			continue;

		err = vfs_fsync(h_file, h_file->f_dentry, datasync);
		if (!err) {
			h_mtx = &h_file->f_dentry->d_inode->i_mutex;
			mutex_lock(h_mtx);
			vfsub_update_h_iattr(&h_file->f_path, /*did*/NULL);
			/*ignore*/
			mutex_unlock(h_mtx);
		}
	}

 out:
	return err;
}

/*
 * @file may be NULL
 */
static int aufs_fsync_dir(struct file *file, struct dentry *dentry,
			  int datasync)
{
	int err;
	struct super_block *sb;

	IMustLock(dentry->d_inode);

	err = 0;
	sb = dentry->d_sb;
	si_noflush_read_lock(sb);
	if (file)
		err = au_do_fsync_dir(file, datasync);
	else {
		di_write_lock_child(dentry);
		err = au_do_fsync_dir_no_file(dentry, datasync);
	}
	au_cpup_attr_timesizes(dentry->d_inode);
	di_write_unlock(dentry);
	if (file)
		fi_write_unlock(file);

	si_read_unlock(sb);
	return err;
}

/* ---------------------------------------------------------------------- */

static int aufs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	int err;
	struct dentry *dentry;
	struct inode *inode;
	struct super_block *sb;

	dentry = file->f_dentry;
	inode = dentry->d_inode;
	IMustLock(inode);

	sb = dentry->d_sb;
	si_read_lock(sb, AuLock_FLUSH);
	err = au_reval_and_lock_fdi(file, reopen_dir, /*wlock*/1);
	if (unlikely(err))
		goto out;
	err = au_vdir_init(file);
	di_downgrade_lock(dentry, AuLock_IR);
	if (unlikely(err))
		goto out_unlock;

	if (!au_test_nfsd(current)) {
		err = au_vdir_fill_de(file, dirent, filldir);
		fsstack_copy_attr_atime(inode,
					au_h_iptr(inode, au_ibstart(inode)));
	} else {
		/*
		 * nfsd filldir may call lookup_one_len(), vfs_getattr(),
		 * encode_fh() and others.
		 */
		struct inode *h_inode = au_h_iptr(inode, au_ibstart(inode));

		di_read_unlock(dentry, AuLock_IR);
		si_read_unlock(sb);
		/* lockdep_off(); */
		err = au_vdir_fill_de(file, dirent, filldir);
		/* lockdep_on(); */
		fsstack_copy_attr_atime(inode, h_inode);
		fi_write_unlock(file);

		AuTraceErr(err);
		return err;
	}

 out_unlock:
	di_read_unlock(dentry, AuLock_IR);
	fi_write_unlock(file);
 out:
	si_read_unlock(sb);
	return err;
}

/* ---------------------------------------------------------------------- */

#define AuTestEmpty_WHONLY	1
#define AuTestEmpty_CALLED	(1 << 1)
#define AuTestEmpty_SHWH	(1 << 2)
#define au_ftest_testempty(flags, name)	((flags) & AuTestEmpty_##name)
#define au_fset_testempty(flags, name)	{ (flags) |= AuTestEmpty_##name; }
#define au_fclr_testempty(flags, name)	{ (flags) &= ~AuTestEmpty_##name; }

#ifndef CONFIG_AUFS_SHWH
#undef AuTestEmpty_SHWH
#define AuTestEmpty_SHWH	0
#endif

struct test_empty_arg {
	struct au_nhash *whlist;
	unsigned int flags;
	int err;
	aufs_bindex_t bindex;
};

static int test_empty_cb(void *__arg, const char *__name, int namelen,
			 loff_t offset __maybe_unused, u64 ino,
			 unsigned int d_type)
{
	struct test_empty_arg *arg = __arg;
	char *name = (void *)__name;

	arg->err = 0;
	au_fset_testempty(arg->flags, CALLED);
	/* smp_mb(); */
	if (name[0] == '.'
	    && (namelen == 1 || (name[1] == '.' && namelen == 2)))
		goto out; /* success */

	if (namelen <= AUFS_WH_PFX_LEN
	    || memcmp(name, AUFS_WH_PFX, AUFS_WH_PFX_LEN)) {
		if (au_ftest_testempty(arg->flags, WHONLY)
		    && !au_nhash_test_known_wh(arg->whlist, name, namelen))
			arg->err = -ENOTEMPTY;
		goto out;
	}

	name += AUFS_WH_PFX_LEN;
	namelen -= AUFS_WH_PFX_LEN;
	if (!au_nhash_test_known_wh(arg->whlist, name, namelen))
		arg->err = au_nhash_append_wh
			(arg->whlist, name, namelen, ino, d_type, arg->bindex,
			 au_ftest_testempty(arg->flags, SHWH));

 out:
	/* smp_mb(); */
	AuTraceErr(arg->err);
	return arg->err;
}

static int do_test_empty(struct dentry *dentry, struct test_empty_arg *arg)
{
	int err;
	struct file *h_file;

	h_file = au_h_open(dentry, arg->bindex,
			   O_RDONLY | O_NONBLOCK | O_DIRECTORY | O_LARGEFILE,
			   /*file*/NULL);
	err = PTR_ERR(h_file);
	if (IS_ERR(h_file))
		goto out;

	err = 0;
	if (!au_opt_test(au_mntflags(dentry->d_sb), UDBA_NONE)
	    && !h_file->f_dentry->d_inode->i_nlink)
		goto out_put;

	do {
		arg->err = 0;
		au_fclr_testempty(arg->flags, CALLED);
		/* smp_mb(); */
		err = vfsub_readdir(h_file, test_empty_cb, arg);
		if (err >= 0)
			err = arg->err;
	} while (!err && au_ftest_testempty(arg->flags, CALLED));

 out_put:
	fput(h_file);
	au_sbr_put(dentry->d_sb, arg->bindex);
 out:
	return err;
}

struct do_test_empty_args {
	int *errp;
	struct dentry *dentry;
	struct test_empty_arg *arg;
};

static void call_do_test_empty(void *args)
{
	struct do_test_empty_args *a = args;
	*a->errp = do_test_empty(a->dentry, a->arg);
}

static int sio_test_empty(struct dentry *dentry, struct test_empty_arg *arg)
{
	int err, wkq_err;
	struct dentry *h_dentry;
	struct inode *h_inode;

	h_dentry = au_h_dptr(dentry, arg->bindex);
	h_inode = h_dentry->d_inode;
	mutex_lock_nested(&h_inode->i_mutex, AuLsc_I_CHILD);
	err = au_test_h_perm_sio(h_inode, MAY_EXEC | MAY_READ);
	mutex_unlock(&h_inode->i_mutex);
	if (!err)
		err = do_test_empty(dentry, arg);
	else {
		struct do_test_empty_args args = {
			.errp	= &err,
			.dentry	= dentry,
			.arg	= arg
		};
		unsigned int flags = arg->flags;

		wkq_err = au_wkq_wait(call_do_test_empty, &args);
		if (unlikely(wkq_err))
			err = wkq_err;
		arg->flags = flags;
	}

	return err;
}

int au_test_empty_lower(struct dentry *dentry)
{
	int err;
	unsigned int rdhash;
	aufs_bindex_t bindex, bstart, btail;
	struct au_nhash whlist;
	struct test_empty_arg arg;

	SiMustAnyLock(dentry->d_sb);

	rdhash = au_sbi(dentry->d_sb)->si_rdhash;
	if (!rdhash)
		rdhash = au_rdhash_est(au_dir_size(/*file*/NULL, dentry));
	err = au_nhash_alloc(&whlist, rdhash, GFP_NOFS);
	if (unlikely(err))
		goto out;

	arg.flags = 0;
	arg.whlist = &whlist;
	bstart = au_dbstart(dentry);
	if (au_opt_test(au_mntflags(dentry->d_sb), SHWH))
		au_fset_testempty(arg.flags, SHWH);
	arg.bindex = bstart;
	err = do_test_empty(dentry, &arg);
	if (unlikely(err))
		goto out_whlist;

	au_fset_testempty(arg.flags, WHONLY);
	btail = au_dbtaildir(dentry);
	for (bindex = bstart + 1; !err && bindex <= btail; bindex++) {
		struct dentry *h_dentry;

		h_dentry = au_h_dptr(dentry, bindex);
		if (h_dentry && h_dentry->d_inode) {
			arg.bindex = bindex;
			err = do_test_empty(dentry, &arg);
		}
	}

 out_whlist:
	au_nhash_wh_free(&whlist);
 out:
	return err;
}

int au_test_empty(struct dentry *dentry, struct au_nhash *whlist)
{
	int err;
	struct test_empty_arg arg;
	aufs_bindex_t bindex, btail;

	err = 0;
	arg.whlist = whlist;
	arg.flags = AuTestEmpty_WHONLY;
	if (au_opt_test(au_mntflags(dentry->d_sb), SHWH))
		au_fset_testempty(arg.flags, SHWH);
	btail = au_dbtaildir(dentry);
	for (bindex = au_dbstart(dentry); !err && bindex <= btail; bindex++) {
		struct dentry *h_dentry;

		h_dentry = au_h_dptr(dentry, bindex);
		if (h_dentry && h_dentry->d_inode) {
			arg.bindex = bindex;
			err = sio_test_empty(dentry, &arg);
		}
	}

	return err;
}

/* ---------------------------------------------------------------------- */

const struct file_operations aufs_dir_fop = {
	.read		= generic_read_dir,
	.readdir	= aufs_readdir,
	.unlocked_ioctl	= aufs_ioctl_dir,
	.open		= aufs_open_dir,
	.release	= aufs_release_dir,
	.flush		= aufs_flush,
	.fsync		= aufs_fsync_dir
};
