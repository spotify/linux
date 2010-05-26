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
 * handling file/dir, and address_space operation
 */

#include <linux/file.h>
#include <linux/fsnotify.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include "aufs.h"

/* drop flags for writing */
unsigned int au_file_roflags(unsigned int flags)
{
	flags &= ~(O_WRONLY | O_RDWR | O_APPEND | O_CREAT | O_TRUNC);
	flags |= O_RDONLY | O_NOATIME;
	return flags;
}

/* common functions to regular file and dir */
struct file *au_h_open(struct dentry *dentry, aufs_bindex_t bindex, int flags,
		       struct file *file)
{
	struct file *h_file;
	struct dentry *h_dentry;
	struct inode *h_inode;
	struct super_block *sb;
	struct au_branch *br;
	int err, exec_flag;
	struct path h_path;

	/* a race condition can happen between open and unlink/rmdir */
	h_file = ERR_PTR(-ENOENT);
	h_dentry = au_h_dptr(dentry, bindex);
	if (au_test_nfsd(current) && !h_dentry)
		goto out;
	h_inode = h_dentry->d_inode;
	if (au_test_nfsd(current) && !h_inode)
		goto out;
	if (unlikely((!d_unhashed(dentry) && d_unhashed(h_dentry))
		     || !h_inode))
		goto out;

	sb = dentry->d_sb;
	br = au_sbr(sb, bindex);
	h_file = ERR_PTR(-EACCES);
	exec_flag = flags & vfsub_fmode_to_uint(FMODE_EXEC);
	if (exec_flag && (br->br_mnt->mnt_flags & MNT_NOEXEC))
			goto out;

	/* drop flags for writing */
	if (au_test_ro(sb, bindex, dentry->d_inode))
		flags = au_file_roflags(flags);
	flags &= ~O_CREAT;
	atomic_inc(&br->br_count);
	h_path.dentry = h_dentry;
	h_path.mnt = br->br_mnt;
	path_get(&h_path);
	h_file = vfsub_dentry_open(&h_path, flags, current_cred());
	if (IS_ERR(h_file))
		goto out_br;

	if (exec_flag) {
		err = deny_write_access(h_file);
		if (unlikely(err)) {
			fput(h_file);
			h_file = ERR_PTR(err);
			goto out_br;
		}
	}
	fsnotify_open(h_dentry);
	goto out; /* success */

 out_br:
	atomic_dec(&br->br_count);
 out:
	return h_file;
}

int au_do_open(struct file *file, int (*open)(struct file *file, int flags))
{
	int err;
	unsigned int flags;
	struct dentry *dentry;
	struct super_block *sb;

	dentry = file->f_dentry;
	sb = dentry->d_sb;
	si_read_lock(sb, AuLock_FLUSH);
	err = au_finfo_init(file);
	if (unlikely(err))
		goto out;

	di_read_lock_child(dentry, AuLock_IR);
	spin_lock(&file->f_lock);
	flags = file->f_flags;
	spin_unlock(&file->f_lock);
	err = open(file, flags);
	di_read_unlock(dentry, AuLock_IR);

	fi_write_unlock(file);
	if (unlikely(err))
		au_finfo_fin(file);
 out:
	si_read_unlock(sb);
	return err;
}

int au_reopen_nondir(struct file *file)
{
	int err;
	unsigned int flags;
	aufs_bindex_t bstart, bindex, bend;
	struct dentry *dentry;
	struct file *h_file, *h_file_tmp;

	dentry = file->f_dentry;
	bstart = au_dbstart(dentry);
	h_file_tmp = NULL;
	if (au_fbstart(file) == bstart) {
		h_file = au_h_fptr(file, bstart);
		if (file->f_mode == h_file->f_mode)
			return 0; /* success */
		h_file_tmp = h_file;
		get_file(h_file_tmp);
		au_set_h_fptr(file, bstart, NULL);
	}
	AuDebugOn(au_fbstart(file) < bstart
		  || au_fi(file)->fi_hfile[0 + bstart].hf_file);

	spin_lock(&file->f_lock);
	flags = file->f_flags & ~O_TRUNC;
	spin_unlock(&file->f_lock);
	h_file = au_h_open(dentry, bstart, flags, file);
	err = PTR_ERR(h_file);
	if (IS_ERR(h_file))
		goto out; /* todo: close all? */

	err = 0;
	au_set_fbstart(file, bstart);
	au_set_h_fptr(file, bstart, h_file);
	au_update_figen(file);
	/* todo: necessary? */
	/* file->f_ra = h_file->f_ra; */

	/* close lower files */
	bend = au_fbend(file);
	for (bindex = bstart + 1; bindex <= bend; bindex++)
		au_set_h_fptr(file, bindex, NULL);
	au_set_fbend(file, bstart);

 out:
	if (h_file_tmp)
		fput(h_file_tmp);
	return err;
}

/* ---------------------------------------------------------------------- */

static int au_reopen_wh(struct file *file, aufs_bindex_t btgt,
			struct dentry *hi_wh)
{
	int err;
	aufs_bindex_t bstart;
	struct au_dinfo *dinfo;
	struct dentry *h_dentry;

	dinfo = au_di(file->f_dentry);
	AuRwMustWriteLock(&dinfo->di_rwsem);

	bstart = dinfo->di_bstart;
	dinfo->di_bstart = btgt;
	h_dentry = dinfo->di_hdentry[0 + btgt].hd_dentry;
	dinfo->di_hdentry[0 + btgt].hd_dentry = hi_wh;
	err = au_reopen_nondir(file);
	dinfo->di_hdentry[0 + btgt].hd_dentry = h_dentry;
	dinfo->di_bstart = bstart;

	return err;
}

static int au_ready_to_write_wh(struct file *file, loff_t len,
				aufs_bindex_t bcpup)
{
	int err;
	struct inode *inode;
	struct dentry *dentry, *hi_wh;
	struct super_block *sb;

	dentry = file->f_dentry;
	inode = dentry->d_inode;
	hi_wh = au_hi_wh(inode, bcpup);
	if (!hi_wh)
		err = au_sio_cpup_wh(dentry, bcpup, len, file);
	else
		/* already copied-up after unlink */
		err = au_reopen_wh(file, bcpup, hi_wh);

	sb = dentry->d_sb;
	if (!err && inode->i_nlink > 1 && au_opt_test(au_mntflags(sb), PLINK))
		au_plink_append(inode, bcpup, au_h_dptr(dentry, bcpup));

	return err;
}

/*
 * prepare the @file for writing.
 */
int au_ready_to_write(struct file *file, loff_t len, struct au_pin *pin)
{
	int err;
	aufs_bindex_t bstart, bcpup;
	struct dentry *dentry, *parent, *h_dentry;
	struct inode *h_inode, *inode;
	struct super_block *sb;

	dentry = file->f_dentry;
	sb = dentry->d_sb;
	bstart = au_fbstart(file);
	inode = dentry->d_inode;
	err = au_test_ro(sb, bstart, inode);
	if (!err && (au_h_fptr(file, bstart)->f_mode & FMODE_WRITE)) {
		err = au_pin(pin, dentry, bstart, AuOpt_UDBA_NONE, /*flags*/0);
		goto out;
	}

	/* need to cpup */
	parent = dget_parent(dentry);
	di_write_lock_parent(parent);
	err = AuWbrCopyup(au_sbi(sb), dentry);
	bcpup = err;
	if (unlikely(err < 0))
		goto out_dgrade;
	err = 0;

	if (!au_h_dptr(parent, bcpup)) {
		err = au_cpup_dirs(dentry, bcpup);
		if (unlikely(err))
			goto out_dgrade;
	}

	err = au_pin(pin, dentry, bcpup, AuOpt_UDBA_NONE,
		     AuPin_DI_LOCKED | AuPin_MNT_WRITE);
	if (unlikely(err))
		goto out_dgrade;

	h_dentry = au_h_fptr(file, bstart)->f_dentry;
	h_inode = h_dentry->d_inode;
	mutex_lock_nested(&h_inode->i_mutex, AuLsc_I_CHILD);
	if (d_unhashed(dentry) /* || d_unhashed(h_dentry) */
	    /* || !h_inode->i_nlink */) {
		err = au_ready_to_write_wh(file, len, bcpup);
		di_downgrade_lock(parent, AuLock_IR);
	} else {
		di_downgrade_lock(parent, AuLock_IR);
		if (!au_h_dptr(dentry, bcpup))
			err = au_sio_cpup_simple(dentry, bcpup, len,
						 AuCpup_DTIME);
		if (!err)
			err = au_reopen_nondir(file);
	}
	mutex_unlock(&h_inode->i_mutex);

	if (!err) {
		au_pin_set_parent_lflag(pin, /*lflag*/0);
		goto out_dput; /* success */
	}
	au_unpin(pin);
	goto out_unlock;

 out_dgrade:
	di_downgrade_lock(parent, AuLock_IR);
 out_unlock:
	di_read_unlock(parent, AuLock_IR);
 out_dput:
	dput(parent);
 out:
	return err;
}

/* ---------------------------------------------------------------------- */

static int au_file_refresh_by_inode(struct file *file, int *need_reopen)
{
	int err;
	aufs_bindex_t bstart;
	struct au_pin pin;
	struct au_finfo *finfo;
	struct dentry *dentry, *parent, *hi_wh;
	struct inode *inode;
	struct super_block *sb;

	FiMustWriteLock(file);

	err = 0;
	finfo = au_fi(file);
	dentry = file->f_dentry;
	sb = dentry->d_sb;
	inode = dentry->d_inode;
	bstart = au_ibstart(inode);
	if (bstart == finfo->fi_bstart)
		goto out;

	parent = dget_parent(dentry);
	if (au_test_ro(sb, bstart, inode)) {
		di_read_lock_parent(parent, !AuLock_IR);
		err = AuWbrCopyup(au_sbi(sb), dentry);
		bstart = err;
		di_read_unlock(parent, !AuLock_IR);
		if (unlikely(err < 0))
			goto out_parent;
		err = 0;
	}

	di_read_lock_parent(parent, AuLock_IR);
	hi_wh = au_hi_wh(inode, bstart);
	if (au_opt_test(au_mntflags(sb), PLINK)
	    && au_plink_test(inode)
	    && !d_unhashed(dentry)) {
		err = au_test_and_cpup_dirs(dentry, bstart);
		if (unlikely(err))
			goto out_unlock;

		/* always superio. */
		err = au_pin(&pin, dentry, bstart, AuOpt_UDBA_NONE,
			     AuPin_DI_LOCKED | AuPin_MNT_WRITE);
		if (!err)
			err = au_sio_cpup_simple(dentry, bstart, -1,
						 AuCpup_DTIME);
		au_unpin(&pin);
	} else if (hi_wh) {
		/* already copied-up after unlink */
		err = au_reopen_wh(file, bstart, hi_wh);
		*need_reopen = 0;
	}

 out_unlock:
	di_read_unlock(parent, AuLock_IR);
 out_parent:
	dput(parent);
 out:
	return err;
}

static void au_do_refresh_file(struct file *file)
{
	aufs_bindex_t bindex, bend, new_bindex, brid;
	struct au_hfile *p, tmp, *q;
	struct au_finfo *finfo;
	struct super_block *sb;

	FiMustWriteLock(file);

	sb = file->f_dentry->d_sb;
	finfo = au_fi(file);
	p = finfo->fi_hfile + finfo->fi_bstart;
	brid = p->hf_br->br_id;
	bend = finfo->fi_bend;
	for (bindex = finfo->fi_bstart; bindex <= bend; bindex++, p++) {
		if (!p->hf_file)
			continue;

		new_bindex = au_br_index(sb, p->hf_br->br_id);
		if (new_bindex == bindex)
			continue;
		if (new_bindex < 0) {
			au_set_h_fptr(file, bindex, NULL);
			continue;
		}

		/* swap two lower inode, and loop again */
		q = finfo->fi_hfile + new_bindex;
		tmp = *q;
		*q = *p;
		*p = tmp;
		if (tmp.hf_file) {
			bindex--;
			p--;
		}
	}

	p = finfo->fi_hfile;
	if (!au_test_mmapped(file) && !d_unhashed(file->f_dentry)) {
		bend = au_sbend(sb);
		for (finfo->fi_bstart = 0; finfo->fi_bstart <= bend;
		     finfo->fi_bstart++, p++)
			if (p->hf_file) {
				if (p->hf_file->f_dentry
				    && p->hf_file->f_dentry->d_inode)
					break;
				else
					au_hfput(p, file);
			}
	} else {
		bend = au_br_index(sb, brid);
		for (finfo->fi_bstart = 0; finfo->fi_bstart < bend;
		     finfo->fi_bstart++, p++)
			if (p->hf_file)
				au_hfput(p, file);
		bend = au_sbend(sb);
	}

	p = finfo->fi_hfile + bend;
	for (finfo->fi_bend = bend; finfo->fi_bend >= finfo->fi_bstart;
	     finfo->fi_bend--, p--)
		if (p->hf_file) {
			if (p->hf_file->f_dentry
			    && p->hf_file->f_dentry->d_inode)
				break;
			else
				au_hfput(p, file);
		}
	AuDebugOn(finfo->fi_bend < finfo->fi_bstart);
}

/*
 * after branch manipulating, refresh the file.
 */
static int refresh_file(struct file *file, int (*reopen)(struct file *file))
{
	int err, need_reopen;
	struct dentry *dentry;
	aufs_bindex_t bend, bindex;

	dentry = file->f_dentry;
	err = au_fi_realloc(au_fi(file), au_sbend(dentry->d_sb) + 1);
	if (unlikely(err))
		goto out;
	au_do_refresh_file(file);

	err = 0;
	need_reopen = 1;
	if (!au_test_mmapped(file))
		err = au_file_refresh_by_inode(file, &need_reopen);
	if (!err && need_reopen && !d_unhashed(dentry))
		err = reopen(file);
	if (!err) {
		au_update_figen(file);
		return 0; /* success */
	}

	/* error, close all lower files */
	bend = au_fbend(file);
	for (bindex = au_fbstart(file); bindex <= bend; bindex++)
		au_set_h_fptr(file, bindex, NULL);

 out:
	return err;
}

/* common function to regular file and dir */
int au_reval_and_lock_fdi(struct file *file, int (*reopen)(struct file *file),
			  int wlock)
{
	int err;
	unsigned int sigen, figen;
	aufs_bindex_t bstart;
	unsigned char pseudo_link;
	struct dentry *dentry;

	err = 0;
	dentry = file->f_dentry;
	sigen = au_sigen(dentry->d_sb);
	fi_write_lock(file);
	figen = au_figen(file);
	di_write_lock_child(dentry);
	bstart = au_dbstart(dentry);
	pseudo_link = (bstart != au_ibstart(dentry->d_inode));
	if (sigen == figen && !pseudo_link && au_fbstart(file) == bstart) {
		if (!wlock) {
			di_downgrade_lock(dentry, AuLock_IR);
			fi_downgrade_lock(file);
		}
		goto out; /* success */
	}

	AuDbg("sigen %d, figen %d\n", sigen, figen);
	if (sigen != au_digen(dentry)
	    || sigen != au_iigen(dentry->d_inode)) {
		err = au_reval_dpath(dentry, sigen);
		if (unlikely(err < 0))
			goto out;
		AuDebugOn(au_digen(dentry) != sigen
			  || au_iigen(dentry->d_inode) != sigen);
	}

	err = refresh_file(file, reopen);
	if (!err) {
		if (!wlock) {
			di_downgrade_lock(dentry, AuLock_IR);
			fi_downgrade_lock(file);
		}
	} else {
		di_write_unlock(dentry);
		fi_write_unlock(file);
	}

 out:
	return err;
}

/* ---------------------------------------------------------------------- */

/* cf. aufs_nopage() */
/* for madvise(2) */
static int aufs_readpage(struct file *file __maybe_unused, struct page *page)
{
	unlock_page(page);
	return 0;
}

/* they will never be called. */
#ifdef CONFIG_AUFS_DEBUG
static int aufs_write_begin(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned flags,
			    struct page **pagep, void **fsdata)
{ AuUnsupport(); return 0; }
static int aufs_write_end(struct file *file, struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned copied,
			  struct page *page, void *fsdata)
{ AuUnsupport(); return 0; }
static int aufs_writepage(struct page *page, struct writeback_control *wbc)
{ AuUnsupport(); return 0; }
static void aufs_sync_page(struct page *page)
{ AuUnsupport(); }

static int aufs_set_page_dirty(struct page *page)
{ AuUnsupport(); return 0; }
static void aufs_invalidatepage(struct page *page, unsigned long offset)
{ AuUnsupport(); }
static int aufs_releasepage(struct page *page, gfp_t gfp)
{ AuUnsupport(); return 0; }
static ssize_t aufs_direct_IO(int rw, struct kiocb *iocb,
			      const struct iovec *iov, loff_t offset,
			      unsigned long nr_segs)
{ AuUnsupport(); return 0; }
static int aufs_get_xip_mem(struct address_space *mapping, pgoff_t pgoff,
			    int create, void **kmem, unsigned long *pfn)
{ AuUnsupport(); return 0; }
static int aufs_migratepage(struct address_space *mapping, struct page *newpage,
			    struct page *page)
{ AuUnsupport(); return 0; }
static int aufs_launder_page(struct page *page)
{ AuUnsupport(); return 0; }
static int aufs_is_partially_uptodate(struct page *page,
				      read_descriptor_t *desc,
				      unsigned long from)
{ AuUnsupport(); return 0; }
static int aufs_error_remove_page(struct address_space *mapping,
				  struct page *page)
{ AuUnsupport(); return 0; }
#endif /* CONFIG_AUFS_DEBUG */

struct address_space_operations aufs_aop = {
	.readpage		= aufs_readpage,
#ifdef CONFIG_AUFS_DEBUG
	.writepage		= aufs_writepage,
	.sync_page		= aufs_sync_page,
	/* no writepages, because of writepage */
	.set_page_dirty		= aufs_set_page_dirty,
	/* no readpages, because of readpage */
	.write_begin		= aufs_write_begin,
	.write_end		= aufs_write_end,
	/* no bmap, no block device */
	.invalidatepage		= aufs_invalidatepage,
	.releasepage		= aufs_releasepage,
	.direct_IO		= aufs_direct_IO,	/* todo */
	.get_xip_mem		= aufs_get_xip_mem,	/* todo */
	.migratepage		= aufs_migratepage,
	.launder_page		= aufs_launder_page,
	.is_partially_uptodate	= aufs_is_partially_uptodate,
	.error_remove_page	= aufs_error_remove_page
#endif /* CONFIG_AUFS_DEBUG */
};
