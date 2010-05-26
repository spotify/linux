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
 * inode functions
 */

#include "aufs.h"

struct inode *au_igrab(struct inode *inode)
{
	if (inode) {
		AuDebugOn(!atomic_read(&inode->i_count));
		atomic_inc_return(&inode->i_count);
	}
	return inode;
}

static void au_refresh_hinode_attr(struct inode *inode, int do_version)
{
	au_cpup_attr_all(inode, /*force*/0);
	au_update_iigen(inode);
	if (do_version)
		inode->i_version++;
}

int au_refresh_hinode_self(struct inode *inode, int do_attr)
{
	int err;
	aufs_bindex_t bindex, new_bindex;
	unsigned char update;
	struct inode *first;
	struct au_hinode *p, *q, tmp;
	struct super_block *sb;
	struct au_iinfo *iinfo;

	IiMustWriteLock(inode);

	update = 0;
	sb = inode->i_sb;
	iinfo = au_ii(inode);
	err = au_ii_realloc(iinfo, au_sbend(sb) + 1);
	if (unlikely(err))
		goto out;

	p = iinfo->ii_hinode + iinfo->ii_bstart;
	first = p->hi_inode;
	err = 0;
	for (bindex = iinfo->ii_bstart; bindex <= iinfo->ii_bend;
	     bindex++, p++) {
		if (!p->hi_inode)
			continue;

		new_bindex = au_br_index(sb, p->hi_id);
		if (new_bindex == bindex)
			continue;

		if (new_bindex < 0) {
			update++;
			au_hiput(p);
			p->hi_inode = NULL;
			continue;
		}

		if (new_bindex < iinfo->ii_bstart)
			iinfo->ii_bstart = new_bindex;
		if (iinfo->ii_bend < new_bindex)
			iinfo->ii_bend = new_bindex;
		/* swap two lower inode, and loop again */
		q = iinfo->ii_hinode + new_bindex;
		tmp = *q;
		*q = *p;
		*p = tmp;
		if (tmp.hi_inode) {
			bindex--;
			p--;
		}
	}
	au_update_brange(inode, /*do_put_zero*/0);
	if (do_attr)
		au_refresh_hinode_attr(inode, update && S_ISDIR(inode->i_mode));

 out:
	return err;
}

int au_refresh_hinode(struct inode *inode, struct dentry *dentry)
{
	int err, update;
	unsigned int flags;
	aufs_bindex_t bindex, bend;
	unsigned char isdir;
	struct inode *first;
	struct au_hinode *p;
	struct au_iinfo *iinfo;

	err = au_refresh_hinode_self(inode, /*do_attr*/0);
	if (unlikely(err))
		goto out;

	update = 0;
	iinfo = au_ii(inode);
	p = iinfo->ii_hinode + iinfo->ii_bstart;
	first = p->hi_inode;
	isdir = S_ISDIR(inode->i_mode);
	flags = au_hi_flags(inode, isdir);
	bend = au_dbend(dentry);
	for (bindex = au_dbstart(dentry); bindex <= bend; bindex++) {
		struct inode *h_i;
		struct dentry *h_d;

		h_d = au_h_dptr(dentry, bindex);
		if (!h_d || !h_d->d_inode)
			continue;

		if (iinfo->ii_bstart <= bindex && bindex <= iinfo->ii_bend) {
			h_i = au_h_iptr(inode, bindex);
			if (h_i) {
				if (h_i == h_d->d_inode)
					continue;
				err = -EIO;
				break;
			}
		}
		if (bindex < iinfo->ii_bstart)
			iinfo->ii_bstart = bindex;
		if (iinfo->ii_bend < bindex)
			iinfo->ii_bend = bindex;
		au_set_h_iptr(inode, bindex, au_igrab(h_d->d_inode), flags);
		update = 1;
	}
	au_update_brange(inode, /*do_put_zero*/0);

	if (unlikely(err))
		goto out;

	au_refresh_hinode_attr(inode, update && isdir);

 out:
	AuTraceErr(err);
	return err;
}

static int set_inode(struct inode *inode, struct dentry *dentry)
{
	int err;
	unsigned int flags;
	umode_t mode;
	aufs_bindex_t bindex, bstart, btail;
	unsigned char isdir;
	struct dentry *h_dentry;
	struct inode *h_inode;
	struct au_iinfo *iinfo;

	IiMustWriteLock(inode);

	err = 0;
	isdir = 0;
	bstart = au_dbstart(dentry);
	h_inode = au_h_dptr(dentry, bstart)->d_inode;
	mode = h_inode->i_mode;
	switch (mode & S_IFMT) {
	case S_IFREG:
		btail = au_dbtail(dentry);
		inode->i_op = &aufs_iop;
		inode->i_fop = &aufs_file_fop;
		inode->i_mapping->a_ops = &aufs_aop;
		break;
	case S_IFDIR:
		isdir = 1;
		btail = au_dbtaildir(dentry);
		inode->i_op = &aufs_dir_iop;
		inode->i_fop = &aufs_dir_fop;
		break;
	case S_IFLNK:
		btail = au_dbtail(dentry);
		inode->i_op = &aufs_symlink_iop;
		break;
	case S_IFBLK:
	case S_IFCHR:
	case S_IFIFO:
	case S_IFSOCK:
		btail = au_dbtail(dentry);
		inode->i_op = &aufs_iop;
		init_special_inode(inode, mode, h_inode->i_rdev);
		break;
	default:
		AuIOErr("Unknown file type 0%o\n", mode);
		err = -EIO;
		goto out;
	}

	/* do not set inotify for whiteouted dirs (SHWH mode) */
	flags = au_hi_flags(inode, isdir);
	if (au_opt_test(au_mntflags(dentry->d_sb), SHWH)
	    && au_ftest_hi(flags, HINOTIFY)
	    && dentry->d_name.len > AUFS_WH_PFX_LEN
	    && !memcmp(dentry->d_name.name, AUFS_WH_PFX, AUFS_WH_PFX_LEN))
		au_fclr_hi(flags, HINOTIFY);
	iinfo = au_ii(inode);
	iinfo->ii_bstart = bstart;
	iinfo->ii_bend = btail;
	for (bindex = bstart; bindex <= btail; bindex++) {
		h_dentry = au_h_dptr(dentry, bindex);
		if (h_dentry)
			au_set_h_iptr(inode, bindex,
				      au_igrab(h_dentry->d_inode), flags);
	}
	au_cpup_attr_all(inode, /*force*/1);

 out:
	return err;
}

/* successful returns with iinfo write_locked */
static int reval_inode(struct inode *inode, struct dentry *dentry, int *matched)
{
	int err;
	aufs_bindex_t bindex, bend;
	struct inode *h_inode, *h_dinode;

	*matched = 0;

	/*
	 * before this function, if aufs got any iinfo lock, it must be only
	 * one, the parent dir.
	 * it can happen by UDBA and the obsoleted inode number.
	 */
	err = -EIO;
	if (unlikely(inode->i_ino == parent_ino(dentry)))
		goto out;

	err = 0;
	ii_write_lock_new_child(inode);
	h_dinode = au_h_dptr(dentry, au_dbstart(dentry))->d_inode;
	bend = au_ibend(inode);
	for (bindex = au_ibstart(inode); bindex <= bend; bindex++) {
		h_inode = au_h_iptr(inode, bindex);
		if (h_inode && h_inode == h_dinode) {
			*matched = 1;
			err = 0;
			if (au_iigen(inode) != au_digen(dentry))
				err = au_refresh_hinode(inode, dentry);
			break;
		}
	}

	if (unlikely(err))
		ii_write_unlock(inode);
 out:
	return err;
}

int au_ino(struct super_block *sb, aufs_bindex_t bindex, ino_t h_ino,
	   unsigned int d_type, ino_t *ino)
{
	int err;
	struct mutex *mtx;
	const int isdir = (d_type == DT_DIR);

	/* prevent hardlinks from race condition */
	mtx = NULL;
	if (!isdir) {
		mtx = &au_sbr(sb, bindex)->br_xino.xi_nondir_mtx;
		mutex_lock(mtx);
	}
	err = au_xino_read(sb, bindex, h_ino, ino);
	if (unlikely(err))
		goto out;

	if (!*ino) {
		err = -EIO;
		*ino = au_xino_new_ino(sb);
		if (unlikely(!*ino))
			goto out;
		err = au_xino_write(sb, bindex, h_ino, *ino);
		if (unlikely(err))
			goto out;
	}

 out:
	if (!isdir)
		mutex_unlock(mtx);
	return err;
}

/* successful returns with iinfo write_locked */
/* todo: return with unlocked? */
struct inode *au_new_inode(struct dentry *dentry, int must_new)
{
	struct inode *inode;
	struct dentry *h_dentry;
	struct super_block *sb;
	ino_t h_ino, ino;
	int err, match;
	aufs_bindex_t bstart;

	sb = dentry->d_sb;
	bstart = au_dbstart(dentry);
	h_dentry = au_h_dptr(dentry, bstart);
	h_ino = h_dentry->d_inode->i_ino;
	err = au_xino_read(sb, bstart, h_ino, &ino);
	inode = ERR_PTR(err);
	if (unlikely(err))
		goto out;
 new_ino:
	if (!ino) {
		ino = au_xino_new_ino(sb);
		if (unlikely(!ino)) {
			inode = ERR_PTR(-EIO);
			goto out;
		}
	}

	AuDbg("i%lu\n", (unsigned long)ino);
	inode = au_iget_locked(sb, ino);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out;

	AuDbg("%lx, new %d\n", inode->i_state, !!(inode->i_state & I_NEW));
	if (inode->i_state & I_NEW) {
		ii_write_lock_new_child(inode);
		err = set_inode(inode, dentry);
		unlock_new_inode(inode);
		if (!err)
			goto out; /* success */

		iget_failed(inode);
		ii_write_unlock(inode);
		goto out_iput;
	} else if (!must_new) {
		err = reval_inode(inode, dentry, &match);
		if (!err)
			goto out; /* success */
		else if (match)
			goto out_iput;
	}

	if (unlikely(au_test_fs_unique_ino(h_dentry->d_inode)))
		AuWarn1("Warning: Un-notified UDBA or repeatedly renamed dir,"
			" b%d, %s, %.*s, hi%lu, i%lu.\n",
			bstart, au_sbtype(h_dentry->d_sb), AuDLNPair(dentry),
			(unsigned long)h_ino, (unsigned long)ino);
	ino = 0;
	err = au_xino_write(sb, bstart, h_ino, /*ino*/0);
	if (!err) {
		iput(inode);
		goto new_ino;
	}

 out_iput:
	iput(inode);
	inode = ERR_PTR(err);
 out:
	return inode;
}

/* ---------------------------------------------------------------------- */

int au_test_ro(struct super_block *sb, aufs_bindex_t bindex,
	       struct inode *inode)
{
	int err;

	err = au_br_rdonly(au_sbr(sb, bindex));

	/* pseudo-link after flushed may happen out of bounds */
	if (!err
	    && inode
	    && au_ibstart(inode) <= bindex
	    && bindex <= au_ibend(inode)) {
		/*
		 * permission check is unnecessary since vfsub routine
		 * will be called later
		 */
		struct inode *hi = au_h_iptr(inode, bindex);
		if (hi)
			err = IS_IMMUTABLE(hi) ? -EROFS : 0;
	}

	return err;
}

int au_test_h_perm(struct inode *h_inode, int mask)
{
	if (!current_fsuid())
		return 0;
	return inode_permission(h_inode, mask);
}

int au_test_h_perm_sio(struct inode *h_inode, int mask)
{
	if (au_test_nfs(h_inode->i_sb)
	    && (mask & MAY_WRITE)
	    && S_ISDIR(h_inode->i_mode))
		mask |= MAY_READ; /* force permission check */
	return au_test_h_perm(h_inode, mask);
}
