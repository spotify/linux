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
 * inode operations (except add/del/rename)
 */

#include <linux/device_cgroup.h>
#include <linux/fs_stack.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include "aufs.h"

static int h_permission(struct inode *h_inode, int mask,
			struct vfsmount *h_mnt, int brperm)
{
	int err;
	const unsigned char write_mask = !!(mask & (MAY_WRITE | MAY_APPEND));

	err = -EACCES;
	if ((write_mask && IS_IMMUTABLE(h_inode))
	    || ((mask & MAY_EXEC)
		&& S_ISREG(h_inode->i_mode)
		&& ((h_mnt->mnt_flags & MNT_NOEXEC)
		    || !(h_inode->i_mode & S_IXUGO))))
		goto out;

	/*
	 * - skip the lower fs test in the case of write to ro branch.
	 * - nfs dir permission write check is optimized, but a policy for
	 *   link/rename requires a real check.
	 */
	if ((write_mask && !au_br_writable(brperm))
	    || (au_test_nfs(h_inode->i_sb) && S_ISDIR(h_inode->i_mode)
		&& write_mask && !(mask & MAY_READ))
	    || !h_inode->i_op->permission) {
		/* AuLabel(generic_permission); */
		err = generic_permission(h_inode, mask, NULL);
	} else {
		/* AuLabel(h_inode->permission); */
		err = h_inode->i_op->permission(h_inode, mask);
		AuTraceErr(err);
	}

	if (!err)
		err = devcgroup_inode_permission(h_inode, mask);
	if (!err)
		err = security_inode_permission
			(h_inode, mask & (MAY_READ | MAY_WRITE | MAY_EXEC
					  | MAY_APPEND));

#if 0
	if (!err) {
		/* todo: do we need to call ima_path_check()? */
		struct path h_path = {
			.dentry	=
			.mnt	= h_mnt
		};
		err = ima_path_check(&h_path,
				     mask & (MAY_READ | MAY_WRITE | MAY_EXEC),
				     IMA_COUNT_LEAVE);
	}
#endif

 out:
	return err;
}

static int aufs_permission(struct inode *inode, int mask)
{
	int err;
	aufs_bindex_t bindex, bend;
	const unsigned char isdir = !!S_ISDIR(inode->i_mode);
	const unsigned char write_mask = !!(mask & (MAY_WRITE | MAY_APPEND));
	struct inode *h_inode;
	struct super_block *sb;
	struct au_branch *br;

	sb = inode->i_sb;
	si_read_lock(sb, AuLock_FLUSH);
	ii_read_lock_child(inode);

	if (!isdir || write_mask) {
		err = au_busy_or_stale();
		h_inode = au_h_iptr(inode, au_ibstart(inode));
		if (unlikely(!h_inode
			     || (h_inode->i_mode & S_IFMT)
			     != (inode->i_mode & S_IFMT)))
			goto out;

		err = 0;
		bindex = au_ibstart(inode);
		br = au_sbr(sb, bindex);
		err = h_permission(h_inode, mask, br->br_mnt, br->br_perm);
		if (write_mask && !err) {
			/* test whether the upper writable branch exists */
			err = -EROFS;
			for (; bindex >= 0; bindex--)
				if (!au_br_rdonly(au_sbr(sb, bindex))) {
					err = 0;
					break;
				}
		}
		goto out;
	}

	/* non-write to dir */
	err = 0;
	bend = au_ibend(inode);
	for (bindex = au_ibstart(inode); !err && bindex <= bend; bindex++) {
		h_inode = au_h_iptr(inode, bindex);
		if (h_inode) {
			err = au_busy_or_stale();
			if (unlikely(!S_ISDIR(h_inode->i_mode)))
				break;

			br = au_sbr(sb, bindex);
			err = h_permission(h_inode, mask, br->br_mnt,
					   br->br_perm);
		}
	}

 out:
	ii_read_unlock(inode);
	si_read_unlock(sb);
	return err;
}

/* ---------------------------------------------------------------------- */

static struct dentry *aufs_lookup(struct inode *dir, struct dentry *dentry,
				  struct nameidata *nd)
{
	struct dentry *ret, *parent;
	struct inode *inode, *h_inode;
	struct mutex *mtx;
	struct super_block *sb;
	int err, npositive;
	aufs_bindex_t bstart;

	IMustLock(dir);

	sb = dir->i_sb;
	si_read_lock(sb, AuLock_FLUSH);
	ret = ERR_PTR(-ENAMETOOLONG);
	if (unlikely(dentry->d_name.len > AUFS_MAX_NAMELEN))
		goto out;
	err = au_alloc_dinfo(dentry);
	ret = ERR_PTR(err);
	if (unlikely(err))
		goto out;

	parent = dentry->d_parent; /* dir inode is locked */
	di_read_lock_parent(parent, AuLock_IR);
	npositive = au_lkup_dentry(dentry, au_dbstart(parent), /*type*/0, nd);
	di_read_unlock(parent, AuLock_IR);
	err = npositive;
	ret = ERR_PTR(err);
	if (unlikely(err < 0))
		goto out_unlock;

	inode = NULL;
	if (npositive) {
		bstart = au_dbstart(dentry);
		h_inode = au_h_dptr(dentry, bstart)->d_inode;
		if (!S_ISDIR(h_inode->i_mode)) {
			/*
			 * stop 'race'-ing between hardlinks under different
			 * parents.
			 */
			mtx = &au_sbr(sb, bstart)->br_xino.xi_nondir_mtx;
			mutex_lock(mtx);
			inode = au_new_inode(dentry, /*must_new*/0);
			mutex_unlock(mtx);
		} else
			inode = au_new_inode(dentry, /*must_new*/0);
		ret = (void *)inode;
	}
	if (IS_ERR(inode))
		goto out_unlock;

	ret = d_splice_alias(inode, dentry);
	if (unlikely(IS_ERR(ret) && inode))
		ii_write_unlock(inode);

 out_unlock:
	di_write_unlock(dentry);
 out:
	si_read_unlock(sb);
	return ret;
}

/* ---------------------------------------------------------------------- */

static int au_wr_dir_cpup(struct dentry *dentry, struct dentry *parent,
			  const unsigned char add_entry, aufs_bindex_t bcpup,
			  aufs_bindex_t bstart)
{
	int err;
	struct dentry *h_parent;
	struct inode *h_dir;

	if (add_entry) {
		au_update_dbstart(dentry);
		IMustLock(parent->d_inode);
	} else
		di_write_lock_parent(parent);

	err = 0;
	if (!au_h_dptr(parent, bcpup)) {
		if (bstart < bcpup)
			err = au_cpdown_dirs(dentry, bcpup);
		else
			err = au_cpup_dirs(dentry, bcpup);
	}
	if (!err && add_entry) {
		h_parent = au_h_dptr(parent, bcpup);
		h_dir = h_parent->d_inode;
		mutex_lock_nested(&h_dir->i_mutex, AuLsc_I_PARENT);
		err = au_lkup_neg(dentry, bcpup);
		/* todo: no unlock here */
		mutex_unlock(&h_dir->i_mutex);
		if (bstart < bcpup && au_dbstart(dentry) < 0) {
			au_set_dbstart(dentry, 0);
			au_update_dbrange(dentry, /*do_put_zero*/0);
		}
	}

	if (!add_entry)
		di_write_unlock(parent);
	if (!err)
		err = bcpup; /* success */

	return err;
}

/*
 * decide the branch and the parent dir where we will create a new entry.
 * returns new bindex or an error.
 * copyup the parent dir if needed.
 */
int au_wr_dir(struct dentry *dentry, struct dentry *src_dentry,
	      struct au_wr_dir_args *args)
{
	int err;
	aufs_bindex_t bcpup, bstart, src_bstart;
	const unsigned char add_entry = !!au_ftest_wrdir(args->flags,
							 ADD_ENTRY);
	struct super_block *sb;
	struct dentry *parent;
	struct au_sbinfo *sbinfo;

	sb = dentry->d_sb;
	sbinfo = au_sbi(sb);
	parent = dget_parent(dentry);
	bstart = au_dbstart(dentry);
	bcpup = bstart;
	if (args->force_btgt < 0) {
		if (src_dentry) {
			src_bstart = au_dbstart(src_dentry);
			if (src_bstart < bstart)
				bcpup = src_bstart;
		} else if (add_entry) {
			err = AuWbrCreate(sbinfo, dentry,
					  au_ftest_wrdir(args->flags, ISDIR));
			bcpup = err;
		}

		if (bcpup < 0 || au_test_ro(sb, bcpup, dentry->d_inode)) {
			if (add_entry)
				err = AuWbrCopyup(sbinfo, dentry);
			else {
				if (!IS_ROOT(dentry)) {
					di_read_lock_parent(parent, !AuLock_IR);
					err = AuWbrCopyup(sbinfo, dentry);
					di_read_unlock(parent, !AuLock_IR);
				} else
					err = AuWbrCopyup(sbinfo, dentry);
			}
			bcpup = err;
			if (unlikely(err < 0))
				goto out;
		}
	} else {
		bcpup = args->force_btgt;
		AuDebugOn(au_test_ro(sb, bcpup, dentry->d_inode));
	}
	AuDbg("bstart %d, bcpup %d\n", bstart, bcpup);
	if (bstart < bcpup)
		au_update_dbrange(dentry, /*do_put_zero*/1);

	err = bcpup;
	if (bcpup == bstart)
		goto out; /* success */

	/* copyup the new parent into the branch we process */
	err = au_wr_dir_cpup(dentry, parent, add_entry, bcpup, bstart);

 out:
	dput(parent);
	return err;
}

/* ---------------------------------------------------------------------- */

struct dentry *au_pinned_h_parent(struct au_pin *pin)
{
	if (pin && pin->parent)
		return au_h_dptr(pin->parent, pin->bindex);
	return NULL;
}

void au_unpin(struct au_pin *p)
{
	if (au_ftest_pin(p->flags, MNT_WRITE))
		mnt_drop_write(p->h_mnt);
	if (!p->hdir)
		return;

	au_hin_imtx_unlock(p->hdir);
	if (!au_ftest_pin(p->flags, DI_LOCKED))
		di_read_unlock(p->parent, AuLock_IR);
	iput(p->hdir->hi_inode);
	dput(p->parent);
	p->parent = NULL;
	p->hdir = NULL;
	p->h_mnt = NULL;
}

int au_do_pin(struct au_pin *p)
{
	int err;
	struct super_block *sb;
	struct dentry *h_dentry, *h_parent;
	struct au_branch *br;
	struct inode *h_dir;

	err = 0;
	sb = p->dentry->d_sb;
	br = au_sbr(sb, p->bindex);
	if (IS_ROOT(p->dentry)) {
		if (au_ftest_pin(p->flags, MNT_WRITE)) {
			p->h_mnt = br->br_mnt;
			err = mnt_want_write(p->h_mnt);
			if (unlikely(err)) {
				au_fclr_pin(p->flags, MNT_WRITE);
				goto out_err;
			}
		}
		goto out;
	}

	h_dentry = NULL;
	if (p->bindex <= au_dbend(p->dentry))
		h_dentry = au_h_dptr(p->dentry, p->bindex);

	p->parent = dget_parent(p->dentry);
	if (!au_ftest_pin(p->flags, DI_LOCKED))
		di_read_lock(p->parent, AuLock_IR, p->lsc_di);

	h_dir = NULL;
	h_parent = au_h_dptr(p->parent, p->bindex);
	p->hdir = au_hi(p->parent->d_inode, p->bindex);
	if (p->hdir)
		h_dir = p->hdir->hi_inode;

	/* udba case */
	if (unlikely(!p->hdir || !h_dir)) {
		if (!au_ftest_pin(p->flags, DI_LOCKED))
			di_read_unlock(p->parent, AuLock_IR);
		dput(p->parent);
		p->parent = NULL;
		goto out_err;
	}

	au_igrab(h_dir);
	au_hin_imtx_lock_nested(p->hdir, p->lsc_hi);

	if (unlikely(p->hdir->hi_inode != h_parent->d_inode)) {
		err = -EBUSY;
		goto out_unpin;
	}
	if (h_dentry) {
		err = au_h_verify(h_dentry, p->udba, h_dir, h_parent, br);
		if (unlikely(err)) {
			au_fclr_pin(p->flags, MNT_WRITE);
			goto out_unpin;
		}
	}

	if (au_ftest_pin(p->flags, MNT_WRITE)) {
		p->h_mnt = br->br_mnt;
		err = mnt_want_write(p->h_mnt);
		if (unlikely(err)) {
			au_fclr_pin(p->flags, MNT_WRITE);
			goto out_unpin;
		}
	}
	goto out; /* success */

 out_unpin:
	au_unpin(p);
 out_err:
	pr_err("err %d\n", err);
	err = au_busy_or_stale();
 out:
	return err;
}

void au_pin_init(struct au_pin *p, struct dentry *dentry,
		 aufs_bindex_t bindex, int lsc_di, int lsc_hi,
		 unsigned int udba, unsigned char flags)
{
	p->dentry = dentry;
	p->udba = udba;
	p->lsc_di = lsc_di;
	p->lsc_hi = lsc_hi;
	p->flags = flags;
	p->bindex = bindex;

	p->parent = NULL;
	p->hdir = NULL;
	p->h_mnt = NULL;
}

int au_pin(struct au_pin *pin, struct dentry *dentry, aufs_bindex_t bindex,
	   unsigned int udba, unsigned char flags)
{
	au_pin_init(pin, dentry, bindex, AuLsc_DI_PARENT, AuLsc_I_PARENT2,
		    udba, flags);
	return au_do_pin(pin);
}

/* ---------------------------------------------------------------------- */

#define AuIcpup_DID_CPUP	1
#define au_ftest_icpup(flags, name)	((flags) & AuIcpup_##name)
#define au_fset_icpup(flags, name)	{ (flags) |= AuIcpup_##name; }
#define au_fclr_icpup(flags, name)	{ (flags) &= ~AuIcpup_##name; }

struct au_icpup_args {
	unsigned char flags;
	unsigned char pin_flags;
	aufs_bindex_t btgt;
	struct au_pin pin;
	struct path h_path;
	struct inode *h_inode;
};

static int au_lock_and_icpup(struct dentry *dentry, struct iattr *ia,
			     struct au_icpup_args *a)
{
	int err;
	unsigned int udba;
	loff_t sz;
	aufs_bindex_t bstart;
	struct dentry *hi_wh, *parent;
	struct inode *inode;
	struct au_wr_dir_args wr_dir_args = {
		.force_btgt	= -1,
		.flags		= 0
	};

	di_write_lock_child(dentry);
	bstart = au_dbstart(dentry);
	inode = dentry->d_inode;
	if (S_ISDIR(inode->i_mode))
		au_fset_wrdir(wr_dir_args.flags, ISDIR);
	/* plink or hi_wh() case */
	if (bstart != au_ibstart(inode))
		wr_dir_args.force_btgt = au_ibstart(inode);
	err = au_wr_dir(dentry, /*src_dentry*/NULL, &wr_dir_args);
	if (unlikely(err < 0))
		goto out_dentry;
	a->btgt = err;
	if (err != bstart)
		au_fset_icpup(a->flags, DID_CPUP);

	err = 0;
	a->pin_flags = AuPin_MNT_WRITE;
	parent = NULL;
	if (!IS_ROOT(dentry)) {
		au_fset_pin(a->pin_flags, DI_LOCKED);
		parent = dget_parent(dentry);
		di_write_lock_parent(parent);
	}

	udba = au_opt_udba(dentry->d_sb);
	if (d_unhashed(dentry) || (ia->ia_valid & ATTR_FILE))
		udba = AuOpt_UDBA_NONE;
	err = au_pin(&a->pin, dentry, a->btgt, udba, a->pin_flags);
	if (unlikely(err)) {
		if (parent) {
			di_write_unlock(parent);
			dput(parent);
		}
		goto out_dentry;
	}
	a->h_path.dentry = au_h_dptr(dentry, bstart);
	a->h_inode = a->h_path.dentry->d_inode;
	mutex_lock_nested(&a->h_inode->i_mutex, AuLsc_I_CHILD);
	sz = -1;
	if ((ia->ia_valid & ATTR_SIZE) && ia->ia_size < i_size_read(a->h_inode))
		sz = ia->ia_size;

	hi_wh = NULL;
	if (au_ftest_icpup(a->flags, DID_CPUP) && d_unhashed(dentry)) {
		hi_wh = au_hi_wh(inode, a->btgt);
		if (!hi_wh) {
			err = au_sio_cpup_wh(dentry, a->btgt, sz, /*file*/NULL);
			if (unlikely(err))
				goto out_unlock;
			hi_wh = au_hi_wh(inode, a->btgt);
			/* todo: revalidate hi_wh? */
		}
	}

	if (parent) {
		au_pin_set_parent_lflag(&a->pin, /*lflag*/0);
		di_downgrade_lock(parent, AuLock_IR);
		dput(parent);
	}
	if (!au_ftest_icpup(a->flags, DID_CPUP))
		goto out; /* success */

	if (!d_unhashed(dentry)) {
		err = au_sio_cpup_simple(dentry, a->btgt, sz, AuCpup_DTIME);
		if (!err)
			a->h_path.dentry = au_h_dptr(dentry, a->btgt);
	} else if (!hi_wh)
		a->h_path.dentry = au_h_dptr(dentry, a->btgt);
	else
		a->h_path.dentry = hi_wh; /* do not dget here */

 out_unlock:
	mutex_unlock(&a->h_inode->i_mutex);
	a->h_inode = a->h_path.dentry->d_inode;
	if (!err) {
		mutex_lock_nested(&a->h_inode->i_mutex, AuLsc_I_CHILD);
		goto out; /* success */
	}

	au_unpin(&a->pin);

 out_dentry:
	di_write_unlock(dentry);
 out:
	return err;
}

static int aufs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct inode *inode;
	struct super_block *sb;
	struct file *file;
	struct au_icpup_args *a;

	err = -ENOMEM;
	a = kzalloc(sizeof(*a), GFP_NOFS);
	if (unlikely(!a))
		goto out;

	inode = dentry->d_inode;
	IMustLock(inode);
	sb = dentry->d_sb;
	si_read_lock(sb, AuLock_FLUSH);

	file = NULL;
	if (ia->ia_valid & ATTR_FILE) {
		/* currently ftruncate(2) only */
		file = ia->ia_file;
		fi_write_lock(file);
		ia->ia_file = au_h_fptr(file, au_fbstart(file));
	}

	if (ia->ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		ia->ia_valid &= ~ATTR_MODE;

	err = au_lock_and_icpup(dentry, ia, a);
	if (unlikely(err < 0))
		goto out_si;
	if (au_ftest_icpup(a->flags, DID_CPUP)) {
		ia->ia_file = NULL;
		ia->ia_valid &= ~ATTR_FILE;
	}

	a->h_path.mnt = au_sbr_mnt(sb, a->btgt);
	if (ia->ia_valid & ATTR_SIZE) {
		struct file *f;

		if (ia->ia_size < i_size_read(inode)) {
			/* unmap only */
			err = vmtruncate(inode, ia->ia_size);
			if (unlikely(err))
				goto out_unlock;
		}

		f = NULL;
		if (ia->ia_valid & ATTR_FILE)
			f = ia->ia_file;
		mutex_unlock(&a->h_inode->i_mutex);
		err = vfsub_trunc(&a->h_path, ia->ia_size, ia->ia_valid, f);
		mutex_lock_nested(&a->h_inode->i_mutex, AuLsc_I_CHILD);
	} else
		err = vfsub_notify_change(&a->h_path, ia);
	if (!err)
		au_cpup_attr_changeable(inode);

 out_unlock:
	mutex_unlock(&a->h_inode->i_mutex);
	au_unpin(&a->pin);
	di_write_unlock(dentry);
 out_si:
	if (file) {
		fi_write_unlock(file);
		ia->ia_file = file;
		ia->ia_valid |= ATTR_FILE;
	}
	si_read_unlock(sb);
	kfree(a);
 out:
	return err;
}

static int au_getattr_lock_reval(struct dentry *dentry, unsigned int sigen)
{
	int err;
	struct inode *inode;
	struct dentry *parent;

	err = 0;
	inode = dentry->d_inode;
	di_write_lock_child(dentry);
	if (au_digen(dentry) != sigen || au_iigen(inode) != sigen) {
		parent = dget_parent(dentry);
		di_read_lock_parent(parent, AuLock_IR);
		/* returns a number of positive dentries */
		err = au_refresh_hdentry(dentry, inode->i_mode & S_IFMT);
		if (err >= 0)
			err = au_refresh_hinode(inode, dentry);
		di_read_unlock(parent, AuLock_IR);
		dput(parent);
	}
	di_downgrade_lock(dentry, AuLock_IR);
	if (unlikely(err))
		di_read_unlock(dentry, AuLock_IR);

	AuTraceErr(err);
	return err;
}

static void au_refresh_iattr(struct inode *inode, struct kstat *st,
			     unsigned int nlink)
{
	inode->i_mode = st->mode;
	inode->i_uid = st->uid;
	inode->i_gid = st->gid;
	inode->i_atime = st->atime;
	inode->i_mtime = st->mtime;
	inode->i_ctime = st->ctime;

	au_cpup_attr_nlink(inode, /*force*/0);
	if (S_ISDIR(inode->i_mode)) {
		inode->i_nlink -= nlink;
		inode->i_nlink += st->nlink;
	}

	spin_lock(&inode->i_lock);
	inode->i_blocks = st->blocks;
	i_size_write(inode, st->size);
	spin_unlock(&inode->i_lock);
}

static int aufs_getattr(struct vfsmount *mnt __maybe_unused,
			struct dentry *dentry, struct kstat *st)
{
	int err;
	unsigned int mnt_flags;
	aufs_bindex_t bindex;
	unsigned char udba_none, positive;
	struct super_block *sb, *h_sb;
	struct inode *inode;
	struct vfsmount *h_mnt;
	struct dentry *h_dentry;

	err = 0;
	sb = dentry->d_sb;
	inode = dentry->d_inode;
	si_read_lock(sb, AuLock_FLUSH);
	mnt_flags = au_mntflags(sb);
	udba_none = !!au_opt_test(mnt_flags, UDBA_NONE);

	/* support fstat(2) */
	if (!d_unhashed(dentry) && !udba_none) {
		unsigned int sigen = au_sigen(sb);
		if (au_digen(dentry) == sigen && au_iigen(inode) == sigen)
			di_read_lock_child(dentry, AuLock_IR);
		else {
			AuDebugOn(IS_ROOT(dentry));
			err = au_getattr_lock_reval(dentry, sigen);
			if (unlikely(err))
				goto out;
		}
	} else
		di_read_lock_child(dentry, AuLock_IR);

	bindex = au_ibstart(inode);
	h_mnt = au_sbr_mnt(sb, bindex);
	h_sb = h_mnt->mnt_sb;
	if (!au_test_fs_bad_iattr(h_sb) && udba_none)
		goto out_fill; /* success */

	h_dentry = NULL;
	if (au_dbstart(dentry) == bindex)
		h_dentry = dget(au_h_dptr(dentry, bindex));
	else if (au_opt_test(mnt_flags, PLINK) && au_plink_test(inode)) {
		h_dentry = au_plink_lkup(inode, bindex);
		if (IS_ERR(h_dentry))
			goto out_fill; /* pretending success */
	}
	/* illegally overlapped or something */
	if (unlikely(!h_dentry))
		goto out_fill; /* pretending success */

	positive = !!h_dentry->d_inode;
	if (positive)
		err = vfs_getattr(h_mnt, h_dentry, st);
	dput(h_dentry);
	if (!err) {
		if (positive)
			au_refresh_iattr(inode, st, h_dentry->d_inode->i_nlink);
		goto out_fill; /* success */
	}
	goto out_unlock;

 out_fill:
	generic_fillattr(inode, st);
 out_unlock:
	di_read_unlock(dentry, AuLock_IR);
 out:
	si_read_unlock(sb);
	return err;
}

/* ---------------------------------------------------------------------- */

static int h_readlink(struct dentry *dentry, int bindex, char __user *buf,
		      int bufsiz)
{
	int err;
	struct super_block *sb;
	struct dentry *h_dentry;

	err = -EINVAL;
	h_dentry = au_h_dptr(dentry, bindex);
	if (unlikely(/* !h_dentry
		     || !h_dentry->d_inode
		     || !h_dentry->d_inode->i_op
		     || */ !h_dentry->d_inode->i_op->readlink))
		goto out;

	err = security_inode_readlink(h_dentry);
	if (unlikely(err))
		goto out;

	sb = dentry->d_sb;
	if (!au_test_ro(sb, bindex, dentry->d_inode)) {
		vfsub_touch_atime(au_sbr_mnt(sb, bindex), h_dentry);
		fsstack_copy_attr_atime(dentry->d_inode, h_dentry->d_inode);
	}
	err = h_dentry->d_inode->i_op->readlink(h_dentry, buf, bufsiz);

 out:
	return err;
}

static int aufs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;

	aufs_read_lock(dentry, AuLock_IR);
	err = h_readlink(dentry, au_dbstart(dentry), buf, bufsiz);
	aufs_read_unlock(dentry, AuLock_IR);

	return err;
}

static void *aufs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	int err;
	char *buf;
	mm_segment_t old_fs;

	err = -ENOMEM;
	buf = __getname();
	if (unlikely(!buf))
		goto out;

	aufs_read_lock(dentry, AuLock_IR);
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = h_readlink(dentry, au_dbstart(dentry), (char __user *)buf,
			 PATH_MAX);
	set_fs(old_fs);
	aufs_read_unlock(dentry, AuLock_IR);

	if (err >= 0) {
		buf[err] = 0;
		/* will be freed by put_link */
		nd_set_link(nd, buf);
		return NULL; /* success */
	}
	__putname(buf);

 out:
	path_put(&nd->path);
	AuTraceErr(err);
	return ERR_PTR(err);
}

static void aufs_put_link(struct dentry *dentry __maybe_unused,
			  struct nameidata *nd, void *cookie __maybe_unused)
{
	__putname(nd_get_link(nd));
}

/* ---------------------------------------------------------------------- */

static void aufs_truncate_range(struct inode *inode __maybe_unused,
				loff_t start __maybe_unused,
				loff_t end __maybe_unused)
{
	AuUnsupport();
}

/* ---------------------------------------------------------------------- */

struct inode_operations aufs_symlink_iop = {
	.permission	= aufs_permission,
	.setattr	= aufs_setattr,
	.getattr	= aufs_getattr,
	.readlink	= aufs_readlink,
	.follow_link	= aufs_follow_link,
	.put_link	= aufs_put_link
};

struct inode_operations aufs_dir_iop = {
	.create		= aufs_create,
	.lookup		= aufs_lookup,
	.link		= aufs_link,
	.unlink		= aufs_unlink,
	.symlink	= aufs_symlink,
	.mkdir		= aufs_mkdir,
	.rmdir		= aufs_rmdir,
	.mknod		= aufs_mknod,
	.rename		= aufs_rename,

	.permission	= aufs_permission,
	.setattr	= aufs_setattr,
	.getattr	= aufs_getattr
};

struct inode_operations aufs_iop = {
	.permission	= aufs_permission,
	.setattr	= aufs_setattr,
	.getattr	= aufs_getattr,
	.truncate_range	= aufs_truncate_range
};
