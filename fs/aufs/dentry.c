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
 * lookup and dentry operations
 */

#include <linux/namei.h>
#include "aufs.h"

static void au_h_nd(struct nameidata *h_nd, struct nameidata *nd)
{
	if (nd) {
		*h_nd = *nd;

		/*
		 * gave up supporting LOOKUP_CREATE/OPEN for lower fs,
		 * due to whiteout and branch permission.
		 */
		h_nd->flags &= ~(/*LOOKUP_PARENT |*/ LOOKUP_OPEN | LOOKUP_CREATE
				 | LOOKUP_FOLLOW);
		/* unnecessary? */
		h_nd->intent.open.file = NULL;
	} else
		memset(h_nd, 0, sizeof(*h_nd));
}

struct au_lkup_one_args {
	struct dentry **errp;
	struct qstr *name;
	struct dentry *h_parent;
	struct au_branch *br;
	struct nameidata *nd;
};

struct dentry *au_lkup_one(struct qstr *name, struct dentry *h_parent,
			   struct au_branch *br, struct nameidata *nd)
{
	struct dentry *h_dentry;
	int err;
	struct nameidata h_nd;

	if (au_test_fs_null_nd(h_parent->d_sb))
		return vfsub_lookup_one_len(name->name, h_parent, name->len);

	au_h_nd(&h_nd, nd);
	h_nd.path.dentry = h_parent;
	h_nd.path.mnt = br->br_mnt;

	err = __lookup_one_len(name->name, &h_nd.last, NULL, name->len);
	h_dentry = ERR_PTR(err);
	if (!err) {
		path_get(&h_nd.path);
		h_dentry = vfsub_lookup_hash(&h_nd);
		path_put(&h_nd.path);
	}

	AuTraceErrPtr(h_dentry);
	return h_dentry;
}

static void au_call_lkup_one(void *args)
{
	struct au_lkup_one_args *a = args;
	*a->errp = au_lkup_one(a->name, a->h_parent, a->br, a->nd);
}

#define AuLkup_ALLOW_NEG	1
#define au_ftest_lkup(flags, name)	((flags) & AuLkup_##name)
#define au_fset_lkup(flags, name)	{ (flags) |= AuLkup_##name; }
#define au_fclr_lkup(flags, name)	{ (flags) &= ~AuLkup_##name; }

struct au_do_lookup_args {
	unsigned int		flags;
	mode_t			type;
	struct nameidata	*nd;
};

/*
 * returns positive/negative dentry, NULL or an error.
 * NULL means whiteout-ed or not-found.
 */
static struct dentry*
au_do_lookup(struct dentry *h_parent, struct dentry *dentry,
	     aufs_bindex_t bindex, struct qstr *wh_name,
	     struct au_do_lookup_args *args)
{
	struct dentry *h_dentry;
	struct inode *h_inode, *inode;
	struct qstr *name;
	struct au_branch *br;
	int wh_found, opq;
	unsigned char wh_able;
	const unsigned char allow_neg = !!au_ftest_lkup(args->flags, ALLOW_NEG);

	name = &dentry->d_name;
	wh_found = 0;
	br = au_sbr(dentry->d_sb, bindex);
	wh_able = !!au_br_whable(br->br_perm);
	if (wh_able)
		wh_found = au_wh_test(h_parent, wh_name, br, /*try_sio*/0);
	h_dentry = ERR_PTR(wh_found);
	if (!wh_found)
		goto real_lookup;
	if (unlikely(wh_found < 0))
		goto out;

	/* We found a whiteout */
	/* au_set_dbend(dentry, bindex); */
	au_set_dbwh(dentry, bindex);
	if (!allow_neg)
		return NULL; /* success */

 real_lookup:
	h_dentry = au_lkup_one(name, h_parent, br, args->nd);
	if (IS_ERR(h_dentry))
		goto out;

	h_inode = h_dentry->d_inode;
	if (!h_inode) {
		if (!allow_neg)
			goto out_neg;
	} else if (wh_found
		   || (args->type && args->type != (h_inode->i_mode & S_IFMT)))
		goto out_neg;

	if (au_dbend(dentry) <= bindex)
		au_set_dbend(dentry, bindex);
	if (au_dbstart(dentry) < 0 || bindex < au_dbstart(dentry))
		au_set_dbstart(dentry, bindex);
	au_set_h_dptr(dentry, bindex, h_dentry);

	inode = dentry->d_inode;
	if (!h_inode || !S_ISDIR(h_inode->i_mode) || !wh_able
	    || (inode && !S_ISDIR(inode->i_mode)))
		goto out; /* success */

	mutex_lock_nested(&h_inode->i_mutex, AuLsc_I_CHILD);
	opq = au_diropq_test(h_dentry, br);
	mutex_unlock(&h_inode->i_mutex);
	if (opq > 0)
		au_set_dbdiropq(dentry, bindex);
	else if (unlikely(opq < 0)) {
		au_set_h_dptr(dentry, bindex, NULL);
		h_dentry = ERR_PTR(opq);
	}
	goto out;

 out_neg:
	dput(h_dentry);
	h_dentry = NULL;
 out:
	return h_dentry;
}

static int au_test_shwh(struct super_block *sb, const struct qstr *name)
{
	if (unlikely(!au_opt_test(au_mntflags(sb), SHWH)
		     && !strncmp(name->name, AUFS_WH_PFX, AUFS_WH_PFX_LEN)))
		return -EPERM;
	return 0;
}

/*
 * returns the number of lower positive dentries,
 * otherwise an error.
 * can be called at unlinking with @type is zero.
 */
int au_lkup_dentry(struct dentry *dentry, aufs_bindex_t bstart, mode_t type,
		   struct nameidata *nd)
{
	int npositive, err;
	aufs_bindex_t bindex, btail, bdiropq;
	unsigned char isdir;
	struct qstr whname;
	struct au_do_lookup_args args = {
		.flags	= 0,
		.type	= type,
		.nd	= nd
	};
	const struct qstr *name = &dentry->d_name;
	struct dentry *parent;
	struct inode *inode;

	parent = dget_parent(dentry);
	err = au_test_shwh(dentry->d_sb, name);
	if (unlikely(err))
		goto out;

	err = au_wh_name_alloc(&whname, name);
	if (unlikely(err))
		goto out;

	inode = dentry->d_inode;
	isdir = !!(inode && S_ISDIR(inode->i_mode));
	if (!type)
		au_fset_lkup(args.flags, ALLOW_NEG);

	npositive = 0;
	btail = au_dbtaildir(parent);
	for (bindex = bstart; bindex <= btail; bindex++) {
		struct dentry *h_parent, *h_dentry;
		struct inode *h_inode, *h_dir;

		h_dentry = au_h_dptr(dentry, bindex);
		if (h_dentry) {
			if (h_dentry->d_inode)
				npositive++;
			if (type != S_IFDIR)
				break;
			continue;
		}
		h_parent = au_h_dptr(parent, bindex);
		if (!h_parent)
			continue;
		h_dir = h_parent->d_inode;
		if (!h_dir || !S_ISDIR(h_dir->i_mode))
			continue;

		mutex_lock_nested(&h_dir->i_mutex, AuLsc_I_PARENT);
		h_dentry = au_do_lookup(h_parent, dentry, bindex, &whname,
					&args);
		mutex_unlock(&h_dir->i_mutex);
		err = PTR_ERR(h_dentry);
		if (IS_ERR(h_dentry))
			goto out_wh;
		au_fclr_lkup(args.flags, ALLOW_NEG);

		if (au_dbwh(dentry) >= 0)
			break;
		if (!h_dentry)
			continue;
		h_inode = h_dentry->d_inode;
		if (!h_inode)
			continue;
		npositive++;
		if (!args.type)
			args.type = h_inode->i_mode & S_IFMT;
		if (args.type != S_IFDIR)
			break;
		else if (isdir) {
			/* the type of lower may be different */
			bdiropq = au_dbdiropq(dentry);
			if (bdiropq >= 0 && bdiropq <= bindex)
				break;
		}
	}

	if (npositive) {
		AuLabel(positive);
		au_update_dbstart(dentry);
	}
	err = npositive;
	if (unlikely(!au_opt_test(au_mntflags(dentry->d_sb), UDBA_NONE)
		     && au_dbstart(dentry) < 0))
		/* both of real entry and whiteout found */
		err = -EIO;

 out_wh:
	kfree(whname.name);
 out:
	dput(parent);
	return err;
}

struct dentry *au_sio_lkup_one(struct qstr *name, struct dentry *parent,
			       struct au_branch *br)
{
	struct dentry *dentry;
	int wkq_err;

	if (!au_test_h_perm_sio(parent->d_inode, MAY_EXEC))
		dentry = au_lkup_one(name, parent, br, /*nd*/NULL);
	else {
		struct au_lkup_one_args args = {
			.errp		= &dentry,
			.name		= name,
			.h_parent	= parent,
			.br		= br,
			.nd		= NULL
		};

		wkq_err = au_wkq_wait(au_call_lkup_one, &args);
		if (unlikely(wkq_err))
			dentry = ERR_PTR(wkq_err);
	}

	return dentry;
}

/*
 * lookup @dentry on @bindex which should be negative.
 */
int au_lkup_neg(struct dentry *dentry, aufs_bindex_t bindex)
{
	int err;
	struct dentry *parent, *h_parent, *h_dentry;
	struct qstr *name;

	name = &dentry->d_name;
	parent = dget_parent(dentry);
	h_parent = au_h_dptr(parent, bindex);
	h_dentry = au_sio_lkup_one(name, h_parent,
				   au_sbr(dentry->d_sb, bindex));
	err = PTR_ERR(h_dentry);
	if (IS_ERR(h_dentry))
		goto out;
	if (unlikely(h_dentry->d_inode)) {
		err = -EIO;
		AuIOErr("b%d %.*s should be negative.\n",
			bindex, AuDLNPair(h_dentry));
		dput(h_dentry);
		goto out;
	}

	if (bindex < au_dbstart(dentry))
		au_set_dbstart(dentry, bindex);
	if (au_dbend(dentry) < bindex)
		au_set_dbend(dentry, bindex);
	au_set_h_dptr(dentry, bindex, h_dentry);
	err = 0;

 out:
	dput(parent);
	return err;
}

/* ---------------------------------------------------------------------- */

/* subset of struct inode */
struct au_iattr {
	unsigned long		i_ino;
	/* unsigned int		i_nlink; */
	uid_t			i_uid;
	gid_t			i_gid;
	u64			i_version;
/*
	loff_t			i_size;
	blkcnt_t		i_blocks;
*/
	umode_t			i_mode;
};

static void au_iattr_save(struct au_iattr *ia, struct inode *h_inode)
{
	ia->i_ino = h_inode->i_ino;
	/* ia->i_nlink = h_inode->i_nlink; */
	ia->i_uid = h_inode->i_uid;
	ia->i_gid = h_inode->i_gid;
	ia->i_version = h_inode->i_version;
/*
	ia->i_size = h_inode->i_size;
	ia->i_blocks = h_inode->i_blocks;
*/
	ia->i_mode = (h_inode->i_mode & S_IFMT);
}

static int au_iattr_test(struct au_iattr *ia, struct inode *h_inode)
{
	return ia->i_ino != h_inode->i_ino
		/* || ia->i_nlink != h_inode->i_nlink */
		|| ia->i_uid != h_inode->i_uid
		|| ia->i_gid != h_inode->i_gid
		|| ia->i_version != h_inode->i_version
/*
		|| ia->i_size != h_inode->i_size
		|| ia->i_blocks != h_inode->i_blocks
*/
		|| ia->i_mode != (h_inode->i_mode & S_IFMT);
}

static int au_h_verify_dentry(struct dentry *h_dentry, struct dentry *h_parent,
			      struct au_branch *br)
{
	int err;
	struct au_iattr ia;
	struct inode *h_inode;
	struct dentry *h_d;
	struct super_block *h_sb;

	err = 0;
	memset(&ia, -1, sizeof(ia));
	h_sb = h_dentry->d_sb;
	h_inode = h_dentry->d_inode;
	if (h_inode)
		au_iattr_save(&ia, h_inode);
	else if (au_test_nfs(h_sb) || au_test_fuse(h_sb))
		/* nfs d_revalidate may return 0 for negative dentry */
		/* fuse d_revalidate always return 0 for negative dentry */
		goto out;

	/* main purpose is namei.c:cached_lookup() and d_revalidate */
	h_d = au_lkup_one(&h_dentry->d_name, h_parent, br, /*nd*/NULL);
	err = PTR_ERR(h_d);
	if (IS_ERR(h_d))
		goto out;

	err = 0;
	if (unlikely(h_d != h_dentry
		     || h_d->d_inode != h_inode
		     || (h_inode && au_iattr_test(&ia, h_inode))))
		err = au_busy_or_stale();
	dput(h_d);

 out:
	AuTraceErr(err);
	return err;
}

int au_h_verify(struct dentry *h_dentry, unsigned int udba, struct inode *h_dir,
		struct dentry *h_parent, struct au_branch *br)
{
	int err;

	err = 0;
	if (udba == AuOpt_UDBA_REVAL) {
		IMustLock(h_dir);
		err = (h_dentry->d_parent->d_inode != h_dir);
	} else if (udba == AuOpt_UDBA_HINOTIFY)
		err = au_h_verify_dentry(h_dentry, h_parent, br);

	return err;
}

/* ---------------------------------------------------------------------- */

static void au_do_refresh_hdentry(struct au_hdentry *p, struct au_dinfo *dinfo,
				  struct dentry *parent)
{
	struct dentry *h_d, *h_dp;
	struct au_hdentry tmp, *q;
	struct super_block *sb;
	aufs_bindex_t new_bindex, bindex, bend, bwh, bdiropq;

	AuRwMustWriteLock(&dinfo->di_rwsem);

	bend = dinfo->di_bend;
	bwh = dinfo->di_bwh;
	bdiropq = dinfo->di_bdiropq;
	for (bindex = dinfo->di_bstart; bindex <= bend; bindex++, p++) {
		h_d = p->hd_dentry;
		if (!h_d)
			continue;

		h_dp = dget_parent(h_d);
		if (h_dp == au_h_dptr(parent, bindex)) {
			dput(h_dp);
			continue;
		}

		new_bindex = au_find_dbindex(parent, h_dp);
		dput(h_dp);
		if (dinfo->di_bwh == bindex)
			bwh = new_bindex;
		if (dinfo->di_bdiropq == bindex)
			bdiropq = new_bindex;
		if (new_bindex < 0) {
			au_hdput(p);
			p->hd_dentry = NULL;
			continue;
		}

		/* swap two lower dentries, and loop again */
		q = dinfo->di_hdentry + new_bindex;
		tmp = *q;
		*q = *p;
		*p = tmp;
		if (tmp.hd_dentry) {
			bindex--;
			p--;
		}
	}

	sb = parent->d_sb;
	dinfo->di_bwh = -1;
	if (bwh >= 0 && bwh <= au_sbend(sb) && au_sbr_whable(sb, bwh))
		dinfo->di_bwh = bwh;

	dinfo->di_bdiropq = -1;
	if (bdiropq >= 0
	    && bdiropq <= au_sbend(sb)
	    && au_sbr_whable(sb, bdiropq))
		dinfo->di_bdiropq = bdiropq;

	bend = au_dbend(parent);
	p = dinfo->di_hdentry;
	for (bindex = 0; bindex <= bend; bindex++, p++)
		if (p->hd_dentry) {
			dinfo->di_bstart = bindex;
			break;
		}

	p = dinfo->di_hdentry + bend;
	for (bindex = bend; bindex >= 0; bindex--, p--)
		if (p->hd_dentry) {
			dinfo->di_bend = bindex;
			break;
		}
}

/*
 * returns the number of found lower positive dentries,
 * otherwise an error.
 */
int au_refresh_hdentry(struct dentry *dentry, mode_t type)
{
	int npositive, err;
	unsigned int sigen;
	aufs_bindex_t bstart;
	struct au_dinfo *dinfo;
	struct super_block *sb;
	struct dentry *parent;

	DiMustWriteLock(dentry);

	sb = dentry->d_sb;
	AuDebugOn(IS_ROOT(dentry));
	sigen = au_sigen(sb);
	parent = dget_parent(dentry);
	AuDebugOn(au_digen(parent) != sigen
		  || au_iigen(parent->d_inode) != sigen);

	dinfo = au_di(dentry);
	err = au_di_realloc(dinfo, au_sbend(sb) + 1);
	npositive = err;
	if (unlikely(err))
		goto out;
	au_do_refresh_hdentry(dinfo->di_hdentry + dinfo->di_bstart, dinfo,
			      parent);

	npositive = 0;
	bstart = au_dbstart(parent);
	if (type != S_IFDIR && dinfo->di_bstart == bstart)
		goto out_dgen; /* success */

	npositive = au_lkup_dentry(dentry, bstart, type, /*nd*/NULL);
	if (npositive < 0)
		goto out;
	if (dinfo->di_bwh >= 0 && dinfo->di_bwh <= dinfo->di_bstart)
		d_drop(dentry);

 out_dgen:
	au_update_digen(dentry);
 out:
	dput(parent);
	AuTraceErr(npositive);
	return npositive;
}

static noinline_for_stack
int au_do_h_d_reval(struct dentry *h_dentry, struct nameidata *nd,
		    struct dentry *dentry, aufs_bindex_t bindex)
{
	int err, valid;
	int (*reval)(struct dentry *, struct nameidata *);

	err = 0;
	reval = NULL;
	if (h_dentry->d_op)
		reval = h_dentry->d_op->d_revalidate;
	if (!reval)
		goto out;

	AuDbg("b%d\n", bindex);
	if (au_test_fs_null_nd(h_dentry->d_sb))
		/* it may return tri-state */
		valid = reval(h_dentry, NULL);
	else {
		struct nameidata h_nd;
		int locked;
		struct dentry *parent;

		au_h_nd(&h_nd, nd);
		parent = nd->path.dentry;
		locked = (nd && nd->path.dentry != dentry);
		if (locked)
			di_read_lock_parent(parent, AuLock_IR);
		BUG_ON(bindex > au_dbend(parent));
		h_nd.path.dentry = au_h_dptr(parent, bindex);
		BUG_ON(!h_nd.path.dentry);
		h_nd.path.mnt = au_sbr(parent->d_sb, bindex)->br_mnt;
		path_get(&h_nd.path);
		valid = reval(h_dentry, &h_nd);
		path_put(&h_nd.path);
		if (locked)
			di_read_unlock(parent, AuLock_IR);
	}

	if (unlikely(valid < 0))
		err = valid;
	else if (!valid)
		err = -EINVAL;

 out:
	AuTraceErr(err);
	return err;
}

/* todo: remove this */
static int h_d_revalidate(struct dentry *dentry, struct inode *inode,
			  struct nameidata *nd, int do_udba)
{
	int err;
	umode_t mode, h_mode;
	aufs_bindex_t bindex, btail, bstart, ibs, ibe;
	unsigned char plus, unhashed, is_root, h_plus;
	struct inode *first, *h_inode, *h_cached_inode;
	struct dentry *h_dentry;
	struct qstr *name, *h_name;

	err = 0;
	plus = 0;
	mode = 0;
	first = NULL;
	ibs = -1;
	ibe = -1;
	unhashed = !!d_unhashed(dentry);
	is_root = !!IS_ROOT(dentry);
	name = &dentry->d_name;

	/*
	 * Theoretically, REVAL test should be unnecessary in case of INOTIFY.
	 * But inotify doesn't fire some necessary events,
	 *	IN_ATTRIB for atime/nlink/pageio
	 *	IN_DELETE for NFS dentry
	 * Let's do REVAL test too.
	 */
	if (do_udba && inode) {
		mode = (inode->i_mode & S_IFMT);
		plus = (inode->i_nlink > 0);
		first = au_h_iptr(inode, au_ibstart(inode));
		ibs = au_ibstart(inode);
		ibe = au_ibend(inode);
	}

	bstart = au_dbstart(dentry);
	btail = bstart;
	if (inode && S_ISDIR(inode->i_mode))
		btail = au_dbtaildir(dentry);
	for (bindex = bstart; bindex <= btail; bindex++) {
		h_dentry = au_h_dptr(dentry, bindex);
		if (!h_dentry)
			continue;

		AuDbg("b%d, %.*s\n", bindex, AuDLNPair(h_dentry));
		h_name = &h_dentry->d_name;
		if (unlikely(do_udba
			     && !is_root
			     && (unhashed != !!d_unhashed(h_dentry)
				 || name->len != h_name->len
				 || memcmp(name->name, h_name->name, name->len))
			    )) {
			AuDbg("unhash 0x%x 0x%x, %.*s %.*s\n",
				  unhashed, d_unhashed(h_dentry),
				  AuDLNPair(dentry), AuDLNPair(h_dentry));
			goto err;
		}

		err = au_do_h_d_reval(h_dentry, nd, dentry, bindex);
		if (unlikely(err))
			/* do not goto err, to keep the errno */
			break;

		/* todo: plink too? */
		if (!do_udba)
			continue;

		/* UDBA tests */
		h_inode = h_dentry->d_inode;
		if (unlikely(!!inode != !!h_inode))
			goto err;

		h_plus = plus;
		h_mode = mode;
		h_cached_inode = h_inode;
		if (h_inode) {
			h_mode = (h_inode->i_mode & S_IFMT);
			h_plus = (h_inode->i_nlink > 0);
		}
		if (inode && ibs <= bindex && bindex <= ibe)
			h_cached_inode = au_h_iptr(inode, bindex);

		if (unlikely(plus != h_plus
			     || mode != h_mode
			     || h_cached_inode != h_inode))
			goto err;
		continue;

	err:
		err = -EINVAL;
		break;
	}

	return err;
}

static int simple_reval_dpath(struct dentry *dentry, unsigned int sigen)
{
	int err;
	struct dentry *parent;
	struct inode *inode;

	inode = dentry->d_inode;
	if (au_digen(dentry) == sigen && au_iigen(inode) == sigen)
		return 0;

	parent = dget_parent(dentry);
	di_read_lock_parent(parent, AuLock_IR);
	AuDebugOn(au_digen(parent) != sigen
		  || au_iigen(parent->d_inode) != sigen);
	au_dbg_verify_gen(parent, sigen);

	/* returns a number of positive dentries */
	err = au_refresh_hdentry(dentry, inode->i_mode & S_IFMT);
	if (err >= 0)
		err = au_refresh_hinode(inode, dentry);

	di_read_unlock(parent, AuLock_IR);
	dput(parent);
	return err;
}

int au_reval_dpath(struct dentry *dentry, unsigned int sigen)
{
	int err;
	struct dentry *d, *parent;
	struct inode *inode;

	if (!au_ftest_si(au_sbi(dentry->d_sb), FAILED_REFRESH_DIRS))
		return simple_reval_dpath(dentry, sigen);

	/* slow loop, keep it simple and stupid */
	/* cf: au_cpup_dirs() */
	err = 0;
	parent = NULL;
	while (au_digen(dentry) != sigen
	       || au_iigen(dentry->d_inode) != sigen) {
		d = dentry;
		while (1) {
			dput(parent);
			parent = dget_parent(d);
			if (au_digen(parent) == sigen
			    && au_iigen(parent->d_inode) == sigen)
				break;
			d = parent;
		}

		inode = d->d_inode;
		if (d != dentry)
			di_write_lock_child(d);

		/* someone might update our dentry while we were sleeping */
		if (au_digen(d) != sigen || au_iigen(d->d_inode) != sigen) {
			di_read_lock_parent(parent, AuLock_IR);
			/* returns a number of positive dentries */
			err = au_refresh_hdentry(d, inode->i_mode & S_IFMT);
			if (err >= 0)
				err = au_refresh_hinode(inode, d);
			di_read_unlock(parent, AuLock_IR);
		}

		if (d != dentry)
			di_write_unlock(d);
		dput(parent);
		if (unlikely(err))
			break;
	}

	return err;
}

/*
 * if valid returns 1, otherwise 0.
 */
static int aufs_d_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	int valid, err;
	unsigned int sigen;
	unsigned char do_udba;
	struct super_block *sb;
	struct inode *inode;

	err = -EINVAL;
	sb = dentry->d_sb;
	inode = dentry->d_inode;
	aufs_read_lock(dentry, AuLock_FLUSH | AuLock_DW);
	sigen = au_sigen(sb);
	if (au_digen(dentry) != sigen) {
		AuDebugOn(IS_ROOT(dentry));
		if (inode)
			err = au_reval_dpath(dentry, sigen);
		if (unlikely(err))
			goto out_dgrade;
		AuDebugOn(au_digen(dentry) != sigen);
	}
	if (inode && au_iigen(inode) != sigen) {
		AuDebugOn(IS_ROOT(dentry));
		err = au_refresh_hinode(inode, dentry);
		if (unlikely(err))
			goto out_dgrade;
		AuDebugOn(au_iigen(inode) != sigen);
	}
	di_downgrade_lock(dentry, AuLock_IR);

	AuDebugOn(au_digen(dentry) != sigen);
	AuDebugOn(inode && au_iigen(inode) != sigen);
	err = -EINVAL;
	do_udba = !au_opt_test(au_mntflags(sb), UDBA_NONE);
	if (do_udba && inode) {
		aufs_bindex_t bstart = au_ibstart(inode);

		if (bstart >= 0
		    && au_test_higen(inode, au_h_iptr(inode, bstart)))
			goto out;
	}

	err = h_d_revalidate(dentry, inode, nd, do_udba);
	if (unlikely(!err && do_udba && au_dbstart(dentry) < 0))
		/* both of real entry and whiteout found */
		err = -EIO;
	goto out;

 out_dgrade:
	di_downgrade_lock(dentry, AuLock_IR);
 out:
	aufs_read_unlock(dentry, AuLock_IR);
	AuTraceErr(err);
	valid = !err;
	if (!valid)
		AuDbg("%.*s invalid\n", AuDLNPair(dentry));
	return valid;
}

static void aufs_d_release(struct dentry *dentry)
{
	struct au_dinfo *dinfo;
	aufs_bindex_t bend, bindex;

	dinfo = dentry->d_fsdata;
	if (!dinfo)
		return;

	/* dentry may not be revalidated */
	bindex = dinfo->di_bstart;
	if (bindex >= 0) {
		struct au_hdentry *p;

		bend = dinfo->di_bend;
		p = dinfo->di_hdentry + bindex;
		while (bindex++ <= bend) {
			if (p->hd_dentry)
				au_hdput(p);
			p++;
		}
	}
	kfree(dinfo->di_hdentry);
	AuRwDestroy(&dinfo->di_rwsem);
	au_cache_free_dinfo(dinfo);
	au_hin_di_reinit(dentry);
}

struct dentry_operations aufs_dop = {
	.d_revalidate	= aufs_d_revalidate,
	.d_release	= aufs_d_release
};
