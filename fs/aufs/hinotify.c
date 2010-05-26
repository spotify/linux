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
 * inotify for the lower directories
 */

#include "aufs.h"

static const __u32 AuHinMask = (IN_MOVE | IN_DELETE | IN_CREATE);
static struct inotify_handle *au_hin_handle;

AuCacheFuncs(hinotify, HINOTIFY);

int au_hin_alloc(struct au_hinode *hinode, struct inode *inode,
		 struct inode *h_inode)
{
	int err;
	struct au_hinotify *hin;
	s32 wd;

	err = -ENOMEM;
	hin = au_cache_alloc_hinotify();
	if (hin) {
		AuDebugOn(hinode->hi_notify);
		hinode->hi_notify = hin;
		hin->hin_aufs_inode = inode;

		inotify_init_watch(&hin->hin_watch);
		wd = inotify_add_watch(au_hin_handle, &hin->hin_watch, h_inode,
				       AuHinMask);
		if (wd >= 0)
			return 0; /* success */

		err = wd;
		put_inotify_watch(&hin->hin_watch);
		au_cache_free_hinotify(hin);
		hinode->hi_notify = NULL;
	}

	return err;
}

void au_hin_free(struct au_hinode *hinode)
{
	int err;
	struct au_hinotify *hin;

	hin = hinode->hi_notify;
	if (hin) {
		err = 0;
		if (atomic_read(&hin->hin_watch.count))
			err = inotify_rm_watch(au_hin_handle, &hin->hin_watch);
		if (unlikely(err))
			/* it means the watch is already removed */
			pr_warning("failed inotify_rm_watch() %d\n", err);
		au_cache_free_hinotify(hin);
		hinode->hi_notify = NULL;
	}
}

/* ---------------------------------------------------------------------- */

void au_hin_ctl(struct au_hinode *hinode, int do_set)
{
	struct inode *h_inode;
	struct inotify_watch *watch;

	if (!hinode->hi_notify)
		return;

	h_inode = hinode->hi_inode;
	IMustLock(h_inode);

	/* todo: try inotify_find_update_watch()? */
	watch = &hinode->hi_notify->hin_watch;
	mutex_lock(&h_inode->inotify_mutex);
	/* mutex_lock(&watch->ih->mutex); */
	if (do_set) {
		AuDebugOn(watch->mask & AuHinMask);
		watch->mask |= AuHinMask;
	} else {
		AuDebugOn(!(watch->mask & AuHinMask));
		watch->mask &= ~AuHinMask;
	}
	/* mutex_unlock(&watch->ih->mutex); */
	mutex_unlock(&h_inode->inotify_mutex);
}

void au_reset_hinotify(struct inode *inode, unsigned int flags)
{
	aufs_bindex_t bindex, bend;
	struct inode *hi;
	struct dentry *iwhdentry;

	bend = au_ibend(inode);
	for (bindex = au_ibstart(inode); bindex <= bend; bindex++) {
		hi = au_h_iptr(inode, bindex);
		if (!hi)
			continue;

		/* mutex_lock_nested(&hi->i_mutex, AuLsc_I_CHILD); */
		iwhdentry = au_hi_wh(inode, bindex);
		if (iwhdentry)
			dget(iwhdentry);
		au_igrab(hi);
		au_set_h_iptr(inode, bindex, NULL, 0);
		au_set_h_iptr(inode, bindex, au_igrab(hi),
			      flags & ~AuHi_XINO);
		iput(hi);
		dput(iwhdentry);
		/* mutex_unlock(&hi->i_mutex); */
	}
}

/* ---------------------------------------------------------------------- */

static int hin_xino(struct inode *inode, struct inode *h_inode)
{
	int err;
	aufs_bindex_t bindex, bend, bfound, bstart;
	struct inode *h_i;

	err = 0;
	if (unlikely(inode->i_ino == AUFS_ROOT_INO)) {
		pr_warning("branch root dir was changed\n");
		goto out;
	}

	bfound = -1;
	bend = au_ibend(inode);
	bstart = au_ibstart(inode);
#if 0 /* reserved for future use */
	if (bindex == bend) {
		/* keep this ino in rename case */
		goto out;
	}
#endif
	for (bindex = bstart; bindex <= bend; bindex++) {
		if (au_h_iptr(inode, bindex) == h_inode) {
			bfound = bindex;
			break;
		}
	}
	if (bfound < 0)
		goto out;

	for (bindex = bstart; bindex <= bend; bindex++) {
		h_i = au_h_iptr(inode, bindex);
		if (!h_i)
			continue;

		err = au_xino_write(inode->i_sb, bindex, h_i->i_ino, /*ino*/0);
		/* ignore this error */
		/* bad action? */
	}

	/* children inode number will be broken */

 out:
	AuTraceErr(err);
	return err;
}

static int hin_gen_tree(struct dentry *dentry)
{
	int err, i, j, ndentry;
	struct au_dcsub_pages dpages;
	struct au_dpage *dpage;
	struct dentry **dentries;

	err = au_dpages_init(&dpages, GFP_NOFS);
	if (unlikely(err))
		goto out;
	err = au_dcsub_pages(&dpages, dentry, NULL, NULL);
	if (unlikely(err))
		goto out_dpages;

	for (i = 0; i < dpages.ndpage; i++) {
		dpage = dpages.dpages + i;
		dentries = dpage->dentries;
		ndentry = dpage->ndentry;
		for (j = 0; j < ndentry; j++) {
			struct dentry *d;

			d = dentries[j];
			if (IS_ROOT(d))
				continue;

			d_drop(d);
			au_digen_dec(d);
			if (d->d_inode)
				/* todo: reset children xino?
				   cached children only? */
				au_iigen_dec(d->d_inode);
		}
	}

 out_dpages:
	au_dpages_free(&dpages);

	/* discard children */
	dentry_unhash(dentry);
	dput(dentry);
 out:
	return err;
}

/*
 * return 0 if processed.
 */
static int hin_gen_by_inode(char *name, unsigned int nlen, struct inode *inode,
			    const unsigned int isdir)
{
	int err;
	struct dentry *d;
	struct qstr *dname;

	err = 1;
	if (unlikely(inode->i_ino == AUFS_ROOT_INO)) {
		pr_warning("branch root dir was changed\n");
		err = 0;
		goto out;
	}

	if (!isdir) {
		AuDebugOn(!name);
		au_iigen_dec(inode);
		spin_lock(&dcache_lock);
		list_for_each_entry(d, &inode->i_dentry, d_alias) {
			dname = &d->d_name;
			if (dname->len != nlen
			    && memcmp(dname->name, name, nlen))
				continue;
			err = 0;
			spin_lock(&d->d_lock);
			__d_drop(d);
			au_digen_dec(d);
			spin_unlock(&d->d_lock);
			break;
		}
		spin_unlock(&dcache_lock);
	} else {
		au_fset_si(au_sbi(inode->i_sb), FAILED_REFRESH_DIRS);
		d = d_find_alias(inode);
		if (!d) {
			au_iigen_dec(inode);
			goto out;
		}

		dname = &d->d_name;
		if (dname->len == nlen && !memcmp(dname->name, name, nlen))
			err = hin_gen_tree(d);
		dput(d);
	}

 out:
	AuTraceErr(err);
	return err;
}

static int hin_gen_by_name(struct dentry *dentry, const unsigned int isdir)
{
	int err;
	struct inode *inode;

	inode = dentry->d_inode;
	if (IS_ROOT(dentry)
	    /* || (inode && inode->i_ino == AUFS_ROOT_INO) */
		) {
		pr_warning("branch root dir was changed\n");
		return 0;
	}

	err = 0;
	if (!isdir) {
		d_drop(dentry);
		au_digen_dec(dentry);
		if (inode)
			au_iigen_dec(inode);
	} else {
		au_fset_si(au_sbi(dentry->d_sb), FAILED_REFRESH_DIRS);
		if (inode)
			err = hin_gen_tree(dentry);
	}

	AuTraceErr(err);
	return err;
}

/* ---------------------------------------------------------------------- */

/* hinotify job flags */
#define AuHinJob_XINO0		1
#define AuHinJob_GEN		(1 << 1)
#define AuHinJob_DIRENT		(1 << 2)
#define AuHinJob_ISDIR		(1 << 3)
#define AuHinJob_TRYXINO0	(1 << 4)
#define AuHinJob_MNTPNT		(1 << 5)
#define au_ftest_hinjob(flags, name)	((flags) & AuHinJob_##name)
#define au_fset_hinjob(flags, name)	{ (flags) |= AuHinJob_##name; }
#define au_fclr_hinjob(flags, name)	{ (flags) &= ~AuHinJob_##name; }

struct hin_job_args {
	unsigned int flags;
	struct inode *inode, *h_inode, *dir, *h_dir;
	struct dentry *dentry;
	char *h_name;
	int h_nlen;
};

static int hin_job(struct hin_job_args *a)
{
	const unsigned int isdir = au_ftest_hinjob(a->flags, ISDIR);

	/* reset xino */
	if (au_ftest_hinjob(a->flags, XINO0) && a->inode)
		hin_xino(a->inode, a->h_inode); /* ignore this error */

	if (au_ftest_hinjob(a->flags, TRYXINO0)
	    && a->inode
	    && a->h_inode) {
		mutex_lock_nested(&a->h_inode->i_mutex, AuLsc_I_CHILD);
		if (!a->h_inode->i_nlink)
			hin_xino(a->inode, a->h_inode); /* ignore this error */
		mutex_unlock(&a->h_inode->i_mutex);
	}

	/* make the generation obsolete */
	if (au_ftest_hinjob(a->flags, GEN)) {
		int err = -1;
		if (a->inode)
			err = hin_gen_by_inode(a->h_name, a->h_nlen, a->inode,
					       isdir);
		if (err && a->dentry)
			hin_gen_by_name(a->dentry, isdir);
		/* ignore this error */
	}

	/* make dir entries obsolete */
	if (au_ftest_hinjob(a->flags, DIRENT) && a->inode) {
		struct au_vdir *vdir;

		vdir = au_ivdir(a->inode);
		if (vdir)
			vdir->vd_jiffy = 0;
		/* IMustLock(a->inode); */
		/* a->inode->i_version++; */
	}

	/* can do nothing but warn */
	if (au_ftest_hinjob(a->flags, MNTPNT)
	    && a->dentry
	    && d_mountpoint(a->dentry))
		pr_warning("mount-point %.*s is removed or renamed\n",
			   AuDLNPair(a->dentry));

	return 0;
}

/* ---------------------------------------------------------------------- */

static char *in_name(u32 mask)
{
#ifdef CONFIG_AUFS_DEBUG
#define test_ret(flag)	if (mask & flag) \
				return #flag;
	test_ret(IN_ACCESS);
	test_ret(IN_MODIFY);
	test_ret(IN_ATTRIB);
	test_ret(IN_CLOSE_WRITE);
	test_ret(IN_CLOSE_NOWRITE);
	test_ret(IN_OPEN);
	test_ret(IN_MOVED_FROM);
	test_ret(IN_MOVED_TO);
	test_ret(IN_CREATE);
	test_ret(IN_DELETE);
	test_ret(IN_DELETE_SELF);
	test_ret(IN_MOVE_SELF);
	test_ret(IN_UNMOUNT);
	test_ret(IN_Q_OVERFLOW);
	test_ret(IN_IGNORED);
	return "";
#undef test_ret
#else
	return "??";
#endif
}

static struct dentry *lookup_wlock_by_name(char *name, unsigned int nlen,
					   struct inode *dir)
{
	struct dentry *dentry, *d, *parent;
	struct qstr *dname;

	parent = d_find_alias(dir);
	if (!parent)
		return NULL;

	dentry = NULL;
	spin_lock(&dcache_lock);
	list_for_each_entry(d, &parent->d_subdirs, d_u.d_child) {
		/* AuDbg("%.*s\n", AuDLNPair(d)); */
		dname = &d->d_name;
		if (dname->len != nlen || memcmp(dname->name, name, nlen))
			continue;
		if (!atomic_read(&d->d_count) || !d->d_fsdata) {
			spin_lock(&d->d_lock);
			__d_drop(d);
			spin_unlock(&d->d_lock);
			continue;
		}

		dentry = dget(d);
		break;
	}
	spin_unlock(&dcache_lock);
	dput(parent);

	if (dentry)
		di_write_lock_child(dentry);

	return dentry;
}

static struct inode *lookup_wlock_by_ino(struct super_block *sb,
					 aufs_bindex_t bindex, ino_t h_ino)
{
	struct inode *inode;
	ino_t ino;
	int err;

	inode = NULL;
	err = au_xino_read(sb, bindex, h_ino, &ino);
	if (!err && ino)
		inode = ilookup(sb, ino);
	if (!inode)
		goto out;

	if (unlikely(inode->i_ino == AUFS_ROOT_INO)) {
		pr_warning("wrong root branch\n");
		iput(inode);
		inode = NULL;
		goto out;
	}

	ii_write_lock_child(inode);

 out:
	return inode;
}

enum { CHILD, PARENT };
struct postproc_args {
	struct inode *h_dir, *dir, *h_child_inode;
	u32 mask;
	unsigned int flags[2];
	unsigned int h_child_nlen;
	char h_child_name[];
};

static void postproc(void *_args)
{
	struct postproc_args *a = _args;
	struct super_block *sb;
	aufs_bindex_t bindex, bend, bfound;
	unsigned char xino, try_iput;
	int err;
	struct inode *inode;
	ino_t h_ino;
	struct hin_job_args args;
	struct dentry *dentry;
	struct au_sbinfo *sbinfo;

	AuDebugOn(!_args);
	AuDebugOn(!a->h_dir);
	AuDebugOn(!a->dir);
	AuDebugOn(!a->mask);
	AuDbg("mask 0x%x %s, i%lu, hi%lu, hci%lu\n",
	      a->mask, in_name(a->mask), a->dir->i_ino, a->h_dir->i_ino,
	      a->h_child_inode ? a->h_child_inode->i_ino : 0);

	inode = NULL;
	dentry = NULL;
	/*
	 * do not lock a->dir->i_mutex here
	 * because of d_revalidate() may cause a deadlock.
	 */
	sb = a->dir->i_sb;
	AuDebugOn(!sb);
	sbinfo = au_sbi(sb);
	AuDebugOn(!sbinfo);
	/* big aufs lock */
	si_noflush_write_lock(sb);

	ii_read_lock_parent(a->dir);
	bfound = -1;
	bend = au_ibend(a->dir);
	for (bindex = au_ibstart(a->dir); bindex <= bend; bindex++)
		if (au_h_iptr(a->dir, bindex) == a->h_dir) {
			bfound = bindex;
			break;
		}
	ii_read_unlock(a->dir);
	if (unlikely(bfound < 0))
		goto out;

	xino = !!au_opt_test(au_mntflags(sb), XINO);
	h_ino = 0;
	if (a->h_child_inode)
		h_ino = a->h_child_inode->i_ino;

	if (a->h_child_nlen
	    && (au_ftest_hinjob(a->flags[CHILD], GEN)
		|| au_ftest_hinjob(a->flags[CHILD], MNTPNT)))
		dentry = lookup_wlock_by_name(a->h_child_name, a->h_child_nlen,
					      a->dir);
	try_iput = 0;
	if (dentry)
		inode = dentry->d_inode;
	if (xino && !inode && h_ino
	    && (au_ftest_hinjob(a->flags[CHILD], XINO0)
		|| au_ftest_hinjob(a->flags[CHILD], TRYXINO0)
		|| au_ftest_hinjob(a->flags[CHILD], GEN))) {
		inode = lookup_wlock_by_ino(sb, bfound, h_ino);
		try_iput = 1;
	    }

	args.flags = a->flags[CHILD];
	args.dentry = dentry;
	args.inode = inode;
	args.h_inode = a->h_child_inode;
	args.dir = a->dir;
	args.h_dir = a->h_dir;
	args.h_name = a->h_child_name;
	args.h_nlen = a->h_child_nlen;
	err = hin_job(&args);
	if (dentry) {
		if (dentry->d_fsdata)
			di_write_unlock(dentry);
		dput(dentry);
	}
	if (inode && try_iput) {
		ii_write_unlock(inode);
		iput(inode);
	}

	ii_write_lock_parent(a->dir);
	args.flags = a->flags[PARENT];
	args.dentry = NULL;
	args.inode = a->dir;
	args.h_inode = a->h_dir;
	args.dir = NULL;
	args.h_dir = NULL;
	args.h_name = NULL;
	args.h_nlen = 0;
	err = hin_job(&args);
	ii_write_unlock(a->dir);

 out:
	au_nwt_done(&sbinfo->si_nowait);
	si_write_unlock(sb);

	iput(a->h_child_inode);
	iput(a->h_dir);
	iput(a->dir);
	kfree(a);
}

/* ---------------------------------------------------------------------- */

static void aufs_inotify(struct inotify_watch *watch, u32 wd __maybe_unused,
			 u32 mask, u32 cookie __maybe_unused,
			 const char *h_child_name, struct inode *h_child_inode)
{
	struct au_hinotify *hinotify;
	struct postproc_args *args;
	int len, wkq_err;
	unsigned char isdir, isroot, wh;
	char *p;
	struct inode *dir;
	unsigned int flags[2];

	/* if IN_UNMOUNT happens, there must be another bug */
	AuDebugOn(mask & IN_UNMOUNT);
	if (mask & (IN_IGNORED | IN_UNMOUNT)) {
		put_inotify_watch(watch);
		return;
	}
#ifdef AuDbgHinotify
	au_debug(1);
	if (1 || !h_child_name || strcmp(h_child_name, AUFS_XINO_FNAME)) {
		AuDbg("i%lu, wd %d, mask 0x%x %s, cookie 0x%x, hcname %s,"
		      " hi%lu\n",
		      watch->inode->i_ino, wd, mask, in_name(mask), cookie,
		      h_child_name ? h_child_name : "",
		      h_child_inode ? h_child_inode->i_ino : 0);
		WARN_ON(1);
	}
	au_debug(0);
#endif

	hinotify = container_of(watch, struct au_hinotify, hin_watch);
	AuDebugOn(!hinotify || !hinotify->hin_aufs_inode);
	dir = igrab(hinotify->hin_aufs_inode);
	if (!dir)
		return;

	isroot = (dir->i_ino == AUFS_ROOT_INO);
	len = 0;
	wh = 0;
	if (h_child_name) {
		len = strlen(h_child_name);
		if (!memcmp(h_child_name, AUFS_WH_PFX, AUFS_WH_PFX_LEN)) {
			h_child_name += AUFS_WH_PFX_LEN;
			len -= AUFS_WH_PFX_LEN;
			wh = 1;
		}
	}

	isdir = 0;
	if (h_child_inode)
		isdir = !!S_ISDIR(h_child_inode->i_mode);
	flags[PARENT] = AuHinJob_ISDIR;
	flags[CHILD] = 0;
	if (isdir)
		flags[CHILD] = AuHinJob_ISDIR;
	switch (mask & IN_ALL_EVENTS) {
	case IN_MOVED_FROM:
	case IN_MOVED_TO:
		AuDebugOn(!h_child_name || !h_child_inode);
		au_fset_hinjob(flags[CHILD], GEN);
		au_fset_hinjob(flags[CHILD], XINO0);
		au_fset_hinjob(flags[CHILD], MNTPNT);
		au_fset_hinjob(flags[PARENT], DIRENT);
		break;

	case IN_CREATE:
		AuDebugOn(!h_child_name || !h_child_inode);
		au_fset_hinjob(flags[PARENT], DIRENT);
		au_fset_hinjob(flags[CHILD], GEN);
		break;

	case IN_DELETE:
		/*
		 * aufs never be able to get this child inode.
		 * revalidation should be in d_revalidate()
		 * by checking i_nlink, i_generation or d_unhashed().
		 */
		AuDebugOn(!h_child_name);
		au_fset_hinjob(flags[PARENT], DIRENT);
		au_fset_hinjob(flags[CHILD], GEN);
		au_fset_hinjob(flags[CHILD], TRYXINO0);
		au_fset_hinjob(flags[CHILD], MNTPNT);
		break;

	default:
		AuDebugOn(1);
	}

	if (wh)
		h_child_inode = NULL;

	/* iput() and kfree() will be called in postproc() */
	/*
	 * inotify_mutex is already acquired and kmalloc/prune_icache may lock
	 * iprune_mutex. strange.
	 */
	/* lockdep_off(); */
	args = kmalloc(sizeof(*args) + len + 1, GFP_NOFS);
	/* lockdep_on(); */
	if (unlikely(!args)) {
		AuErr1("no memory\n");
		iput(dir);
		return;
	}
	args->flags[PARENT] = flags[PARENT];
	args->flags[CHILD] = flags[CHILD];
	args->mask = mask;
	args->dir = dir;
	args->h_dir = igrab(watch->inode);
	if (h_child_inode)
		h_child_inode = igrab(h_child_inode); /* can be NULL */
	args->h_child_inode = h_child_inode;
	args->h_child_nlen = len;
	if (len) {
		p = (void *)args;
		p += sizeof(*args);
		memcpy(p, h_child_name, len + 1);
	}

	/* lockdep_off(); */
	wkq_err = au_wkq_nowait(postproc, args, dir->i_sb);
	/* lockdep_on(); */
	if (unlikely(wkq_err))
		pr_err("wkq %d\n", wkq_err);
}

static void aufs_inotify_destroy(struct inotify_watch *watch __maybe_unused)
{
	return;
}

static struct inotify_operations aufs_inotify_ops = {
	.handle_event	= aufs_inotify,
	.destroy_watch	= aufs_inotify_destroy
};

/* ---------------------------------------------------------------------- */

static void au_hin_destroy_cache(void)
{
	kmem_cache_destroy(au_cachep[AuCache_HINOTIFY]);
	au_cachep[AuCache_HINOTIFY] = NULL;
}

int __init au_hinotify_init(void)
{
	int err;

	err = -ENOMEM;
	au_cachep[AuCache_HINOTIFY] = AuCache(au_hinotify);
	if (au_cachep[AuCache_HINOTIFY]) {
		err = 0;
		au_hin_handle = inotify_init(&aufs_inotify_ops);
		if (IS_ERR(au_hin_handle)) {
			err = PTR_ERR(au_hin_handle);
			au_hin_destroy_cache();
		}
	}
	AuTraceErr(err);
	return err;
}

void au_hinotify_fin(void)
{
	inotify_destroy(au_hin_handle);
	if (au_cachep[AuCache_HINOTIFY])
		au_hin_destroy_cache();
}
