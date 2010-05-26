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
 * mount and super_block operations
 */

#include <linux/buffer_head.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include "aufs.h"

/*
 * super_operations
 */
static struct inode *aufs_alloc_inode(struct super_block *sb __maybe_unused)
{
	struct au_icntnr *c;

	c = au_cache_alloc_icntnr();
	if (c) {
		inode_init_once(&c->vfs_inode);
		c->vfs_inode.i_version = 1; /* sigen(sb); */
		c->iinfo.ii_hinode = NULL;
		return &c->vfs_inode;
	}
	return NULL;
}

static void aufs_destroy_inode(struct inode *inode)
{
	au_iinfo_fin(inode);
	au_cache_free_icntnr(container_of(inode, struct au_icntnr, vfs_inode));
}

struct inode *au_iget_locked(struct super_block *sb, ino_t ino)
{
	struct inode *inode;
	int err;

	inode = iget_locked(sb, ino);
	if (unlikely(!inode)) {
		inode = ERR_PTR(-ENOMEM);
		goto out;
	}
	if (!(inode->i_state & I_NEW))
		goto out;

	err = au_xigen_new(inode);
	if (!err)
		err = au_iinfo_init(inode);
	if (!err)
		inode->i_version++;
	else {
		iget_failed(inode);
		inode = ERR_PTR(err);
	}

 out:
	/* never return NULL */
	AuDebugOn(!inode);
	AuTraceErrPtr(inode);
	return inode;
}

/* lock free root dinfo */
static int au_show_brs(struct seq_file *seq, struct super_block *sb)
{
	int err;
	aufs_bindex_t bindex, bend;
	struct path path;
	struct au_hdentry *hd;
	struct au_branch *br;

	err = 0;
	bend = au_sbend(sb);
	hd = au_di(sb->s_root)->di_hdentry;
	for (bindex = 0; !err && bindex <= bend; bindex++) {
		br = au_sbr(sb, bindex);
		path.mnt = br->br_mnt;
		path.dentry = hd[bindex].hd_dentry;
		err = au_seq_path(seq, &path);
		if (err > 0)
			err = seq_printf(seq, "=%s",
					 au_optstr_br_perm(br->br_perm));
		if (!err && bindex != bend)
			err = seq_putc(seq, ':');
	}

	return err;
}

static void au_show_wbr_create(struct seq_file *m, int v,
			       struct au_sbinfo *sbinfo)
{
	const char *pat;

	AuRwMustAnyLock(&sbinfo->si_rwsem);

	seq_printf(m, ",create=");
	pat = au_optstr_wbr_create(v);
	switch (v) {
	case AuWbrCreate_TDP:
	case AuWbrCreate_RR:
	case AuWbrCreate_MFS:
	case AuWbrCreate_PMFS:
		seq_printf(m, pat);
		break;
	case AuWbrCreate_MFSV:
		seq_printf(m, /*pat*/"mfs:%lu",
			   sbinfo->si_wbr_mfs.mfs_expire / HZ);
		break;
	case AuWbrCreate_PMFSV:
		seq_printf(m, /*pat*/"pmfs:%lu",
			   sbinfo->si_wbr_mfs.mfs_expire / HZ);
		break;
	case AuWbrCreate_MFSRR:
		seq_printf(m, /*pat*/"mfsrr:%llu",
			   sbinfo->si_wbr_mfs.mfsrr_watermark);
		break;
	case AuWbrCreate_MFSRRV:
		seq_printf(m, /*pat*/"mfsrr:%llu:%lu",
			   sbinfo->si_wbr_mfs.mfsrr_watermark,
			   sbinfo->si_wbr_mfs.mfs_expire / HZ);
		break;
	}
}

static int au_show_xino(struct seq_file *seq, struct vfsmount *mnt)
{
#ifdef CONFIG_SYSFS
	return 0;
#else
	int err;
	const int len = sizeof(AUFS_XINO_FNAME) - 1;
	aufs_bindex_t bindex, brid;
	struct super_block *sb;
	struct qstr *name;
	struct file *f;
	struct dentry *d, *h_root;

	AuRwMustAnyLock(&sbinfo->si_rwsem);

	err = 0;
	sb = mnt->mnt_sb;
	f = au_sbi(sb)->si_xib;
	if (!f)
		goto out;

	/* stop printing the default xino path on the first writable branch */
	h_root = NULL;
	brid = au_xino_brid(sb);
	if (brid >= 0) {
		bindex = au_br_index(sb, brid);
		h_root = au_di(sb->s_root)->di_hdentry[0 + bindex].hd_dentry;
	}
	d = f->f_dentry;
	name = &d->d_name;
	/* safe ->d_parent because the file is unlinked */
	if (d->d_parent == h_root
	    && name->len == len
	    && !memcmp(name->name, AUFS_XINO_FNAME, len))
		goto out;

	seq_puts(seq, ",xino=");
	err = au_xino_path(seq, f);

 out:
	return err;
#endif
}

/* seq_file will re-call me in case of too long string */
static int aufs_show_options(struct seq_file *m, struct vfsmount *mnt)
{
	int err, n;
	unsigned int mnt_flags, v;
	struct super_block *sb;
	struct au_sbinfo *sbinfo;

#define AuBool(name, str) do { \
	v = au_opt_test(mnt_flags, name); \
	if (v != au_opt_test(AuOpt_Def, name)) \
		seq_printf(m, ",%s" #str, v ? "" : "no"); \
} while (0)

#define AuStr(name, str) do { \
	v = mnt_flags & AuOptMask_##name; \
	if (v != (AuOpt_Def & AuOptMask_##name)) \
		seq_printf(m, "," #str "=%s", au_optstr_##str(v)); \
} while (0)

#define AuUInt(name, str, val) do { \
	if (val != AUFS_##name##_DEF) \
		seq_printf(m, "," #str "=%u", val); \
} while (0)

	/* lock free root dinfo */
	sb = mnt->mnt_sb;
	si_noflush_read_lock(sb);
	sbinfo = au_sbi(sb);
	seq_printf(m, ",si=%lx", sysaufs_si_id(sbinfo));

	mnt_flags = au_mntflags(sb);
	if (au_opt_test(mnt_flags, XINO)) {
		err = au_show_xino(m, mnt);
		if (unlikely(err))
			goto out;
	} else
		seq_puts(m, ",noxino");

	AuBool(TRUNC_XINO, trunc_xino);
	AuStr(UDBA, udba);
	AuBool(SHWH, shwh);
	AuBool(PLINK, plink);
	/* AuBool(DIRPERM1, dirperm1); */
	/* AuBool(REFROF, refrof); */

	v = sbinfo->si_wbr_create;
	if (v != AuWbrCreate_Def)
		au_show_wbr_create(m, v, sbinfo);

	v = sbinfo->si_wbr_copyup;
	if (v != AuWbrCopyup_Def)
		seq_printf(m, ",cpup=%s", au_optstr_wbr_copyup(v));

	v = au_opt_test(mnt_flags, ALWAYS_DIROPQ);
	if (v != au_opt_test(AuOpt_Def, ALWAYS_DIROPQ))
		seq_printf(m, ",diropq=%c", v ? 'a' : 'w');

	AuUInt(DIRWH, dirwh, sbinfo->si_dirwh);

	n = sbinfo->si_rdcache / HZ;
	AuUInt(RDCACHE, rdcache, n);

	AuUInt(RDBLK, rdblk, sbinfo->si_rdblk);
	AuUInt(RDHASH, rdhash, sbinfo->si_rdhash);

	AuBool(SUM, sum);
	/* AuBool(SUM_W, wsum); */
	AuBool(WARN_PERM, warn_perm);
	AuBool(VERBOSE, verbose);

 out:
	/* be sure to print "br:" last */
	if (!sysaufs_brs) {
		seq_puts(m, ",br:");
		au_show_brs(m, sb);
	}
	si_read_unlock(sb);
	return 0;

#undef Deleted
#undef AuBool
#undef AuStr
}

/* ---------------------------------------------------------------------- */

/* sum mode which returns the summation for statfs(2) */

static u64 au_add_till_max(u64 a, u64 b)
{
	u64 old;

	old = a;
	a += b;
	if (old < a)
		return a;
	return ULLONG_MAX;
}

static int au_statfs_sum(struct super_block *sb, struct kstatfs *buf)
{
	int err;
	u64 blocks, bfree, bavail, files, ffree;
	aufs_bindex_t bend, bindex, i;
	unsigned char shared;
	struct vfsmount *h_mnt;
	struct super_block *h_sb;

	blocks = 0;
	bfree = 0;
	bavail = 0;
	files = 0;
	ffree = 0;

	err = 0;
	bend = au_sbend(sb);
	for (bindex = bend; bindex >= 0; bindex--) {
		h_mnt = au_sbr_mnt(sb, bindex);
		h_sb = h_mnt->mnt_sb;
		shared = 0;
		for (i = bindex + 1; !shared && i <= bend; i++)
			shared = (au_sbr_sb(sb, i) == h_sb);
		if (shared)
			continue;

		/* sb->s_root for NFS is unreliable */
		err = vfs_statfs(h_mnt->mnt_root, buf);
		if (unlikely(err))
			goto out;

		blocks = au_add_till_max(blocks, buf->f_blocks);
		bfree = au_add_till_max(bfree, buf->f_bfree);
		bavail = au_add_till_max(bavail, buf->f_bavail);
		files = au_add_till_max(files, buf->f_files);
		ffree = au_add_till_max(ffree, buf->f_ffree);
	}

	buf->f_blocks = blocks;
	buf->f_bfree = bfree;
	buf->f_bavail = bavail;
	buf->f_files = files;
	buf->f_ffree = ffree;

 out:
	return err;
}

static int aufs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int err;
	struct super_block *sb;

	/* lock free root dinfo */
	sb = dentry->d_sb;
	si_noflush_read_lock(sb);
	if (!au_opt_test(au_mntflags(sb), SUM))
		/* sb->s_root for NFS is unreliable */
		err = vfs_statfs(au_sbr_mnt(sb, 0)->mnt_root, buf);
	else
		err = au_statfs_sum(sb, buf);
	si_read_unlock(sb);

	if (!err) {
		buf->f_type = AUFS_SUPER_MAGIC;
		buf->f_namelen = AUFS_MAX_NAMELEN;
		memset(&buf->f_fsid, 0, sizeof(buf->f_fsid));
	}
	/* buf->f_bsize = buf->f_blocks = buf->f_bfree = buf->f_bavail = -1; */

	return err;
}

/* ---------------------------------------------------------------------- */

/* try flushing the lower fs at aufs remount/unmount time */

static void au_fsync_br(struct super_block *sb)
{
	aufs_bindex_t bend, bindex;
	int brperm;
	struct au_branch *br;
	struct super_block *h_sb;

	bend = au_sbend(sb);
	for (bindex = 0; bindex < bend; bindex++) {
		br = au_sbr(sb, bindex);
		brperm = br->br_perm;
		if (brperm == AuBrPerm_RR || brperm == AuBrPerm_RRWH)
			continue;
		h_sb = br->br_mnt->mnt_sb;
		if (bdev_read_only(h_sb->s_bdev))
			continue;

		/* lockdep_off(); */
		down_write(&h_sb->s_umount);
		shrink_dcache_sb(h_sb);
		sync_filesystem(h_sb);
		up_write(&h_sb->s_umount);
		/* lockdep_on(); */
	}
}

/*
 * this IS NOT for super_operations.
 * I guess it will be reverted someday.
 */
static void aufs_umount_begin(struct super_block *sb)
{
	struct au_sbinfo *sbinfo;

	sbinfo = au_sbi(sb);
	if (!sbinfo)
		return;

	si_write_lock(sb);
	au_fsync_br(sb);
	if (au_opt_test(au_mntflags(sb), PLINK))
		au_plink_put(sb);
	if (sbinfo->si_wbr_create_ops->fin)
		sbinfo->si_wbr_create_ops->fin(sb);
	si_write_unlock(sb);
}

/* final actions when unmounting a file system */
static void aufs_put_super(struct super_block *sb)
{
	struct au_sbinfo *sbinfo;

	sbinfo = au_sbi(sb);
	if (!sbinfo)
		return;

	aufs_umount_begin(sb);
	dbgaufs_si_fin(sbinfo);
	kobject_put(&sbinfo->si_kobj);
}

/* ---------------------------------------------------------------------- */

/*
 * refresh dentry and inode at remount time.
 */
static int do_refresh(struct dentry *dentry, mode_t type,
		      unsigned int dir_flags)
{
	int err;
	struct dentry *parent;

	di_write_lock_child(dentry);
	parent = dget_parent(dentry);
	di_read_lock_parent(parent, AuLock_IR);

	/* returns the number of positive dentries */
	err = au_refresh_hdentry(dentry, type);
	if (err >= 0) {
		struct inode *inode = dentry->d_inode;
		err = au_refresh_hinode(inode, dentry);
		if (!err && type == S_IFDIR)
			au_reset_hinotify(inode, dir_flags);
	}
	if (unlikely(err))
		pr_err("unrecoverable error %d, %.*s\n",
		       err, AuDLNPair(dentry));

	di_read_unlock(parent, AuLock_IR);
	dput(parent);
	di_write_unlock(dentry);

	return err;
}

static int test_dir(struct dentry *dentry, void *arg __maybe_unused)
{
	return S_ISDIR(dentry->d_inode->i_mode);
}

/* gave up consolidating with refresh_nondir() */
static int refresh_dir(struct dentry *root, unsigned int sigen)
{
	int err, i, j, ndentry, e;
	struct au_dcsub_pages dpages;
	struct au_dpage *dpage;
	struct dentry **dentries;
	struct inode *inode;
	const unsigned int flags = au_hi_flags(root->d_inode, /*isdir*/1);

	err = 0;
	list_for_each_entry(inode, &root->d_sb->s_inodes, i_sb_list)
		if (S_ISDIR(inode->i_mode) && au_iigen(inode) != sigen) {
			ii_write_lock_child(inode);
			e = au_refresh_hinode_self(inode, /*do_attr*/1);
			ii_write_unlock(inode);
			if (unlikely(e)) {
				AuDbg("e %d, i%lu\n", e, inode->i_ino);
				if (!err)
					err = e;
				/* go on even if err */
			}
		}

	e = au_dpages_init(&dpages, GFP_NOFS);
	if (unlikely(e)) {
		if (!err)
			err = e;
		goto out;
	}
	e = au_dcsub_pages(&dpages, root, test_dir, NULL);
	if (unlikely(e)) {
		if (!err)
			err = e;
		goto out_dpages;
	}

	for (i = 0; !e && i < dpages.ndpage; i++) {
		dpage = dpages.dpages + i;
		dentries = dpage->dentries;
		ndentry = dpage->ndentry;
		for (j = 0; !e && j < ndentry; j++) {
			struct dentry *d;

			d = dentries[j];
			au_dbg_verify_dir_parent(d, sigen);
			if (au_digen(d) != sigen) {
				e = do_refresh(d, S_IFDIR, flags);
				if (unlikely(e && !err))
					err = e;
				/* break on err */
			}
		}
	}

 out_dpages:
	au_dpages_free(&dpages);
 out:
	return err;
}

static int test_nondir(struct dentry *dentry, void *arg __maybe_unused)
{
	return !S_ISDIR(dentry->d_inode->i_mode);
}

static int refresh_nondir(struct dentry *root, unsigned int sigen,
			  int do_dentry)
{
	int err, i, j, ndentry, e;
	struct au_dcsub_pages dpages;
	struct au_dpage *dpage;
	struct dentry **dentries;
	struct inode *inode;

	err = 0;
	list_for_each_entry(inode, &root->d_sb->s_inodes, i_sb_list)
		if (!S_ISDIR(inode->i_mode) && au_iigen(inode) != sigen) {
			ii_write_lock_child(inode);
			e = au_refresh_hinode_self(inode, /*do_attr*/1);
			ii_write_unlock(inode);
			if (unlikely(e)) {
				AuDbg("e %d, i%lu\n", e, inode->i_ino);
				if (!err)
					err = e;
				/* go on even if err */
			}
		}

	if (!do_dentry)
		goto out;

	e = au_dpages_init(&dpages, GFP_NOFS);
	if (unlikely(e)) {
		if (!err)
			err = e;
		goto out;
	}
	e = au_dcsub_pages(&dpages, root, test_nondir, NULL);
	if (unlikely(e)) {
		if (!err)
			err = e;
		goto out_dpages;
	}

	for (i = 0; i < dpages.ndpage; i++) {
		dpage = dpages.dpages + i;
		dentries = dpage->dentries;
		ndentry = dpage->ndentry;
		for (j = 0; j < ndentry; j++) {
			struct dentry *d;

			d = dentries[j];
			au_dbg_verify_nondir_parent(d, sigen);
			inode = d->d_inode;
			if (inode && au_digen(d) != sigen) {
				e = do_refresh(d, inode->i_mode & S_IFMT,
					       /*dir_flags*/0);
				if (unlikely(e && !err))
					err = e;
				/* go on even err */
			}
		}
	}

 out_dpages:
	au_dpages_free(&dpages);
 out:
	return err;
}

static void au_remount_refresh(struct super_block *sb, unsigned int flags)
{
	int err;
	unsigned int sigen;
	struct au_sbinfo *sbinfo;
	struct dentry *root;
	struct inode *inode;

	au_sigen_inc(sb);
	sigen = au_sigen(sb);
	sbinfo = au_sbi(sb);
	au_fclr_si(sbinfo, FAILED_REFRESH_DIRS);

	root = sb->s_root;
	DiMustNoWaiters(root);
	inode = root->d_inode;
	IiMustNoWaiters(inode);
	au_reset_hinotify(inode, au_hi_flags(inode, /*isdir*/1));
	di_write_unlock(root);

	err = refresh_dir(root, sigen);
	if (unlikely(err)) {
		au_fset_si(sbinfo, FAILED_REFRESH_DIRS);
		pr_warning("Refreshing directories failed, ignored (%d)\n",
			   err);
	}

	if (au_ftest_opts(flags, REFRESH_NONDIR)) {
		err = refresh_nondir(root, sigen, !err);
		if (unlikely(err))
			pr_warning("Refreshing non-directories failed, ignored"
				   "(%d)\n", err);
	}

	/* aufs_write_lock() calls ..._child() */
	di_write_lock_child(root);
	au_cpup_attr_all(root->d_inode, /*force*/1);
}

/* stop extra interpretation of errno in mount(8), and strange error messages */
static int cvt_err(int err)
{
	AuTraceErr(err);

	switch (err) {
	case -ENOENT:
	case -ENOTDIR:
	case -EEXIST:
	case -EIO:
		err = -EINVAL;
	}
	return err;
}

static int aufs_remount_fs(struct super_block *sb, int *flags, char *data)
{
	int err;
	struct au_opts opts;
	struct dentry *root;
	struct inode *inode;
	struct au_sbinfo *sbinfo;

	err = 0;
	root = sb->s_root;
	if (!data || !*data) {
		aufs_write_lock(root);
		err = au_opts_verify(sb, *flags, /*pending*/0);
		if (!err)
			au_fsync_br(sb);
		aufs_write_unlock(root);
		goto out;
	}

	err = -ENOMEM;
	memset(&opts, 0, sizeof(opts));
	opts.opt = (void *)__get_free_page(GFP_NOFS);
	if (unlikely(!opts.opt))
		goto out;
	opts.max_opt = PAGE_SIZE / sizeof(*opts.opt);
	opts.flags = AuOpts_REMOUNT;
	opts.sb_flags = *flags;

	/* parse it before aufs lock */
	err = au_opts_parse(sb, data, &opts);
	if (unlikely(err))
		goto out_opts;

	sbinfo = au_sbi(sb);
	inode = root->d_inode;
	mutex_lock(&inode->i_mutex);
	aufs_write_lock(root);
	au_fsync_br(sb);

	/* au_opts_remount() may return an error */
	err = au_opts_remount(sb, &opts);
	au_opts_free(&opts);

	if (au_ftest_opts(opts.flags, REFRESH_DIR)
	    || au_ftest_opts(opts.flags, REFRESH_NONDIR))
		au_remount_refresh(sb, opts.flags);

	aufs_write_unlock(root);
	mutex_unlock(&inode->i_mutex);

 out_opts:
	free_page((unsigned long)opts.opt);
 out:
	err = cvt_err(err);
	AuTraceErr(err);
	return err;
}

static const struct super_operations aufs_sop = {
	.alloc_inode	= aufs_alloc_inode,
	.destroy_inode	= aufs_destroy_inode,
	.drop_inode	= generic_delete_inode,
	.show_options	= aufs_show_options,
	.statfs		= aufs_statfs,
	.put_super	= aufs_put_super,
	.remount_fs	= aufs_remount_fs
};

/* ---------------------------------------------------------------------- */

static int alloc_root(struct super_block *sb)
{
	int err;
	struct inode *inode;
	struct dentry *root;

	err = -ENOMEM;
	inode = au_iget_locked(sb, AUFS_ROOT_INO);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out;

	inode->i_op = &aufs_dir_iop;
	inode->i_fop = &aufs_dir_fop;
	inode->i_mode = S_IFDIR;
	inode->i_nlink = 2;
	unlock_new_inode(inode);

	root = d_alloc_root(inode);
	if (unlikely(!root))
		goto out_iput;
	err = PTR_ERR(root);
	if (IS_ERR(root))
		goto out_iput;

	err = au_alloc_dinfo(root);
	if (!err) {
		sb->s_root = root;
		return 0; /* success */
	}
	dput(root);
	goto out; /* do not iput */

 out_iput:
	iget_failed(inode);
	iput(inode);
 out:
	return err;

}

static int aufs_fill_super(struct super_block *sb, void *raw_data,
			   int silent __maybe_unused)
{
	int err;
	struct au_opts opts;
	struct dentry *root;
	struct inode *inode;
	char *arg = raw_data;

	if (unlikely(!arg || !*arg)) {
		err = -EINVAL;
		pr_err("no arg\n");
		goto out;
	}

	err = -ENOMEM;
	memset(&opts, 0, sizeof(opts));
	opts.opt = (void *)__get_free_page(GFP_NOFS);
	if (unlikely(!opts.opt))
		goto out;
	opts.max_opt = PAGE_SIZE / sizeof(*opts.opt);
	opts.sb_flags = sb->s_flags;

	err = au_si_alloc(sb);
	if (unlikely(err))
		goto out_opts;

	/* all timestamps always follow the ones on the branch */
	sb->s_flags |= MS_NOATIME | MS_NODIRATIME;
	sb->s_op = &aufs_sop;
	sb->s_magic = AUFS_SUPER_MAGIC;
	sb->s_maxbytes = 0;
	au_export_init(sb);

	err = alloc_root(sb);
	if (unlikely(err)) {
		si_write_unlock(sb);
		goto out_info;
	}
	root = sb->s_root;
	inode = root->d_inode;

	/*
	 * actually we can parse options regardless aufs lock here.
	 * but at remount time, parsing must be done before aufs lock.
	 * so we follow the same rule.
	 */
	ii_write_lock_parent(inode);
	aufs_write_unlock(root);
	err = au_opts_parse(sb, arg, &opts);
	if (unlikely(err))
		goto out_root;

	/* lock vfs_inode first, then aufs. */
	mutex_lock(&inode->i_mutex);
	inode->i_op = &aufs_dir_iop;
	inode->i_fop = &aufs_dir_fop;
	aufs_write_lock(root);
	err = au_opts_mount(sb, &opts);
	au_opts_free(&opts);
	if (unlikely(err))
		goto out_unlock;
	aufs_write_unlock(root);
	mutex_unlock(&inode->i_mutex);
	goto out_opts; /* success */

 out_unlock:
	aufs_write_unlock(root);
	mutex_unlock(&inode->i_mutex);
 out_root:
	dput(root);
	sb->s_root = NULL;
 out_info:
	kobject_put(&au_sbi(sb)->si_kobj);
	sb->s_fs_info = NULL;
 out_opts:
	free_page((unsigned long)opts.opt);
 out:
	AuTraceErr(err);
	err = cvt_err(err);
	AuTraceErr(err);
	return err;
}

/* ---------------------------------------------------------------------- */

static int aufs_get_sb(struct file_system_type *fs_type, int flags,
		       const char *dev_name __maybe_unused, void *raw_data,
		       struct vfsmount *mnt)
{
	int err;
	struct super_block *sb;

	/* all timestamps always follow the ones on the branch */
	/* mnt->mnt_flags |= MNT_NOATIME | MNT_NODIRATIME; */
	err = get_sb_nodev(fs_type, flags, raw_data, aufs_fill_super, mnt);
	if (!err) {
		sb = mnt->mnt_sb;
		si_write_lock(sb);
		sysaufs_brs_add(sb, 0);
		si_write_unlock(sb);
	}
	return err;
}

struct file_system_type aufs_fs_type = {
	.name		= AUFS_FSTYPE,
	.fs_flags	=
		FS_RENAME_DOES_D_MOVE	/* a race between rename and others */
		| FS_REVAL_DOT,		/* for NFS branch and udba */
	.get_sb		= aufs_get_sb,
	.kill_sb	= generic_shutdown_super,
	/* no need to __module_get() and module_put(). */
	.owner		= THIS_MODULE,
};
