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
 * sub-routines for VFS
 */

#ifndef __AUFS_VFSUB_H__
#define __AUFS_VFSUB_H__

#ifdef __KERNEL__

#include <linux/fs.h>
#include <linux/fs_stack.h>

/* ---------------------------------------------------------------------- */

/* lock subclass for lower inode */
/* default MAX_LOCKDEP_SUBCLASSES(8) is not enough */
/* reduce? gave up. */
enum {
	AuLsc_I_Begin = I_MUTEX_QUOTA, /* 4 */
	AuLsc_I_PARENT,		/* lower inode, parent first */
	AuLsc_I_PARENT2,	/* copyup dirs */
	AuLsc_I_PARENT3,	/* copyup wh */
	AuLsc_I_CHILD,
	AuLsc_I_CHILD2,
	AuLsc_I_End
};

/* to debug easier, do not make them inlined functions */
#define MtxMustLock(mtx)	AuDebugOn(!mutex_is_locked(mtx))
#define IMustLock(i)		MtxMustLock(&(i)->i_mutex)

/* ---------------------------------------------------------------------- */

static inline void vfsub_copy_inode_size(struct inode *inode,
					 struct inode *h_inode)
{
	spin_lock(&inode->i_lock);
	fsstack_copy_inode_size(inode, h_inode);
	spin_unlock(&inode->i_lock);
}

int vfsub_update_h_iattr(struct path *h_path, int *did);
struct file *vfsub_filp_open(const char *path, int oflags, int mode);
struct file *vfsub_dentry_open(struct path *path, int flags,
			       const struct cred *cred);
int vfsub_kern_path(const char *name, unsigned int flags, struct path *path);
struct dentry *vfsub_lookup_one_len(const char *name, struct dentry *parent,
				    int len);
struct dentry *vfsub_lookup_hash(struct nameidata *nd);

/* ---------------------------------------------------------------------- */

struct au_hinode;
struct dentry *vfsub_lock_rename(struct dentry *d1, struct au_hinode *hdir1,
				 struct dentry *d2, struct au_hinode *hdir2);
void vfsub_unlock_rename(struct dentry *d1, struct au_hinode *hdir1,
			 struct dentry *d2, struct au_hinode *hdir2);

int vfsub_create(struct inode *dir, struct path *path, int mode);
int vfsub_symlink(struct inode *dir, struct path *path,
		  const char *symname);
int vfsub_mknod(struct inode *dir, struct path *path, int mode, dev_t dev);
int vfsub_link(struct dentry *src_dentry, struct inode *dir,
	       struct path *path);
int vfsub_rename(struct inode *src_hdir, struct dentry *src_dentry,
		 struct inode *hdir, struct path *path);
int vfsub_mkdir(struct inode *dir, struct path *path, int mode);
int vfsub_rmdir(struct inode *dir, struct path *path);

int vfsub_sio_mkdir(struct inode *dir, struct path *path, int mode);
int vfsub_sio_rmdir(struct inode *dir, struct path *path);
int vfsub_sio_notify_change(struct path *path, struct iattr *ia);
int vfsub_notify_change(struct path *path, struct iattr *ia);
int vfsub_unlink(struct inode *dir, struct path *path, int force);

/* ---------------------------------------------------------------------- */

ssize_t vfsub_read_u(struct file *file, char __user *ubuf, size_t count,
		     loff_t *ppos);
ssize_t vfsub_read_k(struct file *file, void *kbuf, size_t count,
			loff_t *ppos);
ssize_t vfsub_write_u(struct file *file, const char __user *ubuf, size_t count,
		      loff_t *ppos);
ssize_t vfsub_write_k(struct file *file, void *kbuf, size_t count,
		      loff_t *ppos);
int vfsub_readdir(struct file *file, filldir_t filldir, void *arg);

long vfsub_splice_to(struct file *in, loff_t *ppos,
		     struct pipe_inode_info *pipe, size_t len,
		     unsigned int flags);
long vfsub_splice_from(struct pipe_inode_info *pipe, struct file *out,
		       loff_t *ppos, size_t len, unsigned int flags);
int vfsub_trunc(struct path *h_path, loff_t length, unsigned int attr,
		struct file *h_file);

static inline void vfsub_file_accessed(struct file *h_file)
{
	file_accessed(h_file);
	vfsub_update_h_iattr(&h_file->f_path, /*did*/NULL); /*ignore*/
}

static inline void vfsub_touch_atime(struct vfsmount *h_mnt,
				     struct dentry *h_dentry)
{
	struct path h_path = {
		.dentry	= h_dentry,
		.mnt	= h_mnt
	};
	touch_atime(h_mnt, h_dentry);
	vfsub_update_h_iattr(&h_path, /*did*/NULL); /*ignore*/
}

/* ---------------------------------------------------------------------- */

static inline loff_t vfsub_llseek(struct file *file, loff_t offset, int origin)
{
	loff_t err;

	/* lockdep_off(); */
	err = vfs_llseek(file, offset, origin);
	/* lockdep_on(); */
	return err;
}

/* ---------------------------------------------------------------------- */

/* dirty workaround for strict type of fmode_t */
union vfsub_fmu {
	fmode_t fm;
	unsigned int ui;
};

static inline unsigned int vfsub_fmode_to_uint(fmode_t fm)
{
	union vfsub_fmu u = {
		.fm = fm
	};

	BUILD_BUG_ON(sizeof(u.fm) != sizeof(u.ui));

	return u.ui;
}

static inline fmode_t vfsub_uint_to_fmode(unsigned int ui)
{
	union vfsub_fmu u = {
		.ui = ui
	};

	return u.fm;
}

#endif /* __KERNEL__ */
#endif /* __AUFS_VFSUB_H__ */
