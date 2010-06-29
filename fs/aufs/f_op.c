/*
 * Copyright (C) 2005-2010 Junjiro R. Okajima
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
 * file and vm operations
 */

#include <linux/file.h>
#include <linux/fs_stack.h>
#include <linux/ima.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/security.h>
#include "aufs.h"

/* common function to regular file and dir */
int aufs_flush(struct file *file, fl_owner_t id)
{
	int err;
	aufs_bindex_t bindex, bend;
	struct dentry *dentry;
	struct file *h_file;

	dentry = file->f_dentry;
	si_noflush_read_lock(dentry->d_sb);
	fi_read_lock(file);
	di_read_lock_child(dentry, AuLock_IW);

	err = 0;
	bend = au_fbend(file);
	for (bindex = au_fbstart(file); !err && bindex <= bend; bindex++) {
		h_file = au_h_fptr(file, bindex);
		if (!h_file || !h_file->f_op || !h_file->f_op->flush)
			continue;

		err = h_file->f_op->flush(h_file, id);
		if (!err)
			vfsub_update_h_iattr(&h_file->f_path, /*did*/NULL);
		/*ignore*/
	}
	au_cpup_attr_timesizes(dentry->d_inode);

	di_read_unlock(dentry, AuLock_IW);
	fi_read_unlock(file);
	si_read_unlock(dentry->d_sb);
	return err;
}

/* ---------------------------------------------------------------------- */

int au_do_open_nondir(struct file *file, int flags)
{
	int err;
	aufs_bindex_t bindex;
	struct file *h_file;
	struct dentry *dentry;
	struct au_finfo *finfo;

	FiMustWriteLock(file);

	err = 0;
	dentry = file->f_dentry;
	finfo = au_fi(file);
	finfo->fi_h_vm_ops = NULL;
	finfo->fi_vm_ops = NULL;
	mutex_init(&finfo->fi_mmap); /* regular file only? */
	bindex = au_dbstart(dentry);
	/* O_TRUNC is processed already */
	BUG_ON(au_test_ro(dentry->d_sb, bindex, dentry->d_inode)
	       && (flags & O_TRUNC));

	h_file = au_h_open(dentry, bindex, flags, file);
	if (IS_ERR(h_file))
		err = PTR_ERR(h_file);
	else {
		au_set_fbstart(file, bindex);
		au_set_fbend(file, bindex);
		au_set_h_fptr(file, bindex, h_file);
		au_update_figen(file);
		/* todo: necessary? */
		/* file->f_ra = h_file->f_ra; */
	}
	return err;
}

static int aufs_open_nondir(struct inode *inode __maybe_unused,
			    struct file *file)
{
	return au_do_open(file, au_do_open_nondir);
}

int aufs_release_nondir(struct inode *inode __maybe_unused, struct file *file)
{
	kfree(au_fi(file)->fi_vm_ops);
	au_finfo_fin(file);
	return 0;
}

/* ---------------------------------------------------------------------- */

static ssize_t aufs_read(struct file *file, char __user *buf, size_t count,
			 loff_t *ppos)
{
	ssize_t err;
	struct dentry *dentry;
	struct file *h_file;
	struct super_block *sb;

	dentry = file->f_dentry;
	sb = dentry->d_sb;
	si_read_lock(sb, AuLock_FLUSH);
	err = au_reval_and_lock_fdi(file, au_reopen_nondir, /*wlock*/0);
	if (unlikely(err))
		goto out;

	h_file = au_h_fptr(file, au_fbstart(file));
	err = vfsub_read_u(h_file, buf, count, ppos);
	/* todo: necessary? */
	/* file->f_ra = h_file->f_ra; */
	fsstack_copy_attr_atime(dentry->d_inode, h_file->f_dentry->d_inode);

	di_read_unlock(dentry, AuLock_IR);
	fi_read_unlock(file);
 out:
	si_read_unlock(sb);
	return err;
}

static ssize_t aufs_write(struct file *file, const char __user *ubuf,
			  size_t count, loff_t *ppos)
{
	ssize_t err;
	aufs_bindex_t bstart;
	struct au_pin pin;
	struct dentry *dentry;
	struct inode *inode;
	struct super_block *sb;
	struct file *h_file;
	char __user *buf = (char __user *)ubuf;

	dentry = file->f_dentry;
	sb = dentry->d_sb;
	inode = dentry->d_inode;
	mutex_lock(&inode->i_mutex);
	si_read_lock(sb, AuLock_FLUSH);

	err = au_reval_and_lock_fdi(file, au_reopen_nondir, /*wlock*/1);
	if (unlikely(err))
		goto out;

	err = au_ready_to_write(file, -1, &pin);
	di_downgrade_lock(dentry, AuLock_IR);
	if (unlikely(err))
		goto out_unlock;

	bstart = au_fbstart(file);
	h_file = au_h_fptr(file, bstart);
	au_unpin(&pin);
	err = vfsub_write_u(h_file, buf, count, ppos);
	au_cpup_attr_timesizes(inode);
	inode->i_mode = h_file->f_dentry->d_inode->i_mode;

 out_unlock:
	di_read_unlock(dentry, AuLock_IR);
	fi_write_unlock(file);
 out:
	si_read_unlock(sb);
	mutex_unlock(&inode->i_mutex);
	return err;
}

static ssize_t au_do_aio(struct file *h_file, int rw, struct kiocb *kio,
			 const struct iovec *iov, unsigned long nv, loff_t pos)
{
	ssize_t err;
	struct file *file;

	err = security_file_permission(h_file, rw);
	if (unlikely(err))
		goto out;

	file = kio->ki_filp;
	if (!is_sync_kiocb(kio)) {
		get_file(h_file);
		fput(file);
	}
	kio->ki_filp = h_file;
	if (rw == MAY_READ)
		err = h_file->f_op->aio_read(kio, iov, nv, pos);
	else if (rw == MAY_WRITE)
		err = h_file->f_op->aio_write(kio, iov, nv, pos);
	else
		BUG();
	/* do not restore kio->ki_filp */

 out:
	return err;
}

static ssize_t aufs_aio_read(struct kiocb *kio, const struct iovec *iov,
			     unsigned long nv, loff_t pos)
{
	ssize_t err;
	struct file *file, *h_file;
	struct dentry *dentry;
	struct super_block *sb;

	file = kio->ki_filp;
	dentry = file->f_dentry;
	sb = dentry->d_sb;
	si_read_lock(sb, AuLock_FLUSH);
	err = au_reval_and_lock_fdi(file, au_reopen_nondir, /*wlock*/0);
	if (unlikely(err))
		goto out;

	err = -ENOSYS;
	h_file = au_h_fptr(file, au_fbstart(file));
	if (h_file->f_op && h_file->f_op->aio_read) {
		err = au_do_aio(h_file, MAY_READ, kio, iov, nv, pos);
		/* todo: necessary? */
		/* file->f_ra = h_file->f_ra; */
		fsstack_copy_attr_atime(dentry->d_inode,
					h_file->f_dentry->d_inode);
	} else
		/* currently there is no such fs */
		WARN_ON_ONCE(h_file->f_op && h_file->f_op->read);

	di_read_unlock(dentry, AuLock_IR);
	fi_read_unlock(file);

 out:
	si_read_unlock(sb);
	return err;
}

static ssize_t aufs_aio_write(struct kiocb *kio, const struct iovec *iov,
			      unsigned long nv, loff_t pos)
{
	ssize_t err;
	struct au_pin pin;
	struct dentry *dentry;
	struct inode *inode;
	struct super_block *sb;
	struct file *file, *h_file;

	file = kio->ki_filp;
	dentry = file->f_dentry;
	sb = dentry->d_sb;
	inode = dentry->d_inode;
	mutex_lock(&inode->i_mutex);
	si_read_lock(sb, AuLock_FLUSH);

	err = au_reval_and_lock_fdi(file, au_reopen_nondir, /*wlock*/1);
	if (unlikely(err))
		goto out;

	err = au_ready_to_write(file, -1, &pin);
	di_downgrade_lock(dentry, AuLock_IR);
	if (unlikely(err))
		goto out_unlock;

	err = -ENOSYS;
	h_file = au_h_fptr(file, au_fbstart(file));
	au_unpin(&pin);
	if (h_file->f_op && h_file->f_op->aio_write) {
		err = au_do_aio(h_file, MAY_WRITE, kio, iov, nv, pos);
		au_cpup_attr_timesizes(inode);
		inode->i_mode = h_file->f_dentry->d_inode->i_mode;
	} else
		/* currently there is no such fs */
		WARN_ON_ONCE(h_file->f_op && h_file->f_op->write);

 out_unlock:
	di_read_unlock(dentry, AuLock_IR);
	fi_write_unlock(file);
 out:
	si_read_unlock(sb);
	mutex_unlock(&inode->i_mutex);
	return err;
}

static ssize_t aufs_splice_read(struct file *file, loff_t *ppos,
				struct pipe_inode_info *pipe, size_t len,
				unsigned int flags)
{
	ssize_t err;
	struct file *h_file;
	struct dentry *dentry;
	struct super_block *sb;

	dentry = file->f_dentry;
	sb = dentry->d_sb;
	si_read_lock(sb, AuLock_FLUSH);
	err = au_reval_and_lock_fdi(file, au_reopen_nondir, /*wlock*/0);
	if (unlikely(err))
		goto out;

	err = -EINVAL;
	h_file = au_h_fptr(file, au_fbstart(file));
	if (au_test_loopback_kthread()) {
		file->f_mapping = h_file->f_mapping;
		smp_mb(); /* unnecessary? */
	}
	err = vfsub_splice_to(h_file, ppos, pipe, len, flags);
	/* todo: necessasry? */
	/* file->f_ra = h_file->f_ra; */
	fsstack_copy_attr_atime(dentry->d_inode, h_file->f_dentry->d_inode);

	di_read_unlock(dentry, AuLock_IR);
	fi_read_unlock(file);

 out:
	si_read_unlock(sb);
	return err;
}

static ssize_t
aufs_splice_write(struct pipe_inode_info *pipe, struct file *file, loff_t *ppos,
		  size_t len, unsigned int flags)
{
	ssize_t err;
	struct au_pin pin;
	struct dentry *dentry;
	struct inode *inode;
	struct super_block *sb;
	struct file *h_file;

	dentry = file->f_dentry;
	inode = dentry->d_inode;
	mutex_lock(&inode->i_mutex);
	sb = dentry->d_sb;
	si_read_lock(sb, AuLock_FLUSH);

	err = au_reval_and_lock_fdi(file, au_reopen_nondir, /*wlock*/1);
	if (unlikely(err))
		goto out;

	err = au_ready_to_write(file, -1, &pin);
	di_downgrade_lock(dentry, AuLock_IR);
	if (unlikely(err))
		goto out_unlock;

	h_file = au_h_fptr(file, au_fbstart(file));
	au_unpin(&pin);
	err = vfsub_splice_from(pipe, h_file, ppos, len, flags);
	au_cpup_attr_timesizes(inode);
	inode->i_mode = h_file->f_dentry->d_inode->i_mode;

 out_unlock:
	di_read_unlock(dentry, AuLock_IR);
	fi_write_unlock(file);
 out:
	si_read_unlock(sb);
	mutex_unlock(&inode->i_mutex);
	return err;
}

/* ---------------------------------------------------------------------- */

static struct file *au_safe_file(struct vm_area_struct *vma)
{
	struct file *file;

	file = vma->vm_file;
	if (file->private_data && au_test_aufs(file->f_dentry->d_sb))
		return file;
	return NULL;
}

static void au_reset_file(struct vm_area_struct *vma, struct file *file)
{
	vma->vm_file = file;
	/* smp_mb(); */ /* flush vm_file */
}

static int aufs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int err;
	static DECLARE_WAIT_QUEUE_HEAD(wq);
	struct file *file, *h_file;
	struct au_finfo *finfo;

	/* todo: non-robr mode, user vm_file as it is? */
	wait_event(wq, (file = au_safe_file(vma)));

	/* do not revalidate, no si lock */
	finfo = au_fi(file);
	h_file = finfo->fi_hfile[0 + finfo->fi_bstart].hf_file;
	AuDebugOn(!h_file || !finfo->fi_h_vm_ops);

	mutex_lock(&finfo->fi_vm_mtx);
	vma->vm_file = h_file;
	err = finfo->fi_h_vm_ops->fault(vma, vmf);
	/* todo: necessary? */
	/* file->f_ra = h_file->f_ra; */
	au_reset_file(vma, file);
	mutex_unlock(&finfo->fi_vm_mtx);
#if 0 /* def CONFIG_SMP */
	/* wake_up_nr(&wq, online_cpu - 1); */
	wake_up_all(&wq);
#else
	wake_up(&wq);
#endif

	return err;
}

static int aufs_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int err;
	static DECLARE_WAIT_QUEUE_HEAD(wq);
	struct file *file, *h_file;
	struct au_finfo *finfo;

	wait_event(wq, (file = au_safe_file(vma)));

	finfo = au_fi(file);
	h_file = finfo->fi_hfile[0 + finfo->fi_bstart].hf_file;
	AuDebugOn(!h_file || !finfo->fi_h_vm_ops);

	mutex_lock(&finfo->fi_vm_mtx);
	vma->vm_file = h_file;
	err = finfo->fi_h_vm_ops->page_mkwrite(vma, vmf);
	au_reset_file(vma, file);
	mutex_unlock(&finfo->fi_vm_mtx);
	wake_up(&wq);

	return err;
}

static void aufs_vm_close(struct vm_area_struct *vma)
{
	static DECLARE_WAIT_QUEUE_HEAD(wq);
	struct file *file, *h_file;
	struct au_finfo *finfo;

	wait_event(wq, (file = au_safe_file(vma)));

	finfo = au_fi(file);
	h_file = finfo->fi_hfile[0 + finfo->fi_bstart].hf_file;
	AuDebugOn(!h_file || !finfo->fi_h_vm_ops);

	mutex_lock(&finfo->fi_vm_mtx);
	vma->vm_file = h_file;
	finfo->fi_h_vm_ops->close(vma);
	au_reset_file(vma, file);
	mutex_unlock(&finfo->fi_vm_mtx);
	wake_up(&wq);
}

static struct vm_operations_struct aufs_vm_ops = {
	/* .close and .page_mkwrite are not set by default */
	.fault		= aufs_fault,
};

/* ---------------------------------------------------------------------- */

/* cf. linux/include/linux/mman.h: calc_vm_prot_bits() */
#define AuConv_VM_PROT(f, b)	_calc_vm_trans(f, VM_##b, PROT_##b)

static unsigned long au_arch_prot_conv(unsigned long flags)
{
	/* currently ppc64 only */
#ifdef CONFIG_PPC64
	/* cf. linux/arch/powerpc/include/asm/mman.h */
	AuDebugOn(arch_calc_vm_prot_bits(-1) != VM_SAO);
	return AuConv_VM_PROT(flags, SAO);
#else
	AuDebugOn(arch_calc_vm_prot_bits(-1));
	return 0;
#endif
}

static unsigned long au_prot_conv(unsigned long flags)
{
	return AuConv_VM_PROT(flags, READ)
		| AuConv_VM_PROT(flags, WRITE)
		| AuConv_VM_PROT(flags, EXEC)
		| au_arch_prot_conv(flags);
}

/* cf. linux/include/linux/mman.h: calc_vm_flag_bits() */
#define AuConv_VM_MAP(f, b)	_calc_vm_trans(f, VM_##b, MAP_##b)

static unsigned long au_flag_conv(unsigned long flags)
{
	return AuConv_VM_MAP(flags, GROWSDOWN)
		| AuConv_VM_MAP(flags, DENYWRITE)
		| AuConv_VM_MAP(flags, EXECUTABLE)
		| AuConv_VM_MAP(flags, LOCKED);
}

static struct vm_operations_struct *au_vm_ops(struct file *h_file,
					      struct vm_area_struct *vma)
{
	struct vm_operations_struct *vm_ops;
	unsigned long prot;
	int err;

	vm_ops = ERR_PTR(-ENODEV);
	if (!h_file->f_op || !h_file->f_op->mmap)
		goto out;

	prot = au_prot_conv(vma->vm_flags);
	err = security_file_mmap(h_file, /*reqprot*/prot, prot,
				 au_flag_conv(vma->vm_flags), vma->vm_start, 0);
	vm_ops = ERR_PTR(err);
	if (unlikely(err))
		goto out;

	err = ima_file_mmap(h_file, prot);
	vm_ops = ERR_PTR(err);
	if (unlikely(err))
		goto out;

	err = h_file->f_op->mmap(h_file, vma);
	vm_ops = ERR_PTR(err);
	if (unlikely(err))
		goto out;

	/* oops, it became 'const' */
	vm_ops = (struct vm_operations_struct *)vma->vm_ops;
	err = do_munmap(current->mm, vma->vm_start,
			vma->vm_end - vma->vm_start);
	if (unlikely(err)) {
		AuIOErr("failed internal unmapping %.*s, %d\n",
			AuDLNPair(h_file->f_dentry), err);
		vm_ops = ERR_PTR(-EIO);
	}

 out:
	return vm_ops;
}

static int au_custom_vm_ops(struct au_finfo *finfo, struct vm_area_struct *vma)
{
	int err;
	struct vm_operations_struct *h_ops;

	MtxMustLock(&finfo->fi_mmap);

	err = 0;
	h_ops = finfo->fi_h_vm_ops;
	AuDebugOn(!h_ops);
	if ((!h_ops->page_mkwrite && !h_ops->close)
	    || finfo->fi_vm_ops)
		goto out;

	err = -ENOMEM;
	finfo->fi_vm_ops = kmemdup(&aufs_vm_ops, sizeof(aufs_vm_ops), GFP_NOFS);
	if (unlikely(!finfo->fi_vm_ops))
		goto out;

	err = 0;
	if (h_ops->page_mkwrite)
		finfo->fi_vm_ops->page_mkwrite = aufs_page_mkwrite;
	if (h_ops->close)
		finfo->fi_vm_ops->close = aufs_vm_close;

	vma->vm_ops = finfo->fi_vm_ops;

 out:
	return err;
}

/*
 * This is another ugly approach to keep the lock order, particularly
 * mm->mmap_sem and aufs rwsem. The previous approach was reverted and you can
 * find it in git-log, if you want.
 *
 * native readdir: i_mutex, copy_to_user, mmap_sem
 * aufs readdir: i_mutex, rwsem, nested-i_mutex, copy_to_user, mmap_sem
 *
 * Before aufs_mmap() mmap_sem is acquired already, but aufs_mmap() has to
 * acquire aufs rwsem. It introduces a circular locking dependency.
 * To address this problem, aufs_mmap() delegates the part which requires aufs
 * rwsem to its internal workqueue.
 */

/* very ugly approach */
#ifdef CONFIG_DEBUG_MUTEXES
#include <../kernel/mutex-debug.h>
#else
#include <../kernel/mutex.h>
#endif

struct au_mmap_pre_args {
	/* input */
	struct file *file;
	struct vm_area_struct *vma;

	/* output */
	int *errp;
	struct file *h_file;
	int mmapped;
};

static int au_mmap_pre(struct file *file, struct vm_area_struct *vma,
		       struct file **h_file, int *mmapped)
{
	int err;
	const unsigned char wlock
		= !!(file->f_mode & FMODE_WRITE) && (vma->vm_flags & VM_SHARED);
	struct dentry *dentry;
	struct super_block *sb;

	dentry = file->f_dentry;
	sb = dentry->d_sb;
	si_read_lock(sb, !AuLock_FLUSH);
	err = au_reval_and_lock_fdi(file, au_reopen_nondir, /*wlock*/1);
	if (unlikely(err))
		goto out;

	*mmapped = !!au_test_mmapped(file);
	if (wlock) {
		struct au_pin pin;

		err = au_ready_to_write(file, -1, &pin);
		di_write_unlock(dentry);
		if (unlikely(err))
			goto out_unlock;
		au_unpin(&pin);
	} else
		di_write_unlock(dentry);
	*h_file = au_h_fptr(file, au_fbstart(file));
	get_file(*h_file);
	au_fi_mmap_lock(file);

out_unlock:
	fi_write_unlock(file);
out:
	si_read_unlock(sb);
	return err;
}

static void au_call_mmap_pre(void *args)
{
	struct au_mmap_pre_args *a = args;
	*a->errp = au_mmap_pre(a->file, a->vma, &a->h_file, &a->mmapped);
}

static int aufs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err, wkq_err;
	struct au_finfo *finfo;
	struct dentry *h_dentry;
	struct vm_operations_struct *vm_ops;
	struct au_mmap_pre_args args = {
		.file		= file,
		.vma		= vma,
		.errp		= &err
	};

	wkq_err = au_wkq_wait_pre(au_call_mmap_pre, &args);
	if (unlikely(wkq_err))
		err = wkq_err;
	if (unlikely(err))
		goto out;
	finfo = au_fi(file);

	h_dentry = args.h_file->f_dentry;
	if (!args.mmapped && au_test_fs_bad_mapping(h_dentry->d_sb)) {
		/*
		 * by this assignment, f_mapping will differs from aufs inode
		 * i_mapping.
		 * if someone else mixes the use of f_dentry->d_inode and
		 * f_mapping->host, then a problem may arise.
		 */
		file->f_mapping = args.h_file->f_mapping;
	}

	vm_ops = NULL;
	if (!args.mmapped) {
		vm_ops = au_vm_ops(args.h_file, vma);
		err = PTR_ERR(vm_ops);
		if (IS_ERR(vm_ops))
			goto out_unlock;
	}

	/*
	 * unnecessary to handle MAP_DENYWRITE and deny_write_access()?
	 * currently MAP_DENYWRITE from userspace is ignored, but elf loader
	 * sets it. when FMODE_EXEC is set (by open_exec() or sys_uselib()),
	 * both of the aufs file and the lower file is deny_write_access()-ed.
	 * finally I hope we can skip handlling MAP_DENYWRITE here.
	 */
	err = generic_file_mmap(file, vma);
	if (unlikely(err))
		goto out_unlock;

	vma->vm_ops = &aufs_vm_ops;
	if (!args.mmapped) {
		finfo->fi_h_vm_ops = vm_ops;
		mutex_init(&finfo->fi_vm_mtx);
	}

	err = au_custom_vm_ops(finfo, vma);
	if (unlikely(err))
		goto out_unlock;

	vfsub_file_accessed(args.h_file);
	fsstack_copy_attr_atime(file->f_dentry->d_inode, h_dentry->d_inode);

 out_unlock:
	au_fi_mmap_unlock(file);
	fput(args.h_file);
 out:
	return err;
}

/* ---------------------------------------------------------------------- */

static int aufs_fsync_nondir(struct file *file, struct dentry *dentry,
			     int datasync)
{
	int err;
	struct au_pin pin;
	struct inode *inode;
	struct file *h_file;
	struct super_block *sb;

	inode = dentry->d_inode;
	IMustLock(file->f_mapping->host);
	if (inode != file->f_mapping->host) {
		mutex_unlock(&file->f_mapping->host->i_mutex);
		mutex_lock(&inode->i_mutex);
	}
	IMustLock(inode);

	sb = dentry->d_sb;
	si_read_lock(sb, AuLock_FLUSH);

	err = 0; /* -EBADF; */ /* posix? */
	if (unlikely(!(file->f_mode & FMODE_WRITE)))
		goto out;
	err = au_reval_and_lock_fdi(file, au_reopen_nondir, /*wlock*/1);
	if (unlikely(err))
		goto out;

	err = au_ready_to_write(file, -1, &pin);
	di_downgrade_lock(dentry, AuLock_IR);
	if (unlikely(err))
		goto out_unlock;
	au_unpin(&pin);

	err = -EINVAL;
	h_file = au_h_fptr(file, au_fbstart(file));
	if (h_file->f_op && h_file->f_op->fsync) {
		struct dentry *h_d;
		struct mutex *h_mtx;

		/*
		 * no filemap_fdatawrite() since aufs file has no its own
		 * mapping, but dir.
		 */
		h_d = h_file->f_dentry;
		h_mtx = &h_d->d_inode->i_mutex;
		mutex_lock_nested(h_mtx, AuLsc_I_CHILD);
		err = h_file->f_op->fsync(h_file, h_d, datasync);
		if (!err)
			vfsub_update_h_iattr(&h_file->f_path, /*did*/NULL);
		/*ignore*/
		au_cpup_attr_timesizes(inode);
		mutex_unlock(h_mtx);
	}

 out_unlock:
	di_read_unlock(dentry, AuLock_IR);
	fi_write_unlock(file);
 out:
	si_read_unlock(sb);
	if (inode != file->f_mapping->host) {
		mutex_unlock(&inode->i_mutex);
		mutex_lock(&file->f_mapping->host->i_mutex);
	}
	return err;
}

/* no one supports this operation, currently */
#if 0
static int aufs_aio_fsync_nondir(struct kiocb *kio, int datasync)
{
	int err;
	struct au_pin pin;
	struct dentry *dentry;
	struct inode *inode;
	struct file *file, *h_file;
	struct super_block *sb;

	file = kio->ki_filp;
	dentry = file->f_dentry;
	inode = dentry->d_inode;
	mutex_lock(&inode->i_mutex);

	sb = dentry->d_sb;
	si_read_lock(sb, AuLock_FLUSH);

	err = 0; /* -EBADF; */ /* posix? */
	if (unlikely(!(file->f_mode & FMODE_WRITE)))
		goto out;
	err = au_reval_and_lock_fdi(file, au_reopen_nondir, /*wlock*/1);
	if (unlikely(err))
		goto out;

	err = au_ready_to_write(file, -1, &pin);
	di_downgrade_lock(dentry, AuLock_IR);
	if (unlikely(err))
		goto out_unlock;
	au_unpin(&pin);

	err = -ENOSYS;
	h_file = au_h_fptr(file, au_fbstart(file));
	if (h_file->f_op && h_file->f_op->aio_fsync) {
		struct dentry *h_d;
		struct mutex *h_mtx;

		h_d = h_file->f_dentry;
		h_mtx = &h_d->d_inode->i_mutex;
		if (!is_sync_kiocb(kio)) {
			get_file(h_file);
			fput(file);
		}
		kio->ki_filp = h_file;
		err = h_file->f_op->aio_fsync(kio, datasync);
		mutex_lock_nested(h_mtx, AuLsc_I_CHILD);
		if (!err)
			vfsub_update_h_iattr(&h_file->f_path, /*did*/NULL);
		/*ignore*/
		au_cpup_attr_timesizes(inode);
		mutex_unlock(h_mtx);
	}

 out_unlock:
	di_read_unlock(dentry, AuLock_IR);
	fi_write_unlock(file);
 out:
	si_read_unlock(sb);
	mutex_unlock(&inode->i_mutex);
	return err;
}
#endif

static int aufs_fasync(int fd, struct file *file, int flag)
{
	int err;
	struct file *h_file;
	struct dentry *dentry;
	struct super_block *sb;

	dentry = file->f_dentry;
	sb = dentry->d_sb;
	si_read_lock(sb, AuLock_FLUSH);
	err = au_reval_and_lock_fdi(file, au_reopen_nondir, /*wlock*/0);
	if (unlikely(err))
		goto out;

	h_file = au_h_fptr(file, au_fbstart(file));
	if (h_file->f_op && h_file->f_op->fasync)
		err = h_file->f_op->fasync(fd, h_file, flag);

	di_read_unlock(dentry, AuLock_IR);
	fi_read_unlock(file);

 out:
	si_read_unlock(sb);
	return err;
}

/* ---------------------------------------------------------------------- */

/* no one supports this operation, currently */
#if 0
static ssize_t aufs_sendpage(struct file *file, struct page *page, int offset,
			     size_t len, loff_t *pos , int more)
{
}
#endif

/* ---------------------------------------------------------------------- */

const struct file_operations aufs_file_fop = {
	/*
	 * while generic_file_llseek/_unlocked() don't use BKL,
	 * don't use it since it operates file->f_mapping->host.
	 * in aufs, it may be a real file and may confuse users by UDBA.
	 */
	/* .llseek		= generic_file_llseek, */

	.read		= aufs_read,
	.write		= aufs_write,
	.aio_read	= aufs_aio_read,
	.aio_write	= aufs_aio_write,
#ifdef CONFIG_AUFS_POLL
	.poll		= aufs_poll,
#endif
	.unlocked_ioctl	= aufs_ioctl_nondir,
	.mmap		= aufs_mmap,
	.open		= aufs_open_nondir,
	.flush		= aufs_flush,
	.release	= aufs_release_nondir,
	.fsync		= aufs_fsync_nondir,
	/* .aio_fsync	= aufs_aio_fsync_nondir, */
	.fasync		= aufs_fasync,
	/* .sendpage	= aufs_sendpage, */
	.splice_write	= aufs_splice_write,
	.splice_read	= aufs_splice_read,
#if 0
	.aio_splice_write = aufs_aio_splice_write,
	.aio_splice_read  = aufs_aio_splice_read
#endif
};
