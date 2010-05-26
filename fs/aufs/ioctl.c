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
 * ioctl
 * plink-management and readdir in userspace.
 * assist the pathconf(3) wrapper library.
 */

#include <linux/file.h>
#include "aufs.h"

static int au_wbr_fd(struct path *path)
{
	int err, fd, flags;
	aufs_bindex_t wbi, bindex, bend;
	struct file *h_file;
	struct super_block *sb;
	struct dentry *root;
	struct au_branch *wbr;

	err = get_unused_fd();
	if (unlikely(err < 0))
		goto out;
	fd = err;

	flags = O_RDONLY | O_DIRECTORY;
	if (force_o_largefile())
		flags |= O_LARGEFILE;

	wbi = 0;
	sb = path->dentry->d_sb;
	root = sb->s_root;
	aufs_read_lock(root, AuLock_IR);
	wbr = au_sbr(sb, wbi);
	if (!(path->mnt->mnt_flags & MNT_READONLY)
	    && !au_br_writable(wbr->br_perm)) {
		bend = au_sbend(sb);
		for (bindex = 1; bindex <= bend; bindex++) {
			wbr = au_sbr(sb, bindex);
			if (au_br_writable(wbr->br_perm)) {
				wbi = bindex;
				break;
			}
		}
		wbr = au_sbr(sb, wbi);
	}
	AuDbg("wbi %d\n", wbi);
	h_file = au_h_open(root, wbi, flags, NULL);
	aufs_read_unlock(root, AuLock_IR);
	err = PTR_ERR(h_file);
	if (IS_ERR(h_file))
		goto out_fd;

	atomic_dec(&wbr->br_count); /* cf. au_h_open() */
	fd_install(fd, h_file);
	err = fd;
	goto out; /* success */

 out_fd:
	put_unused_fd(fd);
 out:
	return err;
}

/* ---------------------------------------------------------------------- */

long aufs_ioctl_dir(struct file *file, unsigned int cmd, unsigned long arg)
{
	long err;

	switch (cmd) {
	case AUFS_CTL_PLINK_MAINT:
	case AUFS_CTL_PLINK_CLEAN:
		err = au_plink_ioctl(file, cmd);
		break;

	case AUFS_CTL_RDU:
	case AUFS_CTL_RDU_INO:
		err = au_rdu_ioctl(file, cmd, arg);
		break;

	case AUFS_CTL_WBR_FD:
		err = au_wbr_fd(&file->f_path);
		break;

	default:
		err = -EINVAL;
	}

	AuTraceErr(err);
	return err;
}

long aufs_ioctl_nondir(struct file *file, unsigned int cmd, unsigned long arg)
{
	long err;

	switch (cmd) {
	case AUFS_CTL_WBR_FD:
		err = au_wbr_fd(&file->f_path);
		break;

	default:
		err = -EINVAL;
	}

	AuTraceErr(err);
	return err;
}
