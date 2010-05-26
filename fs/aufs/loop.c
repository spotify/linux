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
 * support for loopback block device as a branch
 */

#include <linux/loop.h>
#include "aufs.h"

/*
 * test if two lower dentries have overlapping branches.
 */
int au_test_loopback_overlap(struct super_block *sb, struct dentry *h_d1,
			     struct dentry *h_d2)
{
	struct inode *h_inode;
	struct loop_device *l;

	h_inode = h_d1->d_inode;
	if (MAJOR(h_inode->i_sb->s_dev) != LOOP_MAJOR)
		return 0;

	l = h_inode->i_sb->s_bdev->bd_disk->private_data;
	h_d1 = l->lo_backing_file->f_dentry;
	/* h_d1 can be local NFS. in this case aufs cannot detect the loop */
	if (unlikely(h_d1->d_sb == sb))
		return 1;
	return !!au_test_subdir(h_d1, h_d2);
}

/* true if a kernel thread named 'loop[0-9].*' accesses a file */
int au_test_loopback_kthread(void)
{
	const char c = current->comm[4];

	return current->mm == NULL
	       && '0' <= c && c <= '9'
	       && strncmp(current->comm, "loop", 4) == 0;
}
