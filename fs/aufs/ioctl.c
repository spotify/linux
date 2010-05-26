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
 */

#include "aufs.h"

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

	default:
		err = -EINVAL;
	}

	AuTraceErr(err);
	return err;
}
