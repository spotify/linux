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
 * magic sysrq hanlder
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
/* #include <linux/sysrq.h> */
#include "aufs.h"

/* ---------------------------------------------------------------------- */

static void sysrq_sb(struct super_block *sb)
{
	char *plevel;
	struct au_sbinfo *sbinfo;
	struct file *file;

	plevel = au_plevel;
	au_plevel = KERN_WARNING;
	au_debug(1);

	sbinfo = au_sbi(sb);
	/* since we define pr_fmt, call printk directly */
	printk(KERN_WARNING "si=%lx\n", sysaufs_si_id(sbinfo));
	printk(KERN_WARNING AUFS_NAME ": superblock\n");
	au_dpri_sb(sb);
	printk(KERN_WARNING AUFS_NAME ": root dentry\n");
	au_dpri_dentry(sb->s_root);
	printk(KERN_WARNING AUFS_NAME ": root inode\n");
	au_dpri_inode(sb->s_root->d_inode);
#if 0
	struct inode *i;
	printk(KERN_WARNING AUFS_NAME ": isolated inode\n");
	list_for_each_entry(i, &sb->s_inodes, i_sb_list)
		if (list_empty(&i->i_dentry))
			au_dpri_inode(i);
#endif
	printk(KERN_WARNING AUFS_NAME ": files\n");
	list_for_each_entry(file, &sb->s_files, f_u.fu_list) {
		umode_t mode;
		mode = file->f_dentry->d_inode->i_mode;
		if (!special_file(mode) || au_special_file(mode))
			au_dpri_file(file);
	}

	au_plevel = plevel;
	au_debug(0);
}

/* ---------------------------------------------------------------------- */

/* module parameter */
static char *aufs_sysrq_key = "a";
module_param_named(sysrq, aufs_sysrq_key, charp, S_IRUGO);
MODULE_PARM_DESC(sysrq, "MagicSysRq key for " AUFS_NAME);

static void au_sysrq(int key __maybe_unused,
		     struct tty_struct *tty __maybe_unused)
{
	struct kobject *kobj;
	struct au_sbinfo *sbinfo;

	/* spin_lock(&sysaufs_ket->list_lock); */
	list_for_each_entry(kobj, &sysaufs_ket->list, entry) {
		sbinfo = container_of(kobj, struct au_sbinfo, si_kobj);
		sysrq_sb(sbinfo->si_sb);
	}
	/* spin_unlock(&sysaufs_ket->list_lock); */
}

static struct sysrq_key_op au_sysrq_op = {
	.handler	= au_sysrq,
	.help_msg	= "Aufs",
	.action_msg	= "Aufs",
	.enable_mask	= SYSRQ_ENABLE_DUMP
};

/* ---------------------------------------------------------------------- */

int __init au_sysrq_init(void)
{
	int err;
	char key;

	err = -1;
	key = *aufs_sysrq_key;
	if ('a' <= key && key <= 'z')
		err = register_sysrq_key(key, &au_sysrq_op);
	if (unlikely(err))
		pr_err("err %d, sysrq=%c\n", err, key);
	return err;
}

void au_sysrq_fin(void)
{
	int err;
	err = unregister_sysrq_key(*aufs_sysrq_key, &au_sysrq_op);
	if (unlikely(err))
		pr_err("err %d (ignored)\n", err);
}
