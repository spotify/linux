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
 * workqueue for asynchronous/super-io operations
 * todo: try new dredential scheme
 */

#include <linux/module.h>
#include "aufs.h"

/* internal workqueue named AUFS_WKQ_NAME */
static struct au_wkq {
	struct workqueue_struct	*q;

	/* balancing */
	atomic_t		busy;
} *au_wkq;

struct au_wkinfo {
	struct work_struct wk;
	struct super_block *sb;

	unsigned int flags; /* see wkq.h */

	au_wkq_func_t func;
	void *args;

	atomic_t *busyp;
	struct completion *comp;
};

/* ---------------------------------------------------------------------- */

static int enqueue(struct au_wkq *wkq, struct au_wkinfo *wkinfo)
{
	wkinfo->busyp = &wkq->busy;
	if (au_ftest_wkq(wkinfo->flags, WAIT))
		return !queue_work(wkq->q, &wkinfo->wk);
	else
		return !schedule_work(&wkinfo->wk);
}

static void do_wkq(struct au_wkinfo *wkinfo)
{
	unsigned int idle, n;
	int i, idle_idx;

	while (1) {
		if (au_ftest_wkq(wkinfo->flags, WAIT)) {
			idle_idx = 0;
			idle = UINT_MAX;
			for (i = 0; i < aufs_nwkq; i++) {
				n = atomic_inc_return(&au_wkq[i].busy);
				if (n == 1 && !enqueue(au_wkq + i, wkinfo))
					return; /* success */

				if (n < idle) {
					idle_idx = i;
					idle = n;
				}
				atomic_dec(&au_wkq[i].busy);
			}
		} else
			idle_idx = aufs_nwkq;

		atomic_inc(&au_wkq[idle_idx].busy);
		if (!enqueue(au_wkq + idle_idx, wkinfo))
			return; /* success */

		/* impossible? */
		AuWarn1("failed to queue_work()\n");
		yield();
	}
}

static void wkq_func(struct work_struct *wk)
{
	struct au_wkinfo *wkinfo = container_of(wk, struct au_wkinfo, wk);

	wkinfo->func(wkinfo->args);
	atomic_dec_return(wkinfo->busyp);
	if (au_ftest_wkq(wkinfo->flags, WAIT))
		complete(wkinfo->comp);
	else {
		kobject_put(&au_sbi(wkinfo->sb)->si_kobj);
		module_put(THIS_MODULE);
		kfree(wkinfo);
	}
}

/*
 * Since struct completion is large, try allocating it dynamically.
 */
#if defined(CONFIG_4KSTACKS) || defined(AuTest4KSTACKS)
#define AuWkqCompDeclare(name)	struct completion *comp = NULL

static int au_wkq_comp_alloc(struct au_wkinfo *wkinfo, struct completion **comp)
{
	*comp = kmalloc(sizeof(**comp), GFP_NOFS);
	if (*comp) {
		init_completion(*comp);
		wkinfo->comp = *comp;
		return 0;
	}
	return -ENOMEM;
}

static void au_wkq_comp_free(struct completion *comp)
{
	kfree(comp);
}

#else

/* no braces */
#define AuWkqCompDeclare(name) \
	DECLARE_COMPLETION_ONSTACK(_ ## name); \
	struct completion *comp = &_ ## name

static int au_wkq_comp_alloc(struct au_wkinfo *wkinfo, struct completion **comp)
{
	wkinfo->comp = *comp;
	return 0;
}

static void au_wkq_comp_free(struct completion *comp __maybe_unused)
{
	/* empty */
}
#endif /* 4KSTACKS */

static void au_wkq_run(struct au_wkinfo *wkinfo)
{
	au_dbg_verify_kthread();
	INIT_WORK(&wkinfo->wk, wkq_func);
	do_wkq(wkinfo);
}

int au_wkq_wait(au_wkq_func_t func, void *args)
{
	int err;
	AuWkqCompDeclare(comp);
	struct au_wkinfo wkinfo = {
		.flags	= AuWkq_WAIT,
		.func	= func,
		.args	= args
	};

	err = au_wkq_comp_alloc(&wkinfo, &comp);
	if (!err) {
		au_wkq_run(&wkinfo);
		/* no timeout, no interrupt */
		wait_for_completion(wkinfo.comp);
		au_wkq_comp_free(comp);
	}

	return err;

}

int au_wkq_nowait(au_wkq_func_t func, void *args, struct super_block *sb)
{
	int err;
	struct au_wkinfo *wkinfo;

	atomic_inc(&au_sbi(sb)->si_nowait.nw_len);

	/*
	 * wkq_func() must free this wkinfo.
	 * it highly depends upon the implementation of workqueue.
	 */
	err = 0;
	wkinfo = kmalloc(sizeof(*wkinfo), GFP_NOFS);
	if (wkinfo) {
		wkinfo->sb = sb;
		wkinfo->flags = !AuWkq_WAIT;
		wkinfo->func = func;
		wkinfo->args = args;
		wkinfo->comp = NULL;
		kobject_get(&au_sbi(sb)->si_kobj);
		__module_get(THIS_MODULE);

		au_wkq_run(wkinfo);
	} else {
		err = -ENOMEM;
		atomic_dec(&au_sbi(sb)->si_nowait.nw_len);
	}

	return err;
}

/* ---------------------------------------------------------------------- */

void au_nwt_init(struct au_nowait_tasks *nwt)
{
	atomic_set(&nwt->nw_len, 0);
	/* smp_mb();*/ /* atomic_set */
	init_waitqueue_head(&nwt->nw_wq);
}

void au_wkq_fin(void)
{
	int i;

	for (i = 0; i < aufs_nwkq; i++)
		if (au_wkq[i].q && !IS_ERR(au_wkq[i].q))
			destroy_workqueue(au_wkq[i].q);
	kfree(au_wkq);
}

int __init au_wkq_init(void)
{
	int err, i;
	struct au_wkq *nowaitq;

	/* '+1' is for accounting of nowait queue */
	err = -ENOMEM;
	au_wkq = kcalloc(aufs_nwkq + 1, sizeof(*au_wkq), GFP_NOFS);
	if (unlikely(!au_wkq))
		goto out;

	err = 0;
	for (i = 0; i < aufs_nwkq; i++) {
		au_wkq[i].q = create_singlethread_workqueue(AUFS_WKQ_NAME);
		if (au_wkq[i].q && !IS_ERR(au_wkq[i].q)) {
			atomic_set(&au_wkq[i].busy, 0);
			continue;
		}

		err = PTR_ERR(au_wkq[i].q);
		au_wkq_fin();
		goto out;
	}

	/* nowait accounting */
	nowaitq = au_wkq + aufs_nwkq;
	atomic_set(&nowaitq->busy, 0);
	nowaitq->q = NULL;
	/* smp_mb(); */ /* atomic_set */

 out:
	return err;
}
