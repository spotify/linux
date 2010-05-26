#include <linux/kthread.h>
#include <linux/wait.h>

#include "spk_types.h"
#include "speakup.h"
#include "spk_priv.h"

DECLARE_WAIT_QUEUE_HEAD(speakup_event);
EXPORT_SYMBOL_GPL(speakup_event);

int speakup_thread(void *data)
{
	unsigned long flags;
	int should_break;

	mutex_lock(&spk_mutex);
	while (1) {
		DEFINE_WAIT(wait);
		while(1) {
			spk_lock(flags);
			prepare_to_wait(&speakup_event, &wait, TASK_INTERRUPTIBLE);
			should_break = kthread_should_stop() ||
				(synth && synth->catch_up && synth->alive &&
					(speakup_info.flushing ||
					!synth_buffer_empty()));
			spk_unlock(flags);
			if (should_break)
				break;
			mutex_unlock(&spk_mutex);
			schedule();
			mutex_lock(&spk_mutex);
		}
		finish_wait(&speakup_event, &wait);
		if (kthread_should_stop())
			break;

		if (synth && synth->catch_up && synth->alive) {
			/* It is up to the callee to take the lock, so that it
			 * can sleep whenever it likes */
			synth->catch_up(synth);
		}

		speakup_start_ttys();
	}
	mutex_unlock(&spk_mutex);
	return 0;
}
