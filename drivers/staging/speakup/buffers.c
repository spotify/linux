#include <linux/console.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h> /* for in_atomic */
#include <linux/types.h>
#include <linux/wait.h>

#include "speakup.h"
#include "spk_priv.h"

#define synthBufferSize 8192	/* currently 8K bytes */

static u_char synth_buffer[synthBufferSize];	/* guess what this is for! */
static u_char *buff_in = synth_buffer;
static u_char *buff_out = synth_buffer;
static u_char *buffer_end = synth_buffer+synthBufferSize-1;

/* These try to throttle applications by stopping the TTYs
 * Note: we need to make sure that we will restart them eventually, which is
 * usually not possible to do from the notifiers.
 *
 * So we only stop when we know alive == 1 (else we discard the data anyway),
 * and the alive synth will eventually call start_ttys from the thread context.
 */
void speakup_start_ttys(void)
{
	int i;

	BUG_ON(in_atomic());
	lock_kernel();
	for (i = 0; i < MAX_NR_CONSOLES; i++) {
		if (speakup_console[i] && speakup_console[i]->tty_stopped)
			continue;
		if ((vc_cons[i].d != NULL) && (vc_cons[i].d->vc_tty != NULL))
			start_tty(vc_cons[i].d->vc_tty);
	}
	unlock_kernel();
}
EXPORT_SYMBOL_GPL(speakup_start_ttys);

static void speakup_stop_ttys(void)
{
	int i;

	if (!in_atomic())
		lock_kernel();
	else if (!kernel_locked()) {
		/* BKL is not held and we are in a critical section, too bad,
		 * let the buffer continue to fill up.
		 *
		 * This only happens with kernel messages and keyboard echo, so
		 * that shouldn't be so much a concern.
		 */
		return;
	}
	for (i = 0; i < MAX_NR_CONSOLES; i++)
		if ((vc_cons[i].d != NULL) && (vc_cons[i].d->vc_tty != NULL))
			stop_tty(vc_cons[i].d->vc_tty);
	if (!in_atomic())
		unlock_kernel();
	return;
}

static int synth_buffer_free(void)
{
	int bytesFree;

	if (buff_in >= buff_out)
		bytesFree = synthBufferSize - (buff_in - buff_out);
	else
		bytesFree = buff_out - buff_in;
	return bytesFree;
}

int synth_buffer_empty(void)
{
	return (buff_in == buff_out);
}
EXPORT_SYMBOL_GPL(synth_buffer_empty);

void synth_buffer_add(char ch)
{
	if (!synth->alive) {
		/* This makes sure that we won't stop TTYs if there is no synth
		 * to restart them */
		return;
	}
	if (synth_buffer_free() <= 100) {
		synth_start();
		speakup_stop_ttys();
	}
	if (synth_buffer_free() <= 1)
		return;
	*buff_in++ = ch;
	if (buff_in > buffer_end)
		buff_in = synth_buffer;
}

char synth_buffer_getc(void)
{
	char ch;

	if (buff_out == buff_in)
		return 0;
	ch = *buff_out++;
	if (buff_out > buffer_end)
		buff_out = synth_buffer;
	return ch;
}
EXPORT_SYMBOL_GPL(synth_buffer_getc);

char synth_buffer_peek(void)
{
	if (buff_out == buff_in)
		return 0;
	return *buff_out;
}
EXPORT_SYMBOL_GPL(synth_buffer_peek);

void synth_buffer_clear(void)
{
	buff_in = buff_out = synth_buffer;
	return;
}
EXPORT_SYMBOL_GPL(synth_buffer_clear);
