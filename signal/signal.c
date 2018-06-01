#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/mutex.h>
typedef struct{
	struct mutex lock;
	bool enabled;
	wait_queue_head_t wait_q;
	struct task_struct *wakee;
	struct task_struct *waker;

}evt_ctx_t;
static evt_ctx_t ctx;

/* Enable/disable wakeup event (disabled by default) */
static int signal_enabled_param_set(const char *val,const struct kernel_param *kp);
static struct kernel_param_ops signal_enabled_param_ops = {
	.set =		signal_enabled_param_set,
	.get =		param_get_bool,
};
module_param_cb(enabled, &signal_enabled_param_ops, &ctx.enabled, 0644);



static int signal_enabled_param_set(const char *val,
				   const struct kernel_param *kp)
{
	int ret = 0;
	mutex_lock(&ctx.lock);
	ret = param_set_bool(val, kp);
	mutex_unlock(&ctx.lock);
	if(ret != 0)
		return ret;
	ctx.waker = current;
	printk("waker:%d,wakee:%d\n",ctx.waker->pid,ctx.wakee->pid);
	if(!ctx.enabled){
		printk("%s wakeup %s\n",ctx.waker->comm,ctx.wakee->comm);
		wake_up(&ctx.wait_q);
	}
	return 0;
}

static void context_init(evt_ctx_t* ctx)
{
	ctx->wakee = current;
	init_waitqueue_head(&ctx->wait_q);
	mutex_init(&ctx->lock);
}

static void context_destroy(evt_ctx_t* ctx){
	if(mutex_is_locked(&ctx->lock)){
		mutex_unlock(&ctx->lock);
	}
	mutex_destroy(&ctx->lock);

}

//ERESTARTSYS 512
static __init int signal_init(void)
{
	int ret = 0;
	context_init(&ctx);
	printk(KERN_ALERT "%s enter!\n",__func__);
	ret = wait_event_interruptible_timeout(ctx.wait_q,ctx.enabled,10*HZ);
	//ret = wait_event_killable(signal_wait,signal_enabled);
	printk("ret:%d\n",ret);
	if(ret == 0)
		return -ETIME;
	if(ret < 0)
		return -ERESTARTSYS;

	printk(KERN_ALERT "%s exit\n",__func__);
	return 0;
}

static __exit void signal_exit(void)
{
	context_destroy(&ctx);
	printk(KERN_ALERT "%s exit!\n",__func__);
}

module_init(signal_init);
module_exit(signal_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("jiangwei.chow@gmail.com");
MODULE_DESCRIPTION("kernel module sample for singnal handle");


