#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/limits.h>	// for PATH_MAX
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/dcache.h>	// for d_path;

#include <dahdi/user.h>
#include "dcra_comm.h"

#define DCRA		"dcra"
#define DCRA_VER	"0.1.0"

#define DCRA_PROC_ROOT DCRA				//directory name /proc/dcra
#define DCRA_PROC_VERSION	"version"	// /proc/dcra/version
#define DCRA_PROC_REG		"reg"		// /proc/dcra/<n>/reg
#define DCRA_PROC_EXTREG	"extreg"	// /proc/dcra/<n>/extreg
#define DCRA_PROC_MODEL		"model"		// /proc/dcra/<n>/model

/* kernel parameters */
static int debug = 0;
static int maxchan = 128;	// maximum channels allowed
unsigned int dcra_debug_mask = 0;


static DEFINE_MUTEX(access_mutex);
static struct dcra_channel *channels = NULL;
static struct proc_dir_entry*	dcra_proc_root = NULL;
static struct proc_dir_entry*	dcra_proc_version = NULL;

static int dcra_chan_destroy(int channo);

static int dcra_split_path(char* buf, char** level1, char** level2, char ** level3 )
{
	const char *delim = "/";
	char *token, *cur;
	int index;
	
	*level1 = NULL;
	*level2 = NULL;
	*level3 = NULL;
	
	cur = buf;
	index = -1;
	while ( NULL != (token = strsep(&cur, delim)) )	{
        //skip "/proc"
        if (('\0' == token[0]) || 0 == strcmp("proc", token)) {
            continue;
        }
		if (0 == strcmp(DCRA_PROC_ROOT, token)) {
			index = 0; 
			continue;
		}
		
		if (0 == index)	{
			*level1 = token;
			index++;
			continue;
		}
		
		if (1 == index) {
			*level2 = token;
			index++;
			continue;
		}

		if (2 == index) {
			*level3 = token;
			index++;
			continue;
		}
		
		if (debug) {
			printk(DCRA": too many tokens %d, %s\n", index, token);
        }
        index++;
        continue;
	}
	
	if (index <= 0) {
		if (debug)
			printk(DCRA": path too short %d\n", index);
	}
	
	return index;
}


static ssize_t dcra_read(struct file *file, char __user *buf, size_t count, loff_t *f_pos)
{
	ssize_t retval = 0;
	char *name_buf = NULL;
	char *pname = NULL;
	char *level1, *level2, *level3;
	int res;
	
	/* get file full path name */
	name_buf = kmalloc(PATH_MAX + 1, GFP_KERNEL);
	pname = d_path(&file->f_path, name_buf, PATH_MAX);
	if (debug)
		printk(DCRA": read file %s\n", pname);

	/* do not support read from middle of file */
	if (0 != *f_pos) {
		if (debug)
			printk(DCRA": offset must be zero %s\n", pname);
		retval = 0;
		goto dcra_read_exit;
	}

	/* split path to seperate string */
	res = dcra_split_path(pname, &level1, &level2, &level3);
	if ( res <= 0 ) {
		if(debug)
			printk(DCRA": bad path %s\n", pname);
		retval =  -EBADF;
		goto dcra_read_exit;
	}
	
	/* level1 should be version or channel no */
	if (0 == strcmp(level1, DCRA_PROC_VERSION)) {
		char* stmp = DCRA_VER;
		if (copy_to_user(buf, stmp, strlen(stmp) + 1))	{
			if (debug)
				printk(DCRA": copy_to_user failed\n");
			retval =  -EIO;
		} else	{
			retval =  count;//strlen(stmp) + 1;
			*f_pos += retval;	// advance file offset pointer to stop read.
		}
		goto dcra_read_exit;
	} else { /* level1 is channo */
        unsigned int channo = 0; 
		unsigned int  regno = 0;
		struct dcra_channel* pchan;
		if(kstrtouint(level1, 10, &channo)){
			if (debug)
				printk(DCRA": failed parsing channo %s failed\n", name_buf);
			retval = -EBADF;
			goto dcra_read_exit;
        }
		
		if ((channo > maxchan) || (channo <= 0)) {
			if (debug)
				printk(DCRA": invalid channo %s\n", name_buf);
			retval = -EBADF;
			goto dcra_read_exit;
		} 

        if(mutex_lock_interruptible(&access_mutex))
            return -ERESTARTSYS;
        pchan = &channels[channo - 1];
		if (!pchan->reg_ops) {
            mutex_unlock(&access_mutex);
			if (debug)
				printk(DCRA": file operate undefined \n");
			retval = -EBADF;
			goto dcra_read_exit;
		}
		
		/* level 2 should be reg, extreg, or model */
		if ((0 == strcmp(level2, DCRA_PROC_REG)) || (0 == strcmp(level2, DCRA_PROC_EXTREG))) {
			if (NULL == level3) {
                mutex_unlock(&access_mutex);
				if (debug)
					printk(DCRA": no register number\n");
				retval = -EBADF;
				goto dcra_read_exit;
            } else if(kstrtouint(level3, 10, &regno)){
                mutex_unlock(&access_mutex);
                if (debug)
                    printk(DCRA": failed parsing regno %s failed\n", name_buf);
                retval = -EBADF;
                goto dcra_read_exit;

            }
		}
		
		if (0 == strcmp(level2, DCRA_PROC_REG)) {

            if(regno < 0 || regno >= pchan->num_regs){
                mutex_unlock(&access_mutex);
                if (debug)
                    printk(DCRA": failed invalid regno %d\n", regno);
                retval = -EBADF;
                goto dcra_read_exit;
            }
			if (pchan->reg_ops->get_reg) {
				uint8_t value;
				int res = pchan->reg_ops->get_reg(channo, regno, &value);
                mutex_unlock(&access_mutex);
				if (0 == res) {
					char svalue[4] = { 0, 0, 0, 0 };
					sprintf(svalue, "%u", value & 0xff);
					if (count < sizeof(svalue)) {
						if (debug)
							printk(DCRA": buffer too small\n");
						retval = -EBADF;
					} else {
						res = copy_to_user(buf, svalue, sizeof(svalue));
						if (res) {
							if(debug)
								printk(DCRA": copy_to_user failed\n");
							retval = -EIO;
						} else	{
							retval = strlen(svalue) + 1;
							*f_pos += retval;	// advance file offset pointer to stop read.
						}
					}
				} else {
					if (debug)
						printk(DCRA": chan %d reg %d get_reg %d failed\n", channo, regno, res);
					retval = -EIO;
				}
			} else {
                mutex_unlock(&access_mutex);
				if (debug)
					printk(DCRA": chan %d reg %d no get_reg \n", channo, regno);
				retval = -EIO;
			}
			goto dcra_read_exit;
		} else if (0 == strcmp(level2, DCRA_PROC_EXTREG)) {

            if(regno < 0 || regno >= pchan->num_ext_regs){
                mutex_unlock(&access_mutex);
                if (debug)
                    printk(DCRA": Invalid ext regno %d failed\n", regno);
                retval = -EBADF;
                goto dcra_read_exit;
            }

			if (pchan->reg_ops->get_ext_reg) {
				uint16_t value;
				int res = pchan->reg_ops->get_ext_reg(channo, regno, &value);
                mutex_unlock(&access_mutex);
				if (0 == res) {
					char svalue[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
					sprintf(svalue, "%u", value & 0xffff);
					if (count < sizeof(svalue)) {
						if (debug)
							printk(DCRA": buffer too small\n");
						retval = -EBADF;
					} else {
						res = copy_to_user(buf, svalue, sizeof(svalue));
						if (res) {
							if(debug)
								printk(DCRA": copy_to_user failed\n");
							retval = -EIO;
						} else {
							retval = strlen(svalue) + 1;
							*f_pos += retval;	// advance file offset pointer to stop read.
						}
					}
				} else {
					if (debug)
						printk(DCRA": chan %d reg %d get_ext_reg %d failed\n", channo, regno, res);
					retval = -EIO;
				}
			} else {
                mutex_unlock(&access_mutex);
				if (debug)
					printk(DCRA": chan %d reg %d no get_ext_reg \n", channo, regno);
				retval = -EIO;
			}
			goto dcra_read_exit;
		} else if (0 == strcmp(level2, DCRA_PROC_MODEL)) {
			if (pchan->model) {
				int len = strlen(pchan->model) + 1;
				if (count < len) {
                    mutex_unlock(&access_mutex);
					if (debug)
						printk(DCRA": buffer too small\n");
					retval = -EBADF;
				} else {
					res = copy_to_user(buf, pchan->model, len);
                    mutex_unlock(&access_mutex);
					if (res) {
						if (debug)
							printk(DCRA": copy_to_user failed\n");
						retval = -EIO;
					} else {
						retval = len;
						*f_pos += retval;	// advance file offset pointer to stop read.
					}
				}
			} else {
                mutex_unlock(&access_mutex);
				if (debug)
					printk(DCRA": chan %d no model \n", channo);
				retval = -EIO;
			}
			goto dcra_read_exit;
		} else {
            mutex_unlock(&access_mutex);
			if (debug)
				printk(DCRA": unknown node %s\n", level2);
			retval = -EIO;
		}
	}

dcra_read_exit:	
	kfree(name_buf);
	return retval;
}

static ssize_t dcra_write(struct file *file, const char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t retval = 0;
	char *name_buf = NULL;
	char *pname = NULL;
	char *level1, *level2, *level3;
	int res;
	
	/* get file full path name */
	name_buf = kmalloc(PATH_MAX + 1, GFP_KERNEL);
	pname = d_path(&file->f_path, name_buf, PATH_MAX);
	if (debug)
		printk(DCRA": write file %s\n", pname);

	/* do not support write to middle of file */
	if (0 != *f_pos) {
		if (debug)
			printk(DCRA": offset must be zero %s\n", pname);
		retval = 0;
		goto dcra_write_exit;
	}

	/* split path to seperate string */
	res = dcra_split_path(pname, &level1, &level2, &level3);
	if ( res <= 0 ) {
		if(debug)
			printk(DCRA": bad path %s\n", pname);
		retval =  -EBADF;
		goto dcra_write_exit;
	}
	
	/* level1 should be version or channel no */
    if (0 == strcmp(level1, DCRA_PROC_VERSION)) {
        if (debug)
            printk(DCRA": failed version read only\n");
        retval = -EIO;
        goto dcra_write_exit;
	} else { /* level1 is channo */
        unsigned int channo = 0; 
		unsigned int  regno = 0;
		struct dcra_channel* pchan;
		if(kstrtouint(level1, 10, &channo)){
			if (debug)
				printk(DCRA": failed parsing channo %s failed\n", name_buf);
			retval = -EBADF;
			goto dcra_write_exit;
        }
		
		if ((channo > maxchan) || (channo <= 0)) {
			if (debug)
				printk(DCRA": invalid channo %s\n", name_buf);
			retval = -EBADF;
			goto dcra_write_exit;
		} 

        if(mutex_lock_interruptible(&access_mutex))
            return -ERESTARTSYS;
		pchan = &channels[channo - 1];
		if (!pchan->reg_ops) {
            mutex_unlock(&access_mutex);
			if (debug)
				printk(DCRA": file operate undefined \n");
			retval = -EBADF;
			goto dcra_write_exit;
		}
		
		/* level 2 should be reg, extreg, or model */
		if ((0 == strcmp(level2, DCRA_PROC_REG)) || (0 == strcmp(level2, DCRA_PROC_EXTREG))) {
			if (NULL == level3) {
                mutex_unlock(&access_mutex);
				if (debug)
					printk(DCRA": no register number\n");
				retval = -EBADF;
				goto dcra_write_exit;
			} else{
                if(kstrtouint(level3, 10, &regno)){
                    mutex_unlock(&access_mutex);
                    if (debug)
                        printk(DCRA": failed parsing regno %s failed\n", name_buf);
                    retval = -EBADF;
                    goto dcra_write_exit;
                }
            }
		}
		
		if (0 == strcmp(level2, DCRA_PROC_REG)) {

            if(regno < 0 || regno >= pchan->num_regs){
                mutex_unlock(&access_mutex);
                if (debug)
                    printk(DCRA": Invalid regno %d failed\n", regno);
                retval = -EBADF;
                goto dcra_write_exit;
            }

            if (pchan->reg_ops->set_reg) {
                unsigned int value;
                char svalue[6] = { 0, 0, 0, 0, 0, 0 };

                if (count > sizeof(svalue) - 1) {
                    mutex_unlock(&access_mutex);
                    if (debug)
                        printk(DCRA": buffer too small\n");
                    retval = -EBADF;
                } else {
                    res = copy_from_user(svalue, buf, count);
                    if (res) {
                        mutex_unlock(&access_mutex);
                        if(debug)
                            printk(DCRA": copy_from_user failed\n");
                        retval = -EIO;
                    } else	{
                        retval = count;
                        *f_pos += retval;	// advance file offset pointer to stop write.
                    }
                }
                if(kstrtouint(svalue, 0, &value)){
                    mutex_unlock(&access_mutex);
                    if (debug)
                        printk(DCRA": failed parsing value %s failed\n",svalue);
                    retval = -EBADF;
                    goto dcra_write_exit;
                }
                value &= 0xff;
                if(pchan->reg_ops->set_reg(channo, regno, value)){
                    mutex_unlock(&access_mutex);
                    if (debug)
                        printk(DCRA": chan %d reg %d set_reg %d failed\n", channo, regno, value );
                    retval = -EIO;
                }
                mutex_unlock(&access_mutex);
            } else {
                mutex_unlock(&access_mutex);
				if (debug)
					printk(DCRA": chan %d reg %d no set_reg \n", channo, regno);
				retval = -EIO;
			}
			goto dcra_write_exit;
		} else if (0 == strcmp(level2, DCRA_PROC_EXTREG)) {

            if(regno < 0 || regno >= pchan->num_ext_regs){
                mutex_unlock(&access_mutex);
                if (debug)
                    printk(DCRA": Invalid ext regno %d failed\n", regno);
                retval = -EBADF;
                goto dcra_write_exit;
            }

			if (pchan->reg_ops->set_ext_reg) {
                unsigned int value;
                char svalue[8] = { 0, 0, 0, 0, 0, 0 ,0, 0 }; 

                if (count > sizeof(svalue) - 1) {
                    mutex_unlock(&access_mutex);
                    if (debug)
                        printk(DCRA": buffer too small\n");
                    retval = -EBADF;
                } else {
                    res = copy_from_user(svalue, buf, count);
                    if (res) {
                        mutex_unlock(&access_mutex);
                        if(debug)
                            printk(DCRA": copy_from_user failed\n");
                        retval = -EIO;
                    } else	{
                        retval = count;
                        *f_pos += retval;	// advance file offset pointer to stop write.
                    }
                }
                if(kstrtouint(svalue, 0, &value)){
                    mutex_unlock(&access_mutex);
                    if (debug)
                        printk(DCRA": failed parsing value %s failed\n",svalue);
                    retval = -EBADF;
                    goto dcra_write_exit;
                }
                value &= 0xffff;
                if(pchan->reg_ops->set_ext_reg(channo, regno, value)){
                    mutex_unlock(&access_mutex);
                    if (debug)
                        printk(DCRA": chan %d reg %d set_ext_reg %d failed\n", channo, regno, value );
                    retval = -EIO;
                }
                mutex_unlock(&access_mutex);

            } else {
                mutex_unlock(&access_mutex);
				if (debug)
					printk(DCRA": chan %d reg %d no set_ext_reg \n", channo, regno);
				retval = -EIO;
			}
			goto dcra_write_exit;
        } else if (0 == strcmp(level2, DCRA_PROC_MODEL)) {
            mutex_unlock(&access_mutex);
            if (debug)
                printk(DCRA": failed channel %d model read only\n", channo);
			retval = -EIO;
            goto dcra_write_exit;
        } else {
            mutex_unlock(&access_mutex);
			if (debug)
				printk(DCRA": unknown node %s\n", level2);
			retval = -EIO;
		}
	}


dcra_write_exit:	
	kfree(name_buf);
	return retval;

}


/* use this structure for all file operate */
static struct file_operations dcra_fops = {
	.owner = THIS_MODULE,
	.read = dcra_read,
	.write = dcra_write,
};

static int __init dcra_init(void)
{
	int retval = 0;
	
	if (maxchan <= 0) {
		printk(DCRA": invalid param maxchan %d\n", maxchan);
		return -EINVAL;
	}
	
	dcra_proc_root = proc_mkdir(DCRA_PROC_ROOT, NULL);
	if (NULL == dcra_proc_root) {
		printk(DCRA": failed create proc/%s\n", DCRA_PROC_ROOT);
		retval = -ENOENT;
		goto err_exit;
	}
	
	dcra_proc_version = proc_create(DCRA_PROC_VERSION, 0444, dcra_proc_root, &dcra_fops);
	if (NULL == dcra_proc_version) {
		printk(DCRA":failed creat /proc/%s/%s\n failed", DCRA_PROC_ROOT, DCRA_PROC_VERSION);
		retval = -ENOENT;
		goto err_exit;
	}
	
	channels = kmalloc(sizeof(struct dcra_channel)*maxchan, GFP_KERNEL);
	if (NULL == channels) {
		printk(DCRA": no enough memory %d\n", __LINE__);
		retval =  -ENOMEM;
		goto err_exit;
	}
	memset(channels, 0, sizeof(struct dcra_channel)*maxchan);
	
	printk(DCRA": version %s loaded\n", DCRA_VER);
	return 0;
	
err_exit:
	if (dcra_proc_version)
		remove_proc_entry(DCRA_PROC_VERSION, dcra_proc_root);
	if (dcra_proc_root)
		remove_proc_entry(DCRA_PROC_ROOT, NULL);
	if (channels)
		kfree(channels);
	
	return retval;
}

static void __exit dcra_exit(void)
{
#if UNSUPPORT_RPST
    int channo = 0;
    struct proc_dir_entry*	curr_entry = NULL; /* point to channel entry */
#endif
	if (dcra_proc_root){

#if UNSUPPORT_RPST
        /* remove /proc/dcra<channo> */
        curr_entry = dcra_proc_root->subdir;
        while(NULL != curr_entry ) {
            if(kstrtouint(curr_entry->name, 10, &channo)){
                curr_entry = curr_entry->next;
                continue;
            }
            curr_entry = curr_entry->next;
            dcra_chan_destroy(channo);
        }

        /* remove /proc/dcra/version and /proc/dcra */
        if (dcra_proc_version)
            remove_proc_entry(DCRA_PROC_VERSION, dcra_proc_root);

        remove_proc_entry(DCRA_PROC_ROOT, NULL);
#else
        remove_proc_subtree(DCRA_PROC_ROOT, NULL);
#endif
    
    }

	if (channels)
		kfree(channels);
	
    printk(DCRA": removed\n");
}


/* channo is dahhi channel number + 1, start from 1 not 0(the same as /dev/dahdi/<channo>) */
static int dcra_chan_create(unsigned int channo, struct dcra_channel *chan)
{
    struct proc_dir_entry*	chan_entry = NULL;
    struct proc_dir_entry*	reg_root = NULL;
    struct proc_dir_entry*	extreg_root = NULL;
    struct proc_dir_entry*	model_root = NULL;
    struct proc_dir_entry*	file_entry = NULL;
    char no[8]= { 0, 0, 0, 0, 0, 0, 0, 0 };  
    int num = 0;

#if UNSUPPORT_RPST
     /*
      *When invoking proc_mkdir()/proc_create(), kernel use structure proc_dir_entry's 
      *pointer parent,next and subdir to create a directory tree automatically,
      *thus we can use this 3 pointers to remove the tree recursively;
      */
#endif 

    /* create /proc/dcra/<channo> */
    snprintf(no, sizeof(no), "%d", channo);
    chan_entry  = proc_mkdir(no, dcra_proc_root);
    if (NULL == chan_entry ) {
        if (debug)
            printk(DCRA": failed create /proc/%s/%d failed\n", DCRA_PROC_ROOT, channo);
        return -1;
    }

    /* create /proc/dcra/<channo>/reg */
    reg_root = proc_mkdir(DCRA_PROC_REG,chan_entry );
    if ((NULL == reg_root) && debug ) {
        printk(DCRA": failed create /proc/%s/%d/%s failed\n", DCRA_PROC_ROOT, channo, DCRA_PROC_REG);
    }else {

        /* create /proc/dcra/<channo>/reg/<num> */
        for(num = 0; num < chan->num_regs; num++) {
            snprintf(no, sizeof(no), "%d", num);
            file_entry = proc_create(no, 0644, reg_root, &dcra_fops);
            if ((NULL == file_entry) && debug) {
                printk(DCRA":failed creat /proc/%s/%d/%s/%d\n failed", DCRA_PROC_ROOT,channo, DCRA_PROC_REG, num);
            }
        }
    }

    if((0 == strcmp(DCRA_TYPE_SI3210, chan->model)) || \
       (0 == strcmp(DCRA_TYPE_SI3215, chan->model))){
        /* create /proc/dcra/<channo>/extreg */
        extreg_root = proc_mkdir(DCRA_PROC_EXTREG,chan_entry );
        if ((NULL == extreg_root) && debug ) {
            printk(DCRA": failed create /proc/%s/%d/%s failed\n", DCRA_PROC_ROOT, channo,DCRA_PROC_EXTREG);
        }else {
            /* create /proc/dcra/<channo>/extreg/<num> */
            for(num = 0; num < chan->num_ext_regs; num++) {
                snprintf(no,  sizeof(no), "%d", num);
                file_entry= proc_create(no, 0644, extreg_root, &dcra_fops);
                if ((NULL == file_entry) && debug) {
                    printk(DCRA":failed creat /proc/%s/%d/%s/%d\n failed", DCRA_PROC_ROOT,channo, DCRA_PROC_EXTREG, num);
                }
            }
        }

    }

    /* create /proc/dcra/<channo>/model */
    model_root = proc_create(DCRA_PROC_MODEL, 0444, chan_entry , &dcra_fops);
    if((NULL == model_root)  && debug ) {
        printk(DCRA": failed create /proc/%s/%d/%s failed\n", DCRA_PROC_ROOT, channo,DCRA_PROC_MODEL);
    }

    channels[channo -1].model = chan->model;
    channels[channo -1].num_regs = chan->num_regs;
    channels[channo -1].num_ext_regs = chan->num_ext_regs;
    channels[channo -1].reg_ops = chan->reg_ops;

    return 0;
}

/* channo is dahhi channel number + 1, start from 1 not 0(the same as /dev/dahdi/<channo>) */
static int dcra_chan_destroy(int channo)
{
    char no[8] = {0, 0, 0, 0, 0, 0, 0, 0};
#if UNSUPPORT_RPST
    int i;
    struct proc_dir_entry*	curr_entry = NULL; 
    struct proc_dir_entry*	prev_entry = NULL;
    struct proc_dir_entry*	temp_entry = NULL;
#endif

    
	if (channo <= 0 || channo > maxchan)
        return 0;
    if(NULL == dcra_proc_root)
        return 0;


    snprintf(no, sizeof(no), "%d", channo);

#if UNSUPPORT_RPST
    if(NULL == dcra_proc_root->subdir)
        return 0;

    curr_entry = dcra_proc_root->subdir; 
    prev_entry = dcra_proc_root->subdir;

    /*
     *find  <channo> proc entry in dcra_proc_root subdir list and remove it
     *Note: When invoking remove_proc_entry(fname, pentry), the entry that fname belongs to must in pentry->subdir list.
     *      Otherwise you will get a warning, e.g.
     *      {prev_entry->next = curr_entry->next;  remove_proc_entry(curr_entry->name, pentry);}
     *      will get a warning because curr_entry is not in pentry->subdir list when removing
     */
    while(curr_entry) {
	    if(!strcmp(curr_entry->name, no)) {
		    /* Firstly  remove channel's subdir */
		    while(NULL != curr_entry->subdir){
			    temp_entry = curr_entry->subdir->next;

                /* delete the member at head of curr_entry->subdir list */
			    if(!strcmp(curr_entry->subdir->name, DCRA_PROC_REG)) { 
				    /* remove  /proc/dcra/<channo>/reg/<num_regs> */
				    for(i = 0; i <channels[channo - 1].num_regs; i ++) {
					    memset(no, 0, sizeof(no));
					    snprintf(no, sizeof(no), "%d", i);
					    remove_proc_entry(no, curr_entry->subdir);
				    }
				    /* remove  /proc/dcra/<channo>/reg */
				    remove_proc_entry(DCRA_PROC_REG, curr_entry);

			    } else if(!strcmp(curr_entry->subdir->name, DCRA_PROC_EXTREG)) { 
				    /* remove  /proc/dcra/<channo>/extreg/<num_ext_regs> */
				    for(i = 0; i <channels[channo - 1].num_ext_regs; i ++) {
					    memset(no, 0, sizeof(no));
					    snprintf(no, sizeof(no), "%d", i);
					    remove_proc_entry(no,curr_entry->subdir);
				    }
				    /* remove  /proc/dcra/<channo>/extreg */
				    remove_proc_entry(DCRA_PROC_EXTREG, curr_entry);

			    } else if(!strcmp(curr_entry->subdir->name, DCRA_PROC_MODEL)) { 
				    /* remove  /proc/dcra/<channo>/model */
				    remove_proc_entry(DCRA_PROC_MODEL, curr_entry);
			    } else {
                     if(debug)
                         printk(DCRA": WARNING channel %s %s should be removed, but not\n", \
                                curr_entry->name ,curr_entry->subdir->name);
                 }

                /* curr_entry->subdir can't be modified before removing */ 
                curr_entry->subdir = temp_entry;
		    }

		    /* secondly remove  channel entry */
            temp_entry = curr_entry->next;
            if(curr_entry == dcra_proc_root->subdir) { //Remove the first member at dcra_proc_root subdir list 
                remove_proc_entry(curr_entry->name, dcra_proc_root);
                dcra_proc_root->subdir = temp_entry;
            } else {
                remove_proc_entry(curr_entry->name, dcra_proc_root);
                prev_entry->next = temp_entry;;
            }
            goto out;
	    }
	    prev_entry = curr_entry;
	    curr_entry = curr_entry->next;
    }
out:
#else
        remove_proc_subtree(no, dcra_proc_root);
#endif
	channels[channo - 1].model = NULL;
	channels[channo - 1].num_regs = 0;
	channels[channo - 1].num_ext_regs = 0;
	channels[channo - 1].reg_ops = NULL;

    return 0;
}

int dcra_register(unsigned int channo, struct dcra_channel *chan)
{
	if (channo<0 || channo >= maxchan) {
		if (debug)
			printk(DCRA": invalid channel number %d\n", channo);
		return -1;
	}

    if(mutex_lock_interruptible(&access_mutex))
        return -ERESTARTSYS;
	if (channels[channo].reg_ops) {
        mutex_unlock(&access_mutex);
		if(debug)
			printk(DCRA": channel %d already occupied \n", channo);
		return -2;
	}
    
    if(dcra_chan_create(channo + 1, chan)) {
        mutex_unlock(&access_mutex);
        if(debug)
            printk(DCRA": failed create channel %d proc fs \n", channo);
        return -3;
    }

    mutex_unlock(&access_mutex);

	if (debug)
		printk(DCRA": channel %d registered\n", channo);
	return 0;
}

int dcra_unregister(unsigned int channo)
{
	if (channo < 0 || channo >= maxchan) {
		if (debug)
			printk(DCRA": invalid channel number %d\n", channo);
		return -1;
	}
    if(mutex_lock_interruptible(&access_mutex))
        return -ERESTARTSYS;

    dcra_chan_destroy(channo + 1);

    mutex_unlock(&access_mutex);
	if (debug)
		printk(DCRA": channel %d unregistered\n", channo);
	return 0;
}


EXPORT_SYMBOL(dcra_register);
EXPORT_SYMBOL(dcra_unregister);
EXPORT_SYMBOL(dcra_debug_mask);


module_param(debug, int , 0600);
module_param(maxchan, int, 0600);
module_param(dcra_debug_mask, int, 0600);

module_init(dcra_init);
module_exit(dcra_exit);


MODULE_DESCRIPTION("Access Dahdi Channel Registers through procfs");
MODULE_ALIAS("opvx_dcra");
MODULE_LICENSE("GPL v2");

