
#ifndef __DCRA_COMM_H
#define __DCRA_COMM_H
#include <dahdi/kernel.h>


#define DCRA_DEBUG
#ifdef DCRA_DEBUG

extern unsigned int dcra_debug_mask;

#ifndef BIT /* added in 2.6.24 */
#define BIT(i)      (1UL << (i))
#endif
#define DCRA_DMSG_TRC      BIT(0)
#define DCRA_DMSG_DEB      BIT(1)
#define DCRA_DMSG_ERR      BIT(2)
#define DCRA_DMSG_PREFIX "DCRA: "
#define DCRA_DMSG(bits, fmt, arg...)   \
    ((void)(( dcra_debug_mask & (DCRA_DMSG_ ## bits)) && printk(KERN_DEBUG \
             DCRA_DMSG_PREFIX #bits " [%s]  " fmt, __func__, ##arg)))
#else
#define DCRA_DMSG(bits, fmt, arg...)
#endif


/*================miaolin============================= */
/* This project provide an API to access Dahdi Channel Registers
	thus project name is DCRA  */

#define DCRA_TYPE_UNKNOWN	"unknown"	
#define DCRA_TYPE_SI3050	"si3050"
#define DCRA_TYPE_SI3210	"si3210"
#define DCRA_TYPE_SI3215	"si3215"

/*
	procfs structure example:
	/proc/dcra/version		= version of dcra;
	/proc/dcra/1/reg/0		= dahdi channel 1 register 0
	/proc/dcra/1/extreg/0	= dahdi channel 1 extended register 0
	/proc/dcra/1/model		= channel chip modelfrom struct dcra_regops.type
*/

/* this struct is used for register read/write operate, thus name is regops */
struct dcra_regops {
	int (*get_reg)(unsigned int channo, unsigned int reg, uint8_t* value);		/* get register */
	int (*set_reg)(unsigned int channo, unsigned int reg, uint8_t value);		/* set register */
	int (*get_ext_reg)(unsigned int channo, unsigned int reg, uint16_t* value);	/* get extendend register, si321x only */
	int (*set_ext_reg)(unsigned int channo, unsigned int reg, uint16_t value);	/* set extendend register, si321x only */
};

/* dcra channel structure */
struct dcra_channel {
	char* model;			        /* model of hardware, i.e si3050, si3215 or si3210. */
    unsigned int  num_regs;         /* register number */
    unsigned int  num_ext_regs;     /* extendend register number, si321x only */
    struct dcra_regops* reg_ops;    /* channel register operate */
};

// channo must be a dahdi channel number, start from 0, not 1, i.e /dev/dahdi/1 is 0, etc.
int dcra_register(unsigned int channo, struct dcra_channel *chan);
int dcra_unregister(unsigned int channo);

struct dahdi_chan *dahdi_get_chan_from_num(unsigned int channo);
/*================miaolin============================= */

#endif // __DCRA_COMM_H
