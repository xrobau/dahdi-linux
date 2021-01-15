/*
 *
 * $Id: base.h 360 2011-04-06 06:11:45Z yangshugang $
 
 *
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef _UA32XX_H_
#define _UA32XX_H_

#define UA32XX_VERSION "0.0.1"

#define UA32XX_NAME	"ua32xx"

#define VERSION_CODE(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#define DAHDI_VERSION_CODE 	VERSION_CODE(2,6,2)

#define TDM_SLOT_CAP	32		//max 32 tdm time slots(fxs/fxo module) per usb device.
#ifdef FXX_EXT
#define TDM_SLOT_NUM  128
#else
#define TDM_SLOT_NUM  8     //really used tdm time slots
#endif

#define UA_MAX_IFACES 127   //max 127 usb devices per system.

#define NUM_CAL_REGS 12
#define NUM_FXO_REGS 60

#define MOD_TYPE_FXS	0
#define MOD_TYPE_FXO	1

#define DAISY_CARDS_4  4
#define DAISY_CARDS_2  2

#define NUM_CARDS     TDM_SLOT_NUM

#ifdef FXX_EXT
#define CARD_FLAGS_LEN				4
#else
#define CARD_FLAGS_LEN				1
#endif

#define DEV_UC320_CHANNELS	2
#define DEV_UC350_CHANNELS	5
#define DEV_A1008_CHANNELS	8
#define DEV_UC580_CHANNELS	8
#define DEV_UC581_CHANNELS	8
#define DEV_UC540_CHANNELS	4

#define CHAN_LED_BLACK          0
#define CHAN_LED_LITHT          1
#define CHAN_LED_FAST_BLINK     2
#define CHAN_LED_SLOW_BLINK     3
#define CHAN_LED_WARNING        4

#define FLAG_3215	(1 << 0)
#define MAX_ALARMS 10
#define NEON_MWI_RNGY_PULSEWIDTH	0x3e8	/*=> period of 250 mS */

/* Proslic Linefeed options for register 64 - Linefeed Control */
#define SLIC_LF_OPEN				0x0
#define SLIC_LF_ACTIVE_FWD	0x1
#define SLIC_LF_OHTRAN_FWD	0x2 /* Forward On Hook Transfer */
#define SLIC_LF_TIP_OPEN		0x3
#define SLIC_LF_RINGING			0x4
#define SLIC_LF_ACTIVE_REV	0x5
#define SLIC_LF_OHTRAN_REV	0x6 /* Reverse On Hook Transfer */
#define SLIC_LF_RING_OPEN		0x7

#define SLIC_LF_SETMASK			0x7
#define SLIC_LF_OPPENDING 	0x10
/* Mask used to reverse the linefeed mode between forward and
 * reverse polarity. */
#define SLIC_LF_REVMASK 	0x4


#define DEFAULT_DAA_CHECK_INTERVAL	4		/* call voicedaa_check_hook every 4 ms */

/* For ring on detect, if in DEFAULT_RING_DEBOUNCE period,
   ring signal detected >= DEFAULT_RINGON_COUNT, status chage to RINGON. */
#define DEFAULT_RINGON_COUNT		4

/* For ring off detect, if in DEFAULT_RING_DEBOUNCE period,
   ring signal detected <= DEFAULT_RINGOFF_COUNT, status chage to RINGOFF. */
#define DEFAULT_RINGOFF_COUNT		0		/* MiaoLin, count for ring off detect*/

#define DEFAULT_POLARITY_DEBOUNCE 	64		

/* the constants below control the 'debounce' periods enforced by the
   check_hook routines; these routines are called once every 4 interrupts
   (the interrupt cycles around the four modules), so the periods are
   specified in _4 millisecond_ increments
*/
#define DEFAULT_RING_DEBOUNCE	64	
#define DEFAULT_BATT_DEBOUNCE	4		/* Battery debounce (64 ms) */
#define DEFAULT_BATT_THRESH	3		/* Anything under this is "no battery" */

enum cid_hook_state {
	CID_STATE_IDLE = 0,
	CID_STATE_RING_ON,
	CID_STATE_RING_OFF,
	CID_STATE_WAIT_RING_FINISH
};

/* flags for init/deinit */
typedef enum {
	UA32XX_INITF_PKTLIST			,	/* io pkt operation list alloced */
	UA32XX_INITF_ROPLIST    , /*read operations readback list alloced*/
	UA32XX_INITF_RTOLIST    , /*regop timeout list alloced*/
	UA32XX_INITF_OPROTO			,	/* oproto alloced */
	UA32XX_INITF_CHANWQ			,	/* channels workqueue alloced */
	UA32XX_INITF_IOWQ			,	/* io workqueue alloced */
	UA32XX_INITF_IFACES			,	/* already add this interface to the global array ifaces*/
	UA32XX_INITF_USBINTFDATA	,	/* usb_set_intfdata called */
	UA32XX_INITF_USBGETDEV		,	/* usb_get_dev called */
	UA32XX_INITF_DDEVCREATE		,
	UA32XX_INITF_DAHDISOFT		,
} ua32xx_initflag_t;

/* flags for activity */
typedef enum {
	UA32XX_RUNF_CHANWQ		,	/* channels check workqueue running */
	UA32XX_RUNF_IOWQ			,	/* IO workqueue running */
	UA32XX_RUNF_TASKLET		,	/* tdm tasklet running */
} ua32xx_runflag_t;

struct calregs {
	unsigned char vals[NUM_CAL_REGS];
};

enum proslic_power_warn {
	PROSLIC_POWER_UNKNOWN = 0,
	PROSLIC_POWER_ON,
	PROSLIC_POWER_WARNED,
};

enum battery_state {
	BATTERY_UNKNOWN = 0,
	BATTERY_PRESENT,
	BATTERY_LOST,
};

#define BLK_WK_COUNT	NUM_CARDS*4
#define WKTYPE_RING_GEN_MODE 1
#define WKTYPE_FXS_HOOKSIG   2
#define WKTYPE_INIT_PROSLIC  3

struct ua32xx_blk_work {
	struct work_struct work;
	struct ua32xx* ua;
	int card;
	int wktype;
	int used;
	union{
		struct rgm{
			int mode;
		} p_rgm;
		struct hsig{
			enum dahdi_txsig txsig;
			int dahdi_txsig;
		} p_hsig;
		struct fxs_init{
			int fast;
			int manual;
			int sane;
		} p_init;
	} data;
};

struct ua32xx_d_work {
	struct delayed_work work;
	struct ua32xx* ua;
	int card;
};

struct _regwr {
	unsigned char reg;
	unsigned char value;
	int flag;					/*setting 1 means having been writen*/
};

struct ua32xx {
	/* ====================================== usb interface ========================================*/
	struct oproto   proto;						/*  usb protocol codec */

	/* ====================================== hardware/firmware ======================================*/
  char *hw_name;							/* name of this hardware. i.e variety name */
	struct ua32xx_fw_ver {						/* firmware version */
		int major;	
		int minor;
		int bugfix;
		int build;
	} fw_ver;		
	
	/* ====================================== DAHDI ======================================*/
	int max_channel;							/* max channel of fxs/fxo. */
	int hw_channels;
	int module_daisy;
	int slot_id;
  struct dahdi_span span;
#if DAHDI_VERSION_CODE >= VERSION_CODE(2,6,0)
  struct dahdi_device *ddev;
#endif
  unsigned int flags[TDM_SLOT_NUM];
    
	/* ====================================== Kernel ======================================*/
	int usecount;
	int ifaces_index;				/* index in struct ua32xx global array */
	unsigned int cardflag[CARD_FLAGS_LEN];		/* Bit-map of present cards */
	enum proslic_power_warn proslic_power;
	unsigned int tdm_stat;
	
	union {
		struct fxo {
			int wasringing;
			int lastrdtx;
			int fastringoffhooktimer;	/* timer to send ringoffhook event faster */
			int ringoffhooksent;		/* ringoffhook already sent for this ring? */
			int ringdebounce;
			int offhook;
			unsigned int battdebounce;
			unsigned int battalarm;
			enum battery_state battery;
      int lastpol;
      int polarity;
      int polaritydebounce;
      struct _regwr regwr;
      int callout;                  /*if not 0, fxo call fxs */
      int polaritycountwhenoffhook; /* polarity counter when offhook, use for two-way charge */
		} fxo;
		struct fxs {
			int oldrxhook;
			int debouncehook;
			int lastrxhook;
			int debounce;
			int ohttimer;
			int idletxhookstate;		/* IDLE changing hook state */
			int lasttxhook;
			int palarms;
			int reversepolarity;		/* Reverse Line */
			int mwisendtype;
			struct dahdi_vmwi_info vmwisetting;
			int vmwi_active_messages;
			u32 vmwi_lrev:1; /*MWI Line Reversal*/
			u32 vmwi_hvdc:1; /*MWI High Voltage DC Idle line*/
			u32 vmwi_hvac:1; /*MWI Neon High Voltage AC Idle line*/
			u32 neonringing:1; /*Ring Generator is set for NEON*/
			struct calregs calregs;
		} fxs;
	} mod[NUM_CARDS];
	
	struct proc_dir_entry* chan_entry[NUM_CARDS];
	int modtype[NUM_CARDS];
	unsigned char reg0shadow[NUM_CARDS];
	unsigned char reg1shadow[NUM_CARDS];
	unsigned char reg8[NUM_CARDS];			//for fxs modules
	
	struct dahdi_chan _chans[NUM_CARDS];
	struct dahdi_chan *chans[NUM_CARDS];
    /* cidbeforering, to deal with irregular CID */
	char *cid_history_buf[NUM_CARDS];		/* used to support global cid */
	int  cid_history_ptr[NUM_CARDS];
	int  cid_history_clone_cnt[NUM_CARDS];
	enum cid_hook_state cid_state[NUM_CARDS];
	int  cid_ring_on_time[NUM_CARDS];
    /* cidbeforering, to deal with irregular CID end */
	
	struct tasklet_struct tdm_tasklet;
	
	struct workqueue_struct *chan_wq[NUM_CARDS]; /* workqueue for channels */
	unsigned int chan_chk_cnt[NUM_CARDS];
	int running_count;
	atomic_t chan_block_cnt[NUM_CARDS];
	
	struct workqueue_struct *io_wq;		/* io proc workqueue */
	struct oproto_packet* iowq_recvpkt; 
	unsigned long iowq_proc_cnt;
	unsigned long io_err_point ;
	unsigned int io_err_cnt ;
	
	struct ua32xx_blk_work workpool[BLK_WK_COUNT];
	spinlock_t blkw_lock;
	
	wait_queue_head_t io_waitq[NUM_CARDS];					/* io operation wait queue */
	int wkup_cond[NUM_CARDS];
	
	op_pkt_list_t*  pkt_list;	/*io operation queue*/
	spinlock_t list_lock;
	
	regop_list_t *rdbuf_list; /*io read operation buffer list*/
	spinlock_t rd_lock;
	
	regop_list_t *rd_timeout_list; /* timiout list, used to clear timeout regops of rdbuf_list */
	spinlock_t rd_timeout_lock;
	
	/* ====================================== user data ===================================*/
	struct oproto_OP_REPORT report; /* device running status report */
	unsigned long urbrxcount;
	unsigned long urbtxcount;
	unsigned long tdm_proc_cnt;
	unsigned long tdm_err_point ;
	unsigned int tdm_err_cnt ;
	unsigned long init_flags;			/* control init/deinit, such as kmalloc/kfree */
	unsigned long run_flags;			/* control activity , such as workqueue. */
	volatile int dead;						/* set to 1 before exit, and wait for all activity exit*/
	int init_ok;		
};

#endif //_UA32XX_H_

