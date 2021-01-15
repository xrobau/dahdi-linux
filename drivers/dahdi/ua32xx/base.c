/*
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

/* Rev history
 *
 * Rev 0.10 initial version, from scratch
 *
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/init.h>
#include <asm/io.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/memory.h>
#include <linux/usb.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/limits.h>
#include <linux/dcache.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/time.h>

#ifdef TEST_LOG_INCOME_VOICE
#include <asm/uaccess.h> 	/* get_fs(), set_fs(), KERNEL_DS */
#include <linux/file.h> 	/* fput() */
#endif

#include <dahdi/kernel.h>
#include <dahdi/wctdm_user.h>

#include "proslic.h"
#include "fxo_modes.h"

#include "oproto.h"
#include "oproto_host.h"
#include "ua32xx.h"
		
#ifdef CONFIG_DCRA
#include "../dcra/dcra_comm.h"
#endif


#define PROC_ROOT			"ua32xx"
#define PROC_REPORT		"report"
#define PROC_LEDCFG		"ledcfg"

static struct proc_dir_entry*	ua32xx_proc_root = NULL;
static struct proc_dir_entry*	ua32xx_proc_report = NULL;
static struct proc_dir_entry*	ua32xx_ledcfg_root = NULL;

#define OHT_TIMER		6000					/* How long after RING to retain OHT */

static int loopcurrent = 20;
#define POLARITY_XOR (\
		(reversepolarity != 0) ^ (fxs->reversepolarity != 0) ^\
		(fxs->vmwi_lrev != 0) ^\
		((fxs->vmwisetting.vmwi_type & DAHDI_VMWI_HVAC) != 0))

static int reversepolarity = 0;



static struct ua32xx* ifaces[UA_MAX_IFACES] = { (struct ua32xx*) ((int)-1), };
static int g_ifaces = 0;

// hardware description.
struct ua32xx_desc {
	char*	name;
  int		flags;
	int		max_channel;
	int		ep_num;
	
	int		io_epin_addr;
	int		io_epout_addr;
	int		io_bulk_size;

	int		tdm_epin_addr;
	int		tdm_epout_addr;
	int		tdm_bulk_size;
};

static const struct ua32xx_desc proto_model = {
	.name = "proto",
	.max_channel = TDM_SLOT_CAP,
	.flags = 0,
	.ep_num = 4,

	.io_epin_addr = 1,
	.io_epout_addr = 2,
	.io_bulk_size = 64,

	.tdm_epin_addr = 3,
	.tdm_epout_addr = 4,
	.tdm_bulk_size = DAHDI_CHUNKSIZE*TDM_SLOT_CAP,
};

static const struct ua32xx_desc proto_fxx_ext = {
	.name = "FXX_EXT",
	.max_channel = TDM_SLOT_NUM,
	.flags = 0,
	.ep_num = 4,

	.io_epin_addr = 1,
	.io_epout_addr = 2,
	.io_bulk_size = 64,

	.tdm_epin_addr = 3,
	.tdm_epout_addr = 4,
	.tdm_bulk_size = DAHDI_CHUNKSIZE*TDM_SLOT_NUM,
};

static const struct ua32xx_desc proto_uc320 = {
	.name = "UC320",
	.max_channel = TDM_SLOT_NUM,
	.flags = 0,
	.ep_num = 4,

	.io_epin_addr = 1,
	.io_epout_addr = 2,
	.io_bulk_size = 64,

	.tdm_epin_addr = 3,
	.tdm_epout_addr = 4,
	.tdm_bulk_size = DAHDI_CHUNKSIZE*TDM_SLOT_NUM,
};

static const struct ua32xx_desc proto_uc350 = {
	.name = "UC350",
	.max_channel = TDM_SLOT_NUM,
	.flags = 0,
	.ep_num = 4,

	.io_epin_addr = 1,
	.io_epout_addr = 2,
	.io_bulk_size = 64,

	.tdm_epin_addr = 3,
	.tdm_epout_addr = 4,
	.tdm_bulk_size = DAHDI_CHUNKSIZE*TDM_SLOT_NUM,
};

static const struct ua32xx_desc proto_a1008 = {
	.name = "A1008",
	.max_channel = TDM_SLOT_NUM,
	.flags = 0,
	.ep_num = 4,

	.io_epin_addr = 1,
	.io_epout_addr = 2,
	.io_bulk_size = 64,

	.tdm_epin_addr = 3,
	.tdm_epout_addr = 4,
	.tdm_bulk_size = DAHDI_CHUNKSIZE*TDM_SLOT_NUM,
};

static const struct ua32xx_desc proto_uc580 = {
	.name = "UC580",
	.max_channel = TDM_SLOT_NUM,
	.flags = 0,
	.ep_num = 4,

	.io_epin_addr = 1,
	.io_epout_addr = 2,
	.io_bulk_size = 64,

	.tdm_epin_addr = 3,
	.tdm_epout_addr = 4,
	.tdm_bulk_size = DAHDI_CHUNKSIZE*TDM_SLOT_NUM,
};

static const struct ua32xx_desc proto_uc540 = {
	.name = "UC540",
	.max_channel = TDM_SLOT_NUM,
	.flags = 0,
	.ep_num = 4,

	.io_epin_addr = 1,
	.io_epout_addr = 2,
	.io_bulk_size = 64,

	.tdm_epin_addr = 3,
	.tdm_epout_addr = 4,
	.tdm_bulk_size = DAHDI_CHUNKSIZE*TDM_SLOT_NUM,
};

static const struct ua32xx_desc proto_uc581 = {
	.name = "UC581",
	.max_channel = TDM_SLOT_NUM,
	.flags = 0,
	.ep_num = 4,

	.io_epin_addr = 1,
	.io_epout_addr = 2,
	.io_bulk_size = 64,

	.tdm_epin_addr = 3,
	.tdm_epout_addr = 4,
	.tdm_bulk_size = DAHDI_CHUNKSIZE*TDM_SLOT_NUM,
};


static struct usb_device_id  ua32xx_id_table[] = {
    { USB_DEVICE(0xe4e5, 0xa320), .driver_info = (kernel_ulong_t)&proto_model},
    { USB_DEVICE(0xe4e5, 0xa128), .driver_info = (kernel_ulong_t)&proto_fxx_ext},
    { USB_DEVICE(0xe4e5, 0xa082), .driver_info = (kernel_ulong_t)&proto_uc320},
    { USB_DEVICE(0xe4e5, 0xa085), .driver_info = (kernel_ulong_t)&proto_uc350},
    { USB_DEVICE(0xe4e5, 0xa328), .driver_info = (kernel_ulong_t)&proto_a1008},
    { USB_DEVICE(0xe4e5, 0xa508), .driver_info = (kernel_ulong_t)&proto_uc580},
    { USB_DEVICE(0xe4e5, 0xa504), .driver_info = (kernel_ulong_t)&proto_uc540},
    { USB_DEVICE(0xe4e5, 0xa518), .driver_info = (kernel_ulong_t)&proto_uc581},
    { 0 }	// termination.
};
MODULE_DEVICE_TABLE(usb, ua32xx_id_table);

int acim2tiss[16] = { 0x0, 0x1, 0x4, 0x5, 0x7, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x2, 0x0, 0x3 };

/* indirect_resg */
static alpha  indirect_regs[] =
{
{0,255,"DTMF_ROW_0_PEAK",0x55C2},
{1,255,"DTMF_ROW_1_PEAK",0x51E6},
{2,255,"DTMF_ROW2_PEAK",0x4B85},
{3,255,"DTMF_ROW3_PEAK",0x4937},
{4,255,"DTMF_COL1_PEAK",0x3333},
{5,255,"DTMF_FWD_TWIST",0x0202},
{6,255,"DTMF_RVS_TWIST",0x0202},
{7,255,"DTMF_ROW_RATIO_TRES",0x0198},
{8,255,"DTMF_COL_RATIO_TRES",0x0198},
{9,255,"DTMF_ROW_2ND_ARM",0x0611},
{10,255,"DTMF_COL_2ND_ARM",0x0202},
{11,255,"DTMF_PWR_MIN_TRES",0x00E5},
{12,255,"DTMF_OT_LIM_TRES",0x0A1C},
{13,0,"OSC1_COEF",0x7B30},
{14,1,"OSC1X",0x0063},
{15,2,"OSC1Y",0x0000},
{16,3,"OSC2_COEF",0x7870},
{17,4,"OSC2X",0x007D},
{18,5,"OSC2Y",0x0000},
{19,6,"RING_V_OFF",0x0000},
{20,7,"RING_OSC",0x7EF0},
{21,8,"RING_X",0x0160},
{22,9,"RING_Y",0x0000},
{23,255,"PULSE_ENVEL",0x2000},
{24,255,"PULSE_X",0x2000},
{25,255,"PULSE_Y",0x0000},
//{26,13,"RECV_DIGITAL_GAIN",0x4000},	// playback volume set lower
{26,13,"RECV_DIGITAL_GAIN",0x2000},	// playback volume set lower
{27,14,"XMIT_DIGITAL_GAIN",0x4000},
//{27,14,"XMIT_DIGITAL_GAIN",0x2000},
{28,15,"LOOP_CLOSE_TRES",0x1000},
{29,16,"RING_TRIP_TRES",0x3600},
{30,17,"COMMON_MIN_TRES",0x1000},
{31,18,"COMMON_MAX_TRES",0x0200},
{32,19,"PWR_ALARM_Q1Q2",0x07C0},
{33,20,"PWR_ALARM_Q3Q4",0x2600},
{34,21,"PWR_ALARM_Q5Q6",0x1B80},
{35,22,"LOOP_CLOSURE_FILTER",0x8000},
{36,23,"RING_TRIP_FILTER",0x0320},
{37,24,"TERM_LP_POLE_Q1Q2",0x008C},
{38,25,"TERM_LP_POLE_Q3Q4",0x0100},
{39,26,"TERM_LP_POLE_Q5Q6",0x0010},
{40,27,"CM_BIAS_RINGING",0x0C00},
{41,64,"DCDC_MIN_V",0x0C00},
{42,255,"DCDC_XTRA",0x1000},
{43,66,"LOOP_CLOSE_TRES_LOW",0x1000},
};

/*============================================ module parameters ===========================*/
int debug = 0;
int iodebug = 0 ;
int tdmdebug = 0 ;
int ms_per_chkfxs = 16;		/*must >= 8*/
int ms_per_chkfxo = 16;   /*must >= 4*/
int io_op_intv = 1;
int chan_check_intv = 1;
int dsr_intv = 250;   /* the getting device running status report interval(io_op_intv ms) */
int tdm_urb_num = 16;				/* we use 16 urbs for tdm tx/rx */
int tdm_dahdi_buf_len = 32 ;
int ext_reset_len = 200;			/* reset signal enable time in ms when call ext_reset */
int ext_reset_delay = 300;			/* delay after reset signal disabled in ms when call ext_reset */
int s300_lv = 0; /* 0: high version , 1: low version for S300 device */

/**/
static unsigned int fxovoltage;
static unsigned int battdebounce;
static unsigned int battalarm;
static unsigned int battthresh;
static int ringdebounce = DEFAULT_RING_DEBOUNCE;
int ringoncount = DEFAULT_RINGON_COUNT;
int ringoffcount = DEFAULT_RINGOFF_COUNT;
/* fastringoffhook is used to let FXO port send DAHDI_EVENT_RINGOFFHOOK ealier before
    the actual ring signal stop.
	Asterisk use DAHDI_EVENT_RINGOFFHOOK to start callerid detect,
    But DAHDI_EVENT_RINGOFFHOOK sent by DAHDI driver have about 250ms delay than actual ring signal.
    In some case, CID is start sent only 70ms after ring signal stop. this usually cause asterisk
    can not get start part of the callerid signal.
    fastringoffhook is ms after ring begin timer, if it is not zero, DAHDI will generate
    DAHDI_EVENT_RINGOFFHOOK event after fastringoffhook ms when ring begin detected
    fastringoffhook is a temporary solution, final solution will modify ring detect
    state machine, to shorten the detect period.
    */
int fastringoffhook = 0;
static int twowaychargeflag = 0;

/* during ring, polarity also change, final polarity detect must consider ring signal.*/
int polaritydebounce = DEFAULT_POLARITY_DEBOUNCE; 
/* >0 : freeze polarity detect when ringing. when fxo->wasring == 1 */

/*************  Handling irregular CID  ***************/
/* 'cidbeforering' is master switch whether handling irregular CID, only when it is true others parameters effect,
 * and if is regulare CID it must be 0*/
static int cidbeforering = 0;

/* cidbuflen is the lengh of data(including CID and other information, in msec)
 *     before 1st ring is detected by driver */
static int cidbuflen = 3000;

/* During ringing debounce, the ring signal is copied into cid_history_buf[],
 * So we should exclude it by subtractring cutcidbufheadlen ,
 * if not subtractring cutcidbufheadlen , the signalls during debouncing is copied 
 * into the space between 1st and 2nd ring, thus result in asterisk can't get CID*/
static int cutcidbufheadlen = (DEFAULT_RING_DEBOUNCE * 2);

/* Only when the previous rings has ends at least  'cidtimeout' ms,
 * we consider a ringing is the 1st ring. */
static int cidtimeout = 6*1000;	 /* in msec, default 6000 */

/*
 * time delay in ms to send polarity after rise off  of the 1st ring.
 *If fixedtimepolarity=-1,send the 1st ring signal 'DAHDI_RXSIG_RING' to dahdi,
 *otherwise not send and replace it with a polarity signal.
 *For FSK CID,  fixedtimepolarity must be -1.
 *For DTMF CID, Sometimes the DTMF CID is sent just after first
 *ring off, and the system do not have enough time to start detect 1st dtmf. so
 *If fixedtimepolarity= 0 means send polarity at the end of 1st ring.
 *If fixedtimepolarity= x (x > 0) means send ploarity after x ms of 1st ring begin.
 */
static int fixedtimepolarity=-1; 
/************* Handling irregular CID end ***************/

//times 4, because must be a multiple of 4ms: 
static int dialdebounce = 8 * 8;
static int fwringdetect = 0;
static int robust = 0;
static int timingonly = 0;
static int lowpower = 0;
static int boostringer = 0;
static int fastringer = 0;
static int _opermode = 0;
static char *opermode = "FCC";
static int fxshonormode = 0;
static int alawoverride = 0;
static int fastpickup = 0;
static int fxotxgain = 0;
static int fxorxgain = 0;
static int fxstxgain = 0;
static int fxsrxgain = 0;

int fxofullscale = 0;   /* fxo full scale tx/rx, register 30, acim */


#ifdef CONFIG_DCRA
static struct dcra_channel ua32xx_dcra_chan;
static struct dcra_regops ua32xx_dcra_regops;
#endif

struct ua32xx* ua32_master = NULL ;

#define MAX_CONTINUOUS_ERR_CNT 3

/*======================================== module parameters end ===========================*/

int create_block_workthread(struct ua32xx* , int , int , void *);
static void ua32xx_clear_works(struct ua32xx*);
static void ua32xx_stop(struct ua32xx*);
static void free_ua32xx(struct ua32xx*);
static void ua32xx_sel_master(void);

static inline int __usb_endpoint_is_bulk(struct usb_endpoint_descriptor* ep)
{
	return ((ep->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_BULK) ? 1 : 0;
}

static inline int __usb_endpoint_is_in(struct usb_endpoint_descriptor* ep)
{
	return ep->bEndpointAddress & USB_DIR_IN ? 1 : 0;
}

static void wait_just_a_bit(int foo)
{
   unsigned long newjiffies;
   newjiffies = jiffies + foo;
   while(jiffies < newjiffies);
}

static inline int ua32xx_test_cardflag(struct ua32xx* ua, uint8_t card)
{
	return ua->cardflag[card/(sizeof(unsigned int)*8)]	& ( 1 << (card % (sizeof(unsigned int)*8)) );
}

static inline void ua32xx_clear_cardflag(struct ua32xx* ua, uint8_t card)
{
	ua->cardflag[card/(sizeof(unsigned int)*8)] &= ~( 1 << (card % (sizeof(unsigned int)*8)));
}

static inline void ua32xx_set_cardflag(struct ua32xx* ua, uint8_t card)
{
	ua->cardflag[card/(sizeof(unsigned int)*8)] |= ( 1 << (card % (sizeof(unsigned int)*8)));
}

static int ua32xx_get_fwver(struct ua32xx* ua)
{
	int res;
	struct oproto_packet* recvpkt;
	
	recvpkt = oproto_alloc_io_pkt(&ua->proto, GFP_KERNEL);
	if(!recvpkt){
		return -1;
	}
	
	res = oproto_get_fwver(&ua->proto, recvpkt);
	if(res){
		oproto_free_io_pkt(recvpkt);
		printk(UA32XX_NAME": %s line %d error %d!\n", __FUNCTION__, __LINE__, res);
		return res;
	}
	
	ua->fw_ver.major = recvpkt->body[0].ver.major;
	ua->fw_ver.minor = recvpkt->body[0].ver.minor;
	ua->fw_ver.bugfix = recvpkt->body[0].ver.bugfix;
	ua->fw_ver.build = recvpkt->body[0].ver.build;
	
	oproto_free_io_pkt(recvpkt);
	
	return 0;
}

int ua32xx_get_report(struct ua32xx* ua)
{
	int res;
	res = oproto_get_report(&ua->proto,&ua->report);
	if(res){
		printk(UA32XX_NAME": %s line %d error %d!\n", __FUNCTION__, __LINE__, res);
		return res;
	}
#if 0
	if(debug){
		printk(KERN_INFO"ua32xx device %d running status report(jif=%lu):\n",ua->ifaces_index,jiffies);
		printk(KERN_INFO"  tdm_packet_received = %llu \n",ua->report.tdm_packet_received);
	  printk(KERN_INFO"  tdm_packet_send = %llu\n",ua->report.tdm_packet_send);
		printk(KERN_INFO"  usb_cmd_tx_fail = %d \n",ua->report.usb_cmd_tx_fail);
		printk(KERN_INFO"  usb_tdm_tx_fail = %d \n",ua->report.usb_tdm_tx_fail);
	  printk(KERN_INFO"  usb_tx_fifo_load = %d \n",ua->report.tdm_txfifo_load);
		printk(KERN_INFO"  usb_rx_fifo_load = %d\n",ua->report.tdm_rxfifo_load);
		printk(KERN_INFO"  tdm_tx_fifo_underflow = %d \n",ua->report.tdm_tx_fifo_underflow);
		printk(KERN_INFO"  tdm_tx_fifo_overflow = %d \n",ua->report.tdm_tx_fifo_overflow);
	  printk(KERN_INFO"  tdm_rx_fifo_overflow = %d\n",ua->report.tdm_rx_fifo_overflow);
	}	
#endif
	return 0;
}

static int ua32xx_tdm_op(struct ua32xx* ua,unsigned int op)
{
	int res;

	res = oproto_tdm_op(&ua->proto,op);	
	if(res == 0){
		ua->tdm_stat = op;
		oproto_reset_report(&ua->proto);
	}
	return res;
}

static int ua32xx_reg_sync_wr(struct ua32xx* ua,int card,uint8_t reg,uint8_t data)
{
	int res = 0;
	struct oproto_packet* sndpkt;
	struct oproto_packet* recvpkt;
	struct oproto_OP_REG regop;
	
	sndpkt = __oproto_make_regop_pkt(&ua->proto);
	if(!sndpkt)
		return -1;
	
	recvpkt = oproto_alloc_io_pkt(&ua->proto, GFP_KERNEL);
	if(!recvpkt){
		oproto_free_io_pkt(sndpkt);
		return -2;
	}
	
	regop_make(&regop, card, ua->modtype[card], MOD_REG_WR, reg, data);
	__oproto_iopkt_regop_add(&ua->proto, sndpkt, &regop);
	
	res = oproto_io_sync_op(&ua->proto, sndpkt,recvpkt);
	if(res){
		printk(UA32XX_NAME": %s line %d error %d!\n", __FUNCTION__, __LINE__, res);
	}
	
	oproto_free_io_pkt(recvpkt);
	oproto_free_io_pkt(sndpkt);
	return res;
}

static int ua32xx_reg_op_read(struct ua32xx* ua, int card, uint8_t reg)
{
	op_pkt_node_t *node;
	
	spin_lock(&ua->list_lock);
	node = __op_pkt_list_addop(ua->pkt_list, card, ua->modtype[card], MOD_REG_RD, reg, 0);
	spin_unlock(&ua->list_lock);
	
	if(!node){
		printk(UA32XX_NAME": %s line %d error!\n", __FUNCTION__, __LINE__);
		return -1;
	}

#if 0
	if((ua->ifaces_index == 0) && /*(card == 0) && */(reg == I_STATUS))
		printk(KERN_DEBUG "<<<<<<<<<<<<<<<<< %s, device %d, card %d, reg %d, pkt length: %d, pkt_sn = %d, jif = %lu\n",
							__FUNCTION__, ua->ifaces_index, card, reg, ua->pkt_list->pkt_num, node->op_pkt->header.pkt_sn, jiffies);
#endif	
	
	return 0;
}

static int add_timeout_node(struct ua32xx* ua, int card, uint8_t reg)
{
	regop_node_t* opnode;
	
	spin_lock(&ua->rd_timeout_lock);
	opnode = __create_regop_node(ua->rd_timeout_list);
	spin_unlock(&ua->rd_timeout_lock);
	
	if(!opnode)
		return -1;
	
	regop_make(opnode->regop,card,ua->modtype[card],MOD_REG_RD,reg,0);
	if(iodebug)
		printk("------- %s device %d timeout list length %d, card %d, reg %d\n", 
						__FUNCTION__, ua->ifaces_index, ua->rd_timeout_list->regop_num,card, reg);
	
	return 0;
}

#define WAIT_TIMEOUT 20
#define READ_TIMEOUT 100
static int ua32xx_reg_read(struct ua32xx* ua, int card, uint8_t reg, uint8_t *data)
{
	int res;
	unsigned long orijif;
	
	orijif = jiffies;
	if(ua32xx_reg_op_read(ua,card,reg)){
		printk(UA32XX_NAME": %s line %d error!\n", __FUNCTION__, __LINE__);
		return -1;
	}
	
wait_read:	
	res = wait_event_timeout(ua->io_waitq[card],ua->wkup_cond[card] > 0,msecs_to_jiffies(WAIT_TIMEOUT));	
	if(!res){
		if(debug)
			printk(KERN_INFO "!!!!!! %s line %d, read device %d card %d register %d, time's out.\n", 
																						__FUNCTION__, __LINE__,ua->ifaces_index,card,reg);
		if(jiffies - orijif < msecs_to_jiffies(READ_TIMEOUT))
			goto wait_read;
		else
			return -1;
	}
		
	spin_lock(&ua->rd_lock);
	res = __get_op_result(ua->rdbuf_list, card,reg,data);
	spin_unlock(&ua->rd_lock);
	
	if(res){
		if(jiffies - orijif < msecs_to_jiffies(READ_TIMEOUT))
			goto wait_read;
		else{
			add_timeout_node(ua,card,reg);
			printk("!!!!!!!<-------- %s line %d, read device %d card %d register %d failed! jif=%lu. --------->\n", 
																						__FUNCTION__, __LINE__,ua->ifaces_index,card,reg,jiffies);
			return -1;
		}
	}
	ua->wkup_cond[card]-- ;
	return 0;
}

static int ua32xx_reg_write(struct ua32xx* ua,int card,uint8_t reg,uint8_t data)
{
	op_pkt_node_t *node;
	
	spin_lock(&ua->list_lock);
	node = __op_pkt_list_addop(ua->pkt_list, card, ua->modtype[card], MOD_REG_WR, reg, data);
	spin_unlock(&ua->list_lock);
	
	if(!node){
		printk(UA32XX_NAME": %s line %d error!(device %d,card %d, reg %d, data: %02x)\n", 
										__FUNCTION__, __LINE__,ua->ifaces_index, card, reg, data);
		return -1;
	}
		
	return 0;
}

/*put the readback read operations into the read buffer list*/
static int io_readback(struct ua32xx* ua, op_pkt_node_t *pktnode)
{
	int x,opnum,rdnum,in_rtol;
	regop_node_t* opnode;
	struct oproto_OP_REG *optmp;
	uint8_t card,isFxo;
	
	rdnum = 0;
	opnum = pktnode->op_pkt->header.op_num;
	optmp = (struct oproto_OP_REG *)pktnode->op_pkt->body;
	for(x=0;x<opnum;x++){
		if(optmp[x].rw == MOD_REG_RD){
			card = optmp[x].card;
#ifdef FXX_EXT
			isFxo = (optmp[x].card_property & (1 << FXX_EXT_MODTYPE_BIT));
#else
			isFxo = (card & (1<<MOD_TYPE_BIT));
			card &= 0x1f;
#endif
			//channel work status registers
			if(ua->init_ok){
				if( isFxo && (optmp[x].addr == 5) ){  //FXO
					ua->reg0shadow[card] = optmp[x].data;
					continue;
				}else if( isFxo && (optmp[x].addr == 29) ){  //FXO
					ua->reg1shadow[card] = optmp[x].data;
					continue;
				}else if(!isFxo && (optmp[x].addr == 68)){		//FXS
					ua->reg0shadow[card] = optmp[x].data;
					continue;
				}else if(!isFxo && (optmp[x].addr == LINE_STATE)){  //FXS
					ua->reg1shadow[card] = optmp[x].data;
					continue;
				}else if(!isFxo && (optmp[x].addr == 8)){  //FXS
					ua->reg8[card] = optmp[x].data;
					continue;
				}
			}
			
#if 0
			if((ua->ifaces_index == 0) && /*(card == 0) && */(optmp[x].addr == I_STATUS))
				printk(KERN_INFO ">>>>>> %s, device %d, card %d, reg %d, pkt_sn=%d, jif = %lu >>>>>>>>\n",
																__FUNCTION__,ua->ifaces_index,card,optmp[x].addr, pktnode->op_pkt->header.pkt_sn, jiffies);
#endif
			//remove the timeout regops
			in_rtol = 0;
			if(ua->rd_timeout_list->regop_num > 0){
				spin_lock(&ua->rd_timeout_lock);
				in_rtol = __remove_regop(ua->rd_timeout_list,card,optmp[x].addr);
				spin_unlock(&ua->rd_timeout_lock);
				
				if(in_rtol){
					if(iodebug){
						printk("------- %s device %d timeout list length %d, remove timeout regop: card %d, reg %d\n", 
												__FUNCTION__, ua->ifaces_index, ua->rd_timeout_list->regop_num,card, optmp[x].addr);
					}
					continue;
				}
			}
			
			//get the regop result
			spin_lock(&ua->rd_lock);
			opnode = __create_regop_node(ua->rdbuf_list);
			ua->wkup_cond[card]++;
			spin_unlock(&ua->rd_lock);
			
			opnode->regop->card = optmp[x].card;
			opnode->regop->rw = optmp[x].rw;
			opnode->regop->card_property = optmp[x].card_property;
			opnode->regop->addr = optmp[x].addr;
			opnode->regop->data = optmp[x].data;
			rdnum++;
			//wakeup channels wait queue
			wake_up(&(ua->io_waitq[card]));
		}
	}
#if 0
	if(rdnum){
		printk(KERN_DEBUG " >>> Device %d readbuf depth %d\n",
													ua->ifaces_index,rdnum);
	}
#endif	
	
	return rdnum;
}

static int io_list_proc(struct ua32xx* ua)
{
	int res;
	op_pkt_node_t *node;
	struct list_head *pos,*tmp;
	struct list_head *the_list = &ua->pkt_list->list;

	struct timeval tv0,tv1;
	unsigned long jif0,jif1;
	unsigned int tv_us,pktl,pktn = 0;
	
#if 0
	if(ua->pkt_list->pkt_num){
		printk(KERN_DEBUG "<<<>>> Device %d iopkt list depth: %d\n",
																			ua->ifaces_index,ua->pkt_list->pkt_num);	
	}
#endif
	
	if(iodebug){
		if(ua->ifaces_index == 0){
			pktl = ua->pkt_list->pkt_num;
			printk(KERN_INFO "--------device %d iopkt debug info, io_proc_cnt %lu, list length %d, jif=%lu--------\n", 
									ua->ifaces_index, ua->iowq_proc_cnt, pktl, jiffies);
		}
	}

	list_for_each_safe(pos, tmp, the_list){
		node = (op_pkt_node_t*)pos;
		
		if(node->submited == 1)
			continue;
		
		spin_lock(&ua->list_lock);
		node->submited = 1;
		spin_unlock(&ua->list_lock);
		
		if(iodebug){
			if(ua->ifaces_index == 0){
				do_gettimeofday(&tv0);
				jif0 = jiffies;
			}
		}

		res = oproto_io_sync_op(&ua->proto, node->op_pkt,ua->iowq_recvpkt);
		if(res){
			printk(UA32XX_NAME": %s line %d error %d!\n", __FUNCTION__, __LINE__, res);
			res = -2;
			goto op_err;
		}

		if(iodebug){
			if(ua->ifaces_index == 0){
				jif1 = jiffies;
				do_gettimeofday(&tv1);
				tv_us = tv1.tv_usec > tv0.tv_usec ? (tv1.tv_usec - tv0.tv_usec) : (tv1.tv_usec - tv0.tv_usec + 1000000);
			
				printk(KERN_DEBUG "	list length %d, pkt %d, pkt_sn %d, contains %d regops, proc time %d (us), jiffies(%lu, %lu)\n",
												 	ua->pkt_list->pkt_num, pktn, node->op_pkt->header.pkt_sn, node->op_pkt->header.op_num, tv_us, jif0, jif1);
				pktn++;			
			}
		}
	
		res = pkt_comp_update(node,ua->iowq_recvpkt);
		if(res){
			printk(UA32XX_NAME": %s line %d error %d!\n", __FUNCTION__, __LINE__, res);
			res = -3;
			goto op_err;
		}
		
		//read the result and remove the node
		spin_lock(&ua->list_lock);
		list_del(pos);
		ua->pkt_list->pkt_num--;
		spin_unlock(&ua->list_lock);
		
		io_readback(ua,node);
		
		//free the node
		kfree(node->op_pkt);
		kfree(node);
	}

	if(iodebug){
		if(ua->ifaces_index == 0){
			printk(KERN_DEBUG "--------device %d: %d iopkt processed, jif=%lu--------\n\n",ua->ifaces_index, pktn, jiffies);
		}
	}

	return 0;
	
op_err:
	node->submited = 0;	
	return res;
}
	
/*********************************************************************************************************/
static int ua32xx_fxo_detect(struct ua32xx* ua,uint8_t card)
{
	int res,x;
	uint8_t fxo_reg11=0,fxo_reg13=0;
	uint8_t isFxo;
	
	struct oproto_packet* sndpkt;
	struct oproto_packet* recvpkt;
	struct oproto_OP_REG regop;
	struct oproto_OP_REG *tmp;
	
	sndpkt = __oproto_make_regop_pkt(&ua->proto);
	if(!sndpkt)
		return -1;
		
	recvpkt = oproto_alloc_io_pkt(&ua->proto, GFP_KERNEL);
	if(!recvpkt){
		oproto_free_io_pkt(sndpkt);
		return -2;
	}
	
	regop_make(&regop, card, MOD_TYPE_FXO, MOD_REG_RD, 11, 0);
  __oproto_iopkt_regop_add(&ua->proto, sndpkt, &regop);
  
  regop_make(&regop, card, MOD_TYPE_FXO, MOD_REG_RD, 13, 0);
  __oproto_iopkt_regop_add(&ua->proto, sndpkt, &regop);
  
  res = oproto_io_sync_op(&ua->proto, sndpkt,recvpkt);
	if(res){
		oproto_free_io_pkt(sndpkt);
		oproto_free_io_pkt(recvpkt);
		printk(UA32XX_NAME": %s line %d error %d!\n", __FUNCTION__, __LINE__, res);
		return -3;
	}	
	
	oproto_free_io_pkt(sndpkt);
	
	tmp = (struct oproto_OP_REG *)recvpkt->body;
	for(x=0; x<recvpkt->header.op_num; x++){
#ifdef FXX_EXT
	isFxo = (tmp[x].card_property & (1 << FXX_EXT_MODTYPE_BIT));
#else
	isFxo = (tmp[x].card & (1<<MOD_TYPE_BIT));
#endif
		if((tmp[x].rw == MOD_REG_RD)&&(tmp[x].addr == 11)&&isFxo){
			fxo_reg11 = tmp[x].data;
		}else if((tmp[x].rw == MOD_REG_RD)&&(tmp[x].addr == 13)&&isFxo){
			fxo_reg13 = tmp[x].data;
		}
	}
	
	oproto_free_io_pkt(recvpkt);
	
	if(((fxo_reg11 == 0x04)||(fxo_reg11 == 0x05))&&(fxo_reg13 == 0x40)){
		ua32xx_set_cardflag(ua, card);
		ua->modtype[card] = MOD_TYPE_FXO;
		printk(UA32XX_NAME ": Module %d Installed -- AUTO FXO (%s mode)\n",card, fxo_modes[_opermode].name);
	}else
		return 1;
	
	return 0;
}

static int ua32xx_fxs_detect(struct ua32xx* ua,uint8_t card)
{
	int res,x;
	uint8_t fxs_reg1=0,fxs_reg6=0;
	uint8_t isFxo;
	
	struct oproto_packet* sndpkt;
	struct oproto_packet* recvpkt;
	struct oproto_OP_REG regop;
	struct oproto_OP_REG *tmp;
	int mod_daisy,daisy_cards;
	
	if(!strcmp(ua->hw_name,"UC540")){
		daisy_cards = DAISY_CARDS_2;
	}else{
		daisy_cards = DAISY_CARDS_4;
	}
	
	sndpkt = __oproto_make_regop_pkt(&ua->proto);
	if(!sndpkt)
		return -1;
		
	recvpkt = oproto_alloc_io_pkt(&ua->proto, GFP_KERNEL);
	if(!recvpkt){
		oproto_free_io_pkt(sndpkt);
		return -2;
	}

	if( ua->module_daisy ){
		if(ua->hw_channels >= daisy_cards)
			mod_daisy = daisy_cards;
		else
			mod_daisy = 1;
		
		if((card % mod_daisy) == 0)	{
  		daisy_op_make(&regop, card);
  		__oproto_iopkt_regop_add(&ua->proto, sndpkt, &regop);
  	}
	}
	
  regop_make(&regop, card, MOD_TYPE_FXS, MOD_REG_RD, 1, 0);
  __oproto_iopkt_regop_add(&ua->proto, sndpkt, &regop);
  
  regop_make(&regop, card, MOD_TYPE_FXS, MOD_REG_RD, 6, 0);
  __oproto_iopkt_regop_add(&ua->proto, sndpkt, &regop);
	
	res = oproto_io_sync_op(&ua->proto, sndpkt,recvpkt);
	if(res){
		oproto_free_io_pkt(sndpkt);
		oproto_free_io_pkt(recvpkt);
		printk(UA32XX_NAME": %s line %d error %d!\n", __FUNCTION__, __LINE__, res);
		return -3;
	}	
	
	oproto_free_io_pkt(sndpkt);
	
	tmp = (struct oproto_OP_REG *)recvpkt->body;
	for(x=0; x<recvpkt->header.op_num; x++){
#ifdef FXX_EXT
		isFxo = (tmp[x].card_property & (1 << FXX_EXT_MODTYPE_BIT));
#else
		isFxo = (tmp[x].card & (1<<MOD_TYPE_BIT));
#endif
		if((tmp[x].rw == MOD_REG_RD) && (tmp[x].addr == 1) && !isFxo){
			fxs_reg1 = tmp[x].data;
		}else if((tmp[x].rw == MOD_REG_RD) && (tmp[x].addr == 6) && !isFxo){
			fxs_reg6 = tmp[x].data;
		}
	}
	
	oproto_free_io_pkt(recvpkt);
	
	if(((fxs_reg1&0x0F) == 0x08)&&(fxs_reg6 == 0x0)){
		ua32xx_set_cardflag(ua, card);
		ua->modtype[card] = MOD_TYPE_FXS;
		if((fxs_reg1&0x80))
			ua->flags[card] |= FLAG_3215;
				
		printk(UA32XX_NAME ": Module %d Installed -- AUTO FXS/DPO\n",card);
	}
	else
		return 1;
		
	return 0;
}


/*********************************************************************
 * Set the hwgain on the analog modules
 *
 * card = the card position for this module (0-23)
 * gain = gain in dB x10 (e.g. -3.5dB  would be gain=-35)
 * tx = (0 for rx; 1 for tx)
 *
 *******************************************************************/
static int si3050_set_hwgain(struct ua32xx* ua, int card, __s32 gain, __u32 tx)
{
	if(tx){
		if (debug) {
      printk(UA32XX_NAME": setting tx gain for FXO cards : %d\n", gain);
    }	
    if (gain >=  -150 && gain <= 0) {
    	ua32xx_reg_write(ua,card,38,16 + (gain/-10));
    	ua32xx_reg_write(ua,card,40,16 + (-gain%10));
    }else if (gain <= 120 && gain > 0) {
    	ua32xx_reg_write(ua,card,38,gain/10);
    	ua32xx_reg_write(ua,card,40,gain%10);
    }else{
    	printk(UA32XX_NAME": FXO tx gain is out of range (%d)\n", gain);
    }
	}else {
		if (debug) {
      printk(UA32XX_NAME": setting rx gain for FXO cards : %d\n", gain);
    }	
    if (gain >=  -150 && gain <= 0) {
    	ua32xx_reg_write(ua,card,39,16 + (gain/-10));
    	ua32xx_reg_write(ua,card,41,16 + (-gain%10));
    }else if (gain <= 120 && gain > 0) {
    	ua32xx_reg_write(ua,card,39,gain/10);
    	ua32xx_reg_write(ua,card,41,gain%10);
    }else{
    	printk(UA32XX_NAME": FXO rx gain is out of range (%d)\n", gain);
    }
	}
		  
	return 0;
}

static int si3050_init_voicedaa(struct ua32xx* ua,int card)
{
	int retval;
	unsigned long newjiffies;
	unsigned char datatmp;
  unsigned char reg16=0, reg26=0, reg30=0, reg31=0;
 
	/* Software reset */
  ua32xx_reg_write(ua, card, 1, 0x80);
  
  /* Wait just a bit */
  wait_just_a_bit(HZ/10);
  
  /* Enable PCM, ulaw */
  if (alawoverride)
     ua32xx_reg_write(ua,card,33,0x20);
  else
     ua32xx_reg_write(ua,card,33,0x28);
  
  /* Set On-hook speed, Ringer impedence, and ringer threshold */
  reg16 |= (fxo_modes[_opermode].ohs << 6);
  reg16 |= (fxo_modes[_opermode].rz << 1);
  reg16 |= (fxo_modes[_opermode].rt);
  ua32xx_reg_write(ua,card,16,reg16);
  
  if(fwringdetect) {
    /* Enable ring detector full-wave rectifier mode */
    ua32xx_reg_write(ua,card,18,2);
    ua32xx_reg_write(ua,card,24,0);
  } else {
    /* Set to the device defaults */
    ua32xx_reg_write(ua,card,18,0);
    ua32xx_reg_write(ua,card,24,0x19);
  }
  
  /* Set DC Termination:
           Tip/Ring voltage adjust, minimum operational current, current limitation */
  reg26 |= (fxo_modes[_opermode].dcv << 6);
  reg26 |= (fxo_modes[_opermode].mini << 4);
  reg26 |= (fxo_modes[_opermode].ilim << 1);
  ua32xx_reg_write(ua,card,26,reg26);

  /* Set AC Impedence */
  reg30 = (fxofullscale==1) ? (fxo_modes[_opermode].acim|0x10) :  (fxo_modes[_opermode].acim);
  ua32xx_reg_write(ua,card,30,reg30);

  /* Misc. DAA parameters */
  if (fastpickup)
     reg31 = 0xb3;
  else
     reg31 = 0xa3;
  reg31 |= (fxo_modes[_opermode].ohs2 << 3);
  ua32xx_reg_write(ua,card,31,reg31);
  
  /* Set Transmit/Receive timeslot */
  ua32xx_reg_write(ua,card,34,card*8);
  ua32xx_reg_write(ua,card,35,0);
  ua32xx_reg_write(ua,card,36,card*8);
  ua32xx_reg_write(ua,card,37,0);
  
  /* Enable ISO-Cap */
  ua32xx_reg_write(ua,card,6,0);
	
	if (fastpickup)
  {
  	retval = ua32xx_reg_read(ua, card, 17,&datatmp);
  	if(retval){
  		printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,retval);	
  		return -1;
  	}
  	datatmp = datatmp | 0x20;
  	ua32xx_reg_write(ua, card, 17, datatmp);
  }
  
  newjiffies = jiffies + 2 * HZ;
  do{
  	wait_just_a_bit(HZ/10);
  	
  	retval = ua32xx_reg_read(ua, card, 11, &datatmp);
  	if(retval){
  		printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,retval);	
  		return -1;
  	}
  }while((jiffies < newjiffies) && !(datatmp&0xf0));
  
  if(!(datatmp&0xf0)){
  	printk(UA32XX_NAME": Card %d VoiceDAA did not bring up ISO link properly!\n",card);
    return -1;
  }
  
  if (debug) {
  	ua32xx_reg_read(ua, card, 11, &reg16);
  	ua32xx_reg_read(ua, card, 13, &reg26);
		printk(UA32XX_NAME": FXO Card %d, ISO-Cap is now up, line side: %02x rev %02x\n",
  						card,reg16 >> 4,(reg26>>2)&0xf);
  }
  
  /* Enable on-hook line monitor */
  ua32xx_reg_write(ua, card, 5, 0x08);
  
  /* Take values for fxotxgain and fxorxgain and apply them to module */
  si3050_set_hwgain(ua,card,fxotxgain, 1);
  si3050_set_hwgain(ua,card,fxorxgain, 0);
  
  /* NZ -- crank the tx gain up by 7 dB */
  if (!strcmp(fxo_modes[_opermode].name, "NEWZEALAND")) {
    printk(UA32XX_NAME": Adjusting FXO gain\n");
    si3050_set_hwgain(ua,card, 7, 1);
  }
  
  //set writen flag
  ua->mod[card].fxo.regwr.flag = 1;
  
  //light the led
  if(!strcmp(ua->hw_name,"A1008")){
		oproto_cfg_led(&ua->proto, card, ua->modtype[card], CHAN_LED_LITHT);
//	}else if(!strcmp(ua->hw_name,"UC500") ||
	}else if(!strcmp(ua->hw_name,"UC580") ||
		       !strcmp(ua->hw_name,"UC320") ||
		       !strcmp(ua->hw_name,"UC350") ||
	               !strcmp(ua->hw_name,"UC581") ||
		       !strcmp(ua->hw_name,"UC540"))
	{
		oproto_cfg_led(&ua->proto,card, ua->modtype[card], CHAN_LED_LITHT);
		msleep(500);
		oproto_cfg_led(&ua->proto,card, ua->modtype[card], CHAN_LED_BLACK);
	}
  
  if(debug){
  	int x;
  	uint8_t buf[59];
  	ua32xx_reg_read(ua, card, 38, buf);
  	ua32xx_reg_read(ua, card, 40, buf+1);
  	ua32xx_reg_read(ua, card, 39, buf+2);
  	ua32xx_reg_read(ua, card, 41, buf+3);
		printk(UA32XX_NAME": DEBUG card %d fxotxgain:%i.%i fxorxgain:%i.%i\n",card,
  							buf[0]/16 ? -(buf[0]-16) : buf[0],
  							buf[1]/16 ? -(buf[1]-16) : buf[1],	
  							buf[2]/16 ? -(buf[2]-16) : buf[2],
  							buf[3]/16 ? -(buf[3]-16) : buf[3]
  						);
  	
  	for(x=0;x<59;x++){
  		retval = ua32xx_reg_read(ua, card, x+1, buf+x);
  		if(retval){
  			printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,retval);	
  			return -5;
  		}
  	}
  	printk(UA32XX_NAME": FXO Si3050 debug infor for card %d:\n",card);
  	for(x=0;x<59;x++){
  		if (! (x & 15))
      	printk("%02x:", x);
      printk(" %02x", buf[x]);
      if ((x & 15) == 15)
      	printk("\n");
  	}
  	printk("\n");
  }
  
	return 0;	
}

static unsigned char translate_3215(unsigned char address)
{
	int x;
	for (x=0;x<sizeof(indirect_regs)/sizeof(indirect_regs[0]);x++) {
		if (indirect_regs[x].address == address) {
			address = indirect_regs[x].altaddr;
			break;
		}
	}
	return address;
}

#define MAX 30 /* attempts */
static int __wait_access(struct ua32xx* ua,uint8_t card)
{ 
	int res;
	unsigned char data = 0;
  int count = 0;
  
	/* Wait for indirect access */
retry:
		res = ua32xx_reg_read(ua, card, I_STATUS, &data);
		if(res){
			printk(UA32XX_NAME": %s failed on line %d, error %d.(device %d, card %d)\n",
														__FUNCTION__, __LINE__, res, ua->ifaces_index, card);
			return res;
		}
		if (!data)
			return 0;
		
		count++ ;
	if(count < MAX)
		goto retry;
	
  printk(UA32XX_NAME" ##### Loop error (%02x) #####\n", data);
  	
  return 0;
}
	
static int si321x_proslic_setreg_indirect(struct ua32xx* ua, uint8_t card, unsigned char address, unsigned short data)
{
	int res = -1;

	/* Translate 3215 addresses */
	if (ua->flags[card] & FLAG_3215) {
		address = translate_3215(address);
		if (address == 255)
			return 1;
	}
	
	if(!__wait_access(ua, card)) {
		ua32xx_reg_write(ua, card, IDA_LO,(unsigned char)(data & 0xFF));
		ua32xx_reg_write(ua, card, IDA_HI,(unsigned char)((data & 0xFF00)>>8));
		ua32xx_reg_write(ua, card, IAA,address);
		res = 0;
	}
	
  return res;
}

static int si321x_proslic_getreg_indirect(struct ua32xx* ua, uint8_t card, unsigned char address,unsigned short *data)
{
	int res1,res2;
	
	/* Translate 3215 addresses */
	if (ua->flags[card] & FLAG_3215) {
		address = translate_3215(address);
		if (address == 255)
			return 1;
	}
	
	if (!__wait_access(ua, card)) {
		ua32xx_reg_write(ua, card, IAA, address);
		if (!__wait_access(ua, card)) {
			uint8_t buf[] = {0,0};
			
			res1 = ua32xx_reg_read(ua, card,IDA_LO,buf);
			res2 = ua32xx_reg_read(ua, card,IDA_HI,buf+1);
			if(res1 || res2){
				printk(UA32XX_NAME": %s failed on line %d, error(%d %d)\n",__FUNCTION__,__LINE__,res1,res2);
				return -2;
			}
			*data = buf[0] | (buf[1] << 8);
		} else{
			printk(KERN_NOTICE "Failed to wait inside\n");
			return -3;
		}
	} else{
		printk(KERN_NOTICE "Failed to wait\n");
		return -3;
	}
	
  return 0;
}

static int si321x_proslic_init_indirect_regs(struct ua32xx* ua, int card)
{
	unsigned char i;

	for (i=0; i<sizeof(indirect_regs) / sizeof(indirect_regs[0]); i++)
	{
		if(si321x_proslic_setreg_indirect(ua, card, indirect_regs[i].address,indirect_regs[i].initial) < 0)
			return -1;
	}

	return 0;
}

static int si321x_proslic_verify_indirect_regs(struct ua32xx* ua, int card)
{
	int passed = 1,res;
	unsigned short i, initial;
	unsigned short data;

	for (i=0; i<sizeof(indirect_regs) / sizeof(indirect_regs[0]); i++) 
	{
		res = si321x_proslic_getreg_indirect(ua, card, indirect_regs[i].address,&data);
		if(res < 0) {
			printk(KERN_NOTICE "Failed to read indirect register %d\n", i);
			return -1;
		}else if(res > 0)
			continue;
		
		initial= indirect_regs[i].initial;
		if ( (data != initial) && (!(ua->flags[card] & FLAG_3215) || (indirect_regs[i].altaddr != 255)) )
		{
			printk(KERN_NOTICE "!!!!!!! card %d,%s  iREG %d = %04x  should be %04x\n",
																	card,indirect_regs[i].name,indirect_regs[i].address,data,initial );
			passed = 0;
		}	
	}

  if (passed) {
		if (debug)
			printk(KERN_DEBUG "Init Indirect Registers completed successfully.\n");
  } else {
		printk(KERN_NOTICE " !!!!! Init Indirect Registers UNSUCCESSFULLY.\n");
		return -1;
  }
	return 0;
}

static int si321x_proslic_insane(struct ua32xx* ua, int card)
{ 
	int insane_report;
	uint8_t blah;
	insane_report=0;
	
	ua32xx_reg_read(ua, card,0,&blah);
	if (debug) 
		printk(UA32XX_NAME": ProSLIC on module %d, product %d, version %d\n", card, (blah & 0x30) >> 4, (blah & 0xf));
	
	if (((blah & 0xf) == 0) || ((blah & 0xf) == 0xf)) {
		/* SLIC not loaded */
		return -1;
	}
	if ((blah & 0xf) < 2) {
		printk(UA32XX_NAME": ProSLIC 3210 version %d is too old\n", blah & 0xf);
		return -1;
	}
	
	ua32xx_reg_read(ua, card,8,&blah);
	if (blah != 0x2) {
		printk(UA32XX_NAME": ProSLIC on module %d insane (1) %d should be 2\n", card, blah);
		return -1;
	} else if ( insane_report)
		printk(UA32XX_NAME": ProSLIC on module %d Reg 8 Reads %d Expected is 0x2\n",card,blah);
	
	ua32xx_reg_read(ua, card,64,&blah);
	if (blah != 0x0) {
		printk(UA32XX_NAME": ProSLIC on module %d insane (2)\n", card);
		return -1;
	} else if ( insane_report)
		printk(UA32XX_NAME": ProSLIC on module %d Reg 64 Reads %d Expected is 0x0\n",card,blah);
	
	ua32xx_reg_read(ua, card,11,&blah);
	if (blah != 0x33) {
		printk(UA32XX_NAME": ProSLIC on module %d insane (3)\n", card);
		return -1;
	} else if ( insane_report)
		printk(UA32XX_NAME": ProSLIC on module %d Reg 11 Reads %d Expected is 0x33\n",card,blah);
	
	/* Just be sure it's setup right. */
	ua32xx_reg_write(ua, card, 30, 0);
	wait_just_a_bit(5);
	
	if (debug){
		printk(KERN_DEBUG "ProSLIC on module %d seems sane.\n", card);
		printk(UA32XX_NAME ":ProSLIC on module %d seems sane.\n", card);		
	} 

		
  return 0;
}

static int si321x_proslic_powerleak_test(struct ua32xx* ua, int card)
{
	int res;
	unsigned long origjiffies;
	unsigned char vbat;

	/* Turn off linefeed */
	ua32xx_reg_write(ua, card, 64, 0);

	/* Power down */
	ua32xx_reg_write(ua, card, 44, 0x10);
	
	/* Wait for one second */
	origjiffies = jiffies;
	
	do{
		res = ua32xx_reg_read(ua, card, 82, &vbat);
		if(res){
			printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
			return -1;
		}
		if ((jiffies - origjiffies) >= (HZ/2))
			break;
		wait_just_a_bit(10);
	}while(vbat > 0x6);

	if (vbat < 0x06) {
		printk(KERN_NOTICE "Excessive leakage detected on module %d: %d volts (%02x) after %d ms\n", card,
		       376 * vbat / 1000, vbat, (int)((jiffies - origjiffies) * 1000 / HZ));
		return -1;
	} else if (debug) {
		printk(KERN_NOTICE "Post-leakage voltage: %d volts\n", 376 * vbat / 1000);
		printk(UA32XX_NAME ":Post-leakage voltage: %d volts\n", 376 * vbat / 1000);
	}
	
	return 0;
}

static int si321x_powerup_proslic(struct ua32xx* ua, int card, int fast)
{
	int res;
	unsigned char vbat;
	unsigned long origjiffies;
	int lim;
	
	/* Set period of DC-DC converter to 1/64 khz */
	ua32xx_reg_write(ua, card, 92, 0xff);
	
	/* Disable powerdown */
	ua32xx_reg_write(ua, card, 14, 0);
	
	/* If fast, don't bother checking anymore */
	if (fast)
		return 0;
	
	/* Wait for VBat to powerup */
	origjiffies = jiffies;
	
	do{
		res = ua32xx_reg_read(ua, card, 82, &vbat);
		if(res){
			printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
			return -1;
		}
		if ((jiffies - origjiffies) >= (HZ/2))
			break;
		wait_just_a_bit(10);
	}while(vbat < 0xc0);
	
	if (vbat < 0xc0) {
		if (ua->proslic_power == PROSLIC_POWER_UNKNOWN)
				 printk(KERN_NOTICE "ProSLIC on module %d failed to powerup within %d ms (%d mV only)\n\n -- DID YOU REMEMBER TO PLUG IN THE HD POWER CABLE TO THE TDM400P??\n",
					card, (int)(((jiffies - origjiffies) * 1000 / HZ)),
					vbat * 375);
		ua->proslic_power = PROSLIC_POWER_WARNED;
		return -1;
	} else if (debug) {
		printk(KERN_DEBUG "ProSLIC on module %d powered up to -%d volts (%02x) in %d ms\n",
		       card, vbat * 376 / 1000, vbat, (int)(((jiffies - origjiffies) * 1000 / HZ)));
		printk(UA32XX_NAME ":ProSLIC on module %d powered up to -%d volts (%02x) in %d ms\n",
		       card, vbat * 376 / 1000, vbat, (int)(((jiffies - origjiffies) * 1000 / HZ)));
	}
	ua->proslic_power = PROSLIC_POWER_ON;
	
	/* Proslic max allowed loop current, reg 71 LOOP_I_LIMIT */
  /* If out of range, just set it to the default value     */
  lim = (loopcurrent - 20) / 3;
  if ( loopcurrent > 41 ) {
  	lim = 0;
    if (debug){
    	printk(KERN_DEBUG "Loop current out of range! Setting to default 20mA!\n");
    	printk(UA32XX_NAME ":Loop current out of range! Setting to default 20mA!\n");		
	}

  }
  else if (debug){
	printk(KERN_DEBUG "Loop current set to %dmA!\n",(lim*3)+20);
	printk(UA32XX_NAME ":Loop current set to %dmA!\n",(lim*3)+20);
  }

  
  ua32xx_reg_write(ua,card,LOOP_I_LIMIT,lim);

	/* Engage DC-DC converter */
	ua32xx_reg_write(ua, card, 93, 0x19);
	
	wait_just_a_bit(5);
	return 0;
}

static int si321x_proslic_manual_calibrate(struct ua32xx* ua, int card)
{
	int res;
	unsigned long origjiffies;
	unsigned char i,tmp;

	ua32xx_reg_write(ua, card, 21, 0);//(0)  Disable all interupts in DR21
	ua32xx_reg_write(ua, card, 22, 0);//(0)Disable all interupts in DR21
	ua32xx_reg_write(ua, card, 23, 0);//(0)Disable all interupts in DR21
	ua32xx_reg_write(ua, card, 64, 0);//(0)

	ua32xx_reg_write(ua, card, 97, 0x18); //(0x18)Calibrations without the ADC and DAC offset and without common mode calibration.
	ua32xx_reg_write(ua, card, 96, 0x47); //(0x47)	Calibrate common mode and differential DAC mode DAC + ILIM
	
	wait_just_a_bit(10);
	
	origjiffies = jiffies;
	do{
		res = ua32xx_reg_read(ua, card, 96, &tmp);
		if(res){
			printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
			return -1;
		}
		if ((jiffies - origjiffies) >= 80)
			return -1;
		wait_just_a_bit(5);
	}while(tmp != 0);

//Initialized DR 98 and 99 to get consistant results.
// 98 and 99 are the results registers and the search should have same intial conditions.

/*******************************The following is the manual gain mismatch calibration****************************/
/*******************************This is also available as a function *******************************************/
	wait_just_a_bit(1);
	
	si321x_proslic_setreg_indirect(ua, card, 88, 0);
	si321x_proslic_setreg_indirect(ua, card, 89, 0);
	si321x_proslic_setreg_indirect(ua, card, 90, 0);
	si321x_proslic_setreg_indirect(ua, card, 91, 0);
	si321x_proslic_setreg_indirect(ua, card, 92, 0);
	si321x_proslic_setreg_indirect(ua, card, 93, 0);

	ua32xx_reg_write(ua, card, 98, 0x10); // This is necessary if the calibration occurs other than at reset time
	ua32xx_reg_write(ua, card, 99, 0x10);
	wait_just_a_bit(5);
	
	for ( i=0x1f; i>0; i--)
	{
		res = ua32xx_reg_sync_wr(ua, card, 98, i);
		if(res){
			printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
			return -1;
		}
		
		res = ua32xx_reg_read(ua, card, 88, &tmp);
		if(res){
			printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
			return -1;
		}
		if(tmp == 0)
			break;
	} // for

	for ( i=0x1f; i>0; i--)
	{
		res = ua32xx_reg_sync_wr(ua, card, 99, i);
		if(res){
			printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
			return -1;
		}
		
		res = ua32xx_reg_read(ua, card, 89, &tmp);
		if(res){
			printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
			return -1;
		}
		if(tmp == 0)
			break;
	}//for

/*******************************The preceding is the manual gain mismatch calibration****************************/
/**********************************The following is the longitudinal Balance Cal***********************************/
	ua32xx_reg_write(ua,card,64,1);
	wait_just_a_bit(10); // 

	ua32xx_reg_write(ua, card, 64, 0);
	ua32xx_reg_write(ua, card, 23, 0x4);  // enable interrupt for the balance Cal
	ua32xx_reg_write(ua, card, 97, 0x1); // this is a singular calibration bit for longitudinal calibration
	ua32xx_reg_write(ua, card, 96, 0x40);
	
	wait_just_a_bit(10);
	res = ua32xx_reg_read(ua, card, 96,&tmp); /* Read Reg 96 just cause */
	if(res){
		printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
		return -1;
	}

	ua32xx_reg_write(ua, card, 21, 0xFF);
	ua32xx_reg_write(ua, card, 22, 0xFF);
	ua32xx_reg_write(ua, card, 23, 0xFF);
	
	wait_just_a_bit(10);
	/**The preceding is the longitudinal Balance Cal***/
	
	return 0;
}

static int si321x_proslic_calibrate(struct ua32xx* ua, int card)
{
	unsigned long origjiffies;
	int x,res;
	unsigned char tmp;
	
	/* Perform all calibrations */
	ua32xx_reg_write(ua, card, 97, 0x1f);
	wait_just_a_bit(2);
	
	/* Begin, no speedup */
	ua32xx_reg_write(ua, card, 96, 0x5f);
	wait_just_a_bit(5);
	
	/* Wait for it to finish */
	origjiffies = jiffies;
	do{
		res = ua32xx_reg_read(ua, card, 96, &tmp);
		if(res){
			printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
			return -1;
		}
		if ((jiffies - origjiffies) > 2 * HZ){
			printk(UA32XX_NAME": Timeout waiting for calibration of module %d\n", card);
			return -1;
		}
		wait_just_a_bit(10);
	}while(tmp);
	
	if (debug) {
		unsigned char buf[10];
		/* Print calibration parameters */
		printk(KERN_DEBUG "Calibration Vector Regs 98 - 107: \n");
		printk(UA32XX_NAME ":Calibration Vector Regs 98 - 107: \n");
		for (x=0;x<10;x++) {
			res = ua32xx_reg_read(ua, card, 98+x, buf+x);
			if(res){
				printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
				return -1;
			}
		}
		for (x=0;x<10;x++) {
			printk(KERN_DEBUG "%d: %02x\n", 98+x, buf[x]);
			printk(UA32XX_NAME ":%d: %02x\n", 98+x, buf[x]);
		}
	}
	
  return 0;
}

static int si321x_set_ring_generator_mode(struct ua32xx* ua, int card, int mode)
{
	int reg20, reg21, reg74; /* RCO, RNGX, VBATH */
	struct fxs *const fxs = &ua->mod[card].fxs;
		
	fxs->neonringing = mode;	/* track ring generator mode */
	
	if (mode) { /* Neon */
		if (debug){
			printk(KERN_DEBUG "NEON ring on chan %d, "
			"lasttxhook was 0x%x\n", card, fxs->lasttxhook);
			printk(UA32XX_NAME ":NEON ring on chan %d, "
			"lasttxhook was 0x%x\n", card, fxs->lasttxhook);			
		}

		/* Must be in FORWARD ACTIVE before setting ringer */
		fxs->lasttxhook = SLIC_LF_ACTIVE_FWD;
		ua32xx_reg_write(ua, card, LINE_STATE, fxs->lasttxhook);
		
		si321x_proslic_setreg_indirect(ua, card, 22,
					       NEON_MWI_RNGY_PULSEWIDTH);
		si321x_proslic_setreg_indirect(ua, card, 21,
					       0x7bef);	/* RNGX (91.5Vpk) */
		si321x_proslic_setreg_indirect(ua, card, 20,
					       0x009f);	/* RCO (RNGX, t rise)*/
		
		/* Ringing Osc. Control */
		ua32xx_reg_write(ua, card, 34, 0x19);		
		/* VBATH 94.5V */
		ua32xx_reg_write(ua, card, 74, 0x3f);
		
		si321x_proslic_setreg_indirect(ua, card, 29, 0x4600); /* RPTP */
		/* A write of 0x04 to register 64 will turn on the VM led */
	} else {
		ua32xx_reg_write(ua, card, 34, 0x00); /* Ringing Osc. Control */
		/* RNGY Initial Phase */
		si321x_proslic_setreg_indirect(ua, card, 22, 0x0000);
		si321x_proslic_setreg_indirect(ua, card, 29, 0x3600); /* RPTP */
		/* A write of 0x04 to register 64 will turn on the ringer */

		if (fastringer) {
			/* Speed up Ringer */
			reg20 =  0x7e6d;
			reg74 = 0x32;	/* Default */
			/* Beef up Ringing voltage to 89V */
			if (boostringer) {
				reg74 = 0x3f;
				reg21 = 0x0247;	/* RNGX */
				if (debug){
					printk(KERN_DEBUG "Boosting fast ringer"
						" on chan %d (89V peak)\n",
						card);
					printk(UA32XX_NAME ":Boosting fast ringer"
						" on chan %d (89V peak)\n",
						card);						
				}

			} else if (lowpower) {
				reg21 = 0x014b;	/* RNGX */
				if (debug){
					printk(KERN_DEBUG "Reducing fast ring "
					    "power on chan %d (50V peak)\n",
					    card);
					printk(UA32XX_NAME ": Reducing fast ring "
					    "power on chan %d (50V peak)\n",
					    card);						
				}

			} else if (fxshonormode &&
						fxo_modes[_opermode].ring_x) {
				reg21 = fxo_modes[_opermode].ring_x;
				if (debug){
					printk(KERN_DEBUG "fxshonormode: fast "
						"ring_x power on chan %d\n",
						card);
					printk(UA32XX_NAME ": fxshonormode: fast "
						"ring_x power on chan %d\n",
						card);						
				}

			} else {
				reg21 = 0x01b9;
				if (debug){
					printk(KERN_DEBUG "Speeding up ringer "
						"on chan %d (25Hz)\n",
						card);
					printk(UA32XX_NAME ": Speeding up ringer "
						"on chan %d (25Hz)\n",
						card);						
				}

			}
			/* VBATH */
			ua32xx_reg_write(ua, card, 74, reg74);
			/*RCO*/
			si321x_proslic_setreg_indirect(ua, card, 20, reg20);
			/*RNGX*/
			si321x_proslic_setreg_indirect(ua, card, 21, reg21);

		} else {
			/* Ringer Speed */
			if (fxshonormode && fxo_modes[_opermode].ring_osc) {
				reg20 = fxo_modes[_opermode].ring_osc;
				if (debug){
					printk(KERN_DEBUG "fxshonormode: "
						"ring_osc speed on chan %d\n",
						card);
					printk(UA32XX_NAME ": fxshonormode: "
						"ring_osc speed on chan %d\n",
						card);						
				}

			} else {
				reg20 = 0x7ef0;	/* Default */
			}

			reg74 = 0x32;	/* Default */
			/* Beef up Ringing voltage to 89V */
			if (boostringer) {
				reg74 = 0x3f;
				reg21 = 0x1d1;
				if (debug){
					printk(KERN_DEBUG "Boosting ringer on "
						"chan %d (89V peak)\n",
						card);
					printk(UA32XX_NAME ": Boosting ringer on "
						"chan %d (89V peak)\n",
						card);						
				}

			} else if (lowpower) {
				reg21 = 0x108;
				if (debug){
					printk(KERN_DEBUG "Reducing ring power "
						"on chan %d (50V peak)\n",
						card);
					printk(UA32XX_NAME ": Reducing ring power "
						"on chan %d (50V peak)\n",
						card);						
				}

			} else if (fxshonormode &&
						fxo_modes[_opermode].ring_x) {
				reg21 = fxo_modes[_opermode].ring_x;
				if (debug){
					printk(KERN_DEBUG "fxshonormode: ring_x"
						" power on chan %d\n",
						card);
					printk(UA32XX_NAME ": fxshonormode: ring_x"
						" power on chan %d\n",
						card);						
				}

			} else {
				reg21 = 0x160;
				if (debug){
					printk(KERN_DEBUG "Normal ring power on"
						" chan %d\n",
						card);
					printk(UA32XX_NAME ": Normal ring power on"
						" chan %d\n",
						card);						
				}

			}
			/* VBATH */
			ua32xx_reg_write(ua, card, 74, reg74);
			/* RCO */
			si321x_proslic_setreg_indirect(ua, card, 20, reg20);
			  /* RNGX */
			si321x_proslic_setreg_indirect(ua, card, 21, reg21);
		}
	}
	
	return 0;
}

static int si321x_init_ring_generator_mode(struct ua32xx* ua, int card)
{
	ua32xx_reg_write(ua, card, 34, 0x00);	/* Ringing Osc. Control */

	/* neon trapezoid timers */
	ua32xx_reg_write(ua, card, 48, 0xe0);	/* Active Timer low byte */
	ua32xx_reg_write(ua, card, 49, 0x01);	/* Active Timer high byte */
	ua32xx_reg_write(ua, card, 50, 0xF0);	/* Inactive Timer low byte */
	ua32xx_reg_write(ua, card, 51, 0x05);	/* Inactive Timer high byte */
	
	si321x_set_ring_generator_mode(ua, card, 0);
	
	return 0;
}

static int si321x_init_proslic(struct ua32xx* ua, int card, int fast, int manual, int sane)
{
	unsigned short tmp[5];
	unsigned char r19,r9;
	int x,res;
	int fxsmode=0;
	struct fxs *const fxs = &ua->mod[card].fxs;
	
	/* Sanity check the ProSLIC */
	if (!sane && si321x_proslic_insane(ua, card))
		return -2;
	
	/* default messages to none and method to FSK */
	memset(&fxs->vmwisetting, 0, sizeof(fxs->vmwisetting));
	fxs->vmwi_lrev = 0;
	fxs->vmwi_hvdc = 0;
	fxs->vmwi_hvac = 0;
				
	/* By default, don't send on hook */
	if (!reversepolarity != !fxs->reversepolarity)
		fxs->idletxhookstate = SLIC_LF_ACTIVE_REV;
	else
		fxs->idletxhookstate = SLIC_LF_ACTIVE_FWD;
	
	if (sane) {
		/* Make sure we turn off the DC->DC converter to prevent anything from blowing up */
		ua32xx_reg_write(ua, card, 14, 0x10);
	}
	
	if (si321x_proslic_init_indirect_regs(ua, card)) {
		printk(KERN_INFO "Indirect Registers failed to initialize on module %d.\n", card);
		return -1;
	}
	
	/* Clear scratch pad area */
	si321x_proslic_setreg_indirect(ua, card, 97,0);

	/* Clear digital loopback */
	ua32xx_reg_write(ua, card, 8, 0);

	/* Revision C optimization */
	ua32xx_reg_write(ua, card, 108, 0xeb);

	/* Disable automatic VBat switching for safety to prevent
	   Q7 from accidently turning on and burning out. */
	ua32xx_reg_write(ua, card, 67, 0x07);  /* Note, if pulse dialing has problems at high REN loads
					      change this to 0x17 */

	/* Turn off Q7 */
	ua32xx_reg_write(ua, card, 66, 1);

	wait_just_a_bit(10);
	
	/* Flush ProSLIC digital filters by setting to clear, while
	   saving old values */
	for (x=0;x<5;x++) {
		si321x_proslic_getreg_indirect(ua, card, x + 35,tmp+x);
		si321x_proslic_setreg_indirect(ua, card, x + 35, 0x8000);
	}
	
	/* Power up the DC-DC converter */
	if (si321x_powerup_proslic(ua, card, fast)) {
		printk(KERN_NOTICE "Unable to do INITIAL ProSLIC powerup on module %d\n", card);
		return -1;
	}
	
	if (!fast) {
		/* Check for power leaks */
		if (si321x_proslic_powerleak_test(ua, card)) {
			printk(KERN_NOTICE "ProSLIC module %d failed leakage test.  Check for short circuit\n", card);
		}
		/* Power up again */
		if (si321x_powerup_proslic(ua, card, fast)) {
			printk(KERN_NOTICE "Unable to do FINAL ProSLIC powerup on module %d\n", card);
			return -1;
		}
#ifndef NO_CALIBRATION
		/* Perform calibration */
		if(manual) {
			if (si321x_proslic_manual_calibrate(ua, card)) {
				printk(KERN_NOTICE "Proslic failed on Manual Calibration\n");
				if (si321x_proslic_manual_calibrate(ua, card)) {
					printk(KERN_NOTICE "Proslic Failed on Second Attempt to Calibrate Manually. (Try -DNO_CALIBRATION in Makefile)\n");
					return -1;
				}
				printk(KERN_NOTICE "Proslic Passed Manual Calibration on Second Attempt\n");
			}
		}
		else {
			if(si321x_proslic_calibrate(ua, card))  {
				printk(KERN_NOTICE "ProSlic died on Auto Calibration.\n");
				if (si321x_proslic_calibrate(ua, card)) {
					printk(KERN_NOTICE "Proslic Failed on Second Attempt to Auto Calibrate\n");
					return -1;
				}
				printk(KERN_NOTICE "Proslic Passed Auto Calibration on Second Attempt\n");
			}
		}
		/* Perform DC-DC calibration */
		ua32xx_reg_write(ua, card, 93, 0x99);
		wait_just_a_bit(5);
		
		res = ua32xx_reg_read(ua, card, 107, &r19);
		if(res){
			printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
			return -1;
		}
		
		if ((r19 < 0x2) || (r19 > 0xd)) {
			printk(KERN_NOTICE "DC-DC cal has a surprising direct 107 of 0x%02x. card %d!\n", r19,card);
			ua32xx_reg_write(ua, card, 107, 0x8);
		}

		/* Save calibration vectors */
		for (x=0;x<NUM_CAL_REGS;x++){
			res = ua32xx_reg_read(ua, card, 96+x, fxs->calregs.vals+x);
			if(res){
				printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
				return -1;
			}
		}
#endif
	} else {
		/* Restore calibration registers */
		for (x=0;x<NUM_CAL_REGS;x++){
			ua32xx_reg_write(ua, card, 96+x, fxs->calregs.vals[x]);
		}
	}
	
	/* Calibration complete, restore original values */
	for (x=0;x<5;x++) {
		si321x_proslic_setreg_indirect(ua, card, x + 35, tmp[x]);
	}
	
	if (si321x_proslic_verify_indirect_regs(ua, card)) {
		printk(KERN_NOTICE"!!!Indirect Registers failed verification.\n");
		return -1;
	}
	
	if (alawoverride)
  	ua32xx_reg_write(ua, card, 1, 0x20);
  else
    ua32xx_reg_write(ua, card, 1, 0x28);
 	// U-Law 8-bit interface
  ua32xx_reg_write(ua, card, 2, card * 8);    // Tx Start count low byte  0
  ua32xx_reg_write(ua, card, 3, 0);    // Tx Start count high byte 0
  ua32xx_reg_write(ua, card, 4, card * 8);    // Rx Start count low byte  0
  ua32xx_reg_write(ua, card, 5, 0);    // Rx Start count high byte 0
  ua32xx_reg_write(ua, card, 18, 0xff);     // clear all interrupt
  ua32xx_reg_write(ua, card, 19, 0xff);
  ua32xx_reg_write(ua, card, 20, 0xff);
  ua32xx_reg_write(ua, card, 73, 0x04);
	if (fxshonormode) {
		fxsmode = acim2tiss[fxo_modes[_opermode].acim];
		ua32xx_reg_write(ua, card, 10, 0x08 | fxsmode);
	}
  if (lowpower)
  	ua32xx_reg_write(ua, card, 72, 0x10);
  
  wait_just_a_bit(10);
  
  if (si321x_init_ring_generator_mode(ua, card)) {
		return -1;
	}
	
	if(fxstxgain || fxsrxgain) {
		res = ua32xx_reg_read(ua, card, 9, &r9);
		if(res){
			printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
			return -1;
		}
		switch (fxstxgain) {
			case 35:
				r9+=8;
				break;
			case -35:
				r9+=4;
				break;
			case 0: 
				break;
		}
	
		switch (fxsrxgain) {
			case 35:
				r9+=2;
				break;
			case -35:
				r9+=1;
				break;
			case 0:
				break;
		}
		res = ua32xx_reg_sync_wr(ua, card, 9, r9);
		if(res){
			printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
			return -1;
		}
	}
		
	if(debug){
		res = ua32xx_reg_read(ua, card, 9, &r9);
		if(res){
			printk(UA32XX_NAME": %s failed on line %d, error %d\n",__FUNCTION__,__LINE__,res);
			return -1;
		}
		printk(KERN_DEBUG "DEBUG: fxstxgain:%s fxsrxgain:%s\n",
				((r9/8) == 1)?"3.5":(((r9/4) == 1)?"-3.5":"0.0"),
				((r9/2) == 1)?"3.5":((r9%2)?"-3.5":"0.0"));
		printk(UA32XX_NAME " :DEBUG: fxstxgain:%s fxsrxgain:%s\n",
				((r9/8) == 1)?"3.5":(((r9/4) == 1)?"-3.5":"0.0"),
				((r9/2) == 1)?"3.5":((r9%2)?"-3.5":"0.0"));
	}
	
	fxs->lasttxhook = fxs->idletxhookstate;
	ua32xx_reg_write(ua, card, LINE_STATE, fxs->lasttxhook);
	
	//light the led
	if(!strcmp(ua->hw_name,"A1008")){
		oproto_cfg_led(&ua->proto, card, ua->modtype[card], CHAN_LED_LITHT);
//	}else if(!strcmp(ua->hw_name,"UC500")||
	}else if(!strcmp(ua->hw_name,"UC580")||
					 !strcmp(ua->hw_name,"UC320")||
					 !strcmp(ua->hw_name,"UC350")||
					 !strcmp(ua->hw_name,"UC540")||
					 !strcmp(ua->hw_name,"UC581")
					)
	{
		oproto_cfg_led(&ua->proto,card, ua->modtype[card], CHAN_LED_LITHT);
		msleep(500);
		oproto_cfg_led(&ua->proto,card, ua->modtype[card], CHAN_LED_BLACK);
	}
	
	return 0;
}

#ifdef CONFIG_DCRA
static int ua32xx_dcra_get_reg(unsigned int channo, unsigned int reg, uint8_t *value)
{
	struct ua32xx *ua = NULL;
  struct dahdi_chan  *chan = NULL;
  int ret;

  chan = dahdi_get_chan_from_num(channo);
  if(NULL == chan){
  	printk("ua32xx:failed invalid channel %d !\n", channo);
    return -1;
  }
  ua = chan->pvt;
  if(NULL == ua){
  	printk("ua32xx:failed  ua is NULL !\n");
    return -1;
  }

  if (ua->modtype[chan->chanpos - 1] == MOD_TYPE_FXS) { //FXS channel
  	if (reg >= NUM_REGS){
  		printk("ua32xx:failed fxs register %d must less than %d\n",reg, NUM_REGS);
      return -2;
    }
  } else { //FXO channel
    if (reg >= NUM_FXO_REGS){
    	printk("ua32xx:failed fxo register %d must less than %d\n", reg, NUM_FXO_REGS);
      return -2;
    }
  }
  
  ret = 0;
	if ((ua->modtype[chan->chanpos - 1] == MOD_TYPE_FXS)) {  //FXS channel
		if(reg == 8)
			*value = ua->reg8[chan->chanpos - 1];
		else if(reg == LINE_STATE)
			*value = ua->reg1shadow[chan->chanpos - 1];
		else if(reg == 68)
			*value = ua->reg0shadow[chan->chanpos - 1];
		else
			ret = ua32xx_reg_read(ua,chan->chanpos - 1, reg, value);
	}else{
		if(reg == 5)
			*value = ua->reg0shadow[chan->chanpos - 1];
		else if(reg == 29)
			*value = ua->reg1shadow[chan->chanpos - 1];
		else
			ret = ua32xx_reg_read(ua,chan->chanpos - 1, reg, value);
	}
	return ret;
}

static int ua32xx_dcra_get_ext_reg(unsigned int channo, unsigned int reg, uint16_t *value)
{
	struct ua32xx *ua = NULL;
  struct dahdi_chan  *chan = NULL;

  chan = dahdi_get_chan_from_num(channo);
  if(NULL == chan){
  	printk("ua32xx:failed invalid channel %d !\n", channo);
    return -1;
  }
  ua = chan->pvt;
  if(NULL == ua){
  	printk("ua32xx:failed  ua is NULL !\n");
    return -1;
  }

  if (ua->modtype[chan->chanpos - 1] == MOD_TYPE_FXS) { //FXS channel
  	if (reg >= NUM_INDIRECT_REGS){
    	printk("ua32xx:failed fxs register %d must less than  %d\n", reg, NUM_INDIRECT_REGS);
      return -2;
    }
    return si321x_proslic_getreg_indirect(ua, chan->chanpos -1, reg, value);
  }else{
  	printk("ua32xx:failed channel %d is not fxs channel\n", channo);
    return -1;
  }
}

static int ua32xx_dcra_set_reg(unsigned int channo, unsigned int reg, uint8_t value)
{
	struct ua32xx *ua = NULL;
  struct dahdi_chan *chan  = NULL;

  chan = dahdi_get_chan_from_num(channo);
  if(NULL == chan){
  	printk("ua32xx:failed invalid channel %d !\n", channo);
    return -1;
  }
  ua = chan->pvt;
  if(NULL == ua){
  	printk("ua32xx:failed  ua is NULL !\n");
    return -1;
  }

  if (ua->modtype[chan->chanpos - 1] == MOD_TYPE_FXS) { //FXS
  	if (reg >= NUM_REGS){
    	printk("ua32xx: failed fxs register %d must less than %d\n", reg, NUM_REGS);
      return -2;
    }
  } else { //FXO
  	if (reg >= NUM_FXO_REGS){
    	printk("ua32xx: failed  fxo register %d must less than %d\n", reg, NUM_FXO_REGS);
      return -2;
    }
  }
  
  return ua32xx_reg_write(ua, chan->chanpos - 1, reg, value&0xff);
}

static int ua32xx_dcra_set_ext_reg(unsigned int channo, unsigned int reg, uint16_t value)
{
	struct ua32xx *ua = NULL;
  struct dahdi_chan *chan  = NULL;

  chan = dahdi_get_chan_from_num(channo);
  if(NULL == chan){
  	printk("ua32xx:failed invalid channel %d !\n", channo);
   	return -1;
  }
  ua = chan->pvt;
  if(NULL == ua){
  	printk("ua32xx:failed  ua is NULL !\n");
    return -1;
  }

  if (ua->modtype[chan->chanpos - 1] == MOD_TYPE_FXS) { //FXS
  	if (reg >= NUM_REGS){
    	printk("ua32xx: failed fxs register %d must less than %d\n", reg, NUM_REGS);
      return -2;
    }
    return si321x_proslic_setreg_indirect(ua, chan->chanpos - 1, reg, value&0xffff);
  } else { //FXO
    printk("ua32xx:failed channel %d is not fxs channel\n", channo);
    return -1;
  }
}
#endif

static int ua32xx_detect(struct ua32xx* ua)
{
	int x,i,retval;
	int rt1,daisy_cards;
	
	if(!strcmp(ua->hw_name,"UC540")){
		daisy_cards = DAISY_CARDS_2;
	}else{
		daisy_cards = DAISY_CARDS_4;
	}
	
	x = 0;
	while(x < ua->hw_channels){
		retval = ua32xx_fxo_detect(ua,x);
  	if(retval < 0){
			printk(UA32XX_NAME": %s line %d error %d\n", __FUNCTION__,__LINE__,retval);
			return -1;
		}
		else if(retval == 0){
			if(ua->module_daisy &&
				 (ua->hw_channels > daisy_cards) &&
				 (x+daisy_cards <= ua->hw_channels)
				){
				for(i=1; i<daisy_cards; i++){
					rt1 = ua32xx_fxo_detect(ua,x+i);
					if(rt1 < 0){
						printk(UA32XX_NAME": %s line %d detection error(card %d)\n", __FUNCTION__,__LINE__,x+i);
						return -1;
					}else if(rt1 > 0){
					//	printk(UA32XX_NAME": %s line %d bad module(%d)\n",__FUNCTION__,__LINE__,x % daisy_cards);
					//	return -1;
						printk(UA32XX_NAME": Module %d Not installed\n", x+i);
					}
				}
				x += daisy_cards;
			}else{
				x += 1;
			}
		}else{
			retval = ua32xx_fxs_detect(ua,x);
			if(retval < 0){
				printk(UA32XX_NAME": %s line %d error %d\n", __FUNCTION__,__LINE__,retval);
				return -1;
			}
			else if(retval == 0){
				if(ua->module_daisy &&
				 (ua->hw_channels > daisy_cards) &&
				 (x+daisy_cards <= ua->hw_channels)
				){
					for(i=1; i<daisy_cards; i++){
						rt1 = ua32xx_fxs_detect(ua,x+i);
						if(rt1 < 0){
							printk(UA32XX_NAME": %s line %d detection error(card %d)\n", __FUNCTION__,__LINE__,x+i);
							return -1;
						}else if(rt1 > 0){
						//	printk(UA32XX_NAME": %s line %d bad module(%d)\n",__FUNCTION__,__LINE__,x % daisy_cards);
						//	return -1;
						printk(UA32XX_NAME": Module %d Not installed\n", x+i);
						}
					}
					x += daisy_cards;
				}else{
					x += 1;
				}
			}else{
				if(ua->module_daisy &&
				 (ua->hw_channels > daisy_cards) &&
				 (x+daisy_cards <= ua->hw_channels)
				){
					for(i=0;i<daisy_cards;i++)
						printk(UA32XX_NAME ": Module %d Not installed\n", x+i);
					x += daisy_cards;
				}else{
					printk(UA32XX_NAME ": Module %d Not installed\n", x);
					x += 1;
				}
			}	
		}
	}
	
	return 0;
}

static int ua32xx_hw_init(struct ua32xx* ua)
{
	int i,retval;
	uint8_t slotid;

	/* step 1: get frimware version*/
	retval = ua32xx_get_fwver(ua);
	if(retval){
		printk(UA32XX_NAME": %s line %d error %d\n", __FUNCTION__,__LINE__,retval);
		return -1;
	}
	printk(UA32XX_NAME": fimware %d.%d.%d build %d\n", ua->fw_ver.major & 0xff, 
				ua->fw_ver.minor & 0xff, ua->fw_ver.bugfix & 0xff, ua->fw_ver.build & 0xffff);
	/**/
	if(!strcmp(ua->hw_name,"A1008")){
		retval = oproto_get_slotid(&ua->proto,&slotid);
		if(retval){
			printk(UA32XX_NAME": %s line %d error %d\n", __FUNCTION__,__LINE__,retval);
			return -1;
		}
		ua->slot_id = slotid;
		printk(UA32XX_NAME": device %d running on slot %d.\n", ua->ifaces_index, ua->slot_id);
	}
				
	/* step 2: reset all the modules */
	retval = oproto_ext_reset(&ua->proto, ext_reset_len, ext_reset_delay);
	if(retval){
		printk(UA32XX_NAME": %s line %d error %d\n", __FUNCTION__,__LINE__,retval);
		return -2;
	}
		
	/* step 3: detect module type is si3215(fxs) or si3050(fxo) */	
	retval = ua32xx_detect(ua);
	if(retval){
		printk(UA32XX_NAME": %s line %d error %d\n", __FUNCTION__,__LINE__,retval);
		return -3;
	}
	
	for (i=0; i < sizeof(ua->chans)/sizeof(ua->chans[0]); ++i) {
		ua->chans[i] = &ua->_chans[i];
	}
	
	/**/             
	for(i=0;i<NUM_CARDS;i++){
		uint8_t sane=0,readi=0;
		if(ua32xx_test_cardflag(ua, i)){
			if(ua->modtype[i] == MOD_TYPE_FXO){
				retval = si3050_init_voicedaa(ua,i);
				if(retval){
					ua32xx_clear_cardflag(ua, i);
					printk(UA32XX_NAME": %s init card %d failed.\n", __FUNCTION__, i);
				}
			}else{
				retval=si321x_init_proslic(ua, i, 0, 0, sane);
				if(!retval){
					if (debug) {
						ua32xx_reg_read(ua, i, LOOP_I_LIMIT, &readi);
         		printk(KERN_DEBUG "Proslic module %d loop current is %dmA\n",i,
                                ((readi*3)+20));
         		printk(UA32XX_NAME ": Proslic module %d loop current is %dmA\n",i,
                                ((readi*3)+20));
          }
				}else{
					if(retval != -2){
						sane=1;
						//Init with Manual Calibration 
						if (!si321x_init_proslic(ua, i, 0, 1, sane)) {
              if (debug) {
              	ua32xx_reg_read(ua, i, LOOP_I_LIMIT, &readi);
                printk(KERN_DEBUG "Proslic module %d loop current is %dmA\n",i,
                                        ((readi*3)+20));
                printk(UA32XX_NAME ": Proslic module %d loop current is %dmA\n",i,
                                        ((readi*3)+20));
              }
							printk(KERN_INFO "Module %d: Calibration -- MANUAL FXS\n",i);
						} else {
							ua32xx_clear_cardflag(ua, i);
							ua->chans[i]->sigcap = __DAHDI_SIG_FXO | DAHDI_SIG_BROKEN;
							printk(KERN_NOTICE "Module %d: FAILED FXS (%s)\n", i, fxshonormode ? fxo_modes[_opermode].name : "FCC");
						} 
					}else
						ua32xx_clear_cardflag(ua, i);
				}
			}
		}
	}
	ua->init_ok = 1;
	
	return 0;
}

static void ua32xx_fxs_hooksig(struct ua32xx* ua, const int card, enum dahdi_txsig txsig)
{
	struct fxs *const fxs = &ua->mod[card].fxs;
	switch (txsig) {
	case DAHDI_TXSIG_ONHOOK:
		switch (ua->span.chans[card]->sig) {
		case DAHDI_SIG_FXOKS:
		case DAHDI_SIG_FXOLS:
			/* Can't change Ring Generator during OHT */
			if (!fxs->ohttimer) {														
				si321x_set_ring_generator_mode(ua, card, fxs->vmwi_hvac);											
				fxs->lasttxhook = fxs->vmwi_hvac ? SLIC_LF_RINGING : fxs->idletxhookstate;		
			} else {
				fxs->lasttxhook = fxs->idletxhookstate;
			}
			break;
		case DAHDI_SIG_EM:
			fxs->lasttxhook = fxs->idletxhookstate;
			break;
		case DAHDI_SIG_FXOGS:
			fxs->lasttxhook = SLIC_LF_TIP_OPEN;
			break;
		}
		break;
	case DAHDI_TXSIG_OFFHOOK:
		switch (ua->span.chans[card]->sig) {
		case DAHDI_SIG_EM:
			fxs->lasttxhook = SLIC_LF_ACTIVE_REV;
			break;
		default:
			fxs->lasttxhook = fxs->idletxhookstate;
			break;
		}
		break;
	case DAHDI_TXSIG_START:
		/* Set ringer mode */
		si321x_set_ring_generator_mode(ua, card, 0);
		fxs->lasttxhook = SLIC_LF_RINGING;
		break;
	case DAHDI_TXSIG_KEWL:
		fxs->lasttxhook = SLIC_LF_OPEN;
		break;
	default:
		printk(KERN_NOTICE "ua32xx: Can't set tx state to %d\n", txsig);
		printk(UA32XX_NAME ": Can't set tx state to %d\n", txsig);
		return;
	}
	ua32xx_reg_write(ua, card, LINE_STATE, fxs->lasttxhook);
	
	if (debug) {
		printk(KERN_DEBUG
		       "Setting FXS hook state to %d (%02x) on card: %d\n", 
		       txsig, fxs->lasttxhook,card);
		printk(UA32XX_NAME
		       ": Setting FXS hook state to %d (%02x) on card: %d\n", 
		       txsig, fxs->lasttxhook,card);
	}
}

static struct ua32xx_blk_work *get_work_container(struct ua32xx* ua)
{
	int x;
	for(x=0;x<BLK_WK_COUNT;x++){
		if(ua->workpool[x].used == 0){
			spin_lock(&ua->blkw_lock);
			ua->workpool[x].used = 1;
			spin_unlock(&ua->blkw_lock);
			
			return &ua->workpool[x];
		}
	}
	return NULL;
}

static void free_work_container(struct ua32xx_blk_work *cont)
{
	struct ua32xx* ua = cont->ua;
	spin_lock(&ua->blkw_lock);
	cont->used = 0;
	spin_unlock(&ua->blkw_lock);
}

static void buffer_recvprep(struct ua32xx *ua, unsigned char *buf)
{
	int x,y;
	for(y=0;y<DAHDI_CHUNKSIZE;y++){
		for(x=0;x<ua->hw_channels/*NUM_CARDS*/;x++){
			if (ua32xx_test_cardflag(ua, x)) {
				ua->chans[x]->readchunk[y] = buf[y*ua->max_channel + x];
			}
		}
	}
	
	if(cidbeforering){
  	for(x=0; x<NUM_CARDS; x++){
  		if (ua->modtype[ua->chans[x]->chanpos - 1] == MOD_TYPE_FXO)
  			if(ua->mod[ua->chans[x]->chanpos - 1].fxo.offhook == 0){
  				/*unsigned int *p_readchunk, *p_cid_history;

          p_readchunk = (unsigned int*)ua->chans[x].readchunk;
          p_cid_history = (unsigned int*)(ua->cid_history_buf[x] + ua->cid_history_ptr[x]);*/

          if(ua->cid_state[x] == CID_STATE_IDLE)	/* we need copy data to the cid voice buffer */
          {
          	memcpy(ua->cid_history_buf[x] + ua->cid_history_ptr[x], ua->chans[x]->readchunk, DAHDI_CHUNKSIZE);
            ua->cid_history_ptr[x] = (ua->cid_history_ptr[x] + DAHDI_CHUNKSIZE)%(cidbuflen * DAHDI_MAX_CHUNKSIZE);
          }
          else if (ua->cid_state[x] == CID_STATE_RING_ON) {
          	/* During ringing debounce, the ring signal is copied into cid_history_buf[],
             * So we should exclude it by subtractring cutcidbufheadlen ,
             * if not subtractring cutcidbufheadlen , the signalls during debouncing is copied 
             * into the space between 1st and 2nd ring, thus asterisk can't get CID
             */
            ua->cid_history_clone_cnt[x] = cidbuflen - cutcidbufheadlen;
          }
          else if (ua->cid_state[x] == CID_STATE_RING_OFF){
          	if(ua->cid_history_clone_cnt[x]){
          		memcpy(ua->chans[x]->readchunk, ua->cid_history_buf[x] + ua->cid_history_ptr[x], DAHDI_MAX_CHUNKSIZE);
              ua->cid_history_clone_cnt[x]--;
              ua->cid_history_ptr[x] = (ua->cid_history_ptr[x] + DAHDI_MAX_CHUNKSIZE)%(cidbuflen * DAHDI_MAX_CHUNKSIZE);
            }
            else{
          	  ua->cid_state[x] = CID_STATE_WAIT_RING_FINISH;
              ua->cid_history_clone_cnt[x] = cidtimeout; /* wait 6 sec, if no ring, return to idle */
            }
          }
          else if(ua->cid_state[x] == CID_STATE_WAIT_RING_FINISH){
            if(ua->cid_history_clone_cnt[x] > 0)
            	ua->cid_history_clone_cnt[x]--;
            else{
              ua->cid_state[x] = CID_STATE_IDLE;
              ua->cid_history_ptr[x] = 0;
              ua->cid_history_clone_cnt[x] = 0;
            }
          }
        }
    }		
  }
    
	for(x=0;x<ua->hw_channels/*NUM_CARDS*/;x++){
		if (ua32xx_test_cardflag(ua, x)) {
			dahdi_ec_chunk(ua->chans[x], ua->chans[x]->readchunk, ua->chans[x]->writechunk);
		}
	}
	dahdi_receive(&ua->span);
}

static void ua32xx_recvprep(struct urb* urb)
{
	struct oproto* proto = (struct oproto*)urb->context;
	struct ua32xx *ua = container_of(proto, struct ua32xx, proto);
	
	buffer_recvprep(ua, (unsigned char *)urb->transfer_buffer);
}

static void buffer_transprep(struct ua32xx *ua, unsigned char *buf)
{
	int x,y;
	dahdi_transmit(&ua->span);
	for (y=0;y<DAHDI_CHUNKSIZE;y++) {
		for(x=0;x<ua->hw_channels/*NUM_CARDS*/;x++){
			if (ua32xx_test_cardflag(ua, x)) {
				buf[y*ua->max_channel + x] = ua->chans[x]->writechunk[y];
			}
		}
	}	
}

static void ua32xx_transprep(struct urb* urb)
{
	struct oproto* proto = (struct oproto*)urb->context;
	struct ua32xx *ua = container_of(proto, struct ua32xx, proto);
	
	buffer_transprep(ua, (unsigned char *)urb->transfer_buffer);
}

static void slaves_txrx(void)
{
	int x;
	unsigned char *buf;
	struct urb* trans_urb = NULL;
	
	for(x=0;x<UA_MAX_IFACES;x++){
  	struct ua32xx *ua = ifaces[x];
  	if(ua && (ua != ua32_master) && (ua->tdm_stat == OP_START_TDM) && (!ua->dead)){
  		buf = ua->proto.tdm_tmpbuf;
  		
  		/* for receiver */
  		if(tdm_dahdi_buf_load(&(ua->proto.tdm_dahdi_rx_buf)) > 0){
  			tdm_dahdi_buf_pop(&(ua->proto.tdm_dahdi_rx_buf), buf);
				buffer_recvprep(ua, buf);
			}
			
			/* for transmiter */
			trans_urb = __oproto_get_tdm_bulkout_urb(&ua->proto);
			if (trans_urb) {
				ua32xx_transprep(trans_urb);
				__oproto_refill_tdm_urb(&ua->proto, USB_DIR_OUT, trans_urb);
				usb_submit_urb(trans_urb, GFP_ATOMIC);
			}else{
				printk("<---!!!!!!---> %s device %d the tx urbpool is not big enough!\n",__FUNCTION__, ua->ifaces_index);
			}	
  	}
  }
}

static void tdm_workhandler(struct ua32xx *ua, struct urb* urb)
{
	unsigned char *buf;
	struct urb* trans_urb = NULL;
	
	if(!ua || !urb){
		printk(KERN_DEBUG "<---!!!!!!---> %s bad parameter!\n",__FUNCTION__);
		return;
	}
	if(ua == ua32_master){ /* for master span handler */
		//tdm receiver
		ua32xx_recvprep(urb);
	
		__oproto_refill_tdm_urb(&ua->proto, USB_DIR_IN, urb);
		usb_submit_urb(urb, GFP_ATOMIC);	/* re-use the urb for rx */
	
		//tdm transmiter
		trans_urb = __oproto_get_tdm_bulkout_urb(&ua->proto);
		if (trans_urb) {
			ua32xx_transprep(trans_urb);
			__oproto_refill_tdm_urb(&ua->proto, USB_DIR_OUT, trans_urb);
			usb_submit_urb(trans_urb, GFP_ATOMIC);
		}else{
			printk("<---!!!!!!---> %s device %d the tx urbpool is not big enough!\n",__FUNCTION__, ua->ifaces_index);
		}
		
		//for slave spans TX RX 
		if(g_ifaces > 1)
			slaves_txrx();
	}else{/* for slave spans' handler */
		buf = (unsigned char *)urb->transfer_buffer;
		if(tdm_dahdi_buf_push(&(ua->proto.tdm_dahdi_rx_buf), buf)){
			if(tdmdebug)
				printk("!!!!!!device %d tdm dahdi RX buffer overflow!!!!!!\n",ua->ifaces_index);
		}
		__oproto_refill_tdm_urb(&ua->proto, USB_DIR_IN, urb);
		usb_submit_urb(urb, GFP_ATOMIC);	/* re-use the urb for rx */
	}
}

static void block_work_handler(struct work_struct *work)
{
	struct ua32xx_blk_work *block_work = container_of(work, struct ua32xx_blk_work, work);
	struct ua32xx* ua = block_work->ua;
	int card = block_work->card;
	
	switch(block_work->wktype){
	case WKTYPE_RING_GEN_MODE:
		si321x_set_ring_generator_mode(ua,card,block_work->data.p_rgm.mode);
		break;
	case WKTYPE_FXS_HOOKSIG:
		ua32xx_fxs_hooksig(ua,card,block_work->data.p_hsig.txsig);
		if(block_work->data.p_hsig.dahdi_txsig)
			dahdi_hooksig(ua->chans[card], block_work->data.p_hsig.txsig);
		break;
	case WKTYPE_INIT_PROSLIC:
		si321x_init_proslic(ua, card, block_work->data.p_init.fast, block_work->data.p_init.manual, block_work->data.p_init.sane);
		break;
	}
	free_work_container(block_work);
	if(atomic_read(&(ua->chan_block_cnt[card])))
		atomic_dec(&(ua->chan_block_cnt[card]));
}

int create_block_workthread(struct ua32xx* ua, int card, int wktype,void *data)
{
	struct ua32xx_blk_work *block_work = NULL;
	struct rgm *p_rgm;
	struct fxs_init *p_init;
	struct hsig *p_hsig;
	
	if(ua->dead)
		return 0;
		
	block_work = get_work_container(ua);
	if(!block_work){
		printk(KERN_DEBUG "!!!!---> workpool is not big enough.\n");
		return -1;
	}
	
	INIT_WORK(&block_work->work,block_work_handler);	
	block_work->ua = ua;
	block_work->card = card;
	block_work->wktype = wktype;
	switch(wktype){
	case WKTYPE_RING_GEN_MODE:
		p_rgm = (struct rgm *)data;
		block_work->data.p_rgm.mode = p_rgm->mode;			
		break;
	case WKTYPE_FXS_HOOKSIG:
		p_hsig = (struct hsig *)data;
		block_work->data.p_hsig.txsig = p_hsig->txsig;
		block_work->data.p_hsig.dahdi_txsig = p_hsig->dahdi_txsig;
		break;
	case WKTYPE_INIT_PROSLIC:
		p_init = (struct fxs_init *)data;
		block_work->data.p_init.fast = p_init->fast;
		block_work->data.p_init.manual = p_init->manual;
		block_work->data.p_init.sane = p_init->sane;
		break;	
	}
	queue_work(ua->chan_wq[card], &block_work->work);
	atomic_inc(&(ua->chan_block_cnt[card]));
	
	return 0;
}

static int ua32xx_hooksig(struct dahdi_chan *chan, enum dahdi_txsig txsig)
{
	struct ua32xx *ua = chan->pvt;
	int chan_entry = chan->chanpos - 1;
	struct hsig hsig;
		
	if(ua32xx_test_cardflag(ua, chan_entry)){	
		if (ua->modtype[chan_entry] == MOD_TYPE_FXO) {
			/* XXX Enable hooksig for FXO XXX */
			switch(txsig) {
				case DAHDI_TXSIG_START:
				case DAHDI_TXSIG_OFFHOOK:
					ua->mod[chan_entry].fxo.offhook = 1;
					ua->mod[chan_entry].fxo.polaritycountwhenoffhook = 0;
					ua->mod[chan_entry].fxo.callout = 1;
					//ua32xx_reg_write(ua,chan_entry,5,0x9);
					ua->mod[chan_entry].fxo.regwr.reg = 5;
					ua->mod[chan_entry].fxo.regwr.value = 0x9;
          ua->mod[chan_entry].fxo.regwr.flag = 0;
          if(cidbeforering){
          	ua->cid_state[chan->chanpos - 1] = CID_STATE_IDLE;
            ua->cid_history_clone_cnt[chan->chanpos - 1] = 0;
            ua->cid_history_ptr[chan->chanpos - 1] = 0;
            memset(ua->cid_history_buf[chan->chanpos - 1], DAHDI_LIN2X(0, chan), cidbuflen * DAHDI_MAX_CHUNKSIZE);
          }			
          break;
				case DAHDI_TXSIG_ONHOOK:	
					ua->mod[chan_entry].fxo.offhook = 0;
					ua->mod[chan_entry].fxo.callout = 0;	
					//ua32xx_reg_write(ua,chan_entry,5,0x8);
					ua->mod[chan_entry].fxo.regwr.reg = 5;
					ua->mod[chan_entry].fxo.regwr.value = 0x8;
					ua->mod[chan_entry].fxo.regwr.flag = 0;
					break;
				default:
					printk(UA32XX_NAME": fxo card %d: Can't set tx state to %d\n", chan_entry,txsig);
					break;
			}
		} else {
			hsig.txsig = txsig;
			hsig.dahdi_txsig = 0;
			create_block_workthread(ua,chan_entry,WKTYPE_FXS_HOOKSIG,&hsig);
		}
	}
	return 0;
}

static int ua32xx_open(struct dahdi_chan *chan)
{
	struct ua32xx *ua = chan->pvt;
	
	if (!ua32xx_test_cardflag(ua, chan->chanpos - 1))
		return -ENODEV;
	if (ua->dead)
		return -ENODEV;
	ua->usecount++;
	return 0;
}

static int ua32xx_close(struct dahdi_chan *chan)
{
	struct ua32xx *ua = chan->pvt;
	struct fxs *const fxs = &ua->mod[chan->chanpos - 1].fxs;
	
	if(ua->usecount == 0)
		return 0;
	ua->usecount--;
	if (ua32xx_test_cardflag(ua, chan->chanpos - 1) && (ua->modtype[chan->chanpos - 1] == MOD_TYPE_FXS)) {
		int idlehookstate;
		idlehookstate = POLARITY_XOR ?
						SLIC_LF_ACTIVE_REV :
						SLIC_LF_ACTIVE_FWD;
		fxs->idletxhookstate = idlehookstate;
	}
	/* If we're dead, release us now */
	if (!ua->usecount && ua->dead){ 
		ua32xx_stop(ua);
		free_ua32xx(ua);
	}
	return 0;	
}

static int set_vmwi(struct ua32xx *ua, int chan_idx)
{
	struct fxs *const fxs = &ua->mod[chan_idx].fxs;
	
	if (fxs->vmwi_active_messages) {
		fxs->vmwi_lrev =
		    (fxs->vmwisetting.vmwi_type & DAHDI_VMWI_LREV) ? 1 : 0;
		fxs->vmwi_hvdc =
		    (fxs->vmwisetting.vmwi_type & DAHDI_VMWI_HVDC) ? 1 : 0;
		fxs->vmwi_hvac =
		    (fxs->vmwisetting.vmwi_type & DAHDI_VMWI_HVAC) ? 1 : 0;
	} else {
		fxs->vmwi_lrev = 0;
		fxs->vmwi_hvdc = 0;
		fxs->vmwi_hvac = 0;
	}

	if (debug) {
		printk(UA32XX_NAME ": Setting VMWI on channel %d, messages=%d, "
				"lrev=%d, hvdc=%d, hvac=%d\n",
				chan_idx,
				fxs->vmwi_active_messages,
				fxs->vmwi_lrev,
				fxs->vmwi_hvdc,
				fxs->vmwi_hvac
			  );
	}
	if (fxs->vmwi_hvac) {
		/* Can't change ring generator while in On Hook Transfer mode*/
		if (!fxs->ohttimer) {
			if (POLARITY_XOR)
				fxs->idletxhookstate |= SLIC_LF_REVMASK;
			else
				fxs->idletxhookstate &= ~SLIC_LF_REVMASK;
			/* Set ring generator for neon */
			si321x_set_ring_generator_mode(ua, chan_idx, 1);
			
			/* Activate ring to send neon pulses */
			fxs->lasttxhook = SLIC_LF_RINGING;
			/**/
			ua32xx_reg_write(ua,chan_idx, LINE_STATE, fxs->lasttxhook);
		}
	} else {
		if (fxs->neonringing) {
			/* Set ring generator for normal ringer */
			si321x_set_ring_generator_mode(ua, chan_idx, 0);
			
			/* ACTIVE, polarity determined later */
			fxs->lasttxhook = SLIC_LF_ACTIVE_FWD;
		} else if ((fxs->lasttxhook == SLIC_LF_RINGING) ||
					(fxs->lasttxhook == SLIC_LF_OPEN)) {
			/* Can't change polarity while ringing or when open,
				set idlehookstate instead */
			if (POLARITY_XOR)
				fxs->idletxhookstate |= SLIC_LF_REVMASK;
			else
				fxs->idletxhookstate &= ~SLIC_LF_REVMASK;
				
			printk(UA32XX_NAME ": Unable to change polarity on channel"
					    "%d, lasttxhook=0x%X\n",
							chan_idx,
							fxs->lasttxhook
							);
			return 0;
		}
		if (POLARITY_XOR) {
			fxs->idletxhookstate |= SLIC_LF_REVMASK;
			fxs->lasttxhook |= SLIC_LF_REVMASK;
		} else {
			fxs->idletxhookstate &= ~SLIC_LF_REVMASK;
			fxs->lasttxhook &= ~SLIC_LF_REVMASK;
		}
		/**/
		ua32xx_reg_write(ua,chan_idx, LINE_STATE, fxs->lasttxhook);
	}
	return 0;
}

static int ua32xx_ioctl(struct dahdi_chan *chan, unsigned int cmd, unsigned long data)
{
	struct wctdm_stats stats;
	struct wctdm_regs regs;
	struct wctdm_regop regop;
	struct wctdm_echo_coefs echoregs;
	struct dahdi_hwgain hwgain;
	struct ua32xx *ua = chan->pvt;
	struct fxs *const fxs = &ua->mod[chan->chanpos - 1].fxs;
	
	unsigned char buf[(NUM_REGS > NUM_FXO_REGS) ? NUM_REGS : NUM_FXO_REGS];
	int x,retval;
  	
	switch (cmd) {
	case DAHDI_ONHOOKTRANSFER:
		if (ua->modtype[chan->chanpos - 1] != MOD_TYPE_FXS)
			return -EINVAL;
		if (get_user(x, (__user int *) data))
			return -EFAULT;
		fxs->ohttimer = x << 3;

		/* Active mode when idle */
		fxs->idletxhookstate = POLARITY_XOR ?
				SLIC_LF_ACTIVE_REV : SLIC_LF_ACTIVE_FWD;
		if (fxs->neonringing) {
			/* keep same Forward polarity */
			fxs->lasttxhook = SLIC_LF_OHTRAN_FWD;
			if(debug){
				printk("ioctl: Start OnHookTrans, card %d\n",
						chan->chanpos - 1);
				printk(UA32XX_NAME ": ioctl: Start OnHookTrans, card %d\n",
						chan->chanpos - 1);						
			}

			
			ua32xx_reg_write(ua,chan->chanpos - 1, LINE_STATE, fxs->lasttxhook);
		} else if (fxs->lasttxhook == SLIC_LF_ACTIVE_FWD ||
			    fxs->lasttxhook == SLIC_LF_ACTIVE_REV) {
			/* Apply the change if appropriate */
			fxs->lasttxhook = POLARITY_XOR ?
				SLIC_LF_OHTRAN_REV : SLIC_LF_OHTRAN_FWD;
			if(debug){
				printk("ioctl: Start OnHookTrans, card %d\n",
						chan->chanpos - 1);
				printk(UA32XX_NAME ": ioctl: Start OnHookTrans, card %d\n",
						chan->chanpos - 1);						
			}

			
			ua32xx_reg_write(ua,chan->chanpos - 1, LINE_STATE, fxs->lasttxhook);
		}
		break;
	case DAHDI_SETPOLARITY:	
		if (ua->modtype[chan->chanpos - 1] != MOD_TYPE_FXS)
			return -EINVAL;
		
		if (get_user(x, (__user int *) data))
			return -EFAULT;
		/* Can't change polarity while ringing or when open */
		if ((fxs->lasttxhook == SLIC_LF_RINGING) ||
		    (fxs->lasttxhook == SLIC_LF_OPEN))
			return -EINVAL;
		fxs->reversepolarity = x;
		if (POLARITY_XOR) {
			fxs->lasttxhook |= SLIC_LF_REVMASK;
			printk("ioctl: Reverse Polarity, card %d\n",
					chan->chanpos - 1);
		} else {
			fxs->lasttxhook &= ~SLIC_LF_REVMASK;
			printk("ioctl: Normal Polarity, card %d\n",
					chan->chanpos - 1);
		}
		
		ua32xx_reg_write(ua,chan->chanpos - 1, LINE_STATE, fxs->lasttxhook);
		break;
	case DAHDI_VMWI_CONFIG:	
		if (ua->modtype[chan->chanpos - 1] != MOD_TYPE_FXS)
			return -EINVAL;
		if (copy_from_user(&(fxs->vmwisetting), (__user void *) data,
						sizeof(fxs->vmwisetting)))
			return -EFAULT;
		set_vmwi(ua, chan->chanpos - 1);
		break;
	case DAHDI_VMWI:
		if (ua->modtype[chan->chanpos - 1] != MOD_TYPE_FXS)
			return -EINVAL;
		if (get_user(x, (__user int *) data))
			return -EFAULT;
		if (0 > x)
			return -EFAULT;
		fxs->vmwi_active_messages = x;
		set_vmwi(ua, chan->chanpos - 1);
		break;
	case WCTDM_GET_STATS:		
		if (ua->modtype[chan->chanpos - 1] == MOD_TYPE_FXS) {
			ua32xx_reg_read(ua, chan->chanpos - 1, 80, buf);
			ua32xx_reg_read(ua, chan->chanpos - 1, 81, buf+1);
			ua32xx_reg_read(ua, chan->chanpos - 1, 82, buf+2);
			stats.tipvolt = buf[0] * -376;
			stats.ringvolt = buf[1] * -376;
			stats.batvolt = buf[2] * -376;
		} else if (ua->modtype[chan->chanpos - 1] == MOD_TYPE_FXO) {
			stats.tipvolt = (signed char)ua->reg1shadow[(chan->chanpos - 1)&0x1f] * 1000;
      stats.ringvolt = (signed char)ua->reg1shadow[(chan->chanpos - 1)&0x1f] * 1000;
      stats.batvolt = (signed char)ua->reg1shadow[(chan->chanpos - 1)&0x1f] * 1000;
		} else 
			return -EINVAL;
		
		if (copy_to_user((__user void *)data, &stats, sizeof(stats)))
			return -EFAULT;
		break;
	case WCTDM_GET_REGS:
		if (ua->modtype[chan->chanpos - 1] == MOD_TYPE_FXS) {
			for (x=0;x<NUM_INDIRECT_REGS;x++)
				 si321x_proslic_getreg_indirect(ua, chan->chanpos -1, x, &regs.indirect[x]);
			for (x=0;x<NUM_REGS;x++){
				if(x == 8)
					regs.direct[x] = ua->reg8[chan->chanpos - 1];
				else if(x == LINE_STATE)
					regs.direct[x] = ua->reg1shadow[chan->chanpos - 1];
				else if(x == 68)
					regs.direct[x] = ua->reg0shadow[chan->chanpos - 1];
				else{
					retval = ua32xx_reg_read(ua, chan->chanpos - 1, x, regs.direct+x);
					if(retval){
						printk(UA32XX_NAME": %s line %d error %d\n", __FUNCTION__, __LINE__,retval);
						return -EFAULT;
					}
				}
			}
		} else {
			memset(&regs, 0, sizeof(regs));
			for (x=0;x<NUM_FXO_REGS;x++){
				if(x == 5)
					regs.direct[x] = ua->reg0shadow[chan->chanpos - 1];
				else if(x == 29)
					regs.direct[x] = ua->reg1shadow[chan->chanpos - 1];
				else{
					retval = ua32xx_reg_read(ua, chan->chanpos - 1, x, regs.direct+x);
					if(retval){
						printk(UA32XX_NAME": %s line %d error %d\n", __FUNCTION__, __LINE__,retval);
						return retval;
					}
				}
			}
		}
		if (copy_to_user((__user void *)data, &regs, sizeof(regs)))
			return -EFAULT;
		break;
	case WCTDM_SET_REG:
		if (copy_from_user(&regop, (__user void *) data, sizeof(regop)))
			return -EFAULT;
		if (regop.indirect) {
			if (ua->modtype[chan->chanpos - 1] != MOD_TYPE_FXS)
				return -EINVAL;
			printk(KERN_INFO"Setting indirect %d to 0x%04x on %d\n", regop.reg, regop.val, chan->chanpos);
			retval = si321x_proslic_setreg_indirect(ua, chan->chanpos - 1, regop.reg, regop.val);
			if(retval < 0){
				printk(UA32XX_NAME": %s failed %d\n", __FUNCTION__, retval);
				return retval;
			}
		} else {
			regop.val &= 0xff;
			printk(KERN_INFO "Setting direct %d to %04x on %d\n", regop.reg, regop.val, chan->chanpos);
			ua32xx_reg_write(ua, chan->chanpos - 1, regop.reg, regop.val);
		}
		break;
	case WCTDM_SET_ECHOTUNE:
		printk(KERN_INFO "-- Setting echo registers: \n");
		if (copy_from_user(&echoregs, (__user void *)data, sizeof(echoregs)))
			return -EFAULT;
		if (ua->modtype[chan->chanpos - 1] == MOD_TYPE_FXO) {
			/* Set the ACIM register */
			ua32xx_reg_write(ua, chan->chanpos - 1, 30,(1 == fxofullscale) ? (echoregs.acim|0x10) : echoregs.acim);

			/* Set the digital echo canceller registers */
			ua32xx_reg_write(ua, chan->chanpos - 1, 45, echoregs.coef1);
			ua32xx_reg_write(ua, chan->chanpos - 1, 46, echoregs.coef2);
			ua32xx_reg_write(ua, chan->chanpos - 1, 47, echoregs.coef3);
			ua32xx_reg_write(ua, chan->chanpos - 1, 48, echoregs.coef4);
			ua32xx_reg_write(ua, chan->chanpos - 1, 49, echoregs.coef5);
			ua32xx_reg_write(ua, chan->chanpos - 1, 50, echoregs.coef6);
			ua32xx_reg_write(ua, chan->chanpos - 1, 51, echoregs.coef7);
			ua32xx_reg_write(ua, chan->chanpos - 1, 52, echoregs.coef8);
			
			printk(KERN_INFO "-- Set echo registers successfully\n");
		}else{
			return -EINVAL;
		}
		break;
	case DAHDI_SET_HWGAIN:			
		if (copy_from_user(&hwgain, (__user void *) data, sizeof(hwgain)))
			return -EFAULT;

		si3050_set_hwgain(ua, chan->chanpos-1, hwgain.newgain, hwgain.tx);
		
		if (debug){
			printk(KERN_DEBUG "Setting hwgain on channel %d to %d for %s direction\n", 
				chan->chanpos-1, hwgain.newgain, hwgain.tx ? "tx" : "rx");
			printk(UA32XX_NAME ": Setting hwgain on channel %d to %d for %s direction\n", 
				chan->chanpos-1, hwgain.newgain, hwgain.tx ? "tx" : "rx");				
		}

					
		break;		
	default:
		return -ENOTTY;
	}
	
	return 0;
}

static inline struct ua32xx *ua32xx_from_span(struct dahdi_span *span)
{
	return container_of(span, struct ua32xx, span);
}

static int ua32xx_watchdog(struct dahdi_span *span, int event)
{
	if(debug)
		printk(UA32XX_NAME": %s called.\n", __FUNCTION__);
		
	return 0;
}

static const struct dahdi_span_ops ua32xx_span_ops = {
	.owner = THIS_MODULE,
	.hooksig = ua32xx_hooksig,
	.open = ua32xx_open,
	.close = ua32xx_close,
	.ioctl = ua32xx_ioctl,
	.watchdog = ua32xx_watchdog,
};

static int ua32xx_software_init(struct ua32xx* ua)
{
	int x;
	int retval = 0;
  
  /* DAHDI stuff */
  sprintf(ua->span.name, "UA32XX/%d", ua->hw_channels);
//  snprintf(ua->span.desc, sizeof(ua->span.desc) - 1, "ua32xx Card %d", ua->ifaces_index);
  snprintf(ua->span.desc, sizeof(ua->span.desc) - 1, "ua32xx Card %d", ua->ifaces_index);

#if DAHDI_VERSION_CODE >= VERSION_CODE(2,6,0)    
  ua->ddev->manufacturer = "SGM";
  ua->ddev->devicetype = ua->hw_name;
  
  ua->ddev->location = kasprintf(GFP_KERNEL,"USB Bus %02d parent %d devnum %02d", 
    														ua->proto.dev->bus->busnum, ua->proto.dev->parent->devnum, ua->proto.dev->devnum);
  if(debug)
  	printk(UA32XX_NAME": device loactioan : %s\n",ua->ddev->location);
  
  if(!ua->ddev->location){
   	return -ENOMEM;
  }
#else
	ua->span.manufacturer = "SGM";
  dahdi_copy_string(ua->span.devicetype, ua->hw_name, sizeof(ua->span.devicetype));
  snprintf(ua->span.location, sizeof(ua->span.location) - 1, "USB Bus %02d parent %d devnum %02d", 
    				ua->proto.dev->bus->busnum, ua->proto.dev->parent->devnum, ua->proto.dev->devnum);
  if(debug)
  	printk(UA32XX_NAME": device loactioan : %s\n",ua->span.location);
#endif
	
	if (alawoverride){
		ua->span.deflaw = DAHDI_LAW_ALAW;
		printk(UA32XX_NAME": ALAW override parameter detected.  Device will be operating in ALAW\n");  	
  }else{
  	ua->span.deflaw = DAHDI_LAW_MULAW;
  }
	
	for (x = 0; x < ua->hw_channels /*NUM_CARDS*/; x++) {
		sprintf(ua->chans[x]->name, "UA32XX/%d/%d", ua->hw_channels, x);
		ua->chans[x]->sigcap = DAHDI_SIG_FXOKS | DAHDI_SIG_FXOLS | DAHDI_SIG_FXOGS | DAHDI_SIG_SF | DAHDI_SIG_EM | DAHDI_SIG_CLEAR;
		ua->chans[x]->sigcap |= DAHDI_SIG_FXSKS | DAHDI_SIG_FXSLS | DAHDI_SIG_SF | DAHDI_SIG_CLEAR;
		ua->chans[x]->chanpos = x+1;
		ua->chans[x]->pvt = ua;
	}
	
#if DAHDI_VERSION_CODE >= VERSION_CODE(2,7,0)
	ua->span.spantype = SPANTYPE_ANALOG_MIXED;
#endif
	ua->span.chans = ua->chans;
	ua->span.channels = ua->hw_channels /*NUM_CARDS*/;
	ua->span.flags = DAHDI_FLAG_RBS;
	ua->span.ops = &ua32xx_span_ops;
	
#if DAHDI_VERSION_CODE >= VERSION_CODE(2,6,0)
	list_add_tail(&ua->span.device_node, &ua->ddev->spans);
	retval = dahdi_register_device(ua->ddev, &(ua->proto.dev->dev));
	if(retval){
		printk(UA32XX_NAME": Unable to register span with DAHDI\n");
		goto ddev_init_err;
	}
#else
	init_waitqueue_head(&ua->span.maintq);
	if (dahdi_register(&ua->span, 0)) {
  	printk(UA32XX_NAME": Unable to register span with DAHDI\n");
    return -1;
  }
#endif	
	
	for (x=0; x < ua->hw_channels; x++) {
		if (ua32xx_test_cardflag(ua, x)) {
			if (ua->modtype[x] == MOD_TYPE_FXO)
				ua->chans[x]->sigcap = DAHDI_SIG_FXSKS | DAHDI_SIG_FXSLS | DAHDI_SIG_SF | DAHDI_SIG_CLEAR;
			else
				ua->chans[x]->sigcap = DAHDI_SIG_FXOKS | DAHDI_SIG_FXOLS | DAHDI_SIG_FXOGS | DAHDI_SIG_SF | DAHDI_SIG_EM | DAHDI_SIG_CLEAR;
		} else if (!(ua->chans[x]->sigcap & DAHDI_SIG_BROKEN)) {
			ua->chans[x]->sigcap = 0;
		}
	}
	
	return 0;
	
#if DAHDI_VERSION_CODE >= VERSION_CODE(2,6,0)
ddev_init_err:
	kfree(ua->ddev->location);
#endif
	
	return retval;	
}

static int ua32xx_proslic_check_hook(struct ua32xx *ua, int card)
{
	struct fxs *const fxs = &ua->mod[card].fxs;
	struct fxs_init init;
	struct hsig hsig;
	unsigned char res;
	int hook;

	/* For some reason we have to debounce the
	   hook detector.  */
	res = ua->reg0shadow[card];
	hook = (res & 1);
	if (hook != fxs->lastrxhook) {
		/* Reset the debounce (must be multiple of 4ms) */
		fxs->debounce = dialdebounce * 4;
#if 0
		printk(KERN_DEBUG "Resetting debounce card %d hook %d, %d\n",
		       card, hook, fxs->debounce);
#endif
	}else{		
		if (fxs->debounce > 0) {
			fxs->debounce -= ms_per_chkfxs*DAHDI_CHUNKSIZE;/**/
#if 0
			printk(KERN_DEBUG "Card %d,Sustaining hook %d, %d\n",
			       card,hook, fxs->debounce);
#endif
			if (!fxs->debounce) {
#if 0
				printk(KERN_DEBUG "Card %d,Counted down debounce, newhook: %d...\n",card, hook);
#endif
				fxs->debouncehook = hook;
			}
			if (!fxs->oldrxhook && fxs->debouncehook) {
				/* Off hook */
#if 1
				if (debug)
#endif				
					printk(KERN_DEBUG "ua32xx: Card %d Going off hook\n", card);

				switch (fxs->lasttxhook) {
				case SLIC_LF_RINGING:
				case SLIC_LF_OHTRAN_FWD:
				case SLIC_LF_OHTRAN_REV:
					/* just detected OffHook, during
					 * Ringing or OnHookTransfer */
					fxs->idletxhookstate =
						POLARITY_XOR ?
							SLIC_LF_ACTIVE_REV :
							SLIC_LF_ACTIVE_FWD;
					break;
				}
				/*
				ua32xx_fxs_hooksig(ua,card,DAHDI_TXSIG_OFFHOOK);
				dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_OFFHOOK);
				*/
				hsig.txsig = DAHDI_TXSIG_OFFHOOK;
				hsig.dahdi_txsig = 1;
				create_block_workthread(ua,card,WKTYPE_FXS_HOOKSIG,&hsig);
				
				if (robust){
					init.fast = 1;
					init.manual = 0;
					init.sane = 1;
					create_block_workthread(ua,card,WKTYPE_INIT_PROSLIC,&init);
				}
				fxs->oldrxhook = 1;
			} else if (fxs->oldrxhook && !fxs->debouncehook) {
				/* On hook */
#if 1
				if (debug)
#endif				
					printk(KERN_DEBUG "ua32xx: Card %d Going on hook\n", card);
				/*
				ua32xx_fxs_hooksig(ua,card,DAHDI_TXSIG_ONHOOK);
				dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_ONHOOK);
				*/
				hsig.txsig = DAHDI_TXSIG_ONHOOK;
				hsig.dahdi_txsig = 1;
				create_block_workthread(ua,card,WKTYPE_FXS_HOOKSIG,&hsig);
				
				fxs->oldrxhook = 0;
			}
		}
	}
	fxs->lastrxhook = hook;
	
	return 0;
}

static int ua32xx_proslic_recheck_sanity(struct ua32xx *ua, int card)
{
	struct fxs *const fxs = &ua->mod[card].fxs;
	struct fxs_init init;
	uint8_t res;
	
	/* Check loopback */
	res = ua->reg1shadow[card];
	if (!res && (res != fxs->lasttxhook)) {
		res = ua->reg8[card];
		if (res) {/**/
			init.fast = 1;
			init.manual = 0;
			init.sane = 1;
			create_block_workthread(ua,card,WKTYPE_INIT_PROSLIC,&init);
			printk(KERN_NOTICE "Ouch, part reset, quickly restoring reality (%d)\n", card);
		} else {
			if (fxs->palarms++ < MAX_ALARMS) {
				printk(KERN_NOTICE "Power alarm on module %d, resetting!\n", card + 1);
				if (fxs->lasttxhook == SLIC_LF_RINGING)
					fxs->lasttxhook = SLIC_LF_ACTIVE_FWD;
				ua32xx_reg_write(ua, card, 64, fxs->lasttxhook);
			} else {
				if (fxs->palarms == MAX_ALARMS)
					printk(KERN_NOTICE "Too many power alarms on card %d, NOT resetting!\n", card + 1);
			}
		}
	}
	
	return 0;
}

static int ua32xx_fxs_check_card(struct ua32xx *ua, int card)
{
	struct fxs *const fxs = &ua->mod[card].fxs;
	if (fxs->lasttxhook == SLIC_LF_RINGING &&
								!fxs->neonringing) {
		/* RINGing, prepare for OHT */
		fxs->ohttimer = OHT_TIMER << 3;
		/* logical XOR 3 variables
			 module parameter 'reversepolarity', global reverse all FXS lines. 
			 ioctl channel variable fxs 'reversepolarity', Line Reversal Alert Signal if required.
			 ioctl channel variable fxs 'vmwi_lrev', VMWI pending.
		*/

		/* OHT mode when idle */
		fxs->idletxhookstate = POLARITY_XOR ?
							SLIC_LF_OHTRAN_REV :
							SLIC_LF_OHTRAN_FWD;
	} else if (fxs->ohttimer) {
		/* check if still OnHook */
		if (!fxs->oldrxhook) {
			fxs->ohttimer -= DAHDI_CHUNKSIZE;
			if (!fxs->ohttimer) {
				fxs->idletxhookstate = POLARITY_XOR ? SLIC_LF_ACTIVE_REV : SLIC_LF_ACTIVE_FWD; /* Switch to Active, Rev or Fwd */
				/* if currently OHT */
				if ((fxs->lasttxhook == SLIC_LF_OHTRAN_FWD) || (fxs->lasttxhook == SLIC_LF_OHTRAN_REV)) {
					if (fxs->vmwi_hvac) {
						/* force idle polarity Forward if ringing */
						fxs->idletxhookstate = SLIC_LF_ACTIVE_FWD;
						/* Set ring generator for neon */
						si321x_set_ring_generator_mode(ua,card,1);
						fxs->lasttxhook = SLIC_LF_RINGING;
					} else {
						fxs->lasttxhook = fxs->idletxhookstate;
					}
					/* Apply the change as appropriate */
					ua32xx_reg_write(ua, card, LINE_STATE, fxs->lasttxhook);
				}
			}
		} else {
			fxs->ohttimer = 0;
			/* Switch to Active, Rev or Fwd */
			fxs->idletxhookstate = POLARITY_XOR ? SLIC_LF_ACTIVE_REV : SLIC_LF_ACTIVE_FWD;
		}
	}
	
	return 0;
}

static int ua32xx_voicedaa_check_hook(struct ua32xx *ua, int card)
{
#ifndef AUDIO_RINGCHECK
	unsigned char res;
#endif
	
  signed char b;
  int errors = 0;
  struct fxo *fxo = &ua->mod[card].fxo;
	
  b = ua->reg0shadow[card];
  if ((b & 0x2) || !(b & 0x8)) {
  	/* Not good -- don't look at anything else */
    if (debug){
    	printk(UA32XX_NAME ": Error (%02x) on card %d!\n", b, card + 1);
    }
    errors++;
  }
  b &= 0x9b;
  if (fxo->offhook) {
  	if (b != 0x9){ 
  		ua32xx_reg_write(ua,card, SLIC_LF_ACTIVE_REV, 0x9);
  	}
  } else {
    if (b != 0x8){ 
    	ua32xx_reg_write(ua,card, SLIC_LF_ACTIVE_REV, 0x8);
    }
  }
	
  if (errors) {
  	return -2;
  }
    
  if (!fxo->offhook) {
      if(fixedtimepolarity > 0) {
          if (((ua->cid_state[card] == CID_STATE_RING_ON)  ||  //Just Ring on/off status sends DAHDI_EVENT_POLARITY
                      (ua->cid_state[card] == CID_STATE_RING_OFF)) &&
                  (ua->cid_ring_on_time[card] > 0))
          {
              if(ua->cid_ring_on_time[card]>=fixedtimepolarity )
              {
                  dahdi_qevent_lock(ua->chans[card], DAHDI_EVENT_POLARITY);
                  ua->cid_ring_on_time[card] = -1;	/* the polarity already sent */	
              }
              else {
                  ua->cid_ring_on_time[card] += ms_per_chkfxo;
              }
          }
      }
  	if (fwringdetect) {
    	res = ua->reg0shadow[card] & 0x60;
      if (fxo->ringdebounce) {
      	--fxo->ringdebounce;
        if (res && (res != fxo->lastrdtx)&& (fxo->battery == BATTERY_PRESENT)) {
            if (!fxo->wasringing) {
                fxo->wasringing = 1;
                if (debug) {
                    printk(UA32XX_NAME ": %s, RING on %d/%d!\n", __func__, ua->span.spanno, card + 1);
                }
                if(cidbeforering)
                {
                    if(ua->cid_state[card] == CID_STATE_IDLE) {
                        ua->cid_state[card] = CID_STATE_RING_ON;
                        ua->cid_ring_on_time[card] = ms_per_chkfxo;
                        if(-1 == fixedtimepolarity){
                            dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_RING);
                        }
                    } else  {
                        dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_RING);
                    }
                }
                else {
                    dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_RING);
                }
            }
          fxo->lastrdtx = res;
          fxo->ringdebounce = 10;
        } else if (!res) {
          if ((fxo->ringdebounce == 0)&& fxo->wasringing) {
          	fxo->wasringing = 0;
            if (debug) {
            	printk(UA32XX_NAME ": %s, NO RING on %d/%d!\n", __func__, ua->span.spanno, card + 1);
            }
            if(cidbeforering){
            	if(ua->cid_state[card] == CID_STATE_RING_ON){
            		if(fixedtimepolarity==0) {
            			dahdi_qevent_lock(ua->chans[card], DAHDI_EVENT_POLARITY);
                  if(debug){
					printk("Chan %d send event DAHDI_EVENT_POLARITY to dahdi\n", card);
                  	printk(UA32XX_NAME ": Chan %d send event DAHDI_EVENT_POLARITY to dahdi\n", card);							
						      }
						    }
                ua->cid_state[card] = CID_STATE_RING_OFF;
              }
              else{
              	if(ua->cid_state[card] == CID_STATE_WAIT_RING_FINISH)
              		ua->cid_history_clone_cnt[card] = cidtimeout;	
                dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_OFFHOOK);
              }
            } else 
            	dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_OFFHOOK);
          }
        }
      } else if (res && (fxo->battery == BATTERY_PRESENT)) {
        fxo->lastrdtx = res;
        fxo->ringdebounce = 10;
      }
    } else {
      res = ua->reg0shadow[card];    
      if ((res & 0x60) && (fxo->battery == BATTERY_PRESENT)) {
      	fxo->ringdebounce ++;
        if (fxo->ringdebounce >= ringoncount) {
        	if (!fxo->wasringing) {
                fxo->wasringing = 1;
                if(cidbeforering)
                {
                    if(ua->cid_state[card] == CID_STATE_IDLE){
                        ua->cid_state[card] = CID_STATE_RING_ON;
                        ua->cid_ring_on_time[card] = ms_per_chkfxo;
                        if(-1 == fixedtimepolarity){
                            dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_RING);
                            fxo->fastringoffhooktimer = fastringoffhook;
                            fxo->ringoffhooksent = 0;
                        }
                    } else {
                        dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_RING);
                        fxo->fastringoffhooktimer = fastringoffhook;
                        fxo->ringoffhooksent = 0;
                    }
                } else {	
                    dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_RING);
                    fxo->fastringoffhooktimer = fastringoffhook;
                    fxo->ringoffhooksent = 0;
                }
            if (debug) {
            	printk(KERN_DEBUG "%s: %lu RING on %d/%d!\n", __func__, jiffies,ua->span.spanno, card + 1);
				printk(UA32XX_NAME ": %s: %lu RING on %d/%d!\n", __func__, jiffies,ua->span.spanno, card + 1);
            }
          }else{
            if (fastringoffhook && !fxo->ringoffhooksent){
            	fxo->fastringoffhooktimer -= ms_per_chkfxo;
							if (fxo->fastringoffhooktimer <= 0) {
								dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_OFFHOOK);
								fxo->ringoffhooksent = 1;
							}
            }
          }
          fxo->ringdebounce = ringdebounce/ms_per_chkfxo;	//
        }
      } else {
        fxo->ringdebounce--;
        if (fxo->ringdebounce <= ringoffcount) { 
            if (fxo->wasringing) {
                fxo->wasringing = 0;
                if(cidbeforering)
                {
                    if(ua->cid_state[card] == CID_STATE_RING_ON)
                    {
                        if(fixedtimepolarity==0) {
                            dahdi_qevent_lock(ua->chans[card], DAHDI_EVENT_POLARITY); //send polarity event to tell asterisk start parse dtmf cid
                        }
                        else if(-1 == fixedtimepolarity) { //previous has send ONHOOK, so here need to send OFFHOOK
                            if ( ! fxo->ringoffhooksent ) {	/* avoide double send DAHDI_RXSIG_OFFHOOK */
                                dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_OFFHOOK);
                                fxo->ringoffhooksent = 1;
                            }
                        }
                        ua->cid_state[card] = CID_STATE_RING_OFF;
                    }
                    else 
                    {
                        if(ua->cid_state[card] == CID_STATE_WAIT_RING_FINISH)
                            ua->cid_history_clone_cnt[card] = cidtimeout;
                        if ( ! fxo->ringoffhooksent ) {	/* avoide double send DAHDI_RXSIG_OFFHOOK */
                            dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_OFFHOOK);
                            fxo->ringoffhooksent = 1;
                        }
                    }
                } else {
                    if ( !fxo->ringoffhooksent ){
                        dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_OFFHOOK);
                        fxo->ringoffhooksent = 1;
                    }
                }

                if (debug) {
					printk(KERN_DEBUG "%s: %lu NO RING on %d/%d!\n", __func__, jiffies,ua->span.spanno, card + 1);
                    printk(UA32XX_NAME ": %s: %lu NO RING on %d/%d!\n", __func__, jiffies,ua->span.spanno, card + 1);
                }
            }
            fxo->ringdebounce = 0;
        }
      }
    }
  }

	if (unlikely(DAHDI_RXSIG_INITIAL == ua->chans[card]->rxhooksig)) {
		/*
		 * dahdi-base will set DAHDI_RXSIG_INITIAL after a
		 * DAHDI_STARTUP or DAHDI_CHANCONFIG ioctl so that new events
		 * will be queued on the channel with the current received
		 * hook state.  Channels that use robbed-bit signalling always
		 * report the current received state via the dahdi_rbsbits
		 * call. Since we only call dahdi_hooksig when we've detected
		 * a change to report, let's forget our current state in order
		 * to force us to report it again via dahdi_hooksig.
		 *
		 */
		fxo->battery = BATTERY_UNKNOWN;
	}
	
  b = ua->reg1shadow[card];
  if (abs(b) < battthresh) {
  	/* possible existing states:
       battery lost, no debounce timer
       battery lost, debounce timer (going to battery present)
       battery present or unknown, no debounce timer
       battery present or unknown, debounce timer (going to battery lost)
    */    
    if (fxo->battery == BATTERY_LOST) {
    	if (fxo->battdebounce) {
      	/* we were going to BATTERY_PRESENT, but battery was lost again,
                   so clear the debounce timer */
        fxo->battdebounce = 0;
      }
    } else {
      if (fxo->battdebounce) {
      	/* going to BATTERY_LOST, see if we are there yet */
        if (--fxo->battdebounce == 0) {
        	fxo->battery = BATTERY_LOST;
          if (debug){
          	printk(KERN_DEBUG "%s: NO BATTERY on %d/%d!\n", __func__, ua->span.spanno, card + 1);
          	printk(UA32XX_NAME ": %s: NO BATTERY on %d/%d!\n", __func__, ua->span.spanno, card + 1);			
		  }

#ifdef  JAPAN
          if (!fxo->ohdebounce && fxo->offhook) {
          	dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_ONHOOK);
            if (debug)
            	printk(KERN_DEBUG "%s: Signalled On Hook\n", __func__);
#ifdef  ZERO_BATT_RING
            fxo->onhook++;
#endif
          }
#else
          dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_ONHOOK);
                    /* set the alarm timer, taking into account that part of its time
                       period has already passed while debouncing occurred */
          fxo->battalarm = (battalarm - battdebounce) / (ms_per_chkfxo);
#endif
        }
      } else {
        /* start the debounce timer to verify that battery has been lost */
        fxo->battdebounce = battdebounce / (ms_per_chkfxo*2);
      }
    }
  } else {
    /* possible existing states:
       battery lost or unknown, no debounce timer
       battery lost or unknown, debounce timer (going to battery present)
       battery present, no debounce timer
       battery present, debounce timer (going to battery lost)
    */
    if (fxo->battery == BATTERY_PRESENT) {
    	if (fxo->battdebounce) {
      	/* we were going to BATTERY_LOST, but battery appeared again,
           so clear the debounce timer */
        fxo->battdebounce = 0;
      }
    } else {
      if (fxo->battdebounce) {
      	/* going to BATTERY_PRESENT, see if we are there yet */
        if (--fxo->battdebounce == 0) {
        	fxo->battery = BATTERY_PRESENT;
          if (debug){
         		printk(KERN_DEBUG "%s: BATTERY on %d/%d (%s)!\n", __func__, ua->span.spanno, card + 1,
                               (b < 0) ? "-" : "+");
         		printk(UA32XX_NAME ": %s: BATTERY on %d/%d (%s)!\n", __func__, ua->span.spanno, card + 1,
                               (b < 0) ? "-" : "+");							   
		  }

#ifdef  ZERO_BATT_RING
        	if (fxo->onhook) {
          	fxo->onhook = 0;
            dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_OFFHOOK);
            if (debug){
            	printk(KERN_DEBUG "%s: Signalled Off Hook\n", __func__);
            	printk(UA32XX_NAME ": %s: Signalled Off Hook\n", __func__);				
			}

          }
#else
          dahdi_hooksig(ua->chans[card], DAHDI_RXSIG_OFFHOOK);
#endif
                    /* set the alarm timer, taking into account that part of its time
                       period has already passed while debouncing occurred */
          fxo->battalarm = (battalarm - battdebounce) / (ms_per_chkfxo);
        }
      } else {
        /* start the debounce timer to verify that battery has appeared */
        fxo->battdebounce = battdebounce / (ms_per_chkfxo);   //
      }
    }
  }
    
  if (fxo->battalarm) {
  	if (--fxo->battalarm == 0) {
    	/* the alarm timer has expired, so update the battery alarm state
               for this channel */
    	dahdi_alarm_channel(ua->chans[card], fxo->battery == BATTERY_LOST ? DAHDI_ALARM_RED : DAHDI_ALARM_NONE);
    }
  }
            
  if (fxo->lastpol >= 0) {
  	if (b < 0) {
    	fxo->lastpol = -1;
      fxo->polaritydebounce =  polaritydebounce / (ms_per_chkfxo); 
    }
  }
  if (fxo->lastpol <= 0) {
  	if (b > 0) {
    	fxo->lastpol = 1;
    	fxo->polaritydebounce = polaritydebounce / (ms_per_chkfxo);
    }
  }
    		
	if (fxo->polaritydebounce) {
  	if (--fxo->polaritydebounce == 0) {        		
    	if (fxo->lastpol != fxo->polarity) { /**/                  	  	 
      	if (debug){
        	printk(KERN_DEBUG "%s: %lu card[%d] Polarity reversed (%d -> %d)\n", __func__, jiffies,card+1,
                       fxo->polarity,
                       fxo->lastpol);
        	printk(UA32XX_NAME ": %s: %lu card[%d] Polarity reversed (%d -> %d)\n", __func__, jiffies,card+1,
                       fxo->polarity,
                       fxo->lastpol);					   
		}

				
      	if (fxo->polarity) {
      		if(fxo->offhook && fxo->callout && twowaychargeflag){ //
      			fxo->polaritycountwhenoffhook++;
      			if(fxo->polaritycountwhenoffhook != 1){
      				dahdi_qevent_lock(ua->chans[card], DAHDI_EVENT_POLARITY);
      			}
      		}else{
      			dahdi_qevent_lock(ua->chans[card], DAHDI_EVENT_POLARITY);
      		}                     		              		
      	}
            	  
      	fxo->polarity = fxo->lastpol;
      }
    }
  }
	return 0;
}

#define MAX_CONTINUOUS_ERR_CNT 3
static void io_work_handler(struct work_struct *data)
{
	struct ua32xx_d_work* io_work;
	struct delayed_work* d_work;
	struct ua32xx* ua  = NULL;
	int proc_ret;
	
	d_work = container_of(data, struct delayed_work, work);
	io_work = container_of(d_work, struct ua32xx_d_work, work);
	ua = io_work->ua;
	
	if (ua->dead) {
		clear_bit(UA32XX_RUNF_IOWQ, &ua->run_flags);
		kfree(io_work);
		if(debug)
			printk(UA32XX_NAME": device %d io work queue stopped.\n",ua->ifaces_index);
		return;
	}
		
	proc_ret = io_list_proc(ua);
	if(proc_ret){/**/
		if(ua->iowq_proc_cnt - ua->io_err_point == 1)
			ua->io_err_cnt++;
		else
			ua->io_err_cnt = 0;
		
		ua->io_err_point = ua->iowq_proc_cnt ;
		
		if(ua->io_err_cnt > MAX_CONTINUOUS_ERR_CNT){
			ua->dead = 1;
			clear_bit(UA32XX_RUNF_IOWQ, &ua->run_flags);
			kfree(io_work);
			
			if(ua == ua32_master)
				ua32xx_sel_master();	//change the master
			
			printk(KERN_DEBUG "!!!! %s device %d io work queue stopped abnormally(%d).\n", ua->hw_name, ua->ifaces_index, proc_ret);
			printk(UA32XX_NAME ": !!!! %s device %d io work queue stopped abnormally(%d).\n", ua->hw_name, ua->ifaces_index, proc_ret);
			return;
		}else
			printk(UA32XX_NAME ": %s device %d io work queue error %d.\n", ua->hw_name, ua->ifaces_index, proc_ret);
	}
	
	if(!ua->dead){
		if(ua->init_ok){/**/
			// get device running status report about every dsr_intv ms 
			if(dsr_intv > 0)
				if((ua->iowq_proc_cnt % dsr_intv) == dsr_intv - 1){
					ua32xx_get_report(ua);
				}
		}
	}
		
	ua->iowq_proc_cnt++;
	io_work->ua = ua;
	INIT_DELAYED_WORK(&io_work->work, io_work_handler);
	queue_delayed_work(ua->io_wq, &io_work->work, msecs_to_jiffies(io_op_intv));	
}

static void channels_work_handler(struct work_struct *data)
{
	struct ua32xx_d_work* chan_work = NULL;
	struct delayed_work* d_work = NULL;
	struct ua32xx* ua  = NULL;
	int card,retval,count_per_check;
	
	d_work = container_of(data, struct delayed_work, work);
	chan_work = container_of(d_work, struct ua32xx_d_work, work);
	ua = chan_work->ua;
	card = chan_work->card;
	
	if (ua->dead) {
		if(ua->running_count > 0)
			ua->running_count--;
		
		if(ua->running_count == 0)
			clear_bit(UA32XX_RUNF_CHANWQ, &ua->run_flags);
		
		kfree(chan_work);
		
		if(debug)
			printk(UA32XX_NAME": device %d chan_work[%d] stopped.\n",ua->ifaces_index,card);
		
		return;
	}
	/**/
	//channel check work
	if(ua->modtype[card] == MOD_TYPE_FXO){
		struct fxo *fxo = &ua->mod[card].fxo;
		if(fxo->regwr.flag == 0){
			fxo->regwr.flag = 1;
			ua32xx_reg_write(ua, card, fxo->regwr.reg, fxo->regwr.value);
		}
			
		count_per_check = ms_per_chkfxo/chan_check_intv;
		// read channel running status registers
		if(ua->chan_chk_cnt[card] % count_per_check == (card % (count_per_check/2))){
			ua32xx_reg_op_read(ua, card, 5);
			ua32xx_reg_op_read(ua, card, 29);
		}
		//check hook per ms_per_chkfxo ms
		if(ua->chan_chk_cnt[card] % count_per_check == (card % (count_per_check/2)) + count_per_check/2){
			retval = ua32xx_voicedaa_check_hook(ua,card);
			if(retval){
				if(debug)
  				printk(UA32XX_NAME": %s failed line = %d error %d.\n", __FUNCTION__,__LINE__, retval);
			}
		}
	}else{
		count_per_check = ms_per_chkfxs/chan_check_intv;
		ua32xx_fxs_check_card(ua,card);
		// read channel running status registers
		if(ua->chan_chk_cnt[card] % count_per_check == (card % (count_per_check/2))){
			ua32xx_reg_op_read(ua, card, 68);
			ua32xx_reg_op_read(ua, card, LINE_STATE);
			if(!(ua->chan_chk_cnt[card] & 0xf0)){
				ua32xx_reg_op_read(ua, card, 8);
			}
		}
		//check hook per ms_per_chkfxs ms
		if(ua->chan_chk_cnt[card] % count_per_check == (card % (count_per_check/2)) + count_per_check/2){
			ua32xx_proslic_check_hook(ua,card);					
			if (!(ua->chan_chk_cnt[card] & 0xf0)) {
				ua32xx_proslic_recheck_sanity(ua, card);
			}
		}
				
		if (!(ua->chan_chk_cnt[card] % (10000/chan_check_intv))) {
			if (ua->mod[card].fxs.palarms)
				ua->mod[card].fxs.palarms--;
		}	
	}
	ua->chan_chk_cnt[card]++;
#if 0
	if((ua->ifaces_index == 0) && (card == 0))
		printk("------ %s, device %d, card %d, check count %d, jif=%lu\n",
						__FUNCTION__, ua->ifaces_index, card, ua->chan_chk_cnt[card], jiffies);
#endif
	
	INIT_DELAYED_WORK(&chan_work->work, channels_work_handler);
	chan_work->ua = ua;
	chan_work->card = card;
	queue_delayed_work(ua->chan_wq[card], &chan_work->work, msecs_to_jiffies(chan_check_intv));
}

static void tdm_task(unsigned long data)
{
	struct urb* urb = NULL;
	struct ua32xx *ua = (struct ua32xx *)data;
	
	urb = __oproto_pop_task(&ua->proto);
	if(!urb){
		printk(KERN_DEBUG "<---!!!!!!---> %s bad task urb parameter!\n",__FUNCTION__);
		return;
	}
	
	tdm_workhandler(ua,urb);
}

void tdm_urb_compelete(struct urb* urb) 
{
	struct oproto* proto = (struct oproto*)urb->context;
	struct ua32xx *ua;
	static unsigned long start_time;
	int recverror = 0;
	
	/* find ua from context */
	ua = container_of(proto, struct ua32xx, proto);
	if (NULL == ua) {
		printk(KERN_DEBUG "Invalid urb ua!\n");
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,34)
		usb_free_coherent(urb->dev, urb->transfer_buffer_length, urb->transfer_buffer, urb->transfer_dma);
#else
		usb_buffer_free(urb->dev, urb->transfer_buffer_length, urb->transfer_buffer, urb->transfer_dma);
#endif
		return;
	}
	
	if(ua->dead)
		return;
	
	if (urb->status){
		if(!(urb->status == -ENOENT ||
				 urb->status == -ECONNRESET ||
				 urb->status == -ESHUTDOWN)) {	/* sync/async unlink faults aren't errors */		
			printk("%s: URB nonzero status: %d\n", __FUNCTION__, urb->status);
		}
		
		if(ua->tdm_proc_cnt - ua->tdm_err_point == 1)
			ua->tdm_err_cnt++;
		else
			ua->tdm_err_cnt = 0;
		
		ua->tdm_err_point = ua->tdm_proc_cnt ;
		
		if(ua->tdm_err_cnt > MAX_CONTINUOUS_ERR_CNT){
			ua->dead = 1;
			if(ua == ua32_master)
				ua32xx_sel_master();	//change the master
			return;
		}
	}
			
	if (ua->urbrxcount == 0){
		if(ua->ifaces_index == 0)
			start_time = jiffies;
	}

	/* handle bulk out complete*/
	if (urb->pipe == usb_sndbulkpipe(proto->dev, proto->tdm_bulk_out_endpointAddr)) {
		ua->urbtxcount++;
		if (urb->actual_length != proto->tdm_pkt_len){
			proto->tx_err_counter++;
			printk(UA32XX_NAME": bad BULK OUT urb length %d, must be %d,jif = %lu.\n", urb->actual_length, proto->tdm_pkt_len,jiffies);
		}
		
		proto->tx_pkt_counter++;
		__oproto_release_tdm_bulkout_urb(proto, urb);
	} else { /* handle bulk in complete*/
		ua->urbrxcount++;
		recverror = 0;
		if (urb->actual_length != proto->tdm_pkt_len){
			recverror = 1;
			printk(UA32XX_NAME": bad RX urb length %d, must be %d\n", urb->actual_length, proto->tdm_pkt_len);
		}
		
		proto->rx_pkt_counter++;
#if 0		
		if ((ua->urbrxcount % 10) == 1) {
			if(ua->ifaces_index == 0){
				printk(UA32XX_NAME ": %d tx urbs, %d rx urbs in %lu ms \n", ua->urbtxcount, ua->urbrxcount, (jiffies - start_time) * 1000 / HZ /**/);
				start_time = jiffies;
			}
		}
#endif		
		if (ua->tdm_stat == OP_START_TDM) {
			if(!recverror){
				__oproto_push_task(proto,urb);
				tasklet_schedule(&ua->tdm_tasklet);
			}else{
				__oproto_refill_tdm_urb(proto, USB_DIR_IN, urb);
			  usb_submit_urb(urb, GFP_ATOMIC);	/* re-use the urb for rx */
			}
		} else {
			__oproto_release_tdm_bulkin_urb(proto, urb);
		}
	}
	ua->tdm_proc_cnt++;
} 

static void free_led_chan(struct ua32xx* );
static int free_channels_workqueue(struct ua32xx* );

#define HAVE_INI(x)		test_bit(x, &ua->init_flags)
#define CLEAR_INI(x)	clear_bit(x, &ua->init_flags)	

static void ua32xx_clear_works(struct ua32xx* ua)
{
	if(!ua)
		return;
	
	ua->dead = 1;
	
	if(ua == ua32_master)
		ua32xx_sel_master();	//change the master
	
	while(test_bit(UA32XX_RUNF_CHANWQ, &ua->run_flags))	
		msleep(10);
		
	while (test_bit(UA32XX_RUNF_IOWQ, &ua->run_flags))	/* wait wqs stop */
		msleep(10);
	
	if (HAVE_INI(UA32XX_INITF_CHANWQ)) {
		free_channels_workqueue(ua);
		CLEAR_INI(UA32XX_INITF_CHANWQ);
	}
			
	if (HAVE_INI(UA32XX_INITF_IOWQ)) {
		flush_workqueue(ua->io_wq);
		destroy_workqueue(ua->io_wq);
		oproto_free_io_pkt(ua->iowq_recvpkt);
		CLEAR_INI(UA32XX_INITF_IOWQ);
	}
	
	if(test_bit(UA32XX_RUNF_TASKLET, &ua->run_flags)){
		tasklet_kill(&ua->tdm_tasklet);
		clear_bit(UA32XX_RUNF_TASKLET, &ua->run_flags);	
	}
	
	free_led_chan(ua);
}

static void ua32xx_stop(struct ua32xx* ua)
{
	int retval,x;
	
	if(!ua)
		return;
	
	if(!ua->dead){
		if(ua->tdm_stat == OP_START_TDM){
			retval = ua32xx_tdm_op(ua, OP_STOP_TDM);
			if(!retval){
				printk(UA32XX_NAME": device %d tdm stopped.\n",ua->ifaces_index);
			}
		}
		
		//black the leds
		for(x=0;x<NUM_CARDS;x++){
			if(ua32xx_test_cardflag(ua, x)){
				retval = oproto_cfg_led(&ua->proto, x, ua->modtype[x], CHAN_LED_BLACK);
				if(retval)
					break;
			}
		}
	}
	
	ua32xx_clear_works(ua);
}

static void free_ua32xx(struct ua32xx* ua)
{
#ifdef CONFIG_DCRA
  int x;
#endif
	
	if(!ua)
		return;
	
	if (HAVE_INI(UA32XX_INITF_DAHDISOFT)) {
#if DAHDI_VERSION_CODE >= VERSION_CODE(2,6,0) 
		dahdi_unregister_device(ua->ddev);
		kfree(ua->ddev->location);
#else
		dahdi_unregister(&ua->span);
#endif
		CLEAR_INI(UA32XX_INITF_DAHDISOFT);
	}
	
	if (HAVE_INI(UA32XX_INITF_DDEVCREATE)) {
		dahdi_free_device(ua->ddev);
		CLEAR_INI(UA32XX_INITF_DDEVCREATE);
	}
	
#ifdef CONFIG_DCRA
  for(x = 0; x < NUM_CARDS; x++){
  	if(ua32xx_test_cardflag(ua, x)) {
    	dcra_unregister(ua->chans[x]->channo - 1);
    }
  }
#endif
	if (HAVE_INI(UA32XX_INITF_PKTLIST)) {
		__free_op_pkt_list(ua->pkt_list);
		CLEAR_INI(UA32XX_INITF_PKTLIST);
	}
	
	if (HAVE_INI(UA32XX_INITF_ROPLIST)) {
		__free_regop_list(ua->rdbuf_list);
		CLEAR_INI(UA32XX_INITF_ROPLIST);
	}
	
	if (HAVE_INI(UA32XX_INITF_RTOLIST)) {
		__free_regop_list(ua->rd_timeout_list);
		CLEAR_INI(UA32XX_INITF_RTOLIST);
	}
	
	if (HAVE_INI(UA32XX_INITF_USBINTFDATA)) {
		usb_set_intfdata(ua->proto.usb_intf, NULL);
		CLEAR_INI(UA32XX_INITF_USBINTFDATA);
	}

	if (HAVE_INI(UA32XX_INITF_USBGETDEV)) {
		usb_put_dev(ua->proto.dev);
		CLEAR_INI(UA32XX_INITF_USBGETDEV);
	}

	if (HAVE_INI(UA32XX_INITF_OPROTO)) {
		oproto_clear(&ua->proto);
		CLEAR_INI(UA32XX_INITF_OPROTO);
	}

	if (HAVE_INI(UA32XX_INITF_IFACES)) {
		ifaces[ua->ifaces_index] = NULL;
		CLEAR_INI(UA32XX_INITF_IFACES);
	}
		
	kfree(ua);
	g_ifaces--;
} 

static int init_channels_workqueue(struct ua32xx* ua)
{
	int x,y;
	char wq_name[15];
	
	for(x=0;x<NUM_CARDS;x++){
		if(ua32xx_test_cardflag(ua, x)){
			snprintf(wq_name, sizeof(wq_name), "chan_%d_%d", (unsigned int)ua->ifaces_index,x);
			ua->chan_wq[x] = create_workqueue(wq_name);
			if(!ua->chan_wq[x]){
				for(y=0;y<x;y++){
					if(ua32xx_test_cardflag(ua, y))
						destroy_workqueue(ua->chan_wq[y]);
				}
				printk(UA32XX_NAME": create workqueue %s failed!\n", wq_name);
				return -ENODEV;
			}
			atomic_set(&(ua->chan_block_cnt[x]),0);
		}
	}
	__set_bit(UA32XX_INITF_CHANWQ, &ua->init_flags);
	ua->running_count = 0;
	
	return 0;
}

static void wait_block_work_complete(struct ua32xx* ua, int chan)
{
	while(atomic_read(&(ua->chan_block_cnt[chan])))
		msleep(10);
}

static int free_channels_workqueue(struct ua32xx* ua)
{
	int x;
	for(x=0;x<NUM_CARDS;x++){
		if(ua32xx_test_cardflag(ua, x)){
			wait_block_work_complete(ua,x);
			flush_workqueue(ua->chan_wq[x]);
			destroy_workqueue(ua->chan_wq[x]);
		}
	}
	return 0;
}

static int init_channels_work(struct ua32xx* ua)
{
	int x,y;
	struct ua32xx_d_work* chan_work[NUM_CARDS];
	
	for(x=0;x<NUM_CARDS;x++){
		if(ua32xx_test_cardflag(ua, x)){
			chan_work[x] = kmalloc(sizeof(struct ua32xx_d_work), GFP_KERNEL);
			if(!chan_work[x]){
				for(y=0;y<x;y++){
					if(ua32xx_test_cardflag(ua, y))
						kfree(chan_work[y]);
				}
				printk(UA32XX_NAME": create channel work failed!\n");
				return -ENOMEM;
			}
		}
	}
	
	for(x=0;x<NUM_CARDS;x++){
		if(ua32xx_test_cardflag(ua, x)){
			ua->chan_chk_cnt[x] = 0;
			INIT_DELAYED_WORK(&chan_work[x]->work, channels_work_handler);
			chan_work[x]->ua = ua;
			chan_work[x]->card = x;
			queue_delayed_work(ua->chan_wq[x], &chan_work[x]->work, msecs_to_jiffies(1+x));
			ua->running_count++;
			if(debug)
				printk(UA32XX_NAME": chan_work[%d] started.\n",x);
		}
	}
	if(ua->running_count)
		__set_bit(UA32XX_RUNF_CHANWQ, &ua->run_flags);
	
	return 0;
}

static int init_io_workqueue(struct ua32xx* ua)
{
	char wq_name[15];
	struct ua32xx_d_work* io_work;
	
	ua->iowq_recvpkt = oproto_alloc_io_pkt(&ua->proto, GFP_KERNEL);
	if(!ua->iowq_recvpkt){
		printk(UA32XX_NAME": create io workqueue recv pkt error!\n");
		return -ENOMEM;
	}
		
	snprintf(wq_name, sizeof(wq_name), "ua32xx_io_%x", (unsigned int)ua->ifaces_index);
	ua->io_wq = create_singlethread_workqueue(wq_name);
	if (NULL == ua->io_wq) {
		oproto_free_io_pkt(ua->iowq_recvpkt);
		printk(UA32XX_NAME": create io workqueue %s failed.\n", wq_name);
		return -ENODEV;
	}
	__set_bit(UA32XX_INITF_IOWQ, &ua->init_flags);
	
	io_work = kmalloc(sizeof(struct ua32xx_d_work), GFP_KERNEL);
	if(!io_work)
		return -ENOMEM;
		
	INIT_DELAYED_WORK(&io_work->work, io_work_handler);
	io_work->ua = ua;
	ua->iowq_proc_cnt = 0;
	ua->io_err_cnt = 0;
	ua->io_err_point = 0;
	queue_delayed_work(ua->io_wq, &io_work->work, msecs_to_jiffies(io_op_intv));	
	__set_bit(UA32XX_RUNF_IOWQ, &ua->run_flags);
	
	if(debug)
		printk(UA32XX_NAME": io workqueue(%s on device %d) started.\n", wq_name,ua->ifaces_index);
	
	return 0;
}

static int register_led_chan(struct ua32xx* );
static int ua32xx_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
  int retval = -ENOMEM;
  struct ua32xx *ua = NULL;
  struct usb_host_interface *iface_desc;
  struct usb_endpoint_descriptor *endpoint;
  int i;
	struct ua32xx_desc* desc;
	struct usb_device* dev;						/* pointer to usb device.	*/

	/* STEP 1: alloc memory for this interface =============================================================*/
	ua = kmalloc(sizeof(struct ua32xx), GFP_KERNEL);
	if (NULL == ua)
		return -ENOMEM;
	memset(ua, 0, sizeof(struct ua32xx));

	/* STEP 2: find empty element in global ifaces array ====================================================*/
	for (i = 0; i < UA_MAX_IFACES; i++)	{
		if (0 == ifaces[i])
			break;
	}

	if (UA_MAX_IFACES == i) {
		printk(UA32XX_NAME": too many interfaces\n");
		kfree(ua);
		return -EIO;
	}
	ua->ifaces_index = i;
	g_ifaces++;
	
	ifaces[i] = ua;
	__set_bit(UA32XX_INITF_IFACES, &ua->init_flags);

	/* STEP 3: check and set up the endpoint information ===================================================*/
	dev = usb_get_dev(interface_to_usbdev(interface));
	__set_bit(UA32XX_INITF_USBGETDEV, &ua->init_flags);
	ua->proto.dev = dev;

	/* STEP 4:  associate this interface to usb ============================================================*/
	/* connect this instance private data to usb interface */
	usb_set_intfdata(interface, ua);
	__set_bit(UA32XX_INITF_USBINTFDATA, &ua->init_flags);
	ua->proto.usb_intf = interface ;
	
  /* STEP 5: check and set up the endpoint information ===================================================*/
  iface_desc = interface->cur_altsetting;
	printk(UA32XX_NAME": probe on interface config %d epnum %d\n", iface_desc->desc.bAlternateSetting, iface_desc->desc.bNumEndpoints);
    
	desc = (struct ua32xx_desc*)id->driver_info;
	if (iface_desc->desc.bNumEndpoints != desc->ep_num) {
		printk(UA32XX_NAME": bNumEndpoints(%d) must be %d\n", iface_desc->desc.bNumEndpoints, desc->ep_num);
		goto err_exit;
	}

	endpoint = &iface_desc->endpoint[0].desc;
	if (!__usb_endpoint_is_bulk(endpoint) || !__usb_endpoint_is_in(endpoint) ) {
		printk(UA32XX_NAME": EP1 is not BULK IN!\n");
		goto err_exit;
	}

	if(endpoint->wMaxPacketSize != desc->io_bulk_size) {
		printk(UA32XX_NAME": EP1 wMaxPacketSize(%d) is not %d\n", endpoint->wMaxPacketSize, desc->io_bulk_size);
		goto err_exit;
	}
	ua->proto.io_bulk_in_endpointAddr = endpoint->bEndpointAddress;

	endpoint = &iface_desc->endpoint[1].desc;
	if (!__usb_endpoint_is_bulk(endpoint) || __usb_endpoint_is_in(endpoint)) {
		printk(UA32XX_NAME": EP2 is not BULK OUT!\n");
		goto err_exit;
	}
	ua->proto.io_bulk_out_endpointAddr = endpoint->bEndpointAddress;
	
	if(endpoint->wMaxPacketSize != desc->io_bulk_size) {
		printk(UA32XX_NAME": EP2 wMaxPacketSize(%d) is not %d\n", endpoint->wMaxPacketSize, desc->io_bulk_size);
		goto err_exit;
	}
	ua->proto.io_pkt_len = endpoint->wMaxPacketSize;

	endpoint = &iface_desc->endpoint[2].desc;
	if (!__usb_endpoint_is_bulk(endpoint) || !__usb_endpoint_is_in(endpoint)) {
		printk(UA32XX_NAME": EP3 is not BULK IN\n");
		goto err_exit;
	}

	if (endpoint->wMaxPacketSize > desc->tdm_bulk_size) {
		printk(UA32XX_NAME": EP3 wMaxPacketSize(%d) is not %d\n", endpoint->wMaxPacketSize, desc->tdm_bulk_size);
		goto err_exit;
	}
	ua->proto.tdm_bulk_in_endpointAddr = endpoint->bEndpointAddress;

	endpoint = &iface_desc->endpoint[3].desc;
	if (!__usb_endpoint_is_bulk(endpoint) || __usb_endpoint_is_in(endpoint)) {
		printk(UA32XX_NAME": EP4 is not BULK OUT\n");
		goto err_exit;
	}
	ua->proto.tdm_bulk_out_endpointAddr = endpoint->bEndpointAddress;
	
	if (endpoint->wMaxPacketSize > desc->tdm_bulk_size) {
		printk(UA32XX_NAME": EP4 wMaxPacketSize(%d) is not %d\n", endpoint->wMaxPacketSize, desc->tdm_bulk_size);
		goto err_exit;
	}
	ua->proto.tdm_pkt_len = endpoint->wMaxPacketSize;
		
	/* STEP 6:  create oproto protocol codec ========================================================================*/
	retval = oproto_init(&ua->proto, tdm_urb_compelete, tdm_urb_num, tdm_dahdi_buf_len);
	if(retval){
		printk(UA32XX_NAME": create oproto protocol error.\n");
		goto err_exit;
	}
	__set_bit(UA32XX_INITF_OPROTO, &ua->init_flags);
	
	ua->tdm_proc_cnt = 0;
	ua->tdm_err_point = 0;
	ua->tdm_err_cnt = 0;
		
	if (debug)
		printk(UA32XX_NAME": IO EPIN Addr 0x%02x, IO EPOUT Addr 0x%02x, IO EP Size %d, TDM EPIN Addr 0x%02x, TDM EPOUT Addr 0x%02x, TDM EP Size %d\n",
			ua->proto.io_bulk_in_endpointAddr & 0xff, ua->proto.io_bulk_out_endpointAddr & 0xff, ua->proto.io_pkt_len,
			ua->proto.tdm_bulk_in_endpointAddr & 0xff, ua->proto.tdm_bulk_out_endpointAddr & 0xff, ua->proto.tdm_pkt_len);
	
	/* STEP 7:  get hardware information ============================================================================ */
	ua->hw_name = desc->name;
	ua->max_channel = ua->proto.tdm_pkt_len/DAHDI_CHUNKSIZE;
	
	//default settings
	ua->hw_channels = ua->max_channel;
	ua->module_daisy = 0;
	for (i = 0; i < ua->max_channel; i++) {
		ua->flags[i] = desc->flags;
	}
	
	/**/
	if(!strcmp(ua->hw_name,proto_fxx_ext.name)){
		ua->module_daisy = 1;
		ua->hw_channels = ua->max_channel;
	}else if(!strcmp(ua->hw_name,proto_uc320.name)){
		ua->module_daisy = 1;
		ua->hw_channels = DEV_UC320_CHANNELS;
	}else if(!strcmp(ua->hw_name,proto_uc350.name)){
		ua->module_daisy = 1;
		ua->hw_channels = DEV_UC350_CHANNELS;
	}else if(!strcmp(ua->hw_name,proto_a1008.name)){
		ua->module_daisy = 1;
		ua->hw_channels = DEV_A1008_CHANNELS;	//
//	}if(!strcmp(ua->hw_name,proto_uc580.name)){
	}else if(!strcmp(ua->hw_name,proto_uc580.name)){
		ua->module_daisy = 1;
		ua->hw_channels = DEV_UC580_CHANNELS;	//
//	}if(!strcmp(ua->hw_name,proto_uc540.name)){
	}else if(!strcmp(ua->hw_name,proto_uc540.name)){
		ua->module_daisy = 1;
		ua->hw_channels = DEV_UC540_CHANNELS;	//
	}else if(!strcmp(ua->hw_name,proto_uc581.name)){
		ua->module_daisy = 1;
		ua->hw_channels = DEV_UC581_CHANNELS;	//
	}
		
	printk(UA32XX_NAME": found hardware \"%s\", max channels %d, working channels %d\n", 
																ua->hw_name, ua->max_channel,ua->hw_channels);
	/**/
	spin_lock_init(&ua->list_lock);
	ua->pkt_list = __create_op_pkt_list(&ua->proto);
	if(!ua->pkt_list){
		retval = -ENODEV;
		goto err_exit;	
	}
	__set_bit(UA32XX_INITF_PKTLIST, &ua->init_flags);
	
	spin_lock_init(&ua->rd_lock);
	ua->rdbuf_list = __create_regop_list();
	if(!ua->rdbuf_list){
		retval = -ENODEV;
		goto err_exit;	
	}
	__set_bit(UA32XX_INITF_ROPLIST, &ua->init_flags);
	
	spin_lock_init(&ua->rd_timeout_lock);
	ua->rd_timeout_list = __create_regop_list();
	if(!ua->rd_timeout_list){
		retval = -ENODEV;
		goto err_exit;	
	}
	__set_bit(UA32XX_INITF_RTOLIST, &ua->init_flags);
	
	/**/
	for(i=0;i<NUM_CARDS;i++){
		init_waitqueue_head(&(ua->io_waitq[i]));
		ua->wkup_cond[i] = 0 ;
	}
	
	/* init io work queue */
	if(init_io_workqueue(ua))
		goto err_exit;
	
	wait_just_a_bit(50);
	
	/* STEP 8:  get actual channels, channel type, and initialize fxs/fxo modules ==================================== */
	retval = ua32xx_hw_init(ua);
	if (retval) { 
		retval = -ENODEV;
		goto err_exit;
	}
	
	/**/
#if DAHDI_VERSION_CODE >= VERSION_CODE(2,6,0)	
	ua->ddev = dahdi_create_device();
	if(!ua->ddev){
			printk(UA32XX_NAME": dahdi_create_device failed!\n");
			retval = -ENOMEM;
			goto err_exit;
	}
	__set_bit(UA32XX_INITF_DDEVCREATE, &ua->init_flags);
#endif
	
	retval = ua32xx_software_init(ua);
	if (retval) { 
		goto err_exit;
	}
	__set_bit(UA32XX_INITF_DAHDISOFT, &ua->init_flags);
	
	/**/
	for (i = 0; i < ua->proto.tdm_urb_num; i++) {
		ua->proto.tdm_bulk_in_urbpool[i].submitted = 1;
		usb_submit_urb(ua->proto.tdm_bulk_in_urbpool[i].urb, GFP_ATOMIC);
	}
	//printk(UA32XX_NAME": %d tdm BULK IN urbs submitted\n", ua->proto.tdm_urb_num);

  if(cidbeforering){
  	int len = cidbuflen * DAHDI_MAX_CHUNKSIZE;
    if(debug){
    	printk("cidbeforering support enabled, length is %d msec\n", cidbuflen);		
		printk(UA32XX_NAME ": cidbeforering support enabled, length is %d msec\n", cidbuflen);			
		}

    for (i = 0; i < NUM_CARDS; i++){
    	ua->cid_history_buf[i] = kmalloc(len, GFP_KERNEL);
      ua->cid_history_ptr[i] = 0;
      ua->cid_history_clone_cnt[i] = 0;
      ua->cid_state[i] = CID_STATE_IDLE;
    }
  }
	//for tdm tasklet
	tasklet_init(&ua->tdm_tasklet, tdm_task, (unsigned long)ua);
	__set_bit(UA32XX_RUNF_TASKLET, &ua->run_flags);
	
	/* step 9: start tdm transfer */
	retval = ua32xx_tdm_op(ua, OP_START_TDM);
	if (retval) { 
		goto err_exit;
	}
	//if(debug)
	printk(UA32XX_NAME": device %d tdm started.\n",ua->ifaces_index);
		
	//
	wait_just_a_bit(20);
	
	/*init channels workqueues*/
	retval = init_channels_workqueue(ua);
	if(retval)
		goto err_exit;
		
	retval = init_channels_work(ua);
	if(retval)
		goto err_exit;
	
	register_led_chan(ua);
	
#ifdef CONFIG_DCRA  //Registers to dcra
	for(i = 0; i < NUM_CARDS; i++){
		if(ua32xx_test_cardflag(ua, i)) {
    	if (ua->modtype[i] == MOD_TYPE_FXS) { //FXS channel
      	ua32xx_dcra_chan.num_regs = NUM_REGS;
        ua32xx_dcra_chan.num_ext_regs = NUM_INDIRECT_REGS;

        if (ua->flags[i] & FLAG_3215) {
        	ua32xx_dcra_chan.model = DCRA_TYPE_SI3215;
          dcra_register(ua->chans[i]->channo - 1, &ua32xx_dcra_chan);
        }else{
          ua32xx_dcra_chan.model = DCRA_TYPE_SI3210;
          dcra_register(ua->chans[i]->channo - 1, &ua32xx_dcra_chan);
        }
      }else{ //FXO channel
        ua32xx_dcra_chan.model = DCRA_TYPE_SI3050;
        ua32xx_dcra_chan.num_regs = NUM_FXO_REGS;
        ua32xx_dcra_chan.num_ext_regs = 0;
       	dcra_register(ua->chans[i]->channo - 1, &ua32xx_dcra_chan);
      }
		}
	}
#endif	
	
	if(ua->running_count > 0){
		if(!ua32_master){
			ua32_master = ua ;
			printk(UA32XX_NAME": device %d used as master.\n", ua->ifaces_index);
		}
	}
	
	return 0;	
	
err_exit:
	ua32xx_stop(ua);
	free_ua32xx(ua);
	return retval;
}

static void ua32xx_sel_master(void)
{
	int i,found;
	
	found = 0;
  for(i=0;i<UA_MAX_IFACES;i++){
  	struct ua32xx* ua = ifaces[i];
  	if(ua && (ua != ua32_master)&& (!ua->dead) && (ua->running_count > 0)){
  		ua32_master = ua;
  		found = 1;
  		printk(UA32XX_NAME": device %d used as master.\n", ua->ifaces_index);
  		break;
  	}
  }
  if(!found)
  	ua32_master = NULL ;
}

static void ua32xx_disconnect(struct usb_interface *interface)
{
	struct ua32xx* ua = usb_get_intfdata(interface);
	
	if(ua->usecount)
		ua->usecount = 0;
	ua32xx_clear_works(ua);
	free_ua32xx(ua);
	printk(UA32XX_NAME": device %d disconnected.\n",ua->ifaces_index);
}

static ssize_t ua32xx_proc_read(struct file *file, char __user *buf, size_t count, loff_t *f_pos)
{
#define BUF_LEN 512
	int x,res;
	char *strReport;
	size_t rdlen = 0;
	size_t offset = 0;
	
	if(*f_pos != 0){
		return rdlen;
	}
	
	strReport = kmalloc(g_ifaces*BUF_LEN, GFP_KERNEL);
	if(!strReport)
		return -ENOMEM;
	
	rdlen = 0;
	for(x=0;x<UA_MAX_IFACES;x++){
		struct ua32xx* ua = ifaces[x];
		if(!ua)
			continue;
		
		offset = sprintf(strReport + rdlen,
					"ua32xx device %d running status report:\n" \
					"	receiced tdm packet: %llu \n" \
					"	sent tdm packet: %llu\n" \
					"	failed tx usb commands: %d \n" \
					"	failed tx tmd packets: %d \n" \
					"	device tx fifo loading: %d \n" \
					"	device rx fifo loading: %d \n" \
					"	tdm tx fifo underflow times: %d\n" \
					"	tdm tx fifo overflow times: %d\n" \
					"	tdm rx fifo overflow times: %d\n",
					x,
					ua->report.tdm_packet_received,
					ua->report.tdm_packet_send,
					ua->report.usb_cmd_tx_fail,
					ua->report.usb_tdm_tx_fail,
					ua->report.tdm_txfifo_load,
					ua->report.tdm_rxfifo_load,
					ua->report.tdm_tx_fifo_underflow,
					ua->report.tdm_tx_fifo_overflow,
					ua->report.tdm_rx_fifo_overflow
					);
		rdlen += offset;
		if(rdlen > count){
			kfree(strReport);
			if (debug){
				printk(KERN_DEBUG "buffer is not big enough.\n");
				printk(UA32XX_NAME ": buffer is not big enough.\n");					
			}

			return -EBADF;
		}
	}
			
	res = copy_to_user(buf, strReport, rdlen);
	if (res) {
		kfree(strReport);
		if(debug){
			printk(KERN_DEBUG "copy_to_user failed.\n");	
			printk(UA32XX_NAME ": copy_to_user failed.\n");				
		}

		return -EIO;
	}else{
		*f_pos += rdlen;
	}
	
	kfree(strReport);
	return rdlen;
}

static struct file_operations proc_fops = {
	.owner = THIS_MODULE,
	.read = ua32xx_proc_read,
};


static ssize_t ua32xx_led_write(struct file *file, const char __user *buf, size_t count, loff_t *f_pos)
{
	char *name_buf = NULL;
	char *pname = NULL;
	char *tmp, *token;
	
	struct ua32xx *ua = NULL;
  struct dahdi_chan  *chan = NULL;
	unsigned int channo = 0;
	
	char sstat[2] = {0,0};
	unsigned int led_stat;
	
	/* get file full path name */
	name_buf = kmalloc(PATH_MAX + 1, GFP_KERNEL);
	pname = d_path(&file->f_path, name_buf, PATH_MAX);
	
	if(debug > 3 ){
		printk(KERN_INFO "Ledcfg write file %s\n", pname);
		printk(UA32XX_NAME ": Ledcfg write file %s\n", pname);
	}

	
	/* do not support write to middle of file */
	if (0 != *f_pos) {
		if (debug > 3){
			printk(KERN_DEBUG "Ledcfg write offset must be zero %s\n", pname);
			printk(UA32XX_NAME ": Ledcfg write offset must be zero %s\n", pname);			
		}

		kfree(name_buf);
		return 0;
	}
	
	tmp = pname;
	token = strrchr(tmp,'/');
	token++;
	
	if(kstrtouint(token,10,&channo)){
		printk(KERN_DEBUG"Ledcfg write: parse channo %s failed!\n",token);
		printk(UA32XX_NAME ": Ledcfg write: parse channo %s failed!\n",token);
		kfree(name_buf);
		return 0;
	}
	
	if(debug > 3){
		printk("Ledcfg write channo: %d\n",channo);
		printk(UA32XX_NAME ": Ledcfg write channo: %d\n",channo);		
	}

	
	chan = dahdi_get_chan_from_num(channo+1);
	if(!chan){
  	printk("Ledcfg write invalid channel %d !\n", channo);
    kfree(name_buf);
    return 0;
  }
  ua = chan->pvt;
  if(!ua){
  	printk("Ledcfg write NULL  ua!\n");
    kfree(name_buf);
    return 0;
  }
	
	if(copy_from_user(sstat, buf, 1)){
		printk(KERN_DEBUG"Ledcfg write,copy_from_user failed!\n");
		kfree(name_buf);
    return 0;
	}
	*f_pos += count;
	
	if(kstrtouint(sstat,10,&led_stat)){
		printk(KERN_DEBUG"Ledcfg write: parse channo %s failed!\n",token);
		kfree(name_buf);
		return 0;
	}
	if(debug > 3){
		printk(KERN_INFO "Ledcfg write: set channo %d state %d\n",channo,led_stat);
		printk(UA32XX_NAME ": Ledcfg write: set channo %d state %d\n",channo,led_stat);
	}

		
	if(s300_lv == 11)
		oproto_cfg_led(&ua->proto, chan->chanpos-1, 0, led_stat);
	else
		oproto_cfg_led(&ua->proto, chan->chanpos-1, ua->modtype[chan->chanpos-1], led_stat);
	
	kfree(name_buf);	
	return count;
}

static struct file_operations led_fops = {
	.owner = THIS_MODULE,
	.write = ua32xx_led_write,
};

static int register_led_chan(struct ua32xx* ua)
{
	int y;
	unsigned char channo[8] = {0};
	
	if(!ua32xx_ledcfg_root)
		return 0;
	
	for(y=0; y<ua->hw_channels; y++){
		if(ua32xx_test_cardflag(ua, y) && !ua->chan_entry[y]){
			snprintf(channo, sizeof(channo), "%d", ua->chans[y]->channo - 1);
			ua->chan_entry[y] = proc_create(channo, 0x0644, ua32xx_ledcfg_root, &led_fops);
			if(!ua->chan_entry[y]){
				printk(KERN_DEBUG "Creating /proc/%s/%s/%s\n failed", PROC_ROOT, PROC_LEDCFG, channo);
			}
		}
	}
	return 0;
}

static void free_led_chan(struct ua32xx* ua)
{
	int y;
	unsigned char channo[8] = {0};
	
	if(!ua32xx_ledcfg_root)
		return;
	
	for(y=0; y<ua->hw_channels; y++){
		if(ua->chan_entry[y]){
			snprintf(channo, sizeof(channo), "%d", ua->chans[y]->channo - 1);
			remove_proc_entry(channo, ua32xx_ledcfg_root);
			ua->chan_entry[y] = NULL;
		}
	}
}

static int ua32xx_procfs_init(void)
{
	//int x;
	
	ua32xx_proc_root = proc_mkdir(PROC_ROOT, NULL);
	if (!ua32xx_proc_root) {
		printk(KERN_DEBUG "Creating proc/%s failed!\n", PROC_ROOT);
		return -ENOENT;
	}
	
	ua32xx_proc_report = proc_create(PROC_REPORT, 0x0444, ua32xx_proc_root, &proc_fops);
	if(!ua32xx_proc_report){
		remove_proc_entry(PROC_ROOT, NULL);
		printk(KERN_DEBUG "Creating /proc/%s/%s\n failed", PROC_ROOT, PROC_REPORT);
		return -ENOENT;
	}
	
	ua32xx_ledcfg_root = proc_mkdir(PROC_LEDCFG, ua32xx_proc_root);
	if(!ua32xx_ledcfg_root){
		remove_proc_entry(PROC_REPORT, ua32xx_proc_root);
		remove_proc_entry(PROC_ROOT, NULL);
		printk(KERN_DEBUG "Creating /proc/%s/%s\n failed", PROC_ROOT, PROC_LEDCFG);
		return -ENOENT;
	}
	
	/*for(x=0; x<UA_MAX_IFACES; x++){
		struct ua32xx* ua = ifaces[x];
		if(!ua)
			continue;
		register_led_chan(ua);
	}*/
	
	return 0;
}

static void ua32xx_procfs_free(void)
{	
	if(ua32xx_ledcfg_root)
		remove_proc_entry(PROC_LEDCFG, ua32xx_proc_root);
		
	if(ua32xx_proc_report)
		remove_proc_entry(PROC_REPORT, ua32xx_proc_root);
	
	if(ua32xx_proc_root)	
		remove_proc_entry(PROC_ROOT, NULL);
}

static struct usb_driver ua32xx_driver = {
    .name = "ua32xx",
    .probe = ua32xx_probe, /* probe is init_one */
    .disconnect = ua32xx_disconnect,	/* disconnect is remove_one */
    .id_table = ua32xx_id_table,
};

static int __init ua32xx_init(void)
{
	int res,x;
  printk("ua32xx driver ver %s\n", UA32XX_VERSION);
		
	/* init global variable for all interfaces */
	memset(ifaces, 0, sizeof(ifaces));
	
	for (x = 0; x < (sizeof(fxo_modes) / sizeof(fxo_modes[0])); x++) {
	if (!strcmp(fxo_modes[x].name, opermode))
		break;
	}
	if (x < sizeof(fxo_modes) / sizeof(fxo_modes[0])) {
		_opermode = x;
	} else {
		printk(KERN_NOTICE "Invalid/unknown operating mode '%s' specified.  Please choose one of:\n", opermode);
		for (x = 0; x < sizeof(fxo_modes) / sizeof(fxo_modes[0]); x++)
			printk(KERN_INFO "  %s\n", fxo_modes[x].name);
		printk(KERN_INFO "Note this option is CASE SENSITIVE!\n");
		return -ENODEV;
	}

	if (!strcmp(opermode, "AUSTRALIA")) {
		boostringer = 1;
		fxshonormode = 1;
	}

	/* for the voicedaa_check_hook defaults, if the user has not overridden
	 	 them by specifying them as module parameters, then get the values
	 	 from the selected operating mode
	*/
	if (battdebounce == 0) {
		battdebounce = fxo_modes[_opermode].battdebounce;
	}
	if (battalarm == 0) {
		battalarm = fxo_modes[_opermode].battalarm;
	}
	if (battthresh == 0) {
		battthresh = fxo_modes[_opermode].battthresh;
	}

#ifdef CONFIG_DCRA
  /* init dcra register operate */
  memset(&ua32xx_dcra_chan, 0, sizeof(ua32xx_dcra_chan));
  ua32xx_dcra_regops.get_reg = ua32xx_dcra_get_reg;
  ua32xx_dcra_regops.set_reg = ua32xx_dcra_set_reg;
  ua32xx_dcra_regops.get_ext_reg = ua32xx_dcra_get_ext_reg;
  ua32xx_dcra_regops.set_ext_reg = ua32xx_dcra_set_ext_reg;
  ua32xx_dcra_chan.reg_ops = &ua32xx_dcra_regops;
#endif
	
	ua32xx_procfs_init();
	
  res = usb_register(&ua32xx_driver);
  if (res) {
  	printk(UA32XX_NAME":usb_register failed %d\n", res);
    return -ENODEV;
  }
  
	
	
  return 0;
}

static void __exit ua32xx_cleanup(void)
{
	int i;
  for(i=0;i<UA_MAX_IFACES;i++){
  	if(ifaces[i]){
			ua32xx_stop(ifaces[i]);
  	}
  }
  
  ua32xx_procfs_free();
  usb_deregister(&ua32xx_driver);
  
  printk(UA32XX_NAME" exit.\n");
}

module_param(s300_lv, int, 0600);
module_param(debug, int, 0600);
module_param(iodebug, int, 0600);
module_param(tdmdebug, int, 0600);
module_param(ms_per_chkfxs, int, 0600);
module_param(ms_per_chkfxo, int, 0600);
module_param(io_op_intv, int, 0600);
module_param(chan_check_intv, int, 0600);
module_param(dsr_intv, int, 0600);
module_param(tdm_urb_num, int, 0600);
module_param(tdm_dahdi_buf_len, int, 0600);
module_param(ext_reset_len, int, 0600);
module_param(ext_reset_delay, int, 0600);

module_param(fxovoltage, int, 0600);
module_param(loopcurrent, int, 0600);
module_param(reversepolarity, int, 0600);
module_param(robust, int, 0600);
module_param(opermode, charp, 0600);
module_param(timingonly, int, 0600);
module_param(lowpower, int, 0600);
module_param(boostringer, int, 0600);
module_param(fastringer, int, 0600);
module_param(fxshonormode, int, 0600);
module_param(battdebounce, uint, 0600);
module_param(battalarm, uint, 0600);
module_param(battthresh, uint, 0600);
module_param(ringdebounce, int, 0600);
module_param(ringoncount, int, 0600);
module_param(ringoffcount, int, 0600);
module_param(fastringoffhook, int, 0600);
module_param(dialdebounce, int, 0600);
module_param(fwringdetect, int, 0600);
module_param(alawoverride, int, 0600);
module_param(fastpickup, int, 0600);
module_param(fxotxgain, int, 0600);
module_param(fxorxgain, int, 0600);
module_param(fxstxgain, int, 0600);
module_param(fxsrxgain, int, 0600);

module_param(polaritydebounce, int, 0600);
module_param(twowaychargeflag, int, 0600);

module_param(cidbeforering, int, 0600);                          
module_param(cidbuflen, int, 0600);                              
module_param(cutcidbufheadlen, int, 0600);                       
module_param(cidtimeout, int, 0600);                             
module_param(fixedtimepolarity, int, 0600);  

module_param(fxofullscale, int, 0600);

MODULE_DESCRIPTION("SGM USB Analog Voice Adapter DAHDI Driver");
MODULE_AUTHOR("");
MODULE_LICENSE("GPL v2");

MODULE_PARM_DESC(debug, "set debug=5 if you want to print ua32xx debug information");
MODULE_PARM_DESC(s300_lv, "use s300_lv to compatible of old S300 hardware type. s300_lv=11 standard for Ver1.1.");

module_init(ua32xx_init);
module_exit(ua32xx_cleanup);

