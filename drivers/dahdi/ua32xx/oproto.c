
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/init.h>
#include <asm/io.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/memory.h>
#include <linux/usb.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,34)
#include <linux/slab.h>
#endif

#include "oproto.h"
#include "oproto_host.h"


#define SYNC_TIMEOUT 1500


/******************************************************************************************/
/**********for tdm urb*********************************************************************/
/******************************************************************************************/

/* callback of a completed tdm urb.*/
void oproto_tdm_complete(struct urb* urb)
{
	struct oproto* proto = (struct oproto*)urb->context;
	
	/* invalid urb */
	if (NULL == proto) {		
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,34)
		usb_free_coherent(urb->dev, urb->transfer_buffer_length, urb->transfer_buffer, urb->transfer_dma);
#else
		usb_buffer_free(urb->dev, urb->transfer_buffer_length, urb->transfer_buffer, urb->transfer_dma);
#endif
		printk(KERN_DEBUG "Invalid urb context!\n");
		return;
	}
	
	if (proto->tdm_callback)
		proto->tdm_callback(urb);
}

struct urb_pool* __oproto_alloc_tdm_urb_pool(struct oproto* proto, int dir)
{
	struct urb_pool* res = NULL;
	int i, tmp = 0;

	res = kmalloc(sizeof(struct urb_pool)*proto->tdm_urb_num, GFP_KERNEL);
	if (NULL == res)
		return NULL;
	memset(res, 0, sizeof(struct urb_pool)*proto->tdm_urb_num);

	for (i = 0; i < proto->tdm_urb_num; i++) {
		res[i].submitted = 0;
		tmp = oproto_alloc_tdm_urb(proto, dir, &res[i].urb);
		if (tmp)
			break;
	}
	if (tmp) {
		for (i = 0; i < proto->tdm_urb_num; i++) {
			if (res[i].urb) {
				oproto_free_tdm_urb(proto, res[i].urb);
				res[i].urb = NULL;
			}
		}
		kfree(res);
		return NULL;
	}

	return res;
}

void __oproto_free_tdm_urb_pool(struct oproto* proto, struct urb_pool* pool)
{
	int i;

	if (NULL == pool)
		return;
	for (i = 0; i < proto->tdm_urb_num; i++) {
		if (pool[i].urb) {
			oproto_free_tdm_urb(proto, pool[i].urb);
			pool[i].urb = NULL;
			pool[i].submitted = 0;
		}
	}
	kfree(pool);
	pool = NULL;
}

void __oproto_refill_tdm_urb(struct oproto* proto, int dir, struct urb* urb)
{
	void* buf = urb->transfer_buffer;
	
	usb_fill_bulk_urb(urb,
		proto->dev,
		dir == USB_DIR_OUT ? usb_sndbulkpipe(proto->dev, proto->tdm_bulk_out_endpointAddr) : usb_rcvbulkpipe(proto->dev, proto->tdm_bulk_in_endpointAddr),
		buf,
		proto->tdm_pkt_len,
		oproto_tdm_complete,
		proto);
		
	if(dir == USB_DIR_IN)
		urb->transfer_flags |= URB_SHORT_NOT_OK;
}

int oproto_alloc_tdm_urb(struct oproto* proto, int dir, struct urb** urb)
{
	uint8_t* buf;

	*urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (NULL == *urb) {
		printk("%s - no enough memory\n", __FUNCTION__);
		return -ENOMEM;
	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,34)
	buf = usb_alloc_coherent(proto->dev, proto->tdm_pkt_len, GFP_ATOMIC, &(*urb)->transfer_dma);
#else
	buf = usb_buffer_alloc(proto->dev, proto->tdm_pkt_len, GFP_ATOMIC, &(*urb)->transfer_dma);	
#endif
	if (NULL == buf) {
		printk("%s - no enough memory\n", __FUNCTION__);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,34)
		usb_free_coherent(proto->dev, proto->tdm_pkt_len, buf, (*urb)->transfer_dma);
#else
		usb_buffer_free(proto->dev, proto->tdm_pkt_len, buf, (*urb)->transfer_dma);	
#endif
		usb_free_urb(*urb);
		*urb = NULL;
		return -ENOMEM;
	}
	usb_fill_bulk_urb(*urb,
		proto->dev,
		dir == USB_DIR_OUT ? usb_sndbulkpipe(proto->dev, proto->tdm_bulk_out_endpointAddr) : usb_rcvbulkpipe(proto->dev, proto->tdm_bulk_in_endpointAddr),
		buf,
		proto->tdm_pkt_len,
		oproto_tdm_complete,
		proto);
	
	if(dir == USB_DIR_IN)	
		(*urb)->transfer_flags |= URB_SHORT_NOT_OK;

	return 0;
}

int oproto_alloc_tdm_tx_urb(struct oproto* proto, struct urb** urb)
{
	return oproto_alloc_tdm_urb(proto, USB_DIR_OUT, urb);
}

void oproto_free_tdm_urb(struct oproto* proto, struct urb* urb)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,34)
	usb_free_coherent(proto->dev, proto->tdm_pkt_len, urb->transfer_buffer, urb->transfer_dma);
#else
	usb_buffer_free(proto->dev, proto->tdm_pkt_len, urb->transfer_buffer, urb->transfer_dma);
#endif
	usb_free_urb(urb);
}

struct urb* __oproto_get_tdm_bulkout_urb(struct oproto* prot)
{
	int i;
	unsigned long flags;
	
	spin_lock_irqsave(&prot->urb_lock,flags);
	for (i = 0; i < prot->tdm_urb_num; i++) {
		struct urb_pool* up = &prot->tdm_bulk_out_urbpool[i];
		if (!up->submitted) {
			up->submitted = 1;
			spin_unlock_irqrestore(&prot->urb_lock,flags);
			return up->urb;
		}
	}
	spin_unlock_irqrestore(&prot->urb_lock,flags);
	return NULL;
}

int __oproto_release_tdm_bulkout_urb(struct oproto* prot, struct urb* urb)
{
	int i;
	unsigned long flags;
	
	spin_lock_irqsave(&prot->urb_lock,flags);
	for (i = 0; i < prot->tdm_urb_num; i++) {
		struct urb_pool* up = &prot->tdm_bulk_out_urbpool[i];
		if (up->submitted && (up->urb == urb)) {
			up->submitted = 0;
			spin_unlock_irqrestore(&prot->urb_lock,flags);
			return 0;
		}
	}
	spin_unlock_irqrestore(&prot->urb_lock,flags);
	return -EINVAL;
}

int __oproto_release_tdm_bulkin_urb(struct oproto* prot, struct urb* urb)
{
	int i;
	
	for (i = 0; i < prot->tdm_urb_num; i++) {
		struct urb_pool* up = &prot->tdm_bulk_in_urbpool[i];
		if (up->submitted && (up->urb == urb)) {
			up->submitted = 0;
			return 0;
		}
	}
	return -EINVAL;
}

void __oproto_push_task(struct oproto* proto, struct urb* urb)
{
	unsigned long flags;
	
	spin_lock_irqsave(&proto->task_lock,flags);
	proto->urb_task[proto->task_inp].task = 1;
	proto->urb_task[proto->task_inp].urb = urb;
	proto->task_inp++;
	if(proto->task_inp > proto->tdm_urb_num-1)
		proto->task_inp = 0;
	spin_unlock_irqrestore(&proto->task_lock,flags);
}

struct urb* __oproto_pop_task(struct oproto* proto)
{
	struct urb* urb = NULL;
	unsigned long flags;
	
	spin_lock_irqsave(&proto->task_lock,flags);
	if(proto->urb_task[proto->task_outp].task == 0){
		spin_unlock_irqrestore(&proto->task_lock,flags);
		return NULL;
	}
	urb = proto->urb_task[proto->task_outp].urb;
	proto->urb_task[proto->task_outp].task = 0;
	proto->urb_task[proto->task_outp].urb = NULL;
	proto->task_outp++;
	if(proto->task_outp > proto->tdm_urb_num-1)
		proto->task_outp = 0;
	spin_unlock_irqrestore(&proto->task_lock,flags);
	
	return urb;
}

/*****************************************************************
 for tdm dahdi buf operations
******************************************************************/

static int init_tdm_dahdi_buf(struct oproto* proto)
{
	/* RX buf */
	proto->tdm_dahdi_rx_buf.frame_size = proto->tdm_pkt_len;
	proto->tdm_dahdi_rx_buf.frame_num = proto->tdm_dahdi_len;
	proto->tdm_dahdi_rx_buf.frame_load = 0;
	proto->tdm_dahdi_rx_buf.inp = 0;
	proto->tdm_dahdi_rx_buf.outp = 0;
	spin_lock_init(&proto->tdm_dahdi_rx_buf.lock);
	
	proto->tdm_dahdi_rx_buf.buf = kmalloc(proto->tdm_pkt_len * proto->tdm_dahdi_rx_buf.frame_num, GFP_KERNEL);
	if(!proto->tdm_dahdi_rx_buf.buf){
		printk(KERN_DEBUG ": %s line %d error!\n", __FUNCTION__, __LINE__);
		return -ENOMEM;
	}
		
	/* temp buffer */
	proto->tdm_tmpbuf = kmalloc(proto->tdm_pkt_len, GFP_KERNEL);
	if(!proto->tdm_tmpbuf){
		kfree(proto->tdm_dahdi_rx_buf.buf);
		printk(KERN_DEBUG ": %s line %d error!\n", __FUNCTION__, __LINE__);
		return -ENOMEM;
	}
	
	return 0;
}

static void free_tdm_dahdi_buf(struct oproto* proto)
{
	kfree(proto->tdm_dahdi_rx_buf.buf);
	kfree(proto->tdm_tmpbuf);
}

static void round_add_inp(tdm_dahdi_buf_t* tdm_dahdi_buf)
{
	tdm_dahdi_buf->inp++;
	if(tdm_dahdi_buf->inp == tdm_dahdi_buf->frame_num)
		tdm_dahdi_buf->inp = 0;
}

static void round_add_outp(tdm_dahdi_buf_t* tdm_dahdi_buf)
{
	tdm_dahdi_buf->outp++;
	if(tdm_dahdi_buf->outp == tdm_dahdi_buf->frame_num)
		tdm_dahdi_buf->outp = 0;
}

int tdm_dahdi_buf_load(tdm_dahdi_buf_t* tdm_dahdi_buf)
{
	return tdm_dahdi_buf->frame_load;
}

int tdm_dahdi_buf_push(tdm_dahdi_buf_t* tdm_dahdi_buf, unsigned char *data)
{
	int res = 0;
	unsigned long flags;
	
	spin_lock_irqsave(&tdm_dahdi_buf->lock,flags);
	/* if buf is full, pop out one block */
	if(tdm_dahdi_buf->frame_load == tdm_dahdi_buf->frame_num){
		round_add_outp(tdm_dahdi_buf);
		tdm_dahdi_buf->frame_load--;
		res = -1;
	}
	
	memcpy(tdm_dahdi_buf->buf + tdm_dahdi_buf->inp * tdm_dahdi_buf->frame_size, data, tdm_dahdi_buf->frame_size);
	round_add_inp(tdm_dahdi_buf);
	tdm_dahdi_buf->frame_load++;
	spin_unlock_irqrestore(&tdm_dahdi_buf->lock,flags);
	return res;
}

int tdm_dahdi_buf_pop(tdm_dahdi_buf_t* tdm_dahdi_buf, unsigned char *data)
{
	unsigned long flags;
	
	if(!data)
		return -1;
		
	spin_lock_irqsave(&tdm_dahdi_buf->lock,flags);
	if(tdm_dahdi_buf->frame_load == 0){
		spin_unlock_irqrestore(&tdm_dahdi_buf->lock,flags);
		return -1;
	}
		
	memcpy(data, tdm_dahdi_buf->buf + tdm_dahdi_buf->outp * tdm_dahdi_buf->frame_size, tdm_dahdi_buf->frame_size);
	round_add_outp(tdm_dahdi_buf);
	tdm_dahdi_buf->frame_load--;
	spin_unlock_irqrestore(&tdm_dahdi_buf->lock,flags);
	return 0;
}

/******************************************************************/
/*************for sync io pkt**************************************/
/******************************************************************/

int oproto_pkt_sync_tx(struct oproto* proto, void* data, int *len, int timeout)
{
	int actual_len,
		retval;

	retval = usb_bulk_msg(proto->dev,
		usb_sndbulkpipe(proto->dev, proto->io_bulk_out_endpointAddr),
		data,
		*len,
		&actual_len,
		msecs_to_jiffies(timeout));

	*len = actual_len;
	return retval;
}

int oproto_pkt_sync_rx(struct oproto* proto, struct oproto_packet* recvpkt,int *len, int timeout)
{
	int actual_len;
	int res;
	
	if(!recvpkt)
		return -1;
	
	res = usb_bulk_msg(proto->dev,
		usb_rcvbulkpipe(proto->dev, proto->io_bulk_in_endpointAddr),
		recvpkt,
		proto->io_pkt_len,
		&actual_len,
		msecs_to_jiffies(timeout));

	if (0 != res) {
		printk("usb_bulk_msg rx failed %d\n", res);
		return res;
	}

	if (len)
		*len = actual_len;
	
	return 0;
}

int oproto_io_sync_op(struct oproto* proto, struct oproto_packet* sndpkt,struct oproto_packet* recvpkt)
{
	int res,len;
	
	if((!sndpkt)||(!recvpkt))
		return -1;

	len = proto->io_pkt_len;	
	mutex_lock(&proto->opmutex);
	res = oproto_pkt_sync_tx(proto,sndpkt,&len,SYNC_TIMEOUT);
	if (res) {
		mutex_unlock (&proto->opmutex);
		printk("%s %d tx pkt error: %d\n", __FUNCTION__, __LINE__, res);
		return res;
	}
	
	res = oproto_pkt_sync_rx(proto,recvpkt,&len,SYNC_TIMEOUT);
	if (res) {
		mutex_unlock (&proto->opmutex);
		printk("%s %d rx error: %d\n", __FUNCTION__, __LINE__, res);
		return res;
	}
	mutex_unlock(&proto->opmutex);
	
	if(sndpkt->header.pkt_sn != recvpkt->header.pkt_sn)
	{
		printk("%s %d rx bad pkt.\n", __FUNCTION__, __LINE__);
		return -1;
	}
	
	switch(sndpkt->op_code){
	case OP_REG:
		if(sndpkt->header.op_num != recvpkt->header.op_num){
			printk("%s %d rx bad pkt.\n", __FUNCTION__, __LINE__);
			return -1;
		}
		break;
	default:
		break;
	}
	return 0;
}

int oproto_get_fwver(struct oproto* proto, struct oproto_packet* recvpkt)
{
	int res = 0;
	struct oproto_packet* sndpkt;
	
	if(!recvpkt)
		return -1;
	
	sndpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!sndpkt){
		return -2;
	}
	
	sndpkt->header.proto_ver = OPROTO_VER;
	sndpkt->header.op_num = 1;
	spin_lock(&proto->index_lock);
	sndpkt->header.pkt_sn = proto->tx_pkt_index++;
	spin_unlock(&proto->index_lock);
	sndpkt->op_code = OP_GET_FWVER;
	
	res = oproto_io_sync_op(proto,sndpkt,recvpkt);
	if(res){
		res = -3;
	}
	
	oproto_free_io_pkt(sndpkt);
	return res;
}

int oproto_ext_reset(struct oproto* proto, int ms_enable, int ms_delay)
{
	int res = 0;
	struct oproto_packet* sndpkt;
	struct oproto_packet* recvpkt;
	
	sndpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!sndpkt){
		return -1;
	}
	
	recvpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!recvpkt){
		oproto_free_io_pkt(sndpkt);
		return -2;
	}
	
	sndpkt->header.proto_ver = OPROTO_VER;
	sndpkt->header.op_num = 1;
	spin_lock(&proto->index_lock);
	sndpkt->header.pkt_sn = proto->tx_pkt_index++;
	spin_unlock(&proto->index_lock);
	sndpkt->op_code = OP_EXT_RESET;
	
	sndpkt->body[0].reset.pulse_length = ms_enable;
	sndpkt->body[0].reset.delay_after_reset = ms_delay;
	
	res = oproto_io_sync_op(proto,sndpkt,recvpkt);
	if(res){
		printk("%s %d error: %d.\n", __FUNCTION__, __LINE__,res);
		res = -3;
	}
	
	oproto_free_io_pkt(sndpkt);
	oproto_free_io_pkt(recvpkt);
	return res;
}

int oproto_tdm_op(struct oproto* proto,unsigned int op)
{
	int res = 0;
	struct oproto_packet* sndpkt;
	struct oproto_packet* recvpkt;
	
	sndpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!sndpkt){
		return -1;
	}
	
	recvpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!recvpkt){
		oproto_free_io_pkt(sndpkt);
		return -2;
	}
	
	sndpkt->header.proto_ver = OPROTO_VER;
	sndpkt->header.op_num = 1;
	spin_lock(&proto->index_lock);
	sndpkt->header.pkt_sn = proto->tx_pkt_index++;
	spin_unlock(&proto->index_lock);
	sndpkt->op_code = op;
	
	res = oproto_io_sync_op(proto,sndpkt,recvpkt);
	if(res){
		printk("%s %d error: %d.\n", __FUNCTION__, __LINE__,res);
		res = -3;
	}
	
	oproto_free_io_pkt(sndpkt);
	oproto_free_io_pkt(recvpkt);
	return res;
}

int oproto_get_report(struct oproto* proto,struct oproto_OP_REPORT *report)
{
	int res = 0;
	struct oproto_packet* sndpkt;
	struct oproto_packet* recvpkt;
	
	sndpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!sndpkt){
		return -1;
	}
	
	recvpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!recvpkt){
		oproto_free_io_pkt(sndpkt);
		return -2;
	}
	
	sndpkt->header.proto_ver = OPROTO_VER;
	sndpkt->header.op_num = 1;
	spin_lock(&proto->index_lock);
	sndpkt->header.pkt_sn = proto->tx_pkt_index++;
	spin_unlock(&proto->index_lock);
	sndpkt->op_code = OP_REPORT;
	
	res = oproto_io_sync_op(proto,sndpkt,recvpkt);
	if(res){
		printk("%s %d error: %d.\n", __FUNCTION__, __LINE__,res);
		res = -3;
	}
	
	memcpy(report,recvpkt->body,sizeof(struct oproto_OP_REPORT));
	
	oproto_free_io_pkt(sndpkt);
	oproto_free_io_pkt(recvpkt);
	return res;
}

int oproto_reset_report(struct oproto* proto)
{
	int res = 0;
	struct oproto_packet* sndpkt;
	struct oproto_packet* recvpkt;
	
	sndpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!sndpkt){
		return -1;
	}
	
	recvpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!recvpkt){
		oproto_free_io_pkt(sndpkt);
		return -2;
	}
	
	sndpkt->header.proto_ver = OPROTO_VER;
	sndpkt->header.op_num = 1;
	spin_lock(&proto->index_lock);
	sndpkt->header.pkt_sn = proto->tx_pkt_index++;
	spin_unlock(&proto->index_lock);
	sndpkt->op_code = OP_REPORT_RESET;
	
	res = oproto_io_sync_op(proto,sndpkt,recvpkt);
	if(res){
		printk("%s %d error: %d.\n", __FUNCTION__, __LINE__,res);
		res = -3;
	}
	
	oproto_free_io_pkt(sndpkt);
	oproto_free_io_pkt(recvpkt);
	return res;
}

int oproto_get_slotid(struct oproto* proto, uint8_t *slotid)
{
	int res = 0;
	struct oproto_packet* sndpkt;
	struct oproto_packet* recvpkt;
	
	sndpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!sndpkt){
		return -1;
	}
	
	recvpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!recvpkt){
		oproto_free_io_pkt(sndpkt);
		return -2;
	}
	
	sndpkt->header.proto_ver = OPROTO_VER;
	sndpkt->header.op_num = 1;
	spin_lock(&proto->index_lock);
	sndpkt->header.pkt_sn = proto->tx_pkt_index++;
	spin_unlock(&proto->index_lock);
	sndpkt->op_code = (OP_TYPE_GET_SLOTID << 8);
	
	res = oproto_io_sync_op(proto,sndpkt,recvpkt);
	if(res){
		printk("%s %d error: %d.\n", __FUNCTION__, __LINE__,res);
		res = -3;
	}
	
	*slotid = (recvpkt->op_code & 0xFF);
	
	oproto_free_io_pkt(sndpkt);
	oproto_free_io_pkt(recvpkt);
	return res;
}

int oproto_cpld_sel_clk(struct oproto* proto, unsigned int clksrc)
{
	int res = 0;
	struct oproto_packet* sndpkt;
	struct oproto_packet* recvpkt;
	
	sndpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!sndpkt){
		return -1;
	}
	
	recvpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!recvpkt){
		oproto_free_io_pkt(sndpkt);
		return -2;
	}
	
	sndpkt->header.proto_ver = OPROTO_VER;
	sndpkt->header.op_num = 1;
	spin_lock(&proto->index_lock);
	sndpkt->header.pkt_sn = proto->tx_pkt_index++;
	spin_unlock(&proto->index_lock);
	sndpkt->op_code = ((OP_TYPE_SEL_CLK << 8) | (clksrc & 0xFF));
	
	res = oproto_io_sync_op(proto,sndpkt,recvpkt);
	if(res){
		printk("%s %d error: %d.\n", __FUNCTION__, __LINE__,res);
		res = -3;
	}
	
	oproto_free_io_pkt(sndpkt);
	oproto_free_io_pkt(recvpkt);
	return res;
}

int oproto_cfg_led(struct oproto* proto, unsigned int card, int modtype, unsigned int state)
{
	int res = 0;
	struct oproto_packet* sndpkt;
	struct oproto_packet* recvpkt;
	
	sndpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!sndpkt){
		return -1;
	}
	
	recvpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!recvpkt){
		oproto_free_io_pkt(sndpkt);
		return -2;
	}
	
	sndpkt->header.proto_ver = OPROTO_VER;
	sndpkt->header.op_num = 1;
	spin_lock(&proto->index_lock);
	sndpkt->header.pkt_sn = proto->tx_pkt_index++;
	spin_unlock(&proto->index_lock);
#ifdef FXX_EXT
	sndpkt->op_code = (card | (OP_TYPE_CFG_LED << 8) | (state << 16));
#else
	sndpkt->op_code = ((OP_TYPE_CFG_LED << 8) | ((card & 0xF) << 4) | (state & 0xF) | ((modtype & 0x01) << 7));
#endif
	res = oproto_io_sync_op(proto,sndpkt,recvpkt);
	if(res){
		printk("%s %d error: %d.\n", __FUNCTION__, __LINE__,res);
		res = -3;
	}
	
	oproto_free_io_pkt(sndpkt);
	oproto_free_io_pkt(recvpkt);
	return res;
}

int oproto_set_tscap(struct oproto* proto, uint8_t tscap)
{
	int res = 0;
	struct oproto_packet* sndpkt;
	struct oproto_packet* recvpkt;
	
	sndpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!sndpkt){
		return -1;
	}
	
	recvpkt = oproto_alloc_io_pkt(proto, GFP_KERNEL);
	if(!recvpkt){
		oproto_free_io_pkt(sndpkt);
		return -2;
	}
	
	sndpkt->header.proto_ver = OPROTO_VER;
	sndpkt->header.op_num = 1;
	spin_lock(&proto->index_lock);
	sndpkt->header.pkt_sn = proto->tx_pkt_index++;
	spin_unlock(&proto->index_lock);
	
	sndpkt->op_code = ((OP_TYPE_SET_TSCAP << 8) | tscap);
	
	res = oproto_io_sync_op(proto,sndpkt,recvpkt);
	if(res){
		printk("%s %d error: %d.\n", __FUNCTION__, __LINE__,res);
		res = -3;
	}
	
	oproto_free_io_pkt(sndpkt);
	oproto_free_io_pkt(recvpkt);
	return res;
}

/*****************************************************************************/
/***********for regop pkt list operation**************************************/
/*****************************************************************************/

struct oproto_packet* oproto_alloc_io_pkt(struct oproto* proto, gfp_t flags)
{
	struct oproto_packet* ret = kmalloc(proto->io_pkt_len, flags);
	if (NULL == ret) {
		printk("%s no enough mem\n", __FUNCTION__);
	}
	memset(ret, 0, proto->io_pkt_len);
	return ret;
}

void oproto_free_io_pkt(struct oproto_packet* pkt)
{
	if(pkt){
		kfree(pkt);
		pkt = NULL;
	}
}

inline struct list_head* __list_get_tail(struct list_head* head)
{
	return head->prev;
}

inline int oproto_OP_REG_per_pkt(struct oproto* proto)
{
	return (proto->io_pkt_len - sizeof(struct oproto_header) - sizeof(uint32_t)) / sizeof(struct oproto_OP_REG);
}

struct oproto_packet* __oproto_make_regop_pkt(struct oproto* proto)
{
	struct oproto_packet* pkt;
	
	pkt = oproto_alloc_io_pkt(proto, GFP_ATOMIC);		//GFP_KERNEL
	if(pkt == NULL)
		return pkt;
	
	pkt->header.proto_ver = OPROTO_VER;
	pkt->header.op_num = 0;
	spin_lock(&proto->index_lock);
	pkt->header.pkt_sn = proto->tx_pkt_index++;
	spin_unlock(&proto->index_lock);
	pkt->op_code = OP_REG;
	
	return pkt;
}

void __oproto_regop_pkt_reset(struct oproto_packet* pkt, struct oproto* proto)
{
	pkt->header.proto_ver = OPROTO_VER;
	pkt->header.op_num = 0;
	spin_lock(&proto->index_lock);
	pkt->header.pkt_sn = proto->tx_pkt_index++;
	spin_unlock(&proto->index_lock);
	pkt->op_code = OP_REG;
}

int regop_make(struct oproto_OP_REG* regop, uint8_t card, int modtype, unsigned int rw, uint8_t reg, uint8_t data)
{
#ifdef FXX_EXT
	regop->card = card;
	regop->card_property = 0;
	if(modtype)
		regop->card_property |= (1 << FXX_EXT_MODTYPE_BIT);
#else
	regop->card = modtype ? (card | (1<<MOD_TYPE_BIT)):card;
	regop->card_property = 0;
#endif
	regop->rw = rw;
	regop->addr = reg;
	regop->data = data;
		
	return 0;
}

int daisy_op_make(struct oproto_OP_REG* regop, uint8_t card)
{
#ifdef FXX_EXT
	regop->card = card;
	regop->card_property = 0;
	regop->card_property |= (1 << FXX_EXT_DAISY_BIT);
#else
	regop->card = card | (1<<SPI_DAISY_BIT);	
	regop->card_property = 0;
#endif
	regop->rw = MOD_REG_WR;
	regop->addr = 0;
	regop->data = 0x80;
		
	return 0;
}

int __oproto_iopkt_regop_add(struct oproto* proto, struct oproto_packet* pkt, struct oproto_OP_REG* op)
{
	int idx;
	struct oproto_OP_REG* tmp;
	
	if(pkt->header.op_num >= oproto_OP_REG_per_pkt(proto))
		return -1;
	
	tmp = (struct oproto_OP_REG*)pkt->body;
	
	idx = pkt->header.op_num;
	tmp[idx].card = op->card;
	tmp[idx].rw = op->rw;
	tmp[idx].card_property = op->card_property;
	tmp[idx].addr = op->addr;
	tmp[idx].data = op->data;	
	
	pkt->header.op_num++;
	return pkt->header.op_num;
}

op_pkt_list_t* __create_op_pkt_list(struct oproto* proto)
{
	op_pkt_list_t* res = kmalloc(sizeof(op_pkt_list_t), GFP_KERNEL);
	if(res == NULL)
		return res;
	
	INIT_LIST_HEAD(&res->list);
	res->proto = proto;
	res->pkt_num = 0;
	
	return res;
}

/* free reg operation pkt list */
void __free_op_pkt_list(op_pkt_list_t* pkt_list)
{
	struct list_head *pos,*tmp;
	op_pkt_node_t *obj;
	struct list_head *the_list = &pkt_list->list;
	
	list_for_each_safe(pos, tmp, the_list) 
	{
		obj = (op_pkt_node_t*)pos;
		list_del(pos);
		kfree(obj->op_pkt);
		kfree(obj);
	}
	kfree(pkt_list);
	pkt_list = NULL;
}

op_pkt_node_t *__op_pkt_list_addnode(op_pkt_list_t* pkt_list)
{
	op_pkt_node_t *node;
	
	node = kmalloc(sizeof(op_pkt_node_t), GFP_ATOMIC);	//GFP_KERNEL
	if(!node)
		return NULL;
	
	node->submited = 0;
	node->op_pkt = __oproto_make_regop_pkt(pkt_list->proto);
	if(!node->op_pkt){
		kfree(node);	
		return NULL;
	}
	
	list_add_tail((struct list_head*)node, (struct list_head*)pkt_list);
	pkt_list->pkt_num++; 
	
	return node;	
}

op_pkt_node_t * __op_pkt_list_addop(op_pkt_list_t* pkt_list,uint8_t card, int modtype, unsigned int rw, uint8_t reg, uint8_t data)
{
	op_pkt_node_t *node;
	struct oproto_OP_REG regop;
	
	if(!pkt_list)
		return NULL;
	
	if(pkt_list->pkt_num == 0){
		node = __op_pkt_list_addnode(pkt_list);
		if(!node)
			return NULL;
	}else{
		node = (op_pkt_node_t*)__list_get_tail((struct list_head*)pkt_list);
		if((node->submited)||  //pkt is submitted.
			 (node->op_pkt->header.op_num >= oproto_OP_REG_per_pkt(pkt_list->proto)) //pkt is full
			 )
		{	
			node = __op_pkt_list_addnode(pkt_list);
			if(!node)
				return NULL;
		}
	}
	
	regop_make(&regop, card, modtype, rw, reg, data);
	__oproto_iopkt_regop_add(pkt_list->proto, node->op_pkt, &regop);
	
	return node;
}

int pkt_comp_update(op_pkt_node_t *node,struct oproto_packet* src)
{
	int x;
	struct oproto_OP_REG *opdest,*opsrc;
	struct oproto_packet* dest = node->op_pkt;
	
	if(node->submited == 0)
		return 0;
	
	if((src->header.pkt_sn != dest->header.pkt_sn)||
		 (src->header.op_num != dest->header.op_num)||
		 (src->op_code != dest->op_code)
		)
	  return -1;
	
	opdest = (struct oproto_OP_REG *)dest->body;
	opsrc = (struct oproto_OP_REG *)src->body;
	for(x=0;x<src->header.op_num;x++){
		if((opdest[x].card != opsrc[x].card)||
			 (opdest[x].rw != opsrc[x].rw)||
			 (opdest[x].card_property != opsrc[x].card_property)||
			 (opdest[x].addr != opsrc[x].addr)
			)
			return -2;
	}
	for(x=0;x<src->header.op_num;x++){
		if(opdest[x].rw == MOD_REG_RD){
			opdest[x].data = opsrc[x].data;
#if 0
			//if(((opdest[x].card & 0x1f) == 3) && (opdest[x].addr == 31))
				printk("__wait_access op -------<< readback packet %d value 0x%02x\n",
																		node->op_pkt->header.pkt_sn, opdest[x].data);
#endif
		}
#if 0		
		else{
			//if(((opsrc[x].card & 0x1f) == 3) && (opsrc[x].addr == 64))
				printk("Write op jif=%ld -------<< readback packet %d value 0x%02x\n",
														jiffies,node->op_pkt->header.pkt_sn,opsrc[x].data);
		}
#endif
	}
 	
	return 0;
}

/******************************************************************************/
/***for regop list operations**************************************************/
/******************************************************************************/
regop_list_t* __create_regop_list(void)
{
	regop_list_t* res = kmalloc(sizeof(regop_list_t), GFP_KERNEL);
	if(res == NULL)
		return res;
	
	INIT_LIST_HEAD(&res->list);
	res->regop_num = 0;
	
	return res;
}

regop_node_t* __create_regop_node(regop_list_t *list)
{
	regop_node_t* node;
	
	if(!list)
		return NULL;
		
	node = kmalloc(sizeof(regop_node_t), GFP_ATOMIC);	//GFP_KERNEL
	if(node == NULL)
		return node;
	
	node->regop = kmalloc(sizeof(struct oproto_OP_REG), GFP_ATOMIC); 	//GFP_KERNEL
	if(!node->regop){
		kfree(node);
		return NULL;
	}
	
	memset(node->regop,0,sizeof(struct oproto_OP_REG));
	
	list_add_tail((struct list_head*)node, (struct list_head*)list);
	list->regop_num++;
	
	return node;
}

void __free_regop_list(regop_list_t* regop_list)
{
	struct list_head *pos,*tmp;
	regop_node_t *node;
	struct list_head *the_list = &regop_list->list;
	
	list_for_each_safe(pos, tmp, the_list) 
	{
		node = (regop_node_t*)pos;
		list_del(pos);
		kfree(node->regop);
		kfree(node);
	}
	kfree(regop_list);
	regop_list = NULL;
}

int __get_op_result(regop_list_t* regop_list, int card, uint8_t reg, uint8_t *data)
{
	int res=-1;
	struct list_head *pos,*tmp;
	regop_node_t *node;
	struct list_head *the_list = &regop_list->list;
	
	list_for_each_safe(pos, tmp, the_list) 
	{
		struct oproto_OP_REG* regop;
		node = (regop_node_t*)pos;
		
		regop = node->regop;
#ifdef FXX_EXT
		if(((regop->card&0x7f) == card)&&(regop->addr == reg)){
#else
		if(((regop->card&0x1f) == card)&&(regop->addr == reg)){
#endif
			if(regop->rw == MOD_REG_RD){
				*data = regop->data;
			}
			
			//remove the node
			list_del(pos);
			kfree(node->regop);
			kfree(node);
			regop_list->regop_num--;
			
			res = 0;
#if 0
			if(/*(card == 0) && */(reg == 31))
				printk(KERN_DEBUG ">>>>>>> %s card %d reg %d data = 0x%02x. jif=%lu\n",__FUNCTION__,card, reg,*data,jiffies);
#endif
			break;
		}
	}
	
	return res;
}

int __remove_regop(regop_list_t* regop_list, int card, uint8_t reg)
{
	int res = 0;
	struct list_head *pos,*tmp;
	regop_node_t *node;
	struct list_head *the_list = &regop_list->list;
	
	list_for_each_safe(pos, tmp, the_list) 
	{
		struct oproto_OP_REG* regop;
		node = (regop_node_t*)pos;
		
		regop = node->regop;
#ifdef FXX_EXT
		if(((regop->card&0x7f) == card)&&(regop->addr == reg)){
#else
		if(((regop->card&0x1f) == card)&&(regop->addr == reg)){
#endif
			//remove the node
			list_del(pos);
			kfree(node->regop);
			kfree(node);
			regop_list->regop_num--;
			
			res = 1;
			break;
		}
	}
	
	return res;
}

/***********************************************************************************
 *************construct/destruct****************************************************
 ***********************************************************************************/

int oproto_init(struct oproto* proto, oproto_callback_t tdm_callback, int tdm_urb_num, int tdm_dahdi_buf_len)
{
	int x;
	
	if(!proto->dev || !proto->usb_intf)
	 return -1 ;

	proto->tdm_callback = tdm_callback;
	proto->tdm_urb_num = tdm_urb_num;
	proto->tdm_dahdi_len = tdm_dahdi_buf_len ;
	
	proto->tx_pkt_index = 0;
	spin_lock_init(&proto->index_lock);
	
	proto->tx_pkt_counter = 0;
	proto->tx_err_counter = 0;
	proto->rx_pkt_counter = 0;
	proto->rx_err_counter = 0;
	
	if(init_tdm_dahdi_buf(proto))
		return -ENOMEM;
	
	proto->tdm_bulk_in_urbpool =  __oproto_alloc_tdm_urb_pool(proto, USB_DIR_IN);
	proto->tdm_bulk_out_urbpool = __oproto_alloc_tdm_urb_pool(proto, USB_DIR_OUT);
	proto->urb_task = kmalloc(sizeof(struct _urb_task)*proto->tdm_urb_num, GFP_KERNEL);
	
	if ( NULL == proto->tdm_bulk_in_urbpool || 
		   NULL == proto->tdm_bulk_out_urbpool ||
		   NULL == proto->urb_task) 
	{
		free_tdm_dahdi_buf(proto);
		__oproto_free_tdm_urb_pool(proto, proto->tdm_bulk_in_urbpool);
		__oproto_free_tdm_urb_pool(proto, proto->tdm_bulk_out_urbpool);
		if(proto->urb_task)
			kfree(proto->urb_task);
		printk("OPROTO: alloc urb pool failed\n");
		return -ENOMEM;
	}
	spin_lock_init(&proto->urb_lock);
	
	for(x=0;x<proto->tdm_urb_num;x++){
		proto->urb_task[x].task = 0;
	}
	proto->task_outp = 0;
	proto->task_inp = 0;
	spin_lock_init(&proto->task_lock);
	
	mutex_init(&proto->opmutex);
	
	return 0;
}

void oproto_clear(struct oproto* proto)
{
	int x;
	for(x=0; x<proto->tdm_urb_num; x++){
		struct urb_pool* up = &proto->tdm_bulk_in_urbpool[x];
		if (up->submitted) {
			usb_kill_urb(up->urb);
			up->submitted = 0;
		}
		up = &proto->tdm_bulk_out_urbpool[x];
		if (up->submitted) {
			usb_kill_urb(up->urb);
			up->submitted = 0;
		}
	}	
	
	free_tdm_dahdi_buf(proto);
	__oproto_free_tdm_urb_pool(proto, proto->tdm_bulk_in_urbpool);
	__oproto_free_tdm_urb_pool(proto, proto->tdm_bulk_out_urbpool);
	if(proto->urb_task)
		kfree(proto->urb_task);
}


/**************************************************************************/




