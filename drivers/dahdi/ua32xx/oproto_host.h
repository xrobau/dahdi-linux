
#ifndef __OPROTO_HOST_H__
#define __OPROTO_HOST_H__

typedef void (*oproto_callback_t)(struct urb*);

typedef enum {
  TSCAP_0 = 0,  //2.048M  32  TS
  TSCAP_1,      //4.096M  64  TS
  TSCAP_2       //8.192M  128 TS
} tdm_tscap_t;

struct urb_pool {
	int submitted;	/* =1 means already submitted to usb call, 0 = not submitted */
	struct urb* urb;
};

struct _urb_task {
	int task;
	struct urb* urb;
};

/* head of op_pkt list*/
typedef struct {
	struct list_head list;
	struct oproto* proto;
	int pkt_num;	
} op_pkt_list_t;

/* node of op_pkt list */
typedef struct {
	struct list_head list;	/* must be the first element */
	struct oproto_packet* op_pkt;
	int submited;
} op_pkt_node_t;

/* readback buf for read operations */
typedef struct {
	struct list_head list;
	int regop_num;
} regop_list_t;

/*node of regop_list_t*/
typedef struct {
	struct list_head list;
	struct oproto_OP_REG* regop;
} regop_node_t;

/*tdm dahdi buf, used for smoothing the USB velocity jitter.*/
typedef struct {
	unsigned char *buf;
	unsigned int frame_size;
	unsigned int frame_num;
	unsigned int frame_load;
	unsigned int inp;
	unsigned int outp;
	spinlock_t lock;
}	tdm_dahdi_buf_t;

/*
	command io is sync, tdm io is async.
*/
struct oproto {
	struct usb_device* dev;
	struct usb_interface* usb_intf;
	uint8_t io_bulk_in_endpointAddr;	/* the address of the bulk in endpoint */
	uint8_t io_bulk_out_endpointAddr;	/* the address of the bulk out endpoint */
	uint32_t io_pkt_len;				/* usb bulk packet length, for full speed , should be 64 here */

	uint8_t tdm_bulk_in_endpointAddr;	/* the address of the bulk in endpoint */
	uint8_t tdm_bulk_out_endpointAddr;	/* the address of the bulk out endpoint */
	uint32_t tdm_pkt_len;				/* usb bulk packet length, for full speed , should be 256 here */

	//struct usb_anchor bulk_anchor;
	struct urb_pool*	tdm_bulk_out_urbpool;		/* urbs for tdm bulk in/out */
	spinlock_t urb_lock;
	struct urb_pool*	tdm_bulk_in_urbpool;
	struct _urb_task* urb_task;        /* tasklet stack for urb complete callback */
	int task_outp;
	int task_inp;
	spinlock_t task_lock;
	
	int tdm_urb_num;
	
	tdm_dahdi_buf_t tdm_dahdi_rx_buf;
	int tdm_dahdi_len;
	unsigned char *tdm_tmpbuf;
	
	uint64_t tx_pkt_counter;	/* tx tdm packet counter */
	uint32_t tx_err_counter;	/* tx tdm packet error counter */
	uint64_t rx_pkt_counter;	/* rx tdm packet counter */
	uint32_t rx_err_counter;	/* rx tdm packet error counter */
	
	uint32_t tx_pkt_index;		/* index for tx io pkt */
	spinlock_t index_lock;
	
	oproto_callback_t tdm_callback;	/* tdm urbs callback */
	
	struct mutex	opmutex;	/* serializes I/O op	*/
};

/* alloc a packet, size is oproto->pkt_len */
struct oproto_packet* oproto_alloc_io_pkt(struct oproto* proto, gfp_t flags);
void oproto_free_io_pkt(struct oproto_packet* pkt);

/* alloc and init a oproto struct */
int oproto_init(struct oproto* proto,	oproto_callback_t tdm_callback, int tdm_urb_num, int tdm_dahdi_buf_len);

/* destroy a oproto struct, if free_mem is non zero, free memory */
void oproto_clear(struct oproto* proto);

int tdm_dahdi_buf_push(tdm_dahdi_buf_t* tdm_dahdi_buf, unsigned char *data);
int tdm_dahdi_buf_pop(tdm_dahdi_buf_t* tdm_dahdi_buf, unsigned char *data);
int tdm_dahdi_buf_load(tdm_dahdi_buf_t* tdm_dahdi_buf);

/* 
	alloc urb and related usb data buffer, bind them together
	tx: dir=USB_DIR_OUT, rx: dir=USB_DIR_IN
*/
int oproto_alloc_tdm_urb(struct oproto* proto, int dir, struct urb** urb);

/* alloc urb for tx, also set oproto_header.ver */
int oproto_alloc_tdm_tx_urb(struct oproto* proto, struct urb** urb);

/* free a urb created by oproto_alloc_urb */
void oproto_free_tdm_urb(struct oproto* proto, struct urb* urb);

#define oproto_urb_get_buf(urb)	 ( urb->transfer_buffer )

/* alloc and free pre-alloced tdm urb pool */
struct urb_pool* __oproto_alloc_tdm_urb_pool(struct oproto* proto, int dir);
void __oproto_free_tdm_urb_pool(struct oproto* proto, struct urb_pool* pool);

/* get and release tdm bulkout urb from urb pool */
struct urb* __oproto_get_tdm_bulkout_urb(struct oproto* prot);
int __oproto_release_tdm_bulkout_urb(struct oproto* prot, struct urb* urb);
int __oproto_release_tdm_bulkin_urb(struct oproto* prot, struct urb* urb);
void __oproto_push_task(struct oproto* proto, struct urb* urb);
struct urb* __oproto_pop_task(struct oproto* proto);

/* refill necessory information of a URB */
void __oproto_refill_tdm_urb(struct oproto* proto, int dir, struct urb* urb);

/*for sync io*/
int oproto_io_sync_op(struct oproto* proto, struct oproto_packet* sndpkt,struct oproto_packet* recvpkt);
int oproto_get_fwver(struct oproto* proto, struct oproto_packet* recvpkt);
int oproto_ext_reset(struct oproto* proto, int ms_enable, int ms_delay);
int oproto_tdm_op(struct oproto* proto,unsigned int op);
int oproto_get_report(struct oproto* proto,struct oproto_OP_REPORT *report);
int oproto_reset_report(struct oproto* proto);
int oproto_get_slotid(struct oproto* proto, uint8_t *slotid);
int oproto_cpld_sel_clk(struct oproto* proto, unsigned int clksrc);
int oproto_cfg_led(struct oproto* proto, unsigned int card, int modtype, unsigned int state);
int oproto_set_tscap(struct oproto* proto, uint8_t tscap);

/* get max allowed OP_REG operate per packet */
inline int oproto_OP_REG_per_pkt(struct oproto* proto);

inline struct list_head* __list_get_tail(struct list_head* head);

//regop pkt list operations
int regop_make(struct oproto_OP_REG* regop, uint8_t card, int modtype, unsigned int rw, uint8_t reg, uint8_t data);
int __remove_regop(regop_list_t* regop_list, int card, uint8_t reg);
int daisy_op_make(struct oproto_OP_REG* regop, uint8_t card);
struct oproto_packet* __oproto_make_regop_pkt(struct oproto* proto);
void __oproto_regop_pkt_reset(struct oproto_packet* pkt, struct oproto* proto);
int __oproto_iopkt_regop_add(struct oproto* proto, struct oproto_packet* pkt, struct oproto_OP_REG* op);
op_pkt_list_t* __create_op_pkt_list(struct oproto* proto);
void __free_op_pkt_list(op_pkt_list_t* pkt_list);
op_pkt_node_t *__op_pkt_list_addnode(op_pkt_list_t* pkt_list);
op_pkt_node_t * __op_pkt_list_addop(op_pkt_list_t* pkt_list,uint8_t card, int modtype, unsigned int rw, uint8_t reg, uint8_t data);
int pkt_comp_update(op_pkt_node_t *node,struct oproto_packet* src);

//for readback regop list operations
regop_list_t* __create_regop_list(void);
regop_node_t* __create_regop_node(regop_list_t *list);
void __free_regop_list(regop_list_t* regop_list);
int __get_op_result(regop_list_t* regop_list, int card, uint8_t reg, uint8_t *data);


#endif /* __OPROTO_HOST_H__ */
