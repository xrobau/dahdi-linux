/*
	SGM usb voice adapter packet format define.
	at moment support usb full speed only

*/


#ifndef __OPROTO_H__
#define __OPROTO_H__

#ifdef	__GNUC__
#define	PACKED	__attribute__((packed))
#elif defined STM32F042x6
#define PACKED __packed
#else
#error "We do not know how your compiler packs structures"
#endif

#define OPROTO_VER	((int)'O')

//#define FXX_EXT

#define DEV_FIFO_SIZE  4

/* SGM usb protocol define */
#define OP_GET_FWVER		1			/* get firmware version of device */
#define OP_EXT_RESET		2			/* reset external bus */
#define OP_REPORT			3			/* get device status report */
#define OP_STOP_TDM			4			/* stop transfer to host */
#define OP_START_TDM		5			/* start transfer to host */
#define OP_REG				6			/* register operate, it can hold multiple operate in one packet */
#define OP_REPORT_RESET  7

#define OP_TYPE_SEL_CLK         8
#define OP_TYPE_CFG_LED         6
#define OP_TYPE_GET_SLOTID      4
#define OP_TYPE_SET_TSCAP				2

#define CPLD_CLK_0              0
#define CPLD_CLK_1              1
#define CPLD_CLK_EXT            2

//for FXX module extend(max channels: 128).
#ifdef FXX_EXT
#define FXX_EXT_DAISY_BIT			1
#define FXX_EXT_MODTYPE_BIT		0
#else
#define SPI_DAISY_BIT       	5
#define MOD_TYPE_BIT        	6
#endif

#define MOD_REG_WR    1
#define MOD_REG_RD    0

#define DEFINE_OP_STRUCT(s)  PACKED struct oproto_ ## s


DEFINE_OP_STRUCT(OP_GET_FWVER){
	uint16_t build;	/* move to first line due to arm m0 do not support unaligned access. */
	uint8_t major;
	uint8_t minor;
	uint8_t bugfix;
};

DEFINE_OP_STRUCT(OP_RESET){
	uint16_t pulse_length;	// in ms, length of reset pulse
	uint16_t delay_after_reset;	// in ms, after reset pulse, wait delay ms.
};


DEFINE_OP_STRUCT(OP_REG){
  uint8_t card;												// card[5]: FXO(1)/FXS(0); card[4:0]: chip select
	unsigned int rw : 1;								// read or write reg. read:0,write:1.
	unsigned int card_property : 4;			// 
	uint8_t addr;												// register address;
	uint8_t data;
};

DEFINE_OP_STRUCT(OP_REPORT){
	uint64_t tdm_packet_received;	/* received tdm packet count */
	uint64_t tdm_packet_send;		/* send tdm packet count */
	uint32_t usb_cmd_tx_fail;		
	uint32_t usb_tdm_tx_fail;
	uint32_t tdm_txfifo_load;		/* usb to tdm fifo loading */
	uint32_t tdm_rxfifo_load;		/* tdm to usb fifo loading */
	uint32_t tdm_rx_fifo_overflow;	
	uint32_t tdm_tx_fifo_underflow;		
	uint32_t tdm_tx_fifo_overflow;
};

PACKED union oproto_body {
	DEFINE_OP_STRUCT(OP_GET_FWVER)		ver;
	DEFINE_OP_STRUCT(OP_RESET)			reset;
	DEFINE_OP_STRUCT(OP_REG)			reg;
	DEFINE_OP_STRUCT(OP_REPORT)			report;
};

PACKED struct oproto_header {
	uint16_t proto_ver;		/* version of SGM usb protocol */
	uint16_t op_num;			/* number of operator in this block */
	uint32_t pkt_sn;
};

PACKED struct oproto_packet {
	struct oproto_header header;
	uint32_t op_code;
	union oproto_body body[0];
};


#endif // __OPROTO_H__
