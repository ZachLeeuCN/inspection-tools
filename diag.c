#define _GNU_SOURCE	/* For crypt() and termios defines */
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <mtd/mtd-user.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <linux/version.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <mtd/mtd-user.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <linux/version.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <assert.h>
#include <openssl/md5.h> //For MD5


#include "lib_gpioctl.h"

#undef INSPECTION_DEBUG
#define INSPECTION_DEBUG 1

#ifdef CONFIG_DIAG_FW_NORMAL_MODEL
#error "**************** Success config kernel@inspction source  ******************"
#endif

typedef unsigned char           unchar;
typedef unsigned short          ushort;
typedef unsigned int            uint;
typedef unsigned long           ulong;

typedef unsigned char           uchar;
typedef volatile unsigned long  vu_long;
typedef volatile unsigned short vu_short;
typedef volatile unsigned char  vu_char;

typedef unsigned int            u32;



int globaldebug = 1;
#define MTD_NAME_SUPPORT_MAX_LENGTH 32

#define YAMAHA_Header_Len 0x100

#define UBOOT_MTD_NAME      "0:APPSBL"
#define STROAGE_MTD_NAME    "0:HWDATA"
#define ART_MTD_NAME        "0:ART"
#define STROAGE_MTD_LENGTH  0x10000
#define WLX_HWDATA_SIZE 0x10000
uchar hwdata[WLX_HWDATA_SIZE];

#define MAC_LENGTH				6
#define DEVICE_NAME_LENGTH		16
#define BOOTCODE_VERSION_LENGTH	18
#define BUILD_DATE_LENGTH		28
#define HARDWARE_VERSION_LENGTH	1
#define SERIAL_NUMBER_LENGTH	12
#define INSPECTION_LENGTH		1
#define PASSWORD_LENGTH			1
#define DUALIMAGE_LENGTH		1

#define LAN_MAC_OFFSET			0x00
#define WLANG_MAC_OFFSET		0x06
#define WLANA1_MAC_OFFSET		0x0c
#define WLANA2_MAC_OFFSET		0x12


/* 18(WLANA2_MAC_OFFSET) + 6 = 24(0x18) */
#define DEVICE_NAME_OFFSET	(WLANA2_MAC_OFFSET+6)
/* Device name has variant length which <= 15. So we reserve 16, the 1st byte is for storing length */
#define DEVICE_NAME_LENGTH	16

/* 24(DEVICE_NAME_OFFSET) + 16 (DEVICE_NAME_LENGTH) = 40(0x28) */
#define BOOTCODE_VERSION_OFFSET	(DEVICE_NAME_OFFSET+DEVICE_NAME_LENGTH)  /* 40(0x28) */
/* Bootcode Version has variant length which <= 18. So we reserve 17, the 1st byte is for storing length  */
#define BOOTCODE_VERSION_LENGTH	18

/* 40(BOOTCODE_VERSION_OFFSET) + 18(BOOTCODE_VERSION_LENGTH) = 58(0x3a) */
#define BUILD_DATE_OFFSET (BOOTCODE_VERSION_OFFSET+BOOTCODE_VERSION_LENGTH) /* 58(0x3a) */
/* BUILD DATE has variant length which <= 27. So we reserve 28, the 1st byte is for storing length */
#define BUILD_DATE_LENGTH 28

/* 58(BUILD_DATE_OFFSET) + 28 (BUILD_DATE_LENGTH) = 86(0x56) */
#define HARDWARE_VERSION_OFFSET (BUILD_DATE_OFFSET+BUILD_DATE_LENGTH) /* 86(0x56) */
/* Hardware version is 1 digi */
#define HARDWARE_VERSION_LENGTH 1

/* 86(HARDWARE_VERSION_OFFSET) + 1(HARDWARE_VERSION_LENGTH) = 87(0x57) */
#define SERIAL_NUMBER_OFFSET (HARDWARE_VERSION_OFFSET+HARDWARE_VERSION_LENGTH) /* 87(0x57) */
/* Serial number has variant length which <= 11. So we reserve 12, the 1st byte is for storing length */
#define SERIAL_NUMBER_LENGTH 12

/* 87(SERIAL_NUMBER_OFFSET + 12(SERIAL_NUMBER_LENGTH) = 99(0x63) */
#define INSPECTION_OFFSET (SERIAL_NUMBER_OFFSET+SERIAL_NUMBER_LENGTH) /* 99(0x63) */
/* INSPECTION enable is 1 digi */
#define INSPECTION_LENGTH 1

/* 99(INSPECTION_OFFSET + 1(INSPECTION_LENGTH) = 100(0x64) */
#define PASSWORD_OFFSET (INSPECTION_OFFSET+INSPECTION_LENGTH) /* 100(0x64) */
/* PASSWORD enable is 1 digi */
#define PASSWORD_LENGTH 1

/* 100(PASSWORD_OFFSET + 1(PASSWORD_LENGTH) = 101(0x65) */
#define DUALIMAGE_OFFSET (PASSWORD_OFFSET+PASSWORD_LENGTH) /* 101(0x65) */
/* Dual Image enable is 1 digi */
#define DUALIMAGE_LENGTH 1



#define POE_AF_AT     28
#define POE_POW_DET   32
#define POE_AD_DET    38



#define ROOTFS_0_MTD_NAME "firmware"
#define ROOTFS_1_MTD_NAME "firmware_bak"
#define ROOTFS_2_MTD_NAME "firmware3"

#define FIT_DESCRIPT_STRING "Flashing emmc 200 200"
#define ETH_PORT_ID "2"
#define WLX_0_KERNEL_NAME  "kernel1"
#define WLX_1_KERNEL_NAME  "kernel2"
#define WLX_2_KERNEL_NAME  "kernel3"


#define WLX_ROOTFS_0_DEFAULT_ROOTFS_NAME  "rootfs1"
#define WLX_ROOTFS_1_DEFAULT_ROOTFS_NAME  "rootfs2"
#define WLX_ROOTFS_2_DEFAULT_ROOTFS_NAME  "rootfs3"

#define WLX_YAMAHA_ROOTFS_0_DEFAULT_MOUNT_POINT "/mnt/rootfs1"
#define WLX_YAMAHA_ROOTFS_1_DEFAULT_MOUNT_POINT "/mnt/rootfs2"
#define WLX_YAMAHA_ROOTFS_2_DEFAULT_MOUNT_POINT "/mnt/rootfs3"   /*Used for compare firmware*/

#define QUALCOMM_CDT_MTD_NAME  "0:CDT"
#define QUALCOMM_CDT_DATA_LENGTH  548
#define QUALCOMM_CDT_DATA_PATCHED_MD5 "e365079e04cec8c666f6a51eac291cc1"
static char DEV_CDT_MTD_NAME[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_CDT_MTD_INDEX[MTD_NAME_SUPPORT_MAX_LENGTH];

#define YAMAHA_WLX_CFG_MTD_NAME "0:CFG"
static char DEV_ROOTFS_0_MTD_NAME[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_KERNEL_0_MTD_INDEX[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_ROOTFS_0_MTD_INDEX[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_ROOTFS_0_SQUASHFS_MTD_INDEX[MTD_NAME_SUPPORT_MAX_LENGTH];

static char DEV_ROOTFS_1_MTD_NAME[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_KERNEL_1_MTD_INDEX[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_ROOTFS_1_MTD_INDEX[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_ROOTFS_1_SQUASHFS_MTD_INDEX[MTD_NAME_SUPPORT_MAX_LENGTH];

static char DEV_ROOTFS_2_MTD_NAME[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_KERNEL_2_MTD_INDEX[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_ROOTFS_2_MTD_INDEX[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_ROOTFS_2_SQUASHFS_MTD_INDEX[MTD_NAME_SUPPORT_MAX_LENGTH];

#define WLX_FW_DESCRAMBLE_UBI_ROOTFS_IMG_FILE "/tmp/wlx_fw_decrypt_rootfs.bin"
#define WLX_FW_DESCRAMBLE_FILE "/tmp/wlx_fw_decrypt.bin"
#define WLX_FW_ROOTFS_RAW_FILE "/tmp/wlx_rootfs.bin"
#define TMP_FIT_IMAGE_HEADER_NAME "/tmp/_wxr2xxx_fit_hdr.txt"
#define UBOOT_FLASH_BIN "/tmp/flash_uboot.bin"

static char *get_mtd_device_name(char *tg_mtd_name, char *dst_mtd_name);
#define MTD_INDEX_MAX_LENGTH 8
static char FULL_NAND_MTD_INDEX[MTD_INDEX_MAX_LENGTH];// FULL NAND FOR BAD BLOCK
static char PRODUCTFW_ROOTFS_0_MTD_INDEX[MTD_INDEX_MAX_LENGTH];// FULL NAND FOR BAD BLOCK
static char PRODUCTFW_ROOTFS_1_MTD_INDEX[MTD_INDEX_MAX_LENGTH];// FULL NAND FOR BAD BLOCK
static char PRODUCTFW_ROOTFS_2_MTD_INDEX[MTD_INDEX_MAX_LENGTH];// FULL NAND FOR BAD BLOCK
static char PRODUCTFW_SQUASHFS_ROOTFS_0_MTD_NAME[MTD_INDEX_MAX_LENGTH];
static char PRODUCTFW_SQUASHFS_ROOTFS_1_MTD_NAME[MTD_INDEX_MAX_LENGTH];
static char PRODUCTFW_SQUASHFS_ROOTFS_2_MTD_NAME[MTD_INDEX_MAX_LENGTH];

static char YAMAHA_WLX_CFG_MTD_INDEX[MTD_INDEX_MAX_LENGTH];// FULL NAND FOR BAD BLOCK


static char *get_mtd_device_name_index(char *tg_mtd_name, char *dst_mtd_name, int nname);
static int get_mtd_device_size(char *tg_mtd_name, int SecondSameMtdName);

static void get_hwparam_device_name(void);
static char hwparam_device_name[DEVICE_NAME_LENGTH];
static char header_device_name[DEVICE_NAME_LENGTH];

extern char *__progname;
FILE *open_file(const char *filename, const char *mode);
int check_sn(unsigned char SN[]);
static void usage_allparam(void);
static int getfilesize(char *fname);

static void fetch_tftp_server_addr(void);
static void usage_usb_device_status(void);
static void usage_usb_read_speed_check(void);
static void usage_md5();
static void usage_boardinfo(void);
static void usage_eeprom(void);
static void usage_inspect_version(void);
static void usage_write_image_to_eeprom(void);
static void usage_bootcode_version();
static void usage_tftp_server_ipaddr(void);
static void usage_inspect_fw_lanip_addr(void);
static void usage_get_bme280(void);
static void usage_get_aquantia_phy_identity(void);
static void usage_get_aquantia_phy_firmware_version(void);
static void usage_get_poe_config(void);
static void usage_get_bt_status(void);
static void usage_get_rtc_clk(void);
static void usage_get_tpm2(void);
static void usage_get_hwset_param(void);
static void usage_get_bluetooth_param(void);
static void usage_wanport_stat(void);
static void fetch_wanport_stat(void);
static void usage_bad_block_check(void);
static void usage_baf_synchronize_check(void);
static void usage_ddr3_asr_check(void);
static void usage_ecc_correction_check(void);
static void write_image_to_eeprom(int i2c_addr, char *image_name_to_program,
                                  int erase_before_write);
static void fetch_aquantia_phy_identity(void);
static void fetch_aquantia_phy_firmware_version(void);
static void fetch_poe_setting(void);
static void fetch_bluetooth_status(void);
static void usage_temperature_check(void);
static void usage_firmware_version(void);
static void usage_hardware_version(void);
static void usage_wlanmac(void);
static void usage_lanmac(void);
static void usage_allmac(void);
static void usage_firmware_fit();
static void usage_cal_check();
static void usage_remount();
int do_erase_art_mtd(void);



static void usage_reset_firmware_default_config();
static void usage_bootloader_resetenv();
static void usage_erase_art_mtd();
static void usage_flash_fwmd5();
static void usage_firmware_md5();
static void usage_firmware();
static void usage_bootloader();
static void usage_usb_io_check(void);
static int write_mem_to_mtd(char *mtd_dev_name, char *write_buffer, u32 write_size);
static int write_mem_to_mtd_force_size(char *mtd_dev_name, char *write_buffer, int write_size);
static int cal_file_md5(char *file, int len, char md5_ret[15]);


static char DEV_UBOOT_MTD_NAME[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_ROOT_0_MTD_NAME[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_ROOT_1_MTD_NAME[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_ROOT_2_MTD_NAME[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_HWDATA_MTD_NAME[MTD_NAME_SUPPORT_MAX_LENGTH];
static char DEV_ART_MTD_NAME[MTD_NAME_SUPPORT_MAX_LENGTH];

#define BOOTLOADER_MTD_DEV_NAME "0:APPSBL"
static  char BOOT_LOADER_MTD_INDEX_NAME[MTD_NAME_SUPPORT_MAX_LENGTH];


int do_ipq_cal_check(void);
ulong get_mtd_erase_block_size(char *mtd_dev_name);

#define DEFAULT_I2C_EEPROM_ADDRSS 0x53
#define DEFAULT_I2C_EEPROM_IMG_NAME "eeprom-pinocchio.bin"
#define DEFAULT_ERASE_BEFORE_WRITE 0  //default write directly - not erase eeprom content

#define RD_CMD_ALLPARAM          "all"
#define RD_CMD_BD_INFO           "boardinfo"
#define RD_CMD_BOOTCODE_VER      "bootcode_ver"
#define RD_CMD_EEPROM            "eeprom"
#define RD_CMD_PROGRAM_EEPROM    "program_eeprom"
#define UG_CMD_MD5 			         "md5"
#define RD_CMD_WANSTAT           "ethstat"

#define	RD_CMD_BAD_BLOCKCHECK    "bad_block"
#define	RD_CMD_DDR3_ASR_CHECK    "asr"
#define	RD_CMD_ECCCHECK          "ecc_correction"


#define RD_CMD_INSPECT_FW_LAN_IP "inspect_lanip"
#define RD_CMD_INSPECT_FW_WAN_IP "inspect_wanip"
#define RD_CMD_TFTP_SRV_IP       "tftp_srvip"
#define RD_CMD_USB_DEV_SPEED_CHECK  "usb_device_speed"
#define RD_CMD_USBCHECK          "usb"
#define RD_CMD_USBREADSPEEDCHECK  "usbreadspeed"
#define RD_CMD_USBREADWRITECHECK  "usbreadwrite"
#define RD_CMD_BME280            "bme280"
#define RD_CMD_AQR_IDENTITY			 "aq_phy_id"
#define RD_CMD_AQR_FW_VER			   "aq_fw_ver"
#define RD_CMD_POE			 				 "poe"
#define RD_CMD_BT_STATUS				 "btstat"
#define RD_CMD_RTC               "rtc"
#define RD_CMD_TPM2               "tpm2"
#define RD_CMD_BTPARAM           "btparam"
#define BUF_ROOTFS_0_MTD_NAME      "nand_full"
#define RD_CMD_INSPECT_VER       "inspect_ver"
#define	RD_CMD_CHK_TEMPERATURE		"temperature"
#define RD_CMD_HWPARAM           "hwparam"
#define RD_CMD_FW_VER			       "fw_ver"
#define RD_CMD_HW_VER            "hw_ver"
#define RD_CMD_WLANMAC			     "wlanmac"
#define RD_CMD_LANMAC			       "lanmac"
#define RD_CMD_ALLMAC			       "mac"
#define RD_CMD_FLASH_FWMD5       "flash_fwmd5"

#define CG_CMD_CALCHECK          "calcheck"

#define UG_CMD_BDF 				        "bdf"

#define UG_CMD_BOOTLOADER 			 "bootloader"
#define UG_CMD_FIRMWARE 				 "firmware"
#define UG_CMD_FIRMWAREMD5 			 "fwmd5"
#define UG_CMD_FIT_FIRMWARE      "fitimg"
#define UG_CMD_FS_REMOUNT        "remount"


#define UG_CMD_RESETBOOTENV 	   "resetbootenv"
#define UG_CMD_RESETDEFAULT 	   "resetdefault"
#define UG_CMD_ERASE_CALDATA     "eraseart"

#define SHELL_USER_PRIVILEGE        0
#define SHELL_HIDDEN_PRIVILEGE      1
#define SHELL_ADMIN_PRIVILEGE       2
#define SHELL_FILTER                6

#define TMP_FW_IMAGE_FILE_NAME "/tmp/__tmp_firmware__.bin"
#define TFTP_DEFAULT_BLOCK_SIZE 65464   /*octects*/
#define LAN_IF_IF_NAME "br-lan"

#define DEFAULT_FW_UPDATE_SERVERIP "192.168.100.10"

char tftp_server_ip_address[128] = {DEFAULT_FW_UPDATE_SERVERIP};


typedef int (*cmdline_func)(int, char *[], char *tty_name); /*Add tty name*/
typedef void (*help_func)(void) ;

typedef struct s_dni_command {
    const char *command_name ;            // the command name
    const char *command_description ;       // help text
    cmdline_func read_func_entry;               // action routine for the command
    cmdline_func write_func_entry;               // action routine for the command
    help_func help_func_entry;               // action routine for the command
    char privilege ;                 // privilege attribute
} dni_command_t ;

/*For parse MBN header*/
typedef struct {
    unsigned int image_type;
    unsigned int header_vsn_num;
    unsigned int image_src;
    unsigned char *image_dest_ptr;
    unsigned int image_size;
    unsigned int code_size;
    unsigned char *signature_ptr;
    unsigned int signature_size;
    unsigned char *cert_chain_ptr;
    unsigned int cert_chain_size;
} mbn_header_t;

typedef struct {
    char  description[64];
} fit_img_header_t;






static dni_command_t inspection_utility_commands_tbl[] = {

    { RD_CMD_ALLPARAM,   "get all paramaters", NULL, NULL, &usage_allparam , SHELL_USER_PRIVILEGE },
    { RD_CMD_BD_INFO,      "get current borad information", NULL, NULL, usage_boardinfo , SHELL_USER_PRIVILEGE },
    //{ RD_CMD_EEPROM,     "get/set check eeprom h/w read/write function", NULL,NULL,&usage_eeprom ,SHELL_USER_PRIVILEGE },
    //{ RD_CMD_PROGRAM_EEPROM,     "update eeprom image", NULL,NULL,&usage_write_image_to_eeprom ,SHELL_USER_PRIVILEGE },
    { UG_CMD_MD5,        "calculate file md5", NULL, NULL, usage_md5 , SHELL_USER_PRIVILEGE },
    { RD_CMD_BOOTCODE_VER, "get boot loader version", NULL, NULL, usage_bootcode_version , SHELL_USER_PRIVILEGE },
    { RD_CMD_TFTP_SRV_IP, "get/set tftp server ipaddr", NULL, NULL, usage_tftp_server_ipaddr , SHELL_USER_PRIVILEGE },
    { RD_CMD_INSPECT_FW_LAN_IP, "get inspect firmware lan ipaddr", NULL, NULL, usage_inspect_fw_lanip_addr , SHELL_USER_PRIVILEGE },
    //{ RD_CMD_BME280,		"get BME280 data", NULL,NULL,usage_get_bme280 ,SHELL_USER_PRIVILEGE },
    //{ RD_CMD_AQR_IDENTITY,		"get aquantia phy identity", NULL,NULL,usage_get_aquantia_phy_identity ,SHELL_USER_PRIVILEGE },
    //{ RD_CMD_AQR_FW_VER,		  "get aquantia phy firmware version", NULL,NULL,usage_get_aquantia_phy_firmware_version ,SHELL_USER_PRIVILEGE },

    { RD_CMD_POE,		"get poe status", NULL, NULL, usage_get_poe_config , SHELL_USER_PRIVILEGE },
    //{ RD_CMD_RTC,		"get rtc ds1340x clk", NULL,NULL,usage_get_rtc_clk ,SHELL_USER_PRIVILEGE },
    //{ RD_CMD_TPM2,		"get on board tpm2 chip data", NULL,NULL,usage_get_tpm2 ,SHELL_USER_PRIVILEGE },
    //{ RD_CMD_BTPARAM,		"get on board bluetooth parameters", NULL,NULL,usage_get_bluetooth_param ,SHELL_USER_PRIVILEGE },
    //{ RD_CMD_BT_STATUS,		"get bluetooth rssi", NULL,NULL,usage_get_bt_status ,SHELL_USER_PRIVILEGE },
#ifdef SUPPORT_USB
    { RD_CMD_USBCHECK, 			 "check usb device spec", NULL, NULL, usage_usb_device_status  , SHELL_USER_PRIVILEGE },
    { RD_CMD_USB_DEV_SPEED_CHECK,   "detect usb read speed", NULL, NULL, usage_usb_read_speed_check , SHELL_USER_PRIVILEGE },
#endif
    { RD_CMD_WANSTAT, 		 "get ethernet port status", NULL, NULL, usage_wanport_stat , SHELL_USER_PRIVILEGE },
#ifdef SUPPORT_NAND
    { RD_CMD_BAD_BLOCKCHECK, "check bad block status", NULL, NULL, usage_bad_block_check , SHELL_USER_PRIVILEGE },
#endif
#ifdef SUPPORT_DDR_ASR
    { RD_CMD_DDR3_ASR_CHECK, "check DDR3 ASR status", NULL, NULL, usage_ddr3_asr_check , SHELL_USER_PRIVILEGE },
#endif
    { UG_CMD_BDF, "product and diag firmware bdf compare", NULL, NULL, usage_baf_synchronize_check , SHELL_USER_PRIVILEGE },

    { RD_CMD_ECCCHECK,     "check ecc correction status", NULL, NULL, usage_ecc_correction_check , SHELL_USER_PRIVILEGE },
    { RD_CMD_CHK_TEMPERATURE, "get i2c thirmal temperature", NULL, NULL, usage_temperature_check, SHELL_USER_PRIVILEGE },
    { RD_CMD_HWPARAM,		"get on board hwsetting parameters", NULL, NULL, usage_get_hwset_param , SHELL_USER_PRIVILEGE },
    { RD_CMD_FW_VER,       "get	firmware version", NULL, NULL, usage_firmware_version , SHELL_USER_PRIVILEGE },
    { RD_CMD_HW_VER,       "get	hardware version", NULL, NULL, usage_hardware_version , SHELL_USER_PRIVILEGE },
    { RD_CMD_LANMAC,       "(r) get lan default MAC address", NULL, NULL, usage_lanmac, SHELL_USER_PRIVILEGE },
    { RD_CMD_WLANMAC,	   "(r) get wireless default MAC address", NULL, NULL, usage_wlanmac , SHELL_USER_PRIVILEGE },
    { RD_CMD_ALLMAC,       "get all default mac address", NULL, NULL, usage_allmac , SHELL_USER_PRIVILEGE },
    { RD_CMD_INSPECT_VER,  "get current inspection firmware version ", NULL, NULL, usage_inspect_version , SHELL_USER_PRIVILEGE },
    { RD_CMD_FLASH_FWMD5,	 "get firmware md5 from flash", NULL, NULL, usage_flash_fwmd5 , SHELL_USER_PRIVILEGE },

    { UG_CMD_RESETDEFAULT, "reset fimrware default config", NULL, NULL, usage_reset_firmware_default_config , SHELL_USER_PRIVILEGE },
    { UG_CMD_RESETBOOTENV, "reset loader default config", NULL, NULL, usage_bootloader_resetenv , SHELL_USER_PRIVILEGE },
    { UG_CMD_ERASE_CALDATA, "reset art mtd data (Only before calibration used)", NULL, NULL, usage_erase_art_mtd , SHELL_USER_PRIVILEGE },
    { UG_CMD_BOOTLOADER, 	 "upgrade on-flash loader via tftp", NULL, NULL, usage_bootloader , SHELL_USER_PRIVILEGE },
    { UG_CMD_FIRMWAREMD5,	 "Generate/Compare remote firmware md5 info file - wlxmd5info.txt", NULL, NULL, usage_firmware_md5 , SHELL_USER_PRIVILEGE },
    { UG_CMD_FIRMWARE, 		 "Check/upgrade on-flash firmware(kernel+rootfs) via tftp", NULL, NULL, usage_firmware , SHELL_USER_PRIVILEGE },
    { UG_CMD_FIT_FIRMWARE, "upgrade on-flash firmware (FIT image) via tftp", NULL, NULL, usage_firmware_fit , SHELL_USER_PRIVILEGE },
    { UG_CMD_FS_REMOUNT, "remount all rootfs", NULL, NULL, usage_remount , SHELL_USER_PRIVILEGE },
    { CG_CMD_CALCHECK,   "Check on flash calibration valid or not ", NULL, NULL, usage_remount , SHELL_USER_PRIVILEGE },

#if 0
    { RD_CMD_FW_BUILD_DATE, "get FW Build Date", NULL, NULL, usage_fw_build_date , SHELL_USER_PRIVILEGE },
    { RD_CMD_DEST_COUNTRY,  "get/set destination country ", NULL, NULL, usage_destination_country_version , SHELL_USER_PRIVILEGE },
    { RD_CMD_SWITCH_ANTENNA, "set	QCA 9980 antenna config", NULL, NULL, usage_switch_antenna , SHELL_USER_PRIVILEGE },
    //{ RD_CMD_REGION,			 "get/set default region", NULL,NULL,usage_region ,SHELL_USER_PRIVILEGE },
    { UG_CMD_FIRMWARE_INFO, "check firmware size,md5 info via tftp", NULL, NULL, usage_firmware_info , SHELL_USER_PRIVILEGE },
    //{ RD_CMD_UBI_VOL_STATUS,"display ubifs volume size", NULL,NULL,usage_fetch_ubifs_volume_statue ,SHELL_USER_PRIVILEGE },
    //{ RD_CMD_BB_STATUS,"display bad block status", NULL,NULL,usage_fetch_bad_block_statue ,SHELL_USER_PRIVILEGE },
#endif

};

int filesize(char *filename )
{
    int size;
    struct stat statbuf;

    if (stat(filename, &statbuf) == -1) {

        return 0;
    }
    return statbuf.st_size;

}

int file_exist(char *filename)
{
    struct stat buffer;

    return (stat(filename, &buffer) == 0);
    // int i=stat (filename,buffer);

}
int calcsum(const char *ifname, int offset, unsigned long target_size)
{
    FILE *fin;
    int i, n;
    unsigned char ch[129];
    unsigned char checksum = 0;
    int fdin, len = 0;
    int exitcode = 0;
    int size_wanted = 0;
    int reach_target_size = 0;
    unsigned char not_full_size = (target_size != 0) ? 1 : 0;

    if ((fin = open_file(ifname, "rb")) == NULL) {
        exit(errno);
    }
    fdin = fileno(fin);
#ifdef INSPECTION_DEBUG
    printf("========> target_size=%d <========\n", target_size);
#endif

    lseek(fdin, offset, SEEK_SET);

    while (((n = read(fdin, ch, 128)) > 0) && (reach_target_size != 1)) {
        for(i = 0; i < n; i++) {
            checksum = (checksum + ch[i]) & 0xFF;

            if(not_full_size) {
                size_wanted++;

                if(size_wanted >= target_size) {
                    // printf("size_wanted reach target size(%d) break twice! \n",target_size);
                    len += (i + 1);
                    reach_target_size = 1;

                    close_file(fin);
#ifdef INSPECTION_DEBUG
                    printf("last byte value:0X%2X\n", ch[i - 1]);
                    printf("checksum (normal)= 0x%02X, len = %d@1\n", checksum, len);
#endif
                    checksum = ~checksum;
#ifdef INSPECTION_DEBUG
                    printf("checksum = 0x%02X, len = %d\n", checksum, len);
#endif

                    return checksum;
                }
            }
        }

        len += n;
    }
#ifdef INSPECTION_DEBUG
    printf("last byte value:0X%2X\n", ch[i - 1]);
    printf("checksum (normal)= 0x%02X, len = %d@2\n", checksum, len);
#endif
    checksum = ~checksum;
#ifdef INSPECTION_DEBUG
    printf("checksum (~)= 0x%02X, len = %d@2\n", checksum, len);
#endif
    if (checksum != 0x00) {
        exitcode = 1;
    }

    close_file(fin);
    return checksum;
    //return exitcode;
}

FILE *open_file(const char *filename, const char *mode)
{
    FILE *f;

    f = fopen(filename, mode);
    if (f == NULL)
        fprintf(stderr,
                "open_input(\"%s\") failed: %s\n",
                filename, strerror(errno));
    return f;
}

int close_file(FILE *f)
{
    int s = 0;

    if (f == NULL) {
        return 0;
    }
    errno = 0;
    s = fclose(f);
    if (s == EOF) {
        perror("Close failed");
    }
    return s;
}
/****************************************************************************************************************/
int get_ipaddr(char *in_name, char *ipaddr_return)
{
    int fd;
    struct ifreq ifr;

    if(!in_name) {
        printf("Interface name required!\n");
        return -1;
    }
    if(!ipaddr_return) {
        printf("Ipaddress string required!\n");
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;

    /* I want IP address attached to "eth0" */
    strncpy(ifr.ifr_name, in_name, IFNAMSIZ - 1);

    if(ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
        // printf("ioctl get if -%s inet address fail\n",in_name);
        sprintf(ipaddr_return, "---.---.---.---");
        printf("%s", ipaddr_return );
        return ;
    }

    close(fd);

    /* display result */
    printf("%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    strcpy(ipaddr_return, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    return 0;
}


int copy_file_to_buf(char *file_name, long offset, char *buffer, u32 in_cp_size)
{
    FILE  *fptr_source;
    u32 copysize;
    fpos_t pos;
    u32 total_read_bytes = 0;
    u32 read_size = 0;
    long new_offset = (long)offset;
    if(!file_name) {
        return -1;
    }
    if(!buffer) {
        return -1;
    }
    copysize = (u32)in_cp_size;
    /*	printf("copy_file_to_buf:  copysize=%d\n",copysize);*/

    fptr_source = fopen(file_name, "rb");

    if( fptr_source == NULL ) {
#ifdef INSPECTION_DEBUG
        printf("copy_file_to_buf: Open file  %s to read Fail\n", file_name);
#endif
        return -1;
    }

    fseek(fptr_source, offset, SEEK_SET);

    if(fread((void *)buffer, sizeof(unsigned char), copysize, fptr_source) <= 0) {
#ifdef INSPECTION_DEBUG
        printf("COPY %s Firmware from offset %d to buffer Fail\n", file_name, offset);
#endif
        if(fptr_source) {
            fclose(fptr_source);
        }
        return -1;
    }
    if(fptr_source) {
        //	printf("copy_file_to_buf: free file pointer\n");
        fclose(fptr_source);
    }

    //printf("copy_file_to_buf: all done\n");

    return 0;
}


/****************************************************************************************************************/
int copy_buf_to_file(char *file_name, int offset, char *buffer, unsigned long in_cp_size)
{
    FILE  *fptr_destination;
    int copysize;
    if(!file_name) {
        printf("copy_buf_to_file : null file name \n");
        return -1;
    }
    if(!buffer) {
        printf("copy_buf_to_file : empty buffer \n");
        return -1;
    }
    copysize = (int)in_cp_size;
    /*	printf("copy_file_to_buf:  copysize=%d\n",copysize);*/

    fptr_destination = fopen(file_name, "a+");

    if( fptr_destination == NULL ) {
#ifdef INSPECTION_DEBUG
        printf("copy_buf_to_file: Open file  <%s> to write Fail\n", file_name);
#endif
        return -1;
    }
#ifdef INSPECTION_DEBUG
    printf("copy_buf_to_file: Open file  %s to write successfully \n", file_name);
#endif

    fseek(fptr_destination, offset, SEEK_SET);

    if(fwrite((void *)buffer, sizeof(unsigned char), copysize, fptr_destination) <= 0) {
#ifdef INSPECTION_DEBUG
        printf("COPY %s Firmware to buffer offset %d Fail\n", file_name, offset);
#endif
        if(fptr_destination) {
            fclose(fptr_destination);
        }
        return -1;
    }

    if(fptr_destination) {
        fclose(fptr_destination);
    }
    return 0;
}


/****************************************************************************************************************/
void show_all_usage()
{
    int cmd;
    int num_of_commands = sizeof(inspection_utility_commands_tbl) / sizeof(
                              inspection_utility_commands_tbl[0]);


    printf("Usage: %s [command switch] [arg0] [arg1] ...\n", __progname);
    printf("Usage: %s -h [command switch] for specific command in detail\n", __progname);
    printf("  valid [command switch] list as follow: \n");

    // fprintf(stderr,"-------- support command list --------\n");
    for ( cmd = 0; cmd < num_of_commands; ++cmd ) {
        printf("          %-32s - %s\n", inspection_utility_commands_tbl[cmd].command_name,
               inspection_utility_commands_tbl[cmd].command_description);
    }
    printf("\n");

};

void show_specific_cmd_usage(char *cmd_name)
{
    int cmd;
    int num_of_commands = sizeof(inspection_utility_commands_tbl) / sizeof(
                              inspection_utility_commands_tbl[0]);

    if(!cmd_name) {
        printf("Invalid command name..\n");
        return;
    }

    // fprintf(stderr,"-------- support command list --------\n");
    for ( cmd = 0; cmd < num_of_commands; ++cmd ) {
        if(strcmp(cmd_name, inspection_utility_commands_tbl[cmd].command_name) == 0) {
            if(inspection_utility_commands_tbl[cmd].help_func_entry != NULL) {
                inspection_utility_commands_tbl[cmd].help_func_entry();
            }
        }
    }
    printf("\n");

};



/*-----------------------------------------------------------------------------------*/

/*-----------------------------------------VENDOR END-------------------------------------------*/

/*-----------------------------------------BOOTCODE VER -------------------------------------*/
static void fetch_bootcode_version_on_the_fly(void)
{
    char cmd[256] = "";
    char uboot_part_name[128];
    char buf_to_parse[256];
    FILE *fp = NULL;
    char line[128];
    char *cp = NULL;

    if(get_mtd_device_name(BOOTLOADER_MTD_DEV_NAME, BOOT_LOADER_MTD_INDEX_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
        printf("Success get %s mtd device name - %s\n", BOOT_LOADER_MTD_INDEX_NAME,
               BOOTLOADER_MTD_DEV_NAME);
#endif
    } else {
        printf("Bootcode ver            : %s\n", "NA");
        return -1;
    }

    memset(cmd, '\0', sizeof(cmd));
    sprintf(cmd,
            "printf \"Bootcode ver            : \";strings %s| grep -v DEI| grep -E \"BootROM VER|BootROM Ver|BootRom Ver\" |  awk '{print $2}' | cut -c5-",
            BOOT_LOADER_MTD_INDEX_NAME);
    system(cmd);

    return 0;
}



static void usage_bootcode_version()
{
    printf("Get boot loader version, get support only\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_BOOTCODE_VER);
}





/*----------------------------------------- Get FILE MD5 ---------------------------------*/

static void usage_md5()
{
    printf("Calculate file's MD5 SUM\n");
    printf("remount -\n");
    printf("Usage: %s -c %s [FILE NAME] [offset] [size]\n", __progname, UG_CMD_MD5);
    printf("[file name] : file name with full path\n");
    printf("[offset]    : file offset to start calculate md5\n");
    printf("[size]      : file size to calculate md5\n");
}


int do_calmd5(char *filename, int offset, unsigned long md5_size)
{
    FILE *fp = NULL;
    int file_size = 0;
    unsigned char file_md5_digit[16];
    char *file_buffer = NULL;
    int i;

    if(!filename) {
        printf("do_calmd5 : NO file name input\n");
        return ;
    }

    fp = fopen(filename, "rb");
    if (!fp) {
        printf("Open %s error!\n", filename);
        return;
    }
    if(!md5_size) {
        file_size = getfilesize(filename);
    } else {
        if(md5_size > getfilesize(filename)) {
            printf("MD5 check size %lu > file size - %d\n", md5_size, getfilesize(filename));
            return;
        }
        file_size = md5_size;
    }

    printf("md5_size=%d file_size = %d\n", md5_size, file_size);

    file_buffer = malloc(sizeof(char) * (file_size));

    fseek(fp, offset, SEEK_SET);

    if(fread(&file_buffer[0], sizeof(unsigned char), file_size, fp) <= 0) {
        printf("Read content of file -\"%s\" fail\n", filename);
        if(file_buffer) {
            free(file_buffer);
        }
        fclose(fp);
        return -1;
    }
    MD5((unsigned char *)&file_buffer[0], file_size, file_md5_digit);
    printf("FILE - %s MD5: ", filename);

    for(i = 0; i < 16; i++) {
        printf("%02x", file_md5_digit[i]);
    }
    printf("\n");

    if(file_buffer) {
        free(file_buffer);
    }


}
/*----------------------------------------- END OF Get FILE MD5 -----------------------------*/




/*---------------------------------------- TFTP START ---------------------------------*/

static void usage_tftp_server_ipaddr(void)
{
    printf("Get/Set current tftp server ipaddress. (for update firmware/loader)\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_TFTP_SRV_IP);

    printf("write -\n");
    printf("Usage: %s -u %s [new tftp server ip]\n", __progname, RD_CMD_TFTP_SRV_IP);
}

static void fetch_tftp_server_addr(void)
{
    printf("Tftp server ip          : %s\n", tftp_server_ip_address);
    //printf("TFTP SERVER IP          : %s\n",tftp_server_ip_address);
    return;
}

int do_tftp_srv_ipaddr_set(char *serverip)
{
    if(!serverip) {
        printf("Invalid null tftp server ip address set\n");
        usage_tftp_server_ipaddr();
        return -1;
    }

    memset(tftp_server_ip_address, '\0', sizeof(tftp_server_ip_address));
    strcpy(tftp_server_ip_address, serverip);

    fetch_tftp_server_addr();

}

/*----------------------------------------- TFTP END ----------------------------------*/
/*---------------------------------------- INSPECT FW LAN IP START ---------------------------------*/
static void usage_inspect_fw_lanip_addr(void)
{
    printf("Get current system lan ip address\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_INSPECT_FW_LAN_IP);

}


static void fetch_inspect_lan_ip_addr(void)
{
    char lan_ip[128];

    //printf("INSPECT-FW LAN IP       : ");
    printf("Lan ip                  : ");
    get_ipaddr(LAN_IF_IF_NAME, lan_ip);
    printf("\n");

    return;
}
/*---------------------------------------- INSPECT FW LAN IP STOP ---------------------------------*/

/*---------------------------------------- INSPECT FW BME280 START ---------------------------------*/
static void usage_get_bme280(void)
{
    printf("Get current i2c bme280 data.\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_BME280);

}


static void fetch_bme280(void)
{
    char cmd[256];
    //Temperature
    memset(cmd, '\0', sizeof(cmd));
    sprintf(cmd, "%s",
            "printf \"Temperature             : \";bme280 /dev/i2c-0 | awk '{if(NR==2) print$1,$2,substr($3, 1, length($3)-1)}'");

    //printf("Execute cmd===>%s <===\n",cmd);
    system(cmd);

    //Pressure
    memset(cmd, '\0', sizeof(cmd));
    sprintf(cmd, "%s",
            "printf \"Pressure                : \";bme280 /dev/i2c-0 | awk '{if(NR==2) print$4,substr($5, 1, length($5)-1)}'");

    //printf("Execute cmd===>%s <===\n",cmd);
    system(cmd);


    //Humidity
    memset(cmd, '\0', sizeof(cmd));
    sprintf(cmd, "%s",
            "printf \"Humidity                : \";bme280 /dev/i2c-0 | awk '{if(NR==2) print$6,substr($7, 1, length($7)-1)}'");

    //printf("Execute cmd===>%s <===\n",cmd);
    system(cmd);




    return;
}
/*---------------------------------------- INSPECT FW BME280 STOP ---------------------------------*/


/*---------------------------------------- INSPECT FW RTC CLK START ---------------------------------*/
static void usage_get_rtc_clk(void)
{
    printf("Get current i2c bme280 data.\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_RTC);

}


static void fetch_rtc_clk(void)
{
    char cmd[256];
    //Temperature
    memset(cmd, '\0', sizeof(cmd));
    sprintf(cmd, "%s",
            "printf \"RTC                     : \";/sbin/hwclock -r | awk '{print$1,$2,$3,$4,$5}'");

    //printf("Execute cmd===>%s <===\n",cmd);
    system(cmd);





    return;
}
/*---------------------------------------- INSPECT FW RTC CLK  STOP ---------------------------------*/


/*---------------------------------------- INSPECT FW TPM2 START ---------------------------------*/
static void usage_get_tpm2(void)
{
    printf("Get current tpm2 chip data.\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_TPM2);

}


static void fetch_tpm2_data(void)
{
    FILE *fp;
    char cmd[256];
    char line[80] ;
    char dumy[80] ;
    char menufacturestring[80] ;
    char vendorstring[80] ;
    char firmwarestring[80] ;

    char *TPM_PT_MANUFACTURER, *TPM_PT_VENDOR_STRING, *TPM_PT_FIRMWARE_VERSION;

    /*Makesure driver loaded*/
    memset(cmd, '\0', sizeof(cmd));
    system("/usr/sbin/lsmod |grep tpm > /tmp/check_tpm_load.txt");

    if(filesize("/tmp/check_tpm_load.txt") == 0) { //not install yet
        system("insmod /lib/modules/4.4.60/tpm.ko");
        system("insmod /lib/modules/4.4.60/tpm_spi_tis.ko");
    }

    system("/usr/sbin/eltt2 -g >/tmp/tpm.log");

    fp = fopen("/tmp/tpm.log", "r");
    if (!fp) {
        printf("fetch_tpm2_data: Open device %s error!\n", "/tmp/tpm.log");
        return -1;
    }


    while( fgets (line, 80, fp) != NULL ) {
        if (TPM_PT_MANUFACTURER =  strstr(line, "TPM_PT_MANUFACTURER:") ) {
            // printf("line string =%s\n",line);
            sscanf(line, "%s %s", &dumy, &menufacturestring);
            //  printf("menufacturestring string =%s\n",menufacturestring);


        } else if (TPM_PT_VENDOR_STRING =  strstr(line, "TPM_PT_VENDOR_STRING:") ) {
            // printf("line string =%s\n",line);
            sscanf(line, "%s %s", &dumy, &vendorstring);
            //printf("vendorstring string =%s\n",vendorstring);

        }
        if (TPM_PT_FIRMWARE_VERSION =  strstr(line, "TPM_PT_FIRMWARE_VERSION:") ) {
            //printf("line string =%s\n",line);
            sscanf(line, "%s %s", &dumy, &firmwarestring);
            //  printf("firmwarestring string =%s\n",firmwarestring);
            break;

        } else { //if(find != strstr(line,str1))// || (find != strstr(line,str2)))
            // printf("Still processing");

        }
    };

    printf("TPM_PT_MANUFACTURER     : %s\n", menufacturestring);
    printf("TPM_PT_VENDOR_STRING    : %s\n", vendorstring);
    printf("TPM_PT_FIRMWARE_VERSION : %s\n", firmwarestring);



    fclose(fp);


    return;
}
/*---------------------------------------- INSPECT FW TPM2 STOP ---------------------------------*/

/*---------------------------------------- INSPECT HWSETING PARAM START ---------------------------------*/
static void usage_get_hwset_param(void)
{
    printf("Get current hwset info.\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_HWPARAM);

}


static void fetch_hwsetting_param(void)
{
    FILE *fp;
    char cmd[256];
    unsigned char *mac_p = NULL;
    unsigned char mac_file[24] = {0xff};
    char device_name[DEVICE_NAME_LENGTH + 1] = {'\0'};
    char pid_length = 0;
    unsigned char serial[SERIAL_NUMBER_LENGTH + 1] = {'\0'};
    unsigned char serial_lenght = 0;
    char password[PASSWORD_LENGTH] = {0};
    char hwversion[HARDWARE_VERSION_LENGTH] = {0};
    char dualimage[DUALIMAGE_LENGTH] = {0};
    unsigned char hwsetmac_in_string[4][30] = {'\0'};

    int i = 0, j;

    fp = fopen(DEV_HWDATA_MTD_NAME, "r");
    if (!fp) {
        printf("Open device %s error!\n", DEV_HWDATA_MTD_NAME);
        return -1;
    }

    mac_p = &mac_file;
    fseek(fp, 0x0, SEEK_SET);
    for(i = 0; i < 24; i++) {
        *mac_p = fgetc(fp);
        mac_p++;
    }
#ifdef INSPECTION_DEBUG
    printf("mac file dump { \n");
    for(i = 0; i < 24; i++) {
        printf("%02x", mac_file[i]);
        if((i % 6) == 5) {
            printf("\n");
        } else {
            printf(":");
        }
    }
    printf("} \n");
#endif

    for(i = 0; i < 24; i++) {
        if(mac_file[i] >= 'a' && mac_file[i] <= 'z') {
            mac_file[i] = mac_file[i] - 32;
        }
    }

    for(j = 0; j < 4; j++) {
        sprintf(&hwsetmac_in_string[j][0], "%02x:%02x:%02x:%02x:%02x:%02x", mac_file[(6 * j) + 0],
                mac_file[(6 * j) + 1], mac_file[(6 * j) + 2], mac_file[(6 * j) + 3], mac_file[(6 * j) + 4],
                mac_file[(6 * j) + 5]);
    }
#ifdef INSPECTION_DEBUG
    printf("hwsetmac_in_string content dump { \n");
    for(i = 0; i < 24; i++) {
        printf("%02x", mac_file[i]);
        if((i % 7) == 6) {
            printf("\n");
        } else {
            printf(":");
        }
    }
    printf("} \n");
#endif

#ifdef INSPECTION_DEBUG
    for(j = 0; j < 4; j++) {
        printf("hwsetmac_in_string[%d]=%s\n", j, &hwsetmac_in_string[j]);
    }
    for(j = 0; j < 4; j++) {
        printf("bt_mac2[%d]=%s\n", j, &hwsetmac_in_string[j][0]);
    }
#endif

    /*HWSETTING MACS*/
    read_hwsetting(hwdata, WLX_HWDATA_SIZE);

    printf("LAN MAC                 : %02x:%02x:%02x:%02x:%02x:%02x\n", hwdata[LAN_MAC_OFFSET],
           hwdata[LAN_MAC_OFFSET + 1], hwdata[LAN_MAC_OFFSET + 2], hwdata[LAN_MAC_OFFSET + 3],
           hwdata[LAN_MAC_OFFSET + 4], hwdata[LAN_MAC_OFFSET + 5]);
    printf("2G MAC                  : %02x:%02x:%02x:%02x:%02x:%02x\n", hwdata[WLANG_MAC_OFFSET],
           hwdata[WLANG_MAC_OFFSET + 1], hwdata[WLANG_MAC_OFFSET + 2], hwdata[WLANG_MAC_OFFSET + 3],
           hwdata[WLANG_MAC_OFFSET + 4], hwdata[WLANG_MAC_OFFSET + 5]);
    printf("5G MAC                  : %02x:%02x:%02x:%02x:%02x:%02x\n", hwdata[WLANA1_MAC_OFFSET],
           hwdata[WLANA1_MAC_OFFSET + 1], hwdata[WLANA1_MAC_OFFSET + 2], hwdata[WLANA1_MAC_OFFSET + 3],
           hwdata[WLANA1_MAC_OFFSET + 4], hwdata[WLANA1_MAC_OFFSET + 5]);
    if (strcmp(hwparam_device_name, "WLX323") == 0) {
        printf("5G2/6G1 MAC             : %02x:%02x:%02x:%02x:%02x:%02x\n", hwdata[WLANA2_MAC_OFFSET],
               hwdata[WLANA2_MAC_OFFSET + 1], hwdata[WLANA2_MAC_OFFSET + 2], hwdata[WLANA2_MAC_OFFSET + 3],
               hwdata[WLANA2_MAC_OFFSET + 4], hwdata[WLANA2_MAC_OFFSET + 5]);
    }

    /*DEVICE NAME*/
    fseek(fp, DEVICE_NAME_OFFSET, SEEK_SET);
    pid_length = fgetc(fp);
#ifdef INSPECTION_DEBUG
    printf("pid_length=%d\n", pid_length);
#endif
    if((pid_length < DEVICE_NAME_LENGTH) && (pid_length != 0)) {
        memset(device_name, '\0', sizeof(device_name));
        for(i = 0; i < pid_length; i++) {
            device_name[i] = fgetc(fp);
        }
        printf("DEVICE NAME             : %s\n", device_name);
    } else {
        //printf("DEVICE NAME             : %s\n",device_name);
        //printf("DEVICE NAME             : %s\n","----------------");

        sprintf(device_name, "%s", "NA");
        printf("DEVICE NAME             : %s\n", device_name);
    }
    /*SERIAL*/

    fseek(fp, SERIAL_NUMBER_OFFSET, SEEK_SET);
    serial_lenght = fgetc(fp);
#ifdef INSPECTION_DEBUG
    printf("serial length=%d\n", serial_lenght);
#endif
    memset(serial, '\0', SERIAL_NUMBER_LENGTH + 1);

    if((serial_lenght < SERIAL_NUMBER_LENGTH) && (serial_lenght != 0) ) {
        fseek(fp, SERIAL_NUMBER_OFFSET + 1,
              SEEK_SET); //Jacky.Xue: Skip 1st byte,dute to it define serial length.
        for(i = 0; i < serial_lenght; i++) {
            serial[i] = fgetc(fp);
        }
        printf("SERIAL NUMBER           : %s\n", serial );
    } else {
        printf("SERIAL NUMBER           : %s\n", "NA");
    }



    /*PASSWORD*/
    memset(password, '\0', PASSWORD_LENGTH);
    fseek(fp, PASSWORD_OFFSET, SEEK_SET);
    for(i = 0; i < PASSWORD_LENGTH; i++) {
        password[i] = fgetc(fp);
    }
    printf("PASSWORD                : %d\n", password[0]);

    /*HARDWARE VERSION*/
    memset(hwversion, '\0', HARDWARE_VERSION_LENGTH);
    fseek(fp, HARDWARE_VERSION_OFFSET, SEEK_SET);
    for(i = 0; i < HARDWARE_VERSION_LENGTH; i++) {
        hwversion[i] = fgetc(fp);
    }
    printf("HARDWARE VER            : %d\n", hwversion[0]);

    /*DUALIMAGE SETTING*/
    memset(dualimage, '\0', DUALIMAGE_LENGTH);
    fseek(fp, DUALIMAGE_OFFSET, SEEK_SET);
    for(i = 0; i < DUALIMAGE_LENGTH; i++) {
        dualimage[i] = fgetc(fp);
    }
    printf("DUAL IMAGE              : %d\n", dualimage[0]);

    /*INSPECTION MODE*/
    system("fw_printenv inspection 1>/tmp/inspection.txt 2>/dev/null;");

    if(filesize("/tmp/inspection.txt") != 0) {
        system("echo -n \"INSPECTION              : \";fw_printenv  | grep inspection | awk -F '=' '{print $2}'");
    } else {
        printf("INSPECTION              : NA\n");
    }
    fclose(fp);

    return;
}
/*---------------------------------------- INSPECT FW HWSETING PARAM STOP ---------------------------------*/




/*---------------------------------------- INSPECT FW BLUETOOTH PARAM START ---------------------------------*/
/*
   static void usage_get_bluetooth_param(void)
   {
   printf("Get current i2c bme280 data.\n");
   printf("read -\n");
   printf("Usage: %s -r %s\n",__progname,RD_CMD_BTPARAM);

   }
/*------------------------------------------DEVICE NAME START------------------------------------------------------*/
void get_hwparam_device_name(void)
{
    FILE *fp = NULL;
    char length = 0;
    int i = 0;

    fp = fopen(DEV_HWDATA_MTD_NAME, "r");
    if (!fp) {
#ifdef INSPECTION_DEBUG
        printf("Open %s mtd failed, use WLX322 as default device name\n", DEV_HWDATA_MTD_NAME);
#endif
        sprintf(hwparam_device_name, "WLX322");
        sprintf(header_device_name, "Ragtime322");
        return;
    }

    fseek(fp, DEVICE_NAME_OFFSET, SEEK_SET);
    length = fgetc(fp);

    if((length < DEVICE_NAME_LENGTH) && (length != 0)) {
        memset(hwparam_device_name, '\0', DEVICE_NAME_LENGTH);
        for(i = 0; i < length; i++) {
            hwparam_device_name[i] = fgetc(fp);
        }
#ifdef INSPECTION_DEBUG
        printf("Device Name: %s\n", hwparam_device_name);
#endif
        if (strncmp(hwparam_device_name, "WLX323", strlen("WLX323")) == 0) {
            sprintf(header_device_name, "Ragtime323");
        } else {
            sprintf(header_device_name, "Ragtime322");
        }
    } else {
#ifdef INSPECTION_DEBUG
        printf("Length %d is incorrect\n", length);
#endif
        sprintf(hwparam_device_name, "WLX322");
        sprintf(header_device_name, "Ragtime322");
    }

    return;
}
/*------------------------------------------DEVICE NAME END------------------------------------------------------*/

/*-----------------------------------------USB DIAG START------------------------------------------*/

#define DEFAULT_USB_TEST_FILE_NAME "usb_test.img"

#define DEFAULT_USB_TEST_FILE_NAME_FULL_PATH "/tmp/"DEFAULT_USB_TEST_FILE_NAME

#define USB_0_DEFAULT_MOUNT_POINT "/mnt/USB-A1"
#ifdef SUPPORT_2ND_USB
#define USB_1_DEFAULT_MOUNT_POINT "/mnt/USB-A2"
#endif

#define USB_0_TEST_FILE_NAME  USB_0_DEFAULT_MOUNT_POINT"/"DEFAULT_USB_TEST_FILE_NAME
#ifdef SUPPORT_2ND_USB
#define USB_1_TEST_FILE_NAME  USB_1_DEFAULT_MOUNT_POINT"/"DEFAULT_USB_TEST_FILE_NAME
#endif




#define USB_0_RD_RESULE_TMP_FILES "/tmp/usb0_read.log.txt"
#define USB_0_WD_RESULE_TMP_FILES "/tmp/usb0_write.log.txt"
#ifdef SUPPORT_2ND_USB
#define USB_1_RD_RESULE_TMP_FILES "/tmp/usb1_read.log.txt"
#define USB_1_WD_RESULE_TMP_FILES "/tmp/usb1_write.log.txt"
#endif
static void usage_usb_io_check(void)
{
    printf("Check default usb devices read/write\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_USBCHECK);
    printf("check -\n");
    printf("Usage: %s -c %s %s\n", __progname, RD_CMD_USBCHECK, DEFAULT_USB_TEST_FILE_NAME);
    printf("Usage: %s -c %s %s 192.168.100.123\n", __progname, RD_CMD_USBCHECK);
    printf("Usage: %s -c %s\n", __progname, RD_CMD_USBCHECK);
    printf("Usage: %s -c %s\n", __progname, RD_CMD_USBCHECK);



    return;
}

//#define TMP_USB_TEST_FILE_NAME     "__tmp_usb_test.img"
int do_usb_io_check(int argc, char *argv[])
{
    char target_usb_test_file_name[256];
    char remote_frimware_image_name[256];
    char tftp_server_ip[256];
    char localcmd[256];
    char local_test_file_name[128];
    static int usb_id;
    int file_size = 0;
    int checksum = 0;
    int i;

#ifdef INSPECTION_DEBUG
    printf("################## argc =%d ##################\n", argc);
    for(i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
#endif


    if(argc > 4 || argc < 3) {
        usage_usb_io_check();
        return -1;
    }

    if(argc == 3) {
        strcpy(remote_frimware_image_name, DEFAULT_USB_TEST_FILE_NAME);
        strcpy(tftp_server_ip, tftp_server_ip_address);
        usb_id = 2;
    }

    else if(argc == 4) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, tftp_server_ip_address);
        usb_id = 2;
    }

    else  {
        usage_usb_io_check();
        return -1;


    }
#ifdef INSPECTION_DEBUG
    printf("remote_frimware_image_name=%s\n", remote_frimware_image_name);
    printf("tftp_server_ip=%s\n", tftp_server_ip);
    printf("usb_id=%d\n", usb_id);
#endif

    memset(localcmd, '\0', sizeof(localcmd));
    sprintf(localcmd, "cd /tmp;/usr/bin/tftp -g %s -r %s -l /tmp/%s -b %d", tftp_server_ip,
            remote_frimware_image_name, remote_frimware_image_name, TFTP_DEFAULT_BLOCK_SIZE);
    system(localcmd);


    if(1) {

        system("ls -al /mnt");
        memset(local_test_file_name, '\0', sizeof(local_test_file_name));
        sprintf(local_test_file_name, "%s/%s", USB_0_DEFAULT_MOUNT_POINT, remote_frimware_image_name);
        printf("local_test_file_name =%s\n", local_test_file_name);
        // printf("file %s exist=%d@1\n",USB_0_TEST_FILE_NAME,file_exist(USB_0_TEST_FILE_NAME));
        // printf("file %s exist=%d@1\n",DEFAULT_USB_TEST_FILE_NAME_FULL_PATH,file_exist(DEFAULT_USB_TEST_FILE_NAME_FULL_PATH));
        // printf("file %s exist=%d@1\n","/tmp/1234.txt",file_exist("/tmp/1234.txt"));

        if(file_exist(local_test_file_name) != 0) {

#ifdef INSPECTION_DEBUG
            printf("USB 0 TEST FILE NAME=%s\n", local_test_file_name);
#endif

            file_size = getfilesize(local_test_file_name);
            if(file_size > 0x5000000)  { //File over 80M
#ifdef INSPECTION_DEBUG
                printf("USB 0 TEST FILE size=%d\n", file_size);
#endif

                checksum = calcsum(local_test_file_name, 0, file_size);

                //printf("USB 0 TEST FILE CHECKSUM: 0X%X\n",checksum);
                printf("USB test file %s checksum = 0x%02x, len = %d\n", local_test_file_name, checksum, file_size);

                //Check Read Speed
                /*Config not using cache*/
                system("echo 3 > /proc/sys/vm/drop_caches");
                memset(localcmd, '\0', sizeof(localcmd));
                sprintf(localcmd, "dd if=%s of=/dev/null bs=1M count=%d oflag=sync &> %s", local_test_file_name,
                        file_size / (1024 * 1024), USB_0_RD_RESULE_TMP_FILES );
                system(localcmd);
                printf("EXECUTE cmd =%s@ usb 1\n", localcmd);


                memset(localcmd, '\0', sizeof(localcmd));
                sprintf(localcmd,
                        "speedMB=\`cat %s | grep bytes | awk {'printf$8'}\`;speedMbps=$(echo $speedMB \\* 8 | bc); echo \"%s \"$speedMB \"MB/s\"\" (${speedMbps} Mbps)\"",
                        USB_0_RD_RESULE_TMP_FILES, "USB 0 Read Speed   :");
                system(localcmd);
                printf("EXECUTE cmd =%s@ usb 2\n", localcmd);


                //Check Write Speed
                /*Config not using cache*/
                system("echo 3 > /proc/sys/vm/drop_caches");
                memset(localcmd, '\0', sizeof(localcmd));
                sprintf(localcmd, "dd if=/dev/zero of=%s bs=1M count=%d oflag=sync &> %s", local_test_file_name,
                        file_size / (1024 * 1024), USB_0_WD_RESULE_TMP_FILES );
                system(localcmd);
#ifdef INSPECTION_DEBUG
                printf("execute command :==> %s <== done !\n", localcmd);
#endif

                memset(localcmd, '\0', sizeof(localcmd));
                sprintf(localcmd,
                        "speedMB=\`cat %s | grep bytes | awk {'printf$8'}\`;speedMbps=$(echo $speedMB \\* 8 | bc); echo \"%s \"$speedMB \"MB/s\"\" (${speedMbps} Mbps)\"",
                        localcmd, "USB 0 Write Speed  :");
                system(localcmd);
                printf("execute localcmd :==> %s <== done !\n", localcmd);



                // memset(localcmd,'\0',sizeof(localcmd));
                // sprintf(localcmd,"rm -rf %s %s %s %s",USB_0_WD_RESULE_TMP_FILES,USB_0_RD_RESULE_TMP_FILES,USB_0_TEST_FILE_NAME,USB_0_RD_RESULE_TMP_FILES);
                // system(localcmd);
                //  printf("EXECUTE cmd =%s\n",localcmd);

                //  printf("\n");
            }   /*End of chcksum over 50M*/
            else {
                printf("%s test file(%s) size too small (< 80MB)\n", (argc == 3) ? "Local" : "Remote",
                       local_test_file_name);
            }

        } /*End of file exist*/
        else {
            memset(target_usb_test_file_name, '\0', sizeof(target_usb_test_file_name));
            sprintf(target_usb_test_file_name, "%s/%s", USB_0_DEFAULT_MOUNT_POINT, remote_frimware_image_name);
            printf("target_usb_test_file_name =%s\n", target_usb_test_file_name);
            printf("%s test file(%s) not exist!\n", (argc == 3) ? "Local" : "Remote", local_test_file_name);
            //printf("USB 0 Test File    : %s NA\n", target_usb_test_file_name);
            printf("USB golden disk usb test image -%s not exist\n", target_usb_test_file_name);
            printf("Create USB test image %s now ...\n", target_usb_test_file_name);
            memset(localcmd, '\0', sizeof(localcmd));
            /*Generat 100MB test image*/
            sprintf(localcmd, "dd if=/dev/urandom of=%s/%s bs=1048576 count=100", USB_0_DEFAULT_MOUNT_POINT,
                    remote_frimware_image_name);
            system(localcmd);
            printf("done ...\n");
            printf("Now the USB golden disk is ready to test using follow test command\n");
            printf("diag -c usb %s\n", remote_frimware_image_name);




        }

    }
#ifdef SUPPORT_2ND_USB
    if(usb_id == 1 || usb_id == 2) {
        memset(localcmd, '\0', sizeof(localcmd));
        sprintf(localcmd, "cd /tmp;/bin/cp /tmp/%s %s", DEFAULT_USB_TEST_FILE_NAME,
                USB_1_DEFAULT_MOUNT_POINT);
        system(localcmd);


        /// printf("file %s exist=%d@1\n",USB_1_TEST_FILE_NAME,file_exist(USB_1_TEST_FILE_NAME));
        /// printf("file %s exist=%d@1\n",DEFAULT_USB_TEST_FILE_NAME_FULL_PATH,file_exist(DEFAULT_USB_TEST_FILE_NAME_FULL_PATH));
        /// printf("file %s exist=%d@1\n","/tmp/1234.txt",file_exist("/tmp/1234.txt"));

        if(file_exist(USB_1_TEST_FILE_NAME) != 0) {
            file_size = getfilesize(USB_1_TEST_FILE_NAME);
#if 0
            printf("file_size=%d\n", file_size);
#endif

            checksum = calcsum(USB_1_TEST_FILE_NAME, 0, 0);
            printf("%s checksum = 0x%02x, len = %d\n", "USB 1 Test File    :", checksum, file_size);
            //Check Read Speed
            /*Config not using cache*/
            system("echo 3 > /proc/sys/vm/drop_caches");

            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd, "dd if=%s of=/dev/null bs=1M count=%d conv=sync &> %s", USB_1_TEST_FILE_NAME,
                    file_size / (1024 * 1024), USB_1_RD_RESULE_TMP_FILES);
            system(localcmd);

            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd,
                    "speedMB=\`cat %s | grep bytes | awk {'printf$8'}\`;speedMbps=$(echo $speedMB \\* 8 | bc); echo \"%s \"$speedMB \"MB/s\"\" (${speedMbps} Mbps)\"",
                    USB_1_RD_RESULE_TMP_FILES, "USB 1 Read Speed   :");
            system(localcmd);

            //Check Write Speed
            /*Config not using cache*/
            system("echo 3 > /proc/sys/vm/drop_caches");
            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd, "dd if=/dev/zero of=%s bs=1M count=%d conv=sync &> %s", USB_1_TEST_FILE_NAME,
                    file_size / (1024 * 1024), USB_1_WD_RESULE_TMP_FILES );
            system(localcmd);
            //printf("execute command :==> %s <== done !\n",localcmd);

            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd,
                    "speedMB=\`cat %s | grep bytes | awk {'printf$8'}\`;speedMbps=$(echo $speedMB \\* 8 | bc); echo \"%s \"$speedMB \"MB/s\"\" (${speedMbps} Mbps)\"",
                    USB_1_WD_RESULE_TMP_FILES, "USB 1 Write Speed  :");
            system(localcmd);
            //printf("execute command :==> %s <== done !\n",localcmd);

            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd, "rm -rf %s %s %s %s", USB_1_WD_RESULE_TMP_FILES, USB_1_RD_RESULE_TMP_FILES,
                    USB_1_TEST_FILE_NAME, USB_1_RD_RESULE_TMP_FILES);
            system(localcmd);


        }
    }
#endif


    if(file_exist(DEFAULT_USB_TEST_FILE_NAME_FULL_PATH) != 0) {
        memset(localcmd, '\0', sizeof(localcmd));
        sprintf(localcmd, "rm -rf %s", DEFAULT_USB_TEST_FILE_NAME_FULL_PATH);
        system(localcmd);
    }


    return 0;

}



#define USB_1_RD_RESULE_TMP_FILES "/tmp/usb1_read.log.txt"
#define USB_0_WD_RESULE_TMP_FILES "/tmp/usb0_write.log.txt"
#define USB_1_WD_RESULE_TMP_FILES "/tmp/usb1_write.log.txt"


static void usage_usb_read_speed_check(void)
{
    printf("Get default usb devices read speed\n");

    printf("read -\n");
    printf("Usage: %s -r %s [test image name] [image szie] \n", __progname, RD_CMD_USB_DEV_SPEED_CHECK);
    printf("check -\n");
    printf("Usage: %s -c %s [test image name ]\n\n", __progname, RD_CMD_USB_DEV_SPEED_CHECK);

    printf("                [test image name ]:\n");
    printf("                                   specify a test image in usb disk,if test file not exist\n");
    printf("                                   command will autogenerat one for next test\n");
    printf("                [image szie      ]:\n");
    printf("                                   specify a test image size, if not specifice default 40 , unit is MBytes\n");
    printf("                                   range 2~ 200 MB \n");




    return;
}

//#define TMP_USB_TEST_FILE_NAME     "__tmp_usb_test.img"
int do_usb_read_speed_check(int argc, char *argv[])
{

    char local_usb_test_image_name[256];
    char target_usb_test_file_name[256];
    //char tftp_server_ip[256];
    char localcmd[512];

    int file_size = 40;
    int checksum = 0;
    int i;
    unsigned char usb_test_raw_image_md5[16];
    unsigned char usb_test_coped_image_md5[16];
    uchar *usb_test_file_buf = NULL;



#if 0
    printf("################## argc =%d ##################\n", argc);
    for(i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
#endif


    if(argc > 6 || argc < 4) {
        usage_usb_read_speed_check();
        return -1;
    }

    if(argc == 4) {
        strcpy(local_usb_test_image_name, argv[3]);
    } else if(argc == 5) {
        strcpy(local_usb_test_image_name, argv[3]);
        sscanf(argv[4], "%d", &file_size);
        if((file_size > 200) || (file_size < 2)) {

            usage_usb_read_speed_check();
            printf("\n !!!!!!!!!!! Not support create usb test image size (%d) MB !!!!!!!!!!!!\n", file_size);

            return;
        }
    }




    memset(target_usb_test_file_name, '\0', sizeof(target_usb_test_file_name));
    sprintf(target_usb_test_file_name, "%s/%s", USB_0_DEFAULT_MOUNT_POINT, local_usb_test_image_name);
#ifdef INSPECTION_DEBUG
    printf("target_usb_test_file_name=%s\n", target_usb_test_file_name);
#endif


    if(file_exist(target_usb_test_file_name) != 0) {

        if(argc == 5) {
            usage_usb_io_check();
            return;
        }

#ifdef INSPECTION_DEBUG
        printf("USB_0_TEST_FILE_NAME=%s\n", target_usb_test_file_name);
#endif

        file_size = getfilesize(target_usb_test_file_name);
        if( (file_size / (1024 * 1024)) > 200) {
            printf("USB test not support test image over 200 (MB) \n");
            return -1;
        }

#ifdef INSPECTION_DEBUG
        printf("file_size=%d\n", file_size);
#endif

        //checksum=calcsum(target_usb_test_file_name,0,0);
        usb_test_file_buf = malloc(sizeof(char) * (file_size));
        if(usb_test_file_buf) {
        } else {
            printf("malloc fail@1\n");
            return -1;
        }
        copy_file_to_buf(target_usb_test_file_name, 0L, usb_test_file_buf, file_size);
        MD5( (unsigned char *)(usb_test_file_buf), file_size, usb_test_raw_image_md5);
#ifdef INSPECTION_DEBUG
        printf("USB TEST FILE ON USB MD5         : ");
        for(i = 0; i < 16; i++) {
            printf("%02x", usb_test_raw_image_md5[i]);
        }
        printf("\n");
#endif

        if(usb_test_file_buf) {
            free(usb_test_file_buf);
        }



        //system("echo \"2 4 1 7\" >/proc/sys/kernel/printk");
        system("echo 3 > /proc/sys/vm/drop_caches");
        //system("echo \"7 4 1 7\" >/proc/sys/kernel/printk");

        memset(localcmd, '\0', sizeof(localcmd));
        //system("echo \"2 4 1 7\" >/proc/sys/kernel/printk");
        sprintf(localcmd, "dd if=%s of=/tmp/usb_write.img  oflag=sync &> %s", target_usb_test_file_name,
                USB_0_RD_RESULE_TMP_FILES );

        //sprintf(localcmd,"dd if=%s of=/tmp/usb_write.img bs=1M count=%d oflag=sync &> %s",target_usb_test_file_name,file_size/(1024*1024),USB_0_RD_RESULE_TMP_FILES );
        //sprintf(localcmd,"dd if=%s of=/dev/null bs=1M count=%d oflag=sync &> %s",target_usb_test_file_name,file_size/(1024*1024),USB_0_RD_RESULE_TMP_FILES );
        system(localcmd);
        //system("echo \"7 4 1 7\" >/proc/sys/kernel/printk");

        //memset(localcmd,'\0',sizeof(localcmd));
        //sprintf(localcmd,"speedMB=\`cat %s | grep bytes | awk {'printf$8'}\`;speedMbps=$(echo $speedMB \\* 8 | bc); echo \"%s \"$speedMB \"MB/s\"\" (${speedMbps} Mbps)\"",USB_0_RD_RESULE_TMP_FILES,"USB 0 Read Speed   :");
        //system(localcmd);

        file_size = getfilesize("/tmp/usb_write.img");
#ifdef INSPECTION_DEBUG
        printf("file_size=%d @3\n", file_size);
#endif

        usb_test_file_buf = malloc(sizeof(char) * (file_size));
        copy_file_to_buf("/tmp/usb_write.img", 0L, usb_test_file_buf, file_size);
        MD5( (unsigned char *)(usb_test_file_buf), file_size, usb_test_coped_image_md5);
#ifdef INSPECTION_DEBUG
        printf("USB TEST FILE ON DUT MD5         : ");
        for(i = 0; i < 16; i++) {
            printf("%02x", usb_test_coped_image_md5[i]);
        }
        printf("\n");
#endif
        if(usb_test_file_buf) {
            free(usb_test_file_buf);
        }


        for(i = 0; i < 16; i++) {
            if(usb_test_raw_image_md5[i] != usb_test_coped_image_md5[i]) {
                printf("USB READ CHECK          : FAIL\n");
                return 0;
            }
        }

        printf("USB READ CHECK          : PASS\n");

    } else {

        if(argc == 4) {
            file_size = 40;
        } else if(argc == 5) {
        }
        printf("Generate usb test file_size= %d MB\n", file_size);
        //printf("USB 0 Test File    : %s NA\n", target_usb_test_file_name);
        printf("USB golden disk usb test image -%s not exist\n", target_usb_test_file_name);
        printf("Create USB test image %s now ...\n", target_usb_test_file_name);
        memset(localcmd, '\0', sizeof(localcmd));
        /*Generat 100MB test image*/
        if(argc == 4) {
            sprintf(localcmd, "dd if=/dev/urandom of=%s/%s bs=1048576 count=%d", USB_0_DEFAULT_MOUNT_POINT,
                    local_usb_test_image_name, file_size);
        } else if(argc == 5) {
            sprintf(localcmd, "dd if=/dev/urandom of=%s/%s bs=1048576 count=%d", USB_0_DEFAULT_MOUNT_POINT,
                    local_usb_test_image_name, file_size);
        }
        system(localcmd);
        printf("done ...\n");
        printf("Now the USB golden disk is ready to test using follow test command\n");
        printf("diag -c usb %s\n", local_usb_test_image_name);




    }





    return 0;

}















/*-----------------------------------------USB DIAG END------------------------------------------*/



/*---------------------------------------- USB CHECK START  ---------------------------------*/

static void usage_usb_device_status(void)
{
    printf("Get default usb devices speed\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_USBCHECK);
    printf("check -\n");
    printf("Usage: %s -c %s\n", __progname, RD_CMD_USBCHECK);


    return;
}

void fetch_usb_device_status(void)
{

    system("usbtool");

}
/*---------------------------------------- USB CHECK STOP ---------------------------------*/



static void usage_all(void)
{
    show_all_usage();

    exit(-1);
}



/*----------------------------------------- FIT FIRMWARE UPGRADE START ---------------------------------------*/

static void usage_firmware_fit()
{
    printf("Check/Upgrade firmware on flash\n");
    printf("check -\n");
    printf("Usage: %s -c %s\n", __progname, UG_CMD_BOOTLOADER);
    printf("write -\n");
    printf("Usage: %s -u %s [image name]\n", __progname, UG_CMD_FIT_FIRMWARE);
    printf("Usage: %s -u %s [image name] [server ip]\n", __progname, UG_CMD_FIT_FIRMWARE);
    printf("Usage: %s -u %s [image name] [server ip] [keep config]\n", __progname, UG_CMD_FIT_FIRMWARE);


    printf("[image name]  : remote firmware image name on tftp server root\n");
    printf("[server ip]   : tftp server ip address\n");
    printf("[keep config] : 0 - Clean System Config(default)\n");
    printf("              : 1 - Keep System Config\n");

    printf("For instance: %s -u %s nornand-ipq806x-single.img \n", __progname, UG_CMD_FIT_FIRMWARE);
    printf("For instance: %s -u %s nornand-ipq806x-single.img 192.168.11.10\n", __progname,
           UG_CMD_FIT_FIRMWARE);
    printf("For instance: %s -u %s nornand-ipq806x-single.img 192.168.11.10 0\n", __progname,
           UG_CMD_FIT_FIRMWARE);
    printf("For instance: %s -u %s nornand-ipq806x-single.img 192.168.11.10 1 \n", __progname,
           UG_CMD_FIT_FIRMWARE);


}

static int get_fit_header(char *header_file_name, fit_img_header_t *dhd)
{
    FILE *fp;
    char *sptr = NULL;
    char  line[128];
    char  valuestring[64];
    char  skips[64];
    char *cptr = NULL;
    int   no = 0, ms = 0;

    if((!header_file_name) || (!dhd)) {
        return -1;
    }
    if((fp = fopen(header_file_name, "r")) == NULL) {
        printf("Failed to fopen dni image header file - %s!\n", header_file_name);
        return -1;
    }
#ifdef INSPECTION_DEBUG
    printf("open %s ok\n", header_file_name);
#endif

    while(fgets(line, 128, fp) != NULL) {
        if(strncmp(line, "FIT description:", strlen("FIT description:")) == 0) {
            sscanf(line, "FIT description: %[^\n]", dhd->description);
#ifdef INSPECTION_DEBUG
            printf("description=%s\n", dhd->description);
#endif
        }

        no++;

    }
    fclose(fp);




}

int do_firmware_fit_img_update(int argc, char *argv[])
{
    FILE *fp = NULL;
    char remote_frimware_image_name[256];
    char tftp_server_ip[256];
    char localcmd[128];
    fit_img_header_t fit_hd;
    static int i, keepconfig;
    static int ifFITimg = 0;


#ifdef INSPECTION_DEBUG
    printf("################## argc =%d ##################\n", argc);
    for(i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
#endif

    memset(remote_frimware_image_name, '\0', sizeof(remote_frimware_image_name));

    if(argc > 6 || argc < 4) {
        usage_firmware_fit();
        return;
    }
    if(argc == 4) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, tftp_server_ip_address);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&tftp_server_ip_address[0];
        keepconfig = 0;
    } else if(argc == 5) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        keepconfig = 0;
    } else if(argc == 6) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        sscanf(argv[5], "%d", &keepconfig);
        if((keepconfig < 0) || (keepconfig > 1)) {
            usage_firmware_fit();
            return;
        }

        if(keepconfig) {
            printf("UPDATE FIT IMAGE        : Keep config not support yet!\n");
            return;
        }

    }

#ifdef INSPECTION_DEBUG
    printf("remote_frimware_image_name=%s\n", remote_frimware_image_name);
    printf("tftp_server_ip=%s\n", tftp_server_ip);
    printf("keepconfig=%d\n", keepconfig);
#endif


    if(strlen(remote_frimware_image_name) == 0) {
        printf("update firmware fail .. no specify image name\n");
        printf("UPDATE FW Only          : FAIL(1)\n");
        return -1;
    }
    if(strlen(tftp_server_ip) == 0) {
        printf("update firmware fail .. no specify tftp_server_ip\n");
        printf("UPDATE FW Only          : FAIL(2)\n");
        return -2;
    }

#ifdef INSPECTION_DEBUG
    printf("remote_frimware_image_name=%s tftp_server_ip=%s tftp_server_ip_address=%s \n",
           remote_frimware_image_name, tftp_server_ip, tftp_server_ip_address);
#endif


    /*Download image if file not exist*/
    if(file_exist(remote_frimware_image_name) != 0) {
        memset(localcmd, '\0', sizeof(localcmd));
        sprintf(localcmd, "cd /tmp;/bin/cp -f %s %s", remote_frimware_image_name, TMP_FW_IMAGE_FILE_NAME);
#ifdef INSPECTION_DEBUG
        printf("execute command :==> %s <== done !\n", localcmd);
#endif
        system(localcmd);
    } else {
        memset(localcmd, '\0', sizeof(localcmd));
        sprintf(localcmd, "cd /tmp;/usr/bin/tftp -g %s -r %s -l %s -b %d", tftp_server_ip,
                remote_frimware_image_name, TMP_FW_IMAGE_FILE_NAME, TFTP_DEFAULT_BLOCK_SIZE);
#ifdef INSPECTION_DEBUG
        printf("execute command :==> %s <== done !\n", localcmd);
#endif
        system(localcmd);

    }


    /*parse FIT image header */
    memset(localcmd, '\0', sizeof(localcmd));
    sprintf(localcmd, "rm -rf %s;/usr/bin/dumpimage -l %s > %s", TMP_FIT_IMAGE_HEADER_NAME,
            TMP_FW_IMAGE_FILE_NAME, TMP_FIT_IMAGE_HEADER_NAME);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif
    system(localcmd);

#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif


    get_fit_header(TMP_FIT_IMAGE_HEADER_NAME, &fit_hd);
    //printf("Des=%s\n", fit_hd.description);

    if(strncmp(fit_hd.description, FIT_DESCRIPT_STRING, strlen(FIT_DESCRIPT_STRING)) == 0) {
        printf("######## image type= FIT SINLE IMAGE ########@20200414\n");
        ifFITimg = 1;
    }





    if(ifFITimg) {

        //UMOUNT
        memset(localcmd, "", sizeof(localcmd));
        sprintf(localcmd, "/bin/umount %s", WLX_YAMAHA_ROOTFS_0_DEFAULT_MOUNT_POINT);
#ifdef INSPECTION_DEBUG
        printf("execute command :==> %s <== done !\n", localcmd);
#endif
        system(localcmd);

        memset(localcmd, "", sizeof(localcmd));
        sprintf(localcmd, "/bin/umount %s", WLX_YAMAHA_ROOTFS_1_DEFAULT_MOUNT_POINT);
#ifdef INSPECTION_DEBUG
        printf("execute command :==> %s <== done !\n", localcmd);
#endif
        system(localcmd);


        if(keepconfig) { /*Not save config*/
            printf("Keep config not support yet!\n");
#ifdef SYSUPGRADE_INITRAMFS_SUPPORT_KEEP_CONFIG
            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd, "/bin/mount -t ubifs ubi0:ubi_rootfs_data /orgconfig");
#ifdef INSPECTION_DEBUG
            printf("execute command :==> %s <== done !\n", localcmd);
#endif
            system(localcmd);

            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd, "cd /orgconfig;/bin/tar -zcvf /tmp/config.tar.gz .");
#ifdef INSPECTION_DEBUG
            printf("execute command :==> %s <== done !\n", localcmd);
#endif
            system(localcmd);


            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd, "/bin/umount /tmp/orgconfig");
#ifdef INSPECTION_DEBUG
            printf("execute command :==> %s <== done !\n", localcmd);
#endif
            system(localcmd);

            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd, "/sbin/sysupgrade -c %s", TMP_FW_IMAGE_FILE_NAME);
#ifdef INSPECTION_DEBUG
            printf("execute command :==> %s <== done !\n", localcmd);
#endif
            system(localcmd);

            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd, "/usr/sbin/upiattach -m 0");
#ifdef INSPECTION_DEBUG
            printf("execute command :==> %s <== done !\n", localcmd);
#endif
            system(localcmd);

            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd, "/bin/mount -t ubifs ubi0:ubi_rootfs_data /orgconfig");
#ifdef INSPECTION_DEBUG
            printf("execute command :==> %s <== done !\n", localcmd);
#endif
            system(localcmd);

            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd, "/bin/tar -zxvhf /tmp/config.tar.gz /orgconfig");
#ifdef INSPECTION_DEBUG
            printf("execute command :==> %s <== done !\n", localcmd);
#endif
            system(localcmd);


            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd, "/bin/umount /tmp/orgconfig");
#ifdef INSPECTION_DEBUG
            printf("execute command :==> %s <== done !\n", localcmd);
#endif
            system(localcmd);
#endif

        } else {
            memset(localcmd, '\0', sizeof(localcmd));
            sprintf(localcmd, "/sbin/sysupgrade -n -v %s && /usr/sbin/diag -u remount", TMP_FW_IMAGE_FILE_NAME);
#ifdef INSPECTION_DEBUG
            printf("execute command :==> %s <== done !\n", localcmd);
#endif
            system(localcmd);

        }

        /*Jacky.Xue: After execute sysupgrade ,diag process will be killed ,so incoming command won't execute again*/


    } else {
        printf("Image Type not support\n");

    }


}
/*----------------------------------------- FIT FIRMWARE UPGRADE END ---------------------------------------*/
/*----------------------------------------- CALIBRATION DATA CHECK START ----------------------------------*/

/*Jacky.Xue :
  (256k caldata)/dev/mtdxxx ("0:ART" or "ART" MTD partition) offset 0x1180
  and
  bdwlan.bin offset 0x180 should be same and not all 0xff.
  if all 0xff -> fail
  if not same as bdf 0ffset

 */

#define CALIBRATION_FIX_DATA_CHECK_LENGTH      64
#define BDF_FIXED_DATA_OFFSET                  384L
#define ART_MTD_CALDATA_FILE_FIXED_DATA_OFFSET 4480L
#define DBF_COMPARE_FILE_PATH_NAME    "/lib/firmware/IPQ8074/WIFI_FW/bdwlan.bin"

static void usage_cal_check()
{
    printf("Check calibration data valid or not\n");
    printf("Usage: %s -c %s\n", __progname, CG_CMD_CALCHECK);

}

int do_ipq_cal_check(void)
{

    system("/sbin/detect_caldata.sh");
    return 1;

    unsigned char art_mtd_fixed_data_md5_digit[16];
    unsigned char bdf_fixed_data_md5_digit[16];
    uchar *bdf_data_buf = NULL;
    uchar *art_mtd_data_buf = NULL;
    uchar *uboot_buf = NULL;
    char localcmd[128];
    u32 calibration_md5_cmp_result = 0;
    int i;

    if(file_exist(DBF_COMPARE_FILE_PATH_NAME) != 0) {
        /*GET ART MTD DEVICE NAME*/
        memset(DEV_ART_MTD_NAME, '\0', sizeof(DEV_ART_MTD_NAME));
        if(get_mtd_device_name(ART_MTD_NAME, DEV_ART_MTD_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
            printf("Success get %s mtd device name - %s\n", ART_MTD_NAME, DEV_ART_MTD_NAME);
#endif
        } else {
            if(1) {
                printf("%s MTD partition not found\n", ART_MTD_NAME);
            }
            return -1;
        }


        bdf_data_buf = malloc(sizeof(char) * (CALIBRATION_FIX_DATA_CHECK_LENGTH));
        copy_file_to_buf(DBF_COMPARE_FILE_PATH_NAME, BDF_FIXED_DATA_OFFSET, bdf_data_buf,
                         (int)CALIBRATION_FIX_DATA_CHECK_LENGTH);

        MD5( (unsigned char *)(bdf_data_buf), CALIBRATION_FIX_DATA_CHECK_LENGTH, bdf_fixed_data_md5_digit);
#ifdef INSPECTION_DEBUG
        printf("BDF MD5 FOR FIXED DATA                      : ");
        for(i = 0; i < 16; i++) {
            printf("%02x", bdf_fixed_data_md5_digit[i]);
        }
        printf("\n");
#endif
        if(bdf_data_buf) {
            free(bdf_data_buf);
        }

        art_mtd_data_buf = malloc(sizeof(char) * (CALIBRATION_FIX_DATA_CHECK_LENGTH));
        copy_file_to_buf(DEV_ART_MTD_NAME, ART_MTD_CALDATA_FILE_FIXED_DATA_OFFSET, art_mtd_data_buf,
                         (int)CALIBRATION_FIX_DATA_CHECK_LENGTH);
        MD5( (unsigned char *)(art_mtd_data_buf), CALIBRATION_FIX_DATA_CHECK_LENGTH,
             art_mtd_fixed_data_md5_digit);
#ifdef INSPECTION_DEBUG
        printf("ART CALDATA MTD MD5 FOR FIXED DATA          : ");
        for(i = 0; i < 16; i++) {
            printf("%02x", art_mtd_fixed_data_md5_digit[i]);
        }
        printf("\n");
#endif
        if(art_mtd_data_buf) {
            free(art_mtd_data_buf);
        }

        for(i = 0; i < 16; i++) {
            if(bdf_fixed_data_md5_digit[i] != art_mtd_fixed_data_md5_digit[i]) {
                calibration_md5_cmp_result |= 0x1;
                printf("CALIBRATION DATA CHECK  : FAIL\n");
                return -1;

            }
        }
        if((calibration_md5_cmp_result & 0x1) != 0x01) {
            printf("CALIBRATION DATA CHECK  : PASS\n");
        }

    } else {
        printf("CALIBRATION DATA CHECK  : FAIL\n");
    }


}


/*----------------------------------------- END OF CALIBRATION DATA CHECK ----------------------------------*/
/*----------------------------------------- REMOUNT START ----------------------------------*/
static void usage_remount()
{
    printf("remount all rootfs as possible\n");
    printf("remount -\n");
    printf("Usage: %s -u %s\n", __progname, UG_CMD_FS_REMOUNT);

}


int do_remountallrootfs(void)
{
    char localcmd[128];
    //system("echo \"2 4 1 7\" >/proc/sys/kernel/printk");

#ifdef INSPECTION_DEBUG
    fprintf(stderr, "#################################################################\n");
    fprintf(stderr, "######################## Remount fs   ###########################\n");
    fprintf(stderr, "#################################################################\n");
#endif
    //UMOUNT
    if(get_mtd_device_name_index(ROOTFS_0_MTD_NAME, DEV_ROOTFS_0_MTD_INDEX, 0) != NULL) {
#ifdef INSPECTION_DEBUG
        printf("Success get %s mtd device index - %s\n", ROOTFS_0_MTD_NAME, DEV_ROOTFS_0_MTD_INDEX);
#endif
    } else {
        printf("1st-%s MTD partition not found\n", ROOTFS_0_MTD_NAME);
    }

    if(get_mtd_device_name_index(ROOTFS_1_MTD_NAME, DEV_ROOTFS_1_MTD_INDEX, 0) != NULL) {
#ifdef INSPECTION_DEBUG
        printf("Success get %s mtd device index - %s\n", ROOTFS_1_MTD_NAME, DEV_ROOTFS_1_MTD_INDEX);
#endif
    } else {
        printf("2nd-%s MTD partition not found\n", ROOTFS_1_MTD_NAME);
    }

#if 0
    if(get_mtd_device_name_index(ROOTFS_2_MTD_NAME, DEV_ROOTFS_2_MTD_INDEX, 0) != NULL) {
#ifdef INSPECTION_DEBUG
        printf("Success get %s mtd device index - %s\n", ROOTFS_2_MTD_NAME, DEV_ROOTFS_2_MTD_INDEX);
#endif
    } else {
        printf("3rd-%s MTD partition not found\n", ROOTFS_2_MTD_NAME);
    }
#endif

    memset(localcmd, "'\0'", sizeof(localcmd));
    sprintf(localcmd, "/bin/umount %s > /dev/null  2>&1;", WLX_YAMAHA_ROOTFS_0_DEFAULT_MOUNT_POINT);
    system(localcmd);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif
    memset(localcmd, "'\0'", sizeof(localcmd));
    sprintf(localcmd, "/bin/umount %s > /dev/null  2>&1;", WLX_YAMAHA_ROOTFS_1_DEFAULT_MOUNT_POINT);
    system(localcmd);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif


#ifdef SUPPORT_NAND

    memset(localcmd, "'\0'", sizeof(localcmd));
    sprintf(localcmd, "/usr/sbin/ubidetach -m %s > /dev/null  2>&1;", DEV_ROOTFS_0_MTD_INDEX);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif
    system(localcmd);

    memset(localcmd, "'\0'", sizeof(localcmd));
    sprintf(localcmd, "/usr/sbin/ubidetach -m %s > /dev/null  2>&1;", DEV_ROOTFS_1_MTD_INDEX);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif

    system(localcmd);

    //Attach all UBI partitions
    memset(localcmd, "", sizeof(localcmd));
    sprintf(localcmd, "/usr/sbin/ubiattach -m %s > /dev/null  2>&1;", DEV_ROOTFS_0_MTD_INDEX);
    system(localcmd);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif

    memset(localcmd, "", sizeof(localcmd));
    sprintf(localcmd, "/usr/sbin/ubiattach -m %s > /dev/null  2>&1;", DEV_ROOTFS_1_MTD_INDEX);
    system(localcmd);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif

#endif //SUPPORT_NAND


#ifdef INSPECTION_DEBUG
    fprintf(stderr, "******** Remount rootfs1 ********\n");
#endif
    //Re-mount ubi squashfs rootfs partitions
    if(get_mtd_device_name_index(WLX_ROOTFS_0_DEFAULT_ROOTFS_NAME, DEV_ROOTFS_0_SQUASHFS_MTD_INDEX,
                                 0) != NULL) {
#ifdef INSPECTION_DEBUG
        printf("Success get %s mtd device name - %s\n", WLX_ROOTFS_0_DEFAULT_ROOTFS_NAME,
               DEV_ROOTFS_0_SQUASHFS_MTD_INDEX);
#endif
    } else {
        printf("1st %s MTD partition not found\n", WLX_ROOTFS_0_DEFAULT_ROOTFS_NAME);
    }

#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif

    memset(localcmd, "", sizeof(localcmd));
    sprintf(localcmd, "/bin/mount -o loop -t squashfs %s %s", DEV_ROOTFS_0_SQUASHFS_MTD_INDEX,
            WLX_YAMAHA_ROOTFS_0_DEFAULT_MOUNT_POINT);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif
    system(localcmd);
#ifdef INSPECTION_DEBUG
    printf("******** Remount rootfs2 ********\n");
#endif
    //Re-mount rootfs_1
    if(get_mtd_device_name_index(WLX_ROOTFS_1_DEFAULT_ROOTFS_NAME, DEV_ROOTFS_1_SQUASHFS_MTD_INDEX,
                                 1) != NULL) {
#ifdef INSPECTION_DEBUG
        printf("Success get %s mtd device name - %s\n", WLX_ROOTFS_1_DEFAULT_ROOTFS_NAME,
               DEV_ROOTFS_1_SQUASHFS_MTD_INDEX);
#endif
    } else {
        printf("2nd-%s MTD partition not found\n", WLX_ROOTFS_1_DEFAULT_ROOTFS_NAME);
    }


    memset(localcmd, "", sizeof(localcmd));
    sprintf(localcmd, "/bin/mount -o loop -t squashfs %s %s", DEV_ROOTFS_1_SQUASHFS_MTD_INDEX,
            WLX_YAMAHA_ROOTFS_1_DEFAULT_MOUNT_POINT);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif
    system(localcmd);


    //Re-scan loader version
    // printf("******** Re-Scan loader Status ********\n");
    //memset(localcmd,'\0',sizeof(localcmd));
    //sprintf(localcmd,"rm -rf /tmp/uboot_version;/etc/scan_bootcode_ver.sh;echo \"rescan uboot version done!\"");
    //system(localcmd);
    // printf("execute command :==> %s <== done !\n",localcmd);

#ifdef INSPECTION_DEBUG
    fprintf(stderr, "#######################################################################\n");
    fprintf(stderr, "######################## Remount fs - Done  ###########################\n");
    fprintf(stderr, "#######################################################################\n");
#endif

    //system("echo \"7 4 1 7\" >/proc/sys/kernel/printk");

}


/*----------------------------------------- REMOUNT END ----------------------------------*/



int  mem_fd;
void *gpio_map;
volatile unsigned int *ipq_mmap_gpio;

int main(int argc, char **argv)
{
    extern char *optarg;
    int ch;
    int loffset = 0;
    int slb = 0;
    int ii;
    int i2caddr = 0;
    int erase_bfore_write = 0;
    char img_name[128];
    int partsid = 0;
    int qca_99xx_mode = 0;
    int qca_99xx_gpio = 0;
    int qca_99xx_gpio_val = 0;
    unsigned long checksum_size = 0;
    unsigned long kernel_size = 0;
    unsigned long md5_size = 0;

    int fd;
    struct qca_gpio_config gpio_config;
    off_t target = TLMM_BASE_ADDR;
    int gpio_no, gpio_func, gpio_inout, gpio_pull, gpio_driven, gpio_oe, gpio_ve, gpio_ode, gpio_res;
    int value, cur_value;
    int i;


#ifdef INSPECTION_DEBUG
    printf("argc=%d\n", argc);
    for(ii = 0; ii < argc; ii++) {
        printf("argv[%d] = %s\n", ii, argv[ii]);
    }
#endif
    if (argc <= 2) {
        usage_all();
    }

    if((argc == 3) && (strncmp(argv[1], "-h", 2) == 0)) {
        /*try return help message*/
        show_specific_cmd_usage(argv[2]);
        return 0;
    }
    if((argc == 3) && (strncmp(argv[2], "-h", 2) == 0)) {
        /*try return help message*/
        show_specific_cmd_usage(argv[1]);
        return 0;
    }


    memset(DEV_HWDATA_MTD_NAME, '\0', sizeof(DEV_HWDATA_MTD_NAME));

    if(get_mtd_device_name(STROAGE_MTD_NAME, DEV_HWDATA_MTD_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
        printf("Success get %s mtd device name - %s\n", STROAGE_MTD_NAME, DEV_HWDATA_MTD_NAME);
#endif
    } else {
        if(globaldebug) {
            printf("%s MTD partition not found\n", STROAGE_MTD_NAME);
        }
        return -1;
    }

    read_hwsetting(hwdata, WLX_HWDATA_SIZE);
    get_hwparam_device_name();

    setup_io();

#ifdef INSPECTION_DEBUG
    printf("GPIO pin 9 is       :0x%x\n", gpio_get_value(9));
    printf("GPIO pin 25 is       :0x%x\n", gpio_get_value(25));

    printf("GPIO pin 26 is       :0x%x\n", gpio_get_value(26));
    printf("GPIO pin 27 is       :0x%x\n", gpio_get_value(27));

    printf("GPIO pin 9 is       :0x%x\n", GPIO_IN_OUT(gpio_map, 9));
    printf("GPIO pin 25 is       :0x%x\n", GPIO_IN_OUT(gpio_map, 25));
    printf("GPIO pin 26 is       :0x%x\n", GPIO_IN_OUT(gpio_map, 26));
    printf("GPIO pin 27 is       :0x%x\n", GPIO_IN_OUT(gpio_map, 27));

    printf("GPIO pin 9 CFG is   :0x%lx\n", GPIO_CFG(gpio_map, 9));
    printf("GPIO pin 25 CFG is   :0x%lx\n", GPIO_CFG(gpio_map, 25));
    printf("GPIO pin 26 CFG is   :0x%lx\n", GPIO_CFG(gpio_map, 26));
    printf("GPIO pin 27 CFG is   :0x%lx\n", GPIO_CFG(gpio_map, 27));

    printf("GPIO pin 60 is       :0x%lx\n", GPIO_IN_OUT(gpio_map, 60));
    printf("GPIO pin 61 is       :0x%lx\n", GPIO_IN_OUT(gpio_map, 61));
    printf("GPIO pin 62 is       :0x%lx\n", GPIO_IN_OUT(gpio_map, 62));

#endif

    while ((ch = getopt(argc, argv, "a:c:r:u:w:h")) != -1) {
        switch (ch) {

        case 'r':

            if (strcmp(argv[2], "all") == 0) {
                printf("--------------------------------\n");
                fetch_board_info();
                // check_eeprom_status(DEFAULT_I2C_EEPROM_ADDRSS);
                fetch_bootcode_version_on_the_fly();
                fetch_fw_version();
                //fetch_hw_version();
                fetch_inspect_fw_ver();
                //fetch_aquantia_phy_firmware_version();
                //fetch_aquantia_phy_identity();
                fetch_tftp_server_addr();
                fetch_inspect_lan_ip_addr();
                fetch_hwsetting_param();
                // fetch_bme280();
                // fetch_rtc_clk();
                //fetch_tpm2_data();
                // fetch_bluetooth_param();
#ifdef SUPPORT_USB
                fetch_usb_device_status();
#endif
                fetch_wanport_stat();
                fetch_temperature();
                fetch_poe_setting();
                //fetch_bluetooth_status();
#ifdef SUPPORT_NAND
                do_bad_block_check();
#endif
                do_ipq_cal_check();
                //do_ecc_correction_check();
                //do_bdf_md5_check(argc,argv);

                return 0;

            } else if (strcmp(argv[2], RD_CMD_BD_INFO) == 0) {
                fetch_board_info();
                break;
            } else if (strcmp(argv[2], RD_CMD_FW_VER) == 0) {
                fetch_fw_version();
                break;
            } else if (strcmp(argv[2], RD_CMD_HW_VER) == 0) {
                fetch_hw_version();
                break;
            } else if (strcmp(argv[2], RD_CMD_BD_INFO) == 0) {
                fetch_board_info();
                break;
            } else if (strcmp(argv[2], RD_CMD_BOOTCODE_VER) == 0) {
                fetch_bootcode_version_on_the_fly();
                break;
            } else if (strcmp(argv[2], RD_CMD_TFTP_SRV_IP) == 0) {
                fetch_tftp_server_addr();
                break;
            } else if (strcmp(argv[2], RD_CMD_INSPECT_FW_LAN_IP) == 0) {
                fetch_inspect_lan_ip_addr();
                break;
            }
            /*
               else if (strcmp(argv[2],RD_CMD_BME280)==0){
               fetch_bme280();
               break;
               }
             */
            else if (strcmp(argv[2], RD_CMD_AQR_IDENTITY) == 0) {
                fetch_aquantia_phy_identity();
                break;
            } else if (strcmp(argv[2], RD_CMD_CHK_TEMPERATURE) == 0) {
                fetch_temperature();
                break;
            } else if (strcmp(argv[2], RD_CMD_AQR_FW_VER) == 0) {
                fetch_aquantia_phy_firmware_version();
                break;
            }

            else if (strcmp(argv[2], RD_CMD_POE) == 0) {
                fetch_poe_setting();
                break;
            } else if (strcmp(argv[2], RD_CMD_LANMAC) == 0) {
                fetch_lan_mac ();
            } else if (strcmp(argv[2], RD_CMD_WLANMAC) == 0) {
                fetch_wirless_mac();
            } else if (strcmp(argv[2], RD_CMD_ALLMAC) == 0) {
                fetch_all_macs();
            }


            else if (strcmp(argv[2], RD_CMD_HWPARAM) == 0) {
                fetch_hwsetting_param();
                break;
            }
#ifdef SUPPORT_USB
            else	if (strcmp(argv[2], RD_CMD_USBCHECK) == 0) {
                do_usb_read_speed_check(argc, argv);
                break;
            } else if (strcmp(argv[2], RD_CMD_USB_DEV_SPEED_CHECK) == 0) {
                fetch_usb_device_status();
                break;
            }
#endif
            else if (strcmp(argv[2], RD_CMD_INSPECT_VER) == 0) {
                fetch_inspect_fw_ver();
                break;
            } else	if (strcmp(argv[2], RD_CMD_WANSTAT) == 0) {
                fetch_wanport_stat();
                break;
            } else if (strcmp(argv[2], CG_CMD_CALCHECK) == 0) {
                do_ipq_cal_check();
                break;
            }
#ifdef SUPPORT_NAND
            else	if (strcmp(argv[2], RD_CMD_BAD_BLOCKCHECK) == 0) {
                do_bad_block_check();
                break;
            }
#endif
#ifdef SUPPORT_DDR_ASR
            else	if (strcmp(argv[2], RD_CMD_DDR3_ASR_CHECK) == 0) {
                do_ddr3_asr_config_check();
                break;
            }
#endif
            else if (strcmp(argv[2], UG_CMD_FIRMWAREMD5) == 0) {
                do_firmware_md5info(argc, argv);					/*grep peoduct firmware*/
                break;
            } else if (strcmp(argv[2], RD_CMD_FLASH_FWMD5) == 0) {
                do_firmware_md5_check(argc, argv);
                break;
            } else	if (strcmp(argv[2], UG_CMD_BDF) == 0) {
                do_bdf_md5_check(argc, argv);
                return 0;
            }

            else {
                usage_all();
            }

            break; //case break - 'r'

        //	case 'w':
        // 	break;

        case 'c':

            if (strcmp(argv[2], RD_CMD_CHK_TEMPERATURE) == 0) {
                fetch_temperature();
                break;
            } else if (strcmp(argv[2], UG_CMD_FIRMWARE) == 0) {
                do_firmware_check(argc, argv);
                break;
            } else if (strcmp(argv[2], UG_CMD_FIRMWAREMD5) == 0) {
                do_firmware_md5_check(argc, argv);
                break;
            } else	if (strcmp(argv[2], RD_CMD_BAD_BLOCKCHECK) == 0) {
                do_bad_block_check();
                break;
            } else	if (strcmp(argv[2], UG_CMD_BDF) == 0) {
                do_bdf_md5_check(argc, argv);
                return 0;
            }
#ifdef SUPPORT_USB
            else	if (strcmp(argv[2], RD_CMD_USBCHECK) == 0) {
                do_usb_read_speed_check(argc, argv);
                break;
            } else	if (strcmp(argv[2], RD_CMD_USB_DEV_SPEED_CHECK) == 0) {
                fetch_usb_device_status();
                break;
            }
#endif
            else if (strcmp(argv[2], CG_CMD_CALCHECK) == 0) {
                do_ipq_cal_check();
                break;
            } else if (strcmp(argv[2], RD_CMD_ECCCHECK) == 0) {
                do_ecc_correction_check();
                break;
            }
#ifdef SUPPORT_DDR_ASR
            else	if (strcmp(argv[2], RD_CMD_DDR3_ASR_CHECK) == 0) {
                do_ddr3_asr_config_check();
                break;
            }
#endif
            /*MD5 */
            else if (strcmp(argv[2], UG_CMD_MD5) == 0) {
                if(argv[3] != NULL ) {

                    if(argv[4] != NULL ) {
                        loffset = atoi(argv[4]);
                        if(argv[5] != NULL ) {
                            md5_size = strtoul(argv[5], NULL, 10);
                            do_calmd5(argv[3], loffset, md5_size);
                        } else {
                            do_calmd5(argv[3], loffset, 0);
                        }


                    } else {
                        do_calmd5(argv[3], 0, 0);
                    }


                } else {
                    usage_md5();
                }

                break;
            } else {
                usage_all();
            }
            break;  //case break - 'c'

        case 'u':
            //tftp server ip address set
            if (strcmp(argv[2], RD_CMD_TFTP_SRV_IP) == 0) {
                if(argv[3] != NULL ) {
                    do_tftp_srv_ipaddr_set(argv[3]);
                } else {
                    usage_tftp_server_ipaddr();
                }

            } else if (strcmp(argv[2], UG_CMD_FIRMWARE) == 0) {
                do_firmware_update(argc, argv);
                break;
            } else	if (strcmp(argv[2], UG_CMD_FIT_FIRMWARE) == 0) {
                do_firmware_fit_img_update(argc, argv);
                break;
            } else if (strcmp(argv[2], UG_CMD_FS_REMOUNT) == 0) {
                do_remountallrootfs();
                break;
            } else if (strcmp(argv[2], UG_CMD_BOOTLOADER) == 0) {
                do_loader_update(argc, argv);
                break;
            } else if (strcmp(argv[2], UG_CMD_RESETDEFAULT) == 0) {
                do_resetdefault();
                break;
            } else if (strcmp(argv[2], UG_CMD_ERASE_CALDATA) == 0) {
                do_erase_art_mtd();
                break;
            } else if (strcmp(argv[2], UG_CMD_RESETBOOTENV) == 0) {
                do_resetloaderbootenv();
                break;
            } else {
                usage_write_image_to_eeprom();
            }
            break;     // Case u end


        default:  // Case not r,c,u.
            usage_all();
            break;
        }



    }


    close_io();

    return 0;
}


static void usage_allparam(void)
{
    printf("Get all paramaters,get support only\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_ALLPARAM);
}

#include <stdio.h>
#define CPU_INFO_FILE "/proc/cpuinfo"
#define PROC_MEM_TMP_FILE "/tmp/__tmp_proc_mem__.txt"
//#define FETCH_MEMORY_SIZE "echo 'Memory                  : '$((`cat /proc/meminfo | grep VmallocTotal | awk {'printf$2'}`/1024)) 'MB'"



static void usage_boardinfo(void)
{
    printf("Get board information, get support only\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_BD_INFO);
}

void fetch_board_info(void)
{
    FILE *fp = NULL;
    char *cptr = NULL;
    char cmd[512] = {0};
    int i, j, cpu_num = 8;
    char line[1024];
    int  memlow, memhigh;
    int  total_ddr_mem = 0;


    system("echo -n \"MACHINE ID              : \";fw_printenv  | grep machid | head -1 | awk -F '=' '{print $2}'");

    fp = popen("cat /proc/cpuinfo |grep processor |wc -l", "r");
    if (fp) {
        fgets(line , sizeof(line), fp);
        line[sizeof(line) - 1] = '\0';
        pclose(fp);
        if (line[0] != '\0') {
            cpu_num = atoi(line);
        }
    }

    for(i = 0; i < cpu_num; i++) {
        snprintf(cmd, sizeof(cmd),
                 "echo -n \"Type of (CPU#%d)         : \" && cat /sys/devices/system/cpu/cpu%d/uevent | grep \"OF_COMPATIBLE_0=\" | awk -F \"=\" '{print $2}' | sed 's/,/\ /g'",
                 i, i);
        system(cmd);
    }

    for(i = 0; i < cpu_num; i++) {
        snprintf(cmd, sizeof(cmd),
                 "echo 'Clocks(core#%d)          : '$((`cat /sys/devices/system/cpu/cpu%i/cpufreq/cpuinfo_max_freq`/1000)) 'Mhz'",
                 i, i);
        system(cmd);
    }

    for(i = 0; i < cpu_num; i++) {
        snprintf(cmd, sizeof(cmd),
                 "echo \"BogoMIPS(core#%d)	: `cat /proc/cpuinfo |grep BogoMIPS|sed -n %dp|awk '{print $3}'`\"", i,
                 i + 1);
        system(cmd);
    }

    //system(FETCH_MEMORY_SIZE);
    /**************************************************************************************************/
    /*Get some information from dmesg*/
    memset(cmd, '\0', sizeof(cmd));
    sprintf(cmd, "/bin/cat /proc/iomem | grep \"System\" | awk -F ':' '{printf $1\"\\n\"}' > %s",
            PROC_MEM_TMP_FILE);
    system(cmd);
    fp = fopen(PROC_MEM_TMP_FILE, "r");
    if(!fp) {
        printf("File %s open errof!\n", PROC_MEM_TMP_FILE);
        return ;
    }
    total_ddr_mem = 0;

    while(fgets(line, 1024, fp) != NULL) {
        cptr = &line[0];
        if(cptr != NULL) { //already find match string
            sscanf(cptr, "%x-%x", &memlow, &memhigh);
            memhigh += 1;
            total_ddr_mem += (memhigh - memlow);
        } //string search
    }
    total_ddr_mem = (total_ddr_mem / (1024 * 1024));
    total_ddr_mem += 33; /*Add Qualcomm Preserv MEMORY 33MB*/
    sprintf(cmd, "Memory                  : %d MB", total_ddr_mem);
    printf("%s\n", cmd);

    fclose(fp);

    memset(cmd, '\0', sizeof(cmd));
    sprintf(cmd, "/bin/rm -rf %s", PROC_MEM_TMP_FILE);
    system(cmd);
}

/*---------------------------------------- BOARD INFOR END -------------------------------*/










/**************************************** EEPROM CHECK  START *************************************/

void usage_eeprom(void)
{
    printf("Get/Set default wlan authentication mode value\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_EEPROM);
    printf("write -\n");
    printf("Usage: %s -w %s [authmode new value]\n", __progname, RD_CMD_EEPROM);


    return;
}

#define EEPROM_TEST_SIZE 32
#define EEPROM_WRITE_SIZE 8192
void check_eeprom_status(int i2c_addr)
{
    int i = 0;
    unsigned char i2c_eeprom_sys_name[128];
    char command[128] = {0};
    FILE *fp;
    char test_file_buf[EEPROM_TEST_SIZE];
    char test_eeprom_buf[EEPROM_TEST_SIZE];
    unsigned char md5_digit[16];
    unsigned char eeprom_md5_digit[16];

    //system("echo \"0 0 0 0\" > /proc/sys/kernel/printk");
    memset(i2c_eeprom_sys_name, '\0', sizeof(i2c_eeprom_sys_name));
    sprintf(i2c_eeprom_sys_name, "/sys/bus/i2c/devices/0-00%x/eeprom", i2c_addr);
#ifdef INSPECTION_DEBUG
    printf("I2C EEPROM SYS NAME=%s\n", i2c_eeprom_sys_name);
#endif
    /*Setup device node run time*/
    if(file_exist(i2c_eeprom_sys_name) != 0) {
        memset(command, "", sizeof(command));
        sprintf(command, "echo \"0x%x\" > /sys/class/i2c-adapter/i2c-0/delete_device", i2c_addr);
#ifdef INSPECTION_DEBUG
        printf("execute command :==> %s <== done !\n", command);
#endif
        system(command);

    }

    system("rm -rf /512B.dat");

    memset(command, "", sizeof(command));
    sprintf(command, "echo \"24c64 0x%x\" > /sys/class/i2c-adapter/i2c-0/new_device", i2c_addr);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", command);
#endif
    system(command);


    system("dd if=/dev/random of=/512B.dat bs=1 count=512 >& /tmp/dd.log"); //512 byte
    memset(test_file_buf, '\0', sizeof(test_file_buf));
    copy_file_to_buf("/512B.dat", 0L, test_file_buf, EEPROM_TEST_SIZE);
    MD5((unsigned char *)(test_file_buf), EEPROM_TEST_SIZE, md5_digit);
#ifdef INSPECTION_DEBUG
    printf("TEST RANDOM FILE MD5: ");
    for(i = 0; i < 16; i++) {
        printf("%02x", md5_digit[i]);
    }
    printf("\n");
#endif

#ifdef INSPECTION_DEBUG
    printf("I2C EEPROM SYS NAME=%s@2\n", i2c_eeprom_sys_name);
#endif

    copy_buf_to_file(i2c_eeprom_sys_name, 0, test_file_buf, EEPROM_TEST_SIZE);
    //system("echo \"7 4 1 7\" > /proc/sys/kernel/printk");
    //memset(command,"",sizeof(command));
    // sprintf(command,"cat /512B.dat  > /sys/bus/i2c/devices/0-00%x/eeprom",i2c_addr);
    //sprintf(command,"cat /512B.dat  > /sys/bus/i2c/devices/0-00%x/eeprom >& /dev/null",i2c_addr);
    //printf("execute command :==> %s <== done !\n",command);
    //system(command);

#ifdef INSPECTION_DEBUG
    printf("i2c_eeprom_sys_name==> %s <== i2c_eeprom_sys_name !\n", i2c_eeprom_sys_name);
#endif
    memset(test_eeprom_buf, '\0', sizeof(test_eeprom_buf));


    copy_file_to_buf(i2c_eeprom_sys_name, 0L, test_eeprom_buf, EEPROM_TEST_SIZE);

    MD5((unsigned char *)(test_eeprom_buf), EEPROM_TEST_SIZE, eeprom_md5_digit);
#ifdef INSPECTION_DEBUG
    printf("EEPROM MD5          : ");
    for(i = 0; i < 16; i++) {
        printf("%02x", eeprom_md5_digit[i]);
    }
    printf("\n");
#endif

    //system("echo \"7 4 1 7\" > /proc/sys/kernel/printk");
    for(i = 0; i < 16; i++) {
        if(eeprom_md5_digit[i] != md5_digit[i]) {
            printf("EEPROM                  : %s\n", "FAIL");
            return -2;
        }
    }

    printf("EEPROM                  : %s\n", "PASS");

    return;
}

/**************************************** EEPROM CHECK  END *************************************/


/**************************************** EEPROM WRITE  START *************************************/

void usage_write_image_to_eeprom(void)
{
    printf("program image to eeprom\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_PROGRAM_EEPROM);
    printf("write -\n");
    printf("Usage: %s -u %s                                                     (default image name:%s,default i2c address %x ,default erase before write=%d)\n",
           __progname, RD_CMD_PROGRAM_EEPROM, DEFAULT_I2C_EEPROM_IMG_NAME, DEFAULT_I2C_EEPROM_ADDRSS,
           DEFAULT_ERASE_BEFORE_WRITE);
    printf("Usage: %s -u %s [image name]                                        (default i2c address %x ,default erase before write=%d)\n",
           __progname, RD_CMD_PROGRAM_EEPROM, DEFAULT_I2C_EEPROM_ADDRSS, DEFAULT_ERASE_BEFORE_WRITE);
    printf("Usage: %s -u %s [image name]  [i2c addr]                            (default erase before write=%d)\n",
           __progname, RD_CMD_PROGRAM_EEPROM, DEFAULT_ERASE_BEFORE_WRITE);
    printf("Usage: %s -u %s [image name]  [i2c addr]  [erase before write]  \n", __progname,
           RD_CMD_PROGRAM_EEPROM);



    return;
}


void write_image_to_eeprom(int i2c_addr, char *image_name_to_program, int erase_before_write)
{
    int i = 0;
    unsigned char i2c_eeprom_sys_name[128];
    char command[256] = {0};
    FILE *fp;
    char write_eeprom_file_buf[EEPROM_WRITE_SIZE];
    char write_file_buf[EEPROM_WRITE_SIZE];
    char test_eeprom_buf[EEPROM_WRITE_SIZE];
    unsigned char md5_digit[16];
    unsigned char eeprom_md5_digit[16];
    char localcmd[128];
    int  file_size = 0;
    char eeprom_image_name[256] = "";
    char tftp_server_ip[256];

    //system("echo \"0 0 0 0\" > /proc/sys/kernel/printk");
    memset(i2c_eeprom_sys_name, '\0', sizeof(i2c_eeprom_sys_name));
    snprintf(i2c_eeprom_sys_name, sizeof(i2c_eeprom_sys_name), "/sys/bus/i2c/devices/0-00%x/eeprom",
             i2c_addr);
#ifdef INSPECTION_DEBUG
    printf("I2C EEPROM SYS NAME=%s\n", i2c_eeprom_sys_name);
#endif

#ifdef INSPECTION_DEBUG
    if(!image_name_to_program) {
        printf("No image file name exist");
    } else {
        printf("Image file name=%s\n", image_name_to_program);
    }
#endif

    memset(eeprom_image_name, '\0', sizeof(eeprom_image_name));

    if((snprintf(&eeprom_image_name[0], sizeof(eeprom_image_name), "%s",
                 image_name_to_program) <= sizeof(eeprom_image_name) )) {
#ifdef INSPECTION_DEBUG
        printf("copy image name success eeprom_image_name=%s image_name_to_program=%s\n", eeprom_image_name,
               image_name_to_program);
#endif
    } else {
        printf("copy image name fail image name =%s image_name_to_program=%s\n", eeprom_image_name,
               image_name_to_program);
    }

#ifdef INSPECTION_DEBUG
    printf("eeprom_image_name=%s\n", eeprom_image_name);
#endif

    /*Delete EEPROM device node run time*/
    if(file_exist(i2c_eeprom_sys_name) != 0) {
        memset(command, "", sizeof(command));
        snprintf(command, sizeof(command), "echo \"0x%x\" > /sys/class/i2c-adapter/i2c-0/delete_device",
                 i2c_addr);
#ifdef INSPECTION_DEBUG
        printf("execute command :==> %s <== done !\n", command);
#endif
        system(command);
    }

    /*Create EEPROM device node run time*/
    memset(command, "", sizeof(command));
    snprintf(command, sizeof(command), "echo \"24c64 0x%x\" > /sys/class/i2c-adapter/i2c-0/new_device",
             i2c_addr);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", command);
#endif
    system(command);

    /*Download image from tftp server*/
    strcpy(tftp_server_ip, tftp_server_ip_address);
    memset(command, '\0', sizeof(command));
    snprintf(command, sizeof(command), "cd /tmp;/usr/bin/tftp -g %s -r %s -l %s -b %d", tftp_server_ip,
             eeprom_image_name, TMP_FW_IMAGE_FILE_NAME, TFTP_DEFAULT_BLOCK_SIZE);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", command);
#endif
    system(command);


    /*ERASE EEPROM as all 0x00 if Erase Before Write command switch was set to 1 */
    if(erase_before_write) {
        system("dd if=/dev/zero of=/tmp/zeroempty.bin bs=1 count=8192 >& /tmp/zeroempty.bin.log");
        file_size = getfilesize("/tmp/zeroempty.bin");
        printf("/tmp/zeroempty.bin file size =%d\n", file_size);
        memset(command, '\0', sizeof(command));
        snprintf(command, sizeof(command), "cd /tmp;/bin/cat /tmp/zeroempty.bin > %s", i2c_eeprom_sys_name);
#ifdef INSPECTION_DEBUG
        printf("execute command :==> %s <== done !\n", command);
#endif
        printf("eeprom erase .........Please Wait\n");
        system(command);
    }


    file_size = getfilesize(TMP_FW_IMAGE_FILE_NAME);
    memset(command, '\0', sizeof(command));
    snprintf(command, sizeof(command), "dd if=%s of=%s bs=1 count=%d", TMP_FW_IMAGE_FILE_NAME,
             i2c_eeprom_sys_name, file_size); //512 byte
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", command);
#endif
    printf("eeprom write image .........Please Wait\n");
    system(command);



    memset(write_eeprom_file_buf, '\0', sizeof(write_eeprom_file_buf));
    copy_file_to_buf(TMP_FW_IMAGE_FILE_NAME, 0L, write_eeprom_file_buf, EEPROM_WRITE_SIZE);
    MD5((unsigned char *)(write_eeprom_file_buf), EEPROM_WRITE_SIZE, md5_digit);


#ifdef INSPECTION_DEBUG
    printf("EEPROM BIN FILE MD5: ");
    for(i = 0; i < 16; i++) {
        printf("%02x", md5_digit[i]);
    }
    printf("\n");
#endif

#ifdef INSPECTION_DEBUG
    printf("I2C EEPROM SYS NAME=%s@2\n", i2c_eeprom_sys_name);
#endif


#ifdef INSPECTION_DEBUG
    printf("i2c_eeprom_sys_name==> %s <== i2c_eeprom_sys_name !\n", i2c_eeprom_sys_name);
#endif
    memset(test_eeprom_buf, '\0', sizeof(test_eeprom_buf));
    copy_file_to_buf(i2c_eeprom_sys_name, 0L, test_eeprom_buf, EEPROM_WRITE_SIZE);
    MD5((unsigned char *)(test_eeprom_buf), EEPROM_WRITE_SIZE, eeprom_md5_digit);
#ifdef INSPECTION_DEBUG
    printf("EEPROM MD5          : ");
    for(i = 0; i < 16; i++) {
        printf("%02x", eeprom_md5_digit[i]);
    }
    printf("\n");
#endif

    //system("echo \"7 4 1 7\" > /proc/sys/kernel/printk");
    for(i = 0; i < 16; i++) {
        if(eeprom_md5_digit[i] != md5_digit[i]) {
            printf("EEPROM  WRITE IMAGE     : %s\n", "FAIL");

            return -2;
        }
    }
    printf("EEPROM  WRITE IMAGE     : %s\n", "PASS");


    return;
}

/**************************************** EEPROM WRITE  END *************************************/
/*---------------------------------------- INSPECT FW VERSION -----------------------------------*/

#include <stdio.h>
#define INSPECTION_VERSION_FILE_PATH "/inspection_firmware_version"

static void usage_inspect_version(void)
{
    printf("Get current diagnostic firmware version, get support only\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_INSPECT_VER);
}

int checkramboot(void)
{
    FILE *fp = NULL;
    char cmdline_str[80];
    char rootfstype_str[80];
    char *rootfstype_str_ptr = NULL;

    unsigned char dummy_str[80];
    char *rootfstype = NULL;

    fp = fopen("/proc/cmdline", "r");
    if(!fp) {
        perror("File %s open errof!\n");
        return -1;
    }
    memset(cmdline_str, '\0', sizeof(cmdline_str));
    fgets(cmdline_str, sizeof(cmdline_str), fp);
    if(fp) {
        fclose(fp);
    }

    rootfstype = strstr(cmdline_str, "rootfstype");

    if(rootfstype) {
        //printf("Success to get rootfstype string=\"%s\" \n",rootfstype);
        memset(rootfstype_str, '\0', sizeof(rootfstype_str));
        rootfstype_str_ptr = strtok(rootfstype, " ");

        if(!rootfstype_str_ptr) {
            printf("Parsing string fail\n");
            return -1;
        } else {
            if(sscanf(rootfstype_str_ptr, "rootfstype=%s", &rootfstype_str) == 1) {
                //printf("Success to parse rootfstype_str string=%s\n",rootfstype_str);

                if(strncmp(rootfstype_str, "ramfs", strlen("ramfs")) == 0) {
                    return 0;
                } else {
                    return -1;
                }
            } else {
                return -1;
            }

        }
    } else {
        return -1; //Not ramboot
    }


}


void fetch_inspect_fw_ver(void)
{
    FILE *fp = NULL;
    unsigned char version_str[80];
    unsigned char rom_version_str[80];
    unsigned char *cptr = NULL;
    int file_size;

    fp = fopen(INSPECTION_VERSION_FILE_PATH, "r");
    if(!fp) {
        perror("File %s open error!\n");
        return ;
    }
    memset(version_str, '\0', sizeof(version_str));
    memset(rom_version_str, '\0', sizeof(rom_version_str));

    fseek(fp, 0, SEEK_SET);
    fgets(&version_str[0], 80, fp);

    file_size = getfilesize(INSPECTION_VERSION_FILE_PATH);


    if(checkramboot() == 0)  {
        printf("INSPECT VER             : %s", version_str);

        // strcat(version_str,"(RAM Base)\n");
    } else {
        strncpy(rom_version_str, version_str, strlen(version_str) - strlen(" (RAM Base)"));
        strcat(rom_version_str, "(ROM Base)\n");
        //printf("Diagnostic fw version   : %s",version_str);
        printf("INSPECT VER             : %s", rom_version_str);
        /* printf("INSPECT_FW VER          : %s",version_str);  */
    }

    fclose(fp);
}

/*---------------------------------------- INSPECT FW VERSION END -------------------------------*/



static int getfilesize(char *fname)
{

    FILE *fp = NULL;
    int prev, sz;
    if(!fname) {
        perror("Empty file name");
        return 0;
    }

    fp = fopen(fname, "rb");
    if(fp) {
        prev = ftell(fp);
        fseek(fp, 0L, SEEK_END);
        sz = ftell(fp);
        fseek(fp, prev, SEEK_SET); //go back to where we were
        fclose(fp);
        return sz;
    } else {
        printf("open file %s to calculate file size fail\n", fname);
        return 0;
    }
}
static void usage_wanport_stat(void)
{
    printf("Get ethernet port status\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_WANSTAT);
}

static void fetch_wanport_stat(void)
{
    FILE *fp = NULL;
    char cmd[128];
    int i, j, k, len;
    char infoitems[1][64] = {
        "LAN-PORT*",
        //  "WAN-PORT*",
    };
    char line[1024];
    char *cptr = NULL;
    char port_name[64];
    char link_updown[2][64];
    char linkspeed[2][64];
    char link_duplex[2][64];
    char cmd_str[128];


    memset(cmd_str, '\0', sizeof(cmd_str));
    sprintf(cmd_str, "ssdk_sh port linkstatus get %s | grep Status | awk  -F ':' '{print  $2 }'",
            ETH_PORT_ID);
#ifdef INSPECTION_DEBUG
    printf("exe cmd={%s}\n", cmd_str);
#endif
    fp = popen(cmd_str, "r");
    /* read output from command */
    fscanf(fp, "%s", &link_updown[0]); /* or other STDIO input functions */
    fclose(fp);
#ifdef INSPECTION_DEBUG
    printf("link_updown[0]=%s\n", link_updown[0]);
#endif



#ifdef WANPORT_STAT_SHOW
    memset(cmd_str, '\0', sizeof(cmd_str));
    sprintf(cmd_str, "ssdk_sh port linkstatus get %s | grep Status | awk  -F ':' '{print  $2 }'",
            ETH_PORT_ID);
#ifdef INSPECTION_DEBUG
    printf("exe cmd={%s}\n", cmd_str);
#endif
    fp = popen(cmd_str, "r");
    /* read output from command */
    fscanf(fp, "%s", &link_updown[1]); /* or other STDIO input functions */
    fclose(fp);
#ifdef INSPECTION_DEBUG
    printf("link_updown[1]=%s\n", link_updown[1]);
#endif
#endif

    memset(cmd_str, '\0', sizeof(cmd_str));
    sprintf(cmd_str, "ssdk_sh port duplex get %s | grep duplex | awk  -F ':' '{print  $2 }'",
            ETH_PORT_ID);
#ifdef INSPECTION_DEBUG
    printf("exe cmd={%s}\n", cmd_str);
#endif
    fp = popen(cmd_str, "r");
    /* read output from command */
    fscanf(fp, "%s", &link_duplex[0]); /* or other STDIO input functions */
    fclose(fp);
#ifdef INSPECTION_DEBUG
    printf("link_duplex[0]=%s\n", link_duplex[0]);
#endif
#ifdef WANPORT_STAT_SHOW
    memset(cmd_str, '\0', sizeof(cmd_str));
    sprintf(cmd_str, "ssdk_sh port duplex get %s | grep duplex | awk  -F ':' '{print  $2 }'",
            ETH_PORT_ID);
#ifdef INSPECTION_DEBUG
    printf("exe cmd={%s}\n", cmd_str);
#endif
    fp = popen(cmd_str, "r");
    /* read output from command */
    fscanf(fp, "%s", &linkspeed[1]); /* or other STDIO input functions */
    fclose(fp);
#ifdef INSPECTION_DEBUG
    printf("link_duplex[1]=%s\n", link_duplex[1]);
#endif
#endif

    memset(cmd_str, '\0', sizeof(cmd_str));




    //sprintf(cmd_str,"str=`ssdk_sh  port speed get 6 | grep speed | awk  -F ':' '{print  $2}'`;let len=${#str}-6 ;echo \"$str\" | cut -c 1-$len");
    sprintf(cmd_str, "ssdk_sh  port speed get %s | grep speed | awk  -F ':' '{print  $2}'",
            ETH_PORT_ID);


#ifdef INSPECTION_DEBUG
    printf("exe cmd={%s}\n", cmd_str);
#endif
    fp = popen(cmd_str, "r");
    /* read output from command */
    fscanf(fp, "%s", &linkspeed[0]); /* or other STDIO input functions */
    fclose(fp);
#ifdef INSPECTION_DEBUG
    printf("linkspeed[0]=%s\n", linkspeed[0]);
#endif

#ifdef WANPORT_STAT_SHOW
    memset(cmd_str, '\0', sizeof(cmd_str));
    sprintf(cmd_str,
            "str=`ssdk_sh  port speed get %s | grep speed | awk  -F ':' '{print  $2}'`;let len=${#str}-6 ;echo \"$str\" | cut -c 1-$len",
            ETH_PORT_ID);
    // sprintf(cmd_str,"ssdk_sh  port speed get 6 | grep speed | awk  -F ':' '{print  $2}'");
#ifdef INSPECTION_DEBUG
    printf("exe cmd={%s}\n", cmd_str);
#endif
    fp = popen(cmd_str, "r");
    /* read output from command */
    fscanf(fp, "%s", &linkspeed[1]); /* or other STDIO input functions */
    fclose(fp);
#ifdef INSPECTION_DEBUG
    printf("linkspeed[0]=%s\n", linkspeed[1]);
#endif
#endif

    if(strncmp(link_updown[0], "ENABLE", strlen("ENABLE") ) == 0) {
        printf("LAN PORT STATUS         : %s | %s\n", &linkspeed[0], link_duplex[0]);
        // printf("WAN PORT STATUS         : %s | %s\n",&linkspeed[1], link_duplex[1]);
        // printf("PORT4 SPEED             : %s\n",&linkspeed[0]);
        // printf("LAN2 SPEED              : ",linkspeed[0]);
    } else {
        printf("LAN PORT STATUS         : %s\n", "------");
        //printf("PORT4 SPEED             : %s\n","------");
        //printf("LAN1 SPEED              : %s\n","------");
    }

#ifdef WANPORT_STAT_SHOW
    if(strncmp(link_updown[1], "ENABLE", strlen("ENABLE") ) == 0) {
        printf("WAN PORT STATUS         : %s | %s\n", &linkspeed[1], link_duplex[1]);
        // printf("WAN PORT STATUS         : %s | %s\n",&linkspeed[1], link_duplex[1]);
        // printf("PORT5 SPEED             : %s\n",&linkspeed[1]);
        // printf("LAN2 SPEED              : ",linkspeed[0]);
    } else {
        printf("WAN PORT STATUS          : %s\n", "------");
        //  printf("PORT5 SPEED             : %s\n","------");
        //  printf("LAN2 SPEED              : %s\n","------");
    }
#endif


}
/*----------------------------------------- END OF WAN PORT SPEED -------------------------------*/

/*---------------------------------------- INSPECT FW AQUANTIA PHY IDENTITY START ---------------------------------*/
static void usage_get_aquantia_phy_identity(void)
{
    printf("Get current aquantia phy identity.\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_AQR_IDENTITY);

}


static void fetch_aquantia_phy_identity(void)
{
    char cmd[256];
    memset(cmd, '\0', sizeof(cmd));
    system("phyid1=`ssdk_sh debug phy get 8 0x401e0002 | grep \"SSDK Init OK!\" | awk -F ':' '{print $2}'`;phyid2=`ssdk_sh debug phy get 8 0x401e0003 | grep \"SSDK Init OK!\" | awk -F ':' '{print $2}'`;echo \"AQR PHY IDENTIFIER      : \"$phyid1\" \"$phyid2");


    return;
}
/*---------------------------------------- INSPECT FW AQUANTIA PHY IDENTITY  STOP ---------------------------------*/

/*---------------------------------------- INSPECT FW AQUANTIA PHY FW VER START ---------------------------------*/
static void usage_get_aquantia_phy_firmware_version(void)
{
    printf("Get current aquantia phy firmware version.\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_AQR_FW_VER);

}


static void fetch_aquantia_phy_firmware_version(void)
{
    system("echo -n \"AQR FW VER (on chip)    : \";aq-get-chip-fw-ver");
    system("echo -n \"AQR FW VER (on flash )  : \";aq-get-flash-fw-ver");
    system("echo -n \"AQR FW VER (on eeprom ) : \";cat /tmp/aq-eeprom-fw-ver.txt");
    //system("echo -n \"AQR FW VER (on eeprom ) : \";aq-get-eeprom-fw-ver");


    return;
}
/*---------------------------------------- INSPECT FW AQUANTIA PHY FW VER   STOP ---------------------------------*/



/*---------------------------------------- INSPECT FW POE SETTING START ---------------------------------*/
static void usage_get_poe_config(void)
{
    printf("Get poe config.\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_POE);

}


static void fetch_poe_setting(void)
{
    printf("AD  DET(GPIO %d)        : %s\n", POE_AD_DET, gpio_get_value(POE_AD_DET) ? "High" : "Low");
    printf("POE DET(GPIO %d)        : %s\n", POE_POW_DET, gpio_get_value(POE_POW_DET) ? "High" : "Low");
    printf("POE AF_AT(GPIO %d)      : %s\n", POE_AF_AT, gpio_get_value(POE_AF_AT) ? "High" : "Low");

    return;
}
/*---------------------------------------- INSPECT FW POE SETTING STOP ---------------------------------*/

/*---------------------------------------- INSPECT FW BT STATUS START ---------------------------------*/
static void usage_get_bt_status(void)
{
    printf("Get bt config.\n");
    printf("read -\n");
    printf("Usage: %s -r %s\n", __progname, RD_CMD_POE);

}


static void fetch_bluetooth_status(void)
{
    FILE *fp = NULL;
    char line[80];
    char dumystring1[80], dumystring2[80];
    char *rssi_p;
    int bt_rssi = 0;
    int dumyval;
    int ret;
    int rssi_count = 0, rssi_sum = 0;

    if(filesize("/tmp/bt_rssi_data.txt") == 0) { //not install yet
        printf("BT RSSI SIGNAL DETECT   : %s\n", "---");

        //printf("POE DET AT DETECT       : %d\n",gpio_get_value(25));
        return 0;

    }
    /* get the file all information */
    if ((fp = fopen("/tmp/bt_rssi_data.txt", "r")) == NULL) {
        printf("BT RSSI SIGNAL DETECT   : %s\n", "---");
        //printf("%s: Open %s error!\n",__func__,"/tmp/bt_rssi_data.txt");
        return -1;
    }
    while(fgets(line, 80, fp)) {

        rssi_p = strstr(line, "rssi");
        // printf("gets line=%s\n",rssi_p);

        ret = sscanf(rssi_p, "rssi %d flags %x", &bt_rssi, &dumyval);
        // printf("ret=%d  bt_rssi=%d\n",ret,bt_rssi);
        if(ret == 2) {
            rssi_count++;
            rssi_sum += bt_rssi;

        }



    }
    // printf("Count=%d Total sum=%d AVG RSSI = %d\n",rssi_count,rssi_sum,rssi_sum/rssi_count);

    //printf("AQR PHY IDENTIFIER      : %d\n",gpio_get_value(9));
    printf("BT RSSI SIGNAL DETECT   : %d\n", rssi_sum / rssi_count);


    fclose(fp);

    return;
}
/*---------------------------------------- INSPECT FW BT STATUS STOP ---------------------------------*/



/*---------------------------------------- ASR ENABLE CHECK START ----------------------------------------*/
static void usage_ddr3_asr_check(void)
{
    printf("Check DDR3 ASR,TFRESH status\n");
    printf("Usage: %s -c %s\n", __progname, RD_CMD_DDR3_ASR_CHECK);
}



int do_ddr3_asr_config_check(void)
{
    u32 cdt_mtd_size ;
    uchar *cdt_data_buf = NULL;
    char localcmd[128], line[128];
    int error = 0;
    int i;
    unsigned char ddr_cdt_md5_digit[16];
    unsigned char cdt_patched_ddr_md5_digit[16];
    memset(DEV_CDT_MTD_NAME, '\0', sizeof(DEV_CDT_MTD_NAME));
    if(get_mtd_device_name(QUALCOMM_CDT_MTD_NAME, DEV_CDT_MTD_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
        printf("Success get %s mtd device name - %s\n", QUALCOMM_CDT_MTD_NAME, DEV_CDT_MTD_NAME);
#endif
    } else {
        printf("%s MTD partition not found\n", QUALCOMM_CDT_MTD_NAME);
        return -1;
    }

    memset(localcmd, "'\0'", sizeof(localcmd));
    sprintf(localcmd, "%s", DEV_CDT_MTD_NAME);
#ifdef INSPECTION_DEBUG
    printf("ubi uboot mtd name(%s)=(%s)%s\n", QUALCOMM_CDT_MTD_NAME, localcmd, DEV_CDT_MTD_NAME);
#endif
    cdt_mtd_size = getfilesize(DEV_CDT_MTD_NAME);
    cdt_data_buf = malloc(sizeof(char) * (cdt_mtd_size));
    memset(cdt_data_buf, 0x0, sizeof(char) * (cdt_mtd_size));
    copy_file_to_buf(localcmd, 0L, cdt_data_buf, cdt_mtd_size);
    MD5((unsigned char *)(cdt_data_buf), QUALCOMM_CDT_DATA_LENGTH, ddr_cdt_md5_digit);
    if(cdt_data_buf) {
        free(cdt_data_buf);
    }

#ifdef INSPECTION_DEBUG
    printf("CDT MD5 IN FLASH         : ");
    for(i = 0; i < 16; i++) {
        printf("%02x", ddr_cdt_md5_digit[i]);
    }
    printf("\n");
#endif
    memset(localcmd, '\0', sizeof(localcmd));
    sprintf(localcmd, "%s", QUALCOMM_CDT_DATA_PATCHED_MD5);
    sscanf(localcmd,
           "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
           &cdt_patched_ddr_md5_digit[0], &cdt_patched_ddr_md5_digit[1], &cdt_patched_ddr_md5_digit[2],
           &cdt_patched_ddr_md5_digit[3], &cdt_patched_ddr_md5_digit[4],
           &cdt_patched_ddr_md5_digit[5], &cdt_patched_ddr_md5_digit[6], &cdt_patched_ddr_md5_digit[7],
           &cdt_patched_ddr_md5_digit[8], &cdt_patched_ddr_md5_digit[9],
           &cdt_patched_ddr_md5_digit[10], &cdt_patched_ddr_md5_digit[11], &cdt_patched_ddr_md5_digit[12],
           &cdt_patched_ddr_md5_digit[13], &cdt_patched_ddr_md5_digit[14],
           &cdt_patched_ddr_md5_digit[15]
          );
#ifdef INSPECTION_DEBUG
    printf("DDR3 PATCHED MD5         : ");
    for(i = 0; i < 16; i++) {
        printf("%02x", cdt_patched_ddr_md5_digit[i]);
    }
    printf("\n");
#endif

    for(i = 0; i < 16; i++) {
        if(ddr_cdt_md5_digit[i] != cdt_patched_ddr_md5_digit[i]) {
            printf("DDR TEMPERATURE,ASR PATCHED         : NO\n");
            return 0;
        }
    }
    printf("DDR TEMPERATURE,ASR PATCHED         : YES\n");
}
/*---------------------------------------- ASR ENABLE CHECK END ----------------------------------------*/


/*---------------------------------------- BAD BLOCK START ----------------------------------------*/
static void usage_bad_block_check(void)
{
    printf("Check NAND flash bad block status\n");
    printf("Usage: %s -c %s\n", __progname, RD_CMD_BAD_BLOCKCHECK);
}

#define TMP_BB_ROOTFS_0 "/tmp/bb_rootfs_0"

int do_bad_block_check(void)
{
    char localcmd[128], line[128];
    int error = 0;
    int bb_full_nand = 0;
    int bb_rootfs_1 = 0;
    int bb_property = 0;
    FILE *fp;

    if (get_mtd_device_name_index(BUF_ROOTFS_0_MTD_NAME, FULL_NAND_MTD_INDEX, 0) != NULL) {
#ifdef INSPECTION_DEBUG
        printf("Success get %s mtd device name - %s\n", BUF_ROOTFS_0_MTD_NAME, FULL_NAND_MTD_INDEX);
#endif
    } else {
        printf("Get %s mtd device name - %s error!\n", BUF_ROOTFS_0_MTD_NAME, FULL_NAND_MTD_INDEX);
        return;
    }



    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "nanddump -f /dev/null -l 0x1 /dev/mtd%s > /tmp/nanddump_mtd%s 2>&1",
            FULL_NAND_MTD_INDEX, FULL_NAND_MTD_INDEX);
    system(localcmd);

    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "cat /tmp/nanddump_mtd%s | grep 'Number of bad blocks' | awk '{print $5}' > %s",
            FULL_NAND_MTD_INDEX, TMP_BB_ROOTFS_0);
    system(localcmd);


#ifdef INSPECTION_DEBUG
    printf("##### Checking BAD BLOCK ...\n");
#endif

    //BUF_ROOTFS_0_MTD_NAME  "rootfs"
    if((fp = fopen(TMP_BB_ROOTFS_0, "r")) == NULL) {
        printf("Failed to open - %s!\n", TMP_BB_ROOTFS_0);
        return;
    }
    while(fgets(line, sizeof(line), fp)) {
        if(sscanf(line, "%d", &bb_full_nand) == 1) {

            if(bb_full_nand < 21) {
#ifdef INSPECTION_DEBUG
                printf("%-14s  %4d < 21  Pass\n", BUF_ROOTFS_0_MTD_NAME, bb_full_nand);
#endif
            } else {
#ifdef INSPECTION_DEBUG
                printf("%-14s  %4d >= 21 Fail\n", BUF_ROOTFS_0_MTD_NAME, bb_full_nand);
#endif
                error++;
            }

        } else {
            printf("%-24s  Fail!\n", BUF_ROOTFS_0_MTD_NAME);
            error++;
        }
    }
    fclose(fp);



    if (error > 0) {

        printf("Check Bad Block         : FAIL    (%d > 21)\n", bb_full_nand);
    } else {
        printf("Check Bad Block         : PASS    (%d < 21)\n", bb_full_nand);
    }


    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "rm -rf /tmp/nanddump_mtd%s", FULL_NAND_MTD_INDEX);
    system(localcmd);


    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "rm -rf %s", TMP_BB_ROOTFS_0);
    system(localcmd);


}
/*---------------------------------------- BAD BLOCK END ----------------------------------------*/

/*---------------------------------------- ECC CORRECTION START ----------------------------------------*/
static void usage_ecc_correction_check(void)
{
    printf("Check NAND flash ecc correction status\n");
    printf("Usage: %s -c %s\n", __progname, RD_CMD_ECCCHECK);
}

#define TMP_ECC_FAILED_ROOTFS_0 "/tmp/ecc_f_rootfs_0"
#define TMP_ECC_NEW_FAILED_ROOTFS_0 "/tmp/ecc_new_f_rootfs_0"
#define TMP_ECC_CORRECTED_ROOTFS_0 "/tmp/ecc_c_rootfs_0"
#define TMP_ECC_NEW_CORRECTED_ROOTFS_0 "/tmp/ecc_new_c_rootfs_0"



int do_ecc_correction_check(void)
{
    char localcmd[128], line[128];
    int error_failed = 0;
    int error_corrected = 0;
    int ecc_failed_rootfs_0 = 0;
    int ecc_failed_rootfs_1 = 0;
    int ecc_failed_property = 0;
    int ecc_new_failed_rootfs_0 = 0;
    int ecc_new_failed_rootfs_1 = 0;
    int ecc_new_failed_property = 0;
    int ecc_result_failed_rootfs_0 = 0;
    int ecc_result_failed_rootfs_1 = 0;
    int ecc_result_failed_property = 0;
    int ecc_corrected_rootfs_0 = 0;
    int ecc_corrected_rootfs_1 = 0;
    int ecc_corrected_property = 0;
    int ecc_new_corrected_rootfs_0 = 0;
    int ecc_new_corrected_rootfs_1 = 0;
    int ecc_new_corrected_property = 0;
    int ecc_result_corrected_rootfs_0 = 0;
    int ecc_result_corrected_rootfs_1 = 0;
    int ecc_result_corrected_property = 0;
    FILE *fp;

    if (get_mtd_device_name_index(BUF_ROOTFS_0_MTD_NAME, FULL_NAND_MTD_INDEX, 0) != NULL) {
#ifdef INSPECTION_DEBUG
        printf("Success get %s mtd device name - %s\n", BUF_ROOTFS_0_MTD_NAME, FULL_NAND_MTD_INDEX);
#endif
    } else {
        printf("Get %s mtd device name - %s error!\n", BUF_ROOTFS_0_MTD_NAME, FULL_NAND_MTD_INDEX);
        return;
    }


    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "nanddump -f /dev/null /dev/mtd%s > /tmp/nanddump_mtd%s 2>&1",
            FULL_NAND_MTD_INDEX, FULL_NAND_MTD_INDEX);
    system(localcmd);

    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "cat /tmp/nanddump_mtd%s | grep 'ECC failed' | awk '{print $3}' > %s",
            FULL_NAND_MTD_INDEX, TMP_ECC_FAILED_ROOTFS_0);
    system(localcmd);


    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "cat /tmp/nanddump_mtd%s | grep 'ECC new failed' | awk '{print $4}' > %s",
            FULL_NAND_MTD_INDEX, TMP_ECC_NEW_FAILED_ROOTFS_0);
    system(localcmd);


    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "cat /tmp/nanddump_mtd%s | grep 'ECC corrected' | awk '{print $3}' > %s",
            FULL_NAND_MTD_INDEX, TMP_ECC_CORRECTED_ROOTFS_0);
    system(localcmd);


    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "cat /tmp/nanddump_mtd%s | grep 'ECC new corrected' | awk '{print $4}' > %s",
            FULL_NAND_MTD_INDEX, TMP_ECC_NEW_CORRECTED_ROOTFS_0);
    system(localcmd);

    //Check ECC failed
#ifdef INSPECTION_DEBUG
    printf("##### Checking ECC failed ...\n");
#endif
    //BUF_ROOTFS_0_MTD_NAME  "rootfs"
    if((fp = fopen(TMP_ECC_FAILED_ROOTFS_0, "r")) == NULL) {
        printf("Failed to open - %s!\n", TMP_ECC_FAILED_ROOTFS_0);
        return;
    }
    while(fgets(line, sizeof(line), fp)) {
        sscanf(line, "%d", &ecc_failed_rootfs_0);
    }
    fclose(fp);
    if((fp = fopen(TMP_ECC_NEW_FAILED_ROOTFS_0, "r")) == NULL) {
        printf("Failed to open - %s!\n", TMP_ECC_NEW_FAILED_ROOTFS_0);
        return;
    }
    while(fgets(line, sizeof(line), fp)) {
        sscanf(line, "%d", &ecc_new_failed_rootfs_0);
    }
    fclose(fp);

    ecc_result_failed_rootfs_0 = ecc_new_failed_rootfs_0 - ecc_failed_rootfs_0;

    if(ecc_result_failed_rootfs_0 == 0) {
#ifdef INSPECTION_DEBUG
        printf("%-14s  %4d = 0   Pass\n", BUF_ROOTFS_0_MTD_NAME, ecc_result_failed_rootfs_0);
#endif
    } else {
#ifdef INSPECTION_DEBUG
        printf("%-14s  %4d > 0   Fail\n", BUF_ROOTFS_0_MTD_NAME, ecc_result_failed_rootfs_0);
#endif
        error_failed++;
    }






    //Check ECC corrected
#ifdef INSPECTION_DEBUG
    printf("##### Checking ECC corrected ...\n");
#endif
    //BUF_ROOTFS_0_MTD_NAME  "rootfs"
    if((fp = fopen(TMP_ECC_CORRECTED_ROOTFS_0, "r")) == NULL) {
        printf("Failed to open - %s!\n", TMP_ECC_CORRECTED_ROOTFS_0);
        return;
    }
    while(fgets(line, sizeof(line), fp)) {
        sscanf(line, "%d", &ecc_corrected_rootfs_0);
    }
    fclose(fp);
    if((fp = fopen(TMP_ECC_NEW_CORRECTED_ROOTFS_0, "r")) == NULL) {
        printf("Failed to open - %s!\n", TMP_ECC_NEW_CORRECTED_ROOTFS_0);
        return;
    }
    while(fgets(line, sizeof(line), fp)) {
        sscanf(line, "%d", &ecc_new_corrected_rootfs_0);
    }
    fclose(fp);

    ecc_result_corrected_rootfs_0 = ecc_new_corrected_rootfs_0 - ecc_corrected_rootfs_0;

    if(ecc_result_corrected_rootfs_0 >= 21) {
        error_corrected++;
    }

    if (error_failed > 0) {
        printf("Check ECC               : FAIL (ECC failed > 0 )\n");
    } else {
        if (ecc_result_corrected_rootfs_0 < 21) {
            printf("Check ECC               : PASS  (new:%d org:%d)\n", ecc_new_corrected_rootfs_0,
                   ecc_corrected_rootfs_0);
        } else {
            printf("Check ECC               : FAIL  (ECC corrected >  21 ,new:%d org:%d)\n",
                   ecc_new_corrected_rootfs_0, ecc_corrected_rootfs_0);
        }
    }



    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "rm -rf /tmp/nanddump_mtd%s", FULL_NAND_MTD_INDEX);
    system(localcmd);


    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "rm -rf %s", TMP_ECC_FAILED_ROOTFS_0);
    system(localcmd);


    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "rm -rf %s", TMP_ECC_NEW_FAILED_ROOTFS_0);
    system(localcmd);



    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "rm -rf %s", TMP_ECC_CORRECTED_ROOTFS_0);
    system(localcmd);


    memset(localcmd, "\0", sizeof(localcmd));
    sprintf(localcmd, "rm -rf %s", TMP_ECC_NEW_CORRECTED_ROOTFS_0);
    system(localcmd);



}
/*---------------------------------------- ECC CORRECTION END ----------------------------------------*/



static char *get_mtd_device_name_index(char *tg_mtd_name, char *dst_mtd_name, int nname)
{
    FILE *fp;
    char  line[128];
    char  name[65];
    int   i, minor;
    int   size, erasesize;
    char  index[6];
    int   find_2nd_rootfs = nname;

    if(!tg_mtd_name) {
        printf("Unspecify MTD name\n");
        return NULL;
    }
    if(!dst_mtd_name) {
        printf("Unspecify MTD target save name\n");
        return NULL;
    }

    fp = fopen("/proc/mtd", "r");
    if(fp == NULL) {
        return NULL;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "mtd%d: %x %x \"%64[^\"]\"", &minor, &size, &erasesize, name) == 4
            && strcasecmp(name, tg_mtd_name) == 0) {
            if(nname == 0) {
                //memset(dst_mtd_name,'\0',sizeof(dst_mtd_name));
                //printf("dst_mtd_name=%s sizeof(dst_mtd_name)=%s\n",dst_mtd_name);
                sprintf(dst_mtd_name, "/dev/mtd%d", minor);
                fclose(fp);
#ifdef INSPECTION_DEBUG
                printf("Find ART mtd name=%s\n", dst_mtd_name);
#endif
                sscanf(dst_mtd_name, "mtd%s", &index);
#ifdef INSPECTION_DEBUG
                printf("mtd(%s)======================> index=%d\n", dst_mtd_name, minor);
#endif
                memset(dst_mtd_name, '\0', sizeof(dst_mtd_name));
                sprintf(&dst_mtd_name[0], "%d", minor);
#ifdef INSPECTION_DEBUG
                printf("Success get %s mtd device index - %s\n", tg_mtd_name, dst_mtd_name);
#endif
                return &dst_mtd_name[0];
            } else {
                nname--;
            }
        }
    }

    sprintf(dst_mtd_name, "/dev/%s", tg_mtd_name);
    if (0 == access(dst_mtd_name, F_OK)) {
#ifdef INSPECTION_DEBUG
        printf("Success get %s mtd device index - %s\n", tg_mtd_name, dst_mtd_name);
#endif
        return &dst_mtd_name[0];
    }

#ifdef INSPECTION_DEBUG
    printf("%s:%s mtd= not found!\n", (find_2nd_rootfs == 1) ? "Second" : "First", tg_mtd_name);
#endif
    return NULL;
}

static int get_mtd_device_size(char *tg_mtd_name, int SecondSameMtdName)
{

    FILE *fp;
    char  line[128];
    char  name[65];
    int   i, minor;
    int   count = 0;
    int   size, erasesize;

    size = erasesize = 0;

    if(!tg_mtd_name) {
        printf("Unspecify MTD name\n");
        return NULL;
    }

    fp = fopen("/proc/mtd", "r");
    if(fp == NULL) {
        printf("get_mtd_device_size: open file %s fail\n", "/proc/mtd");
        return NULL;
    }

    count = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "mtd%d: %x %x \"%64[^\"]\"", &minor, &size, &erasesize, name) == 4
            && strcasecmp(name, tg_mtd_name) == 0) {
            if(!SecondSameMtdName) {
                fclose(fp);
#ifdef INSPECTION_DEBUG
                printf("get_mtd_device_size: return size=%x@111111\n", size);
#endif
                return size;
            } else {
                if(count >= 1) {
                    fclose(fp);
                    printf("get_mtd_device_size: return size=%x@22222222\n", size);
                    return size;
                }
                count++;
            }
        }
    }
#ifdef INSPECTION_DEBUG
    printf("%s mtd not found! size=%d\n", tg_mtd_name, size);
#endif
    return size;
}

static int commit_to_storage_data_partition(char *BUFFER, int BUFFER_LENGTH)
{

    FILE *fp;

    /* get the file all information */
    if ((fp = fopen(DEV_HWDATA_MTD_NAME, "w")) == NULL) {
        printf("%s: Open %s error!\n", __func__, DEV_HWDATA_MTD_NAME);
        return -1;
    }
    if(fwrite(BUFFER , 1 , BUFFER_LENGTH, fp ) != BUFFER_LENGTH) {
        printf("%s: Write device %s fail\n", __func__, DEV_HWDATA_MTD_NAME);
    }



}

static char *get_mtd_device_name(char *tg_mtd_name, char *dst_mtd_name)
{

    FILE *fp;
    char  line[128];
    char  name[65];
    int   i, minor;
    int   size, erasesize;

    if(!tg_mtd_name) {
        printf("Unspecify MTD name\n");
        return NULL;
    }
    if(!dst_mtd_name) {
        printf("Unspecify MTD target save name\n");
        return NULL;
    }


    fp = fopen("/proc/mtd", "r");
    if(fp == NULL) {
        return NULL;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "mtd%d: %x %x \"%64[^\"]\"", &minor, &size, &erasesize, name) == 4
            && strcasecmp(name, tg_mtd_name) == 0) {

            //memset(dst_mtd_name,'\0',sizeof(dst_mtd_name));
            //printf("dst_mtd_name=%s sizeof(dst_mtd_name)=%s\n",dst_mtd_name);
            sprintf(dst_mtd_name, "/dev/mtd%d", minor);
            fclose(fp);
#ifdef INSPECTION_DEBUG
            printf("Find mtd name=%s\n", dst_mtd_name);
#endif

            return &dst_mtd_name[0];
        }
    }
    sprintf(dst_mtd_name, "/dev/%s", tg_mtd_name);
    if (0 == access(dst_mtd_name, F_OK)) {
        return &dst_mtd_name[0];
    }
#ifdef INSPECTION_DEBUG
    printf("%s mtd= not found!\n", tg_mtd_name);
#endif
    return NULL;

}


int read_hwsetting(uchar *hwsetting_buff, u32 length)
{
    int ret = -1 ;
    u32 start_blocks;
    u32 size_blocks;
    u32 flash_type;
    loff_t vendordata_offset;

    if(get_mtd_device_name(STROAGE_MTD_NAME, DEV_HWDATA_MTD_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
        printf("Success get %s mtd device name - %s\n", STROAGE_MTD_NAME, DEV_HWDATA_MTD_NAME);
#endif
    }

    copy_file_to_buf(DEV_HWDATA_MTD_NAME, 0L, hwsetting_buff, STROAGE_MTD_LENGTH);



    return ret;
}


int write_hwsetting(uchar *hwsetting_buff, u32 length)
{
    int ret = -1 ;
    uint32_t start_blocks;
    uint32_t size_blocks;
    u32 flash_type;
    loff_t vendordata_offset;
    loff_t board_vendordata_size;

    if(get_mtd_device_name(STROAGE_MTD_NAME, DEV_HWDATA_MTD_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
        printf("write_hwsetting : Success get %s mtd device name - %s\n", STROAGE_MTD_NAME,
               DEV_HWDATA_MTD_NAME);
#endif
    }

    write_mem_to_mtd_force_size(DEV_HWDATA_MTD_NAME, (unsigned char *) (hwsetting_buff),
                                STROAGE_MTD_LENGTH);

}


int is_ram_boot()
{
    char line[128];
    char *fstype = NULL;
    FILE *fp = NULL;

    fp = fopen("/proc/cmdline", "r");


    if(fp) {
        if(fgets(line, 128, fp) != NULL) {
            fstype = strstr(line, "rootfstype");
            if(strncmp(fstype, "ramfs", strlen("ramfs")) == 0) {
                return 1;
            } else {
                return 0;
            }
        }

    }


}


unsigned char fw_encrypt_256[] = {
    0xce, 0xc0, 0xfc, 0x19, 0x84, 0xdb, 0xa5, 0xd1, 0xfb, 0x1a, 0x1c, 0xf0, 0xc8, 0xfe, 0xb2, 0xf8,
    0xbf, 0x09, 0xec, 0xa1, 0x82, 0x0a, 0xe7, 0xba, 0xe7, 0x04, 0xdd, 0xcd, 0xf5, 0xac, 0xb9, 0xde,
    0xd8, 0x12, 0xa4, 0xdd, 0xd4, 0x9b, 0xe9, 0xf8, 0xa5, 0x91, 0xf6, 0xe1, 0x92, 0xd7, 0xc6, 0x15,
    0xd6, 0xcb, 0xf0, 0xd7, 0x12, 0xe5, 0xfb, 0x8f, 0xb1, 0x80, 0xd7, 0xb7, 0x16, 0xd3, 0xb3, 0x0a,
    0xe2, 0xb6, 0xab, 0xc5, 0xd0, 0xf2, 0x02, 0xba, 0xe2, 0xce, 0x00, 0xae, 0xce, 0xe9, 0xdb, 0x18,
    0xc6, 0x98, 0x01, 0x12, 0xfb, 0xbc, 0xd6, 0x01, 0xf9, 0x85, 0x96, 0x03, 0x1f, 0xf0, 0xd0, 0x90,
    0xa6, 0x91, 0xcd, 0xc4, 0xc9, 0xfe, 0xdf, 0x9b, 0xe1, 0x10, 0x1a, 0xe3, 0xd4, 0x12, 0xc8, 0xce,
    0x85, 0xa1, 0xb1, 0x1d, 0xc0, 0x91, 0x9c, 0x0d, 0x86, 0x1f, 0xb4, 0xb5, 0x1f, 0x04, 0x1e, 0xf2,
    0x01, 0xac, 0xc7, 0xc8, 0xb5, 0x1f, 0x18, 0x12, 0xf3, 0xa2, 0x9e, 0xa8, 0xcb, 0x0c, 0x85, 0x8b,
    0xa8, 0xf4, 0xc2, 0x0b, 0x8b, 0x99, 0xd7, 0xc6, 0x89, 0xb7, 0x7f, 0x9a, 0xa9, 0x9e, 0x9c, 0x7f,
    0x1d, 0xf2, 0x07, 0x80, 0xda, 0x87, 0xaa, 0xd3, 0x7f, 0xf8, 0xad, 0xd8, 0xf3, 0x0f, 0xee, 0xbd,
    0xd9, 0x91, 0xf6, 0x86, 0xd9, 0x11, 0x18, 0x96, 0xd6, 0x8f, 0xfe, 0x02, 0x07, 0xaf, 0x17, 0x92,
    0x0f, 0x83, 0x88, 0x8f, 0xc8, 0xf6, 0xeb, 0x97, 0x8f, 0xb2, 0x19, 0xb7, 0xbe, 0x9f, 0xe5, 0xd0,
    0x88, 0xf1, 0xf7, 0xc3, 0xa0, 0xf4, 0x09, 0xe1, 0xa4, 0xae, 0xc7, 0x9d, 0xac, 0xe5, 0xf3, 0xe9,
    0xae, 0x8e, 0x10, 0x1d, 0x9c, 0xe1, 0xcd, 0xd3, 0x86, 0x92, 0x05, 0xe9, 0x8c, 0xa0, 0xf0, 0x17,
    0xe6, 0xf1, 0x94, 0x8b, 0xd5, 0x8b, 0x8b, 0xe8, 0xb4, 0xb7, 0xf8, 0xfc, 0xaf, 0xfc, 0xaf, 0xf0
};

void image_decode(uchar *src_buffer , uchar *dest_buffer , ulong file_size)
{
    u32 i, keylen;
    //char encryptkey[] = CLI_PASSWORD; /* modify by alfa */ /* modify for 256 encrypt */
    uchar *psrc =  src_buffer;
    uchar *pdest = dest_buffer;
    //keylen = strlen(encryptkey); /* modify by alfa */ /* modify for 256 encrypt */
    keylen = 256 ;

    for(i = 0 ; i < file_size ; i++) {
        //  ram_header[i] = ram_header[i]^encryptkey[i%keylen] ;  /* modify by alfa */ /* modify for 256 encrypt */
        *pdest = *psrc ^ fw_encrypt_256[i % keylen] ;
        pdest += 1;
        psrc += 1;
#if 0
        if(i % 100000 == 0 && recovery_mode) {
            Check_Firmware_Recovery_LED();
        }
#endif
    }
}




int dni_image_write(uchar *startAddr, u32 len)
{
    char localcmd[128];
    unsigned char product_string[16];
    const uchar *ram_header = (const char *)startAddr;
    const uchar *Uboot = "UbootSize:";
    const uchar  *Kernel = "KernelSize:";
    uchar FileCheckSum = 0;
    char runcmd[256];
    u32 start_blocks;
    u32 size_blocks;
    u32 image_len;
    unsigned int uboot_len ;
    char *ubootsize_ptr;
    unsigned int kernel_len ;
    char *kernelsize_ptr;
    u32 rootfs_mtd_addr ;
    u32 rootfs_mtd_size ;
    u32 rootfs_backup_mtd_addr ;
    u32 rootfs_backup_mtd_size ;
    u32 uboot_mtd_addr ;
    u32 uboot_mtd_size ;
    uchar image_header[YAMAHA_Header_Len];

#ifdef INSPECTION_DEBUG
    printf("debug_dni_image_write : ENTER\n");
#endif

    image_len = len ;

#ifdef INSPECTION_DEBUG
    printf("debug_dni_image_write : image_len=%u\n", image_len);
#endif

    // image_decode(startAddr,destAddr,len); //Jacky.Xue: Already descrambal


    memcpy(product_string, header_device_name, strlen(header_device_name));
#ifdef INSPECTION_DEBUG
    printf("product_string: %s, device_name length: %s", product_string, header_device_name);
    printf("ram_header: %s", ram_header + 7);
#endif
    len = image_len ;
    if(memcmp(product_string, ram_header + 7, strlen(header_device_name)) == 0) {
        int i ;
        memcpy(image_header, ram_header, YAMAHA_Header_Len);
        for(i = 0 ; i < YAMAHA_Header_Len ; i++) {
            if(image_header[i] == 0) {
                image_header[i] = 0x30;
            }
        }
        ubootsize_ptr = (char *)(strstr(image_header ,	Uboot)) + 10;
        uboot_len = strtoul(ubootsize_ptr, NULL, 10);

        kernelsize_ptr = (char *)(strstr(image_header ,	Kernel)) + 11;
        kernel_len = strtoul(kernelsize_ptr, NULL, 10);

        while(len--) {
            FileCheckSum = (FileCheckSum + (*ram_header)) & 0xFF;
            *ram_header++;
        }
        FileCheckSum = ~FileCheckSum;

        if(FileCheckSum != 0) {
            printf("Image Checksum is Error\n");
            return -1;
        } else {
            printf("%s Product Firmware Image Checksum is OK\n", hwparam_device_name);
            /***************************************************************************/
            /*  First Un-mount rootfs because wlx diag fw will auto mount all rootfs during botting */
            /* Start Unmount 1st ubi's rootfs mtd partitin mounted and deattach the ubi partition*/
            memset(localcmd, "", sizeof(localcmd));
            sprintf(localcmd, "/bin/umount %s", WLX_YAMAHA_ROOTFS_0_DEFAULT_MOUNT_POINT);
            system(localcmd);
#ifdef INSPECTION_DEBUG
            printf("execute command :==> %s <== done !\n", localcmd);
#endif

            if(get_mtd_device_name_index(ROOTFS_0_MTD_NAME, DEV_ROOTFS_0_MTD_INDEX, 0) != NULL) {
#ifdef INSPECTION_DEBUG
                printf("Success get %s mtd device index - %s\n", ROOTFS_0_MTD_NAME, DEV_ROOTFS_0_MTD_INDEX);
#endif
            } else {
                printf("1st-%s MTD partition not found\n", ROOTFS_0_MTD_NAME);
            }
            memset(localcmd, "", sizeof(localcmd));
            sprintf(localcmd, "/bin/umount %s", WLX_YAMAHA_ROOTFS_0_DEFAULT_MOUNT_POINT);
            system(localcmd);

#ifdef SUPPORT_NAND
            memset(localcmd, "", sizeof(localcmd));
            sprintf(localcmd, "/usr/sbin/ubidetach -m %s", DEV_ROOTFS_0_MTD_INDEX);
#ifdef INSPECTION_DEBUG
            printf("execute command :==> %s <== done !\n", localcmd);
#endif
            system(localcmd);
#endif
            /* End of Unmount 1st ubi's rootfs mtd partitin mounted and deattach the ubi partition*/

            /* Start Unmount 2nd ubi's rootfs mtd partitin mounted and deattach the ubi partition*/
            memset(localcmd, "", sizeof(localcmd));
            sprintf(localcmd, "/bin/umount %s", WLX_YAMAHA_ROOTFS_1_DEFAULT_MOUNT_POINT);
            system(localcmd);

            if(get_mtd_device_name_index(ROOTFS_1_MTD_NAME, DEV_ROOTFS_1_MTD_INDEX, 0) != NULL) {
#ifdef INSPECTION_DEBUG
                printf("Success get %s mtd device name - %s\n", ROOTFS_1_MTD_NAME, DEV_ROOTFS_1_MTD_INDEX);
#endif
            } else {
                printf("1st-%s MTD partition not found\n", ROOTFS_1_MTD_NAME);
            }
#ifdef SUPPORT_NAND
            memset(localcmd, "", sizeof(localcmd));
            sprintf(localcmd, "/usr/sbin/ubidetach -m %s", DEV_ROOTFS_1_MTD_INDEX);
#ifdef INSPECTION_DEBUG
            printf("execute command :==> %s <== done !\n", localcmd);
#endif
#endif

            system(localcmd);
            /* End of Unmount 2nd ubi's rootfs mtd partitin mounted and deattach the ubi partition*/

            /*GET UBI ROOTFS MTD DEVICE NAME*/
            memset(DEV_ROOT_0_MTD_NAME, '\0', sizeof(DEV_ROOT_0_MTD_NAME));
            if(get_mtd_device_name(ROOTFS_0_MTD_NAME, DEV_ROOT_0_MTD_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
                printf("Success get %s mtd device name - %s\n", ROOTFS_0_MTD_NAME, DEV_ROOT_0_MTD_NAME);
#endif
            } else {
                if(1) {
                    printf("%s MTD partition not found\n", ROOTFS_0_MTD_NAME);
                }
                return -1;
            }

            /*GET UBI BACKUP ROOTFS MTD DEVICE NAME*/
            memset(DEV_ROOT_1_MTD_NAME, '\0', sizeof(DEV_ROOT_1_MTD_NAME));
            if(get_mtd_device_name(ROOTFS_1_MTD_NAME, DEV_ROOT_1_MTD_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
                printf("Success get %s mtd device name - %s\n", ROOTFS_1_MTD_NAME, DEV_ROOT_1_MTD_NAME);
#endif
            } else {
                if(1) {
                    printf("%s MTD partition not found\n", ROOTFS_1_MTD_NAME);
                }
                return -1;
            }

            /*GET U-BOOT MTD DEVICE NAME*/
            memset(DEV_UBOOT_MTD_NAME, '\0', sizeof(DEV_UBOOT_MTD_NAME));
            if(get_mtd_device_name(UBOOT_MTD_NAME, DEV_UBOOT_MTD_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
                printf("Success get %s mtd device name - %s\n", UBOOT_MTD_NAME, DEV_UBOOT_MTD_NAME);
#endif
            } else {
                if(1) {
                    printf("%s MTD partition not found\n", UBOOT_MTD_NAME);
                }
                return -1;
            }




            /***************************************************************************/




            if(uboot_len == 0) {
                printf("\nUpdate the exec firmware of %s\n", hwparam_device_name);
                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/sbin/dniflash erase %s", DEV_ROOT_0_MTD_NAME);
                system(localcmd);
                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/sbin/dniflash erase %s", DEV_ROOT_1_MTD_NAME);
                system(localcmd);

                image_len = image_len - YAMAHA_Header_Len - 1 ;
                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/bin/rm -f %s", WLX_FW_ROOTFS_RAW_FILE);
                system(localcmd);
                copy_buf_to_file(WLX_FW_ROOTFS_RAW_FILE, 0, (char *) (startAddr + YAMAHA_Header_Len), image_len);

                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/sbin/dniflash write %s %s", DEV_ROOT_0_MTD_NAME, WLX_FW_ROOTFS_RAW_FILE);
                system(localcmd);
                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/sbin/dniflash write %s %s", DEV_ROOT_1_MTD_NAME, WLX_FW_ROOTFS_RAW_FILE);
                system(localcmd);

                //write_mem_to_mtd(DEV_ROOT_0_MTD_NAME,(unsigned char *) (startAddr+YAMAHA_Header_Len), image_len);
                // write_mem_to_mtd(DEV_ROOT_1_MTD_NAME,(unsigned char *) (startAddr+YAMAHA_Header_Len), image_len);



            } else if (kernel_len != 0 && uboot_len != 0) {
                printf("\nUpdate the rom firmware of %s\n", hwparam_device_name);


                uboot_mtd_size = getfilesize(DEV_UBOOT_MTD_NAME);
#ifdef INSPECTION_DEBUG
                printf("image_len=%u\n", image_len);
#endif
                image_len = image_len - uboot_mtd_size - YAMAHA_Header_Len - 1 ;
#ifdef INSPECTION_DEBUG
                printf("uboot_mtd_size=%\n", uboot_mtd_size);
                printf("image_len=%u\n", image_len);
#endif

                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/bin/rm -f %s", WLX_FW_ROOTFS_RAW_FILE);
                system(localcmd);
                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/sbin/dniflash erase %s", DEV_ROOT_0_MTD_NAME);
                system(localcmd);
                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/sbin/dniflash erase %s", DEV_ROOT_1_MTD_NAME);
                system(localcmd);
                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/sbin/dniflash erase \"%s\"", DEV_UBOOT_MTD_NAME);
                system(localcmd);

                copy_buf_to_file(WLX_FW_ROOTFS_RAW_FILE, 0,
                                 (char *) (startAddr + YAMAHA_Header_Len + uboot_mtd_size), image_len);


                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/sbin/dniflash erase \"%s\"", DEV_UBOOT_MTD_NAME);
                system(localcmd);


                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/sbin/dniflash write %s %s", DEV_ROOT_0_MTD_NAME, WLX_FW_ROOTFS_RAW_FILE);
                system(localcmd);
                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/sbin/dniflash write %s %s", DEV_ROOT_1_MTD_NAME, WLX_FW_ROOTFS_RAW_FILE);
                system(localcmd);
                write_mem_to_mtd(DEV_UBOOT_MTD_NAME, (unsigned char *) (startAddr + YAMAHA_Header_Len), uboot_len);
                //  write_mem_to_mtd(DEV_ROOT_0_MTD_NAME,(unsigned char *) (startAddr+YAMAHA_Header_Len+uboot_mtd_size), image_len);
                //  write_mem_to_mtd(DEV_ROOT_1_MTD_NAME,(unsigned char *) (startAddr+YAMAHA_Header_Len+uboot_mtd_size), image_len);
                // write_mem_to_mtd(DEV_UBOOT_MTD_NAME,(unsigned char *) (startAddr+YAMAHA_Header_Len), uboot_len);



#if 0
                snprintf(runcmd, sizeof(runcmd), "nand erase 0x%x 0x%x", rootfs_mtd_addr, rootfs_mtd_size);
                run_command(runcmd, 0);
                snprintf(runcmd, sizeof(runcmd), "nand erase 0x%x 0x%x", rootfs_backup_mtd_addr,
                         rootfs_backup_mtd_size);
                run_command(runcmd, 0);

                image_len = image_len - uboot_mtd_size - YAMAHA_Header_Len - 1 ;
                if(image_len % 0x20000) {
                    image_len  = image_len + 0x20000 - (image_len % 0x20000) ;
                }

                snprintf(runcmd, sizeof(runcmd), "nand write 0x%x 0x%x 0x%x",
                         startAddr + YAMAHA_Header_Len + uboot_mtd_size, rootfs_mtd_addr, image_len);
                run_command(runcmd, 0);

                run_command("sf probe", 0);
                snprintf(runcmd, sizeof(runcmd), "sf erase 0x%x +0x%x", uboot_mtd_addr, uboot_mtd_size);
                printf("%s\n", runcmd);
                run_command(runcmd, 0);
                snprintf(runcmd, sizeof(runcmd), "sf write 0x%x 0x%x 0x%x", startAddr + YAMAHA_Header_Len,
                         uboot_mtd_addr, uboot_len);
                printf("%s\n", runcmd);
                run_command(runcmd, 0);
#endif
            } else {
                printf("\nUpdate the boot firmware of %s\n", hwparam_device_name);
                memset(DEV_UBOOT_MTD_NAME, '\0', sizeof(DEV_UBOOT_MTD_NAME));
                if(get_mtd_device_name(UBOOT_MTD_NAME, DEV_UBOOT_MTD_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
                    printf("Success get %s mtd device name - %s\n", UBOOT_MTD_NAME, DEV_UBOOT_MTD_NAME);
#endif
                } else {
                    if(1) {
                        printf("%s MTD partition not found\n", UBOOT_MTD_NAME);
                    }
                    return -1;
                }
                write_mem_to_mtd(DEV_UBOOT_MTD_NAME, (unsigned char *) (startAddr + YAMAHA_Header_Len), uboot_len);
#if 0
                run_command("sf probe", 0);
                snprintf(runcmd, sizeof(runcmd), "sf erase 0x%x +0x%x", uboot_mtd_addr, uboot_mtd_size);
                printf("%s\n", runcmd);
                run_command(runcmd, 0);
                snprintf(runcmd, sizeof(runcmd), "sf write 0x%x 0x%x 0x%x", startAddr + YAMAHA_Header_Len,
                         uboot_mtd_addr, uboot_len);
                printf("%s\n", runcmd);
                run_command(runcmd, 0);
#endif
            }
        }
    } else {

        printf("Image format is not good.\n");
        return -1 ;
    }




    return 0;
}

int dni_image_write_simulate_rootfs_only(uchar *startAddr, u32 len)
{
    char localcmd[128];
    unsigned char product_string[16];
    const uchar *ram_header = (const char *)startAddr;
    const uchar *Uboot = "UbootSize:";
    const uchar  *Kernel = "KernelSize:";
    uchar FileCheckSum = 0;
    char runcmd[256];
    u32 start_blocks;
    u32 size_blocks;
    u32 image_len;
    unsigned int uboot_len ;
    char *ubootsize_ptr;
    unsigned int kernel_len ;
    char *kernelsize_ptr;
    u32 rootfs_mtd_addr ;
    u32 rootfs_mtd_size ;
    u32 rootfs_backup_mtd_addr ;
    u32 rootfs_backup_mtd_size ;
    u32 uboot_mtd_addr ;
    u32 uboot_mtd_size ;
    uchar image_header[YAMAHA_Header_Len];

#ifdef INSPECTION_DEBUG
    printf("debug_dni_image_write : ENTER\n");
#endif

    image_len = len ;

#ifdef INSPECTION_DEBUG
    printf("debug_dni_image_write : image_len=%u\n", image_len);
#endif

    memcpy(product_string, header_device_name, strlen(header_device_name));
#ifdef INSPECTION_DEBUG
    printf("product_string: %s, device_name length: %s", product_string, header_device_name);
    printf("ram_header: %s", ram_header + 7);
#endif
    len = image_len ;
    if(memcmp(product_string, ram_header + 7, strlen(header_device_name)) == 0) {
        int i ;
        memcpy(image_header, ram_header, YAMAHA_Header_Len);
        for(i = 0 ; i < YAMAHA_Header_Len ; i++) {
            if(image_header[i] == 0) {
                image_header[i] = 0x30;
            }
        }
        ubootsize_ptr = (char *)(strstr(image_header ,	Uboot)) + 10;
        uboot_len = strtoul(ubootsize_ptr, NULL, 10);

        kernelsize_ptr = (char *)(strstr(image_header ,	Kernel)) + 11;
        kernel_len = strtoul(kernelsize_ptr, NULL, 10);

        while(len--) {
            FileCheckSum = (FileCheckSum + (*ram_header)) & 0xFF;
            *ram_header++;
        }
        FileCheckSum = ~FileCheckSum;

        if(FileCheckSum != 0) {
            printf("Image Checksum is Error\n");
            return -1;
        } else {
            printf("%s Product Firmware Image Checksum is OK\n", hwparam_device_name);
            /***************************************************************************/
            /*  First Un-mount rootfs because wlx diag fw will auto mount all rootfs during botting */
            /* Start Unmount 1st ubi's rootfs mtd partitin mounted and deattach the ubi partition*/
            memset(localcmd, "", sizeof(localcmd));
            sprintf(localcmd, "/bin/umount %s", WLX_YAMAHA_ROOTFS_2_DEFAULT_MOUNT_POINT);
            system(localcmd);
            printf("execute command :==> %s <== done !\n", localcmd);

            if(get_mtd_device_name_index(ROOTFS_2_MTD_NAME, DEV_ROOTFS_2_MTD_INDEX, 0) != NULL) {
#ifdef INSPECTION_DEBUG
                printf("Success get %s mtd device index - %s\n", ROOTFS_2_MTD_NAME, DEV_ROOTFS_2_MTD_INDEX);
#endif
            } else {
                printf("3rd-%s MTD partition not found\n", ROOTFS_2_MTD_NAME);
            }
#ifdef SUPPORT_NAND
            memset(localcmd, "", sizeof(localcmd));
            sprintf(localcmd, "/usr/sbin/ubidetach -m %s", DEV_ROOTFS_2_MTD_INDEX);
#ifdef INSPECTION_DEBUG
            printf("execute command :==> %s <== done !\n", localcmd);
#endif
            system(localcmd);
#endif
            /* End of Unmount 3rd ubi's rootfs mtd partitin mounted and deattach the ubi partition*/

            /*GET UBI ROOTFS MTD DEVICE NAME*/
            memset(DEV_ROOT_2_MTD_NAME, '\0', sizeof(DEV_ROOT_2_MTD_NAME));
            if(get_mtd_device_name(ROOTFS_2_MTD_NAME, DEV_ROOT_2_MTD_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
                printf("Success get %s mtd device name - %s\n", ROOTFS_2_MTD_NAME, DEV_ROOT_2_MTD_NAME);
#endif
            } else {
                if(1) {
                    printf("%s MTD partition not found\n", ROOTFS_2_MTD_NAME);
                }
                return -1;
            }

            /*GET U-BOOT MTD DEVICE NAME*/
            memset(DEV_UBOOT_MTD_NAME, '\0', sizeof(DEV_UBOOT_MTD_NAME));
            if(get_mtd_device_name(UBOOT_MTD_NAME, DEV_UBOOT_MTD_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
                printf("Success get %s mtd device name - %s\n", UBOOT_MTD_NAME, DEV_UBOOT_MTD_NAME);
#endif
            } else {
                if(1) {
                    printf("%s MTD partition not found\n", UBOOT_MTD_NAME);
                }
                return -1;
            }



            /***************************************************************************/

            if(uboot_len == 0) {
                printf("\nUpdate the exec firmware of %s\n", hwparam_device_name);

                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/sbin/dniflash erase %s", DEV_ROOT_2_MTD_NAME);
                system(localcmd);

                image_len = image_len - YAMAHA_Header_Len - 1 ;
                write_mem_to_mtd(DEV_ROOT_2_MTD_NAME, (unsigned char *) (startAddr + YAMAHA_Header_Len), image_len);


            } else if (kernel_len != 0 && uboot_len != 0) {
                printf("\nUpdate the rom firmware of %s\n", hwparam_device_name);


                uboot_mtd_size = getfilesize(DEV_UBOOT_MTD_NAME);
#ifdef INSPECTION_DEBUG
                printf("image_len=%u\n", image_len);
#endif
                image_len = image_len - uboot_mtd_size - YAMAHA_Header_Len - 1 ;
#ifdef INSPECTION_DEBUG
                printf("uboot_mtd_size=%\n", uboot_mtd_size);
                printf("image_len=%u\n", image_len);
#endif

                memset(localcmd, "", sizeof(localcmd));
                sprintf(localcmd, "/sbin/dniflash erase %s", DEV_ROOT_2_MTD_NAME);
                system(localcmd);
                write_mem_to_mtd(DEV_ROOT_2_MTD_NAME,
                                 (unsigned char *) (startAddr + YAMAHA_Header_Len + uboot_mtd_size), image_len);


            }

        }
    } else {

        printf("Image format is not good.\n");
        return -1 ;
    }




    return 0;
}


int dni_image_md5_get(uchar *startAddr, u32 len)
{
    FILE *pFile;
    char localcmd[128];
    char tftp_server_ip[256];
    unsigned char product_string[16];
    const uchar *ram_header = (const char *)startAddr;
    const uchar *Uboot = "UbootSize:";
    const uchar  *Kernel = "KernelSize:";
    uchar FileCheckSum = 0;
    char runcmd[256];
    u32 start_blocks;
    u32 size_blocks;
    u32 image_len;
    u32 wlx_rootfs_img_len;
    u32 uboot_len ;
    char *ubootsize_ptr;
    unsigned int kernel_len ;
    unsigned int fw_ubi_kernel_volume_size;
    unsigned int fw_ubi_rootfs_volume_size;
    char *kernelsize_ptr;
    u32 rootfs_mtd_addr ;
    u32 rootfs_mtd_size ;
    u32 rootfs_backup_mtd_addr ;
    u32 rootfs_backup_mtd_size ;
    u32 uboot_mtd_addr ;
    u32 uboot_mtd_size ;
    u32 kernel_mtd_size ;
    uchar image_header[YAMAHA_Header_Len];
    char *rootfs_buf = NULL;
    uchar *uboot_buf = NULL;
    unsigned char fw_ubi_img_md5_digit[16];
    unsigned char flsah_ubikernel_1_md5_digit[16];
    unsigned char flsah_ubikernel_2_md5_digit[16];
    unsigned char flsah_ubikernel_3_md5_digit[16];
    unsigned char flsah_ubifs1_img_md5_digit[16];
    unsigned char flsah_ubifs2_img_md5_digit[16];
    unsigned char flsah_ubifs3_img_md5_digit[16];
    unsigned char fw_uboot_md5_digit[16];
    unsigned char flash_uboot_md5_digit[16];
    int firmware_md5_cmp_result = 0;

    //system("");

#ifdef INSPECTION_DEBUG
    printf("debug_dni_image_write : ENTER\n");
#endif
    image_len = len ;

#ifdef INSPECTION_DEBUG
    printf("debug_dni_image_write : image_len=%u\n", image_len);
#endif

    // image_decode(startAddr,destAddr,len); //Jacky.Xue: Already descrambal


    get_mtd_device_name_index(WLX_0_KERNEL_NAME, DEV_KERNEL_0_MTD_INDEX, 0);
    memcpy(product_string, header_device_name, strlen(header_device_name));
#ifdef INSPECTION_DEBUG
    printf("product_string: %s, device_name length: %s", product_string, header_device_name);
    printf("ram_header: %s", ram_header + 7);
#endif

    len = image_len ;

    if(memcmp(product_string, ram_header + 7, strlen(header_device_name)) == 0) {
        int i ;

        memcpy(image_header, ram_header, YAMAHA_Header_Len);

        for(i = 0 ; i < YAMAHA_Header_Len ; i++) {
            if(image_header[i] == 0) {
                image_header[i] = 0x30;
            }
        }

        ubootsize_ptr = (char *)(strstr(image_header ,	Uboot)) + 10;
        uboot_len = strtoul(ubootsize_ptr, NULL, 10);

        kernelsize_ptr = (char *)(strstr(image_header ,	Kernel)) + 11;
        kernel_len = strtoul(kernelsize_ptr, NULL, 10);




        /*GET U-BOOT MTD DEVICE NAME*/
        memset(DEV_UBOOT_MTD_NAME, '\0', sizeof(DEV_UBOOT_MTD_NAME));
        if(get_mtd_device_name(UBOOT_MTD_NAME, DEV_UBOOT_MTD_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
            printf("Success get %s mtd device name - %s\n", UBOOT_MTD_NAME, DEV_UBOOT_MTD_NAME);
#endif
        } else {
            printf("%s MTD partition not found\n", UBOOT_MTD_NAME);
            printf("MTD PARTS-0 MD5 CHECK           : FAIL\n");
            printf("MTD PARTS-1 MD5 CHECK           : FAIL\n");
            printf("U-BOOT MTD PART MD5 CHECK           : FAIL\n");
            return -1;
        }

        uboot_mtd_size = getfilesize(DEV_UBOOT_MTD_NAME);
        wlx_rootfs_img_len = image_len - uboot_mtd_size - YAMAHA_Header_Len - 1;

        //copy_buf_to_file(WLX_FW_DESCRAMBLE_FILE,0,destination_buf,file_size);
#ifdef INSPECTION_DEBUG
        printf("image_len=%u\n", image_len);
        printf("uboot_mtd_size=%u\n", uboot_mtd_size);
        printf("uboot_len=%u\n", uboot_len);
        printf("kernel_len=%u\n", kernel_len);
        printf("YAMAHA_Header_Len=%u\n", YAMAHA_Header_Len);
        printf("rootfs_img_len=%u\n", wlx_rootfs_img_len);
#endif
        copy_buf_to_file(WLX_FW_DESCRAMBLE_UBI_ROOTFS_IMG_FILE, 0,
                         (unsigned char *) (startAddr + YAMAHA_Header_Len + uboot_mtd_size), wlx_rootfs_img_len);

#ifdef SUPPORT_NAND
        memset(localcmd, '\0', sizeof(localcmd));
        sprintf(localcmd, "cd /tmp;/usr/sbin/ubi-extractor -i %s > /dev/null 2>&1",
                WLX_FW_DESCRAMBLE_UBI_ROOTFS_IMG_FILE);
#ifdef INSPECTION_DEBUG
        printf("execute command :==> %s <== done !\n", localcmd);
#endif
        system(localcmd);

        memset(localcmd, "'\0'", sizeof(localcmd));
        sprintf(localcmd, "/tmp/%s", "kernel.bin");
#ifdef INSPECTION_DEBUG
        printf("ubi img kernel file name=%s\n", localcmd);
#endif
        fw_ubi_kernel_volume_size = filesize(localcmd);


        memset(localcmd, "'\0'", sizeof(localcmd));
        sprintf(localcmd, "/tmp/%s", "ubi_rootfs.bin");
#ifdef INSPECTION_DEBUG
        printf("ubi img rootfs file name=%s\n", localcmd);
#endif
        fw_ubi_rootfs_volume_size = filesize(localcmd);

#endif


        while(len--) {
            FileCheckSum = (FileCheckSum + (*ram_header)) & 0xFF;
            *ram_header++;
        }
        FileCheckSum = ~FileCheckSum;




        if(FileCheckSum != 0) {
            printf("Image Checksum is Error\n");
            system("rm -fv *.bin /tmp/*.bin");
            return -1;
        } else {
#ifdef INSPECTION_DEBUG
            printf("%s Product Firmware rom Image Checksum is OK\n", hwparam_device_name);
#endif

            memset(localcmd, "'\0'", sizeof(localcmd));
            sprintf(localcmd, "/tmp/%smd5info.txt", hwparam_device_name);
            pFile = fopen(localcmd, "w");
            if( NULL == pFile ) {
                printf( "open failure" );
                return 1;

            }

            if (kernel_len != 0 && uboot_len != 0) {
#ifdef INSPECTION_DEBUG
                printf("Get DEV_UBOOT_MTD_NAME =%s\n", DEV_UBOOT_MTD_NAME);
#endif
                uboot_mtd_size = getfilesize(DEV_UBOOT_MTD_NAME);
                wlx_rootfs_img_len = image_len - uboot_mtd_size - YAMAHA_Header_Len - 1;
#ifdef INSPECTION_DEBUG
                printf("image_len=%u\n", image_len);
                printf("uboot_mtd_size=%u\n", uboot_mtd_size);
                printf("uboot_len=%u\n", uboot_len);
                printf("kernel_len=%u\n", kernel_len);
                printf("YAMAHA_Header_Len=%u\n", YAMAHA_Header_Len);
                printf("wlx_rootfs_img_len=%u\n", wlx_rootfs_img_len);
                printf("fw_ubi_kernel_volume_size=%u\n", fw_ubi_kernel_volume_size);
                printf("fw_ubi_rootfs_volume_size=%u\n", fw_ubi_rootfs_volume_size);

#endif

#ifdef SUPPORT_NAND
                /*CHECK UBI2 KERNEL MTD*/
                memset(localcmd, "'\0'", sizeof(localcmd));
                sprintf(localcmd, "/tmp/%s", "kernel.bin");
#ifdef INSPECTION_DEBUG
                printf("ubi img kernel file name=%s\n", localcmd);
#endif

                rootfs_buf = malloc(sizeof(char) * (fw_ubi_kernel_volume_size));
                memset(rootfs_buf, 0x0, sizeof(char) * (fw_ubi_kernel_volume_size));
                copy_file_to_buf(localcmd, 0L, rootfs_buf, fw_ubi_kernel_volume_size);
                MD5((unsigned char *)(rootfs_buf), fw_ubi_kernel_volume_size, flsah_ubikernel_3_md5_digit);
                if(rootfs_buf) {
                    free(rootfs_buf);
                }

#if 1 //def INSPECTION_DEBUG
                fprintf(pFile, "FW KERNEL MD5  : ");
                for(i = 0; i < 16; i++) {
                    fprintf(pFile, "%02x", flsah_ubikernel_3_md5_digit[i]);
                }
                fprintf(pFile, "\n");
                fprintf(pFile, "FW KERNEL LEN  : %d\n", fw_ubi_kernel_volume_size);

                printf("FW KERNEL MD5  : ");
                for(i = 0; i < 16; i++) {
                    printf("%02x", flsah_ubikernel_3_md5_digit[i]);
                }
                printf("\n");
                printf("FW KERNEL LEN  : %d\n", fw_ubi_kernel_volume_size);

#endif




                /*CHECK UBI2 FS MTD*/
                memset(localcmd, "'\0'", sizeof(localcmd));
                sprintf(localcmd, "/tmp/%s", "ubi_rootfs.bin");
#ifdef INSPECTION_DEBUG
                printf("ubi img rootfs file name=%s\n", localcmd);
#endif

                rootfs_buf = malloc(sizeof(char) * (fw_ubi_rootfs_volume_size));
                memset(rootfs_buf, 0x0, sizeof(char) * (fw_ubi_rootfs_volume_size));
                copy_file_to_buf(localcmd, 0L, rootfs_buf, fw_ubi_rootfs_volume_size);
                MD5((unsigned char *)(rootfs_buf), fw_ubi_rootfs_volume_size, flsah_ubifs3_img_md5_digit);
                if(rootfs_buf) {
                    free(rootfs_buf);
                }

#if 1 //def INSPECTION_DEBUG
                fprintf(pFile, "FW ROOTFS MD5  : ");
                for(i = 0; i < 16; i++) {
                    fprintf(pFile, "%02x", flsah_ubifs3_img_md5_digit[i]);
                }
                fprintf(pFile, "\n");
                fprintf(pFile, "FW ROOTFS LEN  : %d\n", fw_ubi_rootfs_volume_size);



                printf("FW ROOTFS MD5  : ");
                for(i = 0; i < 16; i++) {
                    printf("%02x", flsah_ubifs3_img_md5_digit[i]);
                }
                printf("\n");
                printf("FW ROOTFS LEN  : %d\n", fw_ubi_rootfs_volume_size);
#endif

#else //for SUPPORT_NAND
                /*CHECK FW kernel+rootfs  */
                snprintf(localcmd, sizeof(localcmd), "%s", WLX_FW_DESCRAMBLE_UBI_ROOTFS_IMG_FILE);
                cal_file_md5(localcmd, wlx_rootfs_img_len, flsah_ubifs3_img_md5_digit);
                fprintf(pFile, "FW KERNEL_ROOTFS MD5  : ");
                for(i = 0; i < 16; i++) {
                    fprintf(pFile, "%02x", flsah_ubifs3_img_md5_digit[i]);
                }
                fprintf(pFile, "\n");
                fprintf(pFile, "FW KERNEL_ROOTFS LEN  : %d\n", wlx_rootfs_img_len);

                printf("FW KERNEL_ROOTFS MD5  : ");
                for(i = 0; i < 16; i++) {
                    printf("%02x", flsah_ubifs3_img_md5_digit[i]);
                }
                printf("\n");
                printf("FW KERNEL_ROOTFS LEN  : %d\n", wlx_rootfs_img_len);

#endif //for SUPPORT_NAND

                /*CHECK FW U-BOOT  */
                //MD5((unsigned char *) (startAddr+YAMAHA_Header_Len),uboot_len,fw_uboot_md5_digit);
                copy_buf_to_file("/tmp/wlx_uboot.bin", 0, (unsigned char *) (startAddr + YAMAHA_Header_Len),
                                 uboot_len);
                cal_file_md5("/tmp/wlx_uboot.bin", uboot_len, fw_uboot_md5_digit);

                fprintf(pFile, "FW U-BOOT MD5  : ");
                for(i = 0; i < 16; i++) {
                    fprintf(pFile, "%02x", fw_uboot_md5_digit[i]);
                }
                fprintf(pFile, "\n");
                fprintf(pFile, "FW U-BOOT LEN  : %d\n", uboot_len);

                printf("FW U-BOOT MD5  : ");
                for(i = 0; i < 16; i++) {
                    printf("%02x", fw_uboot_md5_digit[i]);
                }
                printf("\n");
                printf("FW U-BOOT LEN  : %d\n", uboot_len);


                fclose(pFile);
                /*************************** Send md5info file to tftp server start **************************/
                strcpy(tftp_server_ip, tftp_server_ip_address);
                memset(localcmd, '\0', sizeof(localcmd));
                sprintf(localcmd, "cd /tmp;/usr/bin/tftp -p %s -r %smd5info.txt -l /tmp/%smd5info.txt -b %d",
                        tftp_server_ip,
                        hwparam_device_name, hwparam_device_name, TFTP_DEFAULT_BLOCK_SIZE);
#ifdef INSPECTION_DEBUG
                printf("Execute command=%s\n", localcmd);
#endif
                system(localcmd);
                printf("\nSent firmware md5 file - %smd5info.txt to tftp server root done !\n",
                       hwparam_device_name);


            } else {
                printf("MTD PARTS-0 MD5 INFO           : NA (tftp fw format in-correct -support %s-Rev.ww.xx.yy_build-z.rom only)\n",
                       hwparam_device_name);
                printf("MTD PARTS-1 MD5 INFO           : NA (tftp fw format in-correct -support %s-Rev.ww.xx.yy_build-z.rom only)\n",
                       hwparam_device_name);
                printf("U-BOOT MTD PART MD5 INFO           : NA (tftp fw format in-correct -support %s-Rev.ww.xx.yy_build-z.rom only)\n",
                       hwparam_device_name);

            }


        }
    } else {

        //Sprintf("Image format is not good.\n");
        printf("MTD PARTS-0 MD5 INFO           : NA (tftp fw checksum error)\n");
        printf("MTD PARTS-1 MD5 INFO           : NA (tftp fw checksum error)\n");
        printf("U-BOOT MTD PART MD5 INFO           : NA (tftp fw checksum error)\n");



        system("rm -fv *.bin /tmp/*.bin");

        return -1 ;
    }

    system("rm -fv *.bin /tmp/*.bin");


    return 0;
}

int dni_image_md5_check(int read_flash)
{
    FILE *pFile;
    char localcmd[256] = {0};
    unsigned char product_string[16];
    u32 uboot_len ;
    u32 uboot_mtd_size ;
    unsigned int kernel_len ;
    unsigned int fw_ubi_kernel_volume_size;
    unsigned int fw_ubi_rootfs_volume_size;
    unsigned char fw_ubi_img_md5_digit[16] = {0};
    unsigned char flsah_ubikernel_1_md5_digit[16] = {0};
    unsigned char flsah_ubikernel_2_md5_digit[16] = {0};
    unsigned char flsah_ubikernel_3_md5_digit[16] = {0};
    unsigned char flsah_ubifs1_img_md5_digit[16] = {0};
    unsigned char flsah_ubifs2_img_md5_digit[16] = {0};
    unsigned char flsah_ubifs3_img_md5_digit[16] = {0};
    unsigned char fw_uboot_md5_digit[16] = {0};
    unsigned char flash_uboot_md5_digit[16] = {0};
    int firmware_md5_cmp_result = 0;
    char line[128];
    int i;


    sprintf(localcmd, "/tmp/%smd5info.txt", hwparam_device_name);
    pFile = fopen(localcmd, "r");
    if( NULL == pFile ) {
        printf( "Open file %s failure", localcmd );
        return 1;
    }
    /*Get kernel,rootfs and u-boot image length and md5 */

    while(fgets(line, 128, pFile)) {

        //printf("line=%s",line);

        if(strncmp(line, "FW KERNEL MD5  :", strlen("FW KERNEL MD5  :")) == 0) {
            sscanf(line,
                   "FW KERNEL MD5  : %02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                   &flsah_ubikernel_3_md5_digit[0], &flsah_ubikernel_3_md5_digit[1], &flsah_ubikernel_3_md5_digit[2],
                   &flsah_ubikernel_3_md5_digit[3], &flsah_ubikernel_3_md5_digit[4],
                   &flsah_ubikernel_3_md5_digit[5], &flsah_ubikernel_3_md5_digit[6], &flsah_ubikernel_3_md5_digit[7],
                   &flsah_ubikernel_3_md5_digit[8], &flsah_ubikernel_3_md5_digit[9],
                   &flsah_ubikernel_3_md5_digit[10], &flsah_ubikernel_3_md5_digit[11],
                   &flsah_ubikernel_3_md5_digit[12], &flsah_ubikernel_3_md5_digit[13],
                   &flsah_ubikernel_3_md5_digit[14],
                   &flsah_ubikernel_3_md5_digit[15]
                  );

#ifdef INSPECTION_DEBUG
            printf("FETCH KERNEL MD5 : ");
            for(i = 0; i < 16; i++) {
                printf("%02x", flsah_ubikernel_3_md5_digit[i]);
            }
            printf("\n");
#endif

        }

        else    if(strncmp(line, "FW KERNEL_ROOTFS MD5  :", strlen("FW KERNEL_ROOTFS MD5  :")) == 0) {
            sscanf(line,
                   "FW KERNEL_ROOTFS MD5  : %02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                   &flsah_ubifs3_img_md5_digit[0], &flsah_ubifs3_img_md5_digit[1], &flsah_ubifs3_img_md5_digit[2],
                   &flsah_ubifs3_img_md5_digit[3], &flsah_ubifs3_img_md5_digit[4],
                   &flsah_ubifs3_img_md5_digit[5], &flsah_ubifs3_img_md5_digit[6], &flsah_ubifs3_img_md5_digit[7],
                   &flsah_ubifs3_img_md5_digit[8], &flsah_ubifs3_img_md5_digit[9],
                   &flsah_ubifs3_img_md5_digit[10], &flsah_ubifs3_img_md5_digit[11], &flsah_ubifs3_img_md5_digit[12],
                   &flsah_ubifs3_img_md5_digit[13], &flsah_ubifs3_img_md5_digit[14],
                   &flsah_ubifs3_img_md5_digit[15]
                  );
#ifdef INSPECTION_DEBUG
            printf("FETCH KERNEL_ROOTFS MD5 : ");
            for(i = 0; i < 16; i++) {
                printf("%02x", flsah_ubifs3_img_md5_digit[i]);
            }
            printf("\n");
#endif
        } else    if(strncmp(line, "FW ROOTFS MD5  :", strlen("FW ROOTFS MD5  :")) == 0) {
            sscanf(line,
                   "FW ROOTFS MD5  : %02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                   &flsah_ubifs3_img_md5_digit[0], &flsah_ubifs3_img_md5_digit[1], &flsah_ubifs3_img_md5_digit[2],
                   &flsah_ubifs3_img_md5_digit[3], &flsah_ubifs3_img_md5_digit[4],
                   &flsah_ubifs3_img_md5_digit[5], &flsah_ubifs3_img_md5_digit[6], &flsah_ubifs3_img_md5_digit[7],
                   &flsah_ubifs3_img_md5_digit[8], &flsah_ubifs3_img_md5_digit[9],
                   &flsah_ubifs3_img_md5_digit[10], &flsah_ubifs3_img_md5_digit[11], &flsah_ubifs3_img_md5_digit[12],
                   &flsah_ubifs3_img_md5_digit[13], &flsah_ubifs3_img_md5_digit[14],
                   &flsah_ubifs3_img_md5_digit[15]
                  );
#ifdef INSPECTION_DEBUG
            printf("FETCH ROOTFS MD5 : ");
            for(i = 0; i < 16; i++) {
                printf("%02x", flsah_ubifs3_img_md5_digit[i]);
            }
            printf("\n");
#endif
        } else if(strncmp(line, "FW U-BOOT MD5  :", strlen("FW U-BOOT MD5  :")) == 0) {
            sscanf(line,
                   "FW U-BOOT MD5  : %02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                   &fw_uboot_md5_digit[0], &fw_uboot_md5_digit[1], &fw_uboot_md5_digit[2], &fw_uboot_md5_digit[3],
                   &fw_uboot_md5_digit[4],
                   &fw_uboot_md5_digit[5], &fw_uboot_md5_digit[6], &fw_uboot_md5_digit[7], &fw_uboot_md5_digit[8],
                   &fw_uboot_md5_digit[9],
                   &fw_uboot_md5_digit[10], &fw_uboot_md5_digit[11], &fw_uboot_md5_digit[12], &fw_uboot_md5_digit[13],
                   &fw_uboot_md5_digit[14],
                   &fw_uboot_md5_digit[15]
                  );

#ifdef INSPECTION_DEBUG
            printf("FETCH U-BOOT MD5 : ");
            for(i = 0; i < 16; i++) {
                printf("%02x", fw_uboot_md5_digit[i]);
            }
            printf("\n");
#endif

        }

        else if(strncmp(line, "FW KERNEL LEN  :", strlen("FW KERNEL LEN  :")) == 0) {
            sscanf(line, "FW KERNEL LEN  :%u", &fw_ubi_kernel_volume_size);

#ifdef INSPECTION_DEBUG
            printf("FETCH KERNEL LEN : ");
            printf("%u", fw_ubi_kernel_volume_size);
            printf("\n");
#endif

        } else if(strncmp(line, "FW KERNEL_ROOTFS LEN  :", strlen("FW KERNEL_ROOTFS LEN  :")) == 0) {
            sscanf(line, "FW KERNEL_ROOTFS LEN  :%u", &fw_ubi_rootfs_volume_size);
#ifdef INSPECTION_DEBUG
            printf("FETCH KERNEL_ROOTFS LEN : ");
            printf("%u", fw_ubi_rootfs_volume_size);
            printf("\n");
#endif
        } else if(strncmp(line, "FW ROOTFS LEN  :", strlen("FW ROOTFS LEN  :")) == 0) {
            sscanf(line, "FW ROOTFS LEN  :%u", &fw_ubi_rootfs_volume_size);
#ifdef INSPECTION_DEBUG
            printf("FETCH ROOTFS LEN : ");
            printf("%u", fw_ubi_rootfs_volume_size);
            printf("\n");
#endif
        } else if(strncmp(line, "FW U-BOOT LEN  :", strlen("FW U-BOOT LEN  :")) == 0) {
            sscanf(line, "FW U-BOOT LEN  :%u", &uboot_len);
#ifdef INSPECTION_DEBUG
            printf("FETCH U-BOOT LEN : ");
            printf("%u", uboot_len);
            printf("\n");
#endif
        }


    }
    fclose(pFile);

    if (read_flash == 1) {
        printf("Check firmware in flash ...\n");

#ifdef INSPECTION_DEBUG
        printf("----------------------- Get flash MD5 -------------------\n");
#endif




#ifdef SUPPORT_NAND
        /*Get all ubi kernel volume index */
        if(get_mtd_device_name_index(WLX_0_KERNEL_NAME, DEV_KERNEL_0_MTD_INDEX, 0) == NULL) {
            printf("1st-%s MTD partition not found\n", WLX_0_KERNEL_NAME);
        }

        if(get_mtd_device_name_index(WLX_1_KERNEL_NAME, DEV_KERNEL_1_MTD_INDEX, 1) == NULL) {
            printf("2nd-%s MTD partition not found\n", WLX_1_KERNEL_NAME);
        }

        /*Get all ubi rootfs volume index */
        if(get_mtd_device_name_index(WLX_ROOTFS_0_DEFAULT_ROOTFS_NAME, DEV_ROOTFS_0_MTD_INDEX, 0) == NULL) {
            printf("1st-%s MTD partition not found\n", WLX_ROOTFS_0_DEFAULT_ROOTFS_NAME);
        }

        if(get_mtd_device_name_index(WLX_ROOTFS_1_DEFAULT_ROOTFS_NAME, DEV_ROOTFS_1_MTD_INDEX, 1) == NULL) {
            printf("2st-%s MTD partition not found\n", WLX_ROOTFS_1_DEFAULT_ROOTFS_NAME);
        }
#endif


        if (fw_ubi_rootfs_volume_size != 0 && uboot_len != 0) {
            uboot_mtd_size = getfilesize(DEV_UBOOT_MTD_NAME);
#ifdef INSPECTION_DEBUG
            printf("uboot_mtd_size=%u\n", uboot_mtd_size);
            printf("uboot_len=%u\n", uboot_len);
            printf("kernel_len=%u\n", kernel_len);
            printf("fw_ubi_kernel_volume_size=%u\n", fw_ubi_kernel_volume_size);
            printf("fw_ubi_rootfs_volume_size=%u\n", fw_ubi_rootfs_volume_size);
#endif

#ifdef SUPPORT_NAND
            snprintf(localcmd, sizeof(localcmd), "%s", DEV_KERNEL_0_MTD_INDEX);
            cal_file_md5(localcmd, fw_ubi_kernel_volume_size, flsah_ubikernel_1_md5_digit);

            snprintf(localcmd, sizeof(localcmd), "%s", DEV_KERNEL_1_MTD_INDEX);
            cal_file_md5(localcmd, fw_ubi_kernel_volume_size, flsah_ubikernel_2_md5_digit);
#endif

            get_mtd_device_name_index(ROOTFS_0_MTD_NAME, DEV_ROOTFS_0_MTD_INDEX, 0);
            get_mtd_device_name_index(ROOTFS_1_MTD_NAME, DEV_ROOTFS_1_MTD_INDEX, 0);
            snprintf(localcmd, sizeof(localcmd), "%s", DEV_ROOTFS_0_MTD_INDEX);
            cal_file_md5(localcmd, fw_ubi_rootfs_volume_size, flsah_ubifs1_img_md5_digit);
            snprintf(localcmd, sizeof(localcmd), "%s", DEV_ROOTFS_1_MTD_INDEX);
            cal_file_md5(localcmd, fw_ubi_rootfs_volume_size, flsah_ubifs2_img_md5_digit);

            /*CHECK U-BOOT MTD*/
            get_mtd_device_name(UBOOT_MTD_NAME, DEV_UBOOT_MTD_NAME);
            snprintf(localcmd, sizeof(localcmd), "/sbin/dniflash read %s %s 2>/dev/null", DEV_UBOOT_MTD_NAME,
                     UBOOT_FLASH_BIN);
            system(localcmd);
            /*uboot_buf = malloc(sizeof(char) * (uboot_mtd_size));
            copy_file_to_buf(localcmd,0L,uboot_buf,uboot_len);
            copy_buf_to_file("/tmp/mtduboot",0L,uboot_buf,uboot_len);
            rootfs_buf = malloc(sizeof(char) * (uboot_mtd_size));
            copy_file_to_buf("/tmp/2wlx_uboot.bin",0L,rootfs_buf,uboot_len);
            if(memcmp(uboot_buf, rootfs_buf, 1024) == 0)
            	printf("same\n");
            else
            	printf("not same\n");*/
            cal_file_md5(UBOOT_FLASH_BIN, uboot_len, flash_uboot_md5_digit);

#ifdef INSPECTION_DEBUG
            printf("U-BOOT MD5 IN FLASH         : ");
            for(i = 0; i < 16; i++) {
                printf("%02x", flash_uboot_md5_digit[i]);
            }
            printf("\n");
#endif

            pFile = fopen("/tmp/flash_fwmd5_info.txt", "w");
            if (pFile == NULL) {
                printf("File /tmp/flash_fwmd5_info.txt: Open Failed.");
                return 1;
            }

            fprintf(pFile, "FLASH ROOTFS1 FWMD5  : ");
            for(i = 0; i < 16; i++) {
                fprintf(pFile, "%02x", flsah_ubifs1_img_md5_digit[i]);
            }
            fprintf(pFile, "\n");

            fprintf(pFile, "FLASH ROOTFS2 FWMD5  : ");
            for(i = 0; i < 16; i++) {
                fprintf(pFile, "%02x", flsah_ubifs2_img_md5_digit[i]);
            }
            fprintf(pFile, "\n");

            fprintf(pFile, "FLASH U-BOOT FWMD5  : ");
            for(i = 0; i < 16; i++) {
                fprintf(pFile, "%02x", flash_uboot_md5_digit[i]);
            }
            fprintf(pFile, "\n");
            fclose(pFile);
        }
        system("rm -fv *.bin /tmp/*.bin");
    } else {

        printf("start firmware md5 comparing ...\n");
        /*GET U-BOOT MTD DEVICE NAME*/
        memset(DEV_UBOOT_MTD_NAME, '\0', sizeof(DEV_UBOOT_MTD_NAME));
        if(get_mtd_device_name(UBOOT_MTD_NAME, DEV_UBOOT_MTD_NAME) == NULL) {
            printf("%s MTD partition not found\n", UBOOT_MTD_NAME);
            printf("MTD PARTS-0 MD5 CHECK           : FAIL\n");
            printf("MTD PARTS-1 MD5 CHECK           : FAIL\n");
            printf("U-BOOT MTD PART MD5 CHECK           : FAIL\n");
            return -1;
        }

        /*************************** Compare start **************************/
        if (fw_ubi_rootfs_volume_size != 0 && uboot_len != 0) {

            pFile = fopen("/tmp/flash_fwmd5_info.txt", "r");
            if (pFile == NULL) {
                printf( "File /tmp/flash_fwmd5_info.txt: Open Failed");
                return 1;
            }

            while(fgets(line, 128, pFile)) {
                if(strncmp(line, "FLASH ROOTFS1 FWMD5  :", strlen("FLASH ROOTFS1 FWMD5  :")) == 0) {
                    sscanf(line,
                           "FLASH ROOTFS1 FWMD5  : %02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                           &flsah_ubifs1_img_md5_digit[0], &flsah_ubifs1_img_md5_digit[1], &flsah_ubifs1_img_md5_digit[2],
                           &flsah_ubifs1_img_md5_digit[3],
                           &flsah_ubifs1_img_md5_digit[4], &flsah_ubifs1_img_md5_digit[5], &flsah_ubifs1_img_md5_digit[6],
                           &flsah_ubifs1_img_md5_digit[7],
                           &flsah_ubifs1_img_md5_digit[8], &flsah_ubifs1_img_md5_digit[9], &flsah_ubifs1_img_md5_digit[10],
                           &flsah_ubifs1_img_md5_digit[11],
                           &flsah_ubifs1_img_md5_digit[12], &flsah_ubifs1_img_md5_digit[13], &flsah_ubifs1_img_md5_digit[14],
                           &flsah_ubifs1_img_md5_digit[15]
                          );
#ifdef INSPECTION_DEBUG
                    printf("FLASH ROOTFS1 FWMD5  : ");
                    for(i = 0; i < 16; i++) {
                        printf("%02x", flsah_ubifs1_img_md5_digit[i]);
                    }
                    printf("\n");
#endif
                } else if(strncmp(line, "FLASH ROOTFS2 FWMD5  :", strlen("FLASH ROOTFS2 FWMD5  :")) == 0) {
                    sscanf(line,
                           "FLASH ROOTFS2 FWMD5  : %02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                           &flsah_ubifs2_img_md5_digit[0], &flsah_ubifs2_img_md5_digit[1], &flsah_ubifs2_img_md5_digit[2],
                           &flsah_ubifs2_img_md5_digit[3],
                           &flsah_ubifs2_img_md5_digit[4], &flsah_ubifs2_img_md5_digit[5], &flsah_ubifs2_img_md5_digit[6],
                           &flsah_ubifs2_img_md5_digit[7],
                           &flsah_ubifs2_img_md5_digit[8], &flsah_ubifs2_img_md5_digit[9], &flsah_ubifs2_img_md5_digit[10],
                           &flsah_ubifs2_img_md5_digit[11],
                           &flsah_ubifs2_img_md5_digit[12], &flsah_ubifs2_img_md5_digit[13], &flsah_ubifs2_img_md5_digit[14],
                           &flsah_ubifs2_img_md5_digit[15]
                          );
#ifdef INSPECTION_DEBUG
                    printf("FLASH ROOTFS2 FWMD5  : ");
                    for(i = 0; i < 16; i++) {
                        printf("%02x", flsah_ubifs2_img_md5_digit[i]);
                    }
                    printf("\n");
#endif
                } else if(strncmp(line, "FLASH U-BOOT FWMD5  :", strlen("FLASH U-BOOT FWMD5  :")) == 0) {
                    sscanf(line,
                           "FLASH U-BOOT FWMD5  : %02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                           &flash_uboot_md5_digit[0], &flash_uboot_md5_digit[1], &flash_uboot_md5_digit[2],
                           &flash_uboot_md5_digit[3],
                           &flash_uboot_md5_digit[4], &flash_uboot_md5_digit[5], &flash_uboot_md5_digit[6],
                           &flash_uboot_md5_digit[7],
                           &flash_uboot_md5_digit[8], &flash_uboot_md5_digit[9], &flash_uboot_md5_digit[10],
                           &flash_uboot_md5_digit[11],
                           &flash_uboot_md5_digit[12], &flash_uboot_md5_digit[13], &flash_uboot_md5_digit[14],
                           &flash_uboot_md5_digit[15]
                          );
#ifdef INSPECTION_DEBUG
                    printf("FLASH U-BOOT FWMD5  : ");
                    for(i = 0; i < 16; i++) {
                        printf("%02x", flash_uboot_md5_digit[i]);
                    }
                    printf("\n");
#endif
                }
            }
            fclose(pFile);

            //Compare Rootfs1
            for(i = 0; i < 16; i++) {
                if(flsah_ubikernel_3_md5_digit[i] != flsah_ubikernel_1_md5_digit[i]) {
                    firmware_md5_cmp_result |= 0x01;
                    printf("MTD PARTS-0 KERNEL MD5 CHECK    : FAIL\n");
                    break;
                }
            }
            for(i = 0; i < 16; i++) {
                if(flsah_ubifs3_img_md5_digit[i] != flsah_ubifs1_img_md5_digit[i]) {
                    firmware_md5_cmp_result |= 0x02;
                    printf("MTD PARTS-0 ROOTFS MD5 CHECK    : FAIL\n");
                    break;
                }
            }

            if((firmware_md5_cmp_result & 0x3) == 0x0) {
                printf("MTD PARTS-0 MD5 CHECK           : PASS\n");
            } else {
                printf("MTD PARTS-0 MD5 CHECK           : FAIL\n");
            }

            //Compare Rootfs2
            for(i = 0; i < 16; i++) {
                if(flsah_ubikernel_3_md5_digit[i] != flsah_ubikernel_2_md5_digit[i]) {
                    firmware_md5_cmp_result |= 0x10;
                    break;
                }
            }

            for(i = 0; i < 16; i++) {
                if(flsah_ubifs3_img_md5_digit[i] != flsah_ubifs2_img_md5_digit[i]) {
                    firmware_md5_cmp_result |= 0x20;
                    break;
                }
            }

            if((firmware_md5_cmp_result & 0x30) == 0) {
                printf("MTD PARTS-1 MD5 CHECK           : PASS\n");
            } else {
                printf("MTD PARTS-1 MD5 CHECK           : FAIL\n");
            }

            //Compare U-Boot
            for(i = 0; i < 16; i++) {
                if(fw_uboot_md5_digit[i] != flash_uboot_md5_digit[i]) {
                    firmware_md5_cmp_result |= 0x100;
                    printf("U-BOOT MTD PART MD5 CHECK           : FAIL\n");
                    break;
                }
            }
            if((firmware_md5_cmp_result & 0x100) == 0x0) {
                printf("U-BOOT MTD PART MD5 CHECK           : PASS\n");
            }

        } else {
            printf("MTD PARTS-0 MD5 CHECK           : NA (tftp fw format in-correct -support %s-Rev.ww.xx.yy_build-z.rom only)\n",
                   hwparam_device_name);
            printf("MTD PARTS-1 MD5 CHECK           : NA (tftp fw format in-correct -support %s-Rev.ww.xx.yy_build-z.rom only)\n",
                   hwparam_device_name);
            printf("U-BOOT MTD PART MD5 CHECK           : NA (tftp fw format in-correct -support %s-Rev.ww.xx.yy_build-z.rom only)\n",
                   hwparam_device_name);

        }

        return 0;

    }
}

static int cal_file_md5(char *file, int len, char md5_ret[15])
{
    int i = 0;
    uchar *rootfs_buf = NULL;

    if(file == NULL) {
        return -1;
    }
    rootfs_buf = malloc(sizeof(char) * (len));
    if(!rootfs_buf) {
        return -1;
    }

    memset(rootfs_buf, 0x0, sizeof(char) * (len));
    copy_file_to_buf(file, 0L, rootfs_buf, len);

    MD5( (unsigned char *)(rootfs_buf), len, md5_ret);

#ifdef INSPECTION_DEBUG
    printf("%s %d md5         : ", file, len);
    for(i = 0; i < 16; i++) {
        printf("%02x", md5_ret[i]);
    }
    printf("\n");
#endif
    if(rootfs_buf) {
        free(rootfs_buf);
    }
    return 0;
}

int dni_image_check(uchar *startAddr, u32 len)
{
    char localcmd[128];
    unsigned char product_string[16];
    const uchar *ram_header = (const char *)startAddr;
    const uchar *Uboot = "UbootSize:";
    const uchar  *Kernel = "KernelSize:";
    uchar FileCheckSum = 0;
    char runcmd[256];
    u32 start_blocks;
    u32 size_blocks;
    u32 image_len;
    u32 wlx_rootfs_img_len;
    u32 uboot_len ;
    char *ubootsize_ptr;
    unsigned int kernel_len ;
    unsigned int fw_ubi_kernel_volume_size;
    unsigned int fw_ubi_rootfs_volume_size;
    char *kernelsize_ptr;
    u32 rootfs_mtd_addr ;
    u32 rootfs_mtd_size ;
    u32 rootfs_backup_mtd_addr ;
    u32 rootfs_backup_mtd_size ;
    u32 uboot_mtd_addr ;
    u32 uboot_mtd_size ;
    u32 kernel_mtd_size ;
    uchar image_header[YAMAHA_Header_Len];
    char *rootfs_buf = NULL;
    uchar *uboot_buf = NULL;
    unsigned char fw_ubi_img_md5_digit[16];
    unsigned char flsah_ubikernel_1_md5_digit[16];
    unsigned char flsah_ubikernel_2_md5_digit[16];
    unsigned char flsah_ubikernel_3_md5_digit[16];
    unsigned char flsah_ubifs1_img_md5_digit[16];
    unsigned char flsah_ubifs2_img_md5_digit[16];
    unsigned char flsah_ubifs3_img_md5_digit[16];
    unsigned char fw_uboot_md5_digit[16];
    unsigned char flash_uboot_md5_digit[16];
    int firmware_md5_cmp_result = 0;

    //system("");

#ifdef INSPECTION_DEBUG
    printf("debug_dni_image_write : ENTER\n");
#endif
    image_len = len ;

#ifdef INSPECTION_DEBUG
    printf("debug_dni_image_write : image_len=%u\n", image_len);
#endif

    // image_decode(startAddr,destAddr,len); //Jacky.Xue: Already descrambal
    get_mtd_device_name_index(WLX_0_KERNEL_NAME, DEV_KERNEL_0_MTD_INDEX, 0);
    get_mtd_device_name_index(WLX_1_KERNEL_NAME, DEV_KERNEL_1_MTD_INDEX, 1);
    get_mtd_device_name_index(WLX_ROOTFS_0_DEFAULT_ROOTFS_NAME, DEV_ROOTFS_0_MTD_INDEX, 0);
    get_mtd_device_name_index(WLX_ROOTFS_1_DEFAULT_ROOTFS_NAME, DEV_ROOTFS_1_MTD_INDEX, 1);

    memcpy(product_string, header_device_name, strlen(header_device_name));
#ifdef INSPECTION_DEBUG
    printf("product_string: %s, device_name length: %s", product_string, header_device_name);
    printf("ram_header: %s", ram_header + 7);
#endif

    len = image_len ;

    if(memcmp(product_string, ram_header + 7, strlen(header_device_name)) == 0) {
        int i ;

        memcpy(image_header, ram_header, YAMAHA_Header_Len);

        for(i = 0 ; i < YAMAHA_Header_Len ; i++) {
            if(image_header[i] == 0) {
                image_header[i] = 0x30;
            }
        }

        ubootsize_ptr = (char *)(strstr(image_header ,	Uboot)) + 10;
        uboot_len = strtoul(ubootsize_ptr, NULL, 10);

        kernelsize_ptr = (char *)(strstr(image_header ,	Kernel)) + 11;
        kernel_len = strtoul(kernelsize_ptr, NULL, 10);




        /*GET U-BOOT MTD DEVICE NAME*/
        memset(DEV_UBOOT_MTD_NAME, '\0', sizeof(DEV_UBOOT_MTD_NAME));
        if(get_mtd_device_name(UBOOT_MTD_NAME, DEV_UBOOT_MTD_NAME) != NULL) {
#ifdef INSPECTION_DEBUG
            printf("Success get %s mtd device name - %s\n", UBOOT_MTD_NAME, DEV_UBOOT_MTD_NAME);
#endif
        } else {
            printf("%s MTD partition not found\n", UBOOT_MTD_NAME);
            printf("MTD PARTS-0 MD5 CHECK           : FAIL\n");
            printf("MTD PARTS-1 MD5 CHECK           : FAIL\n");
            printf("U-BOOT MTD PART MD5 CHECK           : FAIL\n");
            return -1;
        }

        uboot_mtd_size = getfilesize(DEV_UBOOT_MTD_NAME);
        wlx_rootfs_img_len = image_len - uboot_mtd_size - YAMAHA_Header_Len - 1;
        //copy_buf_to_file(WLX_FW_DESCRAMBLE_FILE,0,destination_buf,file_size);
#ifdef INSPECTION_DEBUG
        printf("image_len=%u\n", image_len);
        printf("uboot_mtd_size=%u\n", uboot_mtd_size);
        printf("uboot_len=%u\n", uboot_len);
        printf("kernel_len=%u\n", kernel_len);
        printf("YAMAHA_Header_Len=%u\n", YAMAHA_Header_Len);
        printf("wlx_rootfs_img_len=%u\n", wlx_rootfs_img_len);
#endif
        copy_buf_to_file(WLX_FW_DESCRAMBLE_UBI_ROOTFS_IMG_FILE, 0,
                         (unsigned char *) (startAddr + YAMAHA_Header_Len + uboot_mtd_size), wlx_rootfs_img_len);

#ifdef SUPPORT_NAND
        memset(localcmd, '\0', sizeof(localcmd));
        sprintf(localcmd, "cd /tmp;/usr/sbin/ubi-extractor -i %s > /dev/null 2>&1",
                WLX_FW_DESCRAMBLE_UBI_ROOTFS_IMG_FILE);
#ifdef INSPECTION_DEBUG
        printf("execute command :==> %s <== done !\n", localcmd);
#endif
        system(localcmd);

        memset(localcmd, "'\0'", sizeof(localcmd));
        sprintf(localcmd, "/tmp/%s", "kernel.bin");
#ifdef INSPECTION_DEBUG
        printf("ubi img kernel file name=%s\n", localcmd);
#endif
        fw_ubi_kernel_volume_size = filesize(localcmd);


        memset(localcmd, "'\0'", sizeof(localcmd));
        sprintf(localcmd, "/tmp/%s", "ubi_rootfs.bin");
#ifdef INSPECTION_DEBUG
        printf("ubi img rootfs file name=%s\n", localcmd);
#endif
        fw_ubi_rootfs_volume_size = filesize(localcmd);
#endif


        while(len--) {
            FileCheckSum = (FileCheckSum + (*ram_header)) & 0xFF;
            *ram_header++;
        }
        FileCheckSum = ~FileCheckSum;


        // do_remountallrootfs();

        if(FileCheckSum != 0) {
            printf("Image Checksum is Error\n");
            system("rm -fv *.bin /tmp/*.bin");
            return -1;
        } else {
#ifdef INSPECTION_DEBUG
            printf("%s Product Firmware rom Image Checksum is OK\n", hwparam_device_name);
#endif

            if (kernel_len != 0 && uboot_len != 0) {
#ifdef INSPECTION_DEBUG
                printf("Get DEV_UBOOT_MTD_NAME =%s\n", DEV_UBOOT_MTD_NAME);
#endif
                uboot_mtd_size = getfilesize(DEV_UBOOT_MTD_NAME);
                wlx_rootfs_img_len = image_len - uboot_mtd_size - YAMAHA_Header_Len - 1;
#ifdef INSPECTION_DEBUG
                printf("image_len=%u\n", image_len);
                printf("uboot_mtd_size=%u\n", uboot_mtd_size);
                printf("uboot_len=%u\n", uboot_len);
                printf("kernel_len=%u\n", kernel_len);
                printf("YAMAHA_Header_Len=%u\n", YAMAHA_Header_Len);
                printf("wlx_rootfs_img_len=%u\n", wlx_rootfs_img_len);
                printf("fw_ubi_kernel_volume_size=%u\n", fw_ubi_kernel_volume_size);
                printf("fw_ubi_rootfs_volume_size=%u\n", fw_ubi_rootfs_volume_size);

#endif


#ifdef INSPECTION_DEBUG
                rootfs_buf = malloc(sizeof(char) * (wlx_rootfs_img_len));
                //copy_file_to_buf(WLX_FW_DESCRAMBLE_FILE,YAMAHA_Header_Len+uboot_mtd_size,rootfs_buf,wlx_rootfs_img_len);
                memcpy(rootfs_buf, startAddr + YAMAHA_Header_Len + uboot_mtd_size, wlx_rootfs_img_len);
                MD5( rootfs_buf , wlx_rootfs_img_len, fw_ubi_img_md5_digit);
                if(rootfs_buf) {
                    free(rootfs_buf);
                }

                printf("UBI ROOTFS IMAGE MD5 IN FIRMWARE@1          : ");
                for(i = 0; i < 16; i++) {
                    printf("%02x", fw_ubi_img_md5_digit[i]);
                }
                printf("\n");
#endif

                MD5( (unsigned char *)(startAddr + YAMAHA_Header_Len + uboot_mtd_size), wlx_rootfs_img_len,
                     fw_ubi_img_md5_digit);
#ifdef INSPECTION_DEBUG
                printf("UBI ROOTFS IMAGE MD5 IN FIRMWARE@2          : ");
                for(i = 0; i < 16; i++) {
                    printf("%02x", fw_ubi_img_md5_digit[i]);
                }
                printf("\n");
#endif


                MD5((unsigned char *) (startAddr + YAMAHA_Header_Len), uboot_len, fw_uboot_md5_digit);
#ifdef INSPECTION_DEBUG
                printf("U-BOOT IMG MD5 IN FIRMWARE          : ");
                for(i = 0; i < 16; i++) {
                    printf("%02x", fw_uboot_md5_digit[i]);
                }
                printf("\n");
#endif

#ifdef SUPPORT_NAND
                snprintf(localcmd, sizeof(localcmd), "%s", DEV_KERNEL_0_MTD_INDEX);
                cal_file_md5(localcmd, fw_ubi_kernel_volume_size, flsah_ubikernel_1_md5_digit);

                snprintf(localcmd, sizeof(localcmd), "%s", DEV_KERNEL_1_MTD_INDEX);
                cal_file_md5(localcmd, fw_ubi_kernel_volume_size, flsah_ubikernel_2_md5_digit);

                snprintf(localcmd, sizeof(localcmd), "/tmp/%s", "kernel.bin");
                cal_file_md5(localcmd, fw_ubi_kernel_volume_size, flsah_ubikernel_3_md5_digit);

                snprintf(localcmd, sizeof(localcmd), "%s", DEV_ROOTFS_0_MTD_INDEX);
                cal_file_md5(localcmd, fw_ubi_rootfs_volume_size, flsah_ubifs1_img_md5_digit);
                snprintf(localcmd, sizeof(localcmd), "%s", DEV_ROOTFS_1_MTD_INDEX);
                cal_file_md5(localcmd, fw_ubi_rootfs_volume_size, flsah_ubifs2_img_md5_digit);
                snprintf(localcmd, sizeof(localcmd), "/tmp/%s", "ubi_rootfs.bin");
                cal_file_md5(localcmd, fw_ubi_rootfs_volume_size, flsah_ubifs3_img_md5_digit);

#else //SUPPORT_NAND
                get_mtd_device_name_index(ROOTFS_0_MTD_NAME, DEV_ROOTFS_0_MTD_INDEX, 0);
                get_mtd_device_name_index(ROOTFS_1_MTD_NAME, DEV_ROOTFS_1_MTD_INDEX, 0);
                snprintf(localcmd, sizeof(localcmd), "%s", DEV_ROOTFS_0_MTD_INDEX);
                cal_file_md5(localcmd, wlx_rootfs_img_len, flsah_ubifs1_img_md5_digit);
                snprintf(localcmd, sizeof(localcmd), "%s", DEV_ROOTFS_1_MTD_INDEX);
                cal_file_md5(localcmd, wlx_rootfs_img_len, flsah_ubifs2_img_md5_digit);
                snprintf(localcmd, sizeof(localcmd), "%s", WLX_FW_DESCRAMBLE_UBI_ROOTFS_IMG_FILE);
                cal_file_md5(localcmd, wlx_rootfs_img_len, flsah_ubifs3_img_md5_digit);

#endif //SUPPORT_NAND

                /*CHECK U-BOOT MTD*/
                snprintf(localcmd, sizeof(localcmd), "%s", DEV_UBOOT_MTD_NAME);
                cal_file_md5(localcmd, uboot_len, flash_uboot_md5_digit);

                /*************************** Compare start **************************/
#ifdef SUPPORT_NAND
                for(i = 0; i < 16; i++) {
                    if(flsah_ubikernel_3_md5_digit[i] != flsah_ubikernel_1_md5_digit[i]) {
                        firmware_md5_cmp_result |= 0x01;
                        break;
                    }
                }
#endif
                for(i = 0; i < 16; i++) {
                    if(flsah_ubifs3_img_md5_digit[i] != flsah_ubifs1_img_md5_digit[i]) {
                        firmware_md5_cmp_result |= 0x02;
                        break;
                    }
                }

                if((firmware_md5_cmp_result & 0x3) == 0x0) {
                    printf("MTD PARTS-0 MD5 CHECK           : PASS\n");
                } else {
                    printf("MTD PARTS-0 MD5 CHECK           : FAIL\n");
                }

#ifdef SUPPORT_NAND
                for(i = 0; i < 16; i++) {
                    if(flsah_ubikernel_3_md5_digit[i] != flsah_ubikernel_2_md5_digit[i]) {
                        firmware_md5_cmp_result |= 0x10;
                        break;
                    }
                }
#endif

                for(i = 0; i < 16; i++) {
                    if(flsah_ubifs3_img_md5_digit[i] != flsah_ubifs2_img_md5_digit[i]) {
                        firmware_md5_cmp_result |= 0x20;
                        break;
                    }
                }

                if((firmware_md5_cmp_result & 0x30) == 0) {
                    printf("MTD PARTS-1 MD5 CHECK           : PASS\n");
                } else {
                    printf("MTD PARTS-1 MD5 CHECK           : FAIL\n");
                }
                for(i = 0; i < 16; i++) {
                    if(fw_uboot_md5_digit[i] != flash_uboot_md5_digit[i]) {
                        firmware_md5_cmp_result |= 0x100;
                        printf("U-BOOT MTD PART MD5 CHECK           : FAIL\n");
                        break;
                    }
                }


                if((firmware_md5_cmp_result & 0x100) == 0x0) {
                    printf("U-BOOT MTD PART MD5 CHECK           : PASS\n");
                }

            } else {
                printf("MTD PARTS-0 MD5 CHECK           : NA (tftp fw format in-correct -support %s-Rev.ww.xx.yy_build-z.rom only)\n",
                       hwparam_device_name);
                printf("MTD PARTS-1 MD5 CHECK           : NA (tftp fw format in-correct -support %s-Rev.ww.xx.yy_build-z.rom only)\n",
                       hwparam_device_name);
                printf("U-BOOT MTD PART MD5 CHECK           : NA (tftp fw format in-correct -support %s-Rev.ww.xx.yy_build-z.rom only)\n",
                       hwparam_device_name);
            }


        }
    } else {

        //Sprintf("Image format is not good.\n");
        printf("MTD PARTS-0 MD5 CHECK           : NA (tftp fw checksum error)\n");
        printf("MTD PARTS-1 MD5 CHECK           : NA (tftp fw checksum error)\n");
        printf("U-BOOT MTD PART MD5 CHECK           : NA (tftp fw checksum error)\n");



        system("rm -fv *.bin /tmp/*.bin");

        return -1 ;
    }

    system("rm -fv *.bin /tmp/*.bin");


    return 0;
}

static void usage_flash_fwmd5()
{
    printf("get rootfs1/rootfs2/uboot firmware md5 from flash \n");
    printf("read - \n");
    printf("Usage: %s -r %s [server ip]\n", __progname, RD_CMD_FLASH_FWMD5);
    printf("[server ip ] : Remote tftp server ip\n");
    printf("The MD5 results read from flash will be restored to /tmp/flash_fwmd5_info.txt \n");

    printf("For instance: %s -r %s \n", __progname, RD_CMD_FLASH_FWMD5);
    printf("For instance: %s -r %s 192.168.1.88\n", __progname, RD_CMD_FLASH_FWMD5);
}

static void usage_firmware_md5()
{
    printf("Generate/Compare wlxmd5info.txt/firmware from firmware/on flash \n");
    printf("check -\n");
    printf("Usage: %s -c %s [image name] [server ip] \n", __progname, UG_CMD_FIRMWAREMD5);
    printf("[image name] : YAMAHA firmware name - example : %s-Rev.22.00.00_build-10.rom \n",
           hwparam_device_name);
    printf("[server ip ] : Remote tftp server ip\n");


    printf("Generate wlxmd5info.txt to remote tftp server root diectory -\n");
    printf("Usage: %s -r %s [image name]\n", __progname, UG_CMD_FIRMWAREMD5);
    printf("Usage: %s -r %s [image name] [server ip]\n", __progname, UG_CMD_FIRMWAREMD5);
    printf("[image name] : YAMAHA firmware name - example : %s-Rev.22.00.00_build-10.rom \n",
           hwparam_device_name);
    printf("[server ip ] : Remote tftp server ip\n");

    printf("For instance: %s -r %s %s-Rev.22.00.00_build-9.rom\n", __progname, UG_CMD_FIRMWAREMD5,
           hwparam_device_name);
    printf("For instance: %s -r %s %s-Rev.22.00.00_build-10.rom\n", __progname, UG_CMD_FIRMWAREMD5,
           hwparam_device_name);
    printf("For instance: %s -c %s \n", __progname, UG_CMD_FIRMWAREMD5);



}

static void usage_firmware()
{
    printf("Check/Upgrade firmware on flash\n");
    printf("check - (Slow compare, but not required wlxmd5info.txt to comapre)\n");
    printf("Usage: %s -c %s\n", __progname, UG_CMD_BOOTLOADER);
    printf("Usage: %s -c %s [image name] [server ip] \n", __progname, UG_CMD_FIRMWARE);
    printf("[image name] : YAMAHA firmware name - example : %s-Rev.22.00.00_build-10.rom \n",
           hwparam_device_name);
    printf("[server ip ] : Remote tftp server ip\n");


    printf("update -\n");
    printf("Usage: %s -u %s [image name]\n", __progname, UG_CMD_FIRMWARE);
    printf("Usage: %s -u %s [image name] [server ip]\n", __progname, UG_CMD_FIRMWARE);
    printf("[image name] : YAMAHA firmware name - example : %s-Rev.22.00.00_build-10.rom \n",
           hwparam_device_name);
    printf("[server ip ] : Remote tftp server ip\n");

    printf("For instance: %s -u %s %s-Rev.22.00.00_build-10.rom\n", __progname, UG_CMD_FIRMWARE,
           hwparam_device_name);
    printf("For instance: %s -c %s %s-Rev.22.00.00_build-10.rom\n", __progname, UG_CMD_FIRMWARE,
           hwparam_device_name);


}

#define UPDATE_ID_KERNEL 0
#define UPDATE_ID_ROOTFS0 1
#define UPDATE_ID_ROOTFS1 2
#define UPDATE_ID_ALL 3

int do_firmware_update(int argc, char *argv[])
{
    FILE *fp = NULL;
    char remote_frimware_image_name[256];
    char tftp_server_ip[256];
    int  loader_on_flash_checksum = 0;
    int  loader_remote_checksum = 0;
    char localcmd[128];
    u32  file_size = 0;
    unsigned int rootfs_size = 0;
    //dni_img_header_t dni_hd;
    static int i, update_id, keepconfig;
    u32 *source_buf = NULL;
    u32 *destination_buf = NULL;
    char *pWlx402_Fw_Header = NULL;
    unsigned char md5_digit[16];
    char *kernel_buf = NULL;
    char *rootfs_buf = NULL;

#ifdef INSPECTION_DEBUG
    printf("################## argc =%d ##################\n", argc);
    for(i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
#endif

    if(argc > 7 || argc < 4) {
        usage_firmware();
        return;
    }
    if(argc == 4) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, tftp_server_ip_address);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&tftp_server_ip_address[0];
        update_id = UPDATE_ID_ALL;
        keepconfig = 1;
    } else if(argc == 5) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        update_id = UPDATE_ID_ALL;
        keepconfig = 1;
    } else if(argc == 6) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        sscanf(argv[5], "%d", &update_id);
        if((update_id < 0) || (update_id > 3)) {
            usage_firmware();
            return;
        }
        keepconfig = 1;
    } else if(argc == 7) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        sscanf(argv[5], "%d", &update_id);
        sscanf(argv[6], "%d", &keepconfig);
        if((update_id < 0) || (update_id > 3)) {
            usage_firmware();
            return;
        }

        if((keepconfig < 0) || (keepconfig > 1)) {
            usage_firmware();
            return;
        }

    }
#ifdef INSPECTION_DEBUG
    printf("remote_frimware_image_name=%s\n", remote_frimware_image_name);
    printf("tftp_server_ip=%s\n", tftp_server_ip);
    printf("update_id=%d\n", update_id);
    printf("keepconfig=%d\n", keepconfig);
#endif


    if(strlen(remote_frimware_image_name) == 0) {
        printf("update firmware fail .. no specify image name\n");
        printf("UPDATE FW Only          : FAIL(1)\n");
        return -1;
    }
    if(strlen(tftp_server_ip) == 0) {
        printf("update firmware fail .. no specify tftp_server_ip\n");
        printf("UPDATE FW Only          : FAIL(2)\n");
        return -2;
    }

#ifdef INSPECTION_DEBUG
    printf("remote_frimware_image_name=%s tftp_server_ip=%s tftp_server_ip_address=%s \n",
           remote_frimware_image_name, tftp_server_ip, tftp_server_ip_address);
#endif


    memset(localcmd, '\0', sizeof(localcmd));
    sprintf(localcmd, "cd /tmp;/usr/bin/tftp -g %s -r %s -l %s -b %d", tftp_server_ip,
            remote_frimware_image_name, TMP_FW_IMAGE_FILE_NAME, TFTP_DEFAULT_BLOCK_SIZE);
    system(localcmd);

    /*parse dni image header */
    file_size = getfilesize(TMP_FW_IMAGE_FILE_NAME);
#ifdef INSPECTION_DEBUG
    printf ("IMAGE SIZE=%u\n", file_size);
#endif

    source_buf = malloc(sizeof(uchar) * (file_size));
    if(!source_buf) {
        printf("alocate memory for scramble source buffer fail\n");
        return -1;
    }
#ifdef INSPECTION_DEBUG
    printf("Allocate source buffer size=%u successfully\n", (sizeof(uchar) * (file_size)));
#endif
    copy_file_to_buf(TMP_FW_IMAGE_FILE_NAME, 0L, source_buf, file_size);
    unlink(TMP_FW_IMAGE_FILE_NAME); // for free mem

    destination_buf = malloc(sizeof(uchar) * (file_size));
    if(!destination_buf) {
        printf("alocate memory for scramble destination buffer fail\n");
        return -1;
    }
#ifdef INSPECTION_DEBUG
    printf("Allocate dest buffer size=%u successfully\n", (sizeof(uchar) * (file_size)));
#endif

    if(descramble_yamaha_firmware(source_buf, destination_buf, file_size) != 0) {
        if(source_buf) {
            free(source_buf);
        }
        if(destination_buf) {
            free(destination_buf);
        }
        printf("Descramble firmware fail\n");
        return -1;
    }

    if(source_buf) {
        free(source_buf);
    }
    dni_image_write( destination_buf, file_size); /*Jacky.Xue : Porting from u-boot*/
    //do_remountallrootfs();
    if(destination_buf) {
        free(destination_buf);
    }
}

/*Get wlx firmware kernel,rootfs image lngth and md5 info - */
int do_firmware_md5info(int argc, char *argv[])
{
    FILE *fp = NULL;
    char remote_frimware_image_name[256];
    char tftp_server_ip[256];
    int  loader_on_flash_checksum = 0;
    int  loader_remote_checksum = 0;
    char localcmd[128];
    u32  file_size = 0;
    unsigned int rootfs_size = 0;
    //dni_img_header_t dni_hd;
    static int i, update_id, keepconfig;
    u32 *source_buf = NULL;
    u32 *destination_buf = NULL;
    char *pWlx402_Fw_Header = NULL;
    unsigned char md5_digit[16];
    char *kernel_buf = NULL;
    char *rootfs_buf = NULL;

#ifdef INSPECTION_DEBUG
    printf("################## argc =%d ##################\n", argc);
    for(i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
#endif

    if(argc > 7 || argc < 4) {
        usage_firmware_md5();
        return;
    }
    if(argc == 4) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, tftp_server_ip_address);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&tftp_server_ip_address[0];
        update_id = UPDATE_ID_ALL;
        keepconfig = 1;
    } else if(argc == 5) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        update_id = UPDATE_ID_ALL;
        keepconfig = 1;
    } else if(argc == 6) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        sscanf(argv[5], "%d", &update_id);
        if((update_id < 0) || (update_id > 3)) {
            usage_firmware_md5();
            return;
        }
        keepconfig = 1;
    } else if(argc == 7) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        sscanf(argv[5], "%d", &update_id);
        sscanf(argv[6], "%d", &keepconfig);
        if((update_id < 0) || (update_id > 3)) {
            usage_firmware_md5();
            return;
        }

        if((keepconfig < 0) || (keepconfig > 1)) {
            usage_firmware_md5();
            return;
        }

    }
#ifdef INSPECTION_DEBUG
    printf("remote_frimware_image_name=%s\n", remote_frimware_image_name);
    printf("tftp_server_ip=%s\n", tftp_server_ip);
    printf("update_id=%d\n", update_id);
    printf("keepconfig=%d\n", keepconfig);
#endif


    if(strlen(remote_frimware_image_name) == 0) {
        printf("update firmware fail .. no specify image name\n");
        printf("UPDATE FW Only          : FAIL(1)\n");
        return -1;
    }
    if(strlen(tftp_server_ip) == 0) {
        printf("update firmware fail .. no specify tftp_server_ip\n");
        printf("UPDATE FW Only          : FAIL(2)\n");
        return -2;
    }

#ifdef INSPECTION_DEBUG
    printf("remote_frimware_image_name=%s tftp_server_ip=%s tftp_server_ip_address=%s \n",
           remote_frimware_image_name, tftp_server_ip, tftp_server_ip_address);
#endif

    printf("\nPlease wait for generate firmware md5 file - %smd5info.txt ...\n", hwparam_device_name);
    memset(localcmd, '\0', sizeof(localcmd));
    sprintf(localcmd, "cd /tmp;/usr/bin/tftp -g %s -r %s -l %s -b %d > /dev/null  2>&1 ;",
            tftp_server_ip, remote_frimware_image_name, TMP_FW_IMAGE_FILE_NAME, TFTP_DEFAULT_BLOCK_SIZE);
    system(localcmd);

    /*parse dni image header */
    file_size = getfilesize(TMP_FW_IMAGE_FILE_NAME);
#ifdef INSPECTION_DEBUG
    printf ("IMAGE SIZE=%u\n", file_size);
#endif

    source_buf = malloc(sizeof(uchar) * (file_size));
    if(!source_buf) {
        printf("alocate memory for scramble source buffer fail\n");
        return -1;
    }
#ifdef INSPECTION_DEBUG
    printf("Allocate source buffer size=%u successfully\n", (sizeof(uchar) * (file_size)));
#endif
    copy_file_to_buf(TMP_FW_IMAGE_FILE_NAME, 0L, source_buf, file_size);
    unlink(TMP_FW_IMAGE_FILE_NAME);

    destination_buf = malloc(sizeof(uchar) * (file_size));
    if(!destination_buf) {
        printf("alocate memory for scramble destination buffer fail\n");
        return -1;
    }
#ifdef INSPECTION_DEBUG
    printf("Allocate dest buffer size=%u successfully\n", (sizeof(uchar) * (file_size)));
#endif

    if(descramble_yamaha_firmware(source_buf, destination_buf, file_size) != 0) {
        if(source_buf) {
            free(source_buf);
        }
        if(destination_buf) {
            free(destination_buf);
        }
        printf("Descramble firmware fail\n");
        return -1;
    }
    if(source_buf) {
        free(source_buf);
    }

    //copy_buf_to_file(WLX_FW_DESCRAMBLE_FILE,0,destination_buf,file_size); /*For Debug*/
    //dni_image_write_simulate_rootfs_only(destination_buf,file_size);
    dni_image_md5_get( destination_buf, file_size); /*Jacky.Xue : Porting from u-boot*/
    if(destination_buf) {
        free(destination_buf);
    }
}

int do_firmware_md5_check(int argc, char *argv[])
{
    FILE *fp = NULL;
    char remote_frimware_image_name[256] = {0};
    char tftp_server_ip[256] = {0};
    int  loader_on_flash_checksum = 0;
    int  loader_remote_checksum = 0;
    char localcmd[128];
    u32  file_size = 0;
    unsigned int rootfs_size = 0;
    //dni_img_header_t dni_hd;
    static int i, update_id, keepconfig;
    u32 *source_buf = NULL;
    u32 *destination_buf = NULL;
    char *pWlx402_Fw_Header = NULL;
    unsigned char md5_digit[16];
    char *kernel_buf = NULL;
    char *rootfs_buf = NULL;
    int read_flash = 0;

#ifdef INSPECTION_DEBUG
    printf("################## argc =%d ##################\n", argc);
    for(i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
#endif

    if( (argc != 3) &&  (argc != 4)) {
        usage_firmware_md5();
        return -2;
    }
    if(argc == 3) {
        snprintf(remote_frimware_image_name, sizeof(remote_frimware_image_name), "%smd5info.txt",
                 hwparam_device_name);
        strcpy(tftp_server_ip, tftp_server_ip_address);
        update_id = UPDATE_ID_ALL;
        keepconfig = 1;

        if (strcmp(argv[2], UG_CMD_FIRMWAREMD5) == 0) {
            read_flash = 0;
        } else if (strcmp(argv[2], RD_CMD_FLASH_FWMD5) == 0) {
            read_flash = 1;
        }
    } else if(argc == 4) {
        snprintf(remote_frimware_image_name, sizeof(remote_frimware_image_name), "%smd5info.txt",
                 hwparam_device_name);
        strcpy(tftp_server_ip, argv[3]);
        update_id = UPDATE_ID_ALL;
        keepconfig = 1;
        if (strcmp(argv[2], UG_CMD_FIRMWAREMD5) == 0) {
            read_flash = 0;
        } else if (strcmp(argv[2], RD_CMD_FLASH_FWMD5) == 0) {
            read_flash = 1;
        }
    }

#ifdef INSPECTION_DEBUG
    printf("remote_frimware_image_name=%s\n", remote_frimware_image_name);
    printf("tftp_server_ip=%s\n", tftp_server_ip);
    printf("update_id=%d\n", update_id);
    printf("keepconfig=%d\n", keepconfig);
#endif


    if(strlen(remote_frimware_image_name) == 0) {
        printf("update firmware fail .. no specify image name\n");
        printf("UPDATE FW Only          : FAIL(1)\n");
        return -1;
    }
    if(strlen(tftp_server_ip) == 0) {
        printf("update firmware fail .. no specify tftp_server_ip\n");
        printf("UPDATE FW Only          : FAIL(2)\n");
        return -2;
    }

#ifdef INSPECTION_DEBUG
    printf("remote_frimware_image_name=%s tftp_server_ip=%s tftp_server_ip_address=%s \n",
           remote_frimware_image_name, tftp_server_ip, tftp_server_ip_address);
#endif


    memset(localcmd, '\0', sizeof(localcmd));
    sprintf(localcmd,
            "cd /tmp;/usr/bin/tftp -g %s -r %s -l /tmp/%smd5info.txt -b %d > /dev/null  2>&1;",
            tftp_server_ip, remote_frimware_image_name, hwparam_device_name, TFTP_DEFAULT_BLOCK_SIZE);
    system(localcmd);

    /*parse dni image header */
    memset(localcmd, '\0', sizeof(localcmd));
    snprintf(localcmd, sizeof(localcmd), "/tmp/%smd5info.txt", hwparam_device_name);
    file_size = getfilesize(localcmd);
#ifdef INSPECTION_DEBUG
    printf("Get file_size of %s = %d\n", localcmd, file_size);
#endif
    if(!file_size) {
        printf("\n----------------------------------------------------------------------------------\n");
        printf("        Please Prepare %smd5info.txt on remote tftp servr root path First !                  \n",
               hwparam_device_name);
        printf("        example:                                              \n");
        printf("                  diag -r fwmd5 %s-Rev.22.00.00_build-10.rom                  \n",
               hwparam_device_name);
        printf("----------------------------------------------------------------------------------\n");
        return -1;

    }

#ifdef INSPECTION_DEBUG
    printf ("IMAGE SIZE=%u\n", file_size);
#endif
    printf("Check firmware in flash ...\n");

    dni_image_md5_check(read_flash); /*Jacky.Xue : Porting from u-boot*/
}


int do_firmware_check(int argc, char *argv[])
{
    FILE *fp = NULL;
    char remote_frimware_image_name[256];
    char tftp_server_ip[256];
    int  loader_on_flash_checksum = 0;
    int  loader_remote_checksum = 0;
    char localcmd[128];
    u32  file_size = 0;
    unsigned int rootfs_size = 0;
    //dni_img_header_t dni_hd;
    static int i, update_id, keepconfig;
    u32 *source_buf = NULL;
    u32 *destination_buf = NULL;
    char *pWlx402_Fw_Header = NULL;
    unsigned char md5_digit[16];
    char *kernel_buf = NULL;
    char *rootfs_buf = NULL;

#ifdef INSPECTION_DEBUG
    printf("################## argc =%d ##################\n", argc);
    for(i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
#endif

    if(argc > 7 || argc < 4) {
        usage_firmware();
        return;
    }
    if(argc == 4) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, tftp_server_ip_address);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&tftp_server_ip_address[0];
        update_id = UPDATE_ID_ALL;
        keepconfig = 1;
    } else if(argc == 5) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        update_id = UPDATE_ID_ALL;
        keepconfig = 1;
    } else if(argc == 6) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        sscanf(argv[5], "%d", &update_id);
        if((update_id < 0) || (update_id > 3)) {
            usage_firmware();
            return;
        }
        keepconfig = 1;
    } else if(argc == 7) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        sscanf(argv[5], "%d", &update_id);
        sscanf(argv[6], "%d", &keepconfig);
        if((update_id < 0) || (update_id > 3)) {
            usage_firmware();
            return;
        }

        if((keepconfig < 0) || (keepconfig > 1)) {
            usage_firmware();
            return;
        }

    }
#ifdef INSPECTION_DEBUG
    printf("remote_frimware_image_name=%s\n", remote_frimware_image_name);
    printf("tftp_server_ip=%s\n", tftp_server_ip);
    printf("update_id=%d\n", update_id);
    printf("keepconfig=%d\n", keepconfig);
#endif


    if(strlen(remote_frimware_image_name) == 0) {
        printf("update firmware fail .. no specify image name\n");
        printf("UPDATE FW Only          : FAIL(1)\n");
        return -1;
    }
    if(strlen(tftp_server_ip) == 0) {
        printf("update firmware fail .. no specify tftp_server_ip\n");
        printf("UPDATE FW Only          : FAIL(2)\n");
        return -2;
    }

#ifdef INSPECTION_DEBUG
    printf("remote_frimware_image_name=%s tftp_server_ip=%s tftp_server_ip_address=%s \n",
           remote_frimware_image_name, tftp_server_ip, tftp_server_ip_address);
#endif


    memset(localcmd, '\0', sizeof(localcmd));
    sprintf(localcmd, "cd /tmp;/usr/bin/tftp -g %s -r %s -l %s -b %d", tftp_server_ip,
            remote_frimware_image_name, TMP_FW_IMAGE_FILE_NAME, TFTP_DEFAULT_BLOCK_SIZE);
    system(localcmd);

    /*parse dni image header */
    file_size = getfilesize(TMP_FW_IMAGE_FILE_NAME);
#ifdef INSPECTION_DEBUG
    printf ("IMAGE SIZE=%u\n", file_size);
#endif

    source_buf = malloc(sizeof(uchar) * (file_size));
    if(!source_buf) {
        printf("alocate memory for scramble source buffer fail\n");
        return -1;
    }
#ifdef INSPECTION_DEBUG
    printf("Allocate source buffer size=%u successfully\n", (sizeof(uchar) * (file_size)));
#endif

    copy_file_to_buf(TMP_FW_IMAGE_FILE_NAME, 0L, source_buf, file_size);
    unlink(TMP_FW_IMAGE_FILE_NAME);

    destination_buf = malloc(sizeof(uchar) * (file_size));
    if(!destination_buf) {
        printf("alocate memory for scramble destination buffer fail\n");
        return -1;
    }
#ifdef INSPECTION_DEBUG
    printf("Allocate dest buffer size=%u successfully\n", (sizeof(uchar) * (file_size)));
#endif

    if(descramble_yamaha_firmware(source_buf, destination_buf, file_size) != 0) {
        if(source_buf) {
            free(source_buf);
        }
        if(destination_buf) {
            free(destination_buf);
        }
        printf("Descramble firmware fail\n");
        return -1;
    }


    //copy_buf_to_file(WLX_FW_DESCRAMBLE_FILE,0,destination_buf,file_size); /*For Debug*/
    //dni_image_write_simulate_rootfs_only(destination_buf,file_size);

    if(source_buf) {
        free(source_buf);
    }
    dni_image_check( destination_buf, file_size); /*Jacky.Xue : Porting from u-boot*/

    if(destination_buf) {
        free(destination_buf);
    }


}



#define TMP_UBOOT_IMAGE_FILE_NAME "/tmp/_wlxxxx_uboot.mbn"

static void usage_bootloader()
{
    printf("Check/Upgrade bootloader on flash\n");

    printf("check -\n");
    printf("Usage: %s -c %s [image size]\n", __progname, UG_CMD_BOOTLOADER);
    printf("[image size]: specify loader size on flash in byte to be check\n");

    printf("write -\n");
    printf("Usage: %s -u %s [image name]\n", __progname, UG_CMD_BOOTLOADER);
    printf("Usage: %s -u %s [image name] [server ip]\n", __progname, UG_CMD_BOOTLOADER);

    printf("[image name]: remote bootloader image name on tftp server root\n");
    printf("[server ip]: tftp server ip address\n");

    printf("For instance: %s -u %s wgr450hp-uboot.bin \n", __progname, UG_CMD_BOOTLOADER);
    printf("For instance: %s -u %s wgr450hp-uboot.bin 192.168.123.123\n", __progname,
           UG_CMD_BOOTLOADER);
}




int do_loader_update_check(unsigned long checksum_size)
{
    FILE *fp = NULL;
    int loader_on_flash_checksum = 0;
    char localcmd[128];
    int file_size = 0;
#if 0
#ifdef INSPECTION_DEBUG
    printf("wanted checksum_size=%d\n", checksum_size);
#endif

    if(checksum_size != 0) {
        loader_on_flash_checksum = calcsum(DEV_LOADER_0_IMG, 0, checksum_size);
    } else {
        loader_on_flash_checksum = calcsum(DEV_LOADER_0_IMG, 0, 0);
    }

    printf("loader-0: checksum = 0x%02X, len = %d\n", loader_on_flash_checksum, checksum_size);
    //printf("On board bootloader0 checksum = 0x%02X, len = %d\n", loader_on_flash_checksum, checksum_size);


#ifdef SUPPORT_DUAL_U_BOOT
    if(checksum_size != 0) {
        loader_on_flash_checksum = calcsum(DEV_LOADER_1_IMG, 0, checksum_size);
    } else {
        loader_on_flash_checksum = calcsum(DEV_LOADER_1_IMG, 0, 0);
    }
    printf("loader-1: checksum = 0x%02X, len = %d\n", loader_on_flash_checksum, checksum_size);
#endif
    //printf("On board bootloader1 checksum = 0x%02X, len = %d\n", loader_on_flash_checksum, checksum_size);
#endif
}



int do_loader_update(int argc, char *argv[])
{
    FILE *fp = NULL;
    char remote_frimware_image_name[256];
    char tftp_server_ip[256];
    int  loader_on_flash_checksum = 0;
    int  loader_remote_checksum = 0;
    char localcmd[128];
    u32  file_size = 0;
    unsigned int rootfs_size = 0;
    //dni_img_header_t dni_hd;
    static int i, update_id, keepconfig;
    u32 *source_buf = NULL;
    u32 *destination_buf = NULL;
    char *pWlx402_Fw_Header = NULL;
    unsigned char md5_digit[16];
    char *kernel_buf = NULL;
    char *rootfs_buf = NULL;

#ifdef INSPECTION_DEBUG
    printf("################## argc =%d ##################\n", argc);
    for(i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
#endif

    if(argc > 7 || argc < 4) {
        usage_firmware();
        return;
    }
    if(argc == 4) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, tftp_server_ip_address);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&tftp_server_ip_address[0];
        update_id = UPDATE_ID_ALL;
        keepconfig = 1;
    } else if(argc == 5) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        update_id = UPDATE_ID_ALL;
        keepconfig = 1;
    } else if(argc == 6) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        sscanf(argv[5], "%d", &update_id);
        if((update_id < 0) || (update_id > 3)) {
            usage_firmware();
            return;
        }
        keepconfig = 1;
    } else if(argc == 7) {
        strcpy(remote_frimware_image_name, argv[3]);
        strcpy(tftp_server_ip, argv[4]);
        //remote_frimware_image_name=&argv[3];
        //tftp_server_ip=&argv[4];
        sscanf(argv[5], "%d", &update_id);
        sscanf(argv[6], "%d", &keepconfig);
        if((update_id < 0) || (update_id > 3)) {
            usage_firmware();
            return;
        }

        if((keepconfig < 0) || (keepconfig > 1)) {
            usage_firmware();
            return;
        }

    }
#ifdef INSPECTION_DEBUG
    printf("remote_frimware_image_name=%s\n", remote_frimware_image_name);
    printf("tftp_server_ip=%s\n", tftp_server_ip);
    printf("update_id=%d\n", update_id);
    printf("keepconfig=%d\n", keepconfig);
#endif


    if(strlen(remote_frimware_image_name) == 0) {
        printf("update firmware fail .. no specify image name\n");
        printf("UPDATE FW Only          : FAIL(1)\n");
        return -1;
    }
    if(strlen(tftp_server_ip) == 0) {
        printf("update firmware fail .. no specify tftp_server_ip\n");
        printf("UPDATE FW Only          : FAIL(2)\n");
        return -2;
    }

#ifdef INSPECTION_DEBUG
    printf("remote_frimware_image_name=%s tftp_server_ip=%s tftp_server_ip_address=%s \n",
           remote_frimware_image_name, tftp_server_ip, tftp_server_ip_address);
#endif


    memset(localcmd, '\0', sizeof(localcmd));
    sprintf(localcmd, "cd /tmp;/usr/bin/tftp -g %s -r %s -l %s -b %d", tftp_server_ip,
            remote_frimware_image_name, TMP_FW_IMAGE_FILE_NAME, TFTP_DEFAULT_BLOCK_SIZE);
    system(localcmd);

    /*parse dni image header */
    file_size = getfilesize(TMP_FW_IMAGE_FILE_NAME);
#ifdef INSPECTION_DEBUG
    printf ("IMAGE SIZE=%u\n", file_size);
#endif

    source_buf = malloc(sizeof(uchar) * (file_size));
    if(!source_buf) {
        printf("alocate memory for scramble source buffer fail\n");
        return -1;
    }
#ifdef INSPECTION_DEBUG
    printf("Allocate source buffer size=%u successfully\n", (sizeof(uchar) * (file_size)));
#endif
    copy_file_to_buf(TMP_FW_IMAGE_FILE_NAME, 0L, source_buf, file_size);
    unlink(TMP_FW_IMAGE_FILE_NAME);

    destination_buf = malloc(sizeof(uchar) * (file_size));
    if(!destination_buf) {
        printf("alocate memory for scramble destination buffer fail\n");
        return -1;
    }
#ifdef INSPECTION_DEBUG
    printf("Allocate dest buffer size=%u successfully\n", (sizeof(uchar) * (file_size)));
#endif

    if(descramble_yamaha_firmware(source_buf, destination_buf, file_size) != 0) {
        if(source_buf) {
            free(source_buf);
        }
        if(destination_buf) {
            free(destination_buf);
        }
        printf("Descramble firmware fail\n");
        return -1;
    }

    if(source_buf) {
        free(source_buf);
    }
    dni_image_write( destination_buf, file_size); /*Jacky.Xue : Porting from u-boot*/

    //do_remountallrootfs();
    if(destination_buf) {
        free(destination_buf);
    }
}



int xxxxdo_loader_update(char *remote_uboot_image_name, char *tftp_server_ip)
{
    FILE *fp = NULL;
    int loader_on_flash_checksum = 0;
    int loader_remote_checksum = 0;
    char localcmd[128];
    int file_size = 0;
#if 0
    if(!remote_uboot_image_name) {
        printf("update loader fail .. no specify image name\n");
        return -1;
    }
    if(!tftp_server_ip) {
        printf("update loader fail .. no specify tftp_server_ip\n");
        return -1;
    }
    memset(localcmd, '\0', sizeof(localcmd));
    sprintf(localcmd, "cd /tmp;/usr/bin/tftp -g %s -r %s -l %s -b %d", tftp_server_ip,
            remote_uboot_image_name, TMP_UBOOT_IMAGE_FILE_NAME, TFTP_DEFAULT_BLOCK_SIZE);
    system(localcmd);

    memset(localcmd, '\0', sizeof(localcmd));
    sprintf(localcmd, "mtd -e %s write %s %s", DEV_LOADER_0_IMG, TMP_UBOOT_IMAGE_FILE_NAME,
            DEV_LOADER_0_IMG);
    system(localcmd);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif

#ifdef SUPPORT_DUAL_U_BOOT
    memset(localcmd, '\0', sizeof(localcmd));
    sprintf(localcmd, "mtd -e %s write %s %s", DEV_LOADER_1_IMG, TMP_UBOOT_IMAGE_FILE_NAME,
            DEV_LOADER_1_IMG);
    system(localcmd);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif
#endif

    memset(localcmd, '\0', sizeof(localcmd));
    sprintf(localcmd, "cd /tmp;rm -rf %s", TMP_UBOOT_IMAGE_FILE_NAME);
    system(localcmd);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif

    memset(localcmd, '\0', sizeof(localcmd));
    sprintf(localcmd,
            "rm -rf /tmp/uboot_version;/etc/scan_bootcode_ver.sh;echo \"rescan uboot version done!\"");
    system(localcmd);
#ifdef INSPECTION_DEBUG
    printf("execute command :==> %s <== done !\n", localcmd);
#endif

#endif

}


/*******************************************************************************/
ulong get_mtd_erase_block_size(char *mtd_dev_name)
{
    mtd_info_t mtd_info;
    int fd = -1 ;
    if(!mtd_dev_name) {
        printf("write_mem_to_mtd : fail to open mtd device -%s\n", mtd_dev_name);
        return -1;
    }
    fd = open(mtd_dev_name, O_RDWR); // open the mtd device for reading and
    // writing. Note you want mtd0 not mtdblock0
    // also you probably need to open permissions
    // to the dev (sudo chmod 777 /dev/mtd0)
    if(ioctl(fd, MEMGETINFO, &mtd_info) < 0) {
        return  0;
    } else {
        return mtd_info.erasesize;
    }
}

//#define  INSPECTION_DEBUG 1
static int write_mem_to_mtd(char *mtd_dev_name, char *write_buffer, u32 write_size)
{
    mtd_info_t mtd_info;           // the MTD structure
    erase_info_t ei;               // the erase block structure
    char *new_alligned_data_buf = NULL;
    int i;
    u32 org_write_size;
    unsigned char not_alligned_data = 0;

    unsigned char data[20] = { 0xDE, 0xAD, 0xBE, 0xEF,  // our data to write
                               0xDE, 0xAD, 0xBE, 0xEF,
                               0xDE, 0xAD, 0xBE, 0xEF,
                               0xDE, 0xAD, 0xBE, 0xEF,
                               0xDE, 0xAD, 0xBE, 0xEF
                             };
    unsigned char read_buf[20] = {0x00};                // empty array for reading

    if(!mtd_dev_name) {
        printf("write_mem_to_mtd : fail to open mtd device -%s\n", mtd_dev_name);
        return -1;
    }
    if(!write_buffer) {
        printf("write_mem_to_mtd : NULL buffer pointer \n", write_buffer);
        return -2;
    }
    if(write_size <= 0) {
        printf("write_mem_to_mtd : wrong size to write\n", write_size);
        return -3;
    }
    int fd = open(mtd_dev_name, O_RDWR); // open the mtd device for reading and
    // writing. Note you want mtd0 not mtdblock0
    // also you probably need to open permissions
    // to the dev (sudo chmod 777 /dev/mtd0)

    ioctl(fd, MEMGETINFO, &mtd_info);   // get the device info

    // dump it for a sanity check, should match what's in /proc/mtd
#ifdef INSPECTION_DEBUG
    printf("MTD Type: 0x%x\nMTD total size: 0x%x bytes\nMTD erase size: 0x%x bytes\n",
           mtd_info.type, mtd_info.size, mtd_info.erasesize);
#endif

    ei.length = mtd_info.erasesize;   //set the erase block size

    /*20200417:Jacky.Xue : add page aligned data process to avoid nand: nand_do_write_ops: attempt to write non page aligned data*/
    org_write_size =  write_size;
#ifdef INSPECTION_DEBUG
    printf("Taget write_size=%u\n", write_size);
    //printf("Taget write_size=%d\n",write_size);
#endif
    if(write_size % mtd_info.erasesize != 0) {

        write_size = ((write_size / mtd_info.erasesize) + 1) * mtd_info.erasesize;
        printf("Buffer dat size not allignmnet,detect New write_size=%u\n", write_size);
        new_alligned_data_buf = malloc(sizeof(char) * (write_size));

        if(!new_alligned_data_buf) {
            printf("Allocate new write buffer fail\n");
            return -1;
        } else {
            printf("Allocate new write buffer size=%u successfully\n", write_size);
        }

        memcpy(new_alligned_data_buf, write_buffer, org_write_size);
        not_alligned_data = 1;

    }
    printf("Erase ...\n");
    for(ei.start = 0; ei.start < mtd_info.size /*Erase all mtd device*/; ei.start += ei.length) {
        ioctl(fd, MEMUNLOCK, &ei);
#ifdef INSPECTION_DEBUG
        printf("Eraseing Block %#x\n", ei.start); // show the blocks erasing
        // warning, this prints a lot!
#endif
        ioctl(fd, MEMERASE, &ei);
    }


#ifdef INSPECTION_DEBUG
    lseek(fd, 0, SEEK_SET);               // go to the first block
    read(fd, read_buf, sizeof(read_buf)); // read 20 bytes
    // sanity check, should be all 0xFF if erase worked
    for(i = 0; i < 20; i++) {
        printf("buf[%d] = 0x%02x\n", i, (unsigned int)read_buf[i]);
    }
#endif

#ifdef INSPECTION_DEBUG
    printf("MTD WRITE %s size - 0x%x Start!\n", mtd_dev_name, mtd_info.size);
#endif

    printf("Write ...\n");
    lseek(fd, 0, SEEK_SET);        // go back to first block's start
    if(not_alligned_data) {
        write(fd, new_alligned_data_buf, write_size);

        if(new_alligned_data_buf) {
            free(new_alligned_data_buf);
        }
    } else  {
        write(fd, write_buffer, write_size);
    }
#ifdef INSPECTION_DEBUG
    printf("MTD WRITE %s size - 0x%x Done!\n", mtd_dev_name, mtd_info.size);
#endif
    //write(fd, data, sizeof(data)); // write our message
    close(fd);

    printf("done!\n");



    return 0;
}


static int write_mem_to_mtd_force_size(char *mtd_dev_name, char *write_buffer, int write_size)
{
    mtd_info_t mtd_info;           // the MTD structure
    erase_info_t ei;               // the erase block structure
    int i;
    int remainder = 0;

    unsigned char data[20] = { 0xDE, 0xAD, 0xBE, 0xEF,  // our data to write
                               0xDE, 0xAD, 0xBE, 0xEF,
                               0xDE, 0xAD, 0xBE, 0xEF,
                               0xDE, 0xAD, 0xBE, 0xEF,
                               0xDE, 0xAD, 0xBE, 0xEF
                             };
    unsigned char read_buf[20] = {0x00};                // empty array for reading

    if(!mtd_dev_name) {
        printf("write_mem_to_mtd_force_size : fail to open mtd device -%s\n", mtd_dev_name);
        return -1;
    }
    if(!write_buffer) {
        printf("write_mem_to_mtd_force_size : NULL buffer pointer \n", write_buffer);
        return -2;
    }
    if(write_size <= 0) {
        printf("write_mem_to_mtd_force_size : wrong size to write\n", write_size);
        return -3;
    }
    int fd = open(mtd_dev_name, O_RDWR); // open the mtd device for reading and
    // writing. Note you want mtd0 not mtdblock0
    // also you probably need to open permissions
    // to the dev (sudo chmod 777 /dev/mtd0)

    ioctl(fd, MEMGETINFO, &mtd_info);   // get the device info

    // dump it for a sanity check, should match what's in /proc/mtd
#ifdef INSPECTION_DEBUG
    printf("MTD Type: 0x%x\nMTD total size: 0x%x bytes\nMTD erase size: 0x%x bytes\n",
           mtd_info.type, mtd_info.size, mtd_info.erasesize);
#endif

    ei.length = mtd_info.erasesize;   //set the erase block size


    remainder = mtd_info.size % write_size;
#ifdef INSPECTION_DEBUG
    printf("write_size =%x remainder=%d STROAGE_MTD_LENGTH=%x\n", write_size, remainder,
           STROAGE_MTD_LENGTH);
#endif

    if(remainder != 0) {
        write_size = mtd_info.size ;
    }
#ifdef INSPECTION_DEBUG
    printf("write&erase size =%x\n", write_size);
#endif

    for(ei.start = 0; ei.start < write_size/*mtd_info.size*/; ei.start += ei.length) {
        ioctl(fd, MEMUNLOCK, &ei);
        // printf("Eraseing Block %#x\n", ei.start); // show the blocks erasing
        // warning, this prints a lot!
        ioctl(fd, MEMERASE, &ei);
    }


#ifdef INSPECTION_DEBUG
    lseek(fd, 0, SEEK_SET);               // go to the first block
    read(fd, read_buf, sizeof(read_buf)); // read 20 bytes
    // sanity check, should be all 0xFF if erase worked
    for(i = 0; i < 20; i++) {
        printf("buf[%d] = 0x%02x\n", i, (unsigned int)read_buf[i]);
    }
#endif

#ifdef INSPECTION_DEBUG
    printf("MTD WRITE %s size - 0x%x Start!\n", mtd_dev_name, mtd_info.size);
#endif
    lseek(fd, 0, SEEK_SET);        // go back to first block's start
    write(fd, write_buffer, write_size);
#ifdef INSPECTION_DEBUG
    printf("MTD WRITE %s size - 0x%x Done!\n", mtd_dev_name, mtd_info.size);
#endif
    //write(fd, data, sizeof(data)); // write our message



    close(fd);
    return 0;
}


/*---------------------------------------- BDF SYNC TEST START ----------------------------------------*/


#define DIAG_FIRMWARE_BDWLAN_BIN           "/lib/firmware/IPQ8074/WIFI_FW/bdwlan.bin"
#define DIAG_FIRMWARE_BDWLAN_B215_BIN      "/lib/firmware/IPQ8074/WIFI_FW/bdwlan.b215"
#define ROOTFS1_BDWLAN_BIN          			 "/mnt/rootfs1/lib/firmware/IPQ8074/BDF/bdwlan.bin"
#define ROOTFS1_BDWLAN_B215_BIN     			 "/mnt/rootfs1/lib/firmware/IPQ8074/BDF/bdwlan.b215"
#define ROOTFS2_BDWLAN_BIN             		 "/mnt/rootfs2/lib/firmware/IPQ8074/BDF/bdwlan.bin"
#define ROOTFS2_BDWLAN_B215_BIN            "/mnt/rootfs2/lib/firmware/IPQ8074/BDF/bdwlan.b215"


static void usage_baf_synchronize_check(void)
{
    printf("Compare Product BDF in Product Frimware and Qualcomm BDF in WIFIFW partition if Synchronize or not \n");
    printf("Usage: %s -c %s\n", __progname, UG_CMD_BDF);
}

int do_bdf_md5_check(int argc, char *argv[])
{
    int file_size = -1, i;
    unsigned char diag_firmware_bdwlan_bin_md5_digit[16];
    unsigned char diag_firmware_bdwlan_b215_md5_digit[16];
    unsigned char rootfs1_bdwlan_bin_md5_digit[16];
    unsigned char rootfs1_bdwlan_b215_md5_digit[16];
    unsigned char rootfs2_bdwlan_bin_md5_digit[16];
    unsigned char rootfs2_bdwlan_b215_md5_digit[16];
    int product_firmware_rootfs1_md5_cmp_result = 0;
    int product_firmware_rootfs2_md5_cmp_result = 0;
    uchar *bdffile_buf = NULL;
    int debug = 0;

    if(argc == 4) {
        if(strncmp(argv[3], "-g", strlen("-g")) == 0) {
            printf("----------- enable debug mode -----------\n");
            debug = 1;
        }
    }



    file_size = filesize(ROOTFS1_BDWLAN_BIN);
#ifdef INSPECTION_DEBUG
    printf("ROOTFS1 BDWLAN.BIN size=%d\n", file_size);
#endif
    bdffile_buf = malloc(sizeof(char) * (file_size));
    copy_file_to_buf(ROOTFS1_BDWLAN_BIN, 0L, bdffile_buf, file_size);

    MD5( (unsigned char *)(bdffile_buf), file_size, rootfs1_bdwlan_bin_md5_digit);
    free(bdffile_buf);
#ifdef INSPECTION_DEBUG
    printf("BDF WLANBDF.BIN ON ROOTFS1 MD5                 : ");
    for(i = 0; i < 16; i++) {
        printf("%02x", rootfs1_bdwlan_bin_md5_digit[i]);
    }
    printf("\n");
#endif

    file_size = filesize(ROOTFS1_BDWLAN_B215_BIN);
#ifdef INSPECTION_DEBUG
    printf("ROOTFS1 BDWLAN.B215 size=%d\n", file_size);
#endif
    bdffile_buf = malloc(sizeof(char) * (file_size));
    copy_file_to_buf(ROOTFS1_BDWLAN_B215_BIN, 0L, bdffile_buf, file_size);

    MD5( (unsigned char *)(bdffile_buf), file_size, rootfs1_bdwlan_b215_md5_digit);
    free(bdffile_buf);
#ifdef INSPECTION_DEBUG
    printf("BDF WLANBDF.B215 ON ROOTFS1 MD5                : ");
    for(i = 0; i < 16; i++) {
        printf("%02x", rootfs1_bdwlan_b215_md5_digit[i]);
    }
    printf("\n");
#endif



    /*--------------------------- ROOTFS2 ------------------------------------------ */

    file_size = filesize(ROOTFS2_BDWLAN_BIN);
#ifdef INSPECTION_DEBUG
    printf("ROOTFS2 BDWLAN.BIN size=%d\n", file_size);
#endif
    bdffile_buf = malloc(sizeof(char) * (file_size));
    copy_file_to_buf(ROOTFS2_BDWLAN_BIN, 0L, bdffile_buf, file_size);

    MD5( (unsigned char *)(bdffile_buf), file_size, rootfs2_bdwlan_bin_md5_digit);
    free(bdffile_buf);
#ifdef INSPECTION_DEBUG
    printf("BDF WLANBDF.BIN ON ROOTFS2 MD5                 : ");
    for(i = 0; i < 16; i++) {
        printf("%02x", rootfs2_bdwlan_bin_md5_digit[i]);
    }
    printf("\n");
#endif



    file_size = filesize(ROOTFS2_BDWLAN_B215_BIN);
#ifdef INSPECTION_DEBUG
    printf("ROOTFS2 BDWLAN.B215 size=%d\n", file_size);
#endif
    bdffile_buf = malloc(sizeof(char) * (file_size));
    copy_file_to_buf(ROOTFS2_BDWLAN_B215_BIN, 0L, bdffile_buf, file_size);

    MD5( (unsigned char *)(bdffile_buf), file_size, rootfs2_bdwlan_b215_md5_digit);
    free(bdffile_buf);
#ifdef INSPECTION_DEBUG
    printf("BDF WLANBDF.B215 ON ROOTFS2 MD5                : ");
    for(i = 0; i < 16; i++) {
        printf("%02x", rootfs2_bdwlan_b215_md5_digit[i]);
    }
    printf("\n");
#endif


    /*---------------------------  Diag Firmware ------------------------------------------ */

    file_size = filesize(DIAG_FIRMWARE_BDWLAN_BIN);
#ifdef INSPECTION_DEBUG
    printf("DIAG FW BDWLAN.BIN size=%d\n", file_size);
#endif
    bdffile_buf = malloc(sizeof(char) * (file_size));
    copy_file_to_buf(DIAG_FIRMWARE_BDWLAN_BIN, 0L, bdffile_buf, file_size);

    MD5( (unsigned char *)(bdffile_buf), file_size, diag_firmware_bdwlan_bin_md5_digit);
    free(bdffile_buf);
#ifdef INSPECTION_DEBUG
    printf("BDF WLANBDF.BIN ON DIAGFW RETRIVE MD5          : ");
    for(i = 0; i < 16; i++) {
        printf("%02x", diag_firmware_bdwlan_bin_md5_digit[i]);
    }
    printf("\n");
#endif



    file_size = filesize(DIAG_FIRMWARE_BDWLAN_B215_BIN);
#ifdef INSPECTION_DEBUG
    printf("ROOTFS2 BDWLAN.B215 size=%d\n", file_size);
#endif
    bdffile_buf = malloc(sizeof(char) * (file_size));
    copy_file_to_buf(DIAG_FIRMWARE_BDWLAN_B215_BIN, 0L, bdffile_buf, file_size);

    MD5( (unsigned char *)(bdffile_buf), file_size, diag_firmware_bdwlan_b215_md5_digit);
    free(bdffile_buf);
#ifdef INSPECTION_DEBUG
    printf("BDF WLANBDF.B215 ON DIAGFW RETRIVE MD5         : ");
    for(i = 0; i < 16; i++) {
        printf("%02x", diag_firmware_bdwlan_b215_md5_digit[i]);
    }
    printf("\n");
#endif


    for(i = 0; i < 16; i++) {
        if(diag_firmware_bdwlan_bin_md5_digit[i] != rootfs1_bdwlan_bin_md5_digit[i]) {
            product_firmware_rootfs1_md5_cmp_result |= 0x1;
            break;
        }
    }
    for(i = 0; i < 16; i++) {
        if(diag_firmware_bdwlan_b215_md5_digit[i] != rootfs1_bdwlan_b215_md5_digit[i]) {
            product_firmware_rootfs1_md5_cmp_result |= 0x2;
            break;
        }
    }


    for(i = 0; i < 16; i++) {
        if(diag_firmware_bdwlan_bin_md5_digit[i] != rootfs2_bdwlan_bin_md5_digit[i]) {
            product_firmware_rootfs2_md5_cmp_result |= 0x1;
            break;
        }
    }
    for(i = 0; i < 16; i++) {
        if(diag_firmware_bdwlan_b215_md5_digit[i] != rootfs2_bdwlan_b215_md5_digit[i]) {
            product_firmware_rootfs2_md5_cmp_result |= 0x2;
            break;
        }
    }


    if(product_firmware_rootfs1_md5_cmp_result == 0) {
        printf("PRODUCT FW ROOTFS1 BDF  : PASS\n");
    } else {
        printf("PRODUCT FW ROOTFS1 BDF  : FAIL\n");
    }

    if(product_firmware_rootfs2_md5_cmp_result == 0) {
        printf("PRODUCT FW ROOTFS2 BDF  : PASS\n");
    } else {
        printf("PRODUCT FW ROOTFS2 BDF  : FAIL\n");
    }

    if(debug) {
        if((product_firmware_rootfs1_md5_cmp_result == 0)
           && (product_firmware_rootfs2_md5_cmp_result == 0) ) {
            printf("DIAGFW BDWLAN.BIN MD5   : ");
            for(i = 0; i < 16; i++) {
                printf("%02x", diag_firmware_bdwlan_bin_md5_digit[i]);
            }
            printf("\n");
            printf("DIAGFW BDWLAN.B215 MD5  : ");;
            for(i = 0; i < 16; i++) {
                printf("%02x", diag_firmware_bdwlan_b215_md5_digit[i]);
            }
            printf("\n");
        }

        else {

            printf("BDWLAN.BIN ROOTFS1 MD5  : ");
            for(i = 0; i < 16; i++) {
                printf("%02x", rootfs1_bdwlan_bin_md5_digit[i]);
            }
            printf("\n");
            printf("BDWLAN.B215 ROOTFS1 MD5 : ");
            for(i = 0; i < 16; i++) {
                printf("%02x", rootfs1_bdwlan_b215_md5_digit[i]);
            }
            printf("\n");
            printf("BDWLAN.BIN ROOTFS2 MD5  : ");
            for(i = 0; i < 16; i++) {
                printf("%02x", rootfs2_bdwlan_bin_md5_digit[i]);
            }
            printf("\n");
            printf("BDWLAN.B215 ROOTFS2 MD5 : ");
            for(i = 0; i < 16; i++) {
                printf("%02x", rootfs2_bdwlan_b215_md5_digit[i]);
            }
            printf("\n");
            printf("DIAGFW BDWLAN.BIN  MD5  : ");
            for(i = 0; i < 16; i++) {
                printf("%02x", diag_firmware_bdwlan_bin_md5_digit[i]);
            }
            printf("\n");
            printf("DIAGFW BDWLAN.B215 MD5  : ");
            for(i = 0; i < 16; i++) {
                printf("%02x", diag_firmware_bdwlan_b215_md5_digit[i]);
            }
            printf("\n");
        }
    }




}


/*---------------------------------------- BDF SYNC TEST END ----------------------------------------*/
