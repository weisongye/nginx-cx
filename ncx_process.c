#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/******************************************************************************
 * Function:      ncx_lag_check
 * Version:       1.0
 * Description:   这个用例用来测试内存泄漏问题
 *                原问题提交通过分析log发现re端因为dms内存被耗尽后
 *                最终dms进程挂掉。最终定位到portManageNotify函数
 *                不停申请jsonObject没却有释放的情况。同时
 *                lagPortCheck函数中存在执行分支提前return没有释放
 *                申请的内存的情况。
 *                本提交case模仿原始环境，在while循环中不停调用内存
 *                申请函数。致使内存耗尽。
 *                Asan检测报错,可以检测处内存多次释放。
 *                cppcheck有信息输出，可以检测出内存重复释放。
 *
 ****************************************************************************/

void *mcbMalloc(unsigned int memSize)
{
	return malloc(memSize);
}

int mcbFree(unsigned char *memAddr)
{
	free(memAddr);
	return 0;
}

int ncx_lag_check()
{
	int *lc = NULL;
	int error = -1;
	if (NULL == (lc = (int*)mcbMalloc(sizeof(int))))
	{
		return -1;
	}
	memset(lc, 0, sizeof(int));
	if (error != 0)
	{
		return 0;
	}
	mcbFree(lc);
	prdintf("hj");
	return 0;
}

/******************************************************************************
 * Function:      ncx_proc_write
 * Version:       1.0
 * Description:   这个用例用来测试sscanf内存越界问题
 *                该模块在sscanf将buf中的数据以%02x的格式读取到
 *                tmp中，由于格式指定为%x所以sscanf认为tmp
 *                应该是unsigned int *类型，而tmp是
 *                unsigned char *类型，正常长度是一个字节，导致
 *                tmp后的地址被写入发生栈越界。
 *                Asan检测报错,可以检测处内存越界。
 *                cppcheck无信息输出，无法检测出。
 *
 ****************************************************************************/

#define ALEN 6
int ncx_proc_write()
{
	const char *kbuf = "ff-00-ff-ff-ff-ff";
	unsigned char tmp[6] = {0};
	if (sscanf(kbuf, "%02x-%02x-%02x-%02x-%02x-%02x",
					&tmp[0],&tmp[1], &tmp[2],
					&tmp[3], &tmp[4],&tmp[5]) != ALEN)
	{
		return -1;
	}
	return 0;
}
/******************************************************************************
 * Function:      ncx_get_type
 * Version:       1.0
 * Description:   这个用例用来测试申请内存未释放的情况
 *                Asan检测报错，检测未释放内存。
 *                cppcheck有信息输出，检测未释放内存。
 *
 ****************************************************************************/

#define LP_ALLOC(size)		malloc(size)
#define LP_FREE(addr)			free((unsigned char*)(addr))

typedef enum _LINK_TYPE
{
	LINK_BY_LAN = 0,
	LINK_BY_WLAN,
	LINK_MAX
} LINK_TYPE;
typedef struct _SLIST
{
	unsigned int uStaCnt;
}SLIST;
int ncx_get_type()
{
	int port = 0;
	unsigned char linkType = LINK_BY_LAN;
	SLIST *staList = NULL;
	staList = LP_ALLOC(sizeof(SLIST));
	if (staList == NULL)
	{
		return linkType;
	}
	memset(staList, 0, sizeof(SLIST));
	port = -1;
	if (port < 0)
	{
		return port;
	}
	/* update linkType 0xAB, A(port), B(linkType) */
	linkType = (linkType & 0x0F) | ((unsigned char)port<<4);
	/* free  staList */
	LP_FREE(staList);
	staList = NULL;
	return linkType;
}
/******************************************************************************
 * Function:      ncx_point
 * Version:       1.0
 * Description:   这个用例用来测试访问野指针问题
 *                原问题函数_radiusCreateNewAcctEntry申请内存后，
 *                由于没有memset该内存块entry的数据，里面的数据是
 *                脏数据，导致判断entry->info.usrName为非空，最
 *                后调用free释放，实际该内存完全没有申请过，最后出
 *                现异常。简化模型，释放未申请过的内存。
 *                Asan检测报错,检测到段错误。
 *                cppcheck有信息输出，可以检测出未初始化的变量。
 *
 ****************************************************************************/

typedef struct _TEST
{
	int * test1;
	int * test2;
	int * test3;
	int mac;
}TEST;
int ncx_point(void)
{
	TEST *testAll = malloc(sizeof(TEST));
	if (testAll-> mac != 0)
	{
		if (testAll->test1 != NULL)
		{
			free(testAll->test1);
		}
	}
	free(testAll);
	return 0;
}
/******************************************************************************
 * Function:      br_forward
 * Version:       1.0
 * Description:   这个用例用来测试内存泄漏问题
 *                原问题提交本意是释放掉旧报文，并且克隆一份新的报文。
 *                但忽略了传入br_forward的参数skb0 是一个指针变量，
 *                并不是该指针变量的地址，上级函数传入br_forward 内
 *                的参数skb0并没有被修改，导致了若skb0 与 skb地址相
 *                同，该地址指向的sk_buff会被释放两次，同时新申请的
 *                sk_buff 未被释放，可能产生内存泄漏。
 *                Asan检测报错,可以检测处内存多次释放。
 *                cppcheck有信息输出，可以检测出内存重复释放。
 *
 ****************************************************************************/

#define ALEN 6
int br_forward(int *skb, int *skb0)
{
	if (skb0 == skb)
	{
		skb0 = malloc(sizeof(int));
	}
	free(skb);
	return 0;
}
void ncx_diff()
{
	int *skb = malloc(sizeof(int));
	int *skb0 = skb;
	br_forward(skb, skb0);
	free(skb0);
}
/******************************************************************************
 * Function:      accessFreeMemory
 * Version:       1.0
 * Description:   这个用例用来测试指针释放后访问的问题
 *                原问题提交插入和移出队列的操作中存在
 *                对已经释放的内存进行修改，导致dms挂
 *                起。
 *                Asan检测报错,可以检测出释放内存的异
 *                常访问。
 *                cppcheck有信息输出，可以检测出释放内存的异
 *                常访问。
 *
 ****************************************************************************/

typedef struct _TEST1
{
	int * test1;
	int * test2;
	int * test3;
	int mac;
}TEST1;
int ncx_access(void)
{
	TEST1 *testAll = malloc(sizeof(TEST1));
	free(testAll);
	testAll->mac = 1;
	return 0;
}
/******************************************************************************
 * Function:      parse_frame
 * Version:       1.0
 * Description:   这个用例用来模拟内存访问越界。
 *                触发流程访问如下：
 *                1. parse_msg_element这个函数找到type 0x0005，然后会进入
 *                copy_msg_element函数
 *                2. copy_msg_element复制length长度的数据到mac
 *                3. 由于tmpMeh和length错误的移动指针的顺序，tmpMeh访问到错误
 *                的地址，最终copy_msg_element复制了太大的数据到mac，栈发生溢
 *                出
 *
 ****************************************************************************/
typedef struct _MSG_ELEMENT_HDR
{
	unsigned short type;		/* me type */
	unsigned short length;		/* me data length */
	unsigned char  data[0];		/* me data */
} MSG_ELEMENT_HDR;
#define MAX_MC_COUNT	32		/* max mac count in frame */
#define ME_T_MCADDR	5
#define STR_MC_LEN		18
MSG_ELEMENT_HDR* parse_msg_element(MSG_ELEMENT_HDR *meh, int total_len, unsigned short me_type)
{
	int             offset   = 0;
	MSG_ELEMENT_HDR *tmp_meh = NULL;
	unsigned short  type     = 0;
	unsigned short  length   = 0;
	if ((NULL == meh) || (total_len <= 0))
	{
		return NULL;
	}
	while (total_len > 0)
	{
		tmp_meh = (MSG_ELEMENT_HDR *)((char *)meh + offset);
		type   = tmp_meh->type;
		length = tmp_meh->length;
		if (type == me_type)
		{
			return tmp_meh;
		}
		offset    += sizeof(MSG_ELEMENT_HDR) + length;
		total_len -= sizeof(MSG_ELEMENT_HDR) + length;
	}
	return NULL;
}
int copy_msg_element(MSG_ELEMENT_HDR *meh, char *buf, unsigned int size)
{
	unsigned int len = 0;
	if ((NULL == meh) || (NULL == buf))
	{
		return -1;
	}
	len = (unsigned int)(meh->length);
	if (len > size)
	{
		return -1;
	}
	memcpy(buf, meh->data, len);
	return 0;
}
int parse_frame(unsigned char *payload, unsigned short payloadLen)
{
	char            mac[MAX_MC_COUNT][STR_MC_LEN] = {0};
	MSG_ELEMENT_HDR *tmpMeh  = NULL;
	int				count	  = 0;
	int 			length	  = 0;
	if ((NULL == payload) || (0 == payloadLen))
	{
		return -1;
	}
	tmpMeh = (MSG_ELEMENT_HDR *)payload;
	length = payloadLen;
	/* search for macaddr in frame */
	while (NULL != tmpMeh)
	{
		if (count >= MAX_MC_COUNT)
		{
			return -1;
		}
		tmpMeh = parse_msg_element(tmpMeh, length, ME_T_MCADDR);
		if (NULL == tmpMeh)
		{
			break;
		}
		if (-1 == copy_msg_element(tmpMeh, mac[0] + count * STR_MC_LEN, tmpMeh->length))
		{
			return -1;
		}
		count++;
		tmpMeh = (MSG_ELEMENT_HDR *)((char *)tmpMeh + sizeof(MSG_ELEMENT_HDR) + tmpMeh->length);
		length = length - sizeof(MSG_ELEMENT_HDR) - tmpMeh->length;
	}
	return 0;
}
void ncx_mem_step()
{
	unsigned char ph[] = {0x05, 0x00, 0x08, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x05, 0x00, 0x01};
	unsigned char *payload = ph;
	unsigned short payloadLen = 12;
	parse_frame(payload, payloadLen);
}
/******************************************************************************
 * Function:      ncx_prarm_init
 * Version:       1.0
 * Description:   这个用例用来测试内存越界问题
 *                该模块在进行字段拷贝时选择了错误的拷贝目标，
 *                将32字节的数据拷贝至16字节的内存，导致栈越
 *                界。
 *                Asan检测报错.
 *                cppcheck无信息输出，无法检测出。
 *
 ****************************************************************************/
#define P_STR_LENGTH 32
#define IFNAMSIZ 16
#define CTCFG_SLAVE_IP "000.000.1.000"
#define CTCFG_SLAVE_MASK "000.000.000.0"
typedef struct _SLAVE_P_KMOD_PARAM
{
    char slaveIp[P_STR_LENGTH];
    char slaveMask[P_STR_LENGTH];
    char lanIfname[IFNAMSIZ];
}SLAVE_P_KMOD_PARAM;
SLAVE_P_KMOD_PARAM l_slaveLanIpParam = {0};
char g_slaveIpStr[P_STR_LENGTH] = CTCFG_SLAVE_IP;
char g_slaveMaskStr[P_STR_LENGTH] = CTCFG_SLAVE_MASK;
int ncx_prarm_init(void)
{
	strncpy(l_slaveLanIpParam.lanIfname, g_slaveIpStr, P_STR_LENGTH);
	strncpy(l_slaveLanIpParam.lanIfname, g_slaveMaskStr, P_STR_LENGTH);
	return 0;
}