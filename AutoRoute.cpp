//
#include <stdio.h>
#include <direct.h>
#include <math.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#pragma comment(lib,"URlmon")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")

#pragma warning(disable:4996)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// 大小端转换
inline DWORD SWAPBIT(const DWORD a)
{
	return ((a & 0x000000ff) << 24) | ((a & 0x0000ff00) << 8) | ((a & 0x00ff0000) >> 8) | ((a & 0xff000000) >> 24);
}

// 只用到了适配器信息中的这两条
typedef struct my_ADDRESS_INFO
{
	DWORD index;
	char ip[4 * 4];
}MYINFO;

bool GetAdaptersInfoFormIp(const char* ip, MYINFO& info)
{
	if (!ip) return false;
	PIP_ADAPTER_INFO pinfo = nullptr;
	unsigned long len = 0;
	GetAdaptersInfo(pinfo, &len);
	pinfo = (PIP_ADAPTER_INFO)malloc(len);
	if (pinfo)
	{
		if (GetAdaptersInfo(pinfo, &len) == 0)
		{
			PIP_ADAPTER_INFO adapterPointer = pinfo;
			while (adapterPointer != nullptr)
			{
				PIP_ADDR_STRING ipAddressListPointer = &(adapterPointer->IpAddressList);
				PIP_ADDR_STRING ipGatewayListPointer = &(adapterPointer->GatewayList);
				while (ipAddressListPointer != nullptr && ipGatewayListPointer != nullptr) {
					if (strcmp((char*)(ipAddressListPointer->IpAddress).String, ip) == 0)
					{
						info.index = adapterPointer->Index;
						strcpy(info.ip, ipGatewayListPointer->IpAddress.String);
						free(pinfo);
						return true;
					}
					else {
						ipAddressListPointer = ipAddressListPointer->Next;
						ipGatewayListPointer = ipGatewayListPointer->Next;
					}
					adapterPointer = adapterPointer->Next;
				}
			}
		}
		free(pinfo);
	}
	printf("获取IP[%s]对应的网卡接口Index失败。\n", ip);
	return false;
}

// MSDN上的样例，获取默认路由信息
bool PreIpforwardRow(const char* interface_ip, PMIB_IPFORWARDROW pRow)
{
	PMIB_IPFORWARDTABLE pIpForwardTable = NULL;
	DWORD dwSize = 0;
	BOOL bOrder = FALSE;
	DWORD dwStatus = 0;

	// Find out how big our buffer needs to be.
	dwStatus = GetIpForwardTable(pIpForwardTable, &dwSize, bOrder);
	if (dwStatus == ERROR_INSUFFICIENT_BUFFER) {
		// Allocate the memory for the table
		if (!(pIpForwardTable = (PMIB_IPFORWARDTABLE)malloc(dwSize))) {
			printf("Malloc failed. Out of memory.\n");
			return false;
		}
		// Now get the table.
		dwStatus = GetIpForwardTable(pIpForwardTable, &dwSize, bOrder);
	}

	if (dwStatus != ERROR_SUCCESS) {
		printf("getIpForwardTable failed.\n");
		if (pIpForwardTable)
			free(pIpForwardTable);
		return false;
	}

	// Search for the row in the table we want. The default gateway has a destination
	 // of 0.0.0.0. Notice that we continue looking through the table, but copy only
	 // one row. This is so that if there happen to be multiple default gateways, we can
	 // be sure to delete them all.
	for (DWORD i = 0; i < pIpForwardTable->dwNumEntries; i++)
	{
		if (pIpForwardTable->table[i].dwForwardDest == 0)
		{
			memcpy(pRow, &(pIpForwardTable->table[i]), sizeof(MIB_IPFORWARDROW));
			break;
		}
	}

	if (interface_ip && interface_ip[0] != '\0')
	{
		MYINFO info;
		if (GetAdaptersInfoFormIp(interface_ip, info))
		{
			pRow->dwForwardNextHop = inet_addr(info.ip);
			pRow->dwForwardIfIndex = info.index;
			pRow->dwForwardDest = 0;
			pRow->dwForwardMask = 0;
		}
	}

	in_addr addr;
	addr.S_un.S_addr = pRow->dwForwardNextHop;
	printf("境内地址路由默认网关=%s, 默认接口=%d\n", inet_ntoa(addr), pRow->dwForwardIfIndex);

	// Free resources
	if (pIpForwardTable)
		free(pIpForwardTable);

	return true;
}

int main(int argc, char* argv[])
{
	// 参数处理
	if (argc < 2)
	{
		printf("输入参数错误，格式:\"AutoRoute.exe [模式(add/del)] [目标地址(非网关)]\"。\n");
		printf("示例:AutoRoute.exe \"add\" \"192.168.1.103\"\n");
		system("pause");
		return 0;
	}
	char target_ip[4 * 4] = { 0 };
	bool addmode = false;
	if(stricmp(argv[1], "add") == 0)
		addmode = true;
	else if(stricmp(argv[1], "del") == 0)
		addmode = false;
	else
	{
		printf("模式参数错误，可选参数：add / del。\n");
		system("pause");
		return 0;
	}
	if (argc >= 3)
	{
		strncpy(target_ip, argv[2], 15);
	}

	// 初始化结构体
	PMIB_IPFORWARDROW pRow = (PMIB_IPFORWARDROW)malloc(sizeof(MIB_IPFORWARDROW));
	if (!pRow || !PreIpforwardRow(target_ip, pRow))
	{
		printf("初始化路由网关和接口信息失败!\n");
		system("pause");
		return -1;
	}

	// 初始化文件
	char route_list_file[MAX_PATH] = { 0 };
	char route_bakup_file[MAX_PATH] = { 0 };
	if (_getcwd(route_list_file, MAX_PATH) == nullptr)
	{
		printf("获取程序目录失败!\n");
		system("pause");
		return -1;
	}
	strcpy(route_bakup_file, route_list_file);
	strcat_s(route_bakup_file, "\\route_backup.txt");
	strcat_s(route_list_file, "\\delegated-apnic-latest.txt");

	if (addmode)
	{
		printf("正在从APNIC下载文件...\n");
		// 注意这里不要用https，否则某些server版系统由于权限限制无法下载
		HRESULT Result = URLDownloadToFileA(NULL, "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest", route_list_file, 0, NULL);
		if (Result != S_OK)
		{
			printf("URLDownloadToFile ERROR! Ret=%d\n", Result);
			system("pause");
			return -1;
		}
	}

	char szLine[1024] = { 0 }; //每行最大读取的字符数
	FILE* fp_back = nullptr;
	// 第一遍删除旧的，第二遍添加新的
	char* path = route_bakup_file;
	for (auto nPorc = 0; nPorc < (addmode ? 2 : 1); nPorc++)
	{
		if (nPorc == 1)
		{
			path = route_list_file;
			fp_back = fopen(route_bakup_file, "w");
		}
		int nSuccessCount = 0, nErrorCount = 0;
		// 读取文件
		if (FILE* fp = fopen(path, "r"))
		{
			printf("正在更新路由配置...\n");
			while (!feof(fp))
			{
				memset(szLine, 0, 1024);
				if (fgets(szLine, 1024, fp))
				{
					char ip[16] = { 0 }, mask[8] = { 0 };
					if (2 == sscanf(szLine, "apnic|CN|ipv4|%[^|]|%[^|]", ip, mask))
					{
						//printf("%s/%d\n", ip, (int)log(atoi(mask)));
						//DWORD dwMask = pow(2, (32 - (int)log(atoi(mask)))) - 1;
						//DWORD dwMask = SWAPBIT(0xFFFFFFFF - atoi(mask) +1);
						DWORD dwStatus = 0;
						if (nPorc == 0)
						{
							pRow->dwForwardDest = inet_addr(ip);
							pRow->dwForwardMask = SWAPBIT(0xFFFFFFFF - atoi(mask) + 1);// inet_addr(net_mask);
							dwStatus = DeleteIpForwardEntry(pRow);
						}
						else
						{
							pRow->dwForwardDest = inet_addr(ip);
							pRow->dwForwardMask = SWAPBIT(0xFFFFFFFF - atoi(mask) + 1);// inet_addr(net_mask);
							dwStatus = CreateIpForwardEntry(pRow);
							if (dwStatus == NO_ERROR && fp_back)
							{
								fputs(szLine, fp_back);
							}
						}
						if (dwStatus == NO_ERROR)
							nSuccessCount++;
						else
						{
							nErrorCount++;
							if (ERROR_ACCESS_DENIED == dwStatus)
							{
								printf("ERROR_ACCESS_DENIED!\n");
								system("pause");
								return -1;
							}
							else
							{
								LPTSTR lpMsgBuf = NULL;
								FormatMessage(
									FORMAT_MESSAGE_ALLOCATE_BUFFER |
									FORMAT_MESSAGE_FROM_SYSTEM |
									FORMAT_MESSAGE_IGNORE_INSERTS,
									NULL,
									dwStatus,
									MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
									(LPTSTR)&lpMsgBuf,
									0, NULL);
								printf("%s [%s|%s] Error: %d = %s", nPorc == 1 ? "CreateIpForwardEntry" : "DeleteIpForwardEntry",
									ip, mask, dwStatus, lpMsgBuf);
								LocalFree(lpMsgBuf);
							}
						}
						// 测试模式只写入一条，正式版屏蔽break;
						//break;
					}
				}
			}
			fclose(fp);
			printf("%s路由表信息完成，总计%d条，成功%d条，失败%d条。\n",
				nPorc == 1 ? "添加" : "删除", nSuccessCount + nErrorCount, nSuccessCount, nErrorCount);
		}
		else
		{
			printf("打开文件[%s]错误。\n", path);
			//return -1;
		}
		if(fp_back)
			fclose(fp_back);
		else if(nPorc == 0)
			::DeleteFile(route_bakup_file);
	}
	if (pRow)
		free(pRow);

	system("pause");
	return 0;
}
