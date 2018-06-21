#include "netChallengeDLL.h"

using namespace rapidxml;

ULONG requestIcmpIp(std::string ipParam);

NETCHALLENGEDLL_API ULONG execute() {

	ULONG result = 500;
	result = requestIcmpIp("216.58.210.163");
	return result;
}

NETCHALLENGEDLL_API ULONG executeParam(char* xml) {

	ULONG result = 500;

	std::string xmlSAD = xml;

	std::vector<char> xml_copy(xmlSAD.begin(), xmlSAD.end());
	xml_copy.push_back('\0');
	xml_document<> doc;

	doc.parse<0>(&xml_copy[0]);
	xml_node<>* chall_node = NULL;
	std::string chall_param;

	//Cogemos el nodo CHALLENGE
	chall_node = doc.first_node("dronefs");
	chall_node = chall_node->first_node();
	while (strcmp(chall_node->name(), "challenge") != 0) {
		chall_node = chall_node->next_sibling();
	}
	chall_node = chall_node->first_node();
	if (strcmp(chall_node->value(), "ip") == 0) {
		result = requestIcmpIp("216.58.210.163");
	}

	return result;
}

ULONG requestIcmpIp(std::string ipParam) {

	std::string ipStr = ipParam;
	char* ipCharPtr = _strdup(ipStr.c_str());
	HANDLE hIcmpFile;
	unsigned long ipaddr = INADDR_NONE;
	DWORD dwRetVal = 0;
	DWORD dwError = 0;
	char SendData[] = "Data Buffer";
	LPVOID ReplyBuffer = NULL;
	DWORD ReplySize = 0;

	ipaddr = inet_addr(ipCharPtr);
	hIcmpFile = IcmpCreateFile();
	ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData) + 8;
	ReplyBuffer = (VOID *)malloc(ReplySize);

	dwRetVal = IcmpSendEcho2(hIcmpFile, NULL, NULL, NULL,
		ipaddr, SendData, sizeof(SendData), NULL,
		ReplyBuffer, ReplySize, 1000);

	if (dwRetVal != 0) {
		PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
		struct in_addr ReplyAddr;
		ReplyAddr.S_un.S_addr = pEchoReply->Address;

		unsigned long status = (pEchoReply->Status) + 100;
		return status;
	}
	else {
		dwError = GetLastError() + 100;
		return dwError;
	}

}

