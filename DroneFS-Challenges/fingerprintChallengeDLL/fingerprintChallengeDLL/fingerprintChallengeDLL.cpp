#include "fingerprintChallengeDLL.h"

using namespace rapidxml;
int nEnvParams = 1;



FINGERPRINTCHALLENGEDLL_API PUCHAR execute(PUCHAR* parametrosXml) {



	//Get registry main key
	//PCHAR mainKey = (PCHAR)getChallengeProtectParams()[0];

	PCHAR mainKey = (PCHAR)parametrosXml[0];

	//Get subkeys for result
	char* subKeys = EnumerateSubKeys(HKEY_LOCAL_MACHINE, mainKey);
	string subKeysStr(subKeys);

	//string clave = sha256(subKeysStr);

	PUCHAR challengeReturn = (PUCHAR)_strdup(subKeysStr.c_str());

	return challengeReturn;
}

FINGERPRINTCHALLENGEDLL_API PUCHAR* executeParam() {

	//Get registry main key
	PCHAR mainKey = (PCHAR)getChallengeProtectParams()[0];

	//Get subkeys for result
	char* subKeys = EnumerateSubKeys(HKEY_LOCAL_MACHINE, mainKey);
	string subKeysStr(subKeys);

	//string clave = sha256(subKeysStr);

	PUCHAR* challengeReturn = new UCHAR *[2];
	challengeReturn[0] = (PUCHAR)_strdup(subKeysStr.c_str());

	char* xmlReturn = "<Challenge name=\"fingerprintChallenge\">\
		<Params nparams=\"1\">\
		<param>SOFTWARE\\DroneFS</param>\
		</Params>\
		</Challenge>";
	challengeReturn[1] = (PUCHAR)xmlReturn;

	return challengeReturn;

}

PUCHAR* getChallengeProtectParams() {

	std::ifstream file("C:\\W10 PC\\Projects\\DroneFSfilter\\x64\\Debug\\dronefsconfig.txt");
	std::string textcontent((std::istreambuf_iterator<char>(file)),
		std::istreambuf_iterator<char>());

	std::string xmlDroneFS = textcontent;
	std::vector<char> xml_copy(xmlDroneFS.begin(), xmlDroneFS.end());
	xml_copy.push_back('\0');
	xml_document<> doc;
	doc.parse<0>(&xml_copy[0]);
	xml_node<>* top_node = NULL;
	xml_node<>* cipher_node = NULL;
	xml_node<>* chall_node = NULL;
	int numChallenges = 0;


	top_node = doc.first_node("DroneFSConfig");
	top_node = top_node->first_node("CipherData");
	chall_node = top_node->next_sibling("Challenges");

	chall_node = chall_node->first_node("count");
	numChallenges = atoi(chall_node->value());


	for (int i = 0; i < numChallenges; i++) {
		chall_node = chall_node->next_sibling("Challenge");
		char* challNodeName = chall_node->first_attribute("name")->value();
		if (strcmp(challNodeName, "fingerprintChallenge") == 0) {
			chall_node = chall_node->first_node("Params");
			int numParams = atoi(chall_node->first_attribute("nparams")->value());
			if (numParams != 0) {
				char** dllParamList = new char *[numParams];
				chall_node = chall_node->first_node("param");
				char* temp = chall_node->value();
				dllParamList[0] = new char[strlen(temp) + 1];
				memcpy(dllParamList[0], temp, strlen(temp) + 1);
				PUCHAR* envParams = new UCHAR *[nEnvParams];
				envParams[0] = (PUCHAR)dllParamList[0];
				return envParams;
			}
		}
	}
	return 0;
}

PUCHAR* getChallengeUnProtectParams() {

	std::ifstream file("C:\\W10 PC\\Projects\\DroneFSfilter\\x64\\Debug\\dronefsconfig.txt");
	std::string textcontent((std::istreambuf_iterator<char>(file)),
		std::istreambuf_iterator<char>());

	std::string xmlDroneFS = textcontent;
	std::vector<char> xml_copy(xmlDroneFS.begin(), xmlDroneFS.end());
	xml_copy.push_back('\0');
	xml_document<> doc;
	doc.parse<0>(&xml_copy[0]);
	xml_node<>* top_node = NULL;
	xml_node<>* cipher_node = NULL;
	xml_node<>* chall_node = NULL;
	int numChallenges = 0;


	top_node = doc.first_node("DroneFSConfig");
	top_node = top_node->first_node("CipherData");
	chall_node = top_node->next_sibling("Challenges");

	chall_node = chall_node->first_node("count");
	numChallenges = atoi(chall_node->value());


	for (int i = 0; i < numChallenges; i++) {
		chall_node = chall_node->next_sibling("Challenge");
		char* challNodeName = chall_node->first_attribute("name")->value();
		if (strcmp(challNodeName, "fingerprintChallenge") == 0) {
			chall_node = chall_node->first_node("Params");
			int numParams = atoi(chall_node->first_attribute("nparams")->value());
			if (numParams != 0) {
				char** dllParamList = new char *[numParams];
				chall_node = chall_node->first_node("param");
				char* temp = chall_node->value();
				dllParamList[0] = new char[strlen(temp) + 1];
				memcpy(dllParamList[0], temp, strlen(temp) + 1);
				PUCHAR* envParams = new UCHAR *[nEnvParams];
				envParams[0] = (PUCHAR)dllParamList[0];
				return envParams;
			}
		}
	}
	return 0;
}

char* EnumerateSubKeys(HKEY rootKey, LPCSTR mainKey) {

	string fullString = "";

	HKEY hKey;
	DWORD cSubKeys = 0;        //Used to store the number of Subkeys
	DWORD maxSubkeyLen;    //Longest Subkey name length
	DWORD cValues;        //Used to store the number of Subkeys
	DWORD maxValueLen;    //Longest Subkey name length
	DWORD retCode;        //Return values of calls

	DWORD i;
	DWORD    cbName;                   // size of name string
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name

	long n = RegOpenKeyEx(rootKey, mainKey, 0, KEY_READ, &hKey);

	RegQueryInfoKey(hKey,            // key handle
		NULL,            // buffer for class name
		NULL,            // size of class string
		NULL,            // reserved
		&cSubKeys,        // number of subkeys
		&maxSubkeyLen,    // longest subkey length
		NULL,            // longest class string 
		&cValues,        // number of values for this key 
		&maxValueLen,    // longest value name 
		NULL,            // longest value data 
		NULL,            // security descriptor 
		NULL);            // last write time

	if (cSubKeys) {

		for (i = 0; i<cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				NULL);
			if (retCode == ERROR_SUCCESS)
			{
				string temp = achKey;
				fullString += temp;
			}

		}
	}

	char* result = _strdup(fullString.c_str());

	return result;
}