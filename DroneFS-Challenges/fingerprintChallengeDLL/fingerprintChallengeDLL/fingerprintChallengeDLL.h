#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>       // std::cout, std::ios
#include <sstream>        // std::istringstream
#include <stdint.h>
#include <list>
#include <string>
#include <vector>
#include "rapidxml.hpp"
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdio.h>
#include <Windows.h>
#include "sha256.h"
#include <fstream>

using namespace std;

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

char* EnumerateSubKeys(HKEY rootKey, LPCSTR mainKey);


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")


#ifdef FINGERPRINTCHALLENGEDLL_EXPORTS
#define FINGERPRINTCHALLENGEDLL_API __declspec(dllexport)
#else
#define FINGERPRINTCHALLENGEDLL_API __declspec(dllimport)
#endif

extern "C" FINGERPRINTCHALLENGEDLL_API PUCHAR execute(PUCHAR* xml);
extern "C" FINGERPRINTCHALLENGEDLL_API PUCHAR* executeParam();
extern "C" FINGERPRINTCHALLENGEDLL_API PUCHAR* getParamNames();
extern "C" FINGERPRINTCHALLENGEDLL_API int getNumParams();

PUCHAR* getChallengeProtectParams();
PUCHAR* getChallengeUnProtectParams();

