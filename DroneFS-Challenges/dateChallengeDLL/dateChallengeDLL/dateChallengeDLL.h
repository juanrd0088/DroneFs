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
#include <tchar.h>
#include <iostream> 
#include <string>
#include <windows.h>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdlib.h>
#include <setjmp.h>
#include "sha256.h"
#include <stdlib.h>
#include <stdio.h>
#include <ctime>          // std::tm
#include <locale>         // std::locale, std::time_get, std::use_facet
using namespace std;

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

char* EnumerateSubKeys(HKEY rootKey, LPCSTR mainKey);


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")


#ifdef DATECHALLENGEDLL_EXPORTS
#define DATECHALLENGEDLL_API __declspec(dllexport)
#else
#define DATECHALLENGEDLL_API __declspec(dllimport)
#endif

extern "C" DATECHALLENGEDLL_API PUCHAR execute(PUCHAR* xml);
extern "C" DATECHALLENGEDLL_API PUCHAR* executeParam();
extern "C" DATECHALLENGEDLL_API PUCHAR* getParamNames();
extern "C" DATECHALLENGEDLL_API int getNumParams();

PUCHAR* getChallengeProtectParams();
PUCHAR* getChallengeUnProtectParams();
tm AddMonths_OracleStyle(const tm &d, int months);
int GetDaysInMonth(int year, int month);
bool IsLeapYear(int year);
time_t AddMonths_OracleStyle(const time_t &date, int months);

