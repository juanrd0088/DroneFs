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

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")


#ifdef NETCHALLENGEDLL_EXPORTS
#define NETCHALLENGEDLL_API __declspec(dllexport)
#else
#define NETCHALLENGEDLL_API __declspec(dllimport)
#endif

extern "C" NETCHALLENGEDLL_API ULONG execute();
extern "C" NETCHALLENGEDLL_API ULONG executeParam(char* xml);

