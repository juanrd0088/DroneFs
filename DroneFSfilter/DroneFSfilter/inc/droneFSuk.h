/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

    scanuk.h

Abstract:

    Header file which contains the structures, type definitions,
    constants, global variables and function prototypes that are
    shared between kernel and user mode.

Environment:

    Kernel & user mode

--*/

#ifndef __DRONEFSUK_H__
#define __DRONEFSUK_H__

//
//  Name of port used to communicate
//

const PWSTR DroneFSPortName = L"\\DroneFSPort";


#define DRONEFS_READ_BUFFER_SIZE   10240

typedef struct _DRONEFS_NOTIFICATION {

    ULONG BytesToScan;
    ULONG Reserved;             // for quad-word alignement of the Contents structure
    UCHAR Contents[DRONEFS_READ_BUFFER_SIZE];
    
} DRONEFS_NOTIFICATION, *PDRONEFS_NOTIFICATION;

typedef struct _DRONEFS_REPLY {

	ULONG BytesToScan;
	ULONG Reserved;             // for quad-word alignement of the Contents structure
	ULONG Key;
	UCHAR Contents[DRONEFS_READ_BUFFER_SIZE];
    
} DRONEFS_REPLY, *PDRONEFS_REPLY;

#endif //  __DRONEFSUK_H__


