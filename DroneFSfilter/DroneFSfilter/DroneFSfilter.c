/*++

Copyright (c) 1999 - 2002  Microsoft Corporation

Module Name:

DroneFSFilter.c

Abstract:

This is a sample filter which demonstrates proper access of data buffer
and a general guideline of how to swap buffers.
For now it only swaps buffers for:

IRP_MJ_READ
IRP_MJ_WRITE
IRP_MJ_DIRECTORY_CONTROL

By default this filter attaches to all volumes it is notified about.  It
does support having multiple instances on a given volume.

Environment:

Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "DroneFSfilter.h"
#include "inc\droneFSuk.h"
#include <Ntintsafe.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")





//
//  Structure that contains all the global data structures
//  used throughout the scanner.
//

DRONEFS_DATA DroneFSData;

/*************************************************************************
Pool Tags
*************************************************************************/

#define DRONEFS_TAG			'fsBS'
#define CONTEXT_TAG         'xcBS'
#define NAME_TAG            'mnBS'
#define PRE_2_POST_TAG      'ppBS'
#define STREAM_TAG			'chBS'
#define DRONEFS_STRING_TAG  'Sncs'


/*************************************************************************
Prototypes
*************************************************************************/


NTSTATUS
DroneFSAllocateUnicodeString(
	_Inout_ PUNICODE_STRING String
);

VOID
DroneFSFreeUnicodeString(
	_Inout_ PUNICODE_STRING String
);

NTSTATUS
DroneFSPortConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID *ConnectionCookie
);

VOID
DroneFSPortDisconnect(
	_In_opt_ PVOID ConnectionCookie
);

NTSTATUS
DroneFSpScanFileInUserMode(
	_In_ PFLT_INSTANCE Instance,
	_In_ PFILE_OBJECT FileObject,
	_Out_ PBOOLEAN SafeToOpen
);

BOOLEAN 
testArrays(
	_In_ char bufferRead[],
	_In_ char bufferWritten[],
	_In_ int length);

BOOLEAN DroneFSSetHeader(_In_ UNICODE_STRING fileName,
	_In_ PFLT_INSTANCE fileInstance,
	_Out_ PDRONEFS_STREAM_CONTEXT dronefsContext);

BOOLEAN
DroneFSCheckIfHeader(
	_In_ UNICODE_STRING fileName,
	_In_ PFLT_INSTANCE fileInstance,
	_Out_ PDRONEFS_STREAM_CONTEXT dronefsContext
);

int my_atoi(char *str);
//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, InstanceSetup)
#pragma alloc_text(PAGE, CleanupVolumeContext)
#pragma alloc_text(PAGE, InstanceQueryTeardown)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, ReadDriverParameters)
#pragma alloc_text(PAGE, FilterUnload)
#pragma alloc_text(PAGE, DroneFSPortConnect)
#pragma alloc_text(PAGE, DroneFSPortDisconnect)
#pragma alloc_text(PAGE, DroneFSAllocateUnicodeString)
#pragma alloc_text(PAGE, DroneFSFreeUnicodeString)
#endif

//
//  Operation we currently care about.
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

	{ IRP_MJ_CREATE,
	0,
	DroneFSPreCreate,
	DroneFSPostCreate },

	{ IRP_MJ_READ,
	0,
	DroneFSPreRead,
	DroneFSPostRead },

	{ IRP_MJ_WRITE,
	0,
	DroneFSPreWrite,
	DroneFSPostWrite },

	{ IRP_MJ_DIRECTORY_CONTROL,
	0,
	SwapPreDirCtrlBuffers,
	SwapPostDirCtrlBuffers },

	{ IRP_MJ_SET_INFORMATION,
	0,
	DfPreSetInfoCallback,
	DfPostSetInfoCallback },

	{ IRP_MJ_OPERATION_END }
};

//
//  Context definitions we currently care about.  Note that the system will
//  create a lookAside list for the volume context because an explicit size
//  of the context is specified.
//

CONST FLT_CONTEXT_REGISTRATION ContextNotifications[] = {

	{ FLT_VOLUME_CONTEXT,
	0,
	CleanupVolumeContext,
	sizeof(VOLUME_CONTEXT),
	CONTEXT_TAG },

	/*{ FLT_STREAMHANDLE_CONTEXT,
	0,
	NULL,
	sizeof(DRONEFS_STREAM_HANDLE_CONTEXT),
	STREAM_TAG },*/

	{ FLT_STREAM_CONTEXT,
	0,
	NULL,
	sizeof(DRONEFS_STREAM_CONTEXT),
	STREAM_TAG,
	NULL,
	NULL,
	NULL },

	{ FLT_CONTEXT_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	ContextNotifications,               //  Context
	Callbacks,                          //  Operation callbacks

	FilterUnload,                       //  MiniFilterUnload

	InstanceSetup,                      //  InstanceSetup
	InstanceQueryTeardown,              //  InstanceQueryTeardown
	NULL,                               //  InstanceTeardownStart
	NULL,                               //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};

/*************************************************************************
Debug tracing information
*************************************************************************/

//
//  Definitions to display log messages.  The registry DWORD entry:
//  "hklm\system\CurrentControlSet\Services\Swapbuffers\DebugFlags" defines
//  the default state of these logging flags
//

#define LOGFL_ERRORS    0x00000001  // if set, display error messages
#define LOGFL_READ      0x00000002  // if set, display READ operation info
#define LOGFL_WRITE     0x00000004  // if set, display WRITE operation info
#define LOGFL_DIRCTRL   0x00000008  // if set, display DIRCTRL operation info
#define LOGFL_VOLCTX    0x00000010  // if set, display VOLCTX operation info

#define NOTIFICATION_READ 100
#define NOTIFICATION_WRITE 200
#define NOTIFICATION_HEADER 300
#define REPLY_KEY_OK 400
#define GET_HEADER 500

ULONG LoggingFlags = LOGFL_READ;             // all disabled by default
//ULONG LoggingFlags = LOGFL_READ;
ULONG readModFlag = TRUE;             // modify read buffer
ULONG writeModFlag = TRUE;             // modify write buffer

const wchar_t *textCmp = L"demotest";


#define LOG_PRINT( _logFlag, _string )                              \
    (FlagOn(LoggingFlags,(_logFlag)) ?                              \
        DbgPrint _string  :                                         \
        ((int)0))

											  //////////////////////////////////////////////////////////////////////////////
											  //////////////////////////////////////////////////////////////////////////////
											  //
											  //                      Routines
											  //
											  //////////////////////////////////////////////////////////////////////////////
											  //////////////////////////////////////////////////////////////////////////////


NTSTATUS
InstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
/*++

Routine Description:

This routine is called whenever a new instance is created on a volume.

By default we want to attach to all volumes.  This routine will try and
get a "DOS" name for the given volume.  If it can't, it will try and
get the "NT" name for the volume (which is what happens on network
volumes).  If a name is retrieved a volume context will be created with
that name.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Flags describing the reason for this attach request.

Return Value:

STATUS_SUCCESS - attach
STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
	PDEVICE_OBJECT devObj = NULL;
	PVOLUME_CONTEXT ctx = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG retLen;
	PUNICODE_STRING workingName;
	USHORT size;
	UCHAR volPropBuffer[sizeof(FLT_VOLUME_PROPERTIES) + 512];
	PFLT_VOLUME_PROPERTIES volProp = (PFLT_VOLUME_PROPERTIES)volPropBuffer;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	FLT_ASSERT(FltObjects->Filter == DroneFSData.Filter);

	try {

		//
		//  Allocate a volume context structure.
		//

		status = FltAllocateContext(FltObjects->Filter,
			FLT_VOLUME_CONTEXT,
			sizeof(VOLUME_CONTEXT),
			NonPagedPool,
			&ctx);

		if (!NT_SUCCESS(status)) {

			//
			//  We could not allocate a context, quit now
			//

			leave;
		}

		//
		//  Always get the volume properties, so I can get a sector size
		//

		status = FltGetVolumeProperties(FltObjects->Volume,
			volProp,
			sizeof(volPropBuffer),
			&retLen);

		if (!NT_SUCCESS(status)) {

			leave;
		}

		//
		//  Save the sector size in the context for later use.  Note that
		//  we will pick a minimum sector size if a sector size is not
		//  specified.
		//

		FLT_ASSERT((volProp->SectorSize == 0) || (volProp->SectorSize >= MIN_SECTOR_SIZE));

		ctx->SectorSize = max(volProp->SectorSize, MIN_SECTOR_SIZE);

		//
		//  Init the buffer field (which may be allocated later).
		//

		ctx->Name.Buffer = NULL;

		//
		//  Get the storage device object we want a name for.
		//

		status = FltGetDiskDeviceObject(FltObjects->Volume, &devObj);

		if (NT_SUCCESS(status)) {

			//
			//  Try and get the DOS name.  If it succeeds we will have
			//  an allocated name buffer.  If not, it will be NULL
			//

			status = IoVolumeDeviceToDosName(devObj, &ctx->Name);
		}

		//
		//  If we could not get a DOS name, get the NT name.
		//

		if (!NT_SUCCESS(status)) {

			FLT_ASSERT(ctx->Name.Buffer == NULL);

			//
			//  Figure out which name to use from the properties
			//

			if (volProp->RealDeviceName.Length > 0) {

				workingName = &volProp->RealDeviceName;

			}
			else if (volProp->FileSystemDeviceName.Length > 0) {

				workingName = &volProp->FileSystemDeviceName;

			}
			else {

				//
				//  No name, don't save the context
				//

				status = STATUS_FLT_DO_NOT_ATTACH;
				leave;
			}

			//
			//  Get size of buffer to allocate.  This is the length of the
			//  string plus room for a trailing colon.
			//

			size = workingName->Length + sizeof(WCHAR);

			//
			//  Now allocate a buffer to hold this name
			//

#pragma prefast(suppress:__WARNING_MEMORY_LEAK, "ctx->Name.Buffer will not be leaked because it is freed in CleanupVolumeContext")
			ctx->Name.Buffer = ExAllocatePoolWithTag(NonPagedPool,
				size,
				NAME_TAG);
			if (ctx->Name.Buffer == NULL) {

				status = STATUS_INSUFFICIENT_RESOURCES;
				leave;
			}

			//
			//  Init the rest of the fields
			//

			ctx->Name.Length = 0;
			ctx->Name.MaximumLength = size;

			//
			//  Copy the name in
			//

			RtlCopyUnicodeString(&ctx->Name,
				workingName);

			//
			//  Put a trailing colon to make the display look good
			//

			RtlAppendUnicodeToString(&ctx->Name,
				L":");
		}

		//
		//  Set the context
		//

		status = FltSetVolumeContext(FltObjects->Volume,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
			ctx,
			NULL);

		//
		//  Log debug info
		//

		LOG_PRINT(LOGFL_VOLCTX,
			("SwapBuffers!InstanceSetup:                  Real SectSize=0x%04x, Used SectSize=0x%04x, Name=\"%wZ\"\n",
				volProp->SectorSize,
				ctx->SectorSize,
				&ctx->Name));

		//
		//  It is OK for the context to already be defined.
		//

		if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

			status = STATUS_SUCCESS;
		}

	}
	finally {

		//
		//  Always release the context.  If the set failed, it will free the
		//  context.  If not, it will remove the reference added by the set.
		//  Note that the name buffer in the ctx will get freed by the context
		//  cleanup routine.
		//

		if (ctx) {

			FltReleaseContext(ctx);
		}

		//
		//  Remove the reference added to the device object by
		//  FltGetDiskDeviceObject.
		//

		if (devObj) {

			ObDereferenceObject(devObj);
		}
	}

	return status;
}


VOID
CleanupVolumeContext(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
)
/*++

Routine Description:

The given context is being freed.
Free the allocated name buffer if there one.

Arguments:

Context - The context being freed

ContextType - The type of context this is

Return Value:

None

--*/
{
	PVOLUME_CONTEXT ctx = Context;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(ContextType);

	FLT_ASSERT(ContextType == FLT_VOLUME_CONTEXT);

	if (ctx->Name.Buffer != NULL) {

		ExFreePool(ctx->Name.Buffer);
		ctx->Name.Buffer = NULL;
	}
}


NTSTATUS
InstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

This is called when an instance is being manually deleted by a
call to FltDetachVolume or FilterDetach.  We always return it is OK to
detach.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Indicating where this detach request came from.

Return Value:

Always succeed.

--*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	return STATUS_SUCCESS;
}

NTSTATUS
DroneFSAllocateUnicodeString(
	_Inout_ PUNICODE_STRING String
)
/*++

Routine Description:

This routine allocates a unicode string

Arguments:

String - supplies the size of the string to be allocated in the MaximumLength field
return the unicode string

Return Value:

STATUS_SUCCESS                  - success
STATUS_INSUFFICIENT_RESOURCES   - failure

--*/
{

	PAGED_CODE();

	String->Buffer = ExAllocatePoolWithTag(NonPagedPool,
		String->MaximumLength,
		DRONEFS_STRING_TAG);

	if (String->Buffer == NULL) {

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	String->Length = 0;

	return STATUS_SUCCESS;
}


VOID
DroneFSFreeUnicodeString(
	_Inout_ PUNICODE_STRING String
)
/*++

Routine Description:

This routine frees a unicode string

Arguments:

String - supplies the string to be freed

Return Value:

None

--*/
{
	PAGED_CODE();

	if (String->Buffer) {

		ExFreePoolWithTag(String->Buffer,
			DRONEFS_STRING_TAG);
		String->Buffer = NULL;
	}

	String->Length = String->MaximumLength = 0;
	String->Buffer = NULL;
}


NTSTATUS
DroneFSPortConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID *ConnectionCookie
)
/*++

Routine Description

This is called when user-mode connects to the server port - to establish a
connection

Arguments

ClientPort - This is the client connection port that will be used to
send messages from the filter

ServerPortCookie - The context associated with this port when the
minifilter created this port.

ConnectionContext - Context from entity connecting to this port (most likely
your user mode service)

SizeofContext - Size of ConnectionContext in bytes

ConnectionCookie - Context to be passed to the port disconnect routine.

Return Value

STATUS_SUCCESS - to accept the connection

--*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

	FLT_ASSERT(DroneFSData.ClientPort == NULL);
	FLT_ASSERT(DroneFSData.UserProcess == NULL);

	//
	//  Set the user process and port. In a production filter it may
	//  be necessary to synchronize access to such fields with port
	//  lifetime. For instance, while filter manager will synchronize
	//  FltCloseClientPort with FltSendMessage's reading of the port 
	//  handle, synchronizing access to the UserProcess would be up to
	//  the filter.
	//

	DroneFSData.UserProcess = PsGetCurrentProcess();
	DroneFSData.ClientPort = ClientPort;

	DbgPrint("!!! DroneFSFilter.sys --- connected, port=0x%p\n", ClientPort);

	return STATUS_SUCCESS;
}


VOID
DroneFSPortDisconnect(
	_In_opt_ PVOID ConnectionCookie
)
/*++

Routine Description

This is called when the connection is torn-down. We use it to close our
handle to the connection

Arguments

ConnectionCookie - Context from the port connect routine

Return value

None

--*/
{
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	DbgPrint("!!! scanner.sys --- disconnected, port=0x%p\n", DroneFSData.ClientPort);

	//
	//  Close our handle to the connection: note, since we limited max connections to 1,
	//  another connect will not be allowed until we return from the disconnect routine.
	//

	FltCloseClientPort(DroneFSData.Filter, &DroneFSData.ClientPort);

	//
	//  Reset the user-process field.
	//

	DroneFSData.UserProcess = NULL;
}

BOOLEAN testArrays(char bufferRead[], char bufferWritten[], int length) {
	int i;
	for (i = 0; i < length; i++) {
		if (bufferRead[i] != bufferWritten[i]) {
			return FALSE;
		}
	}
	return TRUE;
}

BOOLEAN DroneFSSetHeader(_In_ UNICODE_STRING fileName,
	_In_ PFLT_INSTANCE fileInstance,
	_Out_ PDRONEFS_STREAM_CONTEXT dronefsContext) {

	OBJECT_ATTRIBUTES fObjAttrs;
	HANDLE handle = NULL;
	IO_STATUS_BLOCK ioStatus;
	PFILE_OBJECT pObj;
	NTSTATUS status;

	PDRONEFS_NOTIFICATION notification = NULL;
	PDRONEFS_REPLY reply = NULL;
	ULONG replyLength;

	try {
		InitializeObjectAttributes(
			&fObjAttrs,
			&fileName,
			OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
			NULL,
			NULL
		);
		DbgPrint("[SETHEADER]Atributos inicializados correctamente");
	} except(EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
		DbgPrint("[SETHEADER]Error al inicializar atributos. Codigo: %lu", GetExceptionCode());
		if (handle != NULL) {
			status = FltClose(handle);
		}
		return FALSE;
	}



	try {
		status = FltCreateFile(
			DroneFSData.Filter,
			fileInstance,
			&handle,
			GENERIC_WRITE,
			&fObjAttrs,
			&ioStatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN | FILE_OVERWRITE,
			FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH |
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0,
			IO_IGNORE_SHARE_ACCESS_CHECK
		);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[POSTCREATE]Fallo al abrir el fichero test");
			if (handle != NULL) {
				status = FltClose(handle);
			}
			return FALSE;
		}
		DbgPrint("[SETHEADER]Fichero abierto");
	} except(EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
		DbgPrint("[SETHEADER]Exception en CreateFile");
		if (handle != NULL) {
			status = FltClose(handle);
		}
		return FALSE;
	}

	status = ObReferenceObjectByHandle(handle, GENERIC_READ |
		GENERIC_WRITE, NULL, KernelMode, &pObj, NULL);
	DbgPrint("[SETHEADER]Puntero obtenido");

	notification = ExAllocatePoolWithTag(NonPagedPool,
		sizeof(DRONEFS_NOTIFICATION),
		'nacS');

	reply = ExAllocatePoolWithTag(NonPagedPool,
		sizeof(DRONEFS_REPLY),
		'racS');

	if (notification == NULL) {

		DbgPrint("[DroneFSFilter]Notification null");
	}
	else {


		//
		//ASKING FOR THE HEADER TO THE USER APP AND CREATE THE CIPHER KEY
		//
		notification->Reserved = GET_HEADER;
		notification->BytesToScan = 1;
		DbgPrint("[DroneFSFilter]Sending message");
		replyLength = sizeof(DRONEFS_REPLY);
		status = FltSendMessage(DroneFSData.Filter,
			&DroneFSData.ClientPort,
			notification,
			sizeof(DRONEFS_NOTIFICATION),
			reply,
			&replyLength,
			NULL);

		if (STATUS_SUCCESS == status) {

			//replyBytes = reply->BytesToScan;
			//DbgPrint("replyBytesScan=%lu", replyBytes);
			DbgPrint("[DroneFSFilter]Reply obtenido");

			RtlCopyMemory(&dronefsContext->Header,
				&reply->Contents,
				reply->BytesToScan);
			dronefsContext->headerSize = reply->BytesToScan;
			
			//context->key = reply->Key;
			
			ULONG numBytesWritten;

			try {
				status = FltWriteFile(fileInstance,
					pObj,
					NULL,
					dronefsContext->headerSize,
					&dronefsContext->Header,
					FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
					&numBytesWritten,
					NULL,
					NULL);
				if (NT_SUCCESS(status))
				{
					DbgPrint("[SETHEADER]Fichero modificado");
					if (handle != NULL) {
						status = FltClose(handle);
					}

					return TRUE;
				}
			} except(EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
				DbgPrint("[SETHEADER]Exception en WriteFile");
			}
		}
		else {

			//
			//  Couldn't send message. This sample will let the i/o through.
			//

			DbgPrint("!!! [DroneFSFilter] --- couldn't send message to user-mode to scan file, status 0x%X\n", status);
		}
	}
	if (handle != NULL) {
		status = FltClose(handle);
	}
	return FALSE;
}

BOOLEAN
DroneFSCheckIfHeader(
	_In_ UNICODE_STRING fileName,
	_In_ PFLT_INSTANCE fileInstance,
	_Out_ PDRONEFS_STREAM_CONTEXT dronefsContext
) {

	OBJECT_ATTRIBUTES fObjAttrs;
	HANDLE handle = NULL;
	IO_STATUS_BLOCK ioStatus;
	PFILE_OBJECT pObj;
	NTSTATUS status;

	try {
		InitializeObjectAttributes(
			&fObjAttrs,
			&fileName,
			OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
			NULL,
			NULL
		);
		DbgPrint("[CHECKHEADER]Atributos inicializados correctamente");
	} except(EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
		DbgPrint("[CHECKHEADER]Error al inicializar atributos. Codigo: %lu", GetExceptionCode());
	}

	try {
		status = FltCreateFile(
			DroneFSData.Filter,
			fileInstance,
			&handle,
			GENERIC_READ | GENERIC_WRITE,
			&fObjAttrs,
			&ioStatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH |
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0,
			IO_IGNORE_SHARE_ACCESS_CHECK
		);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[CHECKHEADER]Fallo al abrir el fichero test");
			if (handle != NULL) {
				status = FltClose(handle);
			}
			return FALSE;
		}
		DbgPrint("[CHECKHEADER]Fichero abierto");
	} except(EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
		DbgPrint("[CHECKHEADER]Exception en CreateFile");
	}

	status = ObReferenceObjectByHandle(handle, GENERIC_READ |
		GENERIC_WRITE, NULL, KernelMode, &pObj, NULL);
	DbgPrint("[CHECKHEADER]Puntero obtenido");

	char myArrayRead[33];
	char myArrayHeader[10] = "<DroneFS>";
	ULONG myArrayReadSize = 33;  // myArraySize = 10
	ULONG numBytesRead;
	//ULONG numBytesWritten;

	try {
		status = FltReadFile(fileInstance,
			pObj,
			NULL,
			myArrayReadSize,
			myArrayRead,
			FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
			&numBytesRead,
			NULL,
			NULL);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("[CHECKHEADER]Fichero no leido");
			if (handle != NULL) {
				status = FltClose(handle);
			}
			return FALSE;
		}

		if (myArrayRead != NULL) {

			DbgPrint("[CHECKHEADER]String leido: %s", myArrayRead);
			DbgPrint("[CHECKHEADER]String fijo: %s", myArrayHeader);
			if (testArrays(myArrayRead, myArrayHeader, 9)) {
				DbgPrint("[CHECKHEADER]Ya hay header en el fichero");

				char headerContent[9] = "00000000";
				ULONG contentArraySize = sizeof(headerContent) / sizeof(headerContent[0]) - 1;
				LARGE_INTEGER sizeOffset = { 0 };
				sizeOffset.QuadPart = 24;
				RtlCopyMemory(headerContent,
					myArrayRead+24,
					contentArraySize);
				/*try {
					status = FltReadFile(fileInstance,
						pObj,
						&sizeOffset,
						contentArraySize,
						headerContent,
						FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
						&numBytesRead,
						NULL,
						NULL);

					if (!NT_SUCCESS(status))
					{
						DbgPrint("[CHECKHEADER]Header no leido");
						return FALSE;
					}
					*/
					DbgPrint("[CHECKHEADER]Header leido: %s", headerContent);
					int size = 0;
					size = my_atoi(headerContent);
					ULONG headerSize;
					RtlIntToULong(size, &headerSize);

					dronefsContext->headerSize = headerSize;
					DbgPrint("[CHECKHEADER]Header size: %lu", headerSize);
					char fullHeader[DRONEFS_HEADER_SIZE];
					try {
						status = FltReadFile(fileInstance,
							pObj,
							0,
							headerSize,
							fullHeader,
							FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
							&numBytesRead,
							NULL,
							NULL);
						RtlCopyMemory(&dronefsContext->Header,
							fullHeader,
							headerSize);
						if (handle != NULL) {
							status = FltClose(handle);
						}
						return TRUE;
					} except(EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
						DbgPrint("[CHECKHEADER]Exception en ReadFile");
						if (handle != NULL) {
							status = FltClose(handle);
						}
						return FALSE;
					}
				/*} except(EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
					DbgPrint("[CHECKHEADER]Exception en ReadFile");
					return FALSE;
				}*/
			}
			else {
				DbgPrint("[CHECKHEADER]No hay header en el fichero");
				if (handle != NULL) {
					status = FltClose(handle);
				}
				return FALSE;
			}
		}

	} except(EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
		DbgPrint("[CHECKHEADER]Exception en ReadFile");
		if (handle != NULL) {
			status = FltClose(handle);
		}
		return FALSE;
	}
	if (handle != NULL) {
		status = FltClose(handle);
	}

	return FALSE;
}

int my_atoi(char *str)
{
	int           result;
	int           puiss;

	result = 0;
	puiss = 1;
	while (('-' == (*str)) || ((*str) == '+'))
	{
		if (*str == '-')
			puiss = puiss * -1;
		str++;
	}
	while ((*str >= '0') && (*str <= '9'))
	{
		result = (result * 10) + ((*str) - '0');
		str++;
	}
	return (result * puiss);
}
/*************************************************************************
Initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

This is the initialization routine.  This registers with FltMgr and
initializes all global data structures.

Arguments:

DriverObject - Pointer to driver object created by the system to
represent this driver.

RegistryPath - Unicode string identifying where the parameters for this
driver are located in the registry.

Return Value:

Status of the operation

--*/
{
	NTSTATUS status;
	UNICODE_STRING uniString;
	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa;

	//
	//  Default to NonPagedPoolNx for non paged pool allocations where supported.
	//

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	//
	//  Get debug trace flags
	//

	ReadDriverParameters(RegistryPath);

	//
	//  Init lookaside list used to allocate our context structure used to
	//  pass information from out preOperation callback to our postOperation
	//  callback.
	//

	ExInitializeNPagedLookasideList(&Pre2PostContextList,
		NULL,
		NULL,
		0,
		sizeof(PRE_2_POST_CONTEXT),
		PRE_2_POST_TAG,
		0);

	//
	//  Register with FltMgr
	//

	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&DroneFSData.Filter);

	if (!NT_SUCCESS(status)) {

		goto SwapDriverEntryExit;
	}

	//
	//  Create a communication port.
	//

	RtlInitUnicodeString(&uniString, DroneFSPortName);

	//
	//  We secure the port so only ADMINs & SYSTEM can acecss it.
	//

	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

	if (NT_SUCCESS(status)) {

		InitializeObjectAttributes(&oa,
			&uniString,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			sd);

		status = FltCreateCommunicationPort(DroneFSData.Filter,
			&DroneFSData.ServerPort,
			&oa,
			NULL,
			DroneFSPortConnect,
			DroneFSPortDisconnect,
			NULL,
			1);
		//
		//  Free the security descriptor in all cases. It is not needed once
		//  the call to FltCreateCommunicationPort() is made.
		//

		FltFreeSecurityDescriptor(sd);

		if (NT_SUCCESS(status)) {

			//
			//  Start filtering I/O.
			//

			status = FltStartFiltering(DroneFSData.Filter);

			if (NT_SUCCESS(status)) {

				return STATUS_SUCCESS;
			}

			FltCloseCommunicationPort(DroneFSData.ServerPort);
		}
	}

	if (!NT_SUCCESS(status)) {

		FltUnregisterFilter(DroneFSData.Filter);
		goto SwapDriverEntryExit;
	}

SwapDriverEntryExit:

	if (!NT_SUCCESS(status)) {

		ExDeleteNPagedLookasideList(&Pre2PostContextList);
	}

	return status;
}


NTSTATUS
FilterUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

Called when this mini-filter is about to be unloaded.  We unregister
from the FltMgr and then return it is OK to unload

Arguments:

Flags - Indicating if this is a mandatory unload.

Return Value:

Returns the final status of this operation.

--*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(Flags);

	//
	//  Close the server port.
	//

	FltCloseCommunicationPort(DroneFSData.ServerPort);
	
	//
	//  Unregister from FLT mgr
	//

	FltUnregisterFilter(DroneFSData.Filter);

	//
	//  Delete lookaside list
	//

	ExDeleteNPagedLookasideList(&Pre2PostContextList);

	return STATUS_SUCCESS;
}


/*************************************************************************
MiniFilter callback routines.
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS
DroneFSPreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

Pre create callback.  We need to remember whether this file has been
opened for write access.  If it has, we'll want to rescan it in cleanup.
This scheme results in extra scans in at least two cases:
-- if the create fails (perhaps for access denied)
-- the file is opened for write access but never actually written to
The assumption is that writes are more common than creates, and checking
or setting the context in the write path would be less efficient than
taking a good guess before the create.

Arguments:

Data - The structure which describes the operation parameters.

FltObject - The structure which describes the objects affected by this
operation.

CompletionContext - Output parameter which can be used to pass a context
from this pre-create callback to the post-create callback.

Return Value:

FLT_PREOP_SUCCESS_WITH_CALLBACK - If this is not our user-mode process.
FLT_PREOP_SUCCESS_NO_CALLBACK - All other threads.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext = NULL);

	PAGED_CODE();


	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
DroneFSPostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

Post create callback.  We can't scan the file until after the create has
gone to the filesystem, since otherwise the filesystem wouldn't be ready
to read the file for us.

Arguments:

Data - The structure which describes the operation parameters.

FltObject - The structure which describes the objects affected by this
operation.

CompletionContext - The operation context passed fron the pre-create
callback.

Flags - Flags to say why we are getting this post-operation callback.

Return Value:

FLT_POSTOP_FINISHED_PROCESSING - ok to open the file or we wish to deny
access to this file, hence undo the open

--*/
{
	PDRONEFS_STREAM_CONTEXT dronefsContext;
	FLT_POSTOP_CALLBACK_STATUS returnStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PFLT_FILE_NAME_INFORMATION nameInfo;
	NTSTATUS status;
	BOOLEAN hasHeader = FALSE;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	//
	//  If this create was failing anyway, don't bother scanning now.
	//

	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		(STATUS_REPARSE == Data->IoStatus.Status)) {

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	


	status = FltGetFileNameInformation(Data,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_DEFAULT,
		&nameInfo);

	if (!NT_SUCCESS(status)) {

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	FltParseFileNameInformation(nameInfo);

	UNICODE_STRING fileName = nameInfo->Name;

	if (wcsstr(fileName.Buffer, textCmp)) {

		DbgPrint("[POSTCREATE] Trying to allocate stream context");
		status = FltAllocateContext(DroneFSData.Filter,
			FLT_STREAM_CONTEXT,
			sizeof(DRONEFS_STREAM_CONTEXT),
			PagedPool,
			&dronefsContext);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[POSTCREATE] Failed to allocate streamctx");
			return FLT_POSTOP_FINISHED_PROCESSING;
		}


		if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
			FILE_WRITE_DATA | FILE_APPEND_DATA |
			DELETE | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA |
			WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY)) {

			DbgPrint("[POSTCREATE] WriteAccess: %lu", Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess);
			BOOLEAN setHeader = DroneFSSetHeader(fileName, FltObjects->Instance, dronefsContext);
			if (setHeader) {
				dronefsContext->hasHeader = TRUE;
				dronefsContext->ignore = TRUE;
				DbgPrint("[POSTCREATE] OK setHEader: %s", dronefsContext->Header);
				DbgPrint("[POSTCREATE] Trying to set stream context");
				status = FltSetStreamContext(FltObjects->Instance,
					FltObjects->FileObject,
					FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
					dronefsContext,
					NULL);
				if (!NT_SUCCESS(status)) {
					DbgPrint("[POSTCREATE] Failed to set streamctx 1");
					FltReleaseContext(dronefsContext);
					return FLT_POSTOP_FINISHED_PROCESSING;
				}
				DbgPrint("[POSTCREATE] Already set the stream context");
			}
			else {
				dronefsContext->hasHeader = FALSE;
				dronefsContext->ignore = FALSE;
				DbgPrint("[POSTCREATE] Failed setHeader");
				DbgPrint("[POSTCREATE] Trying to set stream context");
				status = FltSetStreamContext(FltObjects->Instance,
					FltObjects->FileObject,
					FLT_SET_CONTEXT_KEEP_IF_EXISTS,
					dronefsContext,
					NULL);

				if (!NT_SUCCESS(status)) {
					DbgPrint("[POSTCREATE] Failed to set streamctx 2");
					FltReleaseContext(dronefsContext);
					return FLT_POSTOP_FINISHED_PROCESSING;
				}
				DbgPrint("[POSTCREATE] Already set the stream context");
			}
		}
		else {
			DbgPrint("[POSTCREATE] ReadAccess: %lu", Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess);
			
			hasHeader = DroneFSCheckIfHeader(fileName, FltObjects->Instance, dronefsContext);
			//dronefsContext->streamFileName = fileName;

			switch (hasHeader) {
			case TRUE:
				dronefsContext->hasHeader = TRUE;
				dronefsContext->ignore = FALSE;
				DbgPrint("[POSTCREATE] Has Header: %s", dronefsContext->Header);
				DbgPrint("[POSTCREATE] Trying to set stream context");
				status = FltSetStreamContext(FltObjects->Instance,
					FltObjects->FileObject,
					FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
					dronefsContext,
					NULL);
				if (!NT_SUCCESS(status)) {
					DbgPrint("[POSTCREATE] Failed to set streamctx 3");
					FltReleaseContext(dronefsContext);
					return FLT_POSTOP_FINISHED_PROCESSING;
				}
				DbgPrint("[POSTCREATE] Already set the stream context");
				break;
			case FALSE:

				dronefsContext->hasHeader = FALSE;
				dronefsContext->ignore = FALSE;
				DbgPrint("[POSTCREATE] No header");
				DbgPrint("[POSTCREATE] Trying to set stream context");
				status = FltSetStreamContext(FltObjects->Instance,
					FltObjects->FileObject,
					FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
					dronefsContext,
					NULL);
				if (!NT_SUCCESS(status)) {
					DbgPrint("[POSTCREATE] Failed to set streamctx 4");
					FltReleaseContext(dronefsContext);
					return FLT_POSTOP_FINISHED_PROCESSING;
				}
				DbgPrint("[POSTCREATE] Already set the stream context");
				break;
			}
		}

		FltReleaseContext(dronefsContext);
		
	}

	FltReleaseFileNameInformation(nameInfo);
		
	return returnStatus;
}



FLT_PREOP_CALLBACK_STATUS
DroneFSPreRead(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

This routine demonstrates how to swap buffers for the READ operation.

Note that it handles all errors by simply not doing the buffer swap.

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

FLT_PREOP_SUCCESS_WITH_CALLBACK - we want a postOpeatio

CompletionContext - Receives the context that will be passed to the
post-operation callback.

Return Value:n callback
FLT_PREOP_SUCCESS_NO_CALLBACK - we don't want a postOperation callback

--*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PVOID newBuf = NULL;
	PMDL newMdl = NULL;
	PVOLUME_CONTEXT volCtx = NULL;
	PPRE_2_POST_CONTEXT p2pCtx;
	NTSTATUS status;
	ULONG readLen = iopb->Parameters.Read.Length;
	PDRONEFS_STREAM_CONTEXT context = NULL;

	status = FltGetStreamContext(FltObjects->Instance,
		FltObjects->FileObject,
		&context);

	if (!NT_SUCCESS(status)) {

		//
		//  We are not interested in this file
		//
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	DbgPrint("[PREREAD] Succesfully got the stream context");

	if (!context->hasHeader || context->ignore) {

		FltReleaseContext(context);

		DbgPrint("[PREREAD] Readlen leave: %lu", readLen);

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	try {

		//
		//  If they are trying to read ZERO bytes, then don't do anything and
		//  we don't need a post-operation callback.
		//
		

		if (readLen == 0) {

			leave;
		}

		DbgPrint("[PREREAD] Readlen initial: %lu", readLen);
		//
		//  Get our volume context so we can display our volume name in the
		//  debug output.
		//

		status = FltGetVolumeContext(FltObjects->Filter,
			FltObjects->Volume,
			&volCtx);

		if (!NT_SUCCESS(status)) {

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPreReadBuffers:             Error getting volume context, status=%x\n",
					status));

			leave;
		}

		//
		//  If this is a non-cached I/O we need to round the length up to the
		//  sector size for this device.  We must do this because the file
		//  systems do this and we need to make sure our buffer is as big
		//  as they are expecting.
		//

		if (FlagOn(IRP_NOCACHE, iopb->IrpFlags)) {

			readLen = (ULONG)ROUND_TO_SIZE(readLen, volCtx->SectorSize);
			DbgPrint("[PREREAD] Readlen rounded: %lu", readLen);
		}

		

		//
		//  Allocate aligned nonPaged memory for the buffer we are swapping
		//  to. This is really only necessary for noncached IO but we always
		//  do it here for simplification. If we fail to get the memory, just
		//  don't swap buffers on this operation.
		//

		newBuf = FltAllocatePoolAlignedWithTag(FltObjects->Instance,
			NonPagedPool,
			(SIZE_T)readLen,
			DRONEFS_TAG);

		if (newBuf == NULL) {

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPreReadBuffers:             %wZ Failed to allocate %d bytes of memory\n",
					&volCtx->Name,
					readLen));

			leave;
		}

		//
		//  We only need to build a MDL for IRP operations.  We don't need to
		//  do this for a FASTIO operation since the FASTIO interface has no
		//  parameter for passing the MDL to the file system.
		//

		if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION)) {

			//
			//  Allocate a MDL for the new allocated memory.  If we fail
			//  the MDL allocation then we won't swap buffer for this operation
			//

			newMdl = IoAllocateMdl(newBuf,
				readLen,
				FALSE,
				FALSE,
				NULL);

			if (newMdl == NULL) {

				LOG_PRINT(LOGFL_ERRORS,
					("SwapBuffers!SwapPreReadBuffers:             %wZ Failed to allocate MDL\n",
						&volCtx->Name));

				leave;
			}

			//
			//  setup the MDL for the non-paged pool we just allocated
			//

			MmBuildMdlForNonPagedPool(newMdl);
		}

		//
		//  We are ready to swap buffers, get a pre2Post context structure.
		//  We need it to pass the volume context and the allocate memory
		//  buffer to the post operation callback.
		//

		p2pCtx = ExAllocateFromNPagedLookasideList(&Pre2PostContextList);

		if (p2pCtx == NULL) {

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPreReadBuffers:             %wZ Failed to allocate pre2Post context structure\n",
					&volCtx->Name));

			leave;
		}

		//
		//  Log that we are swapping
		//



		LOG_PRINT(LOGFL_READ,
			("SwapBuffers!SwapPreReadBuffers:             %wZ newB=%p newMdl=%p oldB=%p oldMdl=%p len=%d\n",
				&volCtx->Name,
				newBuf,
				newMdl,
				iopb->Parameters.Read.ReadBuffer,
				iopb->Parameters.Read.MdlAddress,
				readLen));


		//
		//  Update the offset so we don't read the header.
		//
		
		/*ULONG headerSize = context->headerSize;
		iopb->Parameters.Read.ByteOffset.QuadPart = headerSize;*/
		

		LARGE_INTEGER largeHeaderSize = { 0 };
		largeHeaderSize.QuadPart = context->headerSize;
		//largeHeaderSize.QuadPart = iopb->Parameters.Read.ByteOffset.QuadPart + context->headerSize;
		//iopb->Parameters.Read.ByteOffset = largeHeaderSize;
		if (iopb->Parameters.Read.ByteOffset.QuadPart == 0) {
			iopb->Parameters.Read.ByteOffset = largeHeaderSize;
		}

		DbgPrint("[PREREAD] Byteoffset is: %lli", iopb->Parameters.Read.ByteOffset);
		DbgPrint("[PREREAD] Readlen after offset: %lu", readLen);
		//DbgPrint("[PREREAD] Headersize: %lu", context->headerSize);

		//
		//  Update the buffer pointers and MDL address, mark we have changed
		//  something.
		//
		DbgPrint("[PREREAD] Cambio buffer tras offset");
		iopb->Parameters.Read.ReadBuffer = newBuf;
		iopb->Parameters.Read.MdlAddress = newMdl;
		FltSetCallbackDataDirty(Data);

		//
		//  Pass state to our post-operation callback.
		//

		p2pCtx->SwappedBuffer = newBuf;
		p2pCtx->VolCtx = volCtx;
		p2pCtx->StreamCtx = context;

		*CompletionContext = p2pCtx;

		//
		//  Return we want a post-operation callback
		//

		retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		DbgPrint("[PREREAD] retValue es Success with");
	}
	finally {

		//
		//  If we don't want a post-operation callback, then cleanup state.
		//

		if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK) {

			if (newBuf != NULL) {

				FltFreePoolAlignedWithTag(FltObjects->Instance,
					newBuf,
					DRONEFS_TAG);
			}

			if (newMdl != NULL) {

				IoFreeMdl(newMdl);
			}

			if (volCtx != NULL) {

				FltReleaseContext(volCtx);
			}

			if (context != NULL) {

				FltReleaseContext(context);
			}
		}

	}

	return retValue;
}




FLT_POSTOP_CALLBACK_STATUS
DroneFSPostRead(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

This routine does postRead buffer swap handling

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The completion context set in the pre-operation routine.

Flags - Denotes whether the completion is successful or is being drained.

Return Value:

FLT_POSTOP_FINISHED_PROCESSING
FLT_POSTOP_MORE_PROCESSING_REQUIRED

--*/
{
	PVOID origBuf;
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
	PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;
	BOOLEAN cleanupAllocatedBuffer = TRUE;

	DbgPrint("[POSTREAD]Inicio: %lu", (ULONG)Data->IoStatus.Information);
	//
	//  This system won't draining an operation with swapped buffers, verify
	//  the draining flag is not set.
	//
	

	FLT_ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));
	DbgPrint("[POSTREAD]No es draining");

	try {

		//
		//  If the operation failed or the count is zero, there is no data to
		//  copy so just return now.
		//

		if (!NT_SUCCESS(Data->IoStatus.Status) ||
			(Data->IoStatus.Information == 0)) {

			LOG_PRINT(LOGFL_READ,
				("SwapBuffers!SwapPostReadBuffers:            %wZ newB=%p No data read, status=%x, info=%Iu\n",
					&p2pCtx->VolCtx->Name,
					p2pCtx->SwappedBuffer,
					Data->IoStatus.Status,
					Data->IoStatus.Information));

			leave;
		}

		//
		//  We need to copy the read data back into the users buffer.  Note
		//  that the parameters passed in are for the users original buffers
		//  not our swapped buffers.
		//
		//DbgPrint("[POSTREAD]Inicio: %lu", (ULONG)Data->IoStatus.Information);

		if (iopb->Parameters.Read.MdlAddress != NULL) {

			//
			//  This should be a simple MDL. We don't expect chained MDLs
			//  this high up the stack
			//

			FLT_ASSERT(((PMDL)iopb->Parameters.Read.MdlAddress)->Next == NULL);

			//
			//  Since there is a MDL defined for the original buffer, get a
			//  system address for it so we can copy the data back to it.
			//  We must do this because we don't know what thread context
			//  we are in.
			//

			origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Read.MdlAddress,
				NormalPagePriority | MdlMappingNoExecute);

			if (origBuf == NULL) {

				LOG_PRINT(LOGFL_ERRORS,
					("SwapBuffers!SwapPostReadBuffers:            %wZ Failed to get system address for MDL: %p\n",
						&p2pCtx->VolCtx->Name,
						iopb->Parameters.Read.MdlAddress));

				//
				//  If we failed to get a SYSTEM address, mark that the read
				//  failed and return.
				//

				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Information = 0;
				leave;
			}

		}
		else if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ||
			FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION)) {

			//
			//  If this is a system buffer, just use the given address because
			//      it is valid in all thread contexts.
			//  If this is a FASTIO operation, we can just use the
			//      buffer (inside a try/except) since we know we are in
			//      the correct thread context (you can't pend FASTIO's).
			//

			origBuf = iopb->Parameters.Read.ReadBuffer;


		}
		else {

			//
			//  They don't have a MDL and this is not a system buffer
			//  or a fastio so this is probably some arbitrary user
			//  buffer.  We can not do the processing at DPC level so
			//  try and get to a safe IRQL so we can do the processing.
			//
			DbgPrint("[POSTREAD] aqui leo (postread user): %lu", (ULONG)Data->IoStatus.Information);

			if (FltDoCompletionProcessingWhenSafe(Data,
				FltObjects,
				CompletionContext,
				Flags,
				DroneFSPostReadWhenSafe,
				&retValue)) {

				//
				//  This operation has been moved to a safe IRQL, the called
				//  routine will do (or has done) the freeing so don't do it
				//  in our routine.
				//

				/*LARGE_INTEGER timeout;
				int miliSec = -10000;
				timeout.QuadPart = miliSec;
				timeout.QuadPart *= 10000;

				DbgPrint("[POSTREAD]Starting timeout POSTREAD-2");
				KeDelayExecutionThread(KernelMode, FALSE, &timeout);*/

				cleanupAllocatedBuffer = FALSE;

			}
			else {

				//
				//  We are in a state where we can not get to a safe IRQL and
				//  we do not have a MDL.  There is nothing we can do to safely
				//  copy the data back to the users buffer, fail the operation
				//  and return.  This shouldn't ever happen because in those
				//  situations where it is not safe to post, we should have
				//  a MDL.
				//

				LOG_PRINT(LOGFL_ERRORS,
					("SwapBuffers!SwapPostReadBuffers:            %wZ Unable to post to a safe IRQL\n",
						&p2pCtx->VolCtx->Name));

				Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
				Data->IoStatus.Information = 0;
			}

			leave;
		}

		//
		//  We either have a system buffer or this is a fastio operation
		//  so we are in the proper context.  Copy the data handling an
		//  exception.
		//

		try {
			DbgPrint("[POSTREAD] aqui leo (postread system): %lu", (ULONG)Data->IoStatus.Information);

			RtlCopyMemory(origBuf,
				p2pCtx->SwappedBuffer,
				Data->IoStatus.Information);


			if (FltDoCompletionProcessingWhenSafe(Data,
				FltObjects,
				CompletionContext,
				Flags,
				DroneFSPostReadWhenSafe,
				&retValue)) {

				//
				//  This operation has been moved to a safe IRQL, the called
				//  routine will do (or has done) the freeing so don't do it
				//  in our routine.
				//

				cleanupAllocatedBuffer = FALSE;

			}
			else {

				//
				//  We are in a state where we can not get to a safe IRQL and
				//  we do not have a MDL.  There is nothing we can do to safely
				//  copy the data back to the users buffer, fail the operation
				//  and return.  This shouldn't ever happen because in those
				//  situations where it is not safe to post, we should have
				//  a MDL.
				//

				LOG_PRINT(LOGFL_ERRORS,
					("SwapBuffers!SwapPostReadBuffers:            %wZ Unable to post to a safe IRQL\n",
						&p2pCtx->VolCtx->Name));

				Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
				Data->IoStatus.Information = 0;
			}

			leave;


		} except(EXCEPTION_EXECUTE_HANDLER) {

			//
			//  The copy failed, return an error, failing the operation.
			//

			Data->IoStatus.Status = GetExceptionCode();
			Data->IoStatus.Information = 0;

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPostReadBuffers:            %wZ Invalid user buffer, oldB=%p, status=%x\n",
					&p2pCtx->VolCtx->Name,
					origBuf,
					Data->IoStatus.Status));
		}

	}
	finally {

		//
		//  If we are supposed to, cleanup the allocated memory and release
		//  the volume context.  The freeing of the MDL (if there is one) is
		//  handled by FltMgr.
		//

		if (cleanupAllocatedBuffer) {

			LOG_PRINT(LOGFL_READ,
				("SwapBuffers!SwapPostReadBuffers:            %wZ newB=%p info=%Iu Freeing\n",
					&p2pCtx->VolCtx->Name,
					p2pCtx->SwappedBuffer,
					Data->IoStatus.Information));

			FltFreePoolAlignedWithTag(FltObjects->Instance,
				p2pCtx->SwappedBuffer,
				DRONEFS_TAG);

			FltReleaseContext(p2pCtx->VolCtx);

			FltReleaseContext(p2pCtx->StreamCtx);

			ExFreeToNPagedLookasideList(&Pre2PostContextList,
				p2pCtx);
		}
	}
	return retValue;
}


FLT_POSTOP_CALLBACK_STATUS
DroneFSPostReadWhenSafe(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

We had an arbitrary users buffer without a MDL so we needed to get
to a safe IRQL so we could lock it and then copy the data.

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - Contains state from our PreOperation callback

Flags - Denotes whether the completion is successful or is being drained.

Return Value:

FLT_POSTOP_FINISHED_PROCESSING - This is always returned.

--*/
{
	FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;
	PVOID origBuf;
	NTSTATUS status;
	PDRONEFS_NOTIFICATION notification = NULL;
	PDRONEFS_REPLY reply = NULL;
	PDRONEFS_NOTIFICATION notificationHeader = NULL;
	PDRONEFS_REPLY replyHeader = NULL;
	ULONG replyLength;
	ULONG replyHeaderLength;
	ULONG filePointer = 0;
	ULONG difference = 0;
	ULONG fileSize = 0;
	ULONG bufferSize = 0;
	ULONG headerSize;


	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	FLT_ASSERT(Data->IoStatus.Information != 0);

	//
	//  This is some sort of user buffer without a MDL, lock the user buffer
	//  so we can access it.  This will create a MDL for it.
	//

	status = FltLockUserBuffer(Data);

	if (!NT_SUCCESS(status)) {

		LOG_PRINT(LOGFL_ERRORS,
			("SwapBuffers!SwapPostReadBuffersWhenSafe:    %wZ Could not lock user buffer, oldB=%p, status=%x\n",
				&p2pCtx->VolCtx->Name,
				iopb->Parameters.Read.ReadBuffer,
				status));

		//
		//  If we can't lock the buffer, fail the operation
		//

		Data->IoStatus.Status = status;
		Data->IoStatus.Information = 0;

	}
	else {

		//
		//  Get a system address for this buffer.
		//

		origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Read.MdlAddress,
			NormalPagePriority | MdlMappingNoExecute);

		if (origBuf == NULL) {

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPostReadBuffersWhenSafe:    %wZ Failed to get system address for MDL: %p\n",
					&p2pCtx->VolCtx->Name,
					iopb->Parameters.Read.MdlAddress));

			//
			//  If we couldn't get a SYSTEM buffer address, fail the operation
			//

			Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			Data->IoStatus.Information = 0;

		}
		else {


			DbgPrint("[POSTREADSAFE] aqui leo (when safe): %lu", (ULONG)Data->IoStatus.Information);

			try {
				RtlCopyMemory(origBuf,
					p2pCtx->SwappedBuffer,
					Data->IoStatus.Information);
				DbgPrint("[POSTREADSAFE]origBuf: %s", origBuf);
			}except(EXCEPTION_EXECUTE_HANDLER) {

				//  The copy failed, return an error, failing the operation.
				DbgPrint("[POSTREADSAFE]Copy failed");
			}
			
			
			notificationHeader = ExAllocatePoolWithTag(NonPagedPool,
				sizeof(DRONEFS_NOTIFICATION),
				'nhcS');

			replyHeader = ExAllocatePoolWithTag(NonPagedPool,
				sizeof(DRONEFS_REPLY),
				'rhcS');

			//
			//SENDING THE HEADER TO THE USER APP TO CREATE THE CIPHER KEY
			//
			headerSize = p2pCtx->StreamCtx->headerSize;
			DbgPrint("[POSTREADSAFE]Header size: %lu", headerSize);

			PUCHAR headerBuffer = ExAllocatePoolWithTag(NonPagedPool,
				headerSize,
				'hacS');
			RtlCopyMemory(headerBuffer,
				&p2pCtx->StreamCtx->Header,
				headerSize);
			DbgPrint("[POSTREADSAFE]Header buffer: %s", headerBuffer);

			notificationHeader->BytesToScan = headerSize;
			notificationHeader->Reserved = NOTIFICATION_HEADER;

			RtlCopyMemory(&notificationHeader->Contents,
				headerBuffer,
				notificationHeader->BytesToScan);

			DbgPrint("[DroneFSFilter]Sending message");
			replyHeaderLength = sizeof(DRONEFS_REPLY);
			status = FltSendMessage(DroneFSData.Filter,
				&DroneFSData.ClientPort,
				notificationHeader,
				sizeof(DRONEFS_NOTIFICATION),
				replyHeader,
				&replyHeaderLength,
				NULL);

			if (STATUS_SUCCESS == status) {
				DbgPrint("[DroneFSFilter]Reply obtenido");
			}
			else {
				//
				//  Couldn't send message. This sample will let the i/o through.
				//
				DbgPrint("!!! [DroneFSFilter] --- couldn't send message to user-mode to scan file, status 0x%X\n", status);
			}
			if (headerBuffer != NULL) {

				ExFreePoolWithTag(headerBuffer, 'hacS');
			}

			if (notificationHeader != NULL) {

				ExFreePoolWithTag(notificationHeader, 'nhcS');
			}

			if (replyHeader != NULL) {

				ExFreePoolWithTag(replyHeader, 'rhcS');
			}


			if (readModFlag) {
				////////////////////////////////////////////////
				//TRYING TO SEND BUFFER TO THE USER APP
				////////////////////////////////////////////////

				//DbgPrint("[DroneFSFilter]Check if clientport");
				if (DroneFSData.ClientPort != NULL) {



						//
						//  In a production-level filter, we would actually let user mode scan the file directly.
						//  Allocating & freeing huge amounts of non-paged pool like this is not very good for system perf.
						//  This is just a sample!
						//
						//DbgPrint("[DroneFSFilter]Allocating pool for notification");

						//iNewSize = FIELD_OFFSET(DRONEFS_NOTIFICATION, Contents[DRONEFS_READ_BUFFER_SIZE]);

						notification = ExAllocatePoolWithTag(NonPagedPool,
							sizeof(DRONEFS_NOTIFICATION),
							'nacS');

						reply = ExAllocatePoolWithTag(NonPagedPool,
							sizeof(DRONEFS_REPLY),
							'racS');

						

						if (notification == NULL) {

							DbgPrint("[DroneFSFilter]Notification null");
						}
						else {

							// PREPARE DECIPHER
							fileSize = (ULONG)Data->IoStatus.Information;
							PUCHAR bufferWithOffset = ExAllocatePoolWithTag(NonPagedPool,
								Data->IoStatus.Information,
								'oacS');

							RtlCopyMemory(bufferWithOffset,
								p2pCtx->SwappedBuffer,
								Data->IoStatus.Information);

							PUCHAR bufferDeciphered = ExAllocatePoolWithTag(NonPagedPool,
								Data->IoStatus.Information,
								'facS');

							while (filePointer < fileSize) {

								//Calculamos la diferencia entre el tamaño del fichero y la posicion actual
								difference = fileSize - filePointer;
								//Si la diferencia es menor que el tamaño del buffer, no es necesario rellenarlo entero
								notification->BytesToScan = min(difference, DRONEFS_READ_BUFFER_SIZE);
								bufferSize = notification->BytesToScan;

								//
								//  The buffer can be a raw user buffer. Protect access to it
								//
								

								try {

									DbgPrint("[DroneFSFilter]Copy buffer->notification");
									RtlCopyMemory(&notification->Contents,
										bufferWithOffset + filePointer,
										notification->BytesToScan);
									//
									//  Send message to user mode to indicate it should scan the buffer.
									//  We don't have to synchronize between the send and close of the handle
									//  as FltSendMessage takes care of that.
									//
									notification->Reserved = NOTIFICATION_READ;
									replyLength = sizeof(DRONEFS_REPLY);

									DbgPrint("[DroneFSFilter]Sending message");
									status = FltSendMessage(DroneFSData.Filter,
										&DroneFSData.ClientPort,
										notification,
										sizeof(DRONEFS_NOTIFICATION),
										reply,
										&replyLength,
										NULL);

									if (STATUS_SUCCESS == status) {

										//replyBytes = reply->BytesToScan;
										//DbgPrint("replyBytesScan=%lu", replyBytes);
										DbgPrint("[DroneFSFilter]Reply obtenido");

										RtlCopyMemory((bufferDeciphered + filePointer),
											&reply->Contents,
											notification->BytesToScan);
										DbgPrint("[POSTREADSAFE]filepointer=%lu", filePointer);
										DbgPrint("[POSTREADSAFE]filesize=%lu", fileSize);
										DbgPrint("[POSTREADSAFE]notifContents[0]: %s", notification->Contents);
										DbgPrint("[POSTREADSAFE]bufferDecip[0+filep]: %s", (bufferDeciphered + filePointer));
									}
									else {

										//
										//  Couldn't send message. This sample will let the i/o through.
										//

										DbgPrint("!!! [DroneFSFilter] --- couldn't send message to user-mode to scan file, status 0x%X\n", status);
									}



								} except(EXCEPTION_EXECUTE_HANDLER) {

									//
									//  Error accessing buffer. Complete i/o with failure
									//
									DbgPrint("[DroneFSFilter]Error accessing buffer");
								}

								filePointer += bufferSize;
							}

							//DbgPrint("Copiando buffer descifrado con longitud: %lu", (ULONG)Data->IoStatus.Information);
							//DbgPrint("[POSTREAD]bufferDecip[0]: %s", &bufferDeciphered[0]);
							try {
								RtlCopyMemory(origBuf,
									bufferDeciphered,
									Data->IoStatus.Information);
								DbgPrint("[POSTREADSAFE]bufferDecip: %s", bufferDeciphered);
								DbgPrint("[POSTREADSAFE]origBuf: %s", bufferDeciphered);
							}except(EXCEPTION_EXECUTE_HANDLER) {

								//  The copy failed, return an error, failing the operation.
								DbgPrint("[POSTREADSAFE]Copy failed");
							}
							/*LARGE_INTEGER timeout;  
							int miliSec = -10000; 
							timeout.QuadPart = miliSec;
							timeout.QuadPart *= 10000;

							DbgPrint("[POSTREADSAFE]Starting timeout POSTREADSAFE");
							KeDelayExecutionThread(KernelMode, FALSE, &timeout);*/

							if (bufferDeciphered != NULL) {

								ExFreePoolWithTag(bufferDeciphered, 'facS');
							}

							if (bufferWithOffset != NULL) {

								ExFreePoolWithTag(bufferWithOffset, 'oacS');
							}	

					}
					if (notification != NULL) {

						ExFreePoolWithTag(notification, 'nacS');
					}

					if (reply != NULL) {

						ExFreePoolWithTag(reply, 'racS');
					}
				}
			}
			/*if (headerBuffer != NULL) {

				ExFreePoolWithTag(headerBuffer, 'hacS');
			}

			if (notificationHeader != NULL) {

				ExFreePoolWithTag(notificationHeader, 'nhcS');
			}

			if (replyHeader != NULL) {

				ExFreePoolWithTag(replyHeader, 'rhcS');
			}*/

		}
	}
	

	//
	//  Free allocated memory and release the volume context
	//

	LOG_PRINT(LOGFL_READ,
		("SwapBuffers!SwapPostReadBuffersWhenSafe:    %wZ newB=%p info=%Iu Freeing\n",
			&p2pCtx->VolCtx->Name,
			p2pCtx->SwappedBuffer,
			Data->IoStatus.Information));



	FltFreePoolAlignedWithTag(FltObjects->Instance,
		p2pCtx->SwappedBuffer,
		DRONEFS_TAG);


	FltReleaseContext(p2pCtx->VolCtx);


	FltReleaseContext(p2pCtx->StreamCtx);


	ExFreeToNPagedLookasideList(&Pre2PostContextList,p2pCtx);

	returnStatus = FLT_POSTOP_FINISHED_PROCESSING;


	return returnStatus;
}


FLT_PREOP_CALLBACK_STATUS
SwapPreDirCtrlBuffers(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

This routine demonstrates how to swap buffers for the Directory Control
operations.  The reason this routine is here is because directory change
notifications are long lived and this allows you to see how FltMgr
handles long lived IRP operations that have swapped buffers when the
mini-filter is unloaded.  It does this by canceling the IRP.

Note that it handles all errors by simply not doing the
buffer swap.

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - Receives the context that will be passed to the
post-operation callback.

Return Value:

FLT_PREOP_SUCCESS_WITH_CALLBACK - we want a postOpeation callback
FLT_PREOP_SUCCESS_NO_CALLBACK - we don't want a postOperation callback

--*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PVOID newBuf = NULL;
	PMDL newMdl = NULL;
	PVOLUME_CONTEXT volCtx = NULL;
	PPRE_2_POST_CONTEXT p2pCtx;
	NTSTATUS status;

	try {

		//
		//  If they are trying to get ZERO bytes, then don't do anything and
		//  we don't need a post-operation callback.
		//

		if (iopb->Parameters.DirectoryControl.QueryDirectory.Length == 0) {

			leave;
		}

		//
		//  Get our volume context.  If we can't get it, just return.
		//

		status = FltGetVolumeContext(FltObjects->Filter,
			FltObjects->Volume,
			&volCtx);

		if (!NT_SUCCESS(status)) {

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPreDirCtrlBuffers:          Error getting volume context, status=%x\n",
					status));

			leave;
		}

		//
		//  Allocate nonPaged memory for the buffer we are swapping to.
		//  If we fail to get the memory, just don't swap buffers on this
		//  operation.
		//

		newBuf = ExAllocatePoolWithTag(NonPagedPool,
			iopb->Parameters.DirectoryControl.QueryDirectory.Length,
			DRONEFS_TAG);

		if (newBuf == NULL) {

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPreDirCtrlBuffers:          %wZ Failed to allocate %d bytes of memory.\n",
					&volCtx->Name,
					iopb->Parameters.DirectoryControl.QueryDirectory.Length));

			leave;
		}

		//
		//  Zero the new buffer so as not to potentially expose any sensitive
		//  data to the user.
		//

		RtlZeroMemory(newBuf, iopb->Parameters.DirectoryControl.QueryDirectory.Length);


		//
		//  We need to build a MDL because Directory Control Operations are always IRP operations.  
		//


		//
		//  Allocate a MDL for the new allocated memory.  If we fail
		//  the MDL allocation then we won't swap buffer for this operation
		//

		newMdl = IoAllocateMdl(newBuf,
			iopb->Parameters.DirectoryControl.QueryDirectory.Length,
			FALSE,
			FALSE,
			NULL);

		if (newMdl == NULL) {

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPreDirCtrlBuffers:          %wZ Failed to allocate MDL.\n",
					&volCtx->Name));

			leave;
		}

		//
		//  setup the MDL for the non-paged pool we just allocated
		//

		MmBuildMdlForNonPagedPool(newMdl);

		//
		//  We are ready to swap buffers, get a pre2Post context structure.
		//  We need it to pass the volume context and the allocate memory
		//  buffer to the post operation callback.
		//

		p2pCtx = ExAllocateFromNPagedLookasideList(&Pre2PostContextList);

		if (p2pCtx == NULL) {

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPreDirCtrlBuffers:          %wZ Failed to allocate pre2Post context structure\n",
					&volCtx->Name));

			leave;
		}

		//
		//  Log that we are swapping
		//

		LOG_PRINT(LOGFL_DIRCTRL,
			("SwapBuffers!SwapPreDirCtrlBuffers:          %wZ newB=%p newMdl=%p oldB=%p oldMdl=%p len=%d\n",
				&volCtx->Name,
				newBuf,
				newMdl,
				iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer,
				iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
				iopb->Parameters.DirectoryControl.QueryDirectory.Length));

		//
		//  Update the buffer pointers and MDL address
		//

		iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = newBuf;
		iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress = newMdl;
		FltSetCallbackDataDirty(Data);

		//
		//  Pass state to our post-operation callback.
		//

		p2pCtx->SwappedBuffer = newBuf;
		p2pCtx->VolCtx = volCtx;

		*CompletionContext = p2pCtx;

		//
		//  Return we want a post-operation callback
		//

		retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	}
	finally {

		//
		//  If we don't want a post-operation callback, then cleanup state.
		//

		if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK) {

			if (newBuf != NULL) {

				ExFreePool(newBuf);
			}

			if (newMdl != NULL) {

				IoFreeMdl(newMdl);
			}

			if (volCtx != NULL) {

				FltReleaseContext(volCtx);
			}
		}
	}

	return retValue;
}


FLT_POSTOP_CALLBACK_STATUS
SwapPostDirCtrlBuffers(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

This routine does the post Directory Control buffer swap handling.

Arguments:

This routine does postRead buffer swap handling
Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The completion context set in the pre-operation routine.

Flags - Denotes whether the completion is successful or is being drained.

Return Value:

FLT_POSTOP_FINISHED_PROCESSING
FLT_POSTOP_MORE_PROCESSING_REQUIRED

--*/
{
	PVOID origBuf;
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
	PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;
	BOOLEAN cleanupAllocatedBuffer = TRUE;

	//
	//  Verify we are not draining an operation with swapped buffers
	//

	FLT_ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));

	try {

		//
		//  If the operation failed or the count is zero, there is no data to
		//  copy so just return now.
		//

		if (!NT_SUCCESS(Data->IoStatus.Status) ||
			(Data->IoStatus.Information == 0)) {

			LOG_PRINT(LOGFL_DIRCTRL,
				("SwapBuffers!SwapPostDirCtrlBuffers:         %wZ newB=%p No data read, status=%x, info=%Ix\n",
					&p2pCtx->VolCtx->Name,
					p2pCtx->SwappedBuffer,
					Data->IoStatus.Status,
					Data->IoStatus.Information));

			leave;
		}

		//
		//  We need to copy the read data back into the users buffer.  Note
		//  that the parameters passed in are for the users original buffers
		//  not our swapped buffers
		//

		if (iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress != NULL) {

			//
			//  There is a MDL defined for the original buffer, get a
			//  system address for it so we can copy the data back to it.
			//  We must do this because we don't know what thread context
			//  we are in.
			//

			origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
				NormalPagePriority | MdlMappingNoExecute);

			if (origBuf == NULL) {

				LOG_PRINT(LOGFL_ERRORS,
					("SwapBuffers!SwapPostDirCtrlBuffers:         %wZ Failed to get system address for MDL: %p\n",
						&p2pCtx->VolCtx->Name,
						iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress));

				//
				//  If we failed to get a SYSTEM address, mark that the
				//  operation failed and return.
				//

				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Information = 0;
				leave;
			}

		}
		else if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ||
			FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION)) {

			//
			//  If this is a system buffer, just use the given address because
			//      it is valid in all thread contexts.
			//  If this is a FASTIO operation, we can just use the
			//      buffer (inside a try/except) since we know we are in
			//      the correct thread context.
			//

			origBuf = iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;

		}
		else {

			//
			//  They don't have a MDL and this is not a system buffer
			//  or a fastio so this is probably some arbitrary user
			//  buffer.  We can not do the processing at DPC level so
			//  try and get to a safe IRQL so we can do the processing.
			//

			if (FltDoCompletionProcessingWhenSafe(Data,
				FltObjects,
				CompletionContext,
				Flags,
				SwapPostDirCtrlBuffersWhenSafe,
				&retValue)) {

				//
				//  This operation has been moved to a safe IRQL, the called
				//  routine will do (or has done) the freeing so don't do it
				//  in our routine.
				//

				cleanupAllocatedBuffer = FALSE;

			}
			else {

				//
				//  We are in a state where we can not get to a safe IRQL and
				//  we do not have a MDL.  There is nothing we can do to safely
				//  copy the data back to the users buffer, fail the operation
				//  and return.  This shouldn't ever happen because in those
				//  situations where it is not safe to post, we should have
				//  a MDL.
				//

				LOG_PRINT(LOGFL_ERRORS,
					("SwapBuffers!SwapPostDirCtrlBuffers:         %wZ Unable to post to a safe IRQL\n",
						&p2pCtx->VolCtx->Name));

				Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
				Data->IoStatus.Information = 0;
			}

			leave;
		}

		//
		//  We either have a system buffer or this is a fastio operation
		//  so we are in the proper context.  Copy the data handling an
		//  exception.
		//
		//  NOTE:  Due to a bug in FASTFAT where it is returning the wrong
		//         length in the information field (it is sort) we are always
		//         going to copy the original buffer length. Please note that
		//         this is a potential security problem because we will copy 
		//         more than what was touched by the FS. So we have to make 
		//         sure the buffer is clean before calling into the FS or we 
		//         risk exposing sensitive data to the user.
		//

		try {

			RtlCopyMemory(origBuf,
				p2pCtx->SwappedBuffer,
				/*Data->IoStatus.Information*/
				iopb->Parameters.DirectoryControl.QueryDirectory.Length);

		} except(EXCEPTION_EXECUTE_HANDLER) {

			Data->IoStatus.Status = GetExceptionCode();
			Data->IoStatus.Information = 0;

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPostDirCtrlBuffers:         %wZ Invalid user buffer, oldB=%p, status=%x, info=%Iu\n",
					&p2pCtx->VolCtx->Name,
					origBuf,
					Data->IoStatus.Status,
					Data->IoStatus.Information));
		}

	}
	finally {

		//
		//  If we are supposed to, cleanup the allocate memory and release
		//  the volume context.  The freeing of the MDL (if there is one) is
		//  handled by FltMgr.
		//

		if (cleanupAllocatedBuffer) {

			LOG_PRINT(LOGFL_DIRCTRL,
				("SwapBuffers!SwapPostDirCtrlBuffers:         %wZ newB=%p info=%Iu Freeing\n",
					&p2pCtx->VolCtx->Name,
					p2pCtx->SwappedBuffer,
					Data->IoStatus.Information));

			ExFreePool(p2pCtx->SwappedBuffer);
			FltReleaseContext(p2pCtx->VolCtx);

			ExFreeToNPagedLookasideList(&Pre2PostContextList,
				p2pCtx);
		}
	}

	return retValue;
}


FLT_POSTOP_CALLBACK_STATUS
SwapPostDirCtrlBuffersWhenSafe(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

We had an arbitrary users buffer without a MDL so we needed to get
to a safe IRQL so we could lock it and then copy the data.

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The buffer we allocated and swapped to

Flags - Denotes whether the completion is successful or is being drained.

Return Value:

FLT_POSTOP_FINISHED_PROCESSING - This is always returned.

--*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;
	PVOID origBuf;
	NTSTATUS status;


	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	FLT_ASSERT(Data->IoStatus.Information != 0);

	//
	//  This is some sort of user buffer without a MDL, lock the
	//  user buffer so we can access it
	//

	status = FltLockUserBuffer(Data);

	if (!NT_SUCCESS(status)) {

		LOG_PRINT(LOGFL_ERRORS,
			("SwapBuffers!SwapPostDirCtrlBuffersWhenSafe: %wZ Could not lock user buffer, oldB=%p, status=%x\n",
				&p2pCtx->VolCtx->Name,
				iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer,
				status));

		//
		//  If we can't lock the buffer, fail the operation
		//

		Data->IoStatus.Status = status;
		Data->IoStatus.Information = 0;

	}
	else {

		//
		//  Get a system address for this buffer.
		//

		origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
			NormalPagePriority | MdlMappingNoExecute);

		if (origBuf == NULL) {

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPostDirCtrlBuffersWhenSafe: %wZ Failed to get System address for MDL: %p\n",
					&p2pCtx->VolCtx->Name,
					iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress));

			//
			//  If we couldn't get a SYSTEM buffer address, fail the operation
			//

			Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			Data->IoStatus.Information = 0;

		}
		else {

			//
			//  Copy the data back to the original buffer
			//
			//  NOTE:  Due to a bug in FASTFAT where it is returning the wrong
			//         length in the information field (it is short) we are
			//         always going to copy the original buffer length.
			//

			RtlCopyMemory(origBuf,
				p2pCtx->SwappedBuffer,
				/*Data->IoStatus.Information*/
				iopb->Parameters.DirectoryControl.QueryDirectory.Length);
		}
	}

	//
	//  Free the memory we allocated and return
	//

	LOG_PRINT(LOGFL_DIRCTRL,
		("SwapBuffers!SwapPostDirCtrlBuffersWhenSafe: %wZ newB=%p info=%Iu Freeing\n",
			&p2pCtx->VolCtx->Name,
			p2pCtx->SwappedBuffer,
			Data->IoStatus.Information));

	ExFreePool(p2pCtx->SwappedBuffer);
	FltReleaseContext(p2pCtx->VolCtx);

	ExFreeToNPagedLookasideList(&Pre2PostContextList,
		p2pCtx);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
DroneFSPreWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

This routine demonstrates how to swap buffers for the WRITE operation.

Note that it handles all errors by simply not doing the buffer swap.

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - Receives the context that will be passed to the
post-operation callback.

Return Value:

FLT_PREOP_SUCCESS_WITH_CALLBACK - we want a postOpeation callback
FLT_PREOP_SUCCESS_NO_CALLBACK - we don't want a postOperation callback
FLT_PREOP_COMPLETE -
--*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PVOID newBuf = NULL;
	PMDL newMdl = NULL;
	PVOLUME_CONTEXT volCtx = NULL;
	PPRE_2_POST_CONTEXT p2pCtx;
	PVOID origBuf;
	NTSTATUS status;
	ULONG writeLen = iopb->Parameters.Write.Length;
	//PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	PDRONEFS_NOTIFICATION notification = NULL;
	PDRONEFS_REPLY reply = NULL;
	ULONG replyLength;
	ULONG filePointer = 0;
	ULONG difference = 0;
	ULONG fileSize = 0;
	ULONG bufferSize = 0;
	PDRONEFS_STREAM_CONTEXT context = NULL;
	BOOLEAN isMdl = FALSE;


	status = FltGetStreamContext(FltObjects->Instance,
		FltObjects->FileObject,
		&context);

	/*PDRONEFS_STREAM_HANDLE_CONTEXT context = NULL;

	status = FltGetStreamHandleContext(FltObjects->Instance,
		FltObjects->FileObject,
		&context);*/


	if (!NT_SUCCESS(status)) {

		//
		//  We are not interested in this file
		//
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!context->hasHeader) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	
	try {

		//
		//  If they are trying to write ZERO bytes, then don't do anything and
		//  we don't need a post-operation callback.
		//

		if (writeLen == 0) {

			leave;
		}

		DbgPrint("[PREWRITE]Length: %d", writeLen);
		//
		//  Get our volume context so we can display our volume name in the
		//  debug output.
		//

		status = FltGetVolumeContext(FltObjects->Filter,
			FltObjects->Volume,
			&volCtx);

		if (!NT_SUCCESS(status)) {

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPreWriteBuffers:            Error getting volume context, status=%x\n",
					status));

			leave;
		}

		//
		//  If this is a non-cached I/O we need to round the length up to the
		//  sector size for this device.  We must do this because the file
		//  systems do this and we need to make sure our buffer is as big
		//  as they are expecting.
		//

		if (FlagOn(IRP_NOCACHE, iopb->IrpFlags)) {

			writeLen = (ULONG)ROUND_TO_SIZE(writeLen, volCtx->SectorSize);
			DbgPrint("[PREWRITE]Length rounded: %d", writeLen);
		}

		//
		//  Allocate aligned nonPaged memory for the buffer we are swapping
		//  to. This is really only necessary for noncached IO but we always
		//  do it here for simplification. If we fail to get the memory, just
		//  don't swap buffers on this operation.
		//

		newBuf = FltAllocatePoolAlignedWithTag(FltObjects->Instance,
			NonPagedPool,
			(SIZE_T)writeLen,
			DRONEFS_TAG);

		if (newBuf == NULL) {

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPreWriteBuffers:            %wZ Failed to allocate %d bytes of memory.\n",
					&volCtx->Name,
					writeLen));

			leave;
		}

		//
		//  We only need to build a MDL for IRP operations.  We don't need to
		//  do this for a FASTIO operation because it is a waste of time since
		//  the FASTIO interface has no parameter for passing the MDL to the
		//  file system.
		//

		if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION)) {

			//
			//  Allocate a MDL for the new allocated memory.  If we fail
			//  the MDL allocation then we won't swap buffer for this operation
			//


			newMdl = IoAllocateMdl(newBuf,
				writeLen,
				FALSE,
				FALSE,
				NULL);

			if (newMdl == NULL) {

				LOG_PRINT(LOGFL_ERRORS,
					("SwapBuffers!SwapPreWriteBuffers:            %wZ Failed to allocate MDL.\n",
						&volCtx->Name));

				leave;
			}

			//
			//  setup the MDL for the non-paged pool we just allocated
			//

			MmBuildMdlForNonPagedPool(newMdl);
		}

		//
		//  If the users original buffer had a MDL, get a system address.
		//

		if (iopb->Parameters.Write.MdlAddress != NULL) {

			//
			//  This should be a simple MDL. We don't expect chained MDLs
			//  this high up the stack
			//

			FLT_ASSERT(((PMDL)iopb->Parameters.Write.MdlAddress)->Next == NULL);

			origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Write.MdlAddress,
				NormalPagePriority | MdlMappingNoExecute);

			DbgPrint("[PREWRITE]El cambio de buffer es MDL");

			isMdl = TRUE;

			if (origBuf == NULL) {

				LOG_PRINT(LOGFL_ERRORS,
					("SwapBuffers!SwapPreWriteBuffers:            %wZ Failed to get system address for MDL: %p\n",
						&volCtx->Name,
						iopb->Parameters.Write.MdlAddress));

				//
				//  If we could not get a system address for the users buffer,
				//  then we are going to fail this operation.
				//

				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Information = 0;
				retValue = FLT_PREOP_COMPLETE;
				leave;
			}

		}
		else {

			//
			//  There was no MDL defined, use the given buffer address.
			//

			origBuf = iopb->Parameters.Write.WriteBuffer;

			DbgPrint("[PREWRITE]El cambio de buffer es WriteBuffer");
		}

		//
		//  Copy the memory, we must do this inside the try/except because we
		//  may be using a users buffer address
		//

		try {
			
			//iopb->Parameters.Write.ByteOffset.QuadPart = context->headerSize;
			RtlCopyMemory(newBuf,
				origBuf,
				writeLen);
			
			if (writeModFlag && !isMdl) {

				LARGE_INTEGER largeHeaderSize = { 0 };
				largeHeaderSize.QuadPart = context->headerSize;
				if (iopb->Parameters.Write.ByteOffset.QuadPart == 0) {
					iopb->Parameters.Write.ByteOffset = largeHeaderSize;
				}
				

				DbgPrint("[PREWRITE]Dentro del if");
				////////////////////////////////////////////////
				//TRYING TO SEND BUFFER TO THE USER APP
				////////////////////////////////////////////////

				DbgPrint("[DroneFSFilter]Check if clientport");
				if (DroneFSData.ClientPort != NULL) {


					//
					//  In a production-level filter, we would actually let user mode scan the file directly.
					//  Allocating & freeing huge amounts of non-paged pool like this is not very good for system perf.
					//  This is just a sample!
					//

					notification = ExAllocatePoolWithTag(NonPagedPool,
						sizeof(DRONEFS_NOTIFICATION),
						'nacS');

					reply = ExAllocatePoolWithTag(NonPagedPool,
						sizeof(DRONEFS_REPLY),
						'racS');

					if (notification == NULL) {

						DbgPrint("[DroneFSFilter]Notification null");
					}
					else {

						fileSize = writeLen;
						DbgPrint("[w]filesize=%lu", fileSize);
						PUCHAR bufferWithOffset = ExAllocatePoolWithTag(NonPagedPool,
							writeLen,
							'oacS');

						RtlCopyMemory(bufferWithOffset,
							origBuf,
							writeLen);

						PUCHAR bufferCiphered = ExAllocatePoolWithTag(NonPagedPool,
							writeLen,
							'facS');

						

						while (filePointer < fileSize) {


							//Calculamos la diferencia entre el tamaño del fichero y la posicion actual
							difference = fileSize - filePointer;
							//Si la diferencia es menor que el tamaño del buffer, no es necesario rellenarlo entero
							notification->BytesToScan = min(difference, DRONEFS_READ_BUFFER_SIZE);
							bufferSize = notification->BytesToScan;


							//
							//  The buffer can be a raw user buffer. Protect access to it
							//
							try {

								DbgPrint("[DroneFSFilter]Copy buffer->notification");
								RtlCopyMemory(&notification->Contents,
									bufferWithOffset + filePointer,
									notification->BytesToScan);
								//
								//  Send message to user mode to indicate it should scan the buffer.
								//  We don't have to synchronize between the send and close of the handle
								//  as FltSendMessage takes care of that.
								//

								replyLength = sizeof(DRONEFS_REPLY);

								//READ or WRITE (100 or 200)

								notification->Reserved = NOTIFICATION_WRITE;

								DbgPrint("[DroneFSFilter]Sending message");
								status = FltSendMessage(DroneFSData.Filter,
									&DroneFSData.ClientPort,
									notification,
									sizeof(DRONEFS_NOTIFICATION),
									reply,
									&replyLength,
									NULL);

								if (STATUS_SUCCESS == status) {

									//replyBytes = reply->BytesToScan;
									//DbgPrint("replyBytesScan=%lu", replyBytes);
									DbgPrint("[DroneFSFilter]Reply obtenido");

									RtlCopyMemory((bufferCiphered + filePointer),
										&reply->Contents,
										notification->BytesToScan);
									DbgPrint("[w]filepointer=%lu", filePointer);
									DbgPrint("[w]filesize=%lu", fileSize);
									DbgPrint("[PREWRITE]notifContents[0]: %s", notification->Contents);
									DbgPrint("[PREWRITE]bufferCip[0+filep]: %s", (bufferCiphered + filePointer));
								}
								else {

									//
									//  Couldn't send message. This sample will let the i/o through.
									//

									DbgPrint("!!! [DroneFSFilter] --- couldn't send message to user-mode to scan file, status 0x%X\n", status);
								}



							} except(EXCEPTION_EXECUTE_HANDLER) {

								//
								//  Error accessing buffer. Complete i/o with failure
								//
								DbgPrint("[DroneFSFilter]Error accessing buffer");
							}

							filePointer += bufferSize;
						}

						DbgPrint("[w]Cambio buffer");

						try {
							RtlCopyMemory(newBuf,
								bufferCiphered,
								writeLen);
						}except(EXCEPTION_EXECUTE_HANDLER) {

							//  The copy failed, return an error, failing the operation.
							DbgPrint("[w]Copy failed");
						}



						if (notification != NULL) {

							ExFreePoolWithTag(notification, 'nacS');
						}

						if (reply != NULL) {

							ExFreePoolWithTag(reply, 'racS');
						}

						if (bufferCiphered != NULL) {

							ExFreePoolWithTag(bufferCiphered, 'facS');
						}

						if (bufferWithOffset != NULL) {

							ExFreePoolWithTag(bufferWithOffset, 'oacS');
						}


					}

				}

			}


			//DbgPrint("[PREWRITE]Se copia memoria aqui");

		} except(EXCEPTION_EXECUTE_HANDLER) {

			//
			//  The copy failed, return an error, failing the operation.
			//

			Data->IoStatus.Status = GetExceptionCode();
			Data->IoStatus.Information = 0;
			retValue = FLT_PREOP_COMPLETE;

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPreWriteBuffers:            %wZ Invalid user buffer, oldB=%p, status=%x\n",
					&volCtx->Name,
					origBuf,
					Data->IoStatus.Status));

			leave;
		}

		//
		//  We are ready to swap buffers, get a pre2Post context structure.
		//  We need it to pass the volume context and the allocate memory
		//  buffer to the post operation callback.
		//

		p2pCtx = ExAllocateFromNPagedLookasideList(&Pre2PostContextList);

		if (p2pCtx == NULL) {

			LOG_PRINT(LOGFL_ERRORS,
				("SwapBuffers!SwapPreWriteBuffers:            %wZ Failed to allocate pre2Post context structure\n",
					&volCtx->Name));

			leave;
		}

		//
		//  Set new buffers
		//

		LOG_PRINT(LOGFL_WRITE,
			("SwapBuffers!SwapPreWriteBuffers:            %wZ newB=%p newMdl=%p oldB=%p oldMdl=%p len=%d\n",
				&volCtx->Name,
				newBuf,
				newMdl,
				iopb->Parameters.Write.WriteBuffer,
				iopb->Parameters.Write.MdlAddress,
				writeLen));

		iopb->Parameters.Write.WriteBuffer = newBuf;
		iopb->Parameters.Write.MdlAddress = newMdl;
		FltSetCallbackDataDirty(Data);

		//
		//  Pass state to our post-operation callback.
		//

		p2pCtx->SwappedBuffer = newBuf;
		p2pCtx->VolCtx = volCtx;

		*CompletionContext = p2pCtx;

		//
		//  Return we want a post-operation callback
		//

		retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	}
	finally {

		//
		//  If we don't want a post-operation callback, then free the buffer
		//  or MDL if it was allocated.
		//

		if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK) {

			if (newBuf != NULL) {

				FltFreePoolAlignedWithTag(FltObjects->Instance,
					newBuf,
					DRONEFS_TAG);

			}

			if (newMdl != NULL) {

				IoFreeMdl(newMdl);
			}

			if (volCtx != NULL) {

				FltReleaseContext(volCtx);
			}
		}
	}

	if (context != NULL) {

		FltReleaseContext(context);
	}

	return retValue;
}


FLT_POSTOP_CALLBACK_STATUS
DroneFSPostWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:


Arguments:


Return Value:

--*/
{
	PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	LOG_PRINT(LOGFL_WRITE,
		("SwapBuffers!SwapPostWriteBuffers:           %wZ newB=%p info=%Iu Freeing\n",
			&p2pCtx->VolCtx->Name,
			p2pCtx->SwappedBuffer,
			Data->IoStatus.Information));

	//
	//  Free allocate POOL and volume context
	//

	FltFreePoolAlignedWithTag(FltObjects->Instance,
		p2pCtx->SwappedBuffer,
		DRONEFS_TAG);

	FltReleaseContext(p2pCtx->VolCtx);

	ExFreeToNPagedLookasideList(&Pre2PostContextList,
		p2pCtx);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
DfPreSetInfoCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) {
	//UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	NTSTATUS status;
	PDRONEFS_STREAM_CONTEXT context = NULL;
	//PFLT_FILE_NAME_INFORMATION nameInfo;

	//DbgPrint("[PRESET]TargetName: %wZ", Data->Iopb->TargetFileObject->FileName);

	
	status = FltGetStreamContext(Data->Iopb->TargetInstance,
		Data->Iopb->TargetFileObject,
		&context);

	if (!NT_SUCCESS(status)) {

		/*status = FltGetFileNameInformation(Data,
			FLT_FILE_NAME_NORMALIZED |
			FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
			&nameInfo);

		if (NT_SUCCESS(status)) {

			FltParseFileNameInformation(nameInfo);

			UNICODE_STRING fileName = nameInfo->Name;
			DbgPrint("[PRESET]FileName: %wZ", fileName);
		}

		
		switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {

		case FileEndOfFileInformation:
			DbgPrint("[PRESET]Length no stream: %lli", ((FILE_END_OF_FILE_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->EndOfFile.QuadPart);
			
			break;
		case FileRenameInformation:
			DbgPrint("[PRESET]Name: %wZ", ((FILE_RENAME_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->FileName);
			break;
		}*/


		//
		//  We are not interested in this file
		//

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/*switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {

	case FileEndOfFileInformation:
		DbgPrint("[PRESET]Length stream: %lli", ((FILE_END_OF_FILE_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->EndOfFile.QuadPart);
		DbgPrint("[PRESET]StreamName: %wZ", context->streamFileName);
		break;
	case FileRenameInformation:
		DbgPrint("[PRESET]Name: %wZ", ((FILE_RENAME_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->FileName);
		break;
	}*/
	
	if (context) {

		FltReleaseContext(context);
	}


	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
DfPostSetInfoCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
) {
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	
	/*NTSTATUS status;
	PDRONEFS_STREAM_HANDLE_CONTEXT context = NULL;

	status = FltGetStreamHandleContext(FltObjects->Instance,
		FltObjects->FileObject,
		&context);


	if (!NT_SUCCESS(status)) {

		//
		//  We are not interested in this file
		//
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {

	case FileEndOfFileInformation:
		DbgPrint("[POSTSET]Length: %lli", ((FILE_END_OF_FILE_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->EndOfFile.QuadPart);
		DbgPrint("[POSTSET]StreamName: %wZ", context->streamFileName);
		break;
	case FileRenameInformation:
		DbgPrint("[POSTSET]Name: %wZ", ((FILE_RENAME_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->FileName);
		break;
	}

	if (context) {

		FltReleaseContext(context);
	}*/
	
	return FLT_POSTOP_FINISHED_PROCESSING;
}

VOID
ReadDriverParameters(
	_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

This routine tries to read the driver-specific parameters from
the registry.  These values will be found in the registry location
indicated by the RegistryPath passed in.

Arguments:

RegistryPath - the path key passed to the driver during driver entry.

Return Value:

None.

--*/
{
	OBJECT_ATTRIBUTES attributes;
	HANDLE driverRegKey;
	NTSTATUS status;
	ULONG resultLength;
	UNICODE_STRING valueName;
	UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(LONG)];

	//
	//  If this value is not zero then somebody has already explicitly set it
	//  so don't override those settings.
	//

	if (0 == LoggingFlags) {

		//
		//  Open the desired registry key
		//

		InitializeObjectAttributes(&attributes,
			RegistryPath,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL);

		status = ZwOpenKey(&driverRegKey,
			KEY_READ,
			&attributes);

		if (!NT_SUCCESS(status)) {

			return;
		}

		//
		// Read the given value from the registry.
		//

		RtlInitUnicodeString(&valueName, L"DebugFlags");

		status = ZwQueryValueKey(driverRegKey,
			&valueName,
			KeyValuePartialInformation,
			buffer,
			sizeof(buffer),
			&resultLength);

		if (NT_SUCCESS(status)) {

			LoggingFlags = *((PULONG) &(((PKEY_VALUE_PARTIAL_INFORMATION)buffer)->Data));
		}

		//
		//  Close the registry entry
		//

		ZwClose(driverRegKey);
	}
}

