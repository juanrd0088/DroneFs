/*++

Module Name:

    DroneFSfilter.c

Abstract:

    This is the main module of the DroneFSfilter miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;


#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002
#define DEBUG_TRACE_FILE_CONTEXT_OPERATIONS             0x00000010  // Operation on file context

#define CTX_FILE_CONTEXT_SIZE sizeof( CTX_FILE_CONTEXT )
#define CTX_FILE_CONTEXT_TAG                  'cFxC'
#define CTX_STRING_TAG                        'tSxC'

ULONG gTraceFlags = PTDBG_TRACE_ROUTINES;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*typedef struct _VOLUME_CONTEXT {

	//
	//  Holds the name to display
	//

	UNICODE_STRING Name;

	//
	//  Holds the sector size for this volume.
	//

	ULONG SectorSize;

} VOLUME_CONTEXT, *PVOLUME_CONTEXT;*/

typedef struct _CTX_FILE_CONTEXT {

	//
	//  Name of the file associated with this context.
	//

	UNICODE_STRING FileName;

	//
	//  There is no resource to protect the context since the
	//  filename in the context is never modified. The filename 
	//  is put in when the context is created and then freed 
	//  with context is cleaned-up
	//

} CTX_FILE_CONTEXT, *PCTX_FILE_CONTEXT;

NTSTATUS
CtxCreateFileContext(
	_In_ PUNICODE_STRING FileName,
	_Outptr_ PCTX_FILE_CONTEXT *FileContext
);

NTSTATUS
CtxFindOrCreateFileContext(
	_In_ PFLT_CALLBACK_DATA Cbd,
	_In_ BOOLEAN CreateIfNotFound,
	_When_(CreateIfNotFound != FALSE, _In_) _When_(CreateIfNotFound == FALSE, _In_opt_) PUNICODE_STRING FileName,
	_Outptr_ PCTX_FILE_CONTEXT *FileContext,
	_Out_opt_ PBOOLEAN ContextCreated
);

_At_(String->Length, _Out_range_(== , 0))
_At_(String->MaximumLength, _In_)
_At_(String->Buffer, _Pre_maybenull_ _Post_notnull_ _Post_writable_byte_size_(String->MaximumLength))
NTSTATUS
CtxAllocateUnicodeString(
	_Out_ PUNICODE_STRING String
);

_At_(String->Length, _Out_range_(== , 0))
_At_(String->MaximumLength, _Out_range_(== , 0))
_At_(String->Buffer, _Pre_notnull_ _Post_null_)
VOID
CtxFreeUnicodeString(
	_Pre_notnull_ PUNICODE_STRING String
);

VOID
CtxContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
);

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
DroneFSfilterInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
DroneFSfilterInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
DroneFSfilterInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
DroneFSfilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
DroneFSfilterInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DroneFSfilterPreCreateOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
DroneFSfilterOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
DroneFSfilterPostCreateOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
DroneFSfilterPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
DroneFSfilterPreReadOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
DroneFSfilterPostReadOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

BOOLEAN
DroneFSfilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DroneFSfilterUnload)
#pragma alloc_text(PAGE, DroneFSfilterInstanceQueryTeardown)
#pragma alloc_text(PAGE, DroneFSfilterInstanceSetup)
#pragma alloc_text(PAGE, DroneFSfilterInstanceTeardownStart)
#pragma alloc_text(PAGE, DroneFSfilterInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

	{ IRP_MJ_CREATE,
	0,
	DroneFSfilterPreCreateOperation,
	DroneFSfilterPostCreateOperation },

	{ IRP_MJ_READ,
	0,
	DroneFSfilterPreReadOperation,
	DroneFSfilterPostReadOperation },

#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_CLOSE,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_READ,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_WRITE,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_SET_EA,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      DroneFSfilterPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_PNP,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      DroneFSfilterPreOperation,
      DroneFSfilterPostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_FILE_CONTEXT,
	0,
	CtxContextCleanup,
	CTX_FILE_CONTEXT_SIZE,
	CTX_FILE_CONTEXT_TAG },

	{ FLT_CONTEXT_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

	ContextRegistration,                               //  Context
    Callbacks,                          //  Operation callbacks

    DroneFSfilterUnload,                           //  MiniFilterUnload

    DroneFSfilterInstanceSetup,                    //  InstanceSetup
    DroneFSfilterInstanceQueryTeardown,            //  InstanceQueryTeardown
    DroneFSfilterInstanceTeardownStart,            //  InstanceTeardownStart
    DroneFSfilterInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
DroneFSfilterInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();


    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("DroneFSfilter!DroneFSfilterInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
DroneFSfilterInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("DroneFSfilter!DroneFSfilterInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
DroneFSfilterInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("DroneFSfilter!DroneFSfilterInstanceTeardownStart: Entered\n") );
}


VOID
DroneFSfilterInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("DroneFSfilter!DroneFSfilterInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("DroneFSfilter!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }

    return status;
}

NTSTATUS
DroneFSfilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("DroneFSfilter!DroneFSfilterUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
DroneFSfilterPreCreateOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	/*NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION fileNameInfo;

	status = FltGetFileNameInformation(Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInfo);

	if (!NT_SUCCESS(status))
		return FLT_POSTOP_FINISHED_PROCESSING;

	FltParseFileNameInformation(fileNameInfo);

	UNICODE_STRING name = fileNameInfo->Name;

	

	const wchar_t *cmp = L"\\testdir\\";
	if (wcsstr(name.Buffer, cmp)) {
		DbgPrint("PRE Created/Opened %wZ", &fileNameInfo->Name);

		ULONG flags = Data->Iopb->Parameters.Create.Options;


		ULONG disposition = flags >> 24;
		ULONG createOptions = flags & 0x00FFFFFF;
		ULONG mask = (ULONG) Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
		
		DbgPrint("The disposition is %lu", disposition);
		DbgPrint("The createOptions is %lu", createOptions);
		DbgPrint("The mask is %lu", mask);


		OBJECT_ATTRIBUTES fObjAttrs;
		//HANDLE handle;
		//IO_STATUS_BLOCK ioStatus;
		//PFILE_OBJECT pObj;

		

		try {
			InitializeObjectAttributes(
				&fObjAttrs,
				&fileNameInfo->Name,
				OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
				NULL,
				NULL
			);
			DbgPrint("Atributos inicializados correctamente");
		} except(EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
			DbgPrint("Error al inicializar atributos. Codigo: %lu", GetExceptionCode());
		}

		/*status = FltCreateFile(
		gFilterHandle,
		FltObjects->Instance,
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
		DbgPrint("Fallo al abrir el fichero test");
		return FLT_POSTOP_FINISHED_PROCESSING;
		}
		DbgPrint("Fichero abierto");
		status = ObReferenceObjectByHandle(handle, GENERIC_READ |
		GENERIC_WRITE, NULL, KernelMode, &pObj, NULL);
		DbgPrint("Puntero obtenido");

		char myArray[] = { 0x41, 0x42, 0x43 };
		ULONG myArraySize = sizeof(myArray);  // myArraySize = 3
		ULONG numBytes;

		status = FltWriteFile(FltObjects->Instance,
		pObj,
		NULL,
		myArraySize,
		myArray,
		FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
		&numBytes,
		NULL,
		NULL);

		if (NT_SUCCESS(status))
		{
		DbgPrint("Fichero modificado");
		}

		if (NT_SUCCESS(status))
		{
		FltClose(handle);
		DbgPrint("Fichero cerrado");
		}

	}



	FltReleaseFileNameInformation(fileNameInfo);*/


	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
DroneFSfilterOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("DroneFSfilter!DroneFSfilterOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("DroneFSfilter!DroneFSfilterOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
DroneFSfilterPostCreateOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    //UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION fileNameInfo;
	PCTX_FILE_CONTEXT fileContext = NULL;
	BOOLEAN fileContextCreated;

	status = FltGetFileNameInformation(Data,
	FLT_FILE_NAME_NORMALIZED|FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInfo);

	if(!NT_SUCCESS(status))
		return FLT_POSTOP_FINISHED_PROCESSING;

	FltParseFileNameInformation(fileNameInfo);

	UNICODE_STRING fileName = fileNameInfo->Name;



	


	const wchar_t *cmp = L"\\testdir\\";
	if (wcsstr(fileName.Buffer, cmp)) {
		DbgPrint("[POSTCREATE] Created/Opened %wZ", &fileNameInfo->Name);

		ULONG createOptions = Data->Iopb->Parameters.Create.Options;

		DbgPrint("[POSTCREATE]Flag: %u", createOptions);


		

		/*OBJECT_ATTRIBUTES fObjAttrs;
		HANDLE handle;
		IO_STATUS_BLOCK ioStatus;
		PFILE_OBJECT pObj;



		try {
			InitializeObjectAttributes(
				&fObjAttrs,
				&fileNameInfo->Name,
				OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
				NULL,
				NULL
			);
			DbgPrint("Atributos inicializados correctamente");
		} except (EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
			DbgPrint("Error al inicializar atributos. Codigo: %lu", GetExceptionCode());
		}

		status = FltCreateFile(
			gFilterHandle,
			FltObjects->Instance,
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
			DbgPrint("Fallo al abrir el fichero test");
			return FLT_POSTOP_FINISHED_PROCESSING;
		}
		DbgPrint("Fichero abierto");
		status = ObReferenceObjectByHandle(handle, GENERIC_READ |
			GENERIC_WRITE, NULL, KernelMode, &pObj, NULL);
		DbgPrint("Puntero obtenido");


		char myArray[] = { 0x41^0x49, 0x42^0x49, 0x43^0x49, 0x44^0x49 };
		ULONG myArraySize = sizeof(myArray);  // myArraySize = 4
		ULONG numBytes;

		status = FltWriteFile(FltObjects->Instance,
			pObj,
			NULL,
			myArraySize,
			myArray,
			FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
			&numBytes,
			NULL,
			NULL);

		if (NT_SUCCESS(status))
		{
			DbgPrint("Fichero modificado");
		}

		FltClose(handle);
		if (NT_SUCCESS(status))
		{
			DbgPrint("Fichero cerrado");
		}*/

		//
		// Find or create a file context
		//

		status = CtxFindOrCreateFileContext(Data,
			TRUE,
			&fileName,
			&fileContext,
			&fileContextCreated);


		if (!NT_SUCCESS(status)) {

			//
			//  This failure will most likely be because file contexts are not supported
			//  on the object we are trying to assign a context to or the object is being 
			//  deleted
			//  

			DbgPrint("[POSTCREATE]File Context create failed");

			return FLT_POSTOP_FINISHED_PROCESSING;
		}
	}

	if (fileContext != NULL) {

		FltReleaseContext(fileContext);
	}

	FltReleaseFileNameInformation(fileNameInfo);
	

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
DroneFSfilterPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("DroneFSfilter!DroneFSfilterPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
DroneFSfilterPreReadOperation(
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

CompletionContext - Receives the context that will be passed to the
post-operation callback.

Return Value:

FLT_PREOP_SUCCESS_WITH_CALLBACK - we want a postOpeation callback
FLT_PREOP_SUCCESS_NO_CALLBACK - we don't want a postOperation callback

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	

	NTSTATUS status;
	PCTX_FILE_CONTEXT fileContext = NULL;
	BOOLEAN fileContextCreated;

	status = CtxFindOrCreateFileContext(Data,
		FALSE,
		NULL,
		&fileContext,
		&fileContextCreated);


	if (!NT_SUCCESS(status)) {

		//
		//  This failure will most likely be because file contexts are not supported
		//  on the object we are trying to assign a context to or the object is being 
		//  deleted
		//  

		//DbgPrint("File Context find failed");

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (fileContext != NULL) {
		UNICODE_STRING name = fileContext->FileName;


		const wchar_t *cmp = L"\\testdir\\";
		if (wcsstr(name.Buffer, cmp)) {

			DbgPrint("[PREREAD] Encontrado el fichero: %wZ", &name);

			OBJECT_ATTRIBUTES fObjAttrs;
			HANDLE handle = NULL;
			IO_STATUS_BLOCK ioStatus;
			PFILE_OBJECT pObj;

			PFLT_VOLUME volume = NULL;
			FLT_VOLUME_PROPERTIES volumeProps;
			PVOID buffer = NULL;
			LARGE_INTEGER offset;
			ULONG length;
			ULONG bytesRead = 0;
			//ULONG bytesWritten = 0;

			try {
				InitializeObjectAttributes(
					&fObjAttrs,
					&name,
					OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
					NULL,
					NULL
				);
				DbgPrint("[PREREAD]Atributos inicializados correctamente");
			} except(EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
				DbgPrint("[PREREAD]Error al inicializar atributos. Codigo: %lu", GetExceptionCode());
			}

			try {
				status = FltCreateFile(
					gFilterHandle,
					FltObjects->Instance,
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
					DbgPrint("[PREREAD]Fallo al abrir el fichero test");
					return FLT_POSTOP_FINISHED_PROCESSING;
				}
				DbgPrint("[PREREAD]Fichero abierto");
			} except(EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
				DbgPrint("[PREREAD]Exception en CreateFile");
			}
			
			status = ObReferenceObjectByHandle(handle, GENERIC_READ |
			GENERIC_WRITE, NULL, KernelMode, &pObj, NULL);
			DbgPrint("[PREREAD]Puntero obtenido");


			/*// Get the buffer.
			PUCHAR buffer;
			ULONG numBytesRead = 0;

			if (Data->Iopb->Parameters.Read.MdlAddress != NULL) {
				buffer = (PUCHAR)
					MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Read.MdlAddress,
						HighPagePriority);
			}
			else {
				buffer = (PUCHAR)Data->Iopb->Parameters.Read.ReadBuffer;
			}

			//FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
			DbgPrint("[PREREAD]Length: %lu", Data->Iopb->Parameters.Read.Length);*/
			

			try{
				//
				//  Obtain the volume object .
				//
				DbgPrint("[PREREAD]Trying to get volume");
				status = FltGetVolumeFromInstance(FltObjects->Instance, &volume);

				if (!NT_SUCCESS(status)) {

					DbgPrint("[PREREAD]No se puede obtener volume");
					leave;
				}

				//
				//  Determine sector size. Noncached I/O can only be done at sector size 
				//offsets, and in lengths which are
				//  multiples of sector size. A more efficient way is to make this call 
				//once and remember the sector size in the
				//  instance setup routine and setup an instance context where we can 
				//cache it.
				
				DbgPrint("[PREREAD]Trying to get volume properties");
				status = FltGetVolumeProperties(volume,
						&volumeProps,
						sizeof(volumeProps),
						&length);
				//
				//  STATUS_BUFFER_OVERFLOW can be returned - however we only need the 
				//properties, not the names
				//  hence we only check for error status.
				//

				if (NT_ERROR(status)) {
					DbgPrint("[PREREAD]No se puede obtener volumeProp");
					leave;
				}

				DbgPrint("[PREREAD]Trying to get length");
				length = max(1024, volumeProps.SectorSize);

				//
				//  Use non-buffered i/o, so allocate aligned pool
				//
				DbgPrint("[PREREAD]Trying to get buffer");
				buffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance,
					NonPagedPool,
					length,
					'nacS');

				if (NULL == buffer) {

					DbgPrint("[PREREAD]Buffer null");
					status = STATUS_INSUFFICIENT_RESOURCES;
					leave;
				}


				//
				//  Read the beginning of the file and pass the contents to user mode.
				//

				DbgPrint("[PREREAD]Trying to read file");
			status = FltReadFile(FltObjects->Instance,
			pObj,
			&offset,
			length,
			buffer,
			FLTFL_IO_OPERATION_NON_CACHED |
			FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
			&bytesRead,
			NULL,
			NULL);

			if (NT_SUCCESS(status))
			{
				DbgPrint("[PREREAD]Fichero leido");
			}


			DbgPrint("[PREREAD]Check bytesRead");
			if (bytesRead != 0) {

				DbgPrint("[PREREAD]Bytes read: %lu", bytesRead);
				UCHAR arrayRead[1024];
				RtlCopyMemory(arrayRead,
					buffer,
					bytesRead);
				DbgPrint("[PREREAD]ArrayRead: %s", &arrayRead[0]);


				//cifrar
				arrayRead[0] = 0x47;

				DbgPrint("[PREREAD]ArrayRead nuevo: %s", &arrayRead[0]);
				RtlCopyMemory(buffer,
					arrayRead,
					bytesRead);

				try {
					Data->Iopb->Parameters.Read.ReadBuffer = buffer;
				}except(EXCEPTION_EXECUTE_HANDLER) {
					DbgPrint("[PREREAD]CAMBIO BUFFER ERROR");
				}
				
				/*DbgPrint("[PREREAD]Trying to write file");
				try {
					status = FltWriteFile(FltObjects->Instance,
						pObj,
						NULL,
						length,
						buffer,
						FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
						&bytesWritten,
						NULL,
						NULL);
					if (NT_SUCCESS(status))
					{
						DbgPrint("[PREREAD]Fichero modificado");

						if (bytesWritten != 0) {
							DbgPrint("[PREREAD]Bytes written: %lu", bytesWritten);
						}
					}
				} except(EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
					DbgPrint("[PREREAD]Exception en WriteFile");
				}*/
			}

				
			
			} except(EXCEPTION_EXECUTE_HANDLER | UNEXPECTED_KERNEL_MODE_TRAP) {
				DbgPrint("[PREREAD]Exception en ReadFile");
			}

			if (NULL != buffer) {

				FltFreePoolAlignedWithTag(FltObjects->Instance, buffer, 'nacS');
			}

			if (NULL != volume) {

				FltObjectDereference(volume);
			}
					
			if (handle != NULL) {
				status = FltClose(handle);
				if (NT_SUCCESS(status))
				{
					DbgPrint("Fichero cerrado");
				}
			}
		}

		FltReleaseContext(fileContext);
	}
	
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
DroneFSfilterPostReadOperation(
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

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	//PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
	/*PVOLUME_CONTEXT volCtx = NULL;
	NTSTATUS status;
	ULONG readLen = iopb->Parameters.Read.Length;

	try {

		//
		//  If they are trying to read ZERO bytes, then don't do anything and
		//  we don't need a post-operation callback.
		//

		if (readLen == 0) {

			leave;
		}

		//
		//  Get our volume context so we can display our volume name in the
		//  debug output.
		//

		status = FltGetVolumeContext(FltObjects->Filter,
			FltObjects->Volume,
			&volCtx);

		if (!NT_SUCCESS(status)) {

			DbgPrint("Error context volume");

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
		}




	} finally {

			
	}
	*/
	return retValue;
}

BOOLEAN
DroneFSfilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}

NTSTATUS
CtxFindOrCreateFileContext(
	_In_ PFLT_CALLBACK_DATA Cbd,
	_In_ BOOLEAN CreateIfNotFound,
	_When_(CreateIfNotFound != FALSE, _In_) _When_(CreateIfNotFound == FALSE, _In_opt_) PUNICODE_STRING FileName,
	_Outptr_ PCTX_FILE_CONTEXT *FileContext,
	_Out_opt_ PBOOLEAN ContextCreated
)
/*++

Routine Description:

This routine finds the file context for the target file.
Optionally, if the context does not exist this routing creates
a new one and attaches the context to the file.

Arguments:

Cbd                   - Supplies a pointer to the callbackData which
declares the requested operation.
CreateIfNotFound      - Supplies if the file context must be created if missing
FileName              - Supplies the file name
FileContext           - Returns the file context
ContextCreated        - Returns if a new context was created

Return Value:

Status

--*/
{
	NTSTATUS status;
	PCTX_FILE_CONTEXT fileContext;
	PCTX_FILE_CONTEXT oldFileContext;

	PAGED_CODE();

	*FileContext = NULL;
	if (ContextCreated != NULL) *ContextCreated = FALSE;

	//
	//  First try to get the file context.
	//

	/*DbgPrint("[Ctx]: Trying to get file context (FileObject = %p, Instance = %p)\n",
		Cbd->Iopb->TargetFileObject,
		Cbd->Iopb->TargetInstance);*/

	PT_DBG_PRINT(DEBUG_TRACE_FILE_CONTEXT_OPERATIONS,
		("[Ctx]: Trying to get file context (FileObject = %p, Instance = %p)\n",
			Cbd->Iopb->TargetFileObject,
			Cbd->Iopb->TargetInstance));



	status = FltGetFileContext(Cbd->Iopb->TargetInstance,
		Cbd->Iopb->TargetFileObject,
		&fileContext);

	//
	//  If the call failed because the context does not exist
	//  and the user wants to creat a new one, the create a
	//  new context
	//

	if (!NT_SUCCESS(status) &&
		(status == STATUS_NOT_FOUND) &&
		CreateIfNotFound) {


		//
		//  Create a file context
		//

		PT_DBG_PRINT(DEBUG_TRACE_FILE_CONTEXT_OPERATIONS,
			("[Ctx]: Creating file context (FileObject = %p, Instance = %p)\n",
				Cbd->Iopb->TargetFileObject,
				Cbd->Iopb->TargetInstance));

		status = CtxCreateFileContext(FileName, &fileContext);

		if (!NT_SUCCESS(status)) {

			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES | DEBUG_TRACE_FILE_CONTEXT_OPERATIONS,
				("[Ctx]: Failed to create file context with status 0x%x. (FileObject = %p, Instance = %p)\n",
					status,
					Cbd->Iopb->TargetFileObject,
					Cbd->Iopb->TargetInstance));

			return status;
		}


		//
		//  Set the new context we just allocated on the file object
		//

		PT_DBG_PRINT(DEBUG_TRACE_FILE_CONTEXT_OPERATIONS,
			("[Ctx]: Setting file context %p (FileObject = %p, Instance = %p)\n",
				fileContext,
				Cbd->Iopb->TargetFileObject,
				Cbd->Iopb->TargetInstance));

		status = FltSetFileContext(Cbd->Iopb->TargetInstance,
			Cbd->Iopb->TargetFileObject,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
			fileContext,
			&oldFileContext);

		if (!NT_SUCCESS(status)) {

			PT_DBG_PRINT(DEBUG_TRACE_FILE_CONTEXT_OPERATIONS,
				("[Ctx]: Failed to set file context with status 0x%x. (FileObject = %p, Instance = %p)\n",
					status,
					Cbd->Iopb->TargetFileObject,
					Cbd->Iopb->TargetInstance));
			//
			//  We release the context here because FltSetFileContext failed
			//
			//  If FltSetFileContext succeeded then the context will be returned
			//  to the caller. The caller will use the context and then release it
			//  when he is done with the context.
			//

			PT_DBG_PRINT(DEBUG_TRACE_FILE_CONTEXT_OPERATIONS,
				("[Ctx]: Releasing file context %p (FileObject = %p, Instance = %p)\n",
					fileContext,
					Cbd->Iopb->TargetFileObject,
					Cbd->Iopb->TargetInstance));

			FltReleaseContext(fileContext);

			if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

				//
				//  FltSetFileContext failed for a reason other than the context already
				//  existing on the file. So the object now does not have any context set
				//  on it. So we return failure to the caller.
				//

				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES | DEBUG_TRACE_FILE_CONTEXT_OPERATIONS,
					("[Ctx]: Failed to set file context with status 0x%x != STATUS_FLT_CONTEXT_ALREADY_DEFINED. (FileObject = %p, Instance = %p)\n",
						status,
						Cbd->Iopb->TargetFileObject,
						Cbd->Iopb->TargetInstance));

				return status;
			}

			//
			//  Race condition. Someone has set a context after we queried it.
			//  Use the already set context instead
			//

			PT_DBG_PRINT(DEBUG_TRACE_FILE_CONTEXT_OPERATIONS,
				("[Ctx]: File context already defined. Retaining old file context %p (FileObject = %p, Instance = %p)\n",
					oldFileContext,
					Cbd->Iopb->TargetFileObject,
					Cbd->Iopb->TargetInstance));

			//
			//  Return the existing context. Note that the new context that we allocated has already been
			//  realeased above.
			//

			fileContext = oldFileContext;
			status = STATUS_SUCCESS;

		}
		else {

			if (ContextCreated != NULL) *ContextCreated = TRUE;
		}
	}

	*FileContext = fileContext;

	return status;
}


NTSTATUS
CtxCreateFileContext(
	_In_ PUNICODE_STRING FileName,
	_Outptr_ PCTX_FILE_CONTEXT *FileContext
)
/*++

Routine Description:

This routine creates a new file context

Arguments:

FileName            - Supplies the file name
FileContext         - Returns the file context

Return Value:

Status

--*/
{
	NTSTATUS status;
	PCTX_FILE_CONTEXT fileContext;

	PAGED_CODE();

	//
	//  Allocate a file context
	//


	PT_DBG_PRINT(DEBUG_TRACE_FILE_CONTEXT_OPERATIONS,
		("[Ctx]: Allocating file context \n"));

	status = FltAllocateContext(gFilterHandle,
		FLT_FILE_CONTEXT,
		CTX_FILE_CONTEXT_SIZE,
		PagedPool,
		&fileContext);

	if (!NT_SUCCESS(status)) {

		PT_DBG_PRINT(DEBUG_TRACE_FILE_CONTEXT_OPERATIONS,
			("[Ctx]: Failed to allocate file context with status 0x%x \n",
				status));
		return status;
	}

	//
	//  Initialize the newly created context
	//

	//
	//  Allocate and copy off the file name
	//

	fileContext->FileName.MaximumLength = FileName->Length;
	status = CtxAllocateUnicodeString(&fileContext->FileName);
	if (NT_SUCCESS(status)) {

		RtlCopyUnicodeString(&fileContext->FileName, FileName);
	}

	*FileContext = fileContext;

	return STATUS_SUCCESS;
}

_At_(String->Length, _Out_range_(== , 0))
_At_(String->MaximumLength, _In_)
_At_(String->Buffer, _Pre_maybenull_ _Post_notnull_ _Post_writable_byte_size_(String->MaximumLength))
NTSTATUS
CtxAllocateUnicodeString(
	_Out_ PUNICODE_STRING String
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

	UNREFERENCED_PARAMETER(String);

	String->Buffer = ExAllocatePoolWithTag(PagedPool,
		String->MaximumLength,
		CTX_STRING_TAG);

	if (String->Buffer == NULL) {

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[Ctx]: Failed to allocate unicode string of size 0x%x\n",
				String->MaximumLength));

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	String->Length = 0;

	return STATUS_SUCCESS;
}

_At_(String->Length, _Out_range_(== , 0))
_At_(String->MaximumLength, _Out_range_(== , 0))
_At_(String->Buffer, _Pre_notnull_ _Post_null_)
VOID
CtxFreeUnicodeString(
	_Pre_notnull_ PUNICODE_STRING String
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

	ExFreePoolWithTag(String->Buffer,
		CTX_STRING_TAG);

	String->Length = String->MaximumLength = 0;
	String->Buffer = NULL;
}

VOID
CtxContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
)
{
	UNREFERENCED_PARAMETER(ContextType);

	PCTX_FILE_CONTEXT fileContext;


	PAGED_CODE();



		fileContext = (PCTX_FILE_CONTEXT)Context;

		PT_DBG_PRINT(DEBUG_TRACE_FILE_CONTEXT_OPERATIONS,
			("[Ctx]: Cleaning up file context for file %wZ (FileContext = %p)\n",
				&fileContext->FileName,
				fileContext));


		//
		//  Free the file name
		//

		if (fileContext->FileName.Buffer != NULL) {

			CtxFreeUnicodeString(&fileContext->FileName);
		}

		PT_DBG_PRINT(DEBUG_TRACE_FILE_CONTEXT_OPERATIONS,
			("[Ctx]: File context cleanup complete.\n"));

}