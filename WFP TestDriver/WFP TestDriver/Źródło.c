#include "ntddk.h"
#include <fwpmk.h>
#include <fwpsk.h>
#include <string.h>
#define INITGUID
#include <guiddef.h>

DEFINE_GUID(WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID, 0xd969fc67, 0x6fb2, 0x4504, 0x91, 0xce, 0xa9, 0x7c, 0x3c, 0x32, 0xad, 0x36);
DEFINE_GUID(WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID_1, 0xd969fc67, 0x6fb2, 0x4504, 0x91, 0xce, 0xa9, 0x7c, 0x3c, 0x32, 0xaa, 0x35);
DEFINE_GUID(WFP_SAMPLE_SUB_LAYER_GUID, 0xed6a516a, 0x36d1, 0x4881, 0xbc, 0xf0, 0xac, 0xeb, 0x4c, 0x4, 0xc2, 0x1c);
DEFINE_GUID(WFP_SAMPLE_SUB_LAYER_GUID_1, 0xed6a516a, 0x36d1, 0x4881, 0xbc, 0xf0, 0xac, 0xeb, 0x4c, 0x4, 0xc1, 0x1d);

PDEVICE_OBJECT DeviceObject = NULL;
HANDLE EngineHandle = NULL;
UINT32 RegCalloutId = 0, AddCalloutId = 0;
UINT64 filterid = 0;
UINT32 RegCalloutId_1 = 0, AddCalloutId_1 = 0;
UINT64 filterid_1 = 0;

VOID UnInitWfp() {
	if (EngineHandle != NULL) {
		if (filterid != 0) {
			FwpmFilterDeleteById(EngineHandle, filterid);
			FwpmSubLayerDeleteByKey(EngineHandle, &WFP_SAMPLE_SUB_LAYER_GUID);
		}
		if (filterid_1 != 0) {
			FwpmFilterDeleteById(EngineHandle, filterid_1);
			FwpmSubLayerDeleteByKey(EngineHandle, &WFP_SAMPLE_SUB_LAYER_GUID_1);
		}
		if (AddCalloutId != 0) {
			FwpmCalloutDeleteById(EngineHandle, AddCalloutId);
		}
		if (AddCalloutId_1 != 0) {
			FwpmCalloutDeleteById(EngineHandle, AddCalloutId_1);
		}

		if (RegCalloutId != 0)
		{
			FwpsCalloutUnregisterById(RegCalloutId);
		}

		if (RegCalloutId_1 != 0)
		{
			FwpsCalloutUnregisterById(RegCalloutId_1);
		}

		FwpmEngineClose(EngineHandle);
	}
}

VOID Unload(PDRIVER_OBJECT DriverObject) {
	UnInitWfp();
	IoDeleteDevice(DeviceObject);
	KdPrint(("unload\r\n"));
}


NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const  GUID* filterkey, const FWPS_FILTER* filter)
{
	return STATUS_SUCCESS;
}

VOID FlowDeleteCallback(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext)
{

}

NTSTATUS NotifyCallback1(FWPS_CALLOUT_NOTIFY_TYPE type, const  GUID* filterkey, const FWPS_FILTER* filter)
{
	return STATUS_SUCCESS;
}

VOID FlowDeleteCallback1(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext)
{

}


VOID FilterCallback(const FWPS_INCOMING_VALUES0* Values, const FWPS_INCOMING_METADATA_VALUES0* MetaData, PVOID layerdata, const void* context, const FWPS_FILTER* filter, UINT64 flowcontext, FWPS_CLASSIFY_OUT* classifyout) {


	ULONG LocalIp, RemoteIp;
	ULONG targetip = 0x99132830;


	if (!(classifyout->rights&FWPS_RIGHT_ACTION_WRITE)) {
		goto end;
	}




	LocalIp = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	RemoteIp = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
	
	KdPrint(("PID is %ld --- Path is %S --- LocalIp is %u.%u.%u.%u --- RemoteIp is %u.%u.%u.%u \r\n",
		(ULONG)(MetaData->processId),
		(PWCHAR)(MetaData->processPath->data),
		(LocalIp>>24)&0xFF, (LocalIp >> 16) & 0xFF, (LocalIp >> 8) & 0xFF, (LocalIp) & 0xFF,
		(RemoteIp >> 24) & 0xFF, (RemoteIp >> 16) & 0xFF, (RemoteIp >> 8) & 0xFF, (RemoteIp) & 0xFF));


	if (targetip == RemoteIp) {
		KdPrint(("block \r\n"));

		if (wcscmp((PWCHAR)(MetaData->processPath->data), L"\device\harddiskvolume2\program files\google\chrome\application\chrome.exe") == 0)
			classifyout->actionType = FWP_ACTION_BLOCK;
		else classifyout->actionType = FWP_ACTION_PERMIT;
		classifyout->rights &= ~FWPS_RIGHT_ACTION_WRITE;

		return;
	}
	else {
		classifyout->actionType = FWP_ACTION_PERMIT;
	}

end:
	classifyout->actionType = FWP_ACTION_PERMIT;

	if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
		classifyout->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	}
}

VOID FilterCallback1(const FWPS_INCOMING_VALUES0* Values, const FWPS_INCOMING_METADATA_VALUES0* MetaData, PVOID layerdata, const void* context, const FWPS_FILTER* filter, UINT64 flowcontext, FWPS_CLASSIFY_OUT* classifyout) {


	ULONG LocalIp, RemoteIp;
	ULONG targetip = 0xd44d6209;


	
	if (!(classifyout->rights&FWPS_RIGHT_ACTION_WRITE)) {
		goto end;
	}

	LocalIp = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	RemoteIp = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;

	KdPrint(("PID is %ld --- Path is %S --- LocalIp is %u.%u.%u.%u --- RemoteIp is %u.%u.%u.%u \r\n",
		(ULONG)(MetaData->processId),
		(PWCHAR)(MetaData->processPath->data),
		(LocalIp >> 24) & 0xFF, (LocalIp >> 16) & 0xFF, (LocalIp >> 8) & 0xFF, (LocalIp) & 0xFF,
		(RemoteIp >> 24) & 0xFF, (RemoteIp >> 16) & 0xFF, (RemoteIp >> 8) & 0xFF, (RemoteIp) & 0xFF));

	if (targetip == RemoteIp) {
		KdPrint(("block \r\n"));
		if ((PWCHAR)(MetaData->processPath->data) == "C:\Program Files\Google\Chrome\Application\chrome.exe")
			classifyout->actionType = FWP_ACTION_BLOCK;
		else classifyout->actionType = FWP_ACTION_PERMIT;
		classifyout->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		
		return;
	}
	else {
		classifyout->actionType = FWP_ACTION_PERMIT;
	}

end:
	classifyout->actionType = FWP_ACTION_PERMIT;

	if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
		classifyout->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	}
}

NTSTATUS WfpOpenEngine()
{
	return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &EngineHandle);
}

NTSTATUS WfpRegisterCallout() {
	FWPS_CALLOUT Callout = { 0 };
	Callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
	Callout.flags = 0;
	Callout.classifyFn = FilterCallback;
	Callout.notifyFn = NotifyCallback;
	Callout.flowDeleteFn = FlowDeleteCallback;
	return FwpsCalloutRegister(DeviceObject, &Callout, &RegCalloutId);
}

NTSTATUS WfpRegisterCallout1() {
	FWPS_CALLOUT Callout = { 0 };
	Callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID_1;
	Callout.flags = 0;
	Callout.classifyFn = FilterCallback1;
	Callout.notifyFn = NotifyCallback1;
	Callout.flowDeleteFn = FlowDeleteCallback1;
	return FwpsCalloutRegister(DeviceObject, &Callout, &RegCalloutId);
}

NTSTATUS WfpAddCallout()
{
	FWPM_CALLOUT callout = { 0 };

	callout.flags = 0;
	callout.displayData.name = L"EstablishedCalloutName";
	callout.displayData.description = L"EstablishedCalloutName";
	callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
	callout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

	return FwpmCalloutAdd(EngineHandle, &callout, NULL, &AddCalloutId);
}

NTSTATUS WfpAddCallout1()
{
	FWPM_CALLOUT callout = { 0 };

	callout.flags = 0;
	callout.displayData.name = L"EstablishedCalloutName1";
	callout.displayData.description = L"EstablishedCalloutName1";
	callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID_1;
	callout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

	return FwpmCalloutAdd(EngineHandle, &callout, NULL, &AddCalloutId);
}

NTSTATUS WfpAddSublayer()
{
	FWPM_SUBLAYER sublayer = { 0 };

	sublayer.displayData.name = L"Establishedsublayername";
	sublayer.displayData.description = L"Establishedsublayername";
	sublayer.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID;
	sublayer.weight = 65500;
	return FwpmSubLayerAdd(EngineHandle, &sublayer, NULL);
}

NTSTATUS WfpAddSublayer1()
{
	FWPM_SUBLAYER sublayer = { 0 };

	sublayer.displayData.name = L"Establishedsublayername1";
	sublayer.displayData.description = L"Establishedsublayername1";
	sublayer.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID_1;
	sublayer.weight = 65400;
	return FwpmSubLayerAdd(EngineHandle, &sublayer, NULL);
}

NTSTATUS WfpAddFilter() {

	FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION condition[1] = { 0 };
	FWP_V4_ADDR_AND_MASK AddrandMask = { 0 };
	filter.displayData.name = L"filterCalloutName";
	filter.displayData.description = L"filterCalloutName";
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID;
	filter.weight.type = FWP_EMPTY;
	filter.numFilterConditions = 1;
	filter.filterCondition = condition;
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	filter.action.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;

	condition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	condition[0].matchType = FWP_MATCH_EQUAL;
	condition[0].conditionValue.type = FWP_V4_ADDR_MASK;
	condition[0].conditionValue.v4AddrMask = &AddrandMask;


	return FwpmFilterAdd(EngineHandle, &filter, NULL, &filterid);


}

NTSTATUS WfpAddFilter1() {

	FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION condition[1] = { 0 };
	FWP_V4_ADDR_AND_MASK AddrandMask1 = { 0 };
	filter.displayData.name = L"filterCalloutName";
	filter.displayData.description = L"filterCalloutName";
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID_1;
	filter.weight.type = FWP_EMPTY;
	filter.numFilterConditions = 1;
	filter.filterCondition = condition;
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	filter.action.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID_1;
	condition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	condition[0].matchType = FWP_MATCH_EQUAL;
	condition[0].conditionValue.type = FWP_V4_ADDR_MASK;
	condition[0].conditionValue.v4AddrMask = &AddrandMask1;


	return FwpmFilterAdd(EngineHandle, &filter, NULL, &filterid);


}

NTSTATUS InitializeWfp()
{

	if (!NT_SUCCESS(WfpOpenEngine())) {
		goto end;
	}

	if (!NT_SUCCESS(WfpRegisterCallout())) {
		goto end;
	}

	if (!NT_SUCCESS(WfpAddCallout())) {
		goto end;
	}

	if (!NT_SUCCESS(WfpAddSublayer())) {
		goto end;
	}

	if (!NT_SUCCESS(WfpAddFilter())) {
		goto end;
	}

	return STATUS_SUCCESS;
end:
	UnInitWfp();
	return STATUS_UNSUCCESSFUL;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;

	DriverObject->DriverUnload = Unload;



	status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = InitializeWfp();

	if (NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
	}

	return status;

}