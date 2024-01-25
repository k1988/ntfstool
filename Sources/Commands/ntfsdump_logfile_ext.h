#include <cstdint>
#include <string>
#include <cmath>
#include <map>
#include <vector>
#include <Windows.h>

// 日志中的操作类型的Hex格式,用于字符串对比
#define Operation_CompensationLogRecord "0100"
#define Operation_InitializeFileRecordSegment "0200"
#define Operation_DeallocateFileRecordSegment "0300"
#define Operation_WriteEndOfFileRecordSegment "0400"
#define Operation_CreateAttribute "0500"
#define Operation_DeleteAttribute "0600"
#define Operation_UpdateResidentAttributeValue "0700"
#define Operation_UpdateNonResidentAttributeValue "0800"
#define Operation_UpdateMappingPairs "0900"
#define Operation_DeleteDirtyClusters "0a00"
#define Operation_SetNewAttributeSizes "0b00"
#define Operation_AddIndexEntryToRoot "0c00"
#define Operation_DeleteIndexEntryFromRoot "0d00"
#define Operation_AddIndexEntryToAllocationBuffer "0e00"
#define Operation_DeleteIndexEntryFromAllocationBuffer "0f00"
#define Operation_WriteEndOfIndexBuffer "1000"
#define Operation_SetIndexEntryVcnInRoot "1100"
#define Operation_SetIndexEntryVcnInAllocationBuffer "1200"
#define Operation_UpdateFileNameInRoot "1300"
#define Operation_UpdateFileNameInAllocationBuffer "1400"
#define Operation_SetBitsInNonResidentBitMap "1500"
#define Operation_ClearBitsInNonResidentBitMap "1600"
#define Operation_HotFix "1700"
#define Operation_EndTopLevelAction "1800"
#define Operation_PrepareTransaction "1900"
#define Operation_CommitTransaction "1a00"
#define Operation_ForgetTransaction "1b00"
#define Operation_OpenNonResidentAttribute "1c00"
#define Operation_OpenAttributeTableDump "1d00"
#define Operation_AttributeNamesDump "1e00"
#define Operation_DirtyPageTableDump "1f00"
#define Operation_TransactionTableDump "2000"
#define Operation_UpdateRecordDataInRoot "2100"
#define Operation_UpdateRecordDataInAllocationBuffer "2200"


//void TestSlackSpace(char* InputData, int64_t last_lsn_tmp, int64_t Offset);
std::string _SolveUndoRedoCodes(int64_t OpCode);
int64_t _Decode_CheckpointRecord(std::string InputData);

// 解析MFT
// 返回非0值表示失败
int64_t _ParserCodeOldVersion(const std::string& MFTEntry, int64_t IsRedo);

int64_t _TestSlackSpace(std::string InputData, int64_t last_lsn_tmp, int64_t Offset);

std::string _DoFixup(std::string record, int64_t offset);

//void DecodeLSNRecord(const char* clientData, int64_t rebuiltLsn);
std::string _CheckOffsetOfAttribute(int64_t TestRef, int64_t TestString);
int64_t _UpdateSeveralOffsetOfAttribute(int64_t TestRef, std::string TestString);
void _RemoveAllOffsetOfAttribute(int64_t TestRef);

std::string _Decode_AttributeName(std::string data);

// 解析一条日志记录
int64_t _DecodeLSNRecord(std::string InputData, int64_t last_lsn_tmp, int64_t RecordOffset);

// 解析一个日志页
std::string _DecodeRCRD(const std::string_view& RCRDRecord, DWORD RCRDOffset, int64_t OffsetAdjustment, int64_t DoNotReturnData);

int64_t _Decode_SetIndexEntryVcn(std::string data);
int64_t _Decode_BitsInNonresidentBitMap2(std::string data);

FILETIME _WinTime_UTCFileTimeToLocalFileTime(FILETIME* iUTCFileTime);
SYSTEMTIME _WinTime_LocalFileTimeToSystemTime(FILETIME iLocalFileTime);
std::string _WinTime_LocalFileTimeFormat(int64_t iLocalFileTime, int64_t iFormat = 4, int64_t iPrecision = 0, bool bAMPMConversion = false);
std::string _WinTime_UTCFileTimeFormat(int64_t iUTCFileTime, int64_t iFormat = 4, int64_t iPrecision = 0, bool bAMPMConversion = false);

std::string _WinTime_FormatTime(int64_t intYear, int64_t  iMonth, int64_t iDay, int64_t iHour, int64_t iMin, int64_t iSec, int64_t iMilSec, int64_t iDayOfWeek, int64_t iFormat = 4, int64_t iPrecision = 0, bool bAMPMConversion = false);

// 获取UTC时间戳和本地文件时间的差
int64_t _WinTime_GetUTCToLocalFileTimeDelta();

int64_t _Decode_UpdateFileName(std::string attribute, bool IsRedo);

// 文件名数组管理 lsn 到 文件名的映射
int64_t _UpdateFileNameArray(int64_t InputRef, int64_t InputRefSeqNo, std::string  InputName, int64_t InputLsn);

// 属性引用数组更新或添加
int64_t _UpdateSingleOffsetOfAttribute(int64_t TestRef, int64_t offset, int64_t size, std::string TestString);

int64_t _Decode_IndexEntry(std::string Entry, std::string AttrType, bool IsRedo);
int64_t _DecodeIndxEntriesSII(std::string InputData, bool IsRedo);
int64_t _DecodeIndxEntriesSDH(std::string InputData, bool IsRedo);
int64_t _Decode_Quota_Q(std::string InputData, bool IsRedo);
int64_t _Decode_Quota_O(std::string InputData, bool IsRedo);
std::string _Decode_QuotaFlags(DWORD InputData);
int64_t _TryIdentifyIndexEntryType(std::string Entry, std::string operation_hex, bool IsRedo);
int64_t _Decode_Reparse_R(std::string InputData, bool IsRedo);
int64_t _Decode_UndoWipeINDX(std::string Entry, bool IsRedo);

// 将原逻辑中一些参数设置为选项,由外界传递进来
struct NtfsDumpOption
{
    bool VerboseOn = true;

    // 对应界面：Sectors per cluster
// 默认认为的每个硬盘簇的sector数量
    int64_t SectorsPerCluster = 8;

    int64_t BytesPerCluster = /*SectorsPerCluster*/ 8 * 512;

    // 发现错误的时间戳时,使用什么时间戳代替
    std::string TimestampErrorVal = "0000-00-00 00:00:00";

    /** 时间戳转换成字符串时使用的格式,可选部分由 Precision控制
     * 1. 年月日时分秒[毫秒|微秒]
     * 2. MM/DD/YYYY HH:MM[:SS[:MSMSMSMS[ AM/PM]]]
     * 3. DD/MM/YYYY HH:MM[:SS[:MSMSMSMS[ AM/PM]]]
     * 4. Month DD, YYYY HH:MM[:SS[:MSMSMSMS[ AM/PM]]]
     * 5. DD Month YYYY HH:MM[:SS[:MSMSMSMS[ AM/PM]]]
     * 6. YYYY-MM-DD HH:MM[:SS[:MSMSMSMS[ AM/PM]]]
    */
    int64_t DateTimeFormat = 6;
};

// 将原逻辑中一些参数设置为选项,由外界传递进来
struct NtfsDumpResult
{
    // 属性计数
    int64_t GlobalAttrCounter = 0;

    // 属性数组
    // std::array<std::string>
    // 索引1格式: 未知
    // 索引2格式为: STANDARD_INFORMATION?56,FILE_NAME?152,DATA?264,,
    std::map<int, std::array<std::string, 2>> AttrArray;

    std::map<int, std::string> FileNamesArray;
    std::map<int, std::string> FileNameLsnArray;

    int64_t HDR_MFTREcordNumber;

    int64_t PredictedRefNumber;

    std::string undo_operation;
    std::string redo_operation;

    // 解析文件属性过程中的属性字符串(会在各个调用环节拼装)
    std::string AttributeString;

    int64_t FN_CTime, FN_ATime, FN_MTime, FN_RTime;
    uint64_t FN_AllocSize, FN_RealSize;
    std::string FN_Flags;
    std::string FN_Name;
    std::string FN_NameType;
};
extern NtfsDumpOption option;
extern NtfsDumpResult result;

constexpr auto GUI_EVENT_CLOSE = -3;
constexpr auto GUI_CHECKED = 1;
constexpr auto GUI_UNCHECKED = 4;
//Comment: constexpr auto ES_AUTOVSCROLL = 64;
//constexpr auto WS_VSCROLL = 0x00200000;
//constexpr auto DT_END_ELLIPSIS = 0x8000;
constexpr auto GUI_DISABLE = 128;

constexpr auto ATTR_TYPE_STANDARD_INFORMATION = "10000000";
constexpr auto ATTR_TYPE_ATTRIBUTE_LIST = "20000000";
constexpr auto ATTR_TYPE_FILE_NAME = "30000000";
constexpr auto ATTR_TYPE_OBJECT_ID = "40000000";
constexpr auto ATTR_TYPE_SECURITY_DESCRIPTOR = "50000000";
constexpr auto ATTR_TYPE_VOLUME_NAME = "60000000";
constexpr auto ATTR_TYPE_VOLUME_INFORMATION = "70000000";
constexpr auto ATTR_TYPE_DATA = "80000000";
constexpr auto ATTR_TYPE_INDEX_ROOT = "90000000";
constexpr auto ATTR_TYPE_INDEX_ALLOCATION = "A0000000";
constexpr auto ATTR_TYPE_BITMAP = "B0000000";
constexpr auto ATTR_TYPE_REPARSE_POint64_t = "C0000000";
constexpr auto ATTR_TYPE_EA_INFORMATION = "D0000000";
constexpr auto ATTR_TYPE_EA = "E0000000";
constexpr auto ATTR_TYPE_PROPERTY_SET = "F0000000";
constexpr auto ATTR_TYPE_LOGGED_UTILITY_STREAM = "00010000";
constexpr auto ATTR_TYPE_ATTRIBUTE_END_MARKER = "FFFFFFFF";
