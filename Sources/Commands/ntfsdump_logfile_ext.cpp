#include  "ntfsdump_logfile_ext.h"
#include "NTFS/ntfs.h"
#include "Utils/utils.h"
#include <cassert>
#include <array>
#include <iomanip>
#include <variant>

#include <algorithm>

// 判断指定元素是否在指定容器中
#define in_std(x, item) (std::find(x.begin(), x.end(), item) != x.end())

// 判断是否所有的字符都是数字
template<typename Str>
inline bool str_is_digit(Str&& x) {
    return std::all_of(x.begin(), x.end(), [](auto c) {\
        return std::isdigit(c) != 0; \
        });
}


#define Mod(x, y) (x % y)
std::string StringRight(std::string str, int64_t count);

inline std::string StringReplace(const std::string& str, const std::string& from, const std::string& to)
{
    std::string result = str;
    utils::strings::replace(result, from, to);
    return result;
}



constexpr auto MftRefReplacement = -2;

#pragma region "整理好的有意义的全局变量"

NtfsDumpOption option;
NtfsDumpResult result;

// 记录上一个解析的Redo操作
std::string PreviousRedoOp;

std::string TextInformation;


auto tDelta = _WinTime_GetUTCToLocalFileTimeDelta();
auto TimeDiff = 5748192000000000;
auto ExampleTimestampVal = "01CD74B3150770B8";

auto TimestampPrecision = 3;

#pragma endregion

#pragma region "原界面参数"

// 对应界面 "LSN's to trigger verbose output (comma separate):
std::vector<int> VerboseArr;

// 对应界面： MFT record size
// 取值 1024或4096
int64_t MFT_Record_Size = 1024;

// LsnValidationLevel 取自界面上的 LSN error leve 默认值 0.1%
float LsnValidationLevel = 0.1f;

#pragma endregion

std::string SI_CTime_Core, SI_ATime_Core, SI_MTime_Core, SI_RTime_Core, SI_CTime_Precision, SI_ATime_Precision, SI_MTime_Precision, SI_RTime_Precision;
namespace std
{
    inline std::string to_string(std::string _Val)
    {
        return _Val;
    }
}

//// 全局重载加法运算符
//std::string operator+(const char* myStr, int64_t num)
//{
//    return std::string(myStr) + std::to_string(num);
//}
//
//// 全局重载加法运算符（反向顺序）
//std::string operator+(int64_t num, const char* myStr) 
//{
//    return std::string(myStr) + std::to_string(num);
//}

//int64_t main()
//{
//	// 在这里初始化你的变量和数据;
//	char *InputData = "your_slack_space_data";
//	int64_t last_lsn_tmp = 0;
//	int64_t Offset = 0;
//
//	// 调用函数进行测试;
//	_TestSlackSpace(InputData, last_lsn_tmp, Offset);
//
//	return {};;
//}

#define _DumpOutputPrintf(...) printf(__VA_ARGS__)

inline void _DumpOutput(std::string msg)
{
    std::cout << msg << std::endl;
    //_DumpOutputPrintf(msg.c_str());
}

// 打印Hex表格,格式:
//0000	31 7c 10 00 00 00 00 00  a3 7b 10 00 00 00 00 00   1 | .......{......
inline void _DumpOutputHex(std::string msg)
{
    auto i = 0;
    auto line = (msg.size() + 31) / 32;
    for (; i < line; i++)
    {
        // 字节索引表,2个hex为1个字节
        std::cout << std::hex << std::setw(4) << std::setfill('0') << 16 * i << "\t";

        // 右侧明文表
        std::string plainText;

        // 中间字节
        for (auto j = i * 32; j < (i * 32) + 32; j += 2)
        {
            // 每8个多加一个空格
            if ((j % 32) == 16)
            {
                std::cout << " ";
            }

            if (j >= msg.size())
            {
                // 最后一行超出部分直接使用空格
                std::cout << "   ";
            }
            else
            {
                auto byteStr = msg.substr(j, 2);
                std::cout << byteStr << " ";

                // 对于可见字符插入明文表
                const auto byte = std::stol(byteStr, nullptr, 16);
                if (std::isprint(byte))
                {
                    plainText.push_back(byte);
                }
                else
                {
                    plainText.push_back('.');
                }
            }
        }

        // 打印明文表
        std::cout << "  " << plainText << std::endl;
    }

    std::cout << std::endl;
    std::cout << std::endl;
}

inline void SetError(int errorCode)
{
    ::SetLastError(errorCode);
}

template <typename T>
size_t Ubound(T& t)
{
    return t.size();
}

// 在多维数组中查找指定值，返回索引
template <typename T>
int64_t _ArraySearch(std::vector<T> aArray, int64_t vValue, int64_t iStart = 0, int64_t iEnd = 0, int64_t iCase = 0, int64_t iCompare = 0, int64_t iForward = 1, int64_t iSubItem = -1, int64_t bRow = false)
{
    assert(false);
    return -1;
}

// void DumpOutput(const char* message);
// {
// 	// 在这里添加输出逻辑，例如使用 std::cout 或其他适当的输出方式;
// 	ntfs_log_debug(message);
// }

template<typename intType>
std::string Hex(intType value, int64_t length = 8)
{
    auto hexValue = StringRight(utils::format::hex(value), length);

    // 转换成大写
    std::for_each(hexValue.begin(), hexValue.end(), [](auto& c) {
        c = std::toupper(c);
        });
    return hexValue;
}

template< >
std::string Hex(int64_t value, int64_t length)
{
    return Hex((uint64_t)value, length);
}

template<typename T>
int64_t Int(T t)
{
    return int(t);
}

template<>
int64_t Int(std::string t)
{
    if (t.empty()) return 0;
    return std::stoll(t);
}

int64_t StringLen(const std::string& str)
{
    return str.length();
}

/**
 * 返回子字符串在父字符串中的位置, 索引返回以1开始
 */
size_t StringInStr(const std::string& str, const std::string& needle)
{
    if (str.find(needle) != std::string::npos)
    {
        return str.find(needle) + 1;
    }
    else
    {
        return 0;
    }
}

/**
 * @param start 索引从1开始
 */
std::string StringMid(const std::string_view& raw, int64_t start, int64_t count = -1)
{
    if (start > raw.size())
    {
        return {};
    }

    //if (count != -1 && start + count >= raw.size())
    //{
    //    return {};
    //}
    return std::string(raw.substr(start - 1, count));
}
std::string StringLeft(std::string str, int64_t count)
{
    if (count <= 0)
    {
        return {};
    }
    count = std::min<int64_t>(count, str.length());
    return str.substr(0, count);
}

std::string StringRight(std::string str, int64_t count)
{
    return str.substr(str.length() - count);
}

std::string StringTrimRight(std::string str, int64_t count)
{
    return StringLeft(str, StringLen(str) - count);
}

std::string _FillZero(std::string inp)
{
    int64_t inplen = 0;
    std::string out;
    std::string tmp = "";
    inplen = (inp.length());
    if (inplen < 4) {
        for (auto i = 0; i < 4 - inplen; i++)
        {
            tmp += "0";
        }
    }

    out = tmp + inp;
    return  out;
}

// 交换hex字节串的端序
std::string _SwapEndian(const std::string_view& hex)
{
    assert(hex.size() % 2 == 0);
    if (hex.empty()) return {};
    std::string result;
    for (auto i = hex.size(); i > 1; i -= 2)
    {
        result += hex.substr(i - 2, 2);
    }
    return result;
}

// 16进制转10进制整数
int64_t Dec(const std::string_view& hex, int64_t flag = 0)
{
    if (hex.empty()) return 0;
    // NUMBER_AUTO (0 ) = string is interpreted as an integer (Default). See remarks.
    // NUMBER_32BIT(1) = string is interpreted as a 32bit integer
    //	NUMBER_64BIT(2) = string is interpreted as a 64bit integer
    //	NUMBER_DOUBLE(3) = string is interpreted as a double
    switch (flag)
    {
    case 0:
    {
        return std::stoull(std::string(hex), nullptr, 16);
    }
    break;
    case 2:
    {
        return std::stoull(std::string(hex), nullptr, 16);
    }
    break;
    default:
        assert(false);
    }
    // TODO
    return {};;
}

std::string BinaryToString(std::string binary, int64_t flag)
{
    /*
    $SB_ANSI (1) = binary data is ANSI (default)
    $SB_UTF16LE (2) = binary data is UTF16 Little Endian
    $SB_UTF16BE (3) = binary data is UTF16 Big Endian
    $SB_UTF8 (4) = binary data is UTF8
     */
    std::string result;
    auto buffer = utils::convert::from_hex(binary);
    switch (flag)
    {
    case 1:// ansi
    {
        result.append((char*)buffer->data(), buffer->size());
    }
    break;
    case 2:
    {
        std::wstring ws;
        ws.append((wchar_t*)buffer->data(), buffer->size() / 2);
        return utils::strings::to_utf8(ws);
        break;
    }
    default:
    {
        // 其它可能用不到,暂时不实现
        assert(false);
    }
    }
}

int64_t HexToInt(std::string_view str)
{
    return Dec(str, 0);
}

std::string _HexEncode(std::string input)
{
    assert(false);
    // 在这里实现十六进制编码逻辑，具体实现根据实际需求调整;
    // 这里只是一个简单的示例;
    // ...
    // TODO
    return ""; // 返回十六进制编码后的字符串;
}

bool StringRegExp(std::string data, std::string regex)
{
    assert(false);
    // TODO
    return false;
}

// 取16进制属性对应的字符串
std::string _ResolveAttributeType(std::string input);

// 将文件属性转换为字符串形式
std::string _File_Attributes(int64_t FAInput)
{
    std::string FAOutput = "";
    if ((FAInput & 0x0001)) {/*If Then in one Line*/
        FAOutput += "read_only+";
    }	 if ((FAInput & 0x0002)) {/*If Then in one Line*/
        FAOutput += "hidden+";
    }	 if ((FAInput & 0x0004)) {/*If Then in one Line*/
        FAOutput += "system+";
    }	 if ((FAInput & 0x0010)) {/*If Then in one Line*/
        FAOutput += "directory1+";
    }	 if ((FAInput & 0x0020)) {/*If Then in one Line*/
        FAOutput += "archive+";
    }	 if ((FAInput & 0x0040)) {/*If Then in one Line*/
        FAOutput += "device+";
    }	 if ((FAInput & 0x0080)) {/*If Then in one Line*/
        FAOutput += "normal+";
    }	 if ((FAInput & 0x0100)) {/*If Then in one Line*/
        FAOutput += "temporary+";
    }	 if ((FAInput & 0x0200)) {/*If Then in one Line*/
        FAOutput += "sparse_file+";
    }	 if ((FAInput & 0x0400)) {/*If Then in one Line*/
        FAOutput += "reparse_point+";
    }	 if ((FAInput & 0x0800)) {/*If Then in one Line*/
        FAOutput += "compressed+";
    }	 if ((FAInput & 0x1000)) {/*If Then in one Line*/
        FAOutput += "offline+";
    }	 if ((FAInput & 0x2000)) {/*If Then in one Line*/
        FAOutput += "not_content_indexed+";
    }	 if ((FAInput & 0x4000)) {/*If Then in one Line*/
        FAOutput += "encrypted+";
    }	 if ((FAInput & 0x8000)) {/*If Then in one Line*/
        FAOutput += "integrity_stream+";
    }	 if ((FAInput & 0x10000)) {/*If Then in one Line*/
        FAOutput += "virtual+";
    }	 if ((FAInput & 0x20000)) {/*If Then in one Line*/
        FAOutput += "no_scrub_data+";
    }	 if ((FAInput & 0x40000)) {/*If Then in one Line*/
        FAOutput += "ea+";
    }	 if ((FAInput & 0x80000)) {/*If Then in one Line*/
        FAOutput += "pinned+";
    }	 if ((FAInput & 0x100000)) {/*If Then in one Line*/
        FAOutput += "unpinned+";
    }	 if ((FAInput & 0x400000)) {/*If Then in one Line*/
        FAOutput += "recall_on_data_access+";
    }	 if ((FAInput & 0x10000000)) {/*If Then in one Line*/
        FAOutput += "directory+";
    }	 if ((FAInput & 0x20000000)) {/*If Then in one Line*/
        FAOutput += "index_view+";  //Comment: strictly_sequencial?;
    }
    FAOutput = StringTrimRight(FAOutput, 1);
    return  FAOutput;
}


std::string _GetReparseType(std::string ReparseType)
{
    if (ReparseType.empty())
    {
        return {};
    }
    if (ReparseType[1] != 'x')
    {
        // 未添加0x
        ReparseType = "0x" + ReparseType;
    }
    //Comment:winnt.h;
    //Comment:ntifs.h;
/*AutoIt_Select 	*/
    if (false) {
    }
    else if (ReparseType == "0x00000000") { /*Case替换*/
        return  "RESERVED_ZERO";
    }
    else if (ReparseType == "0x00000001") { /*Case替换*/
        return  "RESERVED_ONE";
    }
    else if (ReparseType == "0x00000002") { /*Case替换*/
        return  "RESERVED_TWO";
    }
    else if (ReparseType == "0x80000005") { /*Case替换*/
        return  "DRIVER_EXTENDER";
    }
    else if (ReparseType == "0x80000006") { /*Case替换*/
        return  "HSM2";
    }
    else if (ReparseType == "0x80000007") { /*Case替换*/
        return  "SIS";
    }
    else if (ReparseType == "0x80000008") { /*Case替换*/
        return  "WIM";
    }
    else if (ReparseType == "0x80000009") { /*Case替换*/
        return  "CSV";
    }
    else if (ReparseType == "0x8000000A") { /*Case替换*/
        return  "DFS";
    }
    else if (ReparseType == "0x8000000B") { /*Case替换*/
        return  "FILTER_MANAGER";
    }
    else if (ReparseType == "0x80000012") { /*Case替换*/
        return  "DFSR";
    }
    else if (ReparseType == "0x80000013") { /*Case替换*/
        return  "DEDUP";
    }
    else if (ReparseType == "0x80000014") { /*Case替换*/
        return  "NFS";
    }
    else if (ReparseType == "0x80000015") { /*Case替换*/
        return  "FILE_PLACEHOLDER";
    }
    else if (ReparseType == "0x80000017") { /*Case替换*/
        return  "WOF";
    }
    else if (ReparseType == "0x80000018") { /*Case替换*/
        return  "WCI";
    }
    else if (ReparseType == "0x80000019") { /*Case替换*/
        return  "GLOBAL_REPARSE";
    }
    else if (ReparseType == "0x8000001B") { /*Case替换*/
        return  "APPEXECLINK";
    }
    else if (ReparseType == "0x8000001E") { /*Case替换*/
        return  "HFS";
    }
    else if (ReparseType == "0x80000020") { /*Case替换*/
        return  "UNHANDLED";
    }
    else if (ReparseType == "0x80000021") { /*Case替换*/
        return  "ONEDRIVE";
    }
    else if (ReparseType == "0x80000023") { /*Case替换*/
        return  "AF_UNIX";
    }
    else if (ReparseType == "0x9000001C") { /*Case替换*/
        return  "PROJFS";
    }
    else if (ReparseType == "0x9000001A") { /*Case替换*/
        return  "CLOUD";
    }
    else if (ReparseType == "0x90001018") { /*Case替换*/
        return  "WCI_1";
    }
    else if (ReparseType == "0x9000101A") { /*Case替换*/
        return  "CLOUD_1";
    }
    else if (ReparseType == "0x9000201A") { /*Case替换*/
        return  "CLOUD_2";
    }
    else if (ReparseType == "0x9000301A") { /*Case替换*/
        return  "CLOUD_3";
    }
    else if (ReparseType == "0x9000401A") { /*Case替换*/
        return  "CLOUD_4";
    }
    else if (ReparseType == "0x9000501A") { /*Case替换*/
        return  "CLOUD_5";
    }
    else if (ReparseType == "0x9000601A") { /*Case替换*/
        return  "CLOUD_6";
    }
    else if (ReparseType == "0x9000701A") { /*Case替换*/
        return  "CLOUD_7";
    }
    else if (ReparseType == "0x9000801A") { /*Case替换*/
        return  "CLOUD_8";
    }
    else if (ReparseType == "0x9000901A") { /*Case替换*/
        return  "CLOUD_9";
    }
    else if (ReparseType == "0x9000A01A") { /*Case替换*/
        return  "CLOUD_A";
    }
    else if (ReparseType == "0x9000B01A") { /*Case替换*/
        return  "CLOUD_B";
    }
    else if (ReparseType == "0x9000C01A") { /*Case替换*/
        return  "CLOUD_C";
    }
    else if (ReparseType == "0x9000D01A") { /*Case替换*/
        return  "CLOUD_D";
    }
    else if (ReparseType == "0x9000E01A") { /*Case替换*/
        return  "CLOUD_E";
    }
    else if (ReparseType == "0x9000F01A") { /*Case替换*/
        return  "CLOUD_F";
    }
    else if (ReparseType == "0x9000401A") { /*Case替换*/
        return  "CLOUD_MASK";
    }
    else if (ReparseType == "0x0000F000") { /*Case替换*/
        return  "GVFS";
    }
    else if (ReparseType == "0xA0000003") { /*Case替换*/
        return  "MOUNT_POINT";
    }
    else if (ReparseType == "0xA000000C") { /*Case替换*/
        return  "SYMLINK";
    }
    else if (ReparseType == "0xA0000010") { /*Case替换*/
        return  "IIS_CACHE";
    }
    else if (ReparseType == "0xA0000019") { /*Case替换*/
        return  "GLOBAL_REPARSE";
    }
    else if (ReparseType == "0xA000001D") { /*Case替换*/
        return  "LX_SYMLINK";
    }
    else if (ReparseType == "0xA000001F") { /*Case替换*/
        return  "WCI_TOMBSTONE";
    }
    else if (ReparseType == "0xA0000022") { /*Case替换*/
        return  "GVFS_TOMBSTONE";
    }
    else if (ReparseType == "0xA0000027") { /*Case替换*/
        return  "WCI_LINK";
    }
    else if (ReparseType == "0xA0001027") { /*Case替换*/
        return  "WCI_LINK_1";
    }
    else if (ReparseType == "0xA0000028") { /*Case替换*/
        return  "DATALESS_CIM";
    }
    else if (ReparseType == "0xC0000004") { /*Case替换*/
        return  "HSM";
    }
    else if (ReparseType == "0xC0000014") { /*Case替换*/
        return  "APPXSTRM";
    }
    else { /*Case Else替换*/

        return  "UNKNOWN(" + ReparseType + ")";
    }/*AutoIt_EndSelect 	*/
}

int64_t begin, ElapsedTime, CurrentRecord, i, PreviousUsn, PreviousUsnFileName;
int64_t PreviousAttribute, PreviousUsnReason, undo_length, RealMftRef, PreviousRealRef, FromRcrdSlack;
// PreviousRedoOp;

int64_t IncompleteTransaction = 0;

int64_t this_lsn, client_previous_lsn, record_offset_in_mft, attribute_offset, hOutFileMFT, tBuffer, nBytes2, HDR_BaseRecord, FilePath, HDR_SequenceNo;

int64_t GlobalDataKeepCounter = 0, GlobalRecordSpreadCounter = 0, GlobalRecordSpreadReset = 0, GlobalRecordSpreadReset2 = 0;
bool doSlackScan = true;
const char* CharReplacement = ":";
const char* de = "|";
const char* PrecisionSeparator = ".";
const char* PrecisionSeparator2 = "";
bool DoSplitCsv = false;

bool DoRebuildBrokenHeader = false;
int64_t MinSizeBrokenTransaction = 80;
int64_t Is32bit = 0;
int64_t DoExtractResidentUpdates = 0;
int64_t BrokenLogFile = 0;
int64_t last_lsn_tmp = 0;
int64_t last_end_lsn_tmp = 0;

int64_t lsn_openattributestable = 0;


std::vector<std::vector<std::string>> OpenAttributesArray;
std::vector<std::vector<std::string>> SlackOpenAttributesArray;
int64_t InOpenAttributeTable = 0;

int64_t RedoChunkSize, UndoChunkSize, KeptRefTmp, redo_length;
int64_t KeptRef = -1;

void _ClearVar()
{
    // result.PredictedRefNumber = {};
    this_lsn = {};
    client_previous_lsn = {};
    result.redo_operation = {};
    result.undo_operation = {};
    record_offset_in_mft = {};
    attribute_offset = {};
    // record_type = {};
    // transaction_id = {};
    // lf_flags = {};
    // target_attribute = {};
    // lcns_to_follow = {};
    // MftClusterIndex = {};
    // target_vcn = {};
    // target_lcn = {};
    // InOpenAttributeTable = -1;
    IncompleteTransaction = 0;
    // DT_Flags = {};
    // DT_NonResidentFlag = {};
    // DT_ComprUnitSize = {};
    // DT_AllocSize = {};
    // DT_RealSize = {};
    // Comment:	FileSizeBytes={};
    // DT_InitStreamSize = {};
    // DT_DataRuns = {};
    // DT_StartVCN = {};
    // DT_LastVCN = {};
    // DT_AllocSize = {};
    // DT_Name = {};
    // result.FN_Name = {};
    // DT_OffsetToDataRuns = {};
    // SI_CTime = {};
    // SI_ATime = {};
    // SI_MTime = {};
    // SI_RTime = {};
    // SI_RTime = {};
    // SI_FilePermission = {};
    // SI_MaxVersions = {};
    // SI_VersionNumber = {};
    // SI_ClassID = {};
    // SI_SecurityID = {};
    // SI_QuotaCharged = {};
    // SI_USN = {};
    // SI_PartialValue = {};
    // result.FN_CTime = {};
    // result.FN_ATime = {};
    // result.FN_MTime = {};
    // result.FN_RTime = {};
    // result.FN_AllocSize = {};
    // result.FN_RealSize = {};
    // result.FN_Flags = {};
    // result.FN_Name = {};
    // result.FN_NameType = {};
    // UsnJrnlFileName = {};
    // FileNameModified = {};
    // UsnJrnlFileReferenceNumber = {};
    // UsnJrnlParentFileReferenceNumber = {};
    // UsnJrnlTimestamp = {};
    // UsnJrnlReason = {};
    // UsnJrnlUsn = {};
    result.AttributeString = "";
    HDR_BaseRecord = {};
    HDR_SequenceNo = {};
    //TextInformation = {};
    // RedoChunkSize = {};
    // UndoChunkSize = {};
    // CurrentTimestamp = {};
    // RealMftRef = {};
    // undo_length = {};
    // redo_length = {};
    if (DoSplitCsv)
    {	/*If then*/
        SI_CTime_Core = {};
        SI_ATime_Core = {};
        SI_MTime_Core = {};
        SI_RTime_Core = {};
        SI_CTime_Precision = {};
        SI_ATime_Precision = {};
        SI_MTime_Precision = {};
        SI_RTime_Precision = {};
        /*     result.FN_CTime_Core = {};
             result.FN_ATime_Core = {};
             result.FN_MTime_Core = {};
             result.FN_RTime_Core = {};
             result.FN_CTime_Precision = {};
             result.FN_ATime_Precision = {};
             result.FN_MTime_Precision = {};
             result.FN_RTime_Precision = {};*/
    }	/*End of If*/
}

/*
@param OffsetAdjustment 之前不完整的数据数量
@param RCRDOffset 当前RCRD在整个LogFile中的位移
*/
std::string _DecodeRCRD(const std::string_view& RCRDRecord, DWORD RCRDOffset, int64_t OffsetAdjustment, int64_t DoNotReturnData)
{
    // 找到的日志记录占整个LogFile区域的offset
    uint32_t RecordOffset = 0;

    int64_t DataPart = 0;
    int64_t NextOffset = 131;
    int64_t TotalSizeOfRCRD = RCRDRecord.size();
    int64_t CharsToMove = 0;
    int64_t LsnSignatureFound = 0, last_lsn_tmp_refup, last_lsn_tmp_refdown, RebuiltLsn;
    // Local ZeroSample="0000000000000000", LsnSignatureLength=10;
    int64_t SlackPerRCRDCounter = 0;
    //char* result.PredictedRefNumber = "";

    // 如果RCRD头后面有稀疏的未识别的一串数字,则此值在后面判断中设置为1
    FromRcrdSlack = 0;

    if (BrokenLogFile)
    {
        FromRcrdSlack = 1;
    }
    _DumpOutput("<<<<<<<<<<<<<<<DecodeRCRD>>>>>>>>>>>>>>>>\r\n");
    _DumpOutput("RCRDOffset: 0x" + utils::format::hex(RCRDOffset, false, false));

    // ConsoleWrite(_HexEncode(StringMid(RCRDRecord,1,130)) +  "\r\n");
    // ConsoleWrite("TotalSizeOfRCRD: 0x"  Hex(Int((TotalSizeOfRCRD-3)/2),8) +  "\r\n");
    // ConsoleWrite(_HexEncode(Dec(StringMid(RCRDRecord,131)) +  )"\r\n");
    // ConsoleWrite(_HexEncode(StringMid(RCRDRecord,1)) +  "\r\n")

    // last_lsn_tmp = StringMid(RCRDRecord,19,16);
    // last_lsn_tmp = Dec(_SwapEndian(last_lsn_tmp),2;
    auto pRecordBegin = RCRDRecord.data();
    auto pPageHeader = PRECORD_PAGE_HEADER(pRecordBegin);

    //last_lsn_tmp = pPageHeader->copy.last_lsn;
    last_lsn_tmp = Dec(_SwapEndian(StringMid(RCRDRecord, 19, 16)), 2);


    last_end_lsn_tmp = Dec(_SwapEndian(StringMid(RCRDRecord, 67, 16)), 2);
    //last_end_lsn_tmp = pPageHeader->header.packed.last_end_lsn;

    int64_t max_last_lsn = max(last_lsn_tmp, last_end_lsn_tmp);

    // LsnValidationLevel 取自界面上的 LSN error leve 默认值 0.1%。根据;
    // 用来在验证结构或者使用损坏的日志时,限定lsn上下限
    last_lsn_tmp_refup = std::round(max_last_lsn * (1 + LsnValidationLevel));
    last_lsn_tmp_refdown = std::round(max_last_lsn * (1 - LsnValidationLevel));

    //int64_t this_lsn_tmp = *(int64_t*)(pRecordBegin + NextOffset);
    int64_t this_lsn_tmp = Dec(_SwapEndian(StringMid(RCRDRecord, NextOffset, 16)), 2);

    //int64_t next_record_offset = pPageHeader->header.packed.next_record_offset;
    int64_t next_record_offset = Dec(_SwapEndian(StringMid(RCRDRecord, 51, 4)), 2);


    //int64_t client_previous_lsn_tmp = *(int64_t*)(pRecordBegin + NextOffset + 16); 
    int64_t client_previous_lsn_tmp = Dec(_SwapEndian(StringMid(RCRDRecord, NextOffset + 16, 16)), 2);


    //int64_t client_undo_next_lsn_tmp = *(int64_t*)(pRecordBegin + NextOffset + 32);
    int64_t client_undo_next_lsn_tmp = Dec(_SwapEndian(StringMid(RCRDRecord, NextOffset + 32, 16)), 2);

    // if ( (this_lsn_tmp > last_lsn_tmp)  ||  (this_lsn_tmp < last_lsn_tmp - 1000) );
    // 	_DumpOutput("Error: RCRD seems corrupt at offset: 0x"  Hex(RCRDOffset,8) +  "\r\n");
    // 	_DumpOutput("Bytes reassembled: "  OffsetAdjustment +  "\r\n");
    // 	_DumpOutput("last_lsn_tmp: "  last_lsn_tmp +  "\r\n");
    // 	_DumpOutput("this_lsn_tmp: "  this_lsn_tmp +  "\r\n");
    // 	_DumpOutput(_HexEncode(StringMid(RCRDRecord,1)) +  "\r\n");
    // 	return {};;
    // }
    // TestChunk2 = StringMid(last_lsn_tmp_mod,16-LsnSignatureLength);
    // ConsoleWrite("TestChunk2: "  TestChunk2 +  "\r\n");
    if ((this_lsn_tmp > max_last_lsn) || (client_previous_lsn_tmp > max_last_lsn) || (client_undo_next_lsn_tmp > max_last_lsn) || (this_lsn_tmp < last_lsn_tmp_refdown) || (client_previous_lsn_tmp < last_lsn_tmp_refdown && client_previous_lsn_tmp != 0) || (client_undo_next_lsn_tmp < last_lsn_tmp_refdown && client_undo_next_lsn_tmp != 0))
    {
        _DumpOutputPrintf("Scanning for LSN signature from RCRD offset: 0x%s\r\n", utils::format::hex(RCRDOffset, false, false).c_str());
        // 	_DumpOutput("DoNotreturn 0;Data: "  DoNotreturn 0;Data +  "\r\n");
        // 	_DumpOutput("OffsetAdjustment: "  OffsetAdjustment +  "\r\n");
        // 	_DumpOutput("last_lsn_tmp: "  last_lsn_tmp +  "\r\n");
        // 	_DumpOutput("last_end_lsn_tmp: "  last_end_lsn_tmp +  "\r\n");
        // 	_DumpOutput("max_last_lsn: "  max_last_lsn +  "\r\n");
        // 	_DumpOutput("last_lsn_tmp_refup: "  last_lsn_tmp_refup +  "\r\n");
        // 	_DumpOutput("last_lsn_tmp_refdown: "  last_lsn_tmp_refdown +  "\r\n");
        // 	_DumpOutput("NextOffset: "  NextOffset +  "\r\n");
        // 	_DumpOutput("CharsToMove: "  CharsToMove +  "\r\n");

        while (1)
        {
            if (CharsToMove + NextOffset > TotalSizeOfRCRD)
            {
                break;
            }
            // 		_DumpOutput(Dec(Hex(Int((NextOffset+CharsToMove)-3)/2),8) +  "\r\n");
            std::string TestChunk1Str = StringMid(RCRDRecord, NextOffset + CharsToMove, 16);
            int64_t TestChunk1 = Dec(_SwapEndian(TestChunk1Str), 2);
            // 		_DumpOutput("TestChunk1: "  TestChunk1 +  "\r\n")

            if ((TestChunk1 > last_lsn_tmp_refdown) && (TestChunk1 < last_lsn_tmp_refup))
            {
                std::string TestChunk2Str = StringMid(RCRDRecord, NextOffset + CharsToMove + 16, 16);
                int64_t TestChunk2 = Dec(_SwapEndian(TestChunk2Str), 2);
                // 			_DumpOutput("TestChunk2: "  TestChunk2 +  "\r\n");
                std::string TestChunk3Str = StringMid(RCRDRecord, NextOffset + CharsToMove + 16 + 16, 16);
                int64_t TestChunk3 = Dec(_SwapEndian(TestChunk3Str), 2);
                // 			_DumpOutput("TestChunk3: "  TestChunk3 +  "\r\n");
                if (((TestChunk2 > last_lsn_tmp_refdown) && (TestChunk2 < last_lsn_tmp_refup)) || (TestChunk2 == 0))
                {
                    if (((TestChunk3 > last_lsn_tmp_refdown) && (TestChunk3 < last_lsn_tmp_refup)) || (TestChunk3 == 0))
                    {
                        //				ConsoleWrite("Match1!!!"   "\r\n");
                        LsnSignatureFound = 1;
                        break;
                    }
                    else
                    {
                        //				ConsoleWrite("False positive"   "\r\n");
                        CharsToMove += 16;

                        continue;
                    }
                }
                else
                {
                    //			ConsoleWrite("False positive"   "\r\n");
                    CharsToMove += 16;
                    continue;
                }
                // 			ConsoleWrite("Match2!!!"   "\r\n");
                // 			break;
            }

            CharsToMove += 16;
            if (CharsToMove + NextOffset > TotalSizeOfRCRD)
            {
                break;
            }
        } // end of while

        if (!LsnSignatureFound)
        {
            _DumpOutput("LSN signature not found:");
            _DumpOutputHex(/*_HexEncode*/(StringMid(RCRDRecord, NextOffset)));
            return {};;
        }
        else
        {
            if (CharsToMove > 0)
            {
                if (DoNotReturnData > 0 && OffsetAdjustment > 0)
                {
                    // This check should not be necessary?????????????????????????;
                    RecordOffset = RCRDOffset - OffsetAdjustment / 2;
                    // 				_DumpOutput("Unknown slack space found at record offset 0x"  Hex(Int(RCRDOffset-OffsetAdjustment+(NextOffset-3)/2),8) + " - 0x"  Hex(Int(RCRDOffset-OffsetAdjustment+(NextOffset+CharsToMove-3)/2),8) +  "\r\n");
                    _DumpOutput("Unknown slack space found at record offset 0x" + Hex(Int(RCRDOffset - OffsetAdjustment / 2), 8) + " - 0x" + Hex(Int(RCRDOffset - OffsetAdjustment + CharsToMove / 2), 8));
                }
                else
                {
                    RecordOffset = RCRDOffset + (NextOffset - 3) / 2;
                    _DumpOutput("Unknown slack space found at record offset 0x" + Hex(Int(RCRDOffset + (NextOffset - 3) / 2), 8) + " - 0x" + Hex(Int(RCRDOffset + (NextOffset + CharsToMove - 3) / 2), 8));
                }
                _DumpOutputHex(/*_HexEncode*/(StringMid(RCRDRecord, NextOffset, CharsToMove)));
                if (DoRebuildBrokenHeader && CharsToMove >= MinSizeBrokenTransaction)
                {
                    // TODO 代码暂时不实现
                    // _DumpOutput("Attempting a repair of possible broken header 1.."
                    // 			"\r\n");
                    // ClientData = _CheckAndRepairTransactionHeader(StringMid(RCRDRecord, NextOffset, CharsToMove));
                    // if (!::GetLastError())
                    // {
                    // 	RebuiltLsn = StringMid(ClientData, 1, 16);
                    // 	RebuiltLsn = Dec(_SwapEndian(RebuiltLsn), 2);
                    // 	IncompleteTransaction = 1 _DecodeLSNRecord(ClientData, RebuiltLsn);
                    // }
                }
            }
            _DumpOutput("Found LSN signature match at record offset 0x" + Hex(Int(RCRDOffset + (NextOffset + CharsToMove - 3) / 2), 8));
            NextOffset += CharsToMove;
        }
        FromRcrdSlack = 1;
    }
    else
    {
        FromRcrdSlack = 0;
    }

    auto SizeOfClientDataStr = StringMid(RCRDRecord, NextOffset + 48, 8);
    auto SizeOfClientData = Dec(_SwapEndian(SizeOfClientDataStr), 2);
    // _DumpOutput("RCRD Offset: 0x"  Hex(RCRDOffset,8) +  "\r\n");
    // _DumpOutput("SizeOfClientData: 0x"  Hex(Int(SizeOfClientData),8) +  "\r\n");
    if (!DoNotReturnData)
    {
        if (96 + (SizeOfClientData * 2) > TotalSizeOfRCRD - NextOffset)
            // 		_DumpOutput("Data returned 0 ("  GlobalDataKeepCounter + ")"   "\r\n");
            // 		_DumpOutput("return {};;ed data:"   "\r\n");
            // 		_DumpOutput(_HexEncode(Dec(StringMid(RCRDRecord,NextOffset)) +  )"\r\n");
            return StringMid(RCRDRecord, NextOffset);
    }

    do
    {
        if (DataPart && GlobalRecordSpreadReset)
        {
            RecordOffset = RCRDOffset + ((NextOffset - OffsetAdjustment - 3 + (128 * GlobalRecordSpreadReset)) / 2);
            // 		RecordOffset = RCRDOffset+((NextOffset-OffsetAdjustment-3)/2);
            //RecordOffset = Dec(Hex(Int(RecordOffset)));
        }
        else if (DataPart)
        {
            RecordOffset = RCRDOffset + ((NextOffset - OffsetAdjustment - 3) / 2);
            //RecordOffset = Dec(Hex(Int(RecordOffset)));
        }
        else
        {
            RecordOffset = RCRDOffset + ((NextOffset - OffsetAdjustment - 3 - (128 * GlobalDataKeepCounter)) / 2);
            //RecordOffset = Dec(Hex(Int(RecordOffset)));
        }

        if (NextOffset - OffsetAdjustment >= next_record_offset * 2)
        {
            // 		_DumpOutput("RCRD Offset: 0x"  Hex(RCRDOffset,8) +  "\r\n");
            if (!DoNotReturnData)
            {
                // 			_DumpOutput("Data returned 1 ("  GlobalDataKeepCounter + ")"   "\r\n");
                // 			_DumpOutput("return {};; data (split record) at end of RCRD at 0x"  Hex(Int(next_record_offset),4) +  "\r\n");
                // 			_DumpOutput("Bytes returned: 0x"  Hex(Int(((TotalSizeOfRCRD-3-OffsetAdjustment)/2)-next_record_offset),8) +  "\r\n");
                // 			_DumpOutput("NextOffset: "  NextOffset +  "\r\n");
                // 			_DumpOutput("OffsetAdjustment: "  OffsetAdjustment +  "\r\n");
                // 			_DumpOutput("NextOffset-OffsetAdjustment: "  NextOffset-OffsetAdjustment +  "\r\n");
                // 			_DumpOutput("next_record_offset: "  next_record_offset*2 +  "\r\n");
                // 			_DumpOutput("next_record_offset: 0x"  Hex(Int(next_record_offset),4) +  "\r\n");
                //		_DumpOutput(_HexEncode(Dec(StringMid(RCRDRecord,3+(next_record_offset*2))) +  )"\r\n");
                // 			_DumpOutput(_HexEncode(Dec(StringMid(RCRDRecord,NextOffset)) +  )"\r\n");
                return StringMid(RCRDRecord, NextOffset);
            }
            else
            {
                if (doSlackScan)
                {
                    if (option.VerboseOn)
                    {
                        _DumpOutput("Analyzing slack space starting at " + Hex((uint64_t)RecordOffset, 8));
                    }
                    _TestSlackSpace(StringMid(RCRDRecord, NextOffset), max_last_lsn, RecordOffset);
                }
                return "";
            }
        }
        auto SizeOfClientDataStr = StringMid(RCRDRecord, NextOffset + 48, 8);
        auto SizeOfClientData = Dec(_SwapEndian(SizeOfClientDataStr), 2);
        SizeOfClientData = SizeOfClientData * 2;

        if (SizeOfClientData == 0)
        {
            _DumpOutput("Error: SizeOfClientData was 0 at " + Hex((uint64_t)RecordOffset));
            _DumpOutputHex(/*_HexEncode*/(StringMid(RCRDRecord, NextOffset)));
            // 		_TestSlackSpace(StringMid(RCRDRecord,NextOffset),last_lsn_tmp,RecordOffset);
            break;
        }
        /*;
            if (RCRDOffset > 0x1A28000){
            _DumpOutput("------------------------------------"  "\r\n");
            _DumpOutput("RCRD Offset: 0x" +Hex(RCRDOffset, 8) +  "\r\n");
            _DumpOutput("SizeOfClientData: 0x" +Hex(Int(SizeOfClientData / 2), 8) +  "\r\n");
            _DumpOutput("SizeOfClientData: " + SizeOfClientData +  "\r\n");
            _DumpOutput("NextOffset: " + NextOffset +  "\r\n");
            _DumpOutput("OffsetAdjustment: " + OffsetAdjustment +  "\r\n");
            _DumpOutput("TotalSizeOfRCRD: " + TotalSizeOfRCRD +  "\r\n");
            }
        */
        auto ClientData = StringMid(RCRDRecord, NextOffset, 96 + SizeOfClientData);

        // 48 bytes header + data

        if (NextOffset - 1 - OffsetAdjustment + 96 + SizeOfClientData > TotalSizeOfRCRD)
        {
            // We need to return the incomplete record, and attach it to the beginning of the next RCRD and continue processing;
            if (!DoNotReturnData)
            {
                // 			_DumpOutput("Data returned 2 ("  GlobalDataKeepCounter + ")"   "\r\n");
                // 			return ""; ClientData;
                return StringMid(RCRDRecord, NextOffset);
            }
            else
            {
                _DumpOutput("Error should not really be here: " + Hex((uint64_t)RecordOffset));
                _DumpOutput("NextOffset: " + std::to_string(NextOffset));
                _DumpOutput("OffsetAdjustment: " + std::to_string(OffsetAdjustment));
                _DumpOutput("SizeOfClientData: " + std::to_string(SizeOfClientData));
                _DumpOutput("Part 1: " + std::to_string(NextOffset - OffsetAdjustment + 96 + SizeOfClientData));
                _DumpOutput("Part 2: " + std::to_string(TotalSizeOfRCRD));
                if (doSlackScan)
                {
                    _TestSlackSpace(ClientData, max_last_lsn, RecordOffset);
                }
                return {};;
            }
        }
        // 	_DumpOutput("Transaction: "   "\r\n");
        // 	_DumpOutput(_HexEncode(Dec(ClientData) +  )"\r\n");
        _DecodeLSNRecord(ClientData, max_last_lsn, RecordOffset);
        NextOffset += 96 + SizeOfClientData;
        DataPart += 1;
    } while (NextOffset < TotalSizeOfRCRD);

    if (!DoNotReturnData)
    {
        _DumpOutput("Error: Something must be wrong"
            "\r\n");
        _DumpOutputHex(/*_HexEncode*/(StringMid(RCRDRecord, NextOffset)));
    }
    return {};;
}

//int64_t FromRcrdSlack = 0;
int64_t SlackPerRCRDCounter = 0;

int64_t _TestSlackSpace(std::string InputData, int64_t last_lsn_tmp, int64_t Offset)
{
    //InputData = SlackSpace data in RCRD;
    //last_lsn_tmp = From header of RCRD;
    int64_t CharsToMove = 0, LsnSignatureFound = 0, TotalSizeOfRCRD = InputData.length();
    int64_t NextOffset = 1, last_lsn_tmp_refup, last_lsn_tmp_refdown;
    FromRcrdSlack += 1;
    SlackPerRCRDCounter += 1;

    if (TotalSizeOfRCRD < MinSizeBrokenTransaction)
    {
        if (option.VerboseOn)
        {
            _DumpOutput("SlackSpace: The size of input data was too small for a valid record header:"
                "\r\n");
            //_DumpOutputHex(/*_HexEncode*/( InputData));
            _DumpOutputHex(InputData);
        }
        return {};;
    }
    else
    {
        // 		_DumpOutput("SlackSpace: Size of input data: 0x"  Hex(Int(TotalSizeOfRCRD/2),8) +  "\r\n");
    }

    last_lsn_tmp_refup = last_lsn_tmp * (1 + LsnValidationLevel);
    last_lsn_tmp_refdown = last_lsn_tmp * (1 - LsnValidationLevel);

    auto this_lsn_tmp = Dec(_SwapEndian(StringMid(InputData, 1, 16)), 2);

    auto client_previous_lsn_tmp = Dec(_SwapEndian(StringMid(InputData, NextOffset + 16, 16)), 2);

    auto client_undo_next_lsn_tmp = Dec(_SwapEndian(StringMid(InputData, NextOffset + 32, 16)), 2);

    // 因为RECORD_PAGE_HEADER后面还有段不定长度的未和数据,然后才是PRECORD_LOG.
    // 所以向后寻找一个结构正常的record的起始位置
    if ((this_lsn_tmp > last_lsn_tmp) || (client_previous_lsn_tmp > last_lsn_tmp) || (client_undo_next_lsn_tmp > last_lsn_tmp) || (this_lsn_tmp < last_lsn_tmp_refdown) || (client_previous_lsn_tmp < last_lsn_tmp_refdown && client_previous_lsn_tmp != 0) || (client_undo_next_lsn_tmp < last_lsn_tmp_refdown && client_undo_next_lsn_tmp != 0))
    {
        if (option.VerboseOn)
        {
            _DumpOutput("SlackSpace: Scanning for LSN signature""\r\n");
        }

        while (1)
        {
            if (CharsToMove + NextOffset > TotalSizeOfRCRD)
            {
                break;
            }
            auto TestChunk1Str = StringMid(InputData, NextOffset + CharsToMove, 16);
            auto TestChunk1 = Dec(_SwapEndian(TestChunk1Str), 2);
            //		ConsoleWrite(Dec(Hex(Int((NextOffset+CharsToMove)-3)/2),8) + " + TestChunk1: "  TestChunk1 +  "\r\n");
            if ((TestChunk1 > last_lsn_tmp_refdown) && (TestChunk1 < last_lsn_tmp_refup))
            {
                // 			if  (last_lsn_tmp_mod==TestChunk  ){
                auto TestChunk2Str = StringMid(InputData, NextOffset + CharsToMove + 16, 16);
                auto TestChunk2 = Dec(_SwapEndian(TestChunk2Str), 2);
                //			ConsoleWrite("TestChunk2: "  TestChunk2 +  "\r\n");
                auto TestChunk3Str = StringMid(InputData, NextOffset + CharsToMove + 16 + 16, 16);
                auto TestChunk3 = Dec(_SwapEndian(TestChunk3Str), 2);
                //			ConsoleWrite("TestChunk3: "  TestChunk3 +  "\r\n");
                if (((TestChunk2 > last_lsn_tmp_refdown) && (TestChunk2 < last_lsn_tmp_refup)) || (TestChunk2 == 0))
                {
                    if (((TestChunk3 > last_lsn_tmp_refdown) && (TestChunk3 < last_lsn_tmp_refup)) || (TestChunk3 == 0))
                    {
                        //				ConsoleWrite("Match1!!!"   "\r\n");
                        LsnSignatureFound = 1;
                        break;
                    }
                    else
                    {
                        //				ConsoleWrite("False positive"   "\r\n");
                        CharsToMove += 16;
                        continue;
                    }
                }
                else
                {
                    //			ConsoleWrite("False positive"   "\r\n");
                    CharsToMove += 16;
                    continue;
                }
                //			ConsoleWrite("Match2!!!"   "\r\n");
                //			break;
            }
            CharsToMove += 16;

            if (CharsToMove + NextOffset > TotalSizeOfRCRD)
            {
                break;
            }
        }
        if (!LsnSignatureFound)
        {
            if (option.VerboseOn)
            {
                _DumpOutput("SlackSpace: LSN signature not found."
                    "\r\n");
                _DumpOutputHex(/*_HexEncode*/(InputData));
            }
            if (DoRebuildBrokenHeader && CharsToMove >= MinSizeBrokenTransaction)
            {
                // TODO 代码暂时不实现
                // RecordOffset = "0x" +Hex(Int(Offset), 8);
                // _DumpOutput("Attempting a repair of possible broken header 2.."
                // 			"\r\n");
                // ClientData = _CheckAndRepairTransactionHeader(StringMid(InputData, NextOffset, CharsToMove)) if (!::GetLastError())
                // {
                // 	RebuiltLsn = StringMid(ClientData, 1, 16);
                // 	RebuiltLsn = Dec(_SwapEndian(RebuiltLsn), 2);
                // 	IncompleteTransaction = 1 _DecodeLSNRecord(ClientData, RebuiltLsn);
                // }
            }
            return {};;
        }
        else
        {
            if (CharsToMove > 0)
            {
                _DumpOutput("Unknown slack space found at record offset 0x" + Hex(Int(Offset) + (NextOffset) / 2, 8) + " - 0x" + Hex(Int(Offset) + (NextOffset + CharsToMove) / 2, 8));
                _DumpOutputHex(/*_HexEncode*/(StringMid(InputData, NextOffset, CharsToMove)));
                if (DoRebuildBrokenHeader && CharsToMove >= MinSizeBrokenTransaction)
                {
                    // TODO DoRebuildBrokenHeader代码暂时不实现

                    // RecordOffset = "0x" +Hex(Int(Offset + (NextOffset) / 2), 8);
                    // _DumpOutput("Attempting a repair of possible broken header 3.."
                    // 			"\r\n");
                    // ClientData = _CheckAndRepairTransactionHeader(StringMid(InputData, NextOffset, CharsToMove)) if (!::GetLastError())
                    // {
                    // 	RebuiltLsn = StringMid(ClientData, 1, 16);
                    // 	RebuiltLsn = Dec(_SwapEndian(RebuiltLsn), 2);
                    // 	IncompleteTransaction = 1 _DecodeLSNRecord(ClientData, RebuiltLsn);
                    // }
                }
            }
            // 			_DumpOutput(_HexEncode(Dec(StringMid(InputData,NextOffset,CharsToMove)) +  )"\r\n");
            _DumpOutput("SlackSpace: Found LSN signature match at record offset 0x" + Hex(Offset + (NextOffset + CharsToMove) / 2, 8));
            NextOffset += CharsToMove;
        }
    }

    do
    {
        if (NextOffset >= TotalSizeOfRCRD)
        {
            return {};;
        }
        auto RecordOffset = Offset + (NextOffset / 2);
        //RecordOffset = Dec(Hex(RecordOffset));

        this_lsn_tmp = Dec(_SwapEndian(StringMid(InputData, NextOffset, 16)), 2);

        auto client_previous_lsn_tmp = Dec(_SwapEndian(StringMid(InputData, NextOffset + 16, 16)), 2);

        auto client_undo_next_lsn_tmp = Dec(_SwapEndian(StringMid(InputData, NextOffset + 32, 16)), 2);

        // We need some sanity checking on the next bytes;
        if ((this_lsn_tmp > last_lsn_tmp) || (client_previous_lsn_tmp > last_lsn_tmp) || (client_undo_next_lsn_tmp > last_lsn_tmp) || (this_lsn_tmp < last_lsn_tmp_refdown) || (client_previous_lsn_tmp < last_lsn_tmp_refdown && client_previous_lsn_tmp != 0) || (client_undo_next_lsn_tmp < last_lsn_tmp_refdown && client_undo_next_lsn_tmp != 0))
        {
            _DumpOutput("SlackSpace: Invalid record header at 0x" + Hex(Int(Offset) + (NextOffset / 2)));
            _DumpOutput("SlackSpace: Rescanning for LSN signature."
                "\r\n");
            if (SlackPerRCRDCounter < 1800)
            {
                if (doSlackScan)
                {
                    _TestSlackSpace(StringMid(InputData, NextOffset), last_lsn_tmp, Offset + (NextOffset / 2));
                }
                return {};;
            }
            else
            {
                return {};;
            }
        }

        auto SizeOfClientData = Dec(_SwapEndian(StringMid(InputData, NextOffset + 48, 8)), 2) * 2;
        if (SizeOfClientData == 0)
        {
            _DumpOutput("SlackSpace: Error SizeOfClientData = 0 at 0x" + Hex(std::to_string(Int(Offset) + (NextOffset / 2))));
            // 			_TestSlackSpace(StringMid(InputData,NextOffset),last_lsn_tmp,Offset+(NextOffset/2));
            break;
        }

        auto ClientData = StringMid(InputData, NextOffset, 96 + SizeOfClientData);
        if (NextOffset - 1 + 96 + SizeOfClientData > TotalSizeOfRCRD)
        {
            // maybe we should attempt parsing incomplete records as this is record slack space..;
            _DumpOutput("SlackSpace: Warning incomplete record at 0x" + Hex(std::to_string(Int(Offset) + (NextOffset / 2))));
            // 			_DumpOutput("SlackSpace: NextOffset: "  NextOffset +  "\r\n");
            // 			_DumpOutput("SlackSpace: SizeOfClientData: "  SizeOfClientData +  "\r\n");
            // 			_DumpOutput("SlackSpace: Part 1: "  NextOffset+96+SizeOfClientData +  "\r\n");
            // 			_DumpOutput("SlackSpace: Part 2: "  TotalSizeOfRCRD +  "\r\n");
            // 			_DumpOutput(_HexEncode(Dec(ClientData) +  )"\r\n");
            _DecodeLSNRecord(ClientData, this_lsn_tmp, RecordOffset);
            return {};;
        }

        _DumpOutput("SlackSpace: Parsing identif ied record at 0x" + utils::format::hex((uint64_t)RecordOffset));
        // 		_DumpOutput("RecordOffset: "  RecordOffset +  "\r\n");
        // 		_DumpOutput(_HexEncode(Dec(ClientData) +  )"\r\n");
        _DecodeLSNRecord(ClientData, this_lsn_tmp, RecordOffset);
        NextOffset = NextOffset + 96 + SizeOfClientData;
    } while (NextOffset >= TotalSizeOfRCRD);
}

int64_t _DecodeLSNRecord(std::string InputData, int64_t last_lsn_tmp, int64_t RecordOffset)
{
    int64_t DecodeOk = false, UsnOk = false, TestAttributeType, ResolvedAttributeOffset, FoundInTable = -1, FoundInTableSlack = -1, last_lsn_tmp_refdown, FoundInTableDummy = -1,
        FoundInTableSlackDummy = -1;

    std::string AttrNameTmp;
    result.AttributeString = "";

    this_lsn = Dec(_SwapEndian(StringMid(InputData, 1, 16)), 2);
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("--- Start decoding LSN: " + std::to_string(this_lsn));
    } /*End of If*/

    //last_lsn_tmp_refup = last_lsn_tmp*(1+LsnValidationLevel);
    last_lsn_tmp_refdown = last_lsn_tmp * (1 - LsnValidationLevel);

    //<Test for valid lsn>;
    if ((this_lsn > last_lsn_tmp) || (this_lsn < last_lsn_tmp_refdown))
    { /*If then*/
        _DumpOutput("Error: RCRD seems corrupt at offset: " + Hex((uint64_t)RecordOffset));
        _DumpOutput("last_lsn_tmp: " + std::to_string(last_lsn_tmp));
        _DumpOutput("this_lsn: " + std::to_string(this_lsn));
        _DumpOutputHex(/*_HexEncode*/(StringMid(InputData, 1)));
        _ClearVar();
        return {};;
    } /*End of If*/ //
    //</Test for valid lsn>

    auto client_previous_lsnStr = StringMid(InputData, 17, 16);
    auto client_previous_lsn = Dec(_SwapEndian(client_previous_lsnStr), 2);

    auto client_undo_next_lsnStr = StringMid(InputData, 33, 16);
    auto client_undo_next_lsn = Dec(_SwapEndian(client_undo_next_lsnStr), 2);
    auto client_data_lengthStr = StringMid(InputData, 49, 8);
    auto client_data_length = Dec(_SwapEndian(client_data_lengthStr), 2);
    auto client_indexStr = StringMid(InputData, 57, 8);
    auto client_index = Dec(_SwapEndian(client_indexStr));
    auto record_typeStr = StringMid(InputData, 65, 8);
    auto record_type = Dec(_SwapEndian(record_typeStr), 2);
    auto transaction_idStr = StringMid(InputData, 73, 8);
    auto transaction_id = Dec(_SwapEndian(transaction_idStr));
    auto lf_flagsStr = StringMid(InputData, 81, 4);
    auto lf_flags = Dec(_SwapEndian(lf_flagsStr));
    //alignment_or_reserved0 = StringMid(InputData,85,12);
    auto redo_operation_hex = StringMid(InputData, 97, 4);
    auto redo_operation_value = Dec(_SwapEndian(redo_operation_hex), 2);
    result.redo_operation = _SolveUndoRedoCodes(redo_operation_value);

    auto undo_operation_hex = StringMid(InputData, 101, 4);
    auto undo_operation_value = Dec(_SwapEndian(undo_operation_hex), 2);
    result.undo_operation = _SolveUndoRedoCodes(undo_operation_value);

    auto redo_offsetStr = StringMid(InputData, 105, 4);
    auto redo_offset = Dec(_SwapEndian(redo_offsetStr), 2);
    auto redo_lengthStr = StringMid(InputData, 109, 4);
    auto redo_length = Dec(_SwapEndian(redo_lengthStr), 2);
    auto undo_offsetStr = StringMid(InputData, 113, 4);
    auto undo_offset = Dec(_SwapEndian(undo_offsetStr), 2);
    auto undo_lengthStr = StringMid(InputData, 117, 4);
    auto undo_length = Dec(_SwapEndian(undo_lengthStr), 2);
    auto target_attributeStr = StringMid(InputData, 121, 4);
    auto target_attribute = Dec(_SwapEndian(target_attributeStr));

    // Align tmp sizes to 8 bytes;
    auto redo_length_tmp = redo_length;
    if (Mod(redo_length_tmp, 8))
    { /*If then*/
        while (1)
        { // TODO条件手动替换;
            redo_length_tmp += 1;
            if (Mod(redo_length_tmp, 8) == 0)
            {		   /*If then*/
                break; //
            }
        } // End of while;
    }
    /*End of If */

    auto undo_length_tmp = undo_length;
    if (Mod(undo_length_tmp, 8))
    { /*If then*/
        while (1)
        { // TODO条件手动替换;
            undo_length_tmp += 1;
            if (Mod(undo_length_tmp, 8) == 0)
            {		   /*If then*/
                break; //
            }
        } // End of while;
    }	  /*End of If*/

    // Validation check of header values;
    int64_t ValidationTest1 = result.redo_operation == "SetNewAttributeSizes" && client_data_length < undo_offset + undo_length_tmp;

    int64_t ValidationTest2 = client_data_length != undo_offset + undo_length_tmp && result.redo_operation != "CompensationlogRecord" && result.redo_operation != "SetNewAttributeSizes" && result.redo_operation != "ForgetTransaction" && (result.redo_operation != "Noop" && result.undo_operation != "Noop");

    int64_t ValidationTest3 = client_data_length != redo_offset + redo_length_tmp && result.redo_operation != "CompensationlogRecord" && result.redo_operation != "SetNewAttributeSizes" && result.redo_operation != "ForgetTransaction" && (result.redo_operation != "Noop" && result.undo_operation != "Noop");

    int64_t ValidationTest4 = result.redo_operation == "UNKNOWN";
    int64_t ValidationTest5 = result.undo_operation == "UNKNOWN";



    // Local ValidationTest6 = client_data_length != redo_offset+redo_length_tmp && client_data_length != undo_offset+undo_length_tmp && result.redo_operation != "CompensationlogRecord" && result.redo_operation != "SetNewAttributeSizes";
    if (ValidationTest1 || (ValidationTest2 && ValidationTest3) || (ValidationTest4 && ValidationTest5))
    { /*If then*/
        // If ((client_data_length != undo_offset+undo_length_tmp && result.redo_operation != "CompensationlogRecord") && (client_data_length != redo_offset+redo_length_tmp && result.redo_operation != "CompensationlogRecord"))  ||result.redo_operation=="UNKNOWN"    ||result.undo_operation=="UNKNOWN"  Then;
        _DumpOutput("Error: Validation of header values failed at offset: 0x" + Hex((uint64_t)RecordOffset, 8));
        _DumpOutput("this_lsn: " + std::to_string(this_lsn));
        _DumpOutput("client_data_length: 0x" + Hex(client_data_length));
        _DumpOutput("redo_offset: 0x" + Hex(redo_offset, 4));
        _DumpOutput("redo_length_tmp: 0x" + Hex(redo_length_tmp, 4));
        _DumpOutput("undo_offset: 0x" + Hex(undo_offset, 4));
        _DumpOutput("undo_length_tmp: 0x" + Hex(undo_length_tmp, 4));
        _DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex));
        _DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation));
        _DumpOutput("undo_operation_hex: " + std::to_string(undo_operation_hex));
        _DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation));
        _DumpOutputHex(/*_HexEncode*/(StringMid(InputData, 1)));
        _ClearVar();
        return {};;
    } /*End of If*/
    //
    // With broken format LogFile, as from reconstructed RCRD's, chances are that we might hit transactions with mostly 00's, which can't be decoded. But we need to filter.;
    if (BrokenLogFile)
    { /*If then*/
        if (!((result.redo_operation == "ForgetTransaction" && result.undo_operation == "CompensationlogRecord") || (result.redo_operation == "Noop" && result.undo_operation == "Noop")))
        { /*If then*/
            const char* RegExPatternHexNotNull = "[1-9a-fA-F]";
            if (!StringRegExp(StringMid(InputData, 145), RegExPatternHexNotNull))
            { /*If then*/
                _DumpOutput("Error at offset 0x" + utils::format::hex((uint64_t)RecordOffset, 8));
                _DumpOutput("There was only zero's after the transaction header, which means it was too corrupted to process properly\r\n");
                _DumpOutput("this_lsn: " + std::to_string(this_lsn));
                _DumpOutputHex(/*_HexEncode*/(StringMid(InputData, 1)));
                return {};;
            } /*End of If*/
        }	  /*End of If*/
    }		  /*End of If*/
    //
    // Test for incomplete records grabbed from slack space;
    int64_t BytesMissing = Int((48 + client_data_length) - (InputData.length() / 2));
    if (BytesMissing > 0)
    { /*If then*/
        _DumpOutput("Error: Incomplete record recovered at offset: " + Hex(RecordOffset, 8));
        _DumpOutput("From internal transaction offset: 0x" + Hex(Int(InputData.length() / 2)) + " there is 0x" + Hex(BytesMissing) + " bytes missing");
        _DumpOutput("this_lsn: " + std::to_string(this_lsn));
        //	_DumpOutput("Part 1: " + 48 + client_data_length + " 0x" + Hex(Int(48 + client_data_length)));
        //	_DumpOutput("Part 2: " + InputData.length()/2 + " 0x" + Hex(Int(InputData.length()/2)));
        _DumpOutputHex(/*_HexEncode*/(StringMid(InputData, 1)));
        //	MsgBox(0,"Info","Check output");
        TextInformation += "//Incomplete record recovered. 0x" + Hex(BytesMissing, 4) + " bytes missing from internal offset 0x" + Hex(Int(InputData.length() / 2), 4);
        IncompleteTransaction = 1;
    } /*End of If*/
    if (!FromRcrdSlack)
    { /*If then*/
        if (this_lsn > lsn_openattributestable)
        { /*If then*/
            if (!(target_attribute == 0x0000 || target_attribute == 0x0017 || target_attribute == 0x0018))
            { /*If then*/
                if (Ubound(OpenAttributesArray) > 0)
                { /*If then*/
                    FoundInTable = _ArraySearch(OpenAttributesArray, target_attribute, 0, 0, 0, 0, 1, 0);
                    //		ConsoleWrite("FoundInTable: " + std::to_string(FoundInTable) );
                    if (!FoundInTable >= 0)
                    { /*If then*/
                        InOpenAttributeTable = 0;
                        if (option.VerboseOn)
                        { /*If then*/
                            _DumpOutput("Could not find target_attribute in OpenAttributesArray: " + std::to_string(target_attribute) + " for this_lsn: " + std::to_string(this_lsn));
                        }
                    }
                    else
                    { /*Else*/
                        InOpenAttributeTable = lsn_openattributestable;
                    } /*End of If*/
                }
                else
                { /*Else*/
                    InOpenAttributeTable = 0;
                } /*End of If*/
            }	  /*End of If*/
        }		  /*End of If*/
    }
    else
    { /*Else*/
        //	If this_lsn > lsn_openattributestable Then;
        if (!(target_attribute == 0x0000 || target_attribute == 0x0017 || target_attribute == 0x0018))
        { /*If then*/
            if (Ubound(SlackOpenAttributesArray) > 0)
            { /*If then*/
                FoundInTableSlack = _ArraySearch(SlackOpenAttributesArray, target_attribute, 0, 0, 0, 0, 1, 0);
                if (!FoundInTableSlack >= 0)
                { /*If then*/
                    InOpenAttributeTable = 0;
                    if (option.VerboseOn)
                    { /*If then*/
                        _DumpOutput("Could not find target_attribute in SlackOpenAttributesArray: " + std::to_string(target_attribute) + " for this_lsn: " + std::to_string(this_lsn));
                    }
                }
                else
                { /*Else*/
                    InOpenAttributeTable = 0;
                } /*End of If*/
            }
            else
            { /*Else*/
                InOpenAttributeTable = 0;
            } /*End of If*/
        }	  /*End of If*/
        //	EndIf;
    } /*End of If*/

    auto lcns_to_followStr = StringMid(InputData, 125, 4);
    auto lcns_to_follow = HexToInt(_SwapEndian(lcns_to_followStr));
    auto record_offset_in_mftStr = StringMid(InputData, 129, 4);
    record_offset_in_mft = Dec(_SwapEndian(record_offset_in_mftStr), 2);
    auto attribute_offsetStr = StringMid(InputData, 133, 4);
    attribute_offset = Dec(_SwapEndian(attribute_offsetStr), 2);
    auto MftClusterIndexStr = StringMid(InputData, 137, 4);
    auto MftClusterIndex = Dec(_SwapEndian(MftClusterIndexStr), 2);
    //alignment_or_reserved1 = StringMid(InputData,141,4);
    auto target_vcn = Dec(_SwapEndian(StringMid(InputData, 145, 8)), 2);
    //alignment_or_reserved2 = StringMid(InputData,153,8);
    auto target_lcn = HexToInt(_SwapEndian(StringMid(InputData, 161, 8)));
    //alignment_or_reserved3 = StringMid(InputData,169,8);
    result.PredictedRefNumber = ((target_vcn * option.BytesPerCluster) / MFT_Record_Size) + ((MftClusterIndex * 512) / MFT_Record_Size);
    // ConsoleWrite("result.PredictedRefNumber: " + std::to_string(result.PredictedRefNumber) );
    // Need to research more on how to calculate correct MFT ref;
    if ((redo_operation_hex == "0000" && undo_operation_hex != "0000") || redo_operation_hex == Operation_InitializeFileRecordSegment || redo_operation_hex == Operation_DeallocateFileRecordSegment || redo_operation_hex == Operation_WriteEndOfFileRecordSegment || redo_operation_hex == Operation_CreateAttribute || redo_operation_hex == Operation_DeleteAttribute || redo_operation_hex == Operation_UpdateResidentAttributeValue || (redo_operation_hex == Operation_UpdateNonResidentAttributeValue && PreviousRedoOp == Operation_OpenNonResidentAttribute) || redo_operation_hex == Operation_UpdateMappingPairs || redo_operation_hex == Operation_SetNewAttributeSizes || redo_operation_hex == Operation_AddIndexEntryToRoot || redo_operation_hex == Operation_DeleteIndexEntryFromRoot || redo_operation_hex == Operation_SetIndexEntryVcnInRoot || redo_operation_hex == Operation_UpdateFileNameInRoot || redo_operation_hex == Operation_OpenNonResidentAttribute)
    { /*If then*/
        if (!FromRcrdSlack)
        { /*If then*/
            KeptRefTmp = result.PredictedRefNumber;
            KeptRef = result.PredictedRefNumber;
        } /*End of If*/
    }
    else if (client_previous_lsn != 0 && (redo_operation_hex == Operation_AddIndexEntryToAllocationBuffer || redo_operation_hex == Operation_DeleteIndexEntryFromAllocationBuffer || redo_operation_hex == Operation_WriteEndOfIndexBuffer || redo_operation_hex == Operation_SetIndexEntryVcnInAllocationBuffer || redo_operation_hex == Operation_UpdateFileNameInAllocationBuffer || redo_operation_hex == "2500" || (redo_operation_hex == Operation_UpdateNonResidentAttributeValue && (redo_operation_hex == Operation_UpdateNonResidentAttributeValue || PreviousRedoOp == Operation_SetNewAttributeSizes))))
    { /*Else If then*/

        if (!FromRcrdSlack)
        { /*If then*/
            result.PredictedRefNumber = KeptRef;
            //		KeptRefTmp = KeptRef;
        }
        else
        {							  /*Else*/
            result.PredictedRefNumber = -1; // ! possible from slack;
        }							  /*End of If*/
    }
    else
    {
        /*Else*/
        result.PredictedRefNumber = -1; // ! related to any particular MFT ref;
    }							  /*End of If*/

    if (!FromRcrdSlack || BrokenLogFile)
    { /*If then*/
        auto ExcessDataSize = client_data_length - (redo_length_tmp + undo_length_tmp) - redo_offset;
        // fixme 原写入csv代码
        // FileWrite(LogFileTransactionHeaderCsv, RecordOffset + de + this_lsn + de + client_previous_lsn + de + client_undo_next_lsn + de + client_index + de + record_type + de + transaction_id + de + lf_flags + de + result.redo_operation + de + result.undo_operation + de + redo_offset + de + redo_length_tmp + de + undo_offset + de + undo_length_tmp + de + client_data_length + de + target_attribute + de + lcns_to_follow + de + record_offset_in_mft + de + attribute_offset + de + MftClusterIndex + de + target_vcn + de + target_lcn + de + ExcessDataSize);
    } /*End of If*/

    if (!FromRcrdSlack)
    { /*If then*/
        if (FoundInTable >= 0)
        { /*If then*/
            auto AttributeStringTmp = _ResolveAttributeType(StringMid(OpenAttributesArray[FoundInTable][5], 3, 4));

            if (AttributeStringTmp != "UNKNOWN" && Int(OpenAttributesArray[FoundInTable][9]) != 0)
            { /*If then*/
                // Why do these sometimes Point to offsets in OpenAttributeTable containing invalid data?;
                if (Is32bit == 0 || Int(OpenAttributesArray[FoundInTable][7]) > 0)
                { /*If then*/
                    // target_attribute is handled differently on nt5.x than nt6.x;
                    result.AttributeString = AttributeStringTmp;
                    if (OpenAttributesArray[FoundInTable][12] != "")
                    { /*If then*/
                        result.AttributeString += ":" + OpenAttributesArray[FoundInTable][12];
                    } /*End of If*/
                      //		result.PredictedRefNumber = OpenAttributesArray[FoundInTable][7];
                    RealMftRef = Int(OpenAttributesArray[FoundInTable][7]);
                    if (redo_operation_hex == Operation_UpdateNonResidentAttributeValue)
                    { /*If then*/
                        result.PredictedRefNumber = RealMftRef;
                    }
                    if (result.PredictedRefNumber == -1)
                    { /*If then*/
                        result.PredictedRefNumber = RealMftRef;
                    }
                } /*End of If*/
            }
            else
            { /*Else*/
                InOpenAttributeTable = -1 * InOpenAttributeTable;
                ; // Will indicate an offset match in OpenAttributeTable that contains invalid data.;
            }	  /*End of If*/
        }		  /*End of If*/
        if (result.PredictedRefNumber == 0)
        { /*If then*/
            //		If target_attribute = 0x0018 && Ubound(OpenAttributesArray) > 1 Then;
            if (Ubound(OpenAttributesArray) > 0)
            { /*If then*/
                FoundInTable = _ArraySearch(OpenAttributesArray, target_attribute, 0, 0, 0, 0, 1, 0);
                //		ConsoleWrite("FoundInTable: " + std::to_string(FoundInTable) );
                if (FoundInTable >= 0)
                { /*If then*/
                    auto AttributeStringTmp = _ResolveAttributeType(StringMid(OpenAttributesArray[FoundInTable][5], 3, 4));
                    if (AttributeStringTmp != "UNKNOWN" && AttributeStringTmp != "$DATA")
                    { /*If then*/
                        result.AttributeString = AttributeStringTmp;
                    } /*End of If*/
                    if (OpenAttributesArray[FoundInTable][12] != "" && result.AttributeString != "")
                    { /*If then*/
                        result.AttributeString += ":" + OpenAttributesArray[FoundInTable][12];
                    } /*End of If*/
                }
                else
                { /*Else*/
                    if (option.VerboseOn)
                    { /*If then*/
                        _DumpOutput("Warning: target_attribute was not found in array: " + std::to_string(target_attribute) + " at lsn " + std::to_string(this_lsn));
                    }
                    //				_ArrayDisplay(OpenAttributesArray,"OpenAttributesArray");
                } /*End of If*/
            }	  /*End of If*/
        }		  /*End of If*/
    }
    else
    { /*Else*/
        if (FoundInTableSlack > 0)
        { /*If then*/
            //	ConsoleWrite("ubound(OpenAttributesArray): " + ubound(OpenAttributesArray));
            auto AttributeStringTmp = _ResolveAttributeType(StringMid(SlackOpenAttributesArray[FoundInTableSlack][5], 3, 4));
            if (AttributeStringTmp != "UNKNOWN" && Int(SlackOpenAttributesArray[FoundInTableSlack][9]) != 0)
            { /*If then*/ // Why do these sometimes Point to offsets in OpenAttributeTable containing invalid data?;
                result.AttributeString = AttributeStringTmp;
                if (SlackOpenAttributesArray[FoundInTableSlack][12] != "")
                { /*If then*/
                    result.AttributeString += ":" + SlackOpenAttributesArray[FoundInTableSlack][12];
                } /*End of If*/
            }
            else
            { /*Else*/

                InOpenAttributeTable = -1 * InOpenAttributeTable; // Will indicate an offset match in OpenAttributeTable that contains invalid data.;
            }														/*End of If*/
        }															/*End of If*/
    }																/*End of If*/

    if (!VerboseArr.empty())
    { /*If then*/
        option.VerboseOn = false;
        for (auto i = 1; i < VerboseArr.size(); i++)
        {
            if (this_lsn == VerboseArr[i])
            { /*If then*/
                option.VerboseOn = true;
                break; //
            }
        }
        /*End of If*/
    } /*End of If*/

    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("option.VerboseOn"
            "\r\n");
        _DumpOutput("Calculated RefNumber: " + std::to_string(
            ((target_vcn * option.BytesPerCluster) / MFT_Record_Size) + (MftClusterIndex * 512 / MFT_Record_Size)));
        _DumpOutput("result.PredictedRefNumber: " + std::to_string(result.PredictedRefNumber));
        _DumpOutput("KeptRef: " + std::to_string(KeptRef));
        _DumpOutput("this_lsn: " + std::to_string(this_lsn));
        _DumpOutput("client_previous_lsn: " + std::to_string(client_previous_lsn));
        _DumpOutput("client_undo_next_lsn: " + std::to_string(client_undo_next_lsn));
        _DumpOutput("client_data_length: 0x" + Hex(client_data_length, 8));
        _DumpOutput("client_index: 0x" + Hex(client_index, 8));
        _DumpOutput("record_type: " + std::to_string(record_type));
        _DumpOutput("transaction_id: 0x" + Hex(transaction_id, 8));
        _DumpOutput("lf_flags: 0x" + Hex(lf_flags, 4));
        _DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation));
        _DumpOutput("redo_operation_hex: 0x" + std::to_string(redo_operation_hex));
        _DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation));
        _DumpOutput("undo_operation_hex: 0x" + std::to_string(undo_operation_hex));
        _DumpOutput("redo_offset: " + std::to_string(redo_offset));
        _DumpOutput("redo_length: " + std::to_string(redo_length));
        _DumpOutput("undo_offset: " + std::to_string(undo_offset));
        _DumpOutput("undo_length: " + std::to_string(undo_length));
        _DumpOutput("target_attribute: 0x" + Hex(target_attribute, 4));
        _DumpOutput("lcns_to_follow: 0x" + Hex(lcns_to_follow, 4));
        _DumpOutput("record_offset_in_mft: 0x" + Hex(record_offset_in_mft, 8));
        _DumpOutput("attribute_offset: 0x" + Hex(attribute_offset, 8));
        _DumpOutput("MftClusterIndex: 0x" + Hex(MftClusterIndex, 4));
        _DumpOutput("target_vcn: 0x" + Hex(target_vcn));
        _DumpOutput("target_lcn: 0x" + Hex(target_lcn));
        _DumpOutput("result.AttributeString: " + std::to_string(result.AttributeString));
        _DumpOutput("FoundInTable: " + std::to_string(FoundInTable));
        _DumpOutput("FromRcrdSlack: " + std::to_string(FromRcrdSlack));
        _DumpOutput("PreviousRedoOp: " + std::to_string(PreviousRedoOp));
        _DumpOutput("FoundInTable: " + std::to_string(FoundInTable));
        _DumpOutput("FoundInTableSlack: " + std::to_string(FoundInTableSlack));
        _DumpOutput("Raw record: ");
        _DumpOutputHex(/*_HexEncode*/(InputData));
        _DumpOutput("\r\n");
    } /*End of If*/

    if (record_type == 2)
    { /*If then*/
        _Decode_CheckpointRecord(StringMid(InputData, 113));
        TextInformation += "//See LogFile_CheckpointRecord.csv";
    } /*End of If*/

    // FIXME
    std::string redo_chunk;
    std::string undo_chunk;

    // Debug print64_t Redo and Undo for easy comparison;
    if (redo_length > 0)
    { /*If then*/
        redo_chunk = StringMid(InputData, 97 + (redo_offset * 2), redo_length * 2);
        if (option.VerboseOn)
        { /*If then*/
            _DumpOutput("Redo: " + std::to_string(result.redo_operation));
            _DumpOutputHex(/*_HexEncode*/(redo_chunk));
        } /*End of If*/
    }	  /*End of If*/

    if (undo_length > 0)
    { /*If then*/
        undo_chunk = StringMid(InputData, 97 + (undo_offset * 2), undo_length * 2);
        if (option.VerboseOn)
        { /*If then*/
            _DumpOutput("Undo: " + std::to_string(result.undo_operation));
            _DumpOutputHex(/*_HexEncode*/(undo_chunk));
        } /*End of If*/
    }	  /*End of If*/

#pragma region "redo分析"
    if (redo_length > 0)
    { /*If then*/
        RedoChunkSize = strlen(redo_chunk.c_str()) / 2;
        // Select;
        if /*Case*/ (redo_operation_hex == Operation_InitializeFileRecordSegment)
        { // InitializeFileRecordSegment;
            //			_DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn) );
            //			_DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation) );
            //			_DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex) );
            //			_DumpOutput(_HexEncode(Dec(redo_chunk)));
            if (redo_length <= 60)
            { /*If then*/
                TextInformation += "//Initializing empty record";
            }
            else
            { /*Else*/
                auto error = _ParserCodeOldVersion(redo_chunk, 1);
                if (!error)
                { /*If then*/
                    if (!FromRcrdSlack)
                    { /*If then*/
                        // TODO 记录解析出来的文件名到数组中
                        _UpdateFileNameArray(result.PredictedRefNumber, HDR_SequenceNo, result.FN_Name, this_lsn);
                    } /*End of If*/
                }	  /*End of If*/
            }		  /*End of If*/
        }
        else if /*Case*/ (redo_operation_hex == Operation_DeallocateFileRecordSegment)
        { // DeallocateFileRecordSegment;
            // 删除文件
            _RemoveAllOffsetOfAttribute(result.PredictedRefNumber);
        }
        else if /*Case*/ (redo_operation_hex == Operation_WriteEndOfFileRecordSegment)
        { // WriteEndOfFileRecordSegment;
            _DumpOutput("\r\n"  "this_lsn: " + std::to_string(this_lsn));
            _DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation));
            _DumpOutputHex(/*_HexEncode*/(redo_chunk));
            TextInformation += "//Search debug.log for " + std::to_string(this_lsn);
        }
#if 0 // 暂时不放开代码,测试其它的
        else if /*Case*/ (redo_operation_hex == Operation_CreateAttribute)
        { // CreateAttribute;
            TestAttributeType = _Decode_AttributeType(redo_chunk);
            if (TestAttributeType != '')
            { /*If then*/
                _UpdateSingleOffsetOfAttribute(result.PredictedRefNumber, record_offset_in_mft, RedoChunkSize, TestAttributeType);
            }
            _Decode_CreateAttribute(redo_chunk, 1);
        }
        else if /*Case*/ (redo_operation_hex == Operation_DeleteAttribute)
        { // DeleteAttribute;
          //			TestAttributeType = _Decode_AttributeType(undo_chunk);
          //			If TestAttributeType != '' Then _RemoveSingleOffsetOfAttribute(result.PredictedRefNumber, record_offset_in_mft, TestAttributeType);
        }
        else if /*Case*/ (redo_operation_hex == Operation_UpdateResidentAttributeValue)
        { // UpdateResidentValue;
            ResolvedAttributeOffset = _CheckOffsetOfAttribute(result.PredictedRefNumber, record_offset_in_mft);
            if (!::GetLastError())
            { /*If then*/
                //				result.AttributeString+= '->(' + ResolvedAttributeOffset + ')';
                result.AttributeString = ResolvedAttributeOffset;
            } /*End of If*/
            _Decode_UpdateResidentValue(redo_chunk, 1);
        }
        else if /*Case*/ (redo_operation_hex == Operation_UpdateNonResidentAttributeValue)
        { // UpdateNonResidentValue;
            if (StringLeft(redo_chunk, 8) == "494e4458")
            { /*If then*/ // INDX;
                TextInformation += "//INDX";
                if (!FromRcrdSlack)
                { /*If then*/
                    // Select;
                    if /*Case*/ (KeptRefTmp == 9 || result.PredictedRefNumber == 9 || RealMftRef == 9)
                    {
                        if (KeptRefTmp == 9)
                        { /*If then*/
                            if (FoundInTable < 0)
                            { /*If then*/
                                result.AttributeString = "INDEX_ALLOCATION(??)";
                            }
                            result.PredictedRefNumber = KeptRefTmp;
                            KeptRef = KeptRefTmp;
                        } /*End of If*/
                        if ((result.AttributeString == "INDEX_ALLOCATION:SDH" || result.AttributeString == "UNKNOWN:SDH"))
                        { /*If then*/
                            Indx = _GetIndxWoFixup(redo_chunk);
                            _DecodeIndxEntriesSDH(Indx, 1);
                            TextInformation += "//See LogFile_SecureSDH.csv";
                        }
                        else if ((result.AttributeString == "INDEX_ALLOCATION:SII" || result.AttributeString == "UNKNOWN:SII"))
                        { /*Else If then*/

                            Indx = _GetIndxWoFixup(redo_chunk);
                            _DecodeIndxEntriesSII(Indx, 1);
                            TextInformation += "//See LogFile_SecureSII.csv";
                        }
                        else if (StringMid(redo_chunk, 217, 8) = "49004900")
                        { /*Else If then*/

                            Indx = _GetIndxWoFixup(redo_chunk);
                            _DecodeIndxEntriesSII(Indx, 1);
                            result.AttributeString = "INDEX_ALLOCATION:SII";
                            TextInformation += "//See LogFile_SecureSII.csv";
                        }
                        else
                        { /*Else*/
                            _DumpOutput("Error: Secure contained unidentified INDX at lsn: " + std::to_string(this_lsn));
                            _DumpOutputHex(/*_HexEncode*/(redo_chunk));
                        } /*End of If*/
                    }
                    else if /*Case*/ (KeptRefTmp == 24 || result.PredictedRefNumber == 24 || RealMftRef == 24)
                    {
                        if (KeptRefTmp == 24)
                        { /*If then*/
                            if (FoundInTable < 0)
                            { /*If then*/
                                result.AttributeString = "INDEX_ALLOCATION(Quota?)";
                            }
                            result.PredictedRefNumber = KeptRefTmp;
                            KeptRef = KeptRefTmp;
                        } /*End of If*/
                        if ((result.AttributeString == "INDEX_ALLOCATION:O" || result.AttributeString == "$INDEX_ROOT:O" || result.AttributeString == "UNKNOWN:O"))
                        { /*If then*/
                            _Decode_Quota_O(redo_chunk, 1);
                            TextInformation += "//See LogFile_QuotaO.csv";
                        } /*End of If*/
                        if ((result.AttributeString == "INDEX_ALLOCATION:Q" || result.AttributeString == "$INDEX_ROOT:Q" || result.AttributeString == "UNKNOWN:Q"))
                        { /*If then*/
                            _Decode_Quota_Q(redo_chunk, 1);
                            TextInformation += "//See LogFile_QuotaO.csv";
                        } /*End of If*/
                    }
                    else if /*Case*/ (KeptRefTmp == 25 || result.PredictedRefNumber == 25 || RealMftRef == 25)
                    {
                        if (KeptRefTmp == 25)
                        { /*If then*/
                            if (FoundInTable < 0)
                            { /*If then*/
                                result.AttributeString = "INDEX_ALLOCATION(ObjId?)";
                            }
                            result.PredictedRefNumber = KeptRefTmp;
                            KeptRef = KeptRefTmp;
                        } /*End of If*/
                        if ((result.AttributeString == "INDEX_ALLOCATION:O" || result.AttributeString == "$INDEX_ROOT:O" || result.AttributeString == "UNKNOWN:O"))
                        { /*If then*/
                            _Decode_ObjId_O(redo_chunk, 1);
                            TextInformation += "//See LogFile_ObjIdO.csv";
                        } /*End of If*/
                    }
                    else if /*Case*/ (KeptRefTmp == 26 || result.PredictedRefNumber == 26 || RealMftRef == 26)
                    {
                        if (KeptRefTmp == 26)
                        { /*If then*/
                            if (FoundInTable < 0)
                            { /*If then*/
                                result.AttributeString = "INDEX_ALLOCATION(Reparse?)";
                            }
                            result.PredictedRefNumber = KeptRefTmp;
                            KeptRef = KeptRefTmp;
                        } /*End of If*/
                        if ((result.AttributeString == "INDEX_ALLOCATION:R" || result.AttributeString == "$INDEX_ROOT:R" || result.AttributeString == "UNKNOWN:R"))
                        { /*If then*/
                            _Decode_Reparse_R(redo_chunk, 1);
                            TextInformation += "//See LogFile_ReparseR.csv";
                        } /*End of If*/
                    }
                    else
                    {
                        if (StringInStr(result.AttributeString, "I30"))
                        { /*If then*/
                            _Decode_INDX(redo_chunk, 1);
                        } /*End of If*/
                    }
                }
                else
                { /*Else*/
                    DecodeOk = _Decode_INDX(redo_chunk, 1);
                    if (!DecodeOk)
                    { /*If then*/ // Possibly Secure:SDH||  Secure:SII;
                        //						ConsoleWrite("_Decode_INDX() failed for this_lsn: " + std::to_string(this_lsn) );
                        //						ConsoleWrite(_HexEncode(Dec(redo_chunk)));
                        Indx = _GetIndxWoFixup(redo_chunk);
                        if (StringMid(Indx, 89, 8) = "49004900")
                        { /*If then*/ // SDH signature;
                            _DecodeIndxEntriesSDH(Indx, 1);
                            TextInformation += "//See LogFile_SecureSDH.csv";
                        }
                        else
                        { /*Else*/
                            _DecodeIndxEntriesSII(Indx, 1);
                            TextInformation += "//See LogFile_SecureSII.csv";
                        } /*End of If*/
                    }
                    else
                    { /*Else*/
                        TextInformation += "//See LogFile_INDX_I30.csv";
                    } /*End of If*/
                }	  /*End of If*/
                if (PreviousRedoOp == Operation_OpenNonResidentAttribute && !FromRcrdSlack)
                { /*If then*/
                    if (FoundInTable < 0)
                    { /*If then*/
                        result.AttributeString = PreviousAttribute;
                        result.PredictedRefNumber = KeptRef;
                    } /*End of If*/
                }
                else
                { /*Else*/
                    if (FoundInTable >= 0 || FoundInTableSlack >= 0)
                    { /*If then*/
                        // Select;
                        if /*Case*/ (result.AttributeString == "$ATTRIBUTE_LIST")
                        {
                            _DecodeAttrList(redo_chunk, 1);
                            TextInformation += "//See LogFile_AttributeList.csv";
                        }
                        else if /*Case*/ (result.AttributeString == "Data:SDS")
                        {
                            _MainSecure(redo_chunk, 1);
                            if (!::GetLastError())
                            { /*If then*/
                                TextInformation += ";Secure:SDS//See LogFile_SecurityDescriptors.csv";
                            }
                            else
                            { /*Else*/
                                TextInformation += ";Secure:SDS//Partial security information not decoded";
                            } /*End of If*/
                        }
                        else if /*Case*/ (result.AttributeString == "INDEX_ALLOCATION:SII")
                        {
                            Indx = _GetIndxWoFixup(redo_chunk);
                            _DecodeIndxEntriesSII(Indx, 1);
                            TextInformation += "//See LogFile_SecureSII.csv";
                        }
                        else if /*Case*/ (result.AttributeString == "INDEX_ALLOCATION:SDH")
                        {
                            Indx = _GetIndxWoFixup(redo_chunk);
                            _DecodeIndxEntriesSDH(Indx, 1);
                            TextInformation += "//See LogFile_SecureSDH.csv";
                        }
                        else if /*Case*/ (result.AttributeString == "$EA")
                        {
                            //							_DumpOutput("Verbose: Nonresident EA caught at lsn " + std::to_string(this_lsn) );
                            //							_DumpOutput(_HexEncode(Dec(redo_chunk)));
                            Test = _Get_Ea_NonResident(redo_chunk);
                            if (::GetLastError())
                            { /*If then*/
                                _DumpOutput("Error: _Get_Ea_NonResident returned: " + std::to_string(Test));
                            } /*End of If*/
                              //							_ArrayDisplay(EaNonResidentArray,"EaNonResidentArray");
                            Case(result.PredictedRefNumber == 24 || RealMftRef == 24) && (result.AttributeString == "INDEX_ALLOCATION:O" || result.AttributeString == "$INDEX_ROOT:O" || result.AttributeString == "UNKNOWN:O");
                            _Decode_Quota_O(redo_chunk, 1);
                            TextInformation += "//See LogFile_QuotaO.csv";
                            Case(result.PredictedRefNumber == 24 || RealMftRef == 24) && (result.AttributeString == "INDEX_ALLOCATION:Q" || result.AttributeString == "$INDEX_ROOT:Q" || result.AttributeString == "UNKNOWN:Q");
                            _Decode_Quota_Q(redo_chunk, 1);
                            TextInformation += "//See LogFile_QuotaQ.csv";
                            Case(result.PredictedRefNumber == 25 || RealMftRef == 25) && (result.AttributeString == "INDEX_ALLOCATION:O" || result.AttributeString == "$INDEX_ROOT:O" || result.AttributeString == "UNKNOWN:O");
                            _Decode_ObjId_O(redo_chunk, 1);
                            TextInformation += "//See LogFile_ObjIdO.csv";
                            Case(result.PredictedRefNumber == 26 || RealMftRef == 26) && (result.AttributeString == "INDEX_ALLOCATION:R" || result.AttributeString == "$INDEX_ROOT:R" || result.AttributeString == "UNKNOWN:R");
                            _Decode_Reparse_R(redo_chunk, 1);
                            TextInformation += "//See LogFile_ReparseR.csv";
                        }
                        else if /*Case*/ (result.AttributeString == "DATA:J")
                        {
                            UsnOk = 0;
                            UsnOk = _UsnDecodeRecord2(redo_chunk);
                            if (UsnOk)
                            { /*If then*/
                                if (!FromRcrdSlack)
                                { /*If then*/
                                    _UpdateFileNameArray(result.PredictedRefNumber, HDR_SequenceNo, result.FN_Name, this_lsn);
                                } /*End of If*/
                                TextInformation += "//UsnJrnl";
                            }
                            else
                            { /*Else*/
                                if (Int(undo_length) == 0 && undo_operation_hex == "0000" && Int(record_offset_in_mft) + Int(redo_length) == 4096)
                                { /*If then*/
                                    TextInformation += ";UsnJrnl//Filling of zeros to page boundary";
                                    result.AttributeString = "DATA:J";
                                }
                                else
                                { /*Else*/
                                    _DumpOutput("_UsnDecodeRecord2() failed and probably not Filling of zeros to page boundary for this_lsn: " + std::to_string(this_lsn) + " at offset " + Hex((uint64_t)RecordOffset));
                                    _DumpOutputHex(/*_HexEncode*/(redo_chunk));
                                } /*End of If*/
                            }	  /*End of If*/
                        }
                        else if /*Case*/ (result.AttributeString == "LOGGED_UTILITY_STREAM:TXF_DATA")
                        { // may only be resident..;
                            _DumpOutput("Verbose: ! yet implemented for LOGGED_UTILITY_STREAM:TXF_DATA.");
                            _DumpOutput("this_lsn: " + std::to_string(this_lsn));
                            _DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation));
                            _DumpOutputHex(/*_HexEncode*/(redo_chunk));
                            TextInformation += "//Search debug.log for " + this_lsn;
                            //							MsgBox(0,"Error","This indicates an unexpected situation at LSN: " + this_lsn);
                        }
                        else if /*Case*/ (result.AttributeString == "LOGGED_UTILITY_STREAM:EFS")
                        {
                            _DumpOutput("Verbose: ! yet implemented for LOGGED_UTILITY_STREAM:EFS.");
                            _DumpOutput("this_lsn: " + std::to_string(this_lsn));
                            _DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation));
                            _DumpOutputHex(/*_HexEncode*/(redo_chunk));
                            TextInformation += "//Search debug.log for " + this_lsn;
                            //							MsgBox(0,"Error","This indicates an unexpected situation at LSN: " + this_lsn);
                        }
                    }
                    else
                    { /*Else*/
                        UsnOk = 0;
                        UsnOk = _UsnDecodeRecord2(redo_chunk);
                        if (!UsnOk)
                        { /*If then*/
                            //					If record_offset_in_mft + int64_t (redo_length)==4096  Then;
                            if (PreviousRedoOp == Operation_SetNewAttributeSizes)
                            { /*If then*/ // SetNewAttributeSizes;
                                result.PredictedRefNumber = KeptRef;
                                if (Int(undo_length) == 0 && undo_operation_hex == "0000" && Int(record_offset_in_mft) + Int(redo_length) == 4096)
                                { /*If then*/
                                    TextInformation += ";UsnJrnl//Filling of zeros to page boundary";
                                    result.AttributeString = "DATA:J";
                                }
                                else if (Int(undo_length) >= 32 && undo_operation_hex == Operation_UpdateNonResidentAttributeValue)
                                { /*Else If then*/

                                    _MainSecure(redo_chunk, 1);
                                    if (!::GetLastError())
                                    { /*If then*/
                                        TextInformation += ";Secure:SDS//See LogFile_SecurityDescriptors.csv";
                                    }
                                    else
                                    { /*Else*/
                                        TextInformation += ";Secure:SDS//Partial security information not decoded";
                                    } /*End of If*/
                                }
                                else if (Int(undo_length) > 0 && undo_operation_hex == Operation_UpdateNonResidentAttributeValue)
                                { /*Else If then*/

                                    TextInformation += "//Secure";
                                    _DumpOutput("Error in UpdateNonResidentValue: unresolved Secure: " + std::to_string(this_lsn));
                                    _DumpOutputHex(/*_HexEncode*/(redo_chunk));
                                }
                                else
                                { /*Else*/
                                    _DumpOutput("_UsnDecodeRecord2() failed and probably not Filling of zeros to page boundary for this_lsn: " + std::to_string(this_lsn));
                                    _DumpOutputHex(/*_HexEncode*/(redo_chunk));
                                }	 /*End of If*/
                            else // Likely Secure:SDS;
                            {
                                //						ConsoleWrite("_UsnDecodeRecord2() failed and PreviousRedoOp != 0b00 for this_lsn: " + std::to_string(this_lsn) );
                                //						ConsoleWrite(_HexEncode(Dec(redo_chunk)));
                                _MainSecure(redo_chunk, 1);
                                if (!::GetLastError())
                                { /*If then*/
                                    TextInformation += ";Secure:SDS//See LogFile_SecurityDescriptors.csv";
                                }
                                else
                                { /*Else*/
                                    TextInformation += ";Secure:SDS//Partial security information not decoded";
                                } /*End of If*/
                            }	  /*End of If*/
                            }
                            else
                            { /*Else*/
                                if (!FromRcrdSlack)
                                { /*If then*/
                                    _UpdateFileNameArray(result.PredictedRefNumber, HDR_SequenceNo, result.FN_Name, this_lsn);
                                } /*End of If*/
                                TextInformation += "//UsnJrnl";
                            } /*End of If*/
                        }	  /*End of If*/
                    }		  /*End of If*/
                }
            }
        }

        else if /*Case*/ (redo_operation_hex == Operation_UpdateMappingPairs)
        { // UpdateMappingPairs;
            _Decode_UpdateMappingPairs(redo_chunk);
            result.AttributeString = "$DATA";
            ResolvedAttributeOffset = _CheckOffsetOfAttribute(result.PredictedRefNumber, record_offset_in_mft);
            if (!::GetLastError())
            { /*If then*/
                //				result.AttributeString+= '->(' + ResolvedAttributeOffset + ')';
                result.AttributeString = ResolvedAttributeOffset;
            } /*End of If*/
        }
#endif
        else if /*Case*/ (redo_operation_hex == Operation_DeleteDirtyClusters)
        { // DeleteDirtyClusters;
            _DumpOutput("this_lsn: " + std::to_string(this_lsn));
            _DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation));
            _DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex));
            _DumpOutputHex(/*_HexEncode*/(redo_chunk));
        }
#if 0
        else if /*Case*/ (redo_operation_hex == Operation_SetNewAttributeSizes)
        { // SetNewAttributeSizes;
            _Decode_SetNewAttributeSize(redo_chunk);
            if ((RealMftRef == UsnJrnlRef) && (UsnJrnlRef != ""))
            {							   /*If then*/
                result.AttributeString = "$DATA" //UsnJrnl;
                    TextInformation += "//UsnJrnl";
            }
            else if (record_offset_in_mft > 56)
            { /*Else If then*/

                result.AttributeString = "??";
                ResolvedAttributeOffset = _CheckOffsetOfAttribute(result.PredictedRefNumber, record_offset_in_mft);
                if (!::GetLastError())
                { /*If then*/
                    //					result.AttributeString+= '->(' + ResolvedAttributeOffset + ')';
                    result.AttributeString = ResolvedAttributeOffset;
                } /*End of If*/
            }
            else
            {	/*Else*/
                //				_DumpOutput("Error at LSN: " + std::to_string(this_lsn) );
                //				_DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation) );
                //				_DumpOutput(_HexEncode(Dec(redo_chunk)));
            }	/*End of If*/
        }
#endif
        else if /*Case*/ (redo_operation_hex == Operation_AddIndexEntryToRoot || redo_operation_hex == Operation_DeleteIndexEntryFromRoot || redo_operation_hex == Operation_AddIndexEntryToAllocationBuffer || redo_operation_hex == Operation_DeleteIndexEntryFromAllocationBuffer)
        { // AddindexEntryRoot,DeleteindexEntryRoot,AddIndexEntryAllocation,DeleteIndexEntryAllocation;
            if ((redo_operation_hex == Operation_AddIndexEntryToRoot || redo_operation_hex == Operation_DeleteIndexEntryFromRoot) && result.AttributeString == "")
            { /*If then*/
                result.AttributeString = "$INDEX_ROOT";
            }
            if ((redo_operation_hex == Operation_AddIndexEntryToAllocationBuffer || redo_operation_hex == Operation_DeleteIndexEntryFromAllocationBuffer) && result.AttributeString == "")
            { /*If then*/
                result.AttributeString = "$INDEX_ALLOCATION";
            }
            if (StringInStr(result.AttributeString, "I30"))
            { /*If then*/
                DecodeOk = _Decode_IndexEntry(redo_chunk, redo_operation_hex, 1);
                if (!DecodeOk)
                { /*If then*/
                    if (redo_operation_hex == Operation_AddIndexEntryToRoot)
                    { /*If then*/
                        _UpdateSingleOffsetOfAttribute(result.PredictedRefNumber, record_offset_in_mft, RedoChunkSize, "$INDEX_ROOT");
                    }
                    _DumpOutput("_Decode_IndexEntry() failed for this_lsn: " + std::to_string(this_lsn));
                    _DumpOutputHex(/*_HexEncode*/(redo_chunk));
                }
                else
                { /*Else*/
                    if (redo_operation_hex == Operation_AddIndexEntryToRoot)
                    { /*If then*/
                        _UpdateSingleOffsetOfAttribute(RealMftRef, record_offset_in_mft, RedoChunkSize, "$INDEX_ROOT");
                        TextInformation += "//See LogFile_INDX_I30.csv";
                    } /*End of If*/
                    if (redo_operation_hex == Operation_AddIndexEntryToAllocationBuffer)
                    { /*If then*/
                        TextInformation += "//See LogFile_INDX_I30.csv";
                    } /*End of If*/
                }
            }
            else
            {
                if /*Case*/ (result.PredictedRefNumber == 9 || RealMftRef == 9)
                { //Secure;
                    if (redo_length == 40)
                    { /*If then*/ //SII;
                        _DecodeIndxEntriesSII(redo_chunk, 1);
                        TextInformation += ";Secure:SII//See LogFile_SecureSII.csv";
                        result.AttributeString += ":SII";
                    }
                    else if (redo_length == 48)
                    { /*Else If then*/
                        //SDH;
                        _DecodeIndxEntriesSDH(redo_chunk, 1);
                        TextInformation += ";Secure:SDH//See LogFile_SecureSDH.csv";
                        result.AttributeString += ":SDH";
                    } /*End of If*/
                }
                else if /*Case*/ (result.PredictedRefNumber == 24 || RealMftRef == 24)
                { //Quota;
                    if (redo_length > 68)
                    { /*If then*/
                        _Decode_Quota_Q(redo_chunk, 1);
                        TextInformation += "//See LogFile_QuotaQ.csv";
                    }
                    else
                    { /*Else*/
                        _Decode_Quota_O(redo_chunk, 1);
                        TextInformation += "//See LogFile_QuotaO.csv";
                    } /*End of If*/
                }
                else if /*Case*/ (result.PredictedRefNumber == 25 || RealMftRef == 25)
                { //ObjId;

#if 0
                    if (redo_length = 88)
                    {
                        // also 96..;
                        _Decode_ObjId_O(redo_chunk, 1);
                    }
#endif
                    TextInformation += "//See LogFile_ObjIdO.csv";
                    //					EndIf;
                }
                else if /*Case*/ (result.PredictedRefNumber == 26 || RealMftRef == 26)
                { //Reparse;
                    _Decode_Reparse_R(redo_chunk, 1);
                    TextInformation += "//See LogFile_ReparseR.csv";
                }
                else
                {
                    _TryIdentifyIndexEntryType(redo_chunk, redo_operation_hex, 1);
                }
            } /*End of If*/
        }
        else if /*Case*/ (redo_operation_hex == Operation_WriteEndOfIndexBuffer)
        {
            // WriteEndOfIndexBuffer->always 0 (on nt6x ? ) but check undo;
            if (result.AttributeString == "")
            { /*If then*/
                result.AttributeString = "$INDEX_ALLOCATION";
                //_DumpOutput("this_lsn: " + std::to_string(this_lsn) );
                //_DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation) );
                //_DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex) );
                //_DumpOutput(_HexEncode(Dec(redo_chunk)));
            }
        }
        else if /*Case*/ (redo_operation_hex == Operation_SetIndexEntryVcnInRoot)
        { // SetIndexEntryVcnRoot;
            _Decode_SetIndexEntryVcn(redo_chunk);
            result.AttributeString = "$INDEX_ROOT";
            //			ConsoleWrite("this_lsn: " + std::to_string(this_lsn) );
            //			ConsoleWrite("redo_operation_hex: " + std::to_string(redo_operation_hex) );
            //			ConsoleWrite(_HexEncode(Dec(redo_chunk)));
        }
        else if /*Case*/ (redo_operation_hex == Operation_SetIndexEntryVcnInAllocationBuffer)
        { // SetIndexEntryVcnAllocation;
            _Decode_SetIndexEntryVcn(redo_chunk);
            result.AttributeString = "$INDEX_ALLOCATION";
            //			ConsoleWrite("this_lsn: " + std::to_string(this_lsn) );
            //			ConsoleWrite("result.redo_operation: " + std::to_string(result.redo_operation) );
            //			ConsoleWrite(_HexEncode(Dec(redo_chunk)));
        }
        else if /*Case*/ (redo_operation_hex == Operation_UpdateFileNameInRoot)
        { // UpdateFileNameRoot;
            _Decode_UpdateFileName(redo_chunk, 1);
            if (PreviousRedoOp == Operation_OpenNonResidentAttribute)
            { /*If then*/
                result.AttributeString = PreviousAttribute;
            }
            else
            { /*Else*/
                result.AttributeString = "$INDEX_ROOT";
                RealMftRef = MftRefReplacement;
            } /*End of If*/
        }
        else if /*Case*/ (redo_operation_hex == Operation_UpdateFileNameInAllocationBuffer)
        { // UpdateFileNameAllocation;
            //			_DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation) );
            //			_DumpOutput(_HexEncode(Dec(InputData)));
            //			_DumpOutput(_HexEncode(Dec(redo_chunk)));
            if (!FromRcrdSlack)
            { /*If then*/
                if (KeptRefTmp > 0 && client_previous_lsn == 0)
                { /*If then*/
                    result.PredictedRefNumber = KeptRefTmp;
                    KeptRef = KeptRefTmp;
                } /*End of If*/
            }	  /*End of If*/
            _Decode_UpdateFileName(redo_chunk, 1);
            if (PreviousRedoOp == Operation_OpenNonResidentAttribute)
            { /*If then*/
                result.AttributeString = PreviousAttribute;
            }
            else
            { /*Else*/
                result.AttributeString = "$INDEX_ALLOCATION";
                RealMftRef = MftRefReplacement;
            } /*End of If*/
        }
        else if /*Case*/ (redo_operation_hex == Operation_SetBitsInNonResidentBitMap)
        { // SetBitsInNonresidentBitMap;
            _Decode_BitsInNonresidentBitMap2(redo_chunk);
        }
        else if /*Case*/ (redo_operation_hex == Operation_ClearBitsInNonResidentBitMap)
        { // ClearBitsInNonresidentBitMap;
            _Decode_BitsInNonresidentBitMap2(redo_chunk);
        }
        else if /*Case*/ (redo_operation_hex == Operation_HotFix)
        { // HotFix;
            _DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn));
            _DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation));
            _DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex));
            _DumpOutputHex(/*_HexEncode*/(redo_chunk));
        }
        else if /*Case*/ (redo_operation_hex == Operation_EndTopLevelAction)
        { // EndTopLevelAction;
            _DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn));
            _DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation));
            _DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex));
            _DumpOutputHex(/*_HexEncode*/(redo_chunk));
        }
        else if /*Case*/ (redo_operation_hex == Operation_PrepareTransaction)
        { // PrepareTransaction;
            _DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn));
            _DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation));
            _DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex));
            _DumpOutputHex(/*_HexEncode*/(redo_chunk));
        }
        else if /*Case*/ (redo_operation_hex == Operation_OpenNonResidentAttribute)
        {
#if 0
            // OpenNonresidentAttribute;
            if (!FromRcrdSlack)
            { /*If then*/
                FoundInTableDummy = _Decode_OpenNonresidentAttribute(redo_chunk);
                if (undo_length == 0)
                { /*If then*/ // We inject an empty name in array since the undo part did not contain any name.;
                    if (FoundInTableDummy >= 0)
                    { /*If then*/
                        OpenAttributesArray[FoundInTableDummy][12] = "";
                        FileWrite(LogFileOpenAttributeTableCsv, RecordOffset + de + this_lsn + de + OpenAttributesArray[FoundInTableDummy][0] + de + OpenAttributesArray[FoundInTableDummy][12] + de + OpenAttributesArray[FoundInTableDummy][1] + de + OpenAttributesArray[FoundInTableDummy][2] + de + OpenAttributesArray[FoundInTableDummy][3] + de + OpenAttributesArray[FoundInTableDummy][4] + de + OpenAttributesArray[FoundInTableDummy][5] + de + _ResolveAttributeType(StringMid(OpenAttributesArray[FoundInTableDummy][5], 3, 4)) + de + OpenAttributesArray[FoundInTableDummy][6] + de + OpenAttributesArray[FoundInTableDummy][7] + de + OpenAttributesArray[FoundInTableDummy][8] + de + OpenAttributesArray[FoundInTableDummy][9] + de + OpenAttributesArray[FoundInTableDummy][10] + de + OpenAttributesArray[FoundInTableDummy][11] + de + OpenAttributesArray[FoundInTableDummy][13]);
                    } /*End of If*/
                }	  /*End of If*/
            }
            else
            { /*Else if (!FromRcrdSlack)*/
                FoundInTableSlackDummy = _Decode_SlackOpenNonresidentAttribute(redo_chunk);
                if (undo_length == 0)
                { /*If then*/ // We inject an empty name in array since the undo part did not contain any name.;
                    if (FoundInTableSlackDummy >= 0)
                    { /*If then*/
                        SlackOpenAttributesArray[FoundInTableSlackDummy][12] = "";
                        FileWrite(LogFileSlackOpenAttributeTableCsv, RecordOffset + de + this_lsn + de + SlackOpenAttributesArray[FoundInTableSlackDummy][0] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][12] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][1] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][2] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][3] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][4] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][5] + de + _ResolveAttributeType(StringMid(SlackOpenAttributesArray[FoundInTableSlackDummy][5], 3, 4)) + de + SlackOpenAttributesArray[FoundInTableSlackDummy][6] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][7] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][8] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][9] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][10] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][11] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][13]);
                    } /*End of If*/
                }	  /*End of If*/
            }		  /*End of If*/
                      //			ConsoleWrite(_HexEncode(Dec(redo_chunk)));
#endif
        }
        else if /*Case*/ (redo_operation_hex == Operation_OpenAttributeTableDump)
        { // OpenAttributeTableDump;
          //			_DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn) );
          //			_DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation) );
          //			_DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex) );
          //			_DumpOutput(_HexEncode(Dec(redo_chunk)));
#if 0
            if (!FromRcrdSlack)
            { /*If then*/
                OpenAttributesArray = 0;
                Global OpenAttributesArray[1][14];
                if (Is32bit)
                { /*If then*/
                    _Decode_OpenAttributeTableDump32bit(redo_chunk, 1);
                }
                else
                { /*Else*/
                    _Decode_OpenAttributeTableDump64bit(redo_chunk, 1);
                } /*End of If*/
                TextInformation += "//See LogFile_OpenAttributeTable.csv";
            }
            else
            { /*Else*/
                SlackOpenAttributesArray = 0;
                Global SlackOpenAttributesArray[1][14];
                if (Is32bit)
                { /*If then*/
                    _Decode_SlackOpenAttributeTableDump32bit(redo_chunk, 1);
                }
                else
                { /*Else*/
                    _Decode_SlackOpenAttributeTableDump64bit(redo_chunk, 1);
                } /*End of If*/
                TextInformation += "//See LogFile_SlackOpenAttributeTable.csv";
            } /*End of If*/
#endif
        }
        else if /*Case*/ (redo_operation_hex == Operation_AttributeNamesDump)
        { // AttributeNamesDump;
          //			ConsoleWrite("this_lsn: " + std::to_string(this_lsn) );
          //			ConsoleWrite("result.redo_operation: " + std::to_string(result.redo_operation) );
          //			ConsoleWrite("redo_operation_hex: " + std::to_string(redo_operation_hex) );
          //			ConsoleWrite(_HexEncode(Dec(redo_chunk)));
#if  0
            if (!FromRcrdSlack)
            { /*If then*/
                _Decode_AttributeNamesDump(redo_chunk);
            }
            else
            { /*Else*/
                _Decode_SlackAttributeNamesDump(redo_chunk);
            } /*End of If*/
#endif
        }
        else if /*Case*/ (redo_operation_hex == Operation_DirtyPageTableDump)
        { // DirtyPageTableDump 0x2c per entry nt5.x;
          //			_DumpOutput("this_lsn: " + std::to_string(this_lsn) );
          //			_DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation) );
          //			_DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex) );
          //			_DumpOutput(_HexEncode(Dec(redo_chunk)));
#if 0
            if (Is32bit)
            { /*If then*/
                _Decode_DirtyPageTableDump32bit(redo_chunk, 1);
            }
            else
            { /*Else*/
                _Decode_DirtyPageTableDump64bit(redo_chunk, 1);
            } /*End of If*/
#endif
        }
        else if /*Case*/ (redo_operation_hex == Operation_TransactionTableDump)
        { // TransactionTableDump;
          //			_DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn) );
          //			_DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation) );
          //			_DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex) );
          //			_DumpOutput(_HexEncode(Dec(redo_chunk)));
#if 0
            _Decode_TransactionTableDump(redo_chunk);
#endif

            TextInformation += "//See LogFile_TransactionTable.csv";
        }
        else if /*Case*/ (redo_operation_hex == Operation_UpdateRecordDataInRoot)
        { // UpdateRecordDataRoot;
          //			_DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn) );
          //			_DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation) );
          //			_DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex) );
          //			_DumpOutput(_HexEncode(Dec(redo_chunk)));

#if 0
            TextInformation += "//See LogFile_QuotaQ.csv";
#endif

        }
        else if /*Case*/ (redo_operation_hex == Operation_UpdateRecordDataInAllocationBuffer)
        { // UpdateRecordDataAllocation;
          //			_DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn) );
          //			_DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation) );
          //			_DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex) );
          //			_DumpOutput(_HexEncode(Dec(redo_chunk)));
#if 0
            _Decode_Quota_Q_SingleEntry(redo_chunk, 1);
#endif
            TextInformation += "//See LogFile_QuotaQ.csv";
        }
        else if /*Case*/ (redo_operation_hex == "2500")
        { // JS_NewEndOfRecord;
          //			_DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn) );
          //			_DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation) );
          //			_DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex) );
          //			_DumpOutput(_HexEncode(Dec(redo_chunk)));
        }
        else if /*Case*/ (result.redo_operation == "UNKNOWN")
        {
            TextInformation += "//RedoOperation=" + redo_operation_hex;
            _DumpOutput("this_lsn: " + std::to_string(this_lsn));
            _DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation));
            _DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex));
            _DumpOutputHex(/*_HexEncode*/(redo_chunk));
        }
        else
        {
            _DumpOutput("Missed transaction!");
            _DumpOutput("this_lsn: " + std::to_string(this_lsn));
            _DumpOutput("result.redo_operation: " + std::to_string(result.redo_operation));
            _DumpOutput("redo_operation_hex: " + std::to_string(redo_operation_hex));
            _DumpOutputHex(/*_HexEncode*/(redo_chunk));
        }
    }
    else
    { /*Else*/
        RedoChunkSize = 0;
    } /*End of If*/

#pragma region "undo分析"

    if (undo_length > 0)
    { /*If then*/
        UndoChunkSize = StringLen(undo_chunk) / 2;
        if (undo_operation_hex == "0000")
        {
            if (!FromRcrdSlack)
            { /*If then*/
                if (Int(undo_offset) + Int(undo_length) > InputData.length())
                {	/*If then*/
                    //				MsgBox(0,"Error","undo_offset > InputData.length() for LSN: " + this_lsn);
                }
                else
                { /*Else*/
                    AttrNameTmp = _Decode_AttributeName(undo_chunk);
                    if (FoundInTableDummy >= 0)
                    { /*If then*/
                        //					MsgBox(0,"Info","Writing entry");
                        OpenAttributesArray[FoundInTableDummy][12] = AttrNameTmp;
                        // FileWrite(LogFileOpenAttributeTableCsv, RecordOffset + de + this_lsn + de + OpenAttributesArray[FoundInTableDummy][0] + de + OpenAttributesArray[FoundInTableDummy][12] + de + OpenAttributesArray[FoundInTableDummy][1] + de + OpenAttributesArray[FoundInTableDummy][2] + de + OpenAttributesArray[FoundInTableDummy][3] + de + OpenAttributesArray[FoundInTableDummy][4] + de + OpenAttributesArray[FoundInTableDummy][5] + de + _ResolveAttributeType(StringMid(OpenAttributesArray[FoundInTableDummy][5], 3, 4)) + de + OpenAttributesArray[FoundInTableDummy][6] + de + OpenAttributesArray[FoundInTableDummy][7] + de + OpenAttributesArray[FoundInTableDummy][8] + de + OpenAttributesArray[FoundInTableDummy][9] + de + OpenAttributesArray[FoundInTableDummy][10] + de + OpenAttributesArray[FoundInTableDummy][11] + de + OpenAttributesArray[FoundInTableDummy][13]);
                         //					FileWriteLine(LogFileOpenAttributeTableCsv, RecordOffset + de + this_lsn + de + OpenAttributesArray[FoundInTableDummy][0]&de + OpenAttributesArray[FoundInTableDummy][12]&de + OpenAttributesArray[FoundInTableDummy][1]&de + OpenAttributesArray[FoundInTableDummy][2]&de + OpenAttributesArray[FoundInTableDummy][3]&de + OpenAttributesArray[FoundInTableDummy][4]&de + OpenAttributesArray[FoundInTableDummy][5]&de + _ResolveAttributeType(StringMid(OpenAttributesArray[FoundInTableDummy][5],3,4))&de + OpenAttributesArray[FoundInTableDummy][6]&de + OpenAttributesArray[FoundInTableDummy][7]&de + OpenAttributesArray[FoundInTableDummy][8]&de + OpenAttributesArray[FoundInTableDummy][9]&de + OpenAttributesArray[FoundInTableDummy][10]&de + "0xDEADBEEF\r\n");
                        if (option.VerboseOn)
                        { /*If then*/
                            _DumpOutput("_Decode_AttributeName() returned: " + std::to_string(AttrNameTmp));
                            _DumpOutput("Updating OpenAttributesArray at row: " + std::to_string(FoundInTableDummy));
                            //							_ArrayDisplay(OpenAttributesArray,"OpenAttributesArray");
                        } /*End of If*/
                    }	  /*End of If*/
                }		  /*End of If*/
            }
            else
            { /*Else*/
                AttrNameTmp = _Decode_AttributeName(undo_chunk);
                if (FoundInTableSlackDummy >= 0)
                { /*If then*/
                    //					MsgBox(0,"Info","Writing entry");
                    SlackOpenAttributesArray[FoundInTableSlackDummy][12] = AttrNameTmp;
                    //   FileWrite(LogFileSlackOpenAttributeTableCsv, RecordOffset + de + this_lsn + de + SlackOpenAttributesArray[FoundInTableSlackDummy][0] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][12] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][1] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][2] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][3] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][4] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][5] + de + _ResolveAttributeType(StringMid(SlackOpenAttributesArray[FoundInTableSlackDummy][5], 3, 4)) + de + SlackOpenAttributesArray[FoundInTableSlackDummy][6] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][7] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][8] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][9] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][10] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][11] + de + SlackOpenAttributesArray[FoundInTableSlackDummy][13]);
                       //					FileWriteLine(LogFileOpenAttributeTableCsv, RecordOffset + de + this_lsn + de + OpenAttributesArray[FoundInTableDummy][0]&de + OpenAttributesArray[FoundInTableDummy][12]&de + OpenAttributesArray[FoundInTableDummy][1]&de + OpenAttributesArray[FoundInTableDummy][2]&de + OpenAttributesArray[FoundInTableDummy][3]&de + OpenAttributesArray[FoundInTableDummy][4]&de + OpenAttributesArray[FoundInTableDummy][5]&de + _ResolveAttributeType(StringMid(OpenAttributesArray[FoundInTableDummy][5],3,4))&de + OpenAttributesArray[FoundInTableDummy][6]&de + OpenAttributesArray[FoundInTableDummy][7]&de + OpenAttributesArray[FoundInTableDummy][8]&de + OpenAttributesArray[FoundInTableDummy][9]&de + OpenAttributesArray[FoundInTableDummy][10]&de + "0xDEADBEEF\r\n");
                    if (option.VerboseOn)
                    { /*If then*/
                        _DumpOutput("_Decode_AttributeName() returned: " + std::to_string(AttrNameTmp));
                        _DumpOutput("Updating SlackOpenAttributesArray at row: " + std::to_string(FoundInTableSlackDummy));
                        //						_ArrayDisplay(SlackOpenAttributesArray,"SlackOpenAttributesArray");
                    } /*End of If*/
                }	  /*End of If*/
            }		  /*End of If*/
        }
        else if (undo_operation_hex == Operation_CompensationLogRecord) // CompensationlogRecord;
        {
        }
        else if (undo_operation_hex == Operation_InitializeFileRecordSegment) // InitializeFileRecordSegment;
        {
            if (UndoChunkSize > 26)
            { /*If then*/
                //				_DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn) );
                //				_DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation) );
                //				_DumpOutput("undo_operation_hex: " + std::to_string(undo_operation_hex) );
                //				_DumpOutput(_HexEncode(Dec(undo_chunk)));
                //				MsgBox(0,"Info","Check this one out");
                _ParserCodeOldVersion(undo_chunk, 0);
            } /*End of If*/
        }
        else if (undo_operation_hex == Operation_DeallocateFileRecordSegment) // DeallocateFileRecordSegment;
            // Just the FILE header from MFT records;
        {
        }
        else if (undo_operation_hex == Operation_WriteEndOfFileRecordSegment)
        { // WriteEndOfFileRecordSegment;
          //			_DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn) );
          //			_DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation) );
          //			_DumpOutput("undo_operation_hex: " + std::to_string(undo_operation_hex) );
          //			_DumpOutput(_HexEncode(Dec(undo_chunk)));
        }
        else if (undo_operation_hex == Operation_CreateAttribute) // CreateAttribute;
        {
#if 0
            TestAttributeType = _Decode_AttributeType(undo_chunk);
            if (TestAttributeType != '')
            { /*If then*/
                _RemoveSingleOffsetOfAttribute(result.PredictedRefNumber, record_offset_in_mft, UndoChunkSize, TestAttributeType);
            }
            _Decode_CreateAttribute(undo_chunk, 0);
#endif
        }
        else if (undo_operation_hex == Operation_UpdateResidentAttributeValue) // UpdateResidentValue;
        {
#if 0
            _Decode_UpdateResidentValue(undo_chunk, 0);
#endif
        }
        else if /*Case*/ (undo_operation_hex == Operation_UpdateMappingPairs)
        {
            //			_Decode_UpdateMappingPairs(undo_chunk);
        }
        else if /*Case*/ (undo_operation_hex == Operation_UpdateNonResidentAttributeValue) // UpdateNonResidentValue;
        {
            if (StringLeft(undo_chunk, 8) == "494e4458")
            { /*If then*/
#if 0

                _Decode_INDX(undo_chunk, 0);
#endif


                //				_DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn) );
                //				_DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation) );
                //				_DumpOutput("undo_operation_hex: " + std::to_string(undo_operation_hex) );
                //				_DumpOutput(_HexEncode(Dec(undo_chunk)));
                //				MsgBox(0,"Info","Check this one out");
            } /*End of If*/
        }
        else if /*Case*/ (undo_operation_hex == Operation_SetNewAttributeSizes)
        {
            //			_Decode_SetNewAttributeSize(undo_chunk);
        }
        else if /*Case*/ (undo_operation_hex == Operation_AddIndexEntryToRoot || undo_operation_hex == Operation_AddIndexEntryToAllocationBuffer)
        {
            if /*Case*/ (result.PredictedRefNumber == 9 || RealMftRef == 9)
            {
                //Secure;
                if (undo_length == 40)
                { /*If then*/ //SII;
                    _DecodeIndxEntriesSII(undo_chunk, 0);
                    TextInformation += ";Secure:SII//See LogFile_SecureSII.csv";
                    result.AttributeString += ":SII";
                }
                else if (undo_length == 48)
                { /*Else If then*/
                    //SDH;
                    _DecodeIndxEntriesSDH(undo_chunk, 0);
                    TextInformation += ";Secure:SDH//See LogFile_SecureSDH.csv";
                    result.AttributeString += ":SDH";
                } /*End of If*/
            }
            else if /*Case*/ (result.PredictedRefNumber == 24 || RealMftRef == 24)
            { //Quota;
                if (undo_length > 68)
                { /*If then*/
                    _Decode_Quota_Q(undo_chunk, 0);
                    TextInformation += "//See LogFile_QuotaQ.csv";
                }
                else
                { /*Else*/
                    _Decode_Quota_O(undo_chunk, 0);
                    TextInformation += "//See LogFile_QuotaO.csv";
                } /*End of If*/
            }
            else if /*Case*/ (result.PredictedRefNumber == 25 || RealMftRef == 25)
            { //ObjId;
                if (undo_length == 88 || undo_length == 96)
                { /*If then*/
#if 0
                    _Decode_ObjId_O(undo_chunk, 0);
#endif
                    TextInformation += "//See LogFile_ObjIdO.csv";
                } /*End of If*/
            }
            else if /*Case*/ (result.PredictedRefNumber == 26 || RealMftRef == 26)
            { //Reparse;
                _Decode_Reparse_R(undo_chunk, 0);
                TextInformation += "//See LogFile_ReparseR.csv";
            }
            else /*Case*/
            {
                _TryIdentifyIndexEntryType(undo_chunk, undo_operation_hex, 0);
            }
        }
        else if /*Case*/ (undo_operation_hex == Operation_WriteEndOfIndexBuffer)
        { // WriteEndOfIndexBuffer;

            if /*Case*/ (result.AttributeString == "$ATTRIBUTE_LIST")
            {
#if 0
                _DecodeAttrList(undo_chunk, 0);
#endif
                TextInformation += "//See LogFile_AttributeList.csv";
            }
            else if /*Case*/ (result.AttributeString == "Data:SDS")
            {
#if 0
                _MainSecure(undo_chunk, 0);
                if (!::GetLastError())
                { /*If then*/
                    TextInformation += ";Secure:SDS//See LogFile_SecurityDescriptors.csv";
                }
                else
                { /*Else*/
                    TextInformation += ";Secure:SDS//Partial security information not decoded";
                } /*End of If*/
#endif
            }
            else if /*Case*/ (result.AttributeString == "INDEX_ALLOCATION:SII")
            {
#if 0
                Indx = _GetIndxWoFixup(undo_chunk);
                _DecodeIndxEntriesSII(Indx, 0);
#endif
                TextInformation += "//See LogFile_SecureSII.csv";
            }
            else if /*Case*/ (result.AttributeString == "INDEX_ALLOCATION:SDH")
            {
#if 0
                Indx = _GetIndxWoFixup(undo_chunk);
                _DecodeIndxEntriesSDH(Indx, 0);
#endif
                TextInformation += "//See LogFile_SecureSDH.csv";
            }
            else if ((result.PredictedRefNumber == 24 || RealMftRef == 24)
                && (result.AttributeString == "INDEX_ALLOCATION:O" || result.AttributeString == "$INDEX_ROOT:O" || result.AttributeString == "UNKNOWN:O"))
            {
                _Decode_Quota_O(undo_chunk, 0);
                TextInformation += "//See LogFile_QuotaO.csv";
            }
            else if ((result.PredictedRefNumber == 24 || RealMftRef == 24) && (result.AttributeString == "INDEX_ALLOCATION:Q" || result.AttributeString == "$INDEX_ROOT:Q" || result.AttributeString == "UNKNOWN:Q"))
            {
                _Decode_Quota_Q(undo_chunk, 0);
                TextInformation += "//See LogFile_QuotaQ.csv";
            }
            else if ((result.PredictedRefNumber == 25 || RealMftRef == 25) && (result.AttributeString == "INDEX_ALLOCATION:O" || result.AttributeString == "$INDEX_ROOT:O" || result.AttributeString == "UNKNOWN:O"))
            {
#if 0
                _Decode_ObjId_O(undo_chunk, 0);
#endif
                TextInformation += "//See LogFile_ObjIdO.csv";
            }
            else if ((result.PredictedRefNumber == 26 || RealMftRef == 26) && (result.AttributeString == "INDEX_ALLOCATION:R" || result.AttributeString == "$INDEX_ROOT:R" || result.AttributeString == "UNKNOWN:R"))
            {
                _Decode_Reparse_R(undo_chunk, 0);
                TextInformation += "//See LogFile_ReparseR.csv";
            }
            else if /*Case*/ (!(result.PredictedRefNumber == 9 || result.PredictedRefNumber == 24 || result.PredictedRefNumber == 25 || result.PredictedRefNumber == 26 || RealMftRef == 9 || RealMftRef == 24 || RealMftRef == 25 || RealMftRef == 26) && StringInStr(result.AttributeString, "$INDEX_ALLOCATION"))
            {
                _TryIdentifyIndexEntryType(undo_chunk, undo_operation_hex, 0);
            }
            else
            {
                _DumpOutput("Unresolved: " + std::to_string(result.undo_operation));
                {
                    _DumpOutput("this_lsn: " + std::to_string(this_lsn));
                    _DumpOutputHex(/*_HexEncode*/(undo_chunk));
                }
            }
        }
        else if /*Case*/ (undo_operation_hex == Operation_SetIndexEntryVcnInRoot)
        { // SetIndexEntryVcnRoot;
          //			ConsoleWrite("this_lsn: " + std::to_string(this_lsn) );
          //			ConsoleWrite("undo_operation_hex: " + std::to_string(undo_operation_hex) );
          //			ConsoleWrite(_HexEncode(Dec(undo_chunk)));
        }
        else if /*Case*/ (undo_operation_hex == Operation_SetIndexEntryVcnInAllocationBuffer)
        { // SetIndexEntryVcnAllocation;
        }
        else if /*Case*/ (undo_operation_hex == Operation_UpdateFileNameInRoot)
        { // UpdateFileNameRoot;
            _Decode_UpdateFileName(undo_chunk, 0);
        }
        else if /*Case*/ (undo_operation_hex == Operation_UpdateFileNameInAllocationBuffer)
        { // UpdateFileNameAllocation;
            _Decode_UpdateFileName(undo_chunk, 0);
            //			_DumpOutput("this_lsn: " + std::to_string(this_lsn) );
            //			_DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation) );
            //			_DumpOutput(_HexEncode(Dec(undo_chunk)));
        }
        else if /*Case*/ (undo_operation_hex == Operation_SetBitsInNonResidentBitMap)
        { // SetBitsInNonresidentBitMap;
#if 0
            _Decode_BitsInNonresidentBitMap(redo_chunk, result.redo_operation, undo_chunk, result.undo_operation);
#endif
            TextInformation += "//See LogFile_BitsInNonresidentBitMap.csv";
        }
        else if /*Case*/ (undo_operation_hex == Operation_ClearBitsInNonResidentBitMap)
        { // ClearBitsInNonresidentBitMap;
#if 0
            _Decode_BitsInNonresidentBitMap(redo_chunk, result.redo_operation, undo_chunk, result.undo_operation);
#endif

            TextInformation += "//See LogFile_BitsInNonresidentBitMap.csv";
        }
        else if /*Case*/ (undo_operation_hex == Operation_HotFix)
        { // HotFix;
            _DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn));
            _DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation));
            _DumpOutput("undo_operation_hex: " + std::to_string(undo_operation_hex));
            _DumpOutputHex(/*_HexEncode*/(undo_chunk));
        }
        else if /*Case*/ (undo_operation_hex == Operation_EndTopLevelAction)
        { // EndTopLevelAction;
            _DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn));
            _DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation));
            _DumpOutput("undo_operation_hex: " + std::to_string(undo_operation_hex));
            _DumpOutputHex(/*_HexEncode*/(undo_chunk));
        }
        else if /*Case*/ (undo_operation_hex == Operation_PrepareTransaction)
        { // PrepareTransaction;
            _DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn));
            _DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation));
            _DumpOutput("undo_operation_hex: " + std::to_string(undo_operation_hex));
            _DumpOutputHex(/*_HexEncode*/(undo_chunk));
        }
        else if /*Case*/ (undo_operation_hex == Operation_OpenAttributeTableDump)
        { // OpenAttributeTableDump;
          //			ConsoleWrite("this_lsn: " + std::to_string(this_lsn) );
          //			ConsoleWrite("result.undo_operation: " + std::to_string(result.undo_operation) );
          //			ConsoleWrite("undo_operation_hex: " + std::to_string(undo_operation_hex) );
          //			ConsoleWrite(_HexEncode(Dec(undo_chunk)));
        }
        else if /*Case*/ (undo_operation_hex == Operation_AttributeNamesDump)
        { // AttributeNamesDump;
          //			ConsoleWrite("this_lsn: " + std::to_string(this_lsn) );
          //			ConsoleWrite("result.undo_operation: " + std::to_string(result.undo_operation) );
          //			ConsoleWrite("undo_operation_hex: " + std::to_string(undo_operation_hex) );
          //			ConsoleWrite(_HexEncode(Dec(undo_chunk)));
        }
        else if /*Case*/ (undo_operation_hex == Operation_DirtyPageTableDump)
        { // DirtyPageTableDump;
          //			ConsoleWrite("this_lsn: " + std::to_string(this_lsn) );
          //			ConsoleWrite("result.undo_operation: " + std::to_string(result.undo_operation) );
          //			ConsoleWrite("undo_operation_hex: " + std::to_string(undo_operation_hex) );
          //			ConsoleWrite(_HexEncode(Dec(undo_chunk)));
        }
        else if /*Case*/ (undo_operation_hex == Operation_TransactionTableDump)
        { // TransactionTableDump;
            _DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn));
            _DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation));
            _DumpOutput("undo_operation_hex: " + std::to_string(undo_operation_hex));
            _DumpOutputHex(/*_HexEncode*/(undo_chunk));
        }
        else if /*Case*/ (undo_operation_hex == Operation_UpdateRecordDataInRoot)
        { // UpdateRecordDataRoot;
            //			_DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn) );
            //			_DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation) );
            //			_DumpOutput("undo_operation_hex: " + std::to_string(undo_operation_hex) );
            //			_DumpOutput(_HexEncode(Dec(undo_chunk)));

#if 0
            _Decode_Quota_Q_SingleEntry(undo_chunk, 0);
#endif
        }
        else if /*Case*/ (undo_operation_hex == Operation_UpdateRecordDataInAllocationBuffer)
        { // UpdateRecordDataAllocation;
            //			_DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn) );
            //			_DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation) );
            //			_DumpOutput("undo_operation_hex: " + std::to_string(undo_operation_hex) );
            //			_DumpOutput(_HexEncode(Dec(undo_chunk)));


#if 0
            _Decode_Quota_Q_SingleEntry(undo_chunk, 0);
#endif
        }
        else if /*Case*/ (undo_operation_hex == "2500")
        { // JS_NewEndOfRecord;
            _DumpOutput("\r\nthis_lsn: " + std::to_string(this_lsn));
            _DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation));
            _DumpOutput("undo_operation_hex: " + std::to_string(undo_operation_hex));
            _DumpOutputHex(/*_HexEncode*/(undo_chunk));
        }
        else if /*Case*/ (result.undo_operation == "UNKNOWN")
        {
            _DumpOutput("this_lsn: " + std::to_string(this_lsn));
            _DumpOutput("result.undo_operation: " + std::to_string(result.undo_operation));
            _DumpOutput("undo_operation_hex: " + std::to_string(undo_operation_hex));
            _DumpOutputHex(/*_HexEncode*/(undo_chunk));
        }
        else /*Case*/
        {
            _DumpOutput("Missed transaction!");
            _DumpOutput("this_lsn: " + std::to_string(this_lsn));
            _DumpOutput("undo_operation_hex: " + std::to_string(undo_operation_hex));
            _DumpOutputHex(/*_HexEncode*/(undo_chunk));
        }
    }
    else
    { /*Else*/
        UndoChunkSize = 0;
    } /*End of If*/

#pragma endregion


#if 0
    if (!FromRcrdSlack)
    { /*If then*/
        if (SI_USN == PreviousUsn && SI_USN != "")
        { /*If then*/
            //	MsgBox(0,"Usn:","PreviousUsn: " + std::to_string(PreviousUsn)  + ", PreviousUsnFileName: " + PreviousUsnFileName);
            result.FN_Name = PreviousUsnFileName;
        } /*End of If*/
        if (client_previous_lsn == 0)
        { /*If then*/
            PreviousRealRef = "";
        } /*End of If*/
        if (result.undo_operation == "UNKNOWN")
        { /*If then*/
            TextInformation += "//UndoOperation=" + undo_operation_hex
        }
        PreviousRedoOp = redo_operation_hex;
        PreviousAttribute = result.AttributeString;
        if (UsnOk)
        { /*If then*/
            PreviousUsn = UsnJrnlUsn;
            PreviousUsnFileName = UsnJrnlFileName;
            PreviousUsnReason = UsnJrnlReason;
        } /*End of If*/

        //FoundInTable = _ArraySearch(OpenAttributesArray,target_attribute,0,0,0,2,1,0);
        if (FoundInTable >= 0)
        { /*If then*/
            //	ConsoleWrite("ubound(OpenAttributesArray): " + ubound(OpenAttributesArray));
            auto AttributeStringTmp = _ResolveAttributeType(StringMid(OpenAttributesArray[FoundInTable][5], 3, 4));
            if (AttributeStringTmp != "UNKNOWN" && OpenAttributesArray[FoundInTable][9] != 0)
            { /*If then*/ // Why do these sometimes Point to offsets in OpenAttributeTable containing invalid data?;
                if (Is32bit == 0 || OpenAttributesArray[FoundInTable][7] > 0)
                { /*If then*/ // target_attribute is handled differently on nt5.x than nt6.x;
                    result.AttributeString = AttributeStringTmp;
                    if (OpenAttributesArray[FoundInTable][12] != "")
                    { /*If then*/
                        result.AttributeString += ":" + OpenAttributesArray[FoundInTable][12];
                    } /*End of If*/

                    //			result.PredictedRefNumber = OpenAttributesArray[FoundInTable][7];
                    RealMftRef = OpenAttributesArray[FoundInTable][7];
                    result.PredictedRefNumber = RealMftRef;
                    if (result.PredictedRefNumber == -1)
                    { /*If then*/
                        result.PredictedRefNumber = RealMftRef;
                    } /*End of If*/
                }
                else
                {														/*Else*/
                    InOpenAttributeTable = -1 * InOpenAttributeTable; // Will indicate an offset match in OpenAttributeTable that contains invalid data.;
                }														/*End of If*/
            }
        } /*End of If*/

        if (result.PredictedRefNumber == 0)
        { /*If then*/
            //		If target_attribute = 0x0018 && Ubound(OpenAttributesArray) > 1 Then;
            if (Ubound(OpenAttributesArray) > 0)
            { /*If then*/
                FoundInTable = _ArraySearch(OpenAttributesArray, target_attribute, 0, 0, 0, 0, 1, 0);
                //		ConsoleWrite("FoundInTable: " + std::to_string(FoundInTable) );
                if (FoundInTable >= 0)
                { /*If then*/
                    auto AttributeStringTmp = _ResolveAttributeType(StringMid(OpenAttributesArray[FoundInTable][5], 3, 4));
                    if (AttributeStringTmp != "$DATA" && AttributeStringTmp != "UNKNOWN")
                    { /*If then*/
                        result.AttributeString = AttributeStringTmp;
                    } /*End of If*/
                    if (OpenAttributesArray[FoundInTable][12] != "" && result.AttributeString != "")
                    { /*If then*/
                        result.AttributeString += ":" + OpenAttributesArray[FoundInTable][12];
                    } /*End of If*/
                }
                else
                { /*Else*/
                    _DumpOutput("Warning: target_attribute was not found in array: " + std::to_string(target_attribute) + " at lsn " + std::to_string(this_lsn));
                    //				_ArrayDisplay(OpenAttributesArray,"OpenAttributesArray");
                } /*End of If*/
                  //		Else;
                  //			result.PredictedRefNumber = RealMftRef;
            }	  /*End of If*/
        }		  /*End of If*/
    }			  /*End of If*/

    if (result.PredictedRefNumber > 0 && result.FN_Name == "")
    { /*If then*/
        result.FN_Name = _GetFileNameFromArray(result.PredictedRefNumber, this_lsn);
    } /*End of If*/

    if (result.FN_Name == "")
    { /*If then*/
        _SetNameOnSystemFiles();
    }

    _WriteLogFileCsv();
#endif
    // if (DoSplitCsv)
    // { /*If then*/
    // 	_WriteCSVExtra();
    // }
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("End parsing transaction in verbose mode.");
        //	_ArrayDisplay(OpenAttributesArray,"OpenAttributesArray");
        //	_ArrayDisplay(AttrArray,"AttrArray");
    } /*End of If*/

    _ClearVar();

    //assert(false);
    return {};
}

std::string _SolveUndoRedoCodes(int64_t OpCode)
{
    std::string InterpretedCode;
    /**/
    if (false)
    {
    }
    else if (OpCode == 0)
    { /*Case替换*/
        InterpretedCode = "Noop";
    }
    else if (OpCode == 1)
    { /*Case替换*/
        InterpretedCode = "CompensationlogRecord";
    }
    else if (OpCode == 2)
    { /*Case替换*/
        InterpretedCode = "InitializeFileRecordSegment";
    }
    else if (OpCode == 3)
    { /*Case替换*/
        InterpretedCode = "DeallocateFileRecordSegment";
    }
    else if (OpCode == 4)
    { /*Case替换*/
        InterpretedCode = "WriteEndofFileRecordSegement";
    }
    else if (OpCode == 5)
    { /*Case替换*/
        InterpretedCode = "CreateAttribute";
    }
    else if (OpCode == 6)
    { /*Case替换*/
        InterpretedCode = "DeleteAttribute";
    }
    else if (OpCode == 7)
    { /*Case替换*/
        InterpretedCode = "UpdateResidentValue";
    }
    else if (OpCode == 8)
    { /*Case替换*/
        InterpretedCode = "UpdateNonResidentValue";
    }
    else if (OpCode == 9)
    { /*Case替换*/
        InterpretedCode = "UpdateMappingPairs";
    }
    else if (OpCode == 10)
    { /*Case替换*/
        InterpretedCode = "DeleteDirtyClusters";
    }
    else if (OpCode == 11)
    { /*Case替换*/
        InterpretedCode = "SetNewAttributeSizes";
    }
    else if (OpCode == 12)
    { /*Case替换*/
        InterpretedCode = "AddindexEntryRoot";
    }
    else if (OpCode == 13)
    { /*Case替换*/
        InterpretedCode = "DeleteindexEntryRoot";
    }
    else if (OpCode == 14)
    { /*Case替换*/
        InterpretedCode = "AddIndexEntryAllocation";
    }
    else if (OpCode == 15)
    { /*Case替换*/
        InterpretedCode = "DeleteIndexEntryAllocation";
    }
    else if (OpCode == 16)
    { /*Case替换*/
        InterpretedCode = "WriteEndOfIndexBuffer";
    }
    else if (OpCode == 17)
    { /*Case替换*/
        InterpretedCode = "SetIndexEntryVcnRoot";
    }
    else if (OpCode == 18)
    { /*Case替换*/
        InterpretedCode = "SetIndexEntryVcnAllocation";
    }
    else if (OpCode == 19)
    { /*Case替换*/
        InterpretedCode = "UpdateFileNameRoot";
    }
    else if (OpCode == 20)
    { /*Case替换*/
        InterpretedCode = "UpdateFileNameAllocation";
    }
    else if (OpCode == 21)
    { /*Case替换*/
        InterpretedCode = "SetBitsInNonresidentBitMap";
    }
    else if (OpCode == 22)
    { /*Case替换*/
        InterpretedCode = "ClearBitsInNonresidentBitMap";
    }
    else if (OpCode == 23)
    { /*Case替换*/
        InterpretedCode = "HotFix";
    }
    else if (OpCode == 24)
    { /*Case替换*/
        InterpretedCode = "EndTopLevelAction";
    }
    else if (OpCode == 25)
    { /*Case替换*/
        InterpretedCode = "PrepareTransaction";
    }
    else if (OpCode == 26)
    { /*Case替换*/
        InterpretedCode = "CommitTransaction";
    }
    else if (OpCode == 27)
    { /*Case替换*/
        InterpretedCode = "ForgetTransaction";
    }
    else if (OpCode == 28)
    { /*Case替换*/
        InterpretedCode = "OpenNonresidentAttribute";
    }
    else if (OpCode == 29)
    { /*Case替换*/
        InterpretedCode = "OpenAttributeTableDump";
    }
    else if (OpCode == 30)
    { /*Case替换*/
        InterpretedCode = "AttributeNamesDump";
    }
    else if (OpCode == 31)
    { /*Case替换*/
        InterpretedCode = "DirtyPageTableDump";
    }
    else if (OpCode == 32)
    { /*Case替换*/
        InterpretedCode = "TransactionTableDump";
    }
    else if (OpCode == 33)
    { /*Case替换*/
        InterpretedCode = "UpdateRecordDataRoot";
    }
    else if (OpCode == 34)
    { /*Case替换*/
        InterpretedCode = "UpdateRecordDataAllocation";
    }
    else if (OpCode == 37)
    { /*Case替换*/
        InterpretedCode = "JS_NewEndOfRecord";
    }
    else
    { /*Case Else替换*/

        InterpretedCode = "UNKNOWN";
        // Comment:		MsgBox(0,"OpCode",OpCode);
    } /*AutoIt_EndSelect */;
    return InterpretedCode;
}

std::string _ResolveAttributeType(std::string input)
{
    /*AutoIt_Select 	*/
    if (false)
    {
    }
    else if (input == Operation_WriteEndOfIndexBuffer)
    { /*Case替换*/
        return "$STANDARD_INFORMATION";
    }
    else if (input == Operation_TransactionTableDump)
    { /*Case替换*/
        return "$ATTRIBUTE_LIST";
    }
    else if (input == "3000")
    { /*Case替换*/
        return "$FILE_NAME";
    }
    else if (input == "4000")
    { /*Case替换*/
        return "$OBJECT_ID";
    }
    else if (input == "5000")
    { /*Case替换*/
        return "$SECURITY_DESCRIPTOR";
    }
    else if (input == "6000")
    { /*Case替换*/
        return "$VOLUME_NAME";
    }
    else if (input == "7000")
    { /*Case替换*/
        return "$VOLUME_INFORMATION";
    }
    else if (input == "8000")
    { /*Case替换*/
        return "$DATA";
    }
    else if (input == "9000")
    { /*Case替换*/
        return "$INDEX_ROOT";
    }
    else if (input == "a000")
    { /*Case替换*/
        return "$INDEX_ALLOCATION";
    }
    else if (input == "b000")
    { /*Case替换*/
        return "$BITMAP";
    }
    else if (input == "c000")
    { /*Case替换*/
        return "$REPARSE_POINT";
    }
    else if (input == "d000")
    { /*Case替换*/
        return "$EA_INFORMATION";
    }
    else if (input == "e000")
    { /*Case替换*/
        return "$EA";
    }
    else if (input == "0001")
    { /*Case替换*/
        return "$LOGGED_UTILITY_STREAM";
    }
    else
    { /*Case Else替换*/

        return "UNKNOWN";
    } /*AutoIt_EndSelect 	*/
} // Comment:;

int64_t _Decode_CheckpointRecord(std::string InputData)
{
    // std::string LSN_Checkpoint,LSN_OpenAttributeTableDump,LSN_AttributeNamesDump,LSN_DirtyPageTableDump,LSN_TransactionTableDump,Size_OpenAttributeTableDump,Size_AttributeNamesDump,Size_DirtyPageTableDump,Size_TransactionTableDump,UsnjrnlRealSize;
    // int64_t Unknown6,LSN_FlushCache,Unknown7,Unknown8,UsnJrnlMftRef,UsnjrnlMftrefSeqNo,Unknown9,LSN7;
    // int64_t StartOffset = 1

    // LSN_Checkpoint64_t = StringMid(InputData, StartOffset, 16);
    // LSN_Checkpoint64_t = _SwapEndian(LSN_Checkpoint);
    // LSN_Checkpoint64_t = Dec(LSN_Checkpoint,2)

    // LSN_OpenAttributeTableDump = StringMid(InputData, StartOffset + 16, 16);
    // LSN_OpenAttributeTableDump = _SwapEndian(LSN_OpenAttributeTableDump);
    // LSN_OpenAttributeTableDump = Dec(LSN_OpenAttributeTableDump,2)

    // LSN_AttributeNamesDump = StringMid(InputData, StartOffset + 32, 16);
    // LSN_AttributeNamesDump = _SwapEndian(LSN_AttributeNamesDump);
    // LSN_AttributeNamesDump = Dec(LSN_AttributeNamesDump,2)

    // LSN_DirtyPageTableDump = StringMid(InputData, StartOffset + 48, 16);
    // LSN_DirtyPageTableDump = _SwapEndian(LSN_DirtyPageTableDump);
    // LSN_DirtyPageTableDump = Dec(LSN_DirtyPageTableDump,2)

    // LSN_TransactionTableDump = StringMid(InputData, StartOffset + 64, 16);
    // LSN_TransactionTableDump = _SwapEndian(LSN_TransactionTableDump);
    // LSN_TransactionTableDump = Dec(LSN_TransactionTableDump,2)

    // Size_OpenAttributeTableDump = StringMid(InputData, StartOffset + 80, 8);
    // Size_OpenAttributeTableDump = _SwapEndian(Size_OpenAttributeTableDump);
    // Size_OpenAttributeTableDump = Dec(Size_OpenAttributeTableDump,2)

    // Size_AttributeNamesDump = StringMid(InputData, StartOffset + 88, 8);
    // Size_AttributeNamesDump = _SwapEndian(Size_AttributeNamesDump);
    // Size_AttributeNamesDump = Dec(Size_AttributeNamesDump,2)

    // Size_DirtyPageTableDump = StringMid(InputData, StartOffset + 96, 8);
    // Size_DirtyPageTableDump = _SwapEndian(Size_DirtyPageTableDump);
    // Size_DirtyPageTableDump = Dec(Size_DirtyPageTableDump,2)

    // Size_TransactionTableDump = StringMid(InputData, StartOffset + 104, 8);
    // Size_TransactionTableDump = _SwapEndian(Size_TransactionTableDump);
    // Size_TransactionTableDump = Dec(Size_TransactionTableDump,2)

    // UsnjrnlRealSize = StringMid(InputData, StartOffset + 112, 8);
    // UsnjrnlRealSize = _SwapEndian(UsnjrnlRealSize);
    // UsnjrnlRealSize = Dec(UsnjrnlRealSize,2)

    // Unknown6 = StringMid(InputData, StartOffset + 120, 8);
    // Unknown6 = _SwapEndian(Unknown6);
    // Unknown6 = Dec(Unknown6,2)

    // LSN_FlushCache = StringMid(InputData, StartOffset + 128, 16);
    // LSN_FlushCache = _SwapEndian(LSN_FlushCache);
    // LSN_FlushCache = Dec(LSN_FlushCache,2)

    // Unknown7 = StringMid(InputData, StartOffset + 144, 8);
    // Unknown7 = _SwapEndian(Unknown7);
    // Unknown7 = Dec(Unknown7,2)

    // Unknown8 = StringMid(InputData, StartOffset + 152, 8);
    // Unknown8 = _SwapEndian(Unknown8);
    // Unknown8 = Dec(Unknown8,2)

    // UsnJrnlMftRef = StringMid(InputData, StartOffset + 160, 12);
    // UsnJrnlMftRef = _SwapEndian(UsnJrnlMftRef);
    // UsnJrnlMftRef = Dec(UsnJrnlMftRef,2)

    // UsnJrnlMftrefSeqNo = StringMid(InputData, StartOffset + 172, 4);
    // UsnJrnlMftrefSeqNo = _SwapEndian(UsnJrnlMftrefSeqNo);
    // UsnJrnlMftrefSeqNo = Dec(UsnJrnlMftrefSeqNo,2)

    // Unknown9 = StringMid(InputData, StartOffset + 176, 16);
    // Unknown9 = _SwapEndian(Unknown9);
    // Unknown9 = Dec(Unknown9,2)

    // LSN7 = StringMid(InputData, StartOffset + 192, 16);
    // LSN7 = _SwapEndian(LSN7);
    // LSN7 = Dec(LSN7,2)

    // FileWrite(LogFileCheckpointRecordCsv, this_lsn + de + LSN_Checkpoint64_t + de + LSN_OpenAttributeTableDump + de + LSN_AttributeNamesDump + de + LSN_DirtyPageTableDump + de + LSN_TransactionTableDump + de + Size_OpenAttributeTableDump + de + Size_AttributeNamesDump + de + Size_DirtyPageTableDump + de + Size_TransactionTableDump + de + UsnjrnlRealSize + de + Unknown6 + de + LSN_FlushCache + de + Unknown7 + de + Unknown8 + de + UsnJrnlMftRef + de + UsnJrnlMftrefSeqNo + de + Unknown9 + de + LSN7);
    return {};;
}

int64_t _ParserCodeOldVersion(const std::string& MFTEntry, int64_t IsRedo)
{
    int64_t UpdSeqArrOffset = 0, HDR_LSN = 0, HDR_HardLinkCount = 0, HDR_RecRealSize = 0, HDR_RecAllocSize = 0, HDR_BaseRecSeqNo = 0, NextAttributeOffset = 0, AttributeType = 0;

    std::string RecordActive;
    std::string HDR_Flags;


    std::string TestAttributeString;

    // 属性数组
    std::array<int, 17> AttributeArray;

    // 属性名数组
    std::array<std::string, 17> AttributeArrayName;

    AttributeArrayName[0] = "Attribute name";
    //AttributeArray[0] = "Number";
    AttributeArrayName[1] = "$STANDARD_INFORMATION";
    AttributeArrayName[2] = "$ATTRIBUTE_LIST";
    AttributeArrayName[3] = "$FILE_NAME";
    AttributeArrayName[4] = "$OBJECT_ID";
    AttributeArrayName[5] = "$SECURITY_DESCRIPTOR";
    AttributeArrayName[6] = "$VOLUME_NAME";
    AttributeArrayName[7] = "$VOLUME_INFORMATION";
    AttributeArrayName[8] = "$DATA";
    AttributeArrayName[9] = "$INDEX_ROOT";
    AttributeArrayName[10] = "$INDEX_ALLOCATION";
    AttributeArrayName[11] = "$BITMAP";
    AttributeArrayName[12] = "$REPARSE_POINT";
    AttributeArrayName[13] = "$EA_INFORMATION";
    AttributeArrayName[14] = "$EA";
    AttributeArrayName[15] = "$PROPERTY_SET";
    AttributeArrayName[16] = "$LOGGED_UTILITY_STREAM";
    //UpdSeqArrOffset = StringMid(MFTEntry, 9, 4);
    UpdSeqArrOffset = Dec(_SwapEndian(StringMid(MFTEntry, 9, 4)), 2);
    //HDR_LSN = StringMid(MFTEntry, 17, 16);
    HDR_LSN = Dec(_SwapEndian(StringMid(MFTEntry, 17, 16)), 2);
    //HDR_SequenceNo = StringMid(MFTEntry, 33, 4);
    HDR_SequenceNo = Dec(_SwapEndian(StringMid(MFTEntry, 33, 4)), 2);
    //HDR_HardLinkCount = StringMid(MFTEntry, 37, 4);
    HDR_HardLinkCount = Dec(_SwapEndian(StringMid(MFTEntry, 37, 4)), 2);
    HDR_Flags = StringMid(MFTEntry, 45, 4); // 00=deleted file,01=file,02=deleted folder,03=folder;
    /*AutoIt_Select 	*/
    if (false)
    {
    }
    else if (HDR_Flags == "0000")
    { /*Case替换*/
        HDR_Flags = "FILE";
        RecordActive = "DELETED";
    }
    else if (HDR_Flags == Operation_CompensationLogRecord)
    { /*Case替换*/
        HDR_Flags = "FILE";
        RecordActive = "ALLOCATED";
    }
    else if (HDR_Flags == Operation_InitializeFileRecordSegment)
    { /*Case替换*/
        HDR_Flags = "FOLDER";
        RecordActive = "DELETED";
    }
    else if (HDR_Flags == Operation_DeallocateFileRecordSegment)
    { /*Case替换*/
        HDR_Flags = "FOLDER";
        RecordActive = "ALLOCATED";
    }
    else if (HDR_Flags == Operation_UpdateMappingPairs)
    { /*Case替换*/
        HDR_Flags = "FILE+INDEX_SECURITY";
        RecordActive = "ALLOCATED";
    }
    else if (HDR_Flags == Operation_DeleteIndexEntryFromRoot)
    { /*Case替换*/
        HDR_Flags = "FILE+INDEX_OTHER";
        RecordActive = "ALLOCATED";
    }
    else
    { /*Case Else替换*/

        HDR_Flags = "UNKNOWN";
        RecordActive = "UNKNOWN";
    } /*AutoIt_EndSelect 	*/

    //HDR_RecRealSize = StringMid(MFTEntry, 49, 8);
    HDR_RecRealSize = Dec(_SwapEndian(StringMid(MFTEntry, 49, 8)), 2);
    if (StringLen(MFTEntry) < 98)
    { /*If then*/
       // Comment:The critical offset is where the mft record number is located.;
        _DumpOutput("Error in _ParserCodeOldVersion()");
        _DumpOutput("MFT record was too damaged to process properly.");
        _DumpOutput("The size of record was expected to be " + std::to_string(HDR_RecAllocSize) + " bytes, but was only " + std::to_string(StringLen(MFTEntry) / 2) + " bytes");
        _DumpOutputHex(MFTEntry);
        return 1;
    } /*End of If*/

    auto HDR_RecAllocSizeStr = StringMid(MFTEntry, 57, 8);
    HDR_RecAllocSize = Dec(_SwapEndian(HDR_RecAllocSizeStr), 2);
    auto HDR_BaseRecordStr = StringMid(MFTEntry, 65, 12);
    HDR_BaseRecord = Dec(_SwapEndian(HDR_BaseRecordStr), 2);
    auto HDR_BaseRecSeqNoStr = StringMid(MFTEntry, 77, 4);
    HDR_BaseRecSeqNo = Dec(_SwapEndian(HDR_BaseRecSeqNoStr), 2);
    auto HDR_NextAttribIDStr = StringMid(MFTEntry, 81, 4);
    auto HDR_NextAttribID = Dec(_SwapEndian(HDR_NextAttribIDStr));
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("_ParserCodeOldVersion()");
        _DumpOutput("HDR_LSN: " + std::to_string(HDR_LSN));
        _DumpOutput("HDR_SequenceNo: " + std::to_string(HDR_SequenceNo));
        _DumpOutput("HDR_HardLinkCount: " + std::to_string(HDR_HardLinkCount));
        _DumpOutput("HDR_Flags: " + std::to_string(HDR_Flags));
        _DumpOutput("RecordActive: " + std::to_string(RecordActive));
        _DumpOutput("HDR_RecRealSize: " + std::to_string(HDR_RecRealSize));
        _DumpOutput("HDR_RecAllocSize: " + std::to_string(HDR_RecAllocSize));
        _DumpOutput("HDR_BaseRecord: " + std::to_string(HDR_BaseRecord));
        _DumpOutput("HDR_BaseRecSeqNo: " + std::to_string(HDR_BaseRecSeqNo));
        _DumpOutput("HDR_NextAttribID: " + std::to_string(HDR_NextAttribID));
    } /*End of If*/

    auto& HDR_MFTREcordNumberInt = result.HDR_MFTREcordNumber;
    std::string HDR_MFTREcordNumber;
    if (UpdSeqArrOffset == 48)
    { /*If then*/
        HDR_MFTREcordNumber = StringMid(MFTEntry, 89, 8);
        HDR_MFTREcordNumberInt = Dec(_SwapEndian(HDR_MFTREcordNumber), 2);
        HDR_MFTREcordNumber = Hex(HDR_MFTREcordNumberInt);
        if (HDR_MFTREcordNumberInt != result.PredictedRefNumber
            && redo_length > 24
            && result.undo_operation != "CompensationlogRecord")
        { /*If then*/
            _DumpOutput("Error with LSN " + std::to_string(this_lsn) + ". Predicted Reference number: " + std::to_string(result.PredictedRefNumber) + " do not match Reference found in MFT: " + HDR_MFTREcordNumber + ". SectorsPerCluster (" + std::to_string(option.SectorsPerCluster) + ")||  MFT Record size configuration (" + std::to_string(MFT_Record_Size) + ") might be incorrect.");
            return {};
        }
    }
    else
    { /*Else*/
        HDR_MFTREcordNumber = "NT style";
    } /*End of If*/


    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("HDR_MFTREcordNumber: " + std::to_string(HDR_MFTREcordNumber));
    } /*End of If*/

    NextAttributeOffset = (Dec(StringMid(MFTEntry, 41, 2), 0) * 2) + 1;
    // Comment:	ConsoleWrite("NextAttributeOffset: " + NextAttributeOffset);
    auto AttributeTypeStr = StringMid(MFTEntry, NextAttributeOffset, 8);
    // Comment:	ConsoleWrite("AttributeType: " + AttributeType);
    auto AttributeSizeStr = StringMid(MFTEntry, NextAttributeOffset + 8, 8);
    auto AttributeSize = Dec(_SwapEndian(AttributeSizeStr), 2);
    // Comment:	ConsoleWrite("AttributeSize: " + AttributeSize);
    auto AttributeKnown = 1;
    while (AttributeKnown == 1)
    { // TODO条件手动替换;
        auto NextAttributeType = StringMid(MFTEntry, NextAttributeOffset, 8);
        AttributeTypeStr = NextAttributeType;
        auto AttributeSizeStr = StringMid(MFTEntry, NextAttributeOffset + 8, 8);
        AttributeSize = Dec(_SwapEndian(AttributeSizeStr), 2);
        /*AutoIt_Select 		*/
        if (false)
        {
        }
        else if (AttributeTypeStr == ATTR_TYPE_STANDARD_INFORMATION)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[1] += 1;
            // Comment:				_Get_StandardInformation(MFTEntry, NextAttributeOffset, AttributeSize);

            // TODO 解析MFTEntry并打印
            //_Get_StandardInformation(StringMid(MFTEntry, 1, (NextAttributeOffset + (AttributeSize * 2)) - 1), NextAttributeOffset, AttributeSize);

            TestAttributeString += "$STANDARD_INFORMATION?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
            if (AttributeSize - 24 != 72)
            { /*If Then in one Line*/
                TextInformation += ";Non-standard size of STANDARD_INFORMATION";
            }
        }
        else if (AttributeTypeStr == ATTR_TYPE_ATTRIBUTE_LIST)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[2] += 1;
            TestAttributeString += "$ATTRIBUTE_LIST?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
        else if (AttributeTypeStr == ATTR_TYPE_FILE_NAME)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[3] += 1;
            //TODO  _Get_FileName(MFTEntry, NextAttributeOffset, AttributeArray[3]);
            TestAttributeString += "$FILE_NAME?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
        else if (AttributeTypeStr == ATTR_TYPE_OBJECT_ID)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[4] += 1;
            //TODO _Get_ObjectID(MFTEntry, NextAttributeOffset, AttributeSize, 1);
            TestAttributeString += "$OBJECT_ID?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
        else if (AttributeTypeStr == ATTR_TYPE_SECURITY_DESCRIPTOR)
        { /*Case替换*/
            //AttributeKnown = 1;
            //AttributeArray[5] += 1;
            //CoreAttr = _GetAttributeEntry(StringMid(MFTEntry, NextAttributeOffset, AttributeSize * 2));
            //CoreAttrChunk = CoreAttr[0];
            //CoreAttrName = CoreAttr[1];
            //// Comment:				ConsoleWrite("SECURITY_DESCRIPTOR:");
            //// Comment:				ConsoleWrite(_HexEncode(Dec(CoreAttrChunk)));
            //if (CoreAttrChunk != "")
            //{ /*If then*/
            //    _DecodeSecurityDescriptorAttribute(CoreAttrChunk);
            //    ;
            //    Write information to csv;
            //    if (Not ::GetLastError())
            //    { /*If then*/
            //        _WriteCsvSecureSDS(1);
            //    } /*End of If*/
            //    ; Make sure all global variables for csv are cleared;
            //    _ClearVarSecureSDS();
            //} /*End of If*/
            //  // Comment:				TextInformation += ";See LogFile_SecurityDescriptors.csv";
            //// Comment:				result.AttributeString = "$SECURITY_DESCRIPTOR";
            //TestAttributeString += "SECURITY_DESCRIPTOR?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
        else if (AttributeTypeStr == ATTR_TYPE_VOLUME_NAME)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[6] += 1;
            //TODO _Get_VolumeName(MFTEntry, NextAttributeOffset, AttributeSize);
            TestAttributeString += "VOLUME_NAME?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
        else if (AttributeTypeStr == ATTR_TYPE_VOLUME_INFORMATION)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[7] += 1;
            //TODO  _Get_VolumeInformation(MFTEntry, NextAttributeOffset);
            TestAttributeString += "VOLUME_INFORMATION?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
        else if (AttributeTypeStr == ATTR_TYPE_DATA)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[8] += 1;

            //TODO CoreAttr = _GetAttributeEntry(StringMid(MFTEntry, NextAttributeOffset, AttributeSize * 2));
           // CoreAttrChunk = CoreAttr[0];
           // CoreAttrName = CoreAttr[1];
          //  _Get_Data(MFTEntry, NextAttributeOffset, AttributeArray[8], IsRedo);

            TestAttributeString += "DATA?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
#if 0//暂时屏蔽复杂的代码
        else if (AttributeTypeStr == ATTR_TYPE_INDEX_ROOT)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[9] += 1;


            CoreAttr = _GetAttributeEntry(StringMid(MFTEntry, NextAttributeOffset, AttributeSize * 2));
            CoreAttrChunk = CoreAttr[0];
            CoreAttrName = CoreAttr[1];
            if (CoreAttrChunk != "")
            { /*If then*/
                if (CoreAttrName == "I30")
                { /*If Then in one Line*/
                    _Get_IndexRoot(CoreAttrChunk, IsRedo);
                }
                EndIf;
                TestAttributeString += "$INDEX_ROOT?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
            }
        }
        else if (AttributeTypeStr == ATTR_TYPE_INDEX_ALLOCATION)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[10] += 1;
            TestAttributeString += "INDEX_ALLOCATION?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
        else if (AttributeTypeStr == ATTR_TYPE_BITMAP)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[11] += 1;
            CoreAttr = _GetAttributeEntry(StringMid(MFTEntry, NextAttributeOffset, AttributeSize * 2));
            CoreAttrChunk = CoreAttr[0];
            CoreAttrName = CoreAttr[1];
            TestAttributeString += "BITMAP?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
        else if (AttributeTypeStr == ATTR_TYPE_REPARSE_POINT)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[12] += 1;
            CoreAttr = _GetAttributeEntry(StringMid(MFTEntry, NextAttributeOffset, AttributeSize * 2));
            CoreAttrChunk = CoreAttr[0];
            CoreAttrName = CoreAttr[1];
            if (CoreAttrChunk != "")
            { /*If then*/
                _Get_ReparsePoint(CoreAttrChunk);
            } /*End of If*/
            TestAttributeString += "REPARSE_POINT?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
        else if (AttributeTypeStr == ATTR_TYPE_EA_INFORMATION)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[13] += 1;
            CoreAttr = _GetAttributeEntry(StringMid(MFTEntry, NextAttributeOffset, AttributeSize * 2));
            CoreAttrChunk = CoreAttr[0];
            CoreAttrName = CoreAttr[1];
            if (CoreAttrChunk != "")
            { /*If then*/
                _Get_EaInformation(CoreAttrChunk);
            } /*End of If*/
            TestAttributeString += "EA_INFORMATION?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
        else if (AttributeTypeStr == ATTR_TYPE_EA)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[14] += 1;
            CoreAttr = _GetAttributeEntry(StringMid(MFTEntry, NextAttributeOffset, AttributeSize * 2));
            CoreAttrChunk = CoreAttr[0];
            CoreAttrName = CoreAttr[1];
            if (CoreAttrChunk != "")
            { /*If then*/
                _Get_Ea(CoreAttrChunk);
            } /*End of If*/
            TestAttributeString += "EA?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
        else if (AttributeTypeStr == ATTR_TYPE_PROPERTY_SET)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[15] += 1;
            CoreAttr = _GetAttributeEntry(StringMid(MFTEntry, NextAttributeOffset, AttributeSize * 2));
            CoreAttrChunk = CoreAttr[0];
            CoreAttrName = CoreAttr[1];
            TestAttributeString += "PROPERTY_SET?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
        else if (AttributeTypeStr == ATTR_TYPE_LOGGED_UTILITY_STREAM)
        { /*Case替换*/
            AttributeKnown = 1;
            AttributeArray[16] += 1;
            CoreAttr = _GetAttributeEntry(StringMid(MFTEntry, NextAttributeOffset, AttributeSize * 2));
            CoreAttrChunk = CoreAttr[0];
            CoreAttrName = CoreAttr[1];
            if (CoreAttrChunk != "")
            { /*If then*/
                _Get_LoggedUtilityStream(CoreAttrChunk, CoreAttrName);
            } /*End of If*/
            TestAttributeString += "LOGGED_UTILITY_STREAM?" + std::to_string((NextAttributeOffset - 1) / 2) + ",";
        }
#endif
        else if (AttributeTypeStr == ATTR_TYPE_ATTRIBUTE_END_MARKER)
        { /*Case替换*/
            AttributeKnown = 0;
            // Comment:				ConsoleWrite("No more attributes in this record.");

        }
        else
        { /*Case Else替换*/

            AttributeKnown = 0;
            // Comment:				ConsoleWrite("Unknown attribute found in this record.");
        } /*AutoIt_EndSelect ;*/
        NextAttributeOffset = NextAttributeOffset + (AttributeSize * 2);
    } // End of while;

    //For CurrentAttribute = 1 To UBound(AttributeArray) - 1;
    for (auto CurrentAttribute = 1; CurrentAttribute < AttributeArray.size() - 1; CurrentAttribute++)
    {
        if (AttributeArray[CurrentAttribute] != 0)
        { /*If Then in one Line*/
            result.AttributeString += AttributeArrayName[CurrentAttribute] + "(" + std::to_string(AttributeArray[CurrentAttribute]) + ")+";
        }
    }

    if (!result.AttributeString.empty())
    { /*If Then in one Line*/
        result.AttributeString = StringTrimRight(result.AttributeString, 1);
    }

    // FIXME TODO
    //_WriteOut_MFTrecord(MFTEntry);

    if (IsRedo)
    { /*If then*/
        _UpdateSeveralOffsetOfAttribute(HDR_MFTREcordNumberInt, TestAttributeString);
    } /*End of If*/
    return {};
}

int64_t _UpdateSeveralOffsetOfAttribute(int64_t TestRef, std::string TestString)
{
    int64_t RefIndex;
    if (option.VerboseOn) {/*If then*/
        _DumpOutput("_UpdateSeveralOffsetOfAttribute()");
        _DumpOutput("result.TestRef: " + std::to_string(TestRef));
        _DumpOutput("result.TestString: " + std::to_string(TestString));
    }/*End of If*/
   // RefIndex = _ArraySearch(result.AttrArray, TestRef, 0, result.GlobalAttrCounter, 0, 0, 1, 0);

        // 查看全局属性中是否已经有了该索引,如果有则更新
    // 如果没有,则插入一个
    auto refIndex = result.AttrArray.find(TestRef);
    //if (RefIndex > -1)

        // 查看全局属性中是否已经有了该索引,如果有则更新
    // 如果没有,则插入一个
    if (refIndex != result.AttrArray.end())
    {/*If then*/
        auto RefIndex = TestRef;

        //if (RefIndex > -1) 
        //{
            /*If then*/
            //Comment:		_DumpOutput("Ref already exist in array");
        result.AttrArray[RefIndex][0] = TestRef;
        result.AttrArray[RefIndex][1] = TestString + ",";
    }
    else {/*Else*/

        //Comment:		_DumpOutput("Adding new row for new ref");
       // if (result.GlobalAttrCounter == result.AttrArray.size())) {/*If then*/
         //   ReDim result.AttrArray[result.GlobalAttrCounter + 50][2];
        //}/*End of If*/

        result.AttrArray[TestRef][0] = TestRef;
        result.AttrArray[TestRef][1] = TestString + ",";
        result.GlobalAttrCounter += 1;
    }/*End of If*/

    return {};
}

// 查看全局索引数组,看看是否有TestRef对应的索引,并且其中包含 TestString
// 查看索引里的?后面的数字中是否有 TestString 对应的数字
std::string _CheckOffsetOfAttribute(int64_t TestRef, int64_t TestString)
{
    /** 示例日志
    _CheckOffsetOfAttribute()
    TestRef: 33
    StringLen(TestRef): 2
    TestString: 264
    GlobalAttrCounter: 2
    AttrArray[RefIndex][1]: STANDARD_INFORMATION?56,FILE_NAME?152,DATA?264,,
    AttrArraySplit[i]: STANDARD_INFORMATION?56
    TestOffset: 0
    AttrArraySplit[i]: FILE_NAME?152
    TestOffset: 0
    AttrArraySplit[i]: DATA?264
    TestOffset: 7
     */
    std::vector<std::string> attrArraySplit;
    std::string FoundAttr;
    if (option.VerboseOn) {/*If then*/
        _DumpOutput("_CheckOffsetOfAttribute()");
        _DumpOutput("TestRef: " + std::to_string(TestRef));
        _DumpOutput("StringLen(TestRef): " + std::to_string(std::to_string(TestRef).length()));
        _DumpOutput("TestString: " + std::to_string(TestString));
        _DumpOutput("result.GlobalAttrCounter: " + std::to_string(result.GlobalAttrCounter));
        //Comment:		_ArrayDisplay(result.AttrArray,"result.AttrArray");
    }/*End of If*/

    //RefIndex = _ArraySearch(result.AttrArray, TestRef, 0, result.GlobalAttrCounter, 0, 0, 1, 0);
    auto refIndex = result.AttrArray.find(TestRef);
    //if (RefIndex > -1)
    if (refIndex != result.AttrArray.end())
    {/*If then*/
        auto RefIndex = TestRef;

        // 原split后,坐标0为数组数量
        attrArraySplit = utils::strings::split(result.AttrArray[RefIndex][1], ',');
        if (option.VerboseOn) {/*If then*/
            _DumpOutput("result.AttrArray[RefIndex][1]: " + result.AttrArray[RefIndex][1]);
            //Comment:			_ArrayDisplay(attrArraySplit,"attrArraySplit");
        }/*End of If*/

        for (auto i = 0; i < attrArraySplit.size(); i++)
        {
            auto TestOffset = attrArraySplit[i].find(std::to_string(TestString));
            if (option.VerboseOn) {/*If then*/
                _DumpOutput("attrArraySplit[i]: " + attrArraySplit[i]);
                _DumpOutput("TestOffset: " + std::to_string(TestOffset));
            }/*End of If*/
            if (TestOffset != std::string::npos)
            {/*If then*/
                if (!str_is_digit(StringMid(attrArraySplit[i], TestOffset - 1, 1))) {/*If then*/
                    if (StringMid(attrArraySplit[i], TestOffset - 1, 1) != "?") {/*If Then in one Line*/
                        _DumpOutput(std::string("Error in _CheckOffsetOfAttribute()") + attrArraySplit[i] + std::string(" -> ") + attrArraySplit[i] + std::string(" at offset ") + std::to_string(TestOffset - 1));
                    }
                    FoundAttr = StringMid(attrArraySplit[i], 1, TestOffset - 2);
                    //Comment:					ConsoleWrite("FoundAttr: "+ FoundAttr);
                    return  FoundAttr;
                }/*End of If*/
            }/*End of If*/
        }
        //Comment:		_DumpOutput("Attribute offset not found");
       // return  SetError(1, 0, FoundAttr);
        return "";
    }
    else {
        /*Else*/;
        //Comment:		_DumpOutput("Ref not found");
        //return  SetError(1, 0, FoundAttr);
    }/*End of If*/
    return "";
}

void _RemoveAllOffsetOfAttribute(int64_t TestRef)
{
    int64_t RefIndex;
    if (option.VerboseOn) {/*If then*/
        _DumpOutput("_RemoveAllOffsetOfAttribute()");
        _DumpOutput("TestRef: " + std::to_string(TestRef));
    }/*End of If*/

    const auto it = result.AttrArray.find(TestRef);
    if (it != result.AttrArray.end())
    {
        result.AttrArray.erase(it);
    }
}

std::string _Decode_AttributeName(std::string data)
{
    std::string TmpName;

    /*
    Converts a binary variant into a string.
    BinaryToString(expression[, flag = 1])
    [optional] Changes how the binary data is converted :
    SB_ANSI(1) = binary data is ANSI(default)
        SB_UTF16LE(2) = binary data is UTF16 Little Endian
        SB_UTF16BE(3) = binary data is UTF16 Big Endian
        SB_UTF8(4) = binary data is UTF8
    */

    //TmpName = BinaryToString(Dec(data, 2));
    result.AttributeString += ":" + TmpName;
    return  TmpName;
}

std::string _DoFixup(std::string record, int64_t offset)
{
    auto UpdSeqArrOffset = Dec(_SwapEndian(StringMid(record, 11, 4)));
    auto UpdSeqArrSize = Dec(_SwapEndian(StringMid(record, 15, 4)));
    auto UpdSeqArr = StringMid(record, 3 + (UpdSeqArrOffset * 2), UpdSeqArrSize * 2 * 2);
    auto UpdSeqArrPart0 = StringMid(UpdSeqArr, 1, 4);
    auto UpdSeqArrPart1 = StringMid(UpdSeqArr, 5, 4);
    auto UpdSeqArrPart2 = StringMid(UpdSeqArr, 9, 4);
    auto UpdSeqArrPart3 = StringMid(UpdSeqArr, 13, 4);
    auto UpdSeqArrPart4 = StringMid(UpdSeqArr, 17, 4);
    auto UpdSeqArrPart5 = StringMid(UpdSeqArr, 21, 4);
    auto UpdSeqArrPart6 = StringMid(UpdSeqArr, 25, 4);
    auto UpdSeqArrPart7 = StringMid(UpdSeqArr, 29, 4);
    auto UpdSeqArrPart8 = StringMid(UpdSeqArr, 33, 4);
    auto RecordEnd1 = StringMid(record, 1023, 4);
    auto RecordEnd2 = StringMid(record, 2047, 4);
    auto RecordEnd3 = StringMid(record, 3071, 4);
    auto RecordEnd4 = StringMid(record, 4095, 4);
    auto RecordEnd5 = StringMid(record, 5119, 4);
    auto RecordEnd6 = StringMid(record, 6143, 4);
    auto RecordEnd7 = StringMid(record, 7167, 4);
    auto RecordEnd8 = StringMid(record, 8191, 4);
    if (UpdSeqArrPart0 != RecordEnd1 || UpdSeqArrPart0 != RecordEnd2 || UpdSeqArrPart0 != RecordEnd3 || UpdSeqArrPart0 != RecordEnd4 || UpdSeqArrPart0 != RecordEnd5 || UpdSeqArrPart0 != RecordEnd6 || UpdSeqArrPart0 != RecordEnd7 || UpdSeqArrPart0 != RecordEnd8) {
        /*If then*/
        _DumpOutput("Error: Fixup failed at: 0x" + Hex(offset));
        return  "";
    }/*End of If*/
    auto newrecord = StringMid(record, 1, 1022) + UpdSeqArrPart1 + StringMid(record, 1027, 1020) + UpdSeqArrPart2 + StringMid(record, 2051, 1020) + UpdSeqArrPart3 + StringMid(record, 3075, 1020) + UpdSeqArrPart4 + StringMid(record, 4099, 1020) + UpdSeqArrPart5 + StringMid(record, 5123, 1020) + UpdSeqArrPart6 + StringMid(record, 6147, 1020) + UpdSeqArrPart7 + StringMid(record, 7171, 1020) + UpdSeqArrPart8;

    // 这段代码能将原文中的0x21F8位置的 30 00 00 00 08 01 c0 e5 修复成 30 00 00 00 08 01 04 00
    //assert(newrecord == record);
    return newrecord;
} //Comment:;

int64_t _Decode_SetIndexEntryVcn(std::string data)
{
    const auto VCN = _SwapEndian(StringMid(data, 1, 16));
    TextInformation += ";VCN=" + VCN;
    SetError(0);
    return 0;
}

int64_t _Decode_BitsInNonresidentBitMap2(std::string data)
{
    const std::string BitMapOffset = std::to_string(Dec(_SwapEndian(StringMid(data, 1, 8))));
    const std::string NumberOfBits = std::to_string(Dec(_SwapEndian(StringMid(data, 9, 8))));
    TextInformation += ";BitMapOffset=" + BitMapOffset + ";NumberOfBits=" + NumberOfBits;

    SetError(0);
    return 0;
}

int64_t FILETIME2Int(FILETIME fileTime)
{
    return *(int64_t*)(&fileTime);
    ULONGLONG integerTime = (static_cast<ULONGLONG>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime;
    return integerTime;
}

FILETIME _WinTime_UTCFileTimeToLocalFileTime(int64_t iUTCFileTime)
{
    if (iUTCFileTime < 0) {/*If Then in one Line*/
        SetError(-1);
        return  {};
    }
    FILETIME result = { 0 };
    FILETIME  filetime = {
        DWORD(iUTCFileTime & 0xffffffff),
        DWORD(iUTCFileTime >> 32),
    };
    FileTimeToLocalFileTime(&filetime, &result);
    return result;
}

//Comment: start: by Ascend4nt -----------------------------;
int64_t _WinTime_GetUTCToLocalFileTimeDelta()
{
    auto iUTCFileTime = 864000000000u;		 //Comment: exactly 24 hours from the origin (although 12 hours would be more appropriate (max variance = 12));
    auto iLocalFileTime = _WinTime_UTCFileTimeToLocalFileTime(iUTCFileTime);
    if (::GetLastError()) {/*If Then in one Line*/
        return 0;
    }
    return FILETIME2Int(iLocalFileTime) - iUTCFileTime;
    //return *(uint64_t*)(&iLocalFileTime) - iUTCFileTime;
    //Comment: /36000000000 = # hours delta (effectively giving the offset in hours from UTC/GMT);
}

std::string _WinTime_FormatTime(int64_t intYear, int64_t  iMonth, int64_t iDay, int64_t iHour, int64_t iMin, int64_t iSec, int64_t iMilSec, int64_t iDayOfWeek, int64_t iFormat /*= 4*/, int64_t iPrecision /*= 0*/, bool bAMPMConversion /*= false*/)
{
    auto iYear = std::to_string(intYear);
    static std::string _WT_aMonths[12] = { "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December" };
    static std::string _WT_aDays[7] = { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };

    if (!iFormat || iMonth < 1 || iMonth>12 || iDayOfWeek > 6) {/*If Then in one Line*/
        SetError(1);
        return  {};
    }
    //Comment: Pad MM,DD,HH,MM,SS,MSMSMSMS as necessary;
    auto sMM = StringRight("0" + std::to_string(iMonth), 2);
    auto sDD = StringRight("0" + std::to_string(iDay), 2);
    auto sMin = StringRight("0" + std::to_string(iMin), 2);
    //Comment: sYY = iYear	; (no padding);
    //Comment:	[technically Year can be 1-x chars - but this is generally used for 4-digit years. && SystemTime only goes up to 30827/30828];
    std::string sHH, sSS, sMS, sAMPM;

    //Comment: 'Extra precision 1': +SS (Seconds);
    if (iPrecision) {/*If then*/
        sSS = StringRight("0" + std::to_string(iSec), 2);
        //Comment: 'Extra precision 2': +MSMSMSMS (Milliseconds);
        if (iPrecision > 1) {/*If then*/
            //Comment:			sMS=StringRight("000" + iMilSec,4);
            sMS = StringRight("000" + std::to_string(iMilSec), 3); //Comment:Fixed an erronous 0 in front of the milliseconds;
        }
        else {/*Else*/
            sMS = "";
        }/*End of If*/
    }
    else {/*Else*/
        sSS = "";
        sMS = "";
    }/*End of If*/
    if (bAMPMConversion) {/*If then*/
        if (iHour > 11) {/*If then*/
            sAMPM = " PM";
            //Comment: 12 PM will cause 12-12 to equal 0, so avoid the calculation:;
            if (iHour == 12) {/*If then*/
                sHH = "12";
            }
            else {/*Else*/
                sHH = StringRight("0" + std::to_string(iHour - 12), 2);
            }/*End of If*/
        }
        else {/*Else*/
            sAMPM = " AM";
            if (iHour) {/*If then*/
                sHH = StringRight("0" + std::to_string(iHour), 2);
            }
            else {/*Else*/
                //Comment: 00 military = 12 AM;
                sHH = "12";
            }/*End of If*/
        }/*End of If*/
    }
    else {/*Else*/
        sAMPM = "";
        sHH = StringRight("0" + std::to_string(iHour), 2);
    }/*End of If*/

    std::string sDateTimeStr;
    std::string aReturnArray[3];

    //Comment:  return  an array? [formatted string + "Month" + "DayOfWeek"];
    if (iFormat & 0x10) {/*If then*/
        aReturnArray[1] = _WT_aMonths[iMonth - 1];
        if (iDayOfWeek >= 0) {/*If then*/
            aReturnArray[2] = _WT_aDays[iDayOfWeek];
        }
        else {/*Else*/
            aReturnArray[2] = "";
        }/*End of If*/
         //Comment: Strip the "array" bit off (array[1] will now indicate if an array is to be returned);
        iFormat = iFormat & 0xF;
    }
    else {/*Else*/
        //Comment: Signal to below that the array isn't to be returned;
        aReturnArray[1] = "";
    }/*End of If*/

     //Comment: Prefix with "DayOfWeek "?;
    if ((iFormat & 8)) {/*If then*/
        if (iDayOfWeek < 0) {/*If Then in one Line*/
            SetError(1);
            return {};
        }
        sDateTimeStr = _WT_aDays[iDayOfWeek] + ", ";
        //Comment: Strip the "DayOfWeek" bit off;
        iFormat = (iFormat & 0x7);
    }
    else {/*Else*/
        sDateTimeStr = "";
    }/*End of If*/

    if (iFormat < 2) {/*If then*/
        //Comment: Basic String format: YYYYMMDDHHMM[SS[MSMSMSMS[ AM/PM]]];
        sDateTimeStr += std::to_string(iYear) + sMM + sDD + sHH + sMin + sSS + sMS + sAMPM;
    }
    else {/*Else*/
        //Comment: one of 4 formats which ends with " HH:MM[:SS[:MSMSMSMS[ AM/PM]]]";
        switch (iFormat) {
            //Comment: /, : Format - MM/DD/YYYY;
        case 2: { /*Case替换*/
            sDateTimeStr += (sMM + "/" + sDD + "/");
            break;
            //Comment: /, : alt. Format - DD/MM/YYYY;
        }
        case 3: { /*Case替换*/
            sDateTimeStr += (sDD + "/" + sMM + ")");
            //Comment: "Month DD, YYYY" format;
            break;
        }
        case 4: /*Case替换*/
            sDateTimeStr += (_WT_aMonths[iMonth - 1] + " " + sDD + ", ");
            //Comment: "DD Month YYYY" format;
            break;
        case 5:
            sDateTimeStr += (sDD + " " + _WT_aMonths[iMonth - 1] + " "); /*Case替换*/
            break;
        case 6: { /*Case替换*/
            sDateTimeStr += (iYear + "-" + sMM + "-" + sDD);
            iYear = "";
            break;
        }
        default: { /*Case Else替换*/
            //return  SetError(1, 0, "");
            SetError(1);
            return {};
        }
        }
        sDateTimeStr += iYear + " " + sHH + ":" + sMin;
        if (iPrecision) {/*If then*/
            sDateTimeStr += ":" + sSS;
            //Comment:			If iPrecision>1 Then sDateTimeStr+=":" + sMS;
            if (iPrecision > 1) {/*If Then in one Line*/
                sDateTimeStr += PrecisionSeparator + sMS;
            }//EndIf;
            sDateTimeStr += sAMPM;
        }/*End of If*/
    }
    //if (aReturnArray[1] != "") {/*If then*/
    //    aReturnArray[0] = sDateTimeStr;
    //    return  aReturnArray;
    //}/*End of If*/
    return  sDateTimeStr;
}

FILETIME Int2FILETIME(int64_t ts)
{
    FILETIME result;
    result.dwLowDateTime = (DWORD)(ts & 0xffffffff);
    result.dwHighDateTime = (DWORD)(ts >> 32);
    return result;
}

std::string _WinTime_UTCFileTimeFormat(int64_t iUTCFileTime, int64_t iFormat, int64_t iPrecision, bool bAMPMConversion)
{
    //Comment:~ 	If iUTCFileTime<0 Then  return  SetError(1,0,"")	; checked in below call
    //Comment: First convert file time (UTC-based file time) to 'local file time';
    auto iLocalFileTime = FILETIME2Int(_WinTime_UTCFileTimeToLocalFileTime(iUTCFileTime));
    if (::GetLastError()) {/*If Then in one Line*/
        //return  SetError(::GetLastError(), @extended, "");
        SetError(1);
        return {};
    }	 //Comment: Rare occassion: a filetime near the origin (January 1, 1601!!) is used,;
         //Comment:	causing a negative result (for some timezones).  return  as invalid param.;
    if (iLocalFileTime < 0) {/*If Then in one Line*/
        SetError(1);
        return {};
    }
    //Comment: Then convert file time to a system time array + format + return it;
    auto vReturn = _WinTime_LocalFileTimeFormat(iLocalFileTime, iFormat, iPrecision, bAMPMConversion);
    return vReturn;
}

std::string  _WinTime_LocalFileTimeFormat(int64_t iLocalFileTime, int64_t iFormat, int64_t iPrecision, bool bAMPMConversion)
{
    //Comment:~ 	If iLocalFileTime<0 Then  return  SetError(1,0,"")	; checked in below call
    //Comment: Convert file time to a system time array + return result;
    auto aSysTime = _WinTime_LocalFileTimeToSystemTime(Int2FILETIME(iLocalFileTime));
    if (::GetLastError() != 0) {/*If Then in one Line*/
        return {};
    }
    //Comment:  return  only the SystemTime array?;
    if (iFormat == 0) {/*If Then in one Line*/
        assert(false);
        // 未实现
    }

    return _WinTime_FormatTime(aSysTime.wYear, aSysTime.wMonth, aSysTime.wDay, aSysTime.wHour, aSysTime.wMinute, aSysTime.wSecond, aSysTime.wMilliseconds, aSysTime.wDayOfWeek, iFormat, iPrecision, bAMPMConversion);
}

SYSTEMTIME _WinTime_LocalFileTimeToSystemTime(FILETIME iLocalFileTime)
{
    //Comment: SYSTEMTIME structure [Year,Month,DayOfWeek,Day,Hour,Min,Sec,Milliseconds];
    SYSTEMTIME stSysTime;
    if (!FileTimeToSystemTime(&iLocalFileTime, &stSysTime))
    {
        return {};
    }
    return  stSysTime;
}

FILETIME _WinTime_UTCFileTimeToLocalFileTime(FILETIME* iUTCFileTime)
{
    FILETIME local;
    FileTimeToLocalFileTime(iUTCFileTime, &local);
    return local;
}
//Comment:;

int64_t _Decode_UpdateFileName(std::string attribute, bool IsRedo)
{
    //int64_t SI_CTime_tmp, SI_ATime_tmp, SI_MTime_tmp, SI_RTime_tmp;
    std::string SI_CTime, SI_ATime, SI_MTime, SI_RTime;

    auto SI_CTimeStr = StringMid(attribute, 1, 16);
    SI_CTime = _SwapEndian(SI_CTimeStr);
    auto SI_CTime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(SI_CTime));

    SI_CTime = _WinTime_UTCFileTimeFormat(Dec(SI_CTime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
    if (::GetLastError()) {/*If then*/
        SI_CTime = option.TimestampErrorVal;
    }
    else if (TimestampPrecision == 2) {/*Else If then*/

        SI_CTime_Core = StringMid(SI_CTime, 1, StringLen(SI_CTime) - 4);
        SI_CTime_Precision = StringRight(SI_CTime, 3);
    }
    else  if (TimestampPrecision == 3) {/*Else If then*/

        SI_CTime = SI_CTime + PrecisionSeparator2 + StringRight(std::to_string(FILETIME2Int(SI_CTime_tmp)), 4);
        SI_CTime_Core = StringMid(SI_CTime, 1, StringLen(SI_CTime) - 9);
        SI_CTime_Precision = StringRight(SI_CTime, 8);
    }
    else {/*Else*/
        SI_CTime_Core = SI_CTime;
    }/*End of If*/

     //Comment:;
    SI_ATime = StringMid(attribute, 17, 16);
    SI_ATime = _SwapEndian(SI_ATime);
    auto SI_ATime_tmp = FILETIME2Int(_WinTime_UTCFileTimeToLocalFileTime(Dec(SI_ATime)));

    SI_ATime = _WinTime_UTCFileTimeFormat(Dec(SI_ATime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
    if (::GetLastError()) {/*If then*/
        SI_ATime = option.TimestampErrorVal;
    }
    else if (TimestampPrecision == 2) {/*Else If then*/

        SI_ATime_Core = StringMid(SI_ATime, 1, StringLen(SI_ATime) - 4);
        SI_ATime_Precision = StringRight(SI_ATime, 3);
    }
    else if (TimestampPrecision == 3) {/*Else If then*/

        SI_ATime = SI_ATime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(SI_ATime_tmp), 4));
        SI_ATime_Core = StringMid(SI_ATime, 1, StringLen(SI_ATime) - 9);
        SI_ATime_Precision = StringRight(SI_ATime, 8);
    }
    else {/*Else*/
        SI_ATime_Core = SI_ATime;
    }/*End of If*/
     //Comment:;
    SI_MTime = StringMid(attribute, 33, 16);
    SI_MTime = _SwapEndian(SI_MTime);
    auto SI_MTime_tmp = FILETIME2Int(_WinTime_UTCFileTimeToLocalFileTime(Dec(SI_MTime)));

    SI_MTime = _WinTime_UTCFileTimeFormat(Dec(SI_MTime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
    if (::GetLastError()) {/*If then*/
        SI_MTime = option.TimestampErrorVal;
    }
    else if (TimestampPrecision == 2) {/*Else If then*/

        SI_MTime_Core = StringMid(SI_MTime, 1, StringLen(SI_MTime) - 4);
        SI_MTime_Precision = StringRight(SI_MTime, 3);
    }
    else if (TimestampPrecision == 3) {/*Else If then*/

        SI_MTime = SI_MTime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(SI_MTime_tmp), 4));
        SI_MTime_Core = StringMid(SI_MTime, 1, StringLen(SI_MTime) - 9);
        SI_MTime_Precision = StringRight(SI_MTime, 8);
    }
    else {/*Else*/
        SI_MTime_Core = SI_MTime;
    }/*End of If*/
     //Comment:;
    SI_RTime = StringMid(attribute, 49, 16);
    SI_RTime = _SwapEndian(SI_RTime);
    auto SI_RTime_tmp = FILETIME2Int(_WinTime_UTCFileTimeToLocalFileTime(Dec(SI_RTime)));

    SI_RTime = _WinTime_UTCFileTimeFormat(Dec(SI_RTime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
    if (::GetLastError()) {/*If then*/
        SI_RTime = option.TimestampErrorVal;
    }
    else if (TimestampPrecision == 2) {/*Else If then*/

        SI_RTime_Core = StringMid(SI_RTime, 1, StringLen(SI_RTime) - 4);
        SI_RTime_Precision = StringRight(SI_RTime, 3);
    }
    else  if (TimestampPrecision == 3) {/*Else If then*/

        SI_RTime = SI_RTime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(SI_RTime_tmp), 4));
        SI_RTime_Core = StringMid(SI_RTime, 1, StringLen(SI_RTime) - 9);
        SI_RTime_Precision = StringRight(SI_RTime, 8);
    }
    else {/*Else*/
        SI_RTime_Core = SI_RTime;
    }/*End of If*/
     //Comment:;
    auto FN_AllocSizeStr = StringMid(attribute, 65, 16);
    result.FN_AllocSize = Dec(_SwapEndian(FN_AllocSizeStr), 2);
    auto FN_RealSizeStr = StringMid(attribute, 81, 16);
    result.FN_RealSize = Dec(_SwapEndian(FN_RealSizeStr), 2);

    auto FN_FlagsStr = StringMid(attribute, 97, 8);
    FN_FlagsStr = _SwapEndian(FN_FlagsStr);

    bool DoReparseTag, DoEaSize;
    if ((Dec(FN_FlagsStr) & 0x40000)) {/*If then*/
        DoReparseTag = 0;
        DoEaSize = 1;
    }
    else {/*Else*/
        DoReparseTag = 1;
        DoEaSize = 0;
    }/*End of If*/
    result.FN_Flags = _File_Attributes(Dec(FN_FlagsStr));
    /*AutoIt_Select ;
        */

    std::string EaSize, ReparseTag;
    if (false) {
    }
    else if (DoReparseTag) { /*Case替换*/
        EaSize = "";
        ReparseTag = StringMid(attribute, 105, 8);
        ReparseTag = _SwapEndian(ReparseTag);
        ReparseTag = _GetReparseType(ReparseTag);
    }
    else if (DoEaSize) { /*Case替换*/
        ReparseTag = "";
        EaSize = StringMid(attribute, 105, 8);
        EaSize = Dec(_SwapEndian(EaSize), 2);
    }/*AutoIt_EndSelect 	*/

    if (option.VerboseOn) {/*If then*/
        _DumpOutput("_Decode_UpdateFileName()");
        _DumpOutput("SI_CTime: " + std::to_string(SI_CTime));
        _DumpOutput("SI_ATime: " + std::to_string(SI_ATime));
        _DumpOutput("SI_MTime: " + std::to_string(SI_MTime));
        _DumpOutput("SI_RTime: " + std::to_string(SI_RTime));
        _DumpOutput("result.FN_AllocSize: " + result.FN_AllocSize);
        _DumpOutput("result.FN_RealSize: " + result.FN_RealSize);
        _DumpOutput("result.FN_Flags: " + result.FN_Flags);
        _DumpOutput("ReparseTag: " + std::to_string(ReparseTag));
        _DumpOutput("EaSize: " + std::to_string(EaSize));
        _DumpOutput("Isredo: " + std::string(IsRedo ? "1" : "0"));
    }/*End of If*/
    if (IsRedo) {/*If then*/
        //Comment:		If ReparseTag  !=  "ZERO" Then TextInformation += ";ReparseTag=" + ReparseTag;
        TextInformation += ";See LogFile_UpdateFileName_I30.csv";
    }/*End of If*/

    //TODO 这里替换原来写文件的功能
    //FileWrite(LogFileUpdateFileNameCsv, RecordOffset + de + this_lsn + de + SI_CTime + de + SI_ATime + de + SI_MTime + de + SI_RTime + de + result.FN_AllocSize + de + result.FN_RealSize + de + result.FN_Flags + de + ReparseTag + de + EaSize + de + IsRedo);
    SetError(0);
    return 0;
}

int64_t _UpdateFileNameArray(int64_t InputRef, int64_t InputRefSeqNo, std::string  InputName, int64_t InputLsn)
{
    InputRef = Int(InputRef);
    //Comment:	Local FoundInTable = _ArraySearch(result.FileNamesArray,InputRef,0,0,0,0,0,0);
    //int64_t FoundInTable = _ArraySearch(result.FileNamesArray, InputRef, 0, GlobalFileNamesCounter, 0, 0, 1, 0);
    auto it = result.FileNamesArray.find(InputRef);
    int64_t FoundInTable = it != result.FileNamesArray.end() ? InputRef : 0;
    if (option.VerboseOn) {/*If then*/
        _DumpOutput("_UpdateFileNameArray(): ");
        _DumpOutput("InputRef: " + std::to_string(InputRef));
        _DumpOutput("InputRefSeqNo: " + std::to_string(InputRefSeqNo));
        _DumpOutput("InputName: " + std::to_string(InputName));
        _DumpOutput("InputLsn: " + std::to_string(InputLsn));
        _DumpOutput("FoundInTable: " + std::to_string(FoundInTable));
        //Comment:		_DumpOutput("::GetLastError(): " & ::GetLastError() );
        //Comment:		_ArrayDisplay(result.FileNamesArray,"result.FileNamesArray");
    }/*End of If*/
    if (FoundInTable < 0) {/*If then*/
        // Add new entry;
        // ArrayEnd = UBound(result.FileNamesArray);
        // ReDim result.FileNamesArray[ArrayEnd + 1][3];

        result.FileNamesArray[InputRef] = InputName;
        result.FileNameLsnArray[InputRef] = InputLsn;

        //TODO FileWrite(LogFileFileNamesCsv, RecordOffset + de + InputLsn + de + InputRef + de + InputRefSeqNo + de + InputName);
    }
    else {/*Else*/
        // Update existing entry;
        if (result.FileNamesArray[FoundInTable] != InputName) {/*If then*/
            result.FileNamesArray[FoundInTable] = InputName;
            result.FileNameLsnArray[FoundInTable] = InputLsn;
            //TODO FileWrite(LogFileFileNamesCsv, RecordOffset + de + InputLsn + de + InputRef + de + InputRefSeqNo + de + InputName);
        }/*End of If*/
    }/*End of If*/
    return  FoundInTable;
} //Comment:;

int64_t _UpdateSingleOffsetOfAttribute(int64_t TestRef, int64_t offset, int64_t size, std::string TestString)
{
    std::string TestOffsetAttr = std::to_string(offset);
    std::string TestSize = std::to_string(size);
    int64_t RefIndex;
    std::string ConcatString;
    if (option.VerboseOn) {/*If then*/
        _DumpOutput("_UpdateSingleOffsetOfAttribute()");
        _DumpOutput("TestRef: " + std::to_string(TestRef));
        _DumpOutput("TestOffsetAttr: " + std::to_string(TestOffsetAttr));
        _DumpOutput("TestSize: " + std::to_string(TestSize));
        _DumpOutput("TestString: " + std::to_string(TestString));
    }/*End of If*/

    //RefIndex = _ArraySearch(result.AttrArray, TestRef, 0, result.GlobalAttrCounter, 0, 0, 1, 0);
    auto it = result.AttrArray.find(TestRef);
    //if (RefIndex > -1) {/*If then*/
    if (it != result.AttrArray.end()) {
        RefIndex = TestRef;//Array -> Map 索引映射
        if (option.VerboseOn)
        {
            _DumpOutput("Ref already exist in array:" + result.AttrArray[RefIndex][1]);
        }
        // 原split后,坐标0为数组数量
        auto AttrArraySplit = utils::strings::split(result.AttrArray[RefIndex][1], ',');
        auto HighestOffset = 0;
        for (auto i = 0; i < AttrArraySplit.size(); i++) {/*TODO For*/
            if (AttrArraySplit[i] == "") {/*If Then in one Line*/
                continue; //Comment:;
            }
            auto TestOffset2 = StringInStr(AttrArraySplit[i], "?");
            auto FoundAttr = StringMid(AttrArraySplit[i], 1, TestOffset2 - 1);
            auto FoundOffset = StringMid(AttrArraySplit[i], TestOffset2 + 1);
            if (Int(FoundOffset) > HighestOffset) {/*If Then in one Line*/
                HighestOffset = Int(FoundOffset);
            }

            if (option.VerboseOn)
            {
                _DumpOutput("AttrArraySplit[i]: " + AttrArraySplit[i]);
                _DumpOutput("TestOffset2: " + std::to_string(TestOffset2));
                _DumpOutput("FoundAttr: " + std::to_string(FoundAttr));
                _DumpOutput("FoundOffset: " + std::to_string(FoundOffset));
            }/*End of If*/

            auto TestOffset = StringInStr(AttrArraySplit[i], TestOffsetAttr);
            if (TestOffset) {/*If then*/
                //Comment:				ConsoleWrite("Found offset: " + TestOffset );
            }/*End of If*/
            if (!std::all_of(FoundOffset.begin(), FoundOffset.end(), std::isdigit)) {/*If Then in one Line*/
                _DumpOutput("Not number: " + FoundOffset + " at lsn " + std::to_string(this_lsn));
            }

            if (Int(TestOffsetAttr) > Int(FoundOffset)) {/*If Then in one Line*/
                continue; //Comment:;
            }

            if (AttrArraySplit[i] == "") {/*If Then in one Line*/
                continue; //Comment:;
            }

            if (Int(TestOffsetAttr) == Int(FoundOffset)) {
                AttrArraySplit[i] = TestString + "?" + TestOffsetAttr;
                //Comment:check=1;
            }
            else if (Int(TestOffsetAttr) < Int(FoundOffset)) {/*Else If then*/
                AttrArraySplit[i] = FoundAttr + "?" + std::to_string(Int(FoundOffset)) + std::to_string(Int(TestSize));
                _DumpOutput("Modified entry: " + FoundAttr + "?" + std::to_string(Int(FoundOffset)) + std::to_string(Int(TestSize)));
                if (Int(FoundOffset) - Int(TestSize) < 0) {/*If Then in one Line*/
                    _DumpOutput("Error in _UpdateSingleOffsetOfAttribute() with " + std::to_string(this_lsn));
                }				 //Comment:check=1;
            }/*End of If*/
        }/*End of For*/

        if (Int(TestOffsetAttr) > HighestOffset) {/*If then*/
            //auto NewLimit = AttrArraySplit.size();
            //AttrArraySplit.resize(NewLimit + 1);
            AttrArraySplit.push_back(TestString + "?" + TestOffsetAttr);
        }/*End of If*/

        for (auto i = 1; i < Ubound(AttrArraySplit); i++) {/*TODO For*/;
        if (AttrArraySplit[i] == "") {/*If Then in one Line*/
            continue; //Comment:;
            ConcatString += (AttrArraySplit[i] + ",");
        }
        }/*End of For*/
        result.AttrArray[RefIndex][1] = ConcatString;
    }
    else {/*Else*/
        //Comment:		_DumpOutput("Adding new row for new ref" );
        result.AttrArray[TestRef][0] = std::to_string(TestRef);
        result.AttrArray[TestRef][1] = TestString + "?" + TestOffsetAttr + ",";
        result.GlobalAttrCounter += 1;
    }/*End of If*/
    return 0;
}


int64_t _Decode_IndexEntry(std::string Entry, std::string AttrType, bool IsRedo)
{
    int64_t NewLocalAttributeOffset = 1;
    int64_t SubNodeVCN, tmp0 = 0, tmp1 = 0, tmp2 = 0, tmp3 = 0, EntryCounter = 1; // Comment:,DecodeOk=False;
    int64_t SubNodeVCNLength = 0;
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("_Decode_IndexEntry():");
    } /*End of If*/

    auto MFTReferenceStr = StringMid(Entry, NewLocalAttributeOffset, 12);
    MFTReferenceStr = _SwapEndian(MFTReferenceStr);
    auto MFTReference = Dec(MFTReferenceStr, 2);
    if (MFTReference == 0)
    { /*If then*/
        _DumpOutput("Error MFTReference: " + std::to_string(MFTReference));
        SetError(1);
        return {};
    } /*End of If*/

    auto MFTReferenceSeqNoStr = StringMid(Entry, NewLocalAttributeOffset + 12, 4);
    auto MFTReferenceSeqNo = Dec(_SwapEndian(MFTReferenceSeqNoStr), 2);
    if (MFTReferenceSeqNo == 0)
    { /*If then*/
        _DumpOutput("Error MFTReferenceSeqNo: " + std::to_string(MFTReferenceSeqNo));
        SetError(1);
        return {};
    } /*End of If*/

    auto IndexEntryLengthStr = StringMid(Entry, NewLocalAttributeOffset + 16, 4);
    auto IndexEntryLength = Dec(_SwapEndian(IndexEntryLengthStr), 2);
    auto OffsetToFileNameStr = StringMid(Entry, NewLocalAttributeOffset + 20, 4);
    auto OffsetToFileName = Dec(_SwapEndian(OffsetToFileNameStr), 2);
    auto IndexFlags = StringMid(Entry, NewLocalAttributeOffset + 24, 4);
    // Comment:	Padding = StringMid(Entry,NewLocalAttributeOffset+28,4);
    auto MFTReferenceOfParentStr = StringMid(Entry, NewLocalAttributeOffset + 32, 12);
    MFTReferenceOfParentStr = _SwapEndian(MFTReferenceOfParentStr);
    auto MFTReferenceOfParent = Dec(MFTReferenceOfParentStr, 2);
    if (MFTReferenceOfParent < 5 || (MFTReferenceOfParent > 5 && MFTReferenceOfParent < 11))
    { /*If then*/
        _DumpOutput("Error MFTReferenceOfParent: " + std::to_string(MFTReferenceOfParent));
        SetError(1);
        return {};
    } /*End of If*/

    auto MFTReferenceOfParentSeqNoStr = StringMid(Entry, NewLocalAttributeOffset + 44, 4);
    auto MFTReferenceOfParentSeqNo = Dec(_SwapEndian(MFTReferenceOfParentSeqNoStr), 2);
    if (MFTReferenceOfParentSeqNo == 0)
    { /*If then*/
        _DumpOutput("Error MFTReferenceOfParentSeqNo: " + std::to_string(MFTReferenceOfParentSeqNo));
        SetError(1);
        return {};
    } /*End of If*/
      // Comment:;
    auto Indx_CTimeStr = StringMid(Entry, NewLocalAttributeOffset + 48, 16);
    auto Indx_CTime = _SwapEndian(Indx_CTimeStr);

    auto Indx_CTime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(Indx_CTime, 2));
    Indx_CTime = _WinTime_UTCFileTimeFormat(Dec(Indx_CTime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
    if ((::GetLastError() > 0))
    { /*If then*/
        Indx_CTime = option.TimestampErrorVal;
    }
    else if (TimestampPrecision == 2)
    { /*Else If then*/

        // Comment:Indx_CTime_Core = StringMid(Indx_CTime,1,StringLen(Indx_CTime)-4);
        // Comment:Indx_CTime_Precision = StringRight(Indx_CTime,3);
    }
    else if (TimestampPrecision == 3)
    { /*Else If then*/

        Indx_CTime = Indx_CTime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(Indx_CTime_tmp)), 4));
        // Comment:Indx_CTime_Core = StringMid(Indx_CTime,1,StringLen(Indx_CTime)-9);
        // Comment:Indx_CTime_Precision = StringRight(Indx_CTime,8);
    }
    else
    { /*Else*/
        // Comment:Indx_CTime_Core = Indx_CTime;
    } /*End of If*/
    if (Indx_CTime == option.TimestampErrorVal)
    { /*If then*/
        _DumpOutput("Error Indx_CTime: " + std::to_string(Indx_CTime));
        SetError(1);
        return {};
    } /*End of If*/
      // Comment:;
    auto Indx_ATime = StringMid(Entry, NewLocalAttributeOffset + 64, 16);
    Indx_ATime = _SwapEndian(Indx_ATime);
    auto Indx_ATime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(Indx_ATime));
    Indx_ATime = _WinTime_UTCFileTimeFormat(Dec(Indx_ATime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
    if ((::GetLastError() > 0))
    { /*If then*/
        Indx_ATime = option.TimestampErrorVal;
    }
    else if (TimestampPrecision == 2)
    { /*Else If then*/

        // Comment:Indx_ATime_Core = StringMid(Indx_ATime,1,StringLen(Indx_ATime)-4);
        // Comment:Indx_ATime_Precision = StringRight(Indx_ATime,3);
    }
    else if (TimestampPrecision == 3)
    { /*Else If then*/

        Indx_ATime = Indx_ATime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(Indx_ATime_tmp)), 4));
        // Comment:Indx_ATime_Core = StringMid(Indx_ATime,1,StringLen(Indx_ATime)-9);
        // Comment:Indx_ATime_Precision = StringRight(Indx_ATime,8);
    }
    else
    { /*Else*/
        // Comment:Indx_ATime_Core = Indx_ATime;
    } /*End of If*/
    if (Indx_ATime == option.TimestampErrorVal)
    { /*If then*/
        _DumpOutput("Error Indx_ATime: " + std::to_string(Indx_ATime));
        SetError(1);
        return {};
    } /*End of If*/
      // Comment:;
    auto Indx_MTime = StringMid(Entry, NewLocalAttributeOffset + 80, 16);
    Indx_MTime = _SwapEndian(Indx_MTime);
    auto Indx_MTime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(Indx_MTime, 2));
    Indx_MTime = _WinTime_UTCFileTimeFormat(Dec(Indx_MTime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
    if ((::GetLastError() > 0))
    { /*If then*/
        Indx_MTime = option.TimestampErrorVal;
    }
    else if (TimestampPrecision == 2)
    { /*Else If then*/

        // Comment:Indx_MTime_Core = StringMid(Indx_MTime,1,StringLen(Indx_MTime)-4);
        // Comment:Indx_MTime_Precision = StringRight(Indx_MTime,3);
    }
    else if (TimestampPrecision == 3)
    { /*Else If then*/

        Indx_MTime = Indx_MTime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(Indx_MTime_tmp)), 4));
        // Comment:Indx_MTime_Core = StringMid(Indx_MTime,1,StringLen(Indx_MTime)-9);
        // Comment:Indx_MTime_Precision = StringRight(Indx_MTime,8);
    }
    else
    { /*Else*/
        // Comment:Indx_MTime_Core = Indx_MTime;
    } /*End of If*/
    if (Indx_MTime == option.TimestampErrorVal)
    { /*If then*/
        _DumpOutput("Error Indx_MTime: " + std::to_string(Indx_MTime));
        SetError(1);
        return {};
    } /*End of If*/
      // Comment:;
    auto Indx_RTime = StringMid(Entry, NewLocalAttributeOffset + 96, 16);
    Indx_RTime = _SwapEndian(Indx_RTime);
    auto Indx_RTime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(Indx_RTime, 2));
    Indx_RTime = _WinTime_UTCFileTimeFormat(Dec(Indx_RTime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
    if ((::GetLastError() > 0))
    { /*If then*/
        Indx_RTime = option.TimestampErrorVal;
    }
    else if (TimestampPrecision == 2)
    { /*Else If then*/

        // Comment:Indx_RTime_Core = StringMid(Indx_RTime,1,StringLen(Indx_RTime)-4);
        // Comment:Indx_RTime_Precision = StringRight(Indx_RTime,3);
    }
    else if (TimestampPrecision == 3)
    { /*Else If then*/

        Indx_RTime = Indx_RTime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(Indx_RTime_tmp)), 4));
        // Comment:Indx_RTime_Core = StringMid(Indx_RTime,1,StringLen(Indx_RTime)-9);
        // Comment:Indx_RTime_Precision = StringRight(Indx_RTime,8);
    }
    else
    { /*Else*/
        // Comment:Indx_RTime_Core = Indx_RTime;
    } /*End of If*/
    if (Indx_RTime == option.TimestampErrorVal)
    { /*If then*/
        _DumpOutput("Error Indx_RTime: " + std::to_string(Indx_RTime));
        SetError(1);
        return {};
    } /*End of If*/
      // Comment:;
    auto Indx_AllocSizeStr = StringMid(Entry, NewLocalAttributeOffset + 112, 16);
    auto Indx_AllocSize = Dec(_SwapEndian(Indx_AllocSizeStr), 2);
    auto Indx_RealSizeStr = StringMid(Entry, NewLocalAttributeOffset + 128, 16);
    auto Indx_RealSize = Dec(_SwapEndian(Indx_RealSizeStr), 2);

    auto Indx_File_FlagsStr = StringMid(Entry, NewLocalAttributeOffset + 144, 8);
    auto Indx_File_Flags = _SwapEndian(Indx_File_FlagsStr);
    bool DoReparseTag, DoEaSize;
    if ((Dec(Indx_File_Flags) & 0x40000))
    { /*If then*/
        DoReparseTag = 0;
        DoEaSize = 1;
    }
    else
    { /*Else*/
        DoReparseTag = 1;
        DoEaSize = 0;
    } /*End of If*/
    Indx_File_Flags = _File_Attributes(Dec(Indx_File_Flags));
    /*AutoIt_Select ;
     */

    std::string Indx_ReparseTag, Indx_EaSize;
    if (false)
    {
    }
    else if (DoReparseTag) { /*Case替换*/
        Indx_EaSize = "";

        Indx_ReparseTag = StringMid(Entry, NewLocalAttributeOffset + 152, 8);
        Indx_ReparseTag = _SwapEndian(Indx_ReparseTag);
        Indx_ReparseTag = _GetReparseType("0x" + Indx_ReparseTag);
    }
    else if (DoEaSize)
    { /*Case替换*/
        Indx_ReparseTag = "";
        Indx_EaSize = StringMid(Entry, NewLocalAttributeOffset + 152, 8);
        Indx_EaSize = Dec(_SwapEndian(Indx_EaSize), 2);
    } /*AutoIt_EndSelect 	*/

    auto Indx_NameLengthStr = StringMid(Entry, NewLocalAttributeOffset + 160, 2);
    auto Indx_NameLength = Dec(Indx_NameLengthStr);
    if (Indx_NameLength == 0)
    { /*If then*/
        _DumpOutput("Error Indx_NameLength: " + std::to_string(Indx_NameLength));
        SetError(1);
        return {};
    } /*End of If*/

    auto Indx_NameSpace = StringMid(Entry, NewLocalAttributeOffset + 162, 2);
    /*AutoIt_Select 	*/
    if (false)
    {
    }
    else if (Indx_NameSpace == "00")
    { /*Case替换*/
        Indx_NameSpace = "POSIX";
    }
    else if (Indx_NameSpace == "01")
    { /*Case替换*/
        Indx_NameSpace = "WIN32";
    }
    else if (Indx_NameSpace == "02")
    { /*Case替换*/
        Indx_NameSpace = "DOS";
    }
    else if (Indx_NameSpace == "03")
    { /*Case替换*/
        Indx_NameSpace = "DOS+WIN32";
    } /*AutoIt_EndSelect 	*/
    auto Indx_FileName = StringMid(Entry, NewLocalAttributeOffset + 164, Indx_NameLength * 4);
    if (StringLeft(Indx_FileName, 2) == "00")
    { /*If then*/
        _DumpOutput("Error Indx_FileName: " + std::to_string(Indx_FileName));
        SetError(1);
        return {};
    } /*End of If*/
    auto Indx_FileNameRaw = BinaryToString(Indx_FileName, 2);
    Indx_FileName = StringReplace(Indx_FileNameRaw, de, CharReplacement);
    auto FileNameModified = Indx_FileName == Indx_FileNameRaw;
    tmp1 = 164 + (Indx_NameLength * 2 * 2);

    // Comment: Calculate the length of the padding - 8 byte aligned;
    tmp3 = tmp1 % 16;

    //do
    //{ /*Do*/ // Comment: Calculate the length of the padding - 8 byte aligned;
    //    tmp2 = tmp1 / 16;
    //    if (!IsInt(tmp2))
    //    { /*If then*/
    //        tmp0 = 2;
    //        tmp1 += tmp0;
    //        tmp3 += tmp0;
    //    }                      /*End of If*/
    //} while (!(IsInt(tmp2))); // Comment: /*0*/

    auto PaddingLength = tmp3;
    // Comment:	Padding2 = StringMid(Entry,NewLocalAttributeOffset+164+(Indx_NameLength*2*2),PaddingLength);
    if (IndexFlags != "0000")
    { /*If then*/
        auto SubNodeVCNStr = StringMid(Entry, NewLocalAttributeOffset + 164 + (Indx_NameLength * 2 * 2) + PaddingLength, 16);
        SubNodeVCN = Dec(_SwapEndian(SubNodeVCNStr), 2);
        SubNodeVCNLength = 16;
    }
    else
    { /*Else*/
        SubNodeVCN = 0;
        SubNodeVCNLength = 0;
    } /*End of If*/
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("MFTReference==" + std::to_string(MFTReference));
        _DumpOutput("MFTReferenceSeqNo==" + std::to_string(MFTReferenceSeqNo));
        _DumpOutput("IndexEntryLength==" + std::to_string(IndexEntryLength));
        _DumpOutput("OffsetToFileName==" + std::to_string(OffsetToFileName));
        _DumpOutput("IndexFlags==" + std::to_string(IndexFlags));
        _DumpOutput("MFTReferenceOfParent==" + std::to_string(MFTReferenceOfParent));
        _DumpOutput("Indx_CTime==" + std::to_string(Indx_CTime));
        _DumpOutput("Indx_ATime==" + std::to_string(Indx_ATime));
        _DumpOutput("Indx_MTime==" + std::to_string(Indx_MTime));
        _DumpOutput("Indx_RTime==" + std::to_string(Indx_RTime));
        _DumpOutput("Indx_AllocSize==" + std::to_string(Indx_AllocSize));
        _DumpOutput("Indx_RealSize==" + std::to_string(Indx_RealSize));
        _DumpOutput("Indx_File_Flags==" + std::to_string(Indx_File_Flags));
        _DumpOutput("Indx_ReparseTag==" + std::to_string(Indx_ReparseTag));
        _DumpOutput("Indx_EaSize==" + std::to_string(Indx_EaSize));
        _DumpOutput("Indx_NameLength==" + std::to_string(Indx_NameLength));
        _DumpOutput("Indx_NameSpace==" + std::to_string(Indx_NameSpace));
        _DumpOutput("Indx_FileName==" + std::to_string(Indx_FileName));
        _DumpOutput("SubNodeVCN==" + std::to_string(SubNodeVCN));
        _DumpOutput("\r\n");
    } /*End of If*/

   // TODO FileWrite(LogFileIndxCsv, RecordOffset + de + this_lsn + de + EntryCounter + de + MFTReference + de + MFTReferenceSeqNo + de + IndexFlags + de + MFTReferenceOfParent + de + MFTReferenceOfParentSeqNo + de + Indx_CTime + de + Indx_ATime + de + Indx_MTime + de + Indx_RTime + de + Indx_AllocSize + de + Indx_RealSize + de + Indx_File_Flags + de + Indx_ReparseTag + de + Indx_EaSize + de + Indx_FileName + de + FileNameModified + de + Indx_NameSpace + de + SubNodeVCN + de + IsRedo);
    if (!FromRcrdSlack)
    { /*If then*/
        if (Indx_NameSpace != "DOS")
        { /*If Then in one Line*/
            _UpdateFileNameArray(MFTReference, MFTReferenceSeqNo, Indx_FileName, this_lsn);
        }
    }

    RealMftRef = MFTReferenceOfParent;
    result.PredictedRefNumber = MFTReference;
    KeptRef = MFTReference;
    result.FN_Name = Indx_FileName;
    result.FN_NameType = Indx_NameSpace;
    // FIXME SI_系列变量的处理
    auto SI_CTime = Indx_CTime;
    auto SI_ATime = Indx_ATime;
    auto SI_MTime = Indx_MTime;
    auto SI_RTime = Indx_RTime;
    result.FN_AllocSize = Indx_AllocSize;
    result.FN_RealSize = Indx_RealSize;
    result.FN_Flags = Indx_File_Flags;
    TextInformation += ";MftRef=" + std::to_string(MFTReference) + ";MftSeqNo=" + std::to_string(MFTReferenceSeqNo);
    if (AttrType == Operation_AddIndexEntryToRoot || AttrType == Operation_DeleteIndexEntryFromRoot)
    { /*If Then in one Line*/
        result.AttributeString = "$INDEX_ROOT";
    }
    if (AttrType == Operation_AddIndexEntryToAllocationBuffer || AttrType == Operation_DeleteIndexEntryFromAllocationBuffer)
    { /*If Then in one Line*/
        result.AttributeString = "$INDEX_ALLOCATION";
    }
    return true;
}

int64_t _DecodeIndxEntriesSII(std::string InputData, bool IsRedo)
{
    int64_t StartOffset = 1, Counter = 0;
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("_DecodeIndxEntriesSII() ");
    } /*End of If*/

    while (1)
    { /*TODO条件手动替换*/
        if (StartOffset >= InputData.length())
        {         /*If Then in one Line*/
            break; // Comment:;
        }
        Counter += 1;
        // Comment:CurrentDescriptor=Counter

        auto DataOffseSStr = StringMid(InputData, StartOffset, 4);
        auto DataOffset = Dec(_SwapEndian(DataOffseSStr));

        auto DataSizeStr = StringMid(InputData, StartOffset + 4, 4);
        auto DataSize = Dec(_SwapEndian(DataSizeStr));

        if (DataOffset == 0 || DataSize == 0)
        { /*If Then in one Line*/
            StartOffset += 16;
        }
        // Comment:Padding 4 bytes;
        auto IndexEntrySizeStr = StringMid(InputData, StartOffset + 16, 4);
        IndexEntrySizeStr = _SwapEndian(IndexEntrySizeStr);

        auto IndexKeySizeStr = StringMid(InputData, StartOffset + 20, 4);
        IndexKeySizeStr = _SwapEndian(IndexKeySizeStr);

        auto FlagsStr = StringMid(InputData, StartOffset + 24, 4);
        auto Flags = Dec(_SwapEndian(FlagsStr));

        // Comment:Padding 2 bytes;
        auto SecurityIdKeyStr = StringMid(InputData, StartOffset + 32, 8);
        SecurityIdKeyStr = _SwapEndian(SecurityIdKeyStr);
        auto SecurityIdKey = Dec(SecurityIdKeyStr, 2);

        auto SecurityDescriptorHashData = Dec(StringMid(InputData, StartOffset + 40, 8));
        // Comment:		auto SecurityDescriptorHashData = _SwapEndian(SecurityDescriptorHashData)

        auto SecurityIdDataStr = StringMid(InputData, StartOffset + 48, 8);
        SecurityIdDataStr = _SwapEndian(SecurityIdDataStr);
        auto SecurityIdData = Dec(SecurityIdDataStr, 2);

        auto OffsetInSDSStr = StringMid(InputData, StartOffset + 56, 16);
        auto OffsetInSDS = Dec(_SwapEndian(OffsetInSDSStr));

        auto SizeInSDSStr = StringMid(InputData, StartOffset + 72, 8);
        auto SizeInSDS = Dec(_SwapEndian(SizeInSDSStr));

        // TODO FileWrite(LogFileSecureSIICsv, RecordOffset + de + this_lsn + de + Flags + de + SecurityIdKey + de + SecurityDescriptorHashData + de + SecurityIdData + de + OffsetInSDS + de + SizeInSDS + de + IsRedo);
        if (option.VerboseOn)
        { /*If then*/
            _DumpOutput("\r\n");
            _DumpOutput("Entry: " + std::to_string(Counter));
            _DumpOutput("DataOffset: " + std::to_string(DataOffset));
            _DumpOutput("DataSize: " + std::to_string(DataSize));
            _DumpOutput("IndexEntrySize: " + std::to_string(IndexEntrySizeStr));
            _DumpOutput("IndexKeySize: " + std::to_string(IndexKeySizeStr));
            _DumpOutput("Flags: " + std::to_string(Flags));
            _DumpOutput("SecurityIdKey: " + std::to_string(SecurityIdKey));
            _DumpOutput("SecurityDescriptorHashData: " + std::to_string(SecurityDescriptorHashData));
            _DumpOutput("SecurityIdData: " + std::to_string(SecurityIdData));
            _DumpOutput("OffsetInSDS: " + std::to_string(OffsetInSDS));
            _DumpOutput("SizeInSDS: " + std::to_string(SizeInSDS));
        } /*End of If*/
        StartOffset += 80;
    } // End of while;

    SetError(0);
    return 0;
}

int64_t _DecodeIndxEntriesSDH(std::string InputData, bool IsRedo)
{
    int64_t StartOffset = 1, Counter = 0;
    int64_t InputDataSize = InputData.size() / 2;
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("_DecodeIndxEntriesSDH() ");
    } /*End of If*/

    while (1)
    { /*TODO条件手动替换*/
        if (StartOffset >= InputDataSize * 2)
        {         /*If Then in one Line*/
            break; // Comment:;
        }
        Counter += 1;
        // Comment:CurrentDescriptor=Counter

        auto DataOffsetStr = StringMid(InputData, StartOffset, 4);
        auto DataOffset = Dec(_SwapEndian(DataOffsetStr));

        auto DataSizeStr = StringMid(InputData, StartOffset + 4, 4);
        auto DataSize = Dec(_SwapEndian(DataSizeStr));

        if (DataOffset == 0 || DataSize == 0)
        { /*If Then in one Line*/
            StartOffset += 16;
        }
        // Comment:Padding 4 bytes;
        auto IndexEntrySizeStr = StringMid(InputData, StartOffset + 16, 4);
        auto IndexEntrySize = _SwapEndian(IndexEntrySizeStr);

        auto IndexKeySizeStr = StringMid(InputData, StartOffset + 20, 4);
        auto IndexKeySize = _SwapEndian(IndexKeySizeStr);

        auto FlagsStr = StringMid(InputData, StartOffset + 24, 4);
        auto Flags = Dec(_SwapEndian(FlagsStr));

        // Comment:Padding 2 bytes;
        // Comment:Start of SDH index entry;
        // Comment:	StartOffset = StartOffset+24;
        auto SecurityDescriptorHashKey = Dec(StringMid(InputData, StartOffset + 32, 8));
        // Comment:		auto SecurityDescriptorHashKey = _SwapEndian(SecurityDescriptorHashKey)

        auto SecurityIdKeyStr = StringMid(InputData, StartOffset + 40, 8);
        SecurityIdKeyStr = _SwapEndian(SecurityIdKeyStr);
        auto SecurityIdKey = Dec(SecurityIdKeyStr, 2);

        auto SecurityDescriptorHashData = Dec(StringMid(InputData, StartOffset + 48, 8));
        // Comment:		auto SecurityDescriptorHashData = _SwapEndian(SecurityDescriptorHashData)

        auto SecurityIdDataStr = StringMid(InputData, StartOffset + 56, 8);
        SecurityIdDataStr = _SwapEndian(SecurityIdDataStr);
        auto SecurityIdData = Dec(SecurityIdDataStr, 2);

        auto OffsetInSDSStr = StringMid(InputData, StartOffset + 64, 16);
        auto OffsetInSDS = Dec(_SwapEndian(OffsetInSDSStr));

        auto SizeInSDSStr = StringMid(InputData, StartOffset + 80, 8);
        auto SizeInSDS = Dec(_SwapEndian(SizeInSDSStr));

        auto EndPaddingStr = StringMid(InputData, StartOffset + 88, 8);
        if (EndPaddingStr != "49004900")
        { /*If then*/
            // Comment:			_DumpOutput("Wrong end padding (49004900): " + EndPadding );
            // Comment:			 return  SetError(1);
        } /*End of If*/

        // TODO FileWrite(LogFileSecureSDHCsv, RecordOffset + de + this_lsn + de + Flags + de + SecurityDescriptorHashKey + de + SecurityIdKey + de + SecurityDescriptorHashData + de + SecurityIdData + de + OffsetInSDS + de + SizeInSDS + de + IsRedo);
        if (option.VerboseOn)
        { /*If then*/
            _DumpOutput("\r\n");
            _DumpOutput("Entry: " + std::to_string(Counter));
            _DumpOutput("DataOffset: " + std::to_string(DataOffset));
            _DumpOutput("DataSize: " + std::to_string(DataSize));
            _DumpOutput("IndexEntrySize: " + std::to_string(IndexEntrySize));
            _DumpOutput("IndexKeySize: " + std::to_string(IndexKeySize));
            _DumpOutput("Flags: " + std::to_string(Flags));
            _DumpOutput("SecurityDescriptorHashKey: " + std::to_string(SecurityDescriptorHashKey));
            _DumpOutput("SecurityIdKey: " + std::to_string(SecurityIdKey));
            _DumpOutput("SecurityDescriptorHashData: " + std::to_string(SecurityDescriptorHashData));
            _DumpOutput("SecurityIdData: " + std::to_string(SecurityIdData));
            _DumpOutput("OffsetInSDS: " + std::to_string(OffsetInSDS));
            _DumpOutput("SizeInSDS: " + std::to_string(SizeInSDS));
        } /*End of If*/
        StartOffset += 96;
    } // End of while;
    SetError(0);
    return 0;
}


int64_t _Decode_Quota_O(std::string InputData, bool IsRedo)
{
    int64_t Counter = 1;
    auto StartOffset = 1;
    auto InputDataSize = StringLen(InputData);
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("_Decode_Quota_O():\r\n");
        _DumpOutputHex(InputData);
    } /*End of If*/

    do
    { /*Do*/
        auto DataOffsetStr = StringMid(InputData, StartOffset, 4);
        auto DataOffset = Dec(_SwapEndian(DataOffsetStr), 2);

        auto DataSizeStr = StringMid(InputData, StartOffset + 4, 4);
        auto DataSize = Dec(_SwapEndian(DataSizeStr), 2);

        if (DataOffset == 0 || DataSize == 0)
        { /*If Then in one Line*/
            StartOffset += 16;
        }
        // Comment:Padding 4 bytes;
        auto IndexEntrySizeStr = StringMid(InputData, StartOffset + 16, 4);
        auto IndexEntrySize = Dec(_SwapEndian(IndexEntrySizeStr), 2);
        if (IndexEntrySize == 0)
        {         /*If Then in one Line*/
            break; // Comment:;
        }
        auto IndexKeySizeStr = StringMid(InputData, StartOffset + 20, 4);
        auto IndexKeySize = Dec(_SwapEndian(IndexKeySizeStr), 2);

        auto FlagsStr = StringMid(InputData, StartOffset + 24, 4);
        auto Flags = Dec(_SwapEndian(FlagsStr));

        // Comment:Padding 2 bytes;
        auto SIDStr = StringMid(InputData, StartOffset + 32, IndexKeySize * 2);
        // auto SID = _DecodeSID(SIDStr);

        auto OwnerIdStr = StringMid(InputData, StartOffset + 32 + (IndexKeySize * 2), 8);
        auto OwnerId = Dec(_SwapEndian(OwnerIdStr), 2);
        if (option.VerboseOn)
        { /*If then*/
            _DumpOutput("\r\n");
            _DumpOutputHex(StringMid(InputData, StartOffset, IndexEntrySize * 2));
            _DumpOutput("Counter: " + std::to_string(Counter));
            _DumpOutput("DataOffset: " + std::to_string(DataOffset));
            _DumpOutput("DataSize: " + std::to_string(DataSize));
            _DumpOutput("IndexEntrySize: " + std::to_string(IndexEntrySize));
            _DumpOutput("IndexKeySize: " + std::to_string(IndexKeySize));
            _DumpOutput("Flags: " + std::to_string(Flags));
            _DumpOutput("SID: " + std::to_string(SIDStr));
            _DumpOutput("OwnerId: " + std::to_string(OwnerId));
        } /*End of If*/

        // Comment:	auto Padding8Str = StringMid(InputData, StartOffset + 32 + (IndexKeySize*2), 16);
        // TODO FileWrite(LogFileQuotaOCsv, RecordOffset + de + this_lsn + de + IndexEntrySize + de + IndexKeySize + de + Flags + de + SID + de + OwnerId + de + IsRedo);
        Counter += 1;
        StartOffset += IndexEntrySize * 2;
    } while (!(StartOffset >= InputDataSize)); // Comment: /*Until*/

    SetError(0);
    return 0;
}

int64_t _Decode_Quota_Q(std::string InputData, bool IsRedo)
{
    int64_t Counter = 1;
    auto StartOffset = 1;
    auto InputDataSize = StringLen(InputData);
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("_Decode_Quota_Q():");
        _DumpOutputHex(InputData);
    } /*End of If*/

    do
    { /*Do*/
        auto DataOffsetStr = StringMid(InputData, StartOffset, 4);
        auto DataOffset = Dec(_SwapEndian(DataOffsetStr), 2);

        auto DataSizeStr = StringMid(InputData, StartOffset + 4, 4);
        auto DataSize = Dec(_SwapEndian(DataSizeStr), 2);

        if (DataOffset == 0 || DataSize == 0)
        { /*If Then in one Line*/
            StartOffset += 16;
        }
        // Comment:Padding 4 bytes;
        auto IndexEntrySizeStr = StringMid(InputData, StartOffset + 16, 4);
        auto IndexEntrySize = Dec(_SwapEndian(IndexEntrySizeStr), 2);
        if (IndexEntrySize == 0)
        {         /*If Then in one Line*/
            break; // Comment:;
        }
        auto IndexKeySizeStr = StringMid(InputData, StartOffset + 20, 4);
        auto IndexKeySize = Dec(_SwapEndian(IndexKeySizeStr), 2);

        // Comment:1=Entry has subnodes, 2=Last entry;
        auto FlagsStr = StringMid(InputData, StartOffset + 24, 4);
        auto Flags = Dec(_SwapEndian(FlagsStr));

        // Comment:Padding 2 bytes;
        auto OwnerIdStr = StringMid(InputData, StartOffset + 32, 8);
        auto OwnerId = Dec(_SwapEndian(OwnerIdStr), 2);

        auto VersionStr = StringMid(InputData, StartOffset + 40, 8);
        auto Version = Dec(_SwapEndian(VersionStr));

        auto Flags2Str = StringMid(InputData, StartOffset + 48, 8);
        Flags2Str = _SwapEndian(Flags2Str);
        auto        Flags2Text = _Decode_QuotaFlags(Dec(Flags2Str));

        auto BytesUsedStr = StringMid(InputData, StartOffset + 56, 16);
        auto BytesUsed = Dec(_SwapEndian(BytesUsedStr), 2);

        auto ChangeTimeStr = StringMid(InputData, StartOffset + 72, 16);
        auto ChangeTime = _SwapEndian(ChangeTimeStr);
        auto ChangeTime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(ChangeTime));
        ChangeTime = _WinTime_UTCFileTimeFormat(Dec(ChangeTime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
        if ((::GetLastError() > 0))
        { /*If then*/
            ChangeTime = option.TimestampErrorVal;
        }
        else if (TimestampPrecision == 2)
        { /*Else If then*/

            // Comment:auto ChangeTime_CoreStr = StringMid(ChangeTime,1,StringLen(ChangeTime)-4);
            // Comment:ChangeTime_Precision = StringRight(ChangeTime,3);
        }
        else if (TimestampPrecision == 3)
        { /*Else If then*/

            ChangeTime = ChangeTime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(ChangeTime_tmp)), 4));
            // Comment:auto ChangeTime_CoreStr = StringMid(ChangeTime,1,StringLen(ChangeTime)-9);
            // Comment:ChangeTime_Precision = StringRight(ChangeTime,8);
        }
        else
        { /*Else*/
            // Comment:ChangeTime_Core = ChangeTime;
        } /*End of If*/
        TextInformation += ";ChangeTime=" + ChangeTime;

        auto WarningLimitStr = StringMid(InputData, StartOffset + 88, 16);
        auto WarningLimit = Dec(_SwapEndian(WarningLimitStr));

        auto HardLimitStr = StringMid(InputData, StartOffset + 104, 16);
        auto HardLimit = Dec(_SwapEndian(HardLimitStr));

        auto ExceededTime = StringMid(InputData, StartOffset + 120, 16);
        if (ExceededTime != "0000000000000000")
        { /*If then*/
            ExceededTime = _SwapEndian(ExceededTime);
            auto ExceededTime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(ExceededTime));
            ExceededTime = _WinTime_UTCFileTimeFormat(Dec(ExceededTime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
            if ((::GetLastError() > 0))
            { /*If then*/
                ExceededTime = option.TimestampErrorVal;
            }
            else if (TimestampPrecision == 2)
            { /*Else If then*/

                // Comment:auto ExceededTime_CoreStr = StringMid(ExceededTime,1,StringLen(ExceededTime)-4);
                // Comment:ExceededTime_Precision = StringRight(ExceededTime,3);
            }
            else if (TimestampPrecision == 3)
            { /*Else If then*/

                ExceededTime = ExceededTime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(ExceededTime_tmp)), 4));
                // Comment:auto ExceededTime_CoreStr = StringMid(ExceededTime,1,StringLen(ExceededTime)-9);
                // Comment:ExceededTime_Precision = StringRight(ExceededTime,8);
            }
            else
            { /*Else*/
                // Comment:ExceededTime_Core = ExceededTime;
            } /*End of If*/
        }
        else
        { /*Else*/
            ExceededTime = "0";
        } /*End of If*/

        auto SIDStr = StringMid(InputData, StartOffset + 136);
        //auto SID = _DecodeSID(SIDStr);
        if (option.VerboseOn)
        { /*If then*/
            _DumpOutput("\r\n");
            _DumpOutputHex(StringMid(InputData, StartOffset, IndexEntrySize * 2));
            _DumpOutput("Counter: " + std::to_string(Counter));
            _DumpOutput("DataOffset: " + std::to_string(DataOffset));
            _DumpOutput("DataSize: " + std::to_string(DataSize));
            _DumpOutput("IndexEntrySize: " + std::to_string(IndexEntrySize));
            _DumpOutput("IndexKeySize: " + std::to_string(IndexKeySize));
            _DumpOutput("Flags: " + std::to_string(Flags));
            _DumpOutput("OwnerId: " + std::to_string(OwnerId));
            _DumpOutput("Version: " + std::to_string(Version));
            _DumpOutput("Flags2Text: " + std::to_string(Flags2Text));
            _DumpOutput("BytesUsed: " + std::to_string(BytesUsed));
            _DumpOutput("ChangeTime: " + std::to_string(ChangeTime));
            _DumpOutput("WarningLimit: " + std::to_string(WarningLimit));
            _DumpOutput("HardLimit: " + std::to_string(HardLimit));
            _DumpOutput("ExceededTime: " + std::to_string(ExceededTime));
            _DumpOutput("SID: " + std::to_string(SIDStr));
        } /*End of If*/

        // Comment:auto Padding8Str = StringMid(InputData, StartOffset + 32 + (IndexKeySize*2), 16);
        // TODO FileWrite(LogFileQuotaQCsv, RecordOffset + de + this_lsn + de + IndexEntrySize + de + IndexKeySize + de + Flags + de + OwnerId + de + Version + de + Flags2Text + de + BytesUsed + de + ChangeTime + de + WarningLimit + de + HardLimit + de + ExceededTime + de + SID + de + IsRedo);
        Counter += 1;
        StartOffset += IndexEntrySize * 2;
    } while (!(StartOffset >= InputDataSize)); // Comment: /*0*/

    SetError(0);
    return 0;
}

std::string _Decode_QuotaFlags(DWORD InputData)
{
    std::string Output = "";
    if ((InputData & 0x0001))
    { /*If Then in one Line*/
        Output += "Default Limits+";
    }
    if ((InputData & 0x0002))
    { /*If Then in one Line*/
        Output += "Limit Reached+";
    }
    if ((InputData & 0x0004))
    { /*If Then in one Line*/
        Output += "Id Deleted+";
    }
    if ((InputData & 0x0010))
    { /*If Then in one Line*/
        Output += "Tracking Enabled+";
    }
    if ((InputData & 0x0020))
    { /*If Then in one Line*/
        Output += "Enforcement Enabled+";
    }
    if ((InputData & 0x0040))
    { /*If Then in one Line*/
        Output += "Tracking Requested+";
    }
    if ((InputData & 0x0080))
    { /*If Then in one Line*/
        Output += "Log Threshold+";
    }
    if ((InputData & 0x0100))
    { /*If Then in one Line*/
        Output += "Log Limit+";
    }
    if ((InputData & 0x0200))
    { /*If Then in one Line*/
        Output += "Out Of Date+";
    }
    if ((InputData & 0x0400))
    { /*If Then in one Line*/
        Output += "Corrupt+";
    }
    if ((InputData & 0x0800))
    { /*If Then in one Line*/
        Output += "Pending Deletes+";
    }
    Output = StringTrimRight(Output, 1);
    return Output;
}

int64_t _Decode_Reparse_R(std::string InputData, bool IsRedo)
{
    int64_t Counter = 1;
    auto StartOffset = 1;
    auto InputDataSize = StringLen(InputData);
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("_Decode_Reparse_R():");
        _DumpOutput(((InputData)));
    } /*End of If*/

    do
    { /*Do*/
        auto DataOffsetStr = StringMid(InputData, StartOffset, 4);
        auto DataOffset = Dec(_SwapEndian(DataOffsetStr), 2);

        auto DataSizeStr = StringMid(InputData, StartOffset + 4, 4);
        auto DataSize = Dec(_SwapEndian(DataSizeStr), 2);

        // Comment:		If DataOffset = 0 || DataSize = 0 Then StartOffset+=16

        // Comment:Padding 4 bytes;
        auto IndexEntrySizeStr = StringMid(InputData, StartOffset + 16, 4);
        auto IndexEntrySize = Dec(_SwapEndian(IndexEntrySizeStr), 2);
        if (IndexEntrySize == 0)
        { /*If then*/
            _DumpOutput("Error IndexEntrySize: " + std::to_string(IndexEntrySize));
            if (Counter > 1)
            {         /*If then*/
                      // Comment: in the case of an indx structure there might be slack data;
                break; // Comment:;
            }
            else
            { /*Else*/
                SetError(1);
                return {};
            } /*End of If*/
        }     /*End of If*/

        auto IndexKeySizeStr = StringMid(InputData, StartOffset + 20, 4);
        auto IndexKeySize = Dec(_SwapEndian(IndexKeySizeStr), 2);

        auto FlagsStr = StringMid(InputData, StartOffset + 24, 4);
        auto Flags = Dec(_SwapEndian(FlagsStr));

        // Comment:Padding 2 bytes;
        auto KeyReparseTagHex = StringMid(InputData, StartOffset + 32, 8);
        //auto  KeyReparseTag = Dec(_SwapEndian(KeyReparseTagHex));
        auto KeyReparseTag = _GetReparseType(utils::format::hex((uint32_t)Dec(_SwapEndian(KeyReparseTagHex)), true, false));
        if (KeyReparseTag.empty())
        { /*If then*/
            _DumpOutput("Error KeyReparseTag: " + std::to_string(KeyReparseTag));
            if (Counter > 1)
            {         /*If then*/
                      // Comment: in the case of an indx structure there might be slack data;
                break; // Comment:;
            }
            else
            { /*Else*/
                SetError(1);
                return {};
            } /*End of If*/
        }     /*End of If*/

        auto KeyMftRefOfReparsePointStr = StringMid(InputData, StartOffset + 40, 12);
        auto KeyMftRefOfReparsePoint = Dec(_SwapEndian(KeyMftRefOfReparsePointStr), 2);
        if (KeyMftRefOfReparsePoint == 0)
        { /*If then*/
            _DumpOutput("Error KeyMftRefOfReparsePoint: " + std::to_string(KeyMftRefOfReparsePoint));
            if (Counter > 1)
            {         /*If then*/
                      // Comment: in the case of an indx structure there might be slack data;
                break; // Comment:;
            }
            else
            { /*Else*/
                SetError(1);
                return {};
            } /*End of If*/
        }     /*End of If*/

        auto KeyMftRefSeqNoOfReparsePointStr = StringMid(InputData, StartOffset + 52, 4);
        auto KeyMftRefSeqNoOfReparsePoint = Dec(_SwapEndian(KeyMftRefSeqNoOfReparsePointStr), 2);
        if (KeyMftRefSeqNoOfReparsePoint == 0)
        { /*If then*/
            _DumpOutput("Error KeyMftRefSeqNoOfReparsePoint: " + std::to_string(KeyMftRefSeqNoOfReparsePoint));
            if (Counter > 1)
            {         /*If then*/
                      // Comment: in the case of an indx structure there might be slack data;
                break; // Comment:;
            }
            else
            { /*Else*/
                SetError(1);
                return {};
            } /*End of If*/
        }     /*End of If*/

        if (option.VerboseOn)
        { /*If then*/
            _DumpOutput("\r\n");
            _DumpOutput(((StringMid(InputData, StartOffset, IndexEntrySize * 2))));
            _DumpOutput("Counter: " + std::to_string(Counter));
            _DumpOutput("DataOffset: " + Hex(DataOffset, 4));
            _DumpOutput("DataSize: " + Hex(DataSize, 4));
            _DumpOutput("IndexEntrySize: " + Hex(IndexEntrySize, 4));
            _DumpOutput("IndexKeySize: " + Hex(IndexKeySize, 4));
            _DumpOutput("Flags: " + std::to_string(Flags));
            _DumpOutput("KeyReparseTag: " + std::to_string(KeyReparseTag));
            _DumpOutput("KeyMftRefOfReparsePoint: " + std::to_string(KeyMftRefOfReparsePoint));
            _DumpOutput("KeyMftRefSeqNoOfReparsePoint: " + std::to_string(KeyMftRefSeqNoOfReparsePoint));
        } /*End of If*/

        // Comment:	Padding4 = StringMid(InputData, StartOffset + 56, 8);
        // TODO FileWrite(LogFileReparseRCsv, RecordOffset + de + this_lsn + de + IndexEntrySize + de + IndexKeySize + de + Flags + de + KeyReparseTag + de + KeyMftRefOfReparsePoint + de + KeyMftRefSeqNoOfReparsePoint + de + IsRedo)

        Counter += 1;
        StartOffset += IndexEntrySize * 2;

    } while (!(StartOffset >= InputDataSize)); // Comment: /*0*/
}

int64_t _TryIdentifyIndexEntryType(std::string Entry, std::string operation_hex, bool IsRedo)
{
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("_TryIdentifyIndexEntryType():");
    } /*End of If*/

    // Comment:Secure:SII;
    // Comment:If StringLen (Entry)==80  && StringLeft(Entry, 16) == "1400140000000000" Then;
    if (StringLeft(Entry, 16) == "1400140000000000")
    { /*If then*/
        // Comment:If StringLeft(Entry, 8) == "14001400" Then;
        _DecodeIndxEntriesSII(Entry, IsRedo);
        if (!(::GetLastError() > 0))
        { /*If then*/
            TextInformation += ";Secure:SII;See LogFile_SecureSII.csv";
            result.AttributeString += ":SII";
            return true;
        } /*End of If*/
    }     /*End of If*/

    // Comment:Secure:SDH;
    // Comment:If StringLen (Entry)==96  && StringLeft(Entry, 16) == "1800140000000000" Then;
    if (StringLeft(Entry, 16) == "1800140000000000")
    { /*If then*/
        // Comment:If StringLeft(Entry, 8) == "18001400" Then;
        _DecodeIndxEntriesSDH(Entry, IsRedo);
        if (!(::GetLastError() > 0))
        { /*If then*/
            TextInformation += ";Secure:SDH;See LogFile_SecureSDH.csv";
            result.AttributeString += ":SDH";
            return true;
        } /*End of If*/
    }     /*End of If*/

    // Comment:I30;
    /*AutoIt_Select 	*/
    if (false)
    {
    }
    else if (operation_hex == Operation_AddIndexEntryToRoot || operation_hex == Operation_AddIndexEntryToAllocationBuffer)
    { /*Case替换*/
        _Decode_IndexEntry(Entry, operation_hex, IsRedo);
        if ((::GetLastError() > 0))
        { /*If then*/
            if (IsRedo == 1 && operation_hex == Operation_AddIndexEntryToRoot)
            { /*If Then in one Line*/
                _UpdateSingleOffsetOfAttribute(result.PredictedRefNumber, record_offset_in_mft, RedoChunkSize, "$INDEX_ROOT");
            }
            _DumpOutput("_Decode_IndexEntry() failed for this_lsn: " + std::to_string(this_lsn));
            _DumpOutput(((Entry)));
            SetError(1);
            return {};
        }
        else
        { /*Else*/
            if (IsRedo == 1 && operation_hex == Operation_AddIndexEntryToRoot)
            { /*If then*/
                _UpdateSingleOffsetOfAttribute(RealMftRef, record_offset_in_mft, RedoChunkSize, "$INDEX_ROOT");
                TextInformation += ";See LogFile_INDX_I30.csv";
            } /*End of If*/
            if (IsRedo == 1 && operation_hex == Operation_AddIndexEntryToAllocationBuffer)
            { /*If Then in one Line*/
                TextInformation += ";See LogFile_INDX_I30.csv";
            }
            if (IsRedo == 0)
            { /*If Then in one Line*/
                TextInformation += ";See LogFile_INDX_I30.csv";
            }
            return true;
        } /*End of If*/
    }
    else if (operation_hex == Operation_WriteEndOfIndexBuffer)
    { /*Case替换*/
        _Decode_UndoWipeINDX(Entry, IsRedo);
        if ((::GetLastError() > 0))
        { /*If then*/
            _DumpOutput("_Decode_UndoWipeINDX() failed for this_lsn: " + std::to_string(this_lsn));
            _DumpOutput(((Entry)));
        }
        else
        { /*Else*/
            TextInformation += ";See LogFile_INDX_I30.csv";
        } /*End of If*/
        return true;
    } /*AutoIt_EndSelect 	*/

    int64_t inputLength = StringLen(Entry);

    // Comment:Reparse:R;
    if (inputLength <= 168)
    { /*If then*/
        _Decode_Reparse_R(Entry, IsRedo);
        if (!(::GetLastError() > 0))
        { /*If then*/
            TextInformation += ";See LogFile_ReparseR.csv";
            return true;
        } /*End of If*/
    }     /*End of If*/

    // Comment:ObjId:O;
    if (inputLength == 176 || inputLength == 192)
    { /*If then*/
       // Jump _Decode_ObjId_O(Entry, IsRedo);
        if (!(::GetLastError() > 0))
        { /*If then*/
            TextInformation += ";See LogFile_ObjIdO.csv";
            return true;
        } /*End of If*/
    }     /*End of If*/

    _DumpOutput("Index identification failed.");

    return false;
}



int64_t _Decode_UndoWipeINDX(std::string Entry, bool IsRedo)
{
    int64_t SubNodeVCNLength = 0;
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("_Decode_UndoWipeINDX()");
        _DumpOutput(_HexEncode("0x" + Entry));
    } /*End of If*/
    int64_t NewLocalAttributeOffset = 1;
    int64_t SubNodeVCN, tmp0 = 0, tmp1 = 0, tmp2 = 0, tmp3 = 0, EntryCounter = 1;

    auto MFTReferenceStr = StringMid(Entry, NewLocalAttributeOffset, 12);
    MFTReferenceStr = _SwapEndian(MFTReferenceStr);
    auto MFTReference = Dec(MFTReferenceStr, 2);
    if (MFTReference == 0)
    { /*If then*/
        _DumpOutput("Error MFTReference: " + std::to_string(MFTReference));
        SetError(1); return {};
    } /*End of If*/

    auto MFTReferenceSeqNoStr = StringMid(Entry, NewLocalAttributeOffset + 12, 4);
    auto MFTReferenceSeqNo = Dec(_SwapEndian(MFTReferenceSeqNoStr), 2);
    if (MFTReferenceSeqNo == 0)
    { /*If then*/
        _DumpOutput("Error MFTReferenceSeqNo: " + std::to_string(MFTReferenceSeqNo));
        SetError(1); return {};
    } /*End of If*/

    auto IndexEntryLengthStr = StringMid(Entry, NewLocalAttributeOffset + 16, 4);
    auto IndexEntryLength = Dec(_SwapEndian(IndexEntryLengthStr), 2);
    auto OffsetToFileNameStr = StringMid(Entry, NewLocalAttributeOffset + 20, 4);
    auto OffsetToFileName = Dec(_SwapEndian(OffsetToFileNameStr), 2);
    auto IndexFlagsStr = StringMid(Entry, NewLocalAttributeOffset + 24, 4);
    // Comment:auto PaddingStr = StringMid(Entry,NewLocalAttributeOffset+28,4);
    auto MFTReferenceOfParentStr = StringMid(Entry, NewLocalAttributeOffset + 32, 12);
    MFTReferenceOfParentStr = _SwapEndian(MFTReferenceOfParentStr);
    auto MFTReferenceOfParent = Dec(MFTReferenceOfParentStr, 2);
    if (MFTReferenceOfParent < 5 || (MFTReferenceOfParent > 5 && MFTReferenceOfParent < 11))
    { /*If then*/
        _DumpOutput("Error MFTReferenceOfParent: " + std::to_string(MFTReferenceOfParent));
        SetError(1); return {};
    } /*End of If*/

    auto MFTReferenceOfParentSeqNoStr = StringMid(Entry, NewLocalAttributeOffset + 44, 4);
    auto MFTReferenceOfParentSeqNo = Dec(_SwapEndian(MFTReferenceOfParentSeqNoStr), 2);
    if (MFTReferenceOfParentSeqNo == 0)
    { /*If then*/
        _DumpOutput("Error MFTReferenceOfParentSeqNo: " + std::to_string(MFTReferenceOfParentSeqNo));
        SetError(1); return {};
    } /*End of If*/
      // Comment:;
    auto Indx_CTimeStr = StringMid(Entry, NewLocalAttributeOffset + 48, 16);
    auto Indx_CTime = _SwapEndian(Indx_CTimeStr);

    auto Indx_CTime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(Indx_CTime, 2));
    if ((::GetLastError() > 0))
    { /*If then*/
        Indx_CTime = option.TimestampErrorVal;
    }
    else if (TimestampPrecision == 2)
    { /*Else If then*/

        // Comment:Indx_CTime_Core = StringMid(Indx_CTime,1,StringLen(Indx_CTime)-4);
        // Comment:Indx_CTime_Precision = StringRight(Indx_CTime,3);
    }
    else if (TimestampPrecision == 3)
    { /*Else If then*/

        Indx_CTime = Indx_CTime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(Indx_CTime_tmp)), 4));
        // Comment:Indx_CTime_Core = StringMid(Indx_CTime,1,StringLen(Indx_CTime)-9);
        // Comment:Indx_CTime_Precision = StringRight(Indx_CTime,8);
    }
    else
    { /*Else*/
        // Comment:Indx_CTime_Core = Indx_CTime;
    } /*End of If*/
    if (Indx_CTime == option.TimestampErrorVal)
    { /*If then*/
        _DumpOutput("Error Indx_CTime: " + std::to_string(Indx_CTime));
        SetError(1);
        return {};
    } /*End of If*/
      // Comment:;
    auto Indx_ATime = StringMid(Entry, NewLocalAttributeOffset + 64, 16);
    Indx_ATime = _SwapEndian(Indx_ATime);
    auto Indx_ATime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(Indx_ATime));
    Indx_ATime = _WinTime_UTCFileTimeFormat(Dec(Indx_ATime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
    if ((::GetLastError() > 0))
    { /*If then*/
        Indx_ATime = option.TimestampErrorVal;
    }
    else if (TimestampPrecision == 2)
    { /*Else If then*/

        // Comment:Indx_ATime_Core = StringMid(Indx_ATime,1,StringLen(Indx_ATime)-4);
        // Comment:Indx_ATime_Precision = StringRight(Indx_ATime,3);
    }
    else if (TimestampPrecision == 3)
    { /*Else If then*/

        Indx_ATime = Indx_ATime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(Indx_ATime_tmp)), 4));
        // Comment:Indx_ATime_Core = StringMid(Indx_ATime,1,StringLen(Indx_ATime)-9);
        // Comment:Indx_ATime_Precision = StringRight(Indx_ATime,8);
    }
    else
    { /*Else*/
        // Comment:Indx_ATime_Core = Indx_ATime;
    } /*End of If*/
    if (Indx_ATime == option.TimestampErrorVal)
    { /*If then*/
        _DumpOutput("Error Indx_ATime: " + std::to_string(Indx_ATime));
        SetError(1);
        return {};
    } /*End of If*/
      // Comment:;
    auto Indx_MTime = StringMid(Entry, NewLocalAttributeOffset + 80, 16);
    Indx_MTime = _SwapEndian(Indx_MTime);
    auto Indx_MTime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(Indx_MTime, 2));
    Indx_MTime = _WinTime_UTCFileTimeFormat(Dec(Indx_MTime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
    if ((::GetLastError() > 0))
    { /*If then*/
        Indx_MTime = option.TimestampErrorVal;
    }
    else if (TimestampPrecision == 2)
    { /*Else If then*/

        // Comment:Indx_MTime_Core = StringMid(Indx_MTime,1,StringLen(Indx_MTime)-4);
        // Comment:Indx_MTime_Precision = StringRight(Indx_MTime,3);
    }
    else if (TimestampPrecision == 3)
    { /*Else If then*/

        Indx_MTime = Indx_MTime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(Indx_MTime_tmp)), 4));
        // Comment:Indx_MTime_Core = StringMid(Indx_MTime,1,StringLen(Indx_MTime)-9);
        // Comment:Indx_MTime_Precision = StringRight(Indx_MTime,8);
    }
    else
    { /*Else*/
        // Comment:Indx_MTime_Core = Indx_MTime;
    } /*End of If*/
    if (Indx_MTime == option.TimestampErrorVal)
    { /*If then*/
        _DumpOutput("Error Indx_MTime: " + std::to_string(Indx_MTime));
        SetError(1);
        return {};
    } /*End of If*/
      // Comment:;
    auto Indx_RTime = StringMid(Entry, NewLocalAttributeOffset + 96, 16);
    Indx_RTime = _SwapEndian(Indx_RTime);
    auto Indx_RTime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(Indx_RTime, 2));
    Indx_RTime = _WinTime_UTCFileTimeFormat(Dec(Indx_RTime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
    if ((::GetLastError() > 0))
    { /*If then*/
        Indx_RTime = option.TimestampErrorVal;
    }
    else if (TimestampPrecision == 2)
    { /*Else If then*/

        // Comment:Indx_RTime_Core = StringMid(Indx_RTime,1,StringLen(Indx_RTime)-4);
        // Comment:Indx_RTime_Precision = StringRight(Indx_RTime,3);
    }
    else if (TimestampPrecision == 3)
    { /*Else If then*/

        Indx_RTime = Indx_RTime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(Indx_RTime_tmp)), 4));
        // Comment:Indx_RTime_Core = StringMid(Indx_RTime,1,StringLen(Indx_RTime)-9);
        // Comment:Indx_RTime_Precision = StringRight(Indx_RTime,8);
    }
    else
    { /*Else*/
        // Comment:Indx_RTime_Core = Indx_RTime;
    } /*End of If*/
    if (Indx_RTime == option.TimestampErrorVal)
    { /*If then*/
        _DumpOutput("Error Indx_RTime: " + std::to_string(Indx_RTime));
        SetError(1);
        return {};
    } /*End of If*/
      // Comment:;
    auto Indx_AllocSizeStr = StringMid(Entry, NewLocalAttributeOffset + 112, 16);
    auto Indx_AllocSize = Dec(_SwapEndian(Indx_AllocSizeStr), 2);
    auto Indx_RealSizeStr = StringMid(Entry, NewLocalAttributeOffset + 128, 16);
    auto Indx_RealSize = Dec(_SwapEndian(Indx_RealSizeStr), 2);

    auto Indx_File_FlagsStr = StringMid(Entry, NewLocalAttributeOffset + 144, 8);
    auto Indx_File_Flags = _SwapEndian(Indx_File_FlagsStr);
    bool DoReparseTag, DoEaSize;
    if ((Dec(Indx_File_Flags) & 0x40000))
    { /*If then*/
        DoReparseTag = 0;
        DoEaSize = 1;
    }
    else
    { /*Else*/
        DoReparseTag = 1;
        DoEaSize = 0;
    } /*End of If*/
    Indx_File_Flags = _File_Attributes(Dec(Indx_File_Flags));
    /*AutoIt_Select ;
     */

    std::string Indx_ReparseTag, Indx_EaSize;
    if (false)
    {
    }
    else if (DoReparseTag) { /*Case替换*/
        Indx_EaSize = "";

        Indx_ReparseTag = StringMid(Entry, NewLocalAttributeOffset + 152, 8);
        Indx_ReparseTag = _SwapEndian(Indx_ReparseTag);
        Indx_ReparseTag = _GetReparseType("0x" + Indx_ReparseTag);
    }
    else if (DoEaSize)
    { /*Case替换*/
        Indx_ReparseTag = "";
        Indx_EaSize = StringMid(Entry, NewLocalAttributeOffset + 152, 8);
        Indx_EaSize = Dec(_SwapEndian(Indx_EaSize), 2);
    } /*AutoIt_EndSelect 	*/

    auto Indx_NameLengthStr = StringMid(Entry, NewLocalAttributeOffset + 160, 2);
    auto Indx_NameLength = Dec(Indx_NameLengthStr);
    if (Indx_NameLength == 0)
    { /*If then*/
        _DumpOutput("Error Indx_NameLength: " + std::to_string(Indx_NameLength));
        SetError(1);
        return {};
    } /*End of If*/

    auto Indx_NameSpace = StringMid(Entry, NewLocalAttributeOffset + 162, 2);
    /*AutoIt_Select 	*/
    if (false)
    {
    }
    else if (Indx_NameSpace == "00")
    { /*Case替换*/
        Indx_NameSpace = "POSIX";
    }
    else if (Indx_NameSpace == "01")
    { /*Case替换*/
        Indx_NameSpace = "WIN32";
    }
    else if (Indx_NameSpace == "02")
    { /*Case替换*/
        Indx_NameSpace = "DOS";
    }
    else if (Indx_NameSpace == "03")
    { /*Case替换*/
        Indx_NameSpace = "DOS+WIN32";
    } /*AutoIt_EndSelect 	*/
    auto Indx_FileName = StringMid(Entry, NewLocalAttributeOffset + 164, Indx_NameLength * 4);
    if (StringLeft(Indx_FileName, 2) == "00")
    { /*If then*/
        _DumpOutput("Error Indx_FileName: " + std::to_string(Indx_FileName));
        SetError(1);
        return {};
    } /*End of If*/
    auto Indx_FileNameRaw = BinaryToString(Indx_FileName, 2);
    Indx_FileName = StringReplace(Indx_FileNameRaw, de, CharReplacement);
    auto FileNameModified = Indx_FileName == Indx_FileNameRaw;
    tmp1 = 164 + (Indx_NameLength * 2 * 2);

    // Comment: Calculate the length of the padding - 8 byte aligned;
    tmp3 = tmp1 % 16;

    //do
    //{ /*Do*/ // Comment: Calculate the length of the padding - 8 byte aligned;
    //    tmp2 = tmp1 / 16;
    //    if (!IsInt(tmp2))
    //    { /*If then*/
    //        tmp0 = 2;
    //        tmp1 += tmp0;
    //        tmp3 += tmp0;
    //    }                      /*End of If*/
    //} while (!(IsInt(tmp2))); // Comment: /*0*/

    auto PaddingLength = tmp3;
    // Comment:	Padding2 = StringMid(Entry,NewLocalAttributeOffset+164+(Indx_NameLength*2*2),PaddingLength);
    if (IndexFlagsStr != "0000")
    { /*If then*/
        auto SubNodeVCNStr = StringMid(Entry, NewLocalAttributeOffset + 164 + (Indx_NameLength * 2 * 2) + PaddingLength, 16);
        SubNodeVCN = Dec(_SwapEndian(SubNodeVCNStr), 2);
        SubNodeVCNLength = 16;
    }
    else
    { /*Else*/
        SubNodeVCN = 0;
        SubNodeVCNLength = 0;
    } /*End of If*/
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("MFTReference==" + std::to_string(MFTReference));
        _DumpOutput("MFTReferenceSeqNo==" + std::to_string(MFTReferenceSeqNo));
        _DumpOutput("IndexEntryLength==" + std::to_string(IndexEntryLength));
        _DumpOutput("OffsetToFileName==" + std::to_string(OffsetToFileName));
        _DumpOutput("IndexFlags==" + std::to_string(IndexFlagsStr));
        _DumpOutput("MFTReferenceOfParent==" + std::to_string(MFTReferenceOfParent));
        _DumpOutput("Indx_CTime==" + std::to_string(Indx_CTime));
        _DumpOutput("Indx_ATime==" + std::to_string(Indx_ATime));
        _DumpOutput("Indx_MTime==" + std::to_string(Indx_MTime));
        _DumpOutput("Indx_RTime==" + std::to_string(Indx_RTime));
        _DumpOutput("Indx_AllocSize==" + std::to_string(Indx_AllocSize));
        _DumpOutput("Indx_RealSize==" + std::to_string(Indx_RealSize));
        _DumpOutput("Indx_File_Flags==" + std::to_string(Indx_File_Flags));
        _DumpOutput("Indx_ReparseTag==" + std::to_string(Indx_ReparseTag));
        _DumpOutput("Indx_EaSize==" + std::to_string(Indx_EaSize));
        _DumpOutput("Indx_NameLength==" + std::to_string(Indx_NameLength));
        _DumpOutput("Indx_NameSpace==" + std::to_string(Indx_NameSpace));
        _DumpOutput("Indx_FileName==" + std::to_string(Indx_FileName));
        _DumpOutput("SubNodeVCN==" + std::to_string(SubNodeVCN));
        _DumpOutput("\r\n");
    } /*End of If*/

   // TODO FileWrite(LogFileIndxCsv, RecordOffset + de + this_lsn + de + EntryCounter + de + MFTReference + de + MFTReferenceSeqNo + de + IndexFlags + de + MFTReferenceOfParent + de + MFTReferenceOfParentSeqNo + de + Indx_CTime + de + Indx_ATime + de + Indx_MTime + de + Indx_RTime + de + Indx_AllocSize + de + Indx_RealSize + de + Indx_File_Flags + de + Indx_ReparseTag + de + Indx_EaSize + de + Indx_FileName + de + FileNameModified + de + Indx_NameSpace + de + SubNodeVCN + de + IsRedo);
    if (!FromRcrdSlack)
    { /*If then*/
        if (Indx_NameSpace != "DOS")
        { /*If Then in one Line*/
            _UpdateFileNameArray(MFTReference, MFTReferenceSeqNo, Indx_FileName, this_lsn);
        }
    }

    result.PredictedRefNumber = MFTReferenceOfParent;
    KeptRef = MFTReferenceOfParent;
    result.AttributeString = "$INDEX_ALLOCATION";
    if (!FromRcrdSlack)
    { /*If then*/
        if (Indx_NameSpace != "DOS")
        { /*If Then in one Line*/
            _UpdateFileNameArray(MFTReference, MFTReferenceSeqNo, Indx_FileName, this_lsn);
        }
    }

    // Comment: Work through the rest of the index entries;
    auto NextEntryOffset = NewLocalAttributeOffset + 164 + (Indx_NameLength * 2 * 2) + PaddingLength + SubNodeVCNLength;
    if (option.VerboseOn)
    { /*If then*/
        _DumpOutput("NextEntryOffset+64 = " + NextEntryOffset + 64);
        _DumpOutput("StringLen(Entry)==" + StringLen(Entry));
    } /*End of If*/
    if (NextEntryOffset + 64 >= StringLen(Entry))
    { /*If then*/
        return true;
    } /*End of If*/

    do
    { /*Do*/
        EntryCounter += 1;
        if (option.VerboseOn)
        { /*If then*/
            _DumpOutput("NextEntryOffset==0x" + Hex(Int((NextEntryOffset - 1) / 2), 8));
        } /*End of If*/
        auto MFTReferenceStr = StringMid(Entry, NextEntryOffset, 12);
        MFTReferenceStr = _SwapEndian(MFTReferenceStr);
        auto MFTReference = Dec(MFTReferenceStr, 2);
        if (MFTReference == 0)
        { /*If then*/
            _DumpOutput("Error MFTReference: " + std::to_string(MFTReference));
            if (EntryCounter > 1)
            { /*If then*/
                break;
            }
            else
            { /*Else*/
                SetError(1); return {};
            } /*End of If*/
        }     /*End of If*/
        auto MFTReferenceSeqNoStr = StringMid(Entry, NextEntryOffset + 12, 4);
        MFTReferenceSeqNo = Dec(_SwapEndian(MFTReferenceSeqNoStr), 2);
        if (MFTReferenceSeqNo == 0)
        { /*If then*/
            _DumpOutput("Error MFTReferenceSeqNo: " + std::to_string(MFTReferenceSeqNo));
            if (EntryCounter > 1)
            { /*If then*/
                break;
            }
            else
            { /*Else*/
                SetError(1); return {};
            } /*End of If*/
        }     /*End of If*/
        auto IndexEntryLengthStr = StringMid(Entry, NewLocalAttributeOffset + 16, 4);
        auto IndexEntryLength = Dec(_SwapEndian(IndexEntryLengthStr), 2);
        auto OffsetToFileNameStr = StringMid(Entry, NewLocalAttributeOffset + 20, 4);
        auto OffsetToFileName = Dec(_SwapEndian(OffsetToFileNameStr), 2);
        auto IndexFlags = StringMid(Entry, NewLocalAttributeOffset + 24, 4);
        // Comment:	Padding = StringMid(Entry,NewLocalAttributeOffset+28,4);
        auto MFTReferenceOfParentStr = StringMid(Entry, NewLocalAttributeOffset + 32, 12);
        MFTReferenceOfParentStr = _SwapEndian(MFTReferenceOfParentStr);
        auto MFTReferenceOfParent = Dec(MFTReferenceOfParentStr, 2);
        if (MFTReferenceOfParent < 5 || (MFTReferenceOfParent > 5 && MFTReferenceOfParent < 11))
        { /*If then*/
            _DumpOutput("Error MFTReferenceOfParent: " + std::to_string(MFTReferenceOfParent));
            SetError(1);
            return {};
        } /*End of If*/

        auto MFTReferenceOfParentSeqNoStr = StringMid(Entry, NewLocalAttributeOffset + 44, 4);
        auto MFTReferenceOfParentSeqNo = Dec(_SwapEndian(MFTReferenceOfParentSeqNoStr), 2);
        if (MFTReferenceOfParentSeqNo == 0)
        { /*If then*/
            _DumpOutput("Error MFTReferenceOfParentSeqNo: " + std::to_string(MFTReferenceOfParentSeqNo));
            SetError(1);
            return {};
        } /*End of If*/
          // Comment:;
        auto Indx_CTimeStr = StringMid(Entry, NewLocalAttributeOffset + 48, 16);
        auto Indx_CTime = _SwapEndian(Indx_CTimeStr);

        auto Indx_CTime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(Indx_CTime, 2));
        Indx_CTime = _WinTime_UTCFileTimeFormat(Dec(Indx_CTime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
        if ((::GetLastError() > 0))
        { /*If then*/
            Indx_CTime = option.TimestampErrorVal;
        }
        else if (TimestampPrecision == 2)
        { /*Else If then*/

            // Comment:Indx_CTime_Core = StringMid(Indx_CTime,1,StringLen(Indx_CTime)-4);
            // Comment:Indx_CTime_Precision = StringRight(Indx_CTime,3);
        }
        else if (TimestampPrecision == 3)
        { /*Else If then*/

            Indx_CTime = Indx_CTime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(Indx_CTime_tmp)), 4));
            // Comment:Indx_CTime_Core = StringMid(Indx_CTime,1,StringLen(Indx_CTime)-9);
            // Comment:Indx_CTime_Precision = StringRight(Indx_CTime,8);
        }
        else
        { /*Else*/
            // Comment:Indx_CTime_Core = Indx_CTime;
        } /*End of If*/
        if (Indx_CTime == option.TimestampErrorVal)
        { /*If then*/
            _DumpOutput("Error Indx_CTime: " + std::to_string(Indx_CTime));
            SetError(1);
            return {};
        } /*End of If*/
          // Comment:;
        auto Indx_ATime = StringMid(Entry, NewLocalAttributeOffset + 64, 16);
        Indx_ATime = _SwapEndian(Indx_ATime);
        auto Indx_ATime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(Indx_ATime));
        Indx_ATime = _WinTime_UTCFileTimeFormat(Dec(Indx_ATime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
        if ((::GetLastError() > 0))
        { /*If then*/
            Indx_ATime = option.TimestampErrorVal;
        }
        else if (TimestampPrecision == 2)
        { /*Else If then*/

            // Comment:Indx_ATime_Core = StringMid(Indx_ATime,1,StringLen(Indx_ATime)-4);
            // Comment:Indx_ATime_Precision = StringRight(Indx_ATime,3);
        }
        else if (TimestampPrecision == 3)
        { /*Else If then*/

            Indx_ATime = Indx_ATime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(Indx_ATime_tmp)), 4));
            // Comment:Indx_ATime_Core = StringMid(Indx_ATime,1,StringLen(Indx_ATime)-9);
            // Comment:Indx_ATime_Precision = StringRight(Indx_ATime,8);
        }
        else
        { /*Else*/
            // Comment:Indx_ATime_Core = Indx_ATime;
        } /*End of If*/
        if (Indx_ATime == option.TimestampErrorVal)
        { /*If then*/
            _DumpOutput("Error Indx_ATime: " + std::to_string(Indx_ATime));
            SetError(1);
            return {};
        } /*End of If*/
          // Comment:;
        auto Indx_MTime = StringMid(Entry, NewLocalAttributeOffset + 80, 16);
        Indx_MTime = _SwapEndian(Indx_MTime);
        auto Indx_MTime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(Indx_MTime, 2));
        Indx_MTime = _WinTime_UTCFileTimeFormat(Dec(Indx_MTime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
        if ((::GetLastError() > 0))
        { /*If then*/
            Indx_MTime = option.TimestampErrorVal;
        }
        else if (TimestampPrecision == 2)
        { /*Else If then*/

            // Comment:Indx_MTime_Core = StringMid(Indx_MTime,1,StringLen(Indx_MTime)-4);
            // Comment:Indx_MTime_Precision = StringRight(Indx_MTime,3);
        }
        else if (TimestampPrecision == 3)
        { /*Else If then*/

            Indx_MTime = Indx_MTime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(Indx_MTime_tmp)), 4));
            // Comment:Indx_MTime_Core = StringMid(Indx_MTime,1,StringLen(Indx_MTime)-9);
            // Comment:Indx_MTime_Precision = StringRight(Indx_MTime,8);
        }
        else
        { /*Else*/
            // Comment:Indx_MTime_Core = Indx_MTime;
        } /*End of If*/
        if (Indx_MTime == option.TimestampErrorVal)
        { /*If then*/
            _DumpOutput("Error Indx_MTime: " + std::to_string(Indx_MTime));
            SetError(1);
            return {};
        } /*End of If*/
          // Comment:;
        auto Indx_RTime = StringMid(Entry, NewLocalAttributeOffset + 96, 16);
        Indx_RTime = _SwapEndian(Indx_RTime);
        auto Indx_RTime_tmp = _WinTime_UTCFileTimeToLocalFileTime(Dec(Indx_RTime, 2));
        Indx_RTime = _WinTime_UTCFileTimeFormat(Dec(Indx_RTime, 2) - tDelta, option.DateTimeFormat, TimestampPrecision);
        if ((::GetLastError() > 0))
        { /*If then*/
            Indx_RTime = option.TimestampErrorVal;
        }
        else if (TimestampPrecision == 2)
        { /*Else If then*/

            // Comment:Indx_RTime_Core = StringMid(Indx_RTime,1,StringLen(Indx_RTime)-4);
            // Comment:Indx_RTime_Precision = StringRight(Indx_RTime,3);
        }
        else if (TimestampPrecision == 3)
        { /*Else If then*/

            Indx_RTime = Indx_RTime + PrecisionSeparator2 + _FillZero(StringRight(std::to_string(FILETIME2Int(Indx_RTime_tmp)), 4));
            // Comment:Indx_RTime_Core = StringMid(Indx_RTime,1,StringLen(Indx_RTime)-9);
            // Comment:Indx_RTime_Precision = StringRight(Indx_RTime,8);
        }
        else
        { /*Else*/
            // Comment:Indx_RTime_Core = Indx_RTime;
        } /*End of If*/
        if (Indx_RTime == option.TimestampErrorVal)
        { /*If then*/
            _DumpOutput("Error Indx_RTime: " + std::to_string(Indx_RTime));
            SetError(1);
            return {};
        } /*End of If*/
          // Comment:;
        auto Indx_AllocSizeStr = StringMid(Entry, NewLocalAttributeOffset + 112, 16);
        auto Indx_AllocSize = Dec(_SwapEndian(Indx_AllocSizeStr), 2);
        auto Indx_RealSizeStr = StringMid(Entry, NewLocalAttributeOffset + 128, 16);
        auto Indx_RealSize = Dec(_SwapEndian(Indx_RealSizeStr), 2);

        auto Indx_File_FlagsStr = StringMid(Entry, NewLocalAttributeOffset + 144, 8);
        auto Indx_File_Flags = _SwapEndian(Indx_File_FlagsStr);
        bool DoReparseTag, DoEaSize;
        if ((Dec(Indx_File_Flags) & 0x40000))
        { /*If then*/
            DoReparseTag = 0;
            DoEaSize = 1;
        }
        else
        { /*Else*/
            DoReparseTag = 1;
            DoEaSize = 0;
        } /*End of If*/
        Indx_File_Flags = _File_Attributes(Dec(Indx_File_Flags));
        /*AutoIt_Select ;
         */

        std::string Indx_ReparseTag, Indx_EaSize;
        if (false)
        {
        }
        else if (DoReparseTag) { /*Case替换*/
            Indx_EaSize = "";

            Indx_ReparseTag = StringMid(Entry, NewLocalAttributeOffset + 152, 8);
            Indx_ReparseTag = _SwapEndian(Indx_ReparseTag);
            Indx_ReparseTag = _GetReparseType("0x" + Indx_ReparseTag);
        }
        else if (DoEaSize)
        { /*Case替换*/
            Indx_ReparseTag = "";
            Indx_EaSize = StringMid(Entry, NewLocalAttributeOffset + 152, 8);
            Indx_EaSize = Dec(_SwapEndian(Indx_EaSize), 2);
        } /*AutoIt_EndSelect 	*/

        auto Indx_NameLengthStr = StringMid(Entry, NewLocalAttributeOffset + 160, 2);
        auto Indx_NameLength = Dec(Indx_NameLengthStr);
        if (Indx_NameLength == 0)
        { /*If then*/
            _DumpOutput("Error Indx_NameLength: " + std::to_string(Indx_NameLength));
            SetError(1);
            return {};
        } /*End of If*/

        auto Indx_NameSpace = StringMid(Entry, NewLocalAttributeOffset + 162, 2);
        /*AutoIt_Select 	*/
        if (false)
        {
        }
        else if (Indx_NameSpace == "00")
        { /*Case替换*/
            Indx_NameSpace = "POSIX";
        }
        else if (Indx_NameSpace == "01")
        { /*Case替换*/
            Indx_NameSpace = "WIN32";
        }
        else if (Indx_NameSpace == "02")
        { /*Case替换*/
            Indx_NameSpace = "DOS";
        }
        else if (Indx_NameSpace == "03")
        { /*Case替换*/
            Indx_NameSpace = "DOS+WIN32";
        } /*AutoIt_EndSelect 	*/
        auto Indx_FileName = StringMid(Entry, NewLocalAttributeOffset + 164, Indx_NameLength * 4);
        if (StringLeft(Indx_FileName, 2) == "00")
        { /*If then*/
            _DumpOutput("Error Indx_FileName: " + std::to_string(Indx_FileName));
            SetError(1);
            return {};
        } /*End of If*/
        auto Indx_FileNameRaw = BinaryToString(Indx_FileName, 2);
        Indx_FileName = StringReplace(Indx_FileNameRaw, de, CharReplacement);
        auto FileNameModified = Indx_FileName == Indx_FileNameRaw;
        tmp1 = 164 + (Indx_NameLength * 2 * 2);

        // Comment: Calculate the length of the padding - 8 byte aligned;
        tmp3 = tmp1 % 16;

        //do
        //{ /*Do*/ // Comment: Calculate the length of the padding - 8 byte aligned;
        //    tmp2 = tmp1 / 16;
        //    if (!IsInt(tmp2))
        //    { /*If then*/
        //        tmp0 = 2;
        //        tmp1 += tmp0;
        //        tmp3 += tmp0;
        //    }                      /*End of If*/
        //} while (!(IsInt(tmp2))); // Comment: /*0*/

        auto PaddingLength = tmp3;
        // Comment:	Padding2 = StringMid(Entry,NewLocalAttributeOffset+164+(Indx_NameLength*2*2),PaddingLength);
        if (IndexFlags != "0000")
        { /*If then*/
            auto SubNodeVCNStr = StringMid(Entry, NewLocalAttributeOffset + 164 + (Indx_NameLength * 2 * 2) + PaddingLength, 16);
            SubNodeVCN = Dec(_SwapEndian(SubNodeVCNStr), 2);
            SubNodeVCNLength = 16;
        }
        else
        { /*Else*/
            SubNodeVCN = 0;
            SubNodeVCNLength = 0;
        } /*End of If*/


        NextEntryOffset = NextEntryOffset + 164 + (Indx_NameLength * 2 * 2) + PaddingLength + SubNodeVCNLength;
        if (option.VerboseOn)
        { /*If then*/
            _DumpOutput("Entry==" + std::to_string(EntryCounter));
            _DumpOutput("MFTReference==" + std::to_string(MFTReference));
            _DumpOutput("MFTReferenceSeqNo==" + std::to_string(MFTReferenceSeqNo));
            _DumpOutput("IndexEntryLength==" + std::to_string(IndexEntryLength));
            _DumpOutput("OffsetToFileName==" + std::to_string(OffsetToFileName));
            _DumpOutput("IndexFlags==" + std::to_string(IndexFlags));
            _DumpOutput("MFTReferenceOfParent==" + std::to_string(MFTReferenceOfParent));
            _DumpOutput("Indx_CTime==" + std::to_string(Indx_CTime));
            _DumpOutput("Indx_ATime==" + std::to_string(Indx_ATime));
            _DumpOutput("Indx_MTime==" + std::to_string(Indx_MTime));
            _DumpOutput("Indx_RTime==" + std::to_string(Indx_RTime));
            _DumpOutput("Indx_AllocSize==" + std::to_string(Indx_AllocSize));
            _DumpOutput("Indx_RealSize==" + std::to_string(Indx_RealSize));
            _DumpOutput("Indx_File_Flags==" + std::to_string(Indx_File_Flags));
            _DumpOutput("Indx_ReparseTag==" + std::to_string(Indx_ReparseTag));
            _DumpOutput("Indx_EaSize==" + std::to_string(Indx_EaSize));
            _DumpOutput("Indx_NameLength==" + std::to_string(Indx_NameLength));
            _DumpOutput("Indx_NameSpace==" + std::to_string(Indx_NameSpace));
            _DumpOutput("Indx_FileName==" + std::to_string(Indx_FileName));
            _DumpOutput("SubNodeVCN==" + std::to_string(SubNodeVCN));
            _DumpOutput("\r\n");
        } /*End of If*/

        // TODO FileWrite(LogFileIndxCsv, RecordOffset + de + this_lsn + de + EntryCounter + de + MFTReference + de + MFTReferenceSeqNo + de + IndexFlags + de + MFTReferenceOfParent + de + MFTReferenceOfParentSeqNo + de + Indx_CTime + de + Indx_ATime + de + Indx_MTime + de + Indx_RTime + de + Indx_AllocSize + de + Indx_RealSize + de + Indx_File_Flags + de + Indx_ReparseTag + de + Indx_EaSize + de + Indx_FileName + de + FileNameModified + de + Indx_NameSpace + de + SubNodeVCN + de + IsRedo);

        result.PredictedRefNumber = MFTReferenceOfParent;
        KeptRef = MFTReferenceOfParent;
        result.AttributeString = "$INDEX_ALLOCATION";
        if (!FromRcrdSlack)
        { /*If then*/
            if (Indx_NameSpace != "DOS")
            { /*If Then in one Line*/
                _UpdateFileNameArray(MFTReference, MFTReferenceSeqNo, Indx_FileName, this_lsn);
            }
        }
    } while (!(NextEntryOffset + 32 >= StringLen(Entry))); // Comment: /*Until*/

    return true;
}