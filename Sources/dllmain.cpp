#include <Windows.h>

#include "options.h"
#include "Commands/commands.h"
#include <Utils/crash_handler.h>

#include <iostream>
#include <filesystem>

#include "Drive/disk.h"
#include "Utils/utils.h"
#include "options.h"
//#include "Commands/commands.h"
#include "libntfsinfo.h"
#include "NTFS/ntfs.h"
#include "NTFS/ntfs_explorer.h"
#include "NTFS/ntfs_mft_record_mem.h"
#include "Utils/constant_names.h"
#include "Utils/path_finder.h"
#include "Utils/table.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <iterator>
#include <Utils/csv_file.h>
#include <Utils/json_file.h>

std::vector<LogFileFileRecord> g_records;
std::vector<UsnFileRecord> g_usn_records;

//#define OPEN_COUT 

std::wstring LogFileFileRecord::filename() const
{
    std::wstring filename(filename_pointer, filename_length);
    std::replace_if(filename.begin(), filename.end(), [](auto v) {
        return v == ':';
        }, L'|');
    return filename;
}

int is_ntfs(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol)
{
    if ((vol->filesystem() != "NTFS") && (vol->filesystem() != "Bitlocker"))
    {
        std::cerr << "[!] NTFS volume required" << std::endl;
        return 0;
    }
    return 1;
}

/// @brief windows 窄字符串转换为unicode字符串
/// @param local_str 输入的待转换的字符串
/// @param codepage utf8:65001 OEMCP:1 GB2313:936
/// @return 返回转换的字符串
inline std::wstring local_to_unicode(const std::string& local_str, int codepage = 0)
{
    std::wstring result;
    int minSize = ::MultiByteToWideChar(/*codepage*/ codepage, /*flags*/ 0, local_str.c_str(), local_str.length(), NULL, 0);
    if (minSize > 0)
    {
        result.resize(minSize);
        int ret = ::MultiByteToWideChar(/*codepage*/ codepage, /*flags*/ 0, local_str.c_str(), local_str.length(),
            (wchar_t*)result.data(), minSize);
        if ((ret > 0))
        {
            return result;
        }
    }
    return {};
}

/**
 * 类型为DeleteIndexEntryAllocation和AddIndexEntryAllocation时,LogRecord附带的客户端数据的结构
 */
struct LogFileIndexEntry
{
public:
    uint64_t mftIndex() const
    {
        return mft & 0xffffffffffffUL;
    }

    uint16_t mftUpdateSequenceCount() const
    {
        return mft >> 48;
    }

    uint64_t parentMftIndex() const
    {
        return mft_parent & 0xffffffffffffUL;
    }

    uint16_t parentMftUpdateSequenceCount() const
    {
        return mft_parent >> 48;
    }

    std::wstring filename() const
    {
        auto filename = std::wstring((wchar_t*)(this) + filename_offset, filename_length);
        std::replace_if(filename.begin(), filename.end(), [](auto v) {
            return v == ':';
            }, L'|');
        return filename;
    }

public:
    uint64_t mft;
    uint16_t entry_length;
    uint16_t filename_offset;
    uint16_t flags; // f
    uint16_t padding;

    uint64_t mft_parent;    // 父文件的mft索引,高位的2字节表示MFT记录的更新次数update sequence count
    FILETIME create_time; // 文件创建时间

    FILETIME access_time; // 文件访问时间
    FILETIME modify_time; // 文件修改时间

    FILETIME unknown_time;
    uint64_t allocate_size;// 文件分配空间大小

    uint64_t real_size; // 文件真实大小
    uint32_t file_flags;// 文件属性 FILE_ATTRIBUTE_ARCHIVE 等
    union {
        // file_flags有FILE_ATTRIBUTE_EA时,这位置的值是EaSize
        uint32_t EaSize;
        // file_flags没有FILE_ATTRIBUTE_EA时,这位置的值是ReparseTag
        uint32_t ReparseTag;
    } file_flags_data;

    uint8_t filename_length;// 文件名长度
    uint8_t filename_namespace;// 文件名类型 0-posix 1-win32 2-dos 3-dos+win32

    // 文件名变长数组,
    wchar_t filename_pointer[1];

    // 整个结构体大小不是8的整数的,后面需要补齐8字节
};

#ifdef _DEBUG
#define _DumpOutputPrintf(...) printf("[CPP] " __VA_ARGS__)
static inline void _DumpOutput(std::string msg)
{
#ifdef OPEN_COUT 
    std::cout << "[CPP] " << msg << std::endl;
#endif
    //_DumpOutputPrintf(msg.c_str());
}
#else
#define _DumpOutputPrintf(...) void(0);
#define _DumpOutput(...) void(0);
#endif

bool My_Decode_IndexEntry(std::string_view Entry, int AttrType, bool IsRedo);

void ParseMft(std::string_view Entry, std::shared_ptr<NTFSReader> reader)
{
    const char* pBuffer = Entry.data();
    const auto pEntry = PMFT_RECORD_HEADER(pBuffer);
    if (!MFTRecordMem::is_valid(pEntry))
    {
        return;
    }

    MFTRecordMem mft(Entry, reader->sizes);
    auto header = mft.attribute_header($FILE_NAME);
    if (header != nullptr)
    {
        auto pattr_filename = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_FILENAME, header, header->Form.Resident.ValueOffset);

        // 复制数据结构
        LogFileFileRecord record;
        record.mft = pEntry->MFTRecordIndex | (uint64_t)pEntry->sequenceNumber << 48;
        record.file_flags = pattr_filename->FileAttributes;
        record.mft_parent = pattr_filename->ParentDirectory.FileRecordNumber | ((uint64_t)pattr_filename->ParentDirectory.SequenceNumber << 48);
        record.create_time = *(FILETIME*)(&pattr_filename->CreationTime);
        record.access_time = *(FILETIME*)(&pattr_filename->LastAccessTime);
        record.modify_time = *(FILETIME*)(&pattr_filename->LastWriteTime);
        record.unknown_time = *(FILETIME*)(&pattr_filename->ChangeTime);
        record.allocate_size = pattr_filename->AllocatedSize;
        record.real_size = pattr_filename->DataSize;
        record.file_flags_data.EaSize = pattr_filename->Extended.EaInfo.PackedEaSize;
        record.filename_length = pattr_filename->NameLength;
        record.filename_namespace = pattr_filename->NameType;

        if (record.filename_length < MAX_PATH)
        {
            auto filename = mft.filename();
            memcpy(record.filename_pointer, filename.c_str(), record.filename_length * 2);
            record.filename_pointer[record.filename_length] = 0;

            g_records.emplace_back(record);
        }
    }
}

/**
 * 数据结构修复
 */
void fixup_sequence(PRECORD_PAGE_HEADER prh)
{
    if (prh->update_sequence_array_count > 1)
    {
        PWORD pfixup = POINTER_ADD(PWORD, prh, prh->update_sequence_array_offset);
        DWORD offset = 0x200 - sizeof(WORD);
        for (int i = 1; i < prh->update_sequence_array_count; i++)
        {
            if (*POINTER_ADD(PWORD, prh, offset) == pfixup[0])
            {
                *POINTER_ADD(PWORD, prh, offset) = pfixup[i];
            }
            offset += 0x200;
            if (offset > 0x1000 - sizeof(WORD))
            {
                break;
            }
        }
    }
}

PRESTART_PAGE_HEADER find_newest_restart_page(PBYTE logfile)
{
    PRESTART_PAGE_HEADER newestRestartPageHeader = nullptr;

    PRESTART_PAGE_HEADER prstpage0 = POINTER_ADD(PRESTART_PAGE_HEADER, logfile, 0);
    PRESTART_PAGE_HEADER prstpage1 = POINTER_ADD(PRESTART_PAGE_HEADER, logfile, 4096);
    PRESTART_AREA prstarea0 = POINTER_ADD(PRESTART_AREA, prstpage0, prstpage0->restart_area_offset);
    PRESTART_AREA prstarea1 = POINTER_ADD(PRESTART_AREA, prstpage1, prstpage1->restart_area_offset);
    if (prstarea0->current_lsn > prstarea1->current_lsn)
    {
        newestRestartPageHeader = prstpage0;
    }
    else
    {
        newestRestartPageHeader = prstpage1;
    }

    return newestRestartPageHeader;
}

std::vector<std::string> get_log_clients(PRESTART_AREA ra)
{
    std::vector<std::string> ret;
    WORD log_clients_count = ra->log_clients;
    if (log_clients_count != MFT_LOGFILE_NO_CLIENT)
    {
        PLOG_CLIENT_RECORD plcr = POINTER_ADD(PLOG_CLIENT_RECORD, ra, ra->client_array_offset);
        for (int i = 0; i < log_clients_count; i++)
        {
            std::wstring client_name = std::wstring(plcr->client_name);
            client_name.resize(plcr->client_name_length);
            ret.push_back(utils::strings::to_utf8(client_name));
            plcr = POINTER_ADD(PLOG_CLIENT_RECORD, plcr, plcr->next_client);
        }
    }
    return ret;
}

void _add_record(std::shared_ptr<FormatteddFile> ffile, PRECORD_LOG rl)
{
    ffile->add_item(rl->lsn);
    ffile->add_item(rl->client_previous_lsn);
    ffile->add_item(rl->client_undo_next_lsn);
    ffile->add_item(rl->client_id.client_index);
    ffile->add_item(rl->record_type);
    ffile->add_item(rl->transaction_id);
    ffile->add_item(constants::disk::logfile::operation(rl->redo_operation));
    ffile->add_item(constants::disk::logfile::operation(rl->undo_operation));
    ffile->add_item(rl->mft_cluster_index);
    ffile->add_item(rl->target_vcn);
    ffile->add_item(rl->target_lcn);

    ffile->new_line();
}

/* 打印logfile指定的日志文件数据
 * @param format 文档格式,json 或 csv
 * @param output 输出文件路径
 * @param logfile 日志文件的内存数据
 *
*/
void dump_logdata(const std::shared_ptr<Buffer<PBYTE>>& logFileData, std::shared_ptr<NTFSExplorer> explorer)
{
    auto reader = explorer->reader();

    PRESTART_PAGE_HEADER newest_restart_header = find_newest_restart_page(logFileData->data());
    PRESTART_AREA newest_restart_area = POINTER_ADD(PRESTART_AREA, newest_restart_header, newest_restart_header->restart_area_offset);

    std::cout << "[-] Newest Restart Page LSN : " << std::to_string(newest_restart_area->current_lsn) << std::endl;

    if (newest_restart_area->flags & MFT_LOGFILE_RESTART_AREA_FLAG_VOLUME_CLEANLY_UNMOUNTED)
    {
        std::cout << "[!] Volume marked as not cleanly unmounted" << std::endl;
    }
    else
    {
        std::cout << "[-] Volume marked as cleanly unmounted" << std::endl;
    }

    //////////

    DWORD client_i = 1;
    for (auto& client : get_log_clients(newest_restart_area))
    {
        std::cout << "[-] Client found : [" << std::to_string(client_i++) << "] " << client << std::endl;
    }

    //////////

    std::cout << "[+] Parsing $LogFile Record Pages" << std::endl;

    std::vector<PRECORD_PAGE_HEADER> record_page_offsets;

    // modify by k1988 4=>2
    // 按页面大小将每个开头为RCRD的页插入队列
    for (DWORD offset = /*4*/ 2 * newest_restart_header->log_page_size; offset < logFileData->size(); offset += newest_restart_header->log_page_size)
    {
        PRECORD_PAGE_HEADER prh = POINTER_ADD(PRECORD_PAGE_HEADER, logFileData->data(), offset);

        // 这种方式,容易漏掉多跨页的Record Page?? 应该不会,因为分页后也是RCRD开头
        if (memcmp(prh->magic, "RCRD", 4) != 0) {
            continue;
        }
        record_page_offsets.push_back(prh);
    }

    std::cout << "[-] $LogFile Record Page Count : " << std::to_string(record_page_offsets.size()) << std::endl;

    /////////
    std::cout << "[-] Parsing $LogFile Records" << std::endl;

    Buffer<PBYTE> leftover_buffer(8 * 4096);
    // 某个跨页记录在第一页中的字节数
    DWORD leftover_size = 0;
    // 某个跨页记录还缺的字节数
    DWORD leftover_missing_size = 0;
    DWORD processed = 0;

    // 用于验证usn页的变量
    int64_t last_lsn_tmp = 0;
    int64_t last_end_lsn_tmp = 0;

    // 解析每个页
    for (PRECORD_PAGE_HEADER prh : record_page_offsets)
    {
        uint64_t page_offset = (PBYTE)prh - logFileData->data();

#ifdef _DEBUG
        std::set<uint64_t> care_pos = {
            // 0x0000d000,
             0x00013000,// lsn 1148978 里有删除9CF7.tmp的记录
        };
        if (care_pos.count(page_offset))
        {
            int i = 0;
            i++;
        }
#endif

        fixup_sequence(prh);

        DWORD offset = 64;// 
        DWORD index = 1;

        if (leftover_size > 0)
        {
            // 这一块数据中用来补齐前页的字节数
            DWORD used_count = (min(leftover_missing_size, 4096 - offset));
            memcpy(leftover_buffer.data() + leftover_size, POINTER_ADD(PBYTE, prh, offset), used_count);
            leftover_missing_size -= used_count;
            offset += used_count;

            // 如果补齐了一整个记录,则直接使用
            if (leftover_missing_size == 0)
            {
                leftover_size = 0;
               // _add_record(ffile, POINTER_ADD(PRECORD_LOG, leftover_buffer.data(), 0));

                auto prl = POINTER_ADD(PRECORD_LOG, leftover_buffer.data(), 0);
                if (prl->lsn == 0 || prl->record_type == 0 || prl->record_type > 37)
                {
                    continue;
                }

                // 验证数据是否正确
                if (prl->redo_length > prl->client_data_length
                    || prl->undo_length > prl->client_data_length)
                {
                    // 错误数据,跳过
                    _DumpOutput("Found error record offset with multi page 0x" + utils::format::hex6(offset + page_offset)); 
                    continue;
                }

                std::string_view redo_chunk;
                std::string_view undo_chunk;

                // DeleteIndexEntryAllocation
                if (prl->redo_operation == LOG_RECORD_OP_ADD_INDEX_ENTRY_ALLOCATION)
                {
                    if (prl->redo_length > 0)
                    {
                        redo_chunk = std::string_view((char*)prl + MFT_LOGFILE_LOG_RECORD_HEADER_SIZE + prl->redo_offset, prl->redo_length);
                        My_Decode_IndexEntry(redo_chunk, prl->redo_operation, true);
                    }
                }
                
                // AddIndexEntryAllocation 删除文件
                if (prl->undo_operation == LOG_RECORD_OP_ADD_INDEX_ENTRY_ALLOCATION)
                {
                    if (prl->undo_length > 0)
                    {
                        undo_chunk = std::string_view((char*)prl + MFT_LOGFILE_LOG_RECORD_HEADER_SIZE + prl->undo_offset, prl->undo_length);

                        // 这里继续处理删除文件的日志
                       // std::cout << std::endl << "file delete record..." << std::endl;
                        My_Decode_IndexEntry(undo_chunk, prl->undo_operation, false);
                    }
                }

                if (prl->undo_operation == LOG_RECORD_OP_INITIALIZE_FILE_RECORD_SEGMENT && prl->undo_length > sizeof(MFT_RECORD_HEADER))
                {
                    ParseMft(undo_chunk, reader);
                }

                processed++;
#ifdef OPEN_COUT 
                std::cout << "\r[-] $LogFile Record Count : " << std::to_string(processed) + "     ";
#endif
            }
            else
            {
                continue;
            }
        }

        index = 1;
        DWORD stop = min(prh->header.packed.next_record_offset + MFT_LOGFILE_LOG_RECORD_HEADER_SIZE, 4096 - MFT_LOGFILE_LOG_RECORD_HEADER_SIZE);

        // 解析头后面的日志记录
        int error = 0;
        while (offset < stop)
        {
            if (error > 1)
            {
                break;
            }

            PRECORD_LOG prl = POINTER_ADD(PRECORD_LOG, prh, offset);

            // 检查当前位置是不是正确的RECORD_LOG
            int64_t CharsToMove = 0;
            bool FromRcrdSlack = false;

            last_lsn_tmp = prh->copy.last_lsn;
            last_lsn_tmp = prh->header.packed.last_end_lsn;
            int64_t max_last_lsn = max(last_lsn_tmp, last_end_lsn_tmp);

            // 计算上下限
            const auto lsnValidationLevel = 0.1f;
            auto last_lsn_tmp_refup = std::round(max_last_lsn * (1 + lsnValidationLevel));
            auto last_lsn_tmp_refdown = std::round(max_last_lsn * (1 - lsnValidationLevel));

            if ((prl->lsn > max_last_lsn) || (prl->client_previous_lsn > max_last_lsn) || (prl->client_undo_next_lsn > max_last_lsn) || (prl->lsn < last_lsn_tmp_refdown) || (prl->client_previous_lsn < last_lsn_tmp_refdown && prl->client_previous_lsn != 0) || (prl->client_undo_next_lsn < last_lsn_tmp_refdown && prl->client_undo_next_lsn != 0))
            {
#ifdef OPEN_COUT 
                _DumpOutputPrintf("Scanning for LSN signature from RCRD offset: 0x%s\r\n", utils::format::hex(offset + page_offset, false, false).c_str());
                // 	_DumpOutput("DoNotreturn 0;Data: "  DoNotreturn 0;Data +  "\r\n");
                // 	_DumpOutput("OffsetAdjustment: "  OffsetAdjustment +  "\r\n");
                // 	_DumpOutput("last_lsn_tmp: "  last_lsn_tmp +  "\r\n");
                // 	_DumpOutput("last_end_lsn_tmp: "  last_end_lsn_tmp +  "\r\n");
                // 	_DumpOutput("max_last_lsn: "  max_last_lsn +  "\r\n");
                // 	_DumpOutput("last_lsn_tmp_refup: "  last_lsn_tmp_refup +  "\r\n");
                // 	_DumpOutput("last_lsn_tmp_refdown: "  last_lsn_tmp_refdown +  "\r\n");
                // 	_DumpOutput("NextOffset: "  NextOffset +  "\r\n");
                // 	_DumpOutput("CharsToMove: "  CharsToMove +  "\r\n");
#endif

                bool LsnSignatureFound = false;
                while (true)
                {
                    if (CharsToMove + offset > stop)
                    {
                        break;
                    }
                    PRECORD_LOG prlTest = POINTER_ADD(PRECORD_LOG, prh, CharsToMove + offset);
                    int64_t TestChunk1 = prlTest->lsn;
                    // 		_DumpOutput("TestChunk1: "  TestChunk1 +  "\r\n")

                    if ((TestChunk1 > last_lsn_tmp_refdown) && (TestChunk1 < last_lsn_tmp_refup))
                    {
                        int64_t TestChunk2 = prlTest->client_previous_lsn;
                        int64_t TestChunk3 = prlTest->client_undo_next_lsn;
                        // 			_DumpOutput("TestChunk3: "  TestChunk3 +  "\r\n");
                        if (((TestChunk2 > last_lsn_tmp_refdown) && (TestChunk2 < last_lsn_tmp_refup)) || (TestChunk2 == 0))
                        {
                            if (((TestChunk3 > last_lsn_tmp_refdown) && (TestChunk3 < last_lsn_tmp_refup)) || (TestChunk3 == 0))
                            {
                                // ConsoleWrite("Match1!!!"   "\r\n");
                                LsnSignatureFound = true;
                                break;
                            }
                            else
                            {
                                // ConsoleWrite("False positive"   "\r\n");
                                CharsToMove += 8;
                                continue;
                            }
                        }
                        else
                        {
                            //			ConsoleWrite("False positive"   "\r\n");
                            CharsToMove += 8;
                            continue;
                        }
                        // 			ConsoleWrite("Match2!!!"   "\r\n");
                        // 			break;
                    }

                    CharsToMove += 8;
                    if (CharsToMove + offset > stop)
                    {
                        break;
                    }
                } // end of while

                if (!LsnSignatureFound)
                {
                    _DumpOutput("LSN signature not found:");
                    //_DumpOutputHex(/*_HexEncode*/(StringMid(RCRDRecord, NextOffset)));
                    error++;
                    continue;
                }
                else
                {
                    if (CharsToMove > 0)
                    {
#ifdef DISABLE_CODE
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
#endif
                    }
                    _DumpOutput("Found LSN signature match at record offset 0x" + utils::format::hex6(offset + page_offset + CharsToMove));
                    offset += CharsToMove;
                }
                FromRcrdSlack = 1;
            }
            else
            {
                FromRcrdSlack = 0;
            }

            prl = POINTER_ADD(PRECORD_LOG, prh, offset);
            if (prl->lsn == 0 || prl->record_type == 0 || prl->record_type > 37)
            {
                error++;
                offset = prh->header.packed.next_record_offset;
                continue;
            }

#ifdef _DEBUG
            static std::set<uint64_t> care_lsn = {
                 1148978,//创建9CF7.tmp的记录
                 1149664,//删除9CF7.tmp的记录
                 2207502, // $undo_operation: AddindexEntryRoot test.txt 
                 2207526, // $undo_operation: InitializeFileRecordSegment test.txt 
            };
            if (care_lsn.count(prl->lsn))
            {
                int i = 0;
                i++;
            }
#endif

            // 验证数据是否正确
            if (prl->redo_length > prl->client_data_length
                || prl->undo_length > prl->client_data_length)
            {
                // 错误数据,跳过
                _DumpOutput("Found error record offset 0x" + utils::format::hex6(offset + page_offset + CharsToMove));
                offset += MFT_LOGFILE_LOG_RECORD_HEADER_SIZE + prl->client_data_length;
                continue;
            }

            // 跳转到下一个record开头
            offset += MFT_LOGFILE_LOG_RECORD_HEADER_SIZE + prl->client_data_length;

            if (prl->flags & LOG_RECORD_MULTI_PAGE)
            {
                memcpy(leftover_buffer.data(), prl, 4096 - prh->header.packed.next_record_offset);
                leftover_size = 4096 - prh->header.packed.next_record_offset;
                leftover_missing_size = prl->client_data_length - (leftover_size - MFT_LOGFILE_LOG_RECORD_HEADER_SIZE);
            }
            else
            {
                std::string_view redo_chunk;
                std::string_view undo_chunk;

                // DeleteIndexEntryAllocation
                if (prl->redo_operation == LOG_RECORD_OP_ADD_INDEX_ENTRY_ALLOCATION)
                {
                    if (prl->redo_length > 0)
                    {
                        redo_chunk = std::string_view((char*)prl + MFT_LOGFILE_LOG_RECORD_HEADER_SIZE + prl->redo_offset, prl->redo_length);
                        My_Decode_IndexEntry(redo_chunk, prl->redo_operation, true);
                    }
                }
                if (prl->undo_length > 0)
                {
                    undo_chunk = std::string_view((char*)prl + MFT_LOGFILE_LOG_RECORD_HEADER_SIZE + prl->undo_offset, prl->undo_length);

                    // AddIndexEntryAllocation 删除文件 LOG_RECORD_OP_DEALLOCATE_FILE_RECORD_SEGMENT
                    if (prl->undo_operation == LOG_RECORD_OP_ADD_INDEX_ENTRY_ALLOCATION||
                        prl->undo_operation == LOG_RECORD_OP_ADD_INDEX_ENTRY_ROOT)
                    {
                        // 这里继续处理删除文件的日志
                       // std::cout << std::endl << "file delete record..." << std::endl;
                        My_Decode_IndexEntry(undo_chunk, prl->undo_operation, false);

                    }
                    else if (prl->undo_operation == LOG_RECORD_OP_INITIALIZE_FILE_RECORD_SEGMENT && prl->undo_length > sizeof(MFT_RECORD_HEADER))
                    {
                        ParseMft(undo_chunk, reader);
                    }
                }
                processed++;
               // std::cout << "\r[-] $LogFile Record Count : " << std::to_string(processed) + "     ";
            }
        }
    }
}

int print_logfile_records(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol)
{
    if (!is_ntfs(disk, vol)) return 1;

    utils::ui::title("LogFile from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

    std::cout << "[+] Opening " << vol->name() << std::endl;

    std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

    std::cout << "[+] Reading $LogFile record" << std::endl;
    std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_number(LOG_FILE_NUMBER);

    ULONG64 total_size = record->datasize();
    std::cout << "[+] $LogFile size : " << utils::format::size(total_size) << std::endl;

    std::shared_ptr<Buffer<PBYTE>> logfile = record->data();
    dump_logdata(logfile, explorer);

    // 恢复全路径
    std::shared_ptr<PathFinder> pf = std::make_shared<PathFinder>(vol, true);
    std::cout << "[+] " << pf->count() << " $MFT records loaded" << std::endl;
    for (auto& log : g_records)
    {
        // 返回 "volume:\\" 或 "orphan:\\" 开头
        auto path = pf->get_file_path(utils::strings::to_utf8(log.filename()), log.mft);
#define UTF8_CODE 65001
        auto filename = local_to_unicode(path, UTF8_CODE);
        filename.erase(0, strlen("volume:\\"));
        if (filename.length() >= MAX_PATH)
        {
            continue;
        }
        memcpy(log.filename_pointer, filename.c_str(), filename.length() * 2);
        log.filename_pointer[filename.length()] = 0;
    }

    std::cout << std::endl << "[+] Closing volume" << std::endl;

    return 0;
}

void process_usn(std::shared_ptr<NTFSExplorer> explorer, std::shared_ptr<MFTRecord> record_usn, std::shared_ptr<PathFinder> path_finder, bool full_mode)
{
    ULONG64 processed_size = 0;
    ULONG64 processed_count = 0;

    Buffer<PBYTE> clusterBuf((DWORD64)2 * 1024 * 1024);
    ULONG64 filled_size = 0;

    for (auto& block : record_usn->process_data(MFT_ATTRIBUTE_DATA_USN_NAME, explorer->reader()->sizes.cluster_size, true))
    {
        processed_size += block.second;

        if ((processed_count % 100) == 0)
        {
            std::cout << "\r[+] Processing USN records: " << std::to_string(processed_count) << " (" << utils::format::size(processed_size) << ")     ";
        }

        if (filled_size)
        {
            break;
        }

        memcpy(clusterBuf.data() + filled_size, block.first, block.second);
        filled_size += block.second;

        PUSN_RECORD_COMMON_HEADER header = (PUSN_RECORD_COMMON_HEADER)clusterBuf.data();
        while ((filled_size > 0) && (header->RecordLength <= filled_size))
        {
            switch (header->MajorVersion)
            {
            case 0:
            {
                DWORD i = 0;
                while ((i < filled_size) && (POINTER_ADD(PWORD, header, i)[0] == 0))
                {
                    i += 2;
                }
                header = POINTER_ADD(PUSN_RECORD_COMMON_HEADER, header, i);
                filled_size -= i;
                break;
            }
            case 2:
            {
                processed_count++;

                PUSN_RECORD_V2 usn_record = (PUSN_RECORD_V2)header;
                if (!(usn_record->Reason & USN_REASON_FILE_DELETE))
                {
                    filled_size -= usn_record->RecordLength;
                    header = POINTER_ADD(PUSN_RECORD_COMMON_HEADER, header, usn_record->RecordLength);
                    break;
                }

                std::wstring filename = std::wstring(usn_record->FileName);
                filename.resize(usn_record->FileNameLength / sizeof(WCHAR));

                UsnFileRecord record;
                record.usn = usn_record->Usn;
                record.file_reference.mft = usn_record->FileReferenceNumber & 0xffffffffffff;
                record.file_reference.update_count = usn_record->FileReferenceNumber >> 4;
                record.parent_file_reference.mft = usn_record->ParentFileReferenceNumber & 0xffffffffffff;
                record.parent_file_reference.update_count = usn_record->ParentFileReferenceNumber >> 4;

                record.file_attribute = usn_record->FileAttributes;
                record.reason_flags = usn_record->Reason;
                record.update_time = *(FILETIME*)(&usn_record->TimeStamp);
                if (filename.length() >= MAX_PATH)
                {
                    break;
                }
                if (full_mode)
                {
                    // 返回 "volume:\\" 或 "orphan:\\" 开头
                    auto path = path_finder->get_file_path(utils::strings::to_utf8(filename), usn_record->ParentFileReferenceNumber);
#define UTF8_CODE 65001
                    filename = local_to_unicode(path, UTF8_CODE);
                    filename.erase(0, strlen("volume:\\"));
                }

                if (filename.length() >= MAX_PATH)
                {
                    break;
                }
                memcpy(record.filename, filename.c_str(), filename.length()*2);
                record.filename[filename.length()] = 0;
                g_usn_records.emplace_back(record);

                filled_size -= usn_record->RecordLength;
                header = POINTER_ADD(PUSN_RECORD_COMMON_HEADER, header, usn_record->RecordLength);
                break;
            }
            default:
                return;
            }
        }

        if (filled_size <= clusterBuf.size())
        {
            memcpy(clusterBuf.data(), header, (size_t)filled_size);
        }
    }
    std::cout << "\r[+] Processing USN records: " << std::to_string(processed_count) << " (" << utils::format::size(processed_size) << ")     ";
}

int print_usn_records(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol)
{
    if (!is_ntfs(disk, vol)) return 1;

    utils::ui::title("Dump USN journal for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

    std::shared_ptr<PathFinder> pf = nullptr;   
    {
        pf = std::make_shared<PathFinder>(vol, true);
        //std::cout << "[+] " << pf->count() << " $MFT records loaded" << std::endl;
    }

    std::cout << "[+] Opening " << vol->name() << std::endl;
    std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

    std::cout << "[+] Finding $Extend\\$UsnJrnl record" << std::endl;
    std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_path("\\$Extend\\$UsnJrnl");
    if (record == nullptr)
    {
        std::cout << "[!] Not found" << std::endl;
        return 2;
    }
    std::cout << "[+] Found in file record: " << std::to_string(record->header()->MFTRecordIndex) << std::endl;

    ULONG64 total_size = record->datasize(MFT_ATTRIBUTE_DATA_USN_NAME, true);
    std::cout << "[+] $J stream size: " << utils::format::size(total_size) << " (could be sparse)" << std::endl;

    process_usn(explorer, record, pf, true);

    std::cout << std::endl << "[+] Closing volume" << std::endl;

    return 0;
}

// AttrType
bool My_Decode_IndexEntry(std::string_view Entry, int AttrType, bool IsRedo)
{
    const char* pBuffer = Entry.data();
    const auto pEntry = reinterpret_cast<const LogFileIndexEntry*>(pBuffer);

    // 验证数据是否合法
    if (pEntry->entry_length < sizeof(LogFileIndexEntry))
    {
        return false;
    }

    if (pEntry->filename_offset + pEntry->filename_length > Entry.size())
    {
        return false;
    }

    if (pEntry->filename_namespace > 3)
    {
        return false;
    }

    // 仅undo并且undo是恢复文件时才有效
    if (!IsRedo && (
        AttrType == LOG_RECORD_OP_ADD_INDEX_ENTRY_ALLOCATION
        || AttrType == LOG_RECORD_OP_ADD_INDEX_ENTRY_ROOT))
    {
        LogFileFileRecord record;
        memcpy(&record, pBuffer, Entry.size());
        record.filename_pointer[record.filename_length] = 0;
        g_records.emplace_back(record);
    }

#ifdef _DEBUG
#ifdef OPEN_COUT 
    { /*If then*/
        _DumpOutput("_Decode_IndexEntry():");

        _DumpOutput("Error MFTReference: " + std::to_string(pEntry->mftIndex()));
        _DumpOutput("Error MFTReferenceSeqNo: " + std::to_string(pEntry->mftUpdateSequenceCount()));
        _DumpOutput("Error MFTReferenceOfParent: " + std::to_string(pEntry->parentMftIndex()));
        _DumpOutput("Error MFTReferenceOfParentSeqNo: " + std::to_string(pEntry->mftUpdateSequenceCount()));
        _DumpOutput("Error Indx_NameLength: " + std::to_string(pEntry->filename_length));

        std::string Indx_NameSpace;
        switch (pEntry->filename_namespace)
        {
        case 0:
            Indx_NameSpace = "POSIX";
            break;
        case 1:
            Indx_NameSpace = "WIN32";
            break;
        case 2:
            Indx_NameSpace = "DOS";
            break;
        case 3:
            Indx_NameSpace = "DOS+WIN32";
            break;
        default:
            assert(false);
        }

        auto filename = pEntry->filename();
    }
#endif
#endif

    if (AttrType == LOG_RECORD_OP_ADD_INDEX_ENTRY_ROOT || AttrType == LOG_RECORD_OP_DELETE_INDEX_ENTRY_ROOT)
    { /*If Then in one Line*/
       // result.AttributeString = "$INDEX_ROOT";
    }

    if (AttrType == LOG_RECORD_OP_ADD_INDEX_ENTRY_ALLOCATION || AttrType == LOG_RECORD_OP_DELETE_INDEX_ENTRY_ALLOCATION)
    { /*If Then in one Line*/
        //result.AttributeString = "$INDEX_ALLOCATION";
    }
    return true;
}

extern "C" __declspec(dllexport) int InitNtfsTool()
{
	if (!utils::processes::elevated(GetCurrentProcess()))
	{
		std::cerr << "Administrator rights are required to read physical drives" << std::endl;
		return 1;
	}
    return 0;
}
extern "C" __declspec(dllexport) void DeinitNtfsInfo()
{

}

extern "C" __declspec(dllexport) int GetDeleteRecordsByFileRecord(int disk_index, uint64_t volume_offset, LogFileFileRecord** records, int* count)
{
    g_records.clear();
    std::shared_ptr<Disk> disk = core::win::disks::by_index(disk_index);;
    if (disk != nullptr)
    {
        for (auto volume: disk->volumes())
        {
            if (volume != nullptr && volume->offset() == volume_offset)
            {
                print_logfile_records(disk, volume);
                *records = g_records.data();
                *count = g_records.size();
                return 0;
            }
        }
    }
    return 1;
}

extern "C" __declspec(dllexport) int GetDeleteRecords(int disk_index, uint64_t volume_offset, UsnFileRecord** records, int* count)
{
    g_usn_records.clear();
    std::shared_ptr<Disk> disk = core::win::disks::by_index(disk_index);;
    if (disk != nullptr)
    {
        for (auto volume : disk->volumes())
        {
            if (volume != nullptr && volume->offset() == volume_offset)
            {
                print_usn_records(disk, volume);

                *records = g_usn_records.data();
                *count = g_usn_records.size();
                return 0;
            }
        }
    }
    return 1;
}

extern "C" __declspec(dllexport) int ReadFromMft(int disk_index, uint64_t volume_offset, uint64_t mft, int(*on_data)(char* buffer, int size))
{
    std::shared_ptr<Disk> disk = core::win::disks::by_index(disk_index);;
    if (disk != nullptr)
    {
        for (auto volume : disk->volumes())
        {
            if (volume != nullptr && volume->offset() == volume_offset)
            {
#ifdef OPEN_COUT 
                std::cout << "[+] Opening " << volume->name() << std::endl;
#endif
                std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(volume);
#ifdef OPEN_COUT 
                std::cout << "[+] Finding file record" << std::endl;
#endif
                std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_number(mft & 0xffffffffffffUL);
                if (!record)
                {
                    return MFT_ERROR_NOT_FOUND;
                }

                auto sequenceCount = mft >> 48;
                // 允许MFT索引加1,这是因为删除文件本身会使mft更新
                if (record->header()->sequenceNumber > sequenceCount + 1)
                {
                    // 更新次数不同于表示该mft已经发生变化,原文件已经被覆盖,所以无法读取
#ifdef OPEN_COUT 
                    std::cout << "原文件已经被覆盖,所以无法读取 " << pRecord.mftUpdateSequenceCount() << " - " << record->header()->sequenceNumber;
#endif
                    return MFT_ERROR_OVERRIDE;
                }
                else
                {
                    auto bytes = record->data_to_callback(on_data, {});
                }
                return 0;
            }
        }

        return MFT_ERROR_VOLUME_NOT_FOUND;
    }
    else
    {
        return MFT_ERROR_DISK_NOT_FOUND;
    }
}

int test_on_data(char* buffer, int size)
{
    std::cout << size << " : " << buffer << std::endl;
    return size;
}

void TestReadFileByMft(int disk_index, uint64_t volume_offset, LogFileFileRecord pRecord)
{
    std::shared_ptr<Disk> disk = core::win::disks::by_index(disk_index);;
    if (disk != nullptr)
    {
        for (auto volume : disk->volumes())
        {
            if (volume != nullptr && volume->offset() == volume_offset)
            {
                std::cout << "[+] Opening " << volume->name() << std::endl;
                std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(volume);

                std::cout << "[+] Finding file record" << std::endl;
                std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_number(pRecord.mftIndex());

                // 允许MFT索引加1,这是因为删除文件本身会使mft更新
                if (record->header()->sequenceNumber > pRecord.mftUpdateSequenceCount() + 1)
                {
                    // 更新次数不同于表示该mft已经发生变化,原文件已经被覆盖,所以无法读取
                    std::cout << "原文件已经被覆盖,所以无法读取 " << pRecord.mftUpdateSequenceCount() << " - " << record->header()->sequenceNumber;
                }
                else
                {
                    std::wcout << pRecord.filename_pointer;
                    auto bytes = record->data_to_callback(&test_on_data,{});
                }
                return ;
            }
        }
    }
}

void main()
{
    // D盘
    //const auto disk_index = 1;
    //const auto volume_offset = 16777216;


#ifdef _DEBUG
    // W
    const auto disk_index = 2;
    const auto volume_offset = 52642709504;

    LogFileFileRecord* records = nullptr;
    int count = 0;
    GetDeleteRecordsByFileRecord(disk_index, volume_offset, &records, &count);
    std::cout << "log records: " << count;

    for (auto i = 0; i < count; i++)
    {
        if (records[i].filename() == L"test.txt"
            || records[i].filename() == L"d_megadrive.cpp")
        {
            TestReadFileByMft(disk_index, volume_offset, records[i]);
        }
    }

    UsnFileRecord* usn_records = nullptr;
    int usn_count = 0;
    GetDeleteRecords(disk_index, volume_offset, &usn_records, &usn_count);
    std::cout << "usn records: " << count;

    // 找一个文件,读取所有MFT
    int a;
    std::cin >> a;
#endif
}