#include "Drive/disk.h"
#include "Utils/utils.h"
#include "options.h"
#include "Commands/commands.h"
#include "NTFS/ntfs.h"
#include "NTFS/ntfs_explorer.h"
#include "Utils/constant_names.h"
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

#include "ntfsdump_logfile_ext.h"


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


#define _DumpOutputPrintf(...) printf("[CPP] " __VA_ARGS__)
static inline void _DumpOutput(std::string msg)
{
    std::cout << "[CPP] " << msg << std::endl;
    //_DumpOutputPrintf(msg.c_str());
}
int64_t My_Decode_IndexEntry(std::string_view Entry, int AttrType, bool IsRedo);

// 打印Hex表格,格式:
//0000	31 7c 10 00 00 00 00 00  a3 7b 10 00 00 00 00 00   1 | .......{......
static inline void _DumpOutputHex(std::string msg)
{
    auto i = 0;
    auto line = (msg.size() + 15) / 16;
    for (; i < line; i++)
    {
        // 字节索引表,2个hex为1个字节
        std::cout << std::hex << std::setw(4) << std::setfill('0') << 16 * i << "\t";

        // 右侧明文表
        std::string plainText;

        // 中间字节
        for (auto j = i * 16; j < (i * 16) + 16; j += 1)
        {
            // 每8个多加一个空格
            if ((j % 16) == 8)
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
                auto byte = (BYTE)msg[j];
                std::cout << utils::format::hex((BYTE)byte) << " ";

                // 对于可见字符插入明文表
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
void dump_logdata(const std::string& format, std::string output, const std::shared_ptr<Buffer<PBYTE>>& logFileData)
{
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
        if (memcmp(prh->magic, "RCRD", 4) != 0) {
            continue;
        }
        record_page_offsets.push_back(prh);
    }

    std::cout << "[-] $LogFile Record Page Count : " << std::to_string(record_page_offsets.size()) << std::endl;

    /////////

    std::shared_ptr<FormatteddFile> ffile;

    if (format == "csv")
    {
        ffile = std::make_shared<CSVFile>(output);
    }
    else
    {
        ffile = std::make_shared<JSONFile>(output);
    }

    ffile->set_columns(
        {
            "LSN",
            "ClientPreviousLSN",
            "UndoNextLSN",
            "ClientID",
            "RecordType",
            "TransactionID",
            "RedoOperation",
            "UndoOperation",
            "MFTClusterIndex",
            "TargetVCN",
            "TargetLCN"
        }
    );

    std::cout << "[-] Parsing $LogFile Records" << std::endl;

    Buffer<PBYTE> leftover_buffer(8 * 4096);
    DWORD leftover_size = 0;
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

		// 转换为hex字节串
		{
			/*std::string_view pageData((char*)prh, newest_restart_header->log_page_size);*/
			auto pageData = utils::convert::to_hex((char*)prh, newest_restart_header->log_page_size, false);
			pageData.insert(0, "  ");
			pageData = _DoFixup(pageData, page_offset);
			_DecodeRCRD(pageData, page_offset, 0, 1);
		}		

        fixup_sequence(prh);

        DWORD offset = 64;// 
        DWORD index = 1;

        if (leftover_size > 0)
        {
            memcpy(leftover_buffer.data() + leftover_size, POINTER_ADD(PBYTE, prh, offset), min(leftover_missing_size, 4096 - offset));
            leftover_missing_size -= min(leftover_missing_size, 4096 - offset);

            if (leftover_missing_size == 0)
            {
                _add_record(ffile, POINTER_ADD(PRECORD_LOG, leftover_buffer.data(), 0));

                processed++;
                std::cout << "\r[-] $LogFile Record Count : " << std::to_string(processed) + "     ";

                offset += leftover_missing_size;
                leftover_size = 0;
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
                _add_record(ffile, prl);

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
                        std::cout << std::endl << "file delete record..." << std::endl;
                        My_Decode_IndexEntry(undo_chunk, prl->undo_operation, false);
                    }
                }

                processed++;
                std::cout << "\r[-] $LogFile Record Count : " << std::to_string(processed) + "     ";
            }
        }
    }
}

int print_logfile_records(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, const std::string& format, std::string output)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	utils::ui::title("LogFile from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << vol->name() << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Reading $LogFile record" << std::endl;
	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_number(LOG_FILE_NUMBER);

	ULONG64 total_size = record->datasize();
	std::cout << "[+] $LogFile size : " << utils::format::size(total_size) << std::endl;

	std::cout << "[+] Creating " << output << std::endl;

	if (format == "raw")
	{
		HANDLE houtput = CreateFileA(output.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (houtput == INVALID_HANDLE_VALUE)
		{
			std::cout << "[!] Failed to create output file" << std::endl;
			return 1;
		}

		ULONG64 processed_size = 0;

		for (auto& block : record->process_data(MFT_ATTRIBUTE_DATA_USN_NAME, 1024 * 1024, true))
		{
			std::cout << "\r[+] Processing data: " << utils::format::size(processed_size) << "     ";
			processed_size += block.second;

			DWORD written = 0;
			WriteFile(houtput, block.first, block.second, &written, NULL);
		}
		std::cout << "\r[+] Processing data: " << utils::format::size(processed_size);

		CloseHandle(houtput);

		std::cout << "[+] Closing volume" << std::endl;
	}
	else if (format == "json" || format == "csv")
	{
		std::shared_ptr<Buffer<PBYTE>> logfile = record->data();

		dump_logdata(format, output, logfile);
	}
	else
	{
		std::cout << "[!] Invalid or missing format" << std::endl;
		return 2;
	}

	std::cout << std::endl << "[+] Closing volume" << std::endl;

	return 0;
}

// 从dump出来的$LogFile文件中打印所有的日志记录
int print_logfile_records_file(std::string input, std::shared_ptr<Buffer<PBYTE>> input_data, const std::string& format, std::string output)
{
	utils::ui::title("LogFile from " + input);

	std::cout << "[+] Opening " << input << std::endl;

	std::ifstream record(input, std::ios_base::binary | std::ios_base::in);
	if (!record.is_open())
	{
		std::cerr << "无法打开文件:" << input << std::endl;
		return -1;
	}
	// 定位到文件末尾
	record.seekg(0, std::ios::end);

	// 获取文件大小
	std::streampos fileSize = record.tellg();

	ULONG64 total_size = fileSize;

	std::cout << "[+] $LogFile size : " << utils::format::size(total_size) << std::endl;

	std::cout << "[+] Creating " << output << std::endl;

	if (format == "raw")
	{
		std::cerr << "暂时不支持raw模式" << std::endl;
	}
	else if (format == "json" || format == "csv")
	{
		std::shared_ptr<Buffer<PBYTE>> logfile(new Buffer<PBYTE>(total_size));
		record.seekg(0);
		record.read((char*)logfile->address(), total_size);
		dump_logdata(format, output, logfile);
	}
	else
	{
		std::cout << "[!] Invalid or missing format" << std::endl;
		return 2;
	}

	std::cout << std::endl << "[+] Closing volume" << std::endl;

	return 0;
}

namespace commands
{
	namespace logfile
	{
		int dispatch(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			if (opts->from != "")
			{
				std::shared_ptr<Buffer<PBYTE>> filebuf = Buffer<PBYTE>::from_file(utils::strings::from_string(opts->from));
				if (filebuf != nullptr)
				{
					if (opts->output != "")
					{
						if (opts->format == "") opts->format = "csv";
					}
                    else
                    {
                        opts->output = "temp.csv";
                        opts->format = "csv";
                    }

					print_logfile_records_file(opts->from, filebuf, opts->format, opts->output);
				}
				else
				{
					invalid_option(opts, "from", opts->from);
				}
			}
			else
			{
				std::shared_ptr<Disk> disk = get_disk(opts);
				if (disk != nullptr)
				{
					std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
					if (volume != nullptr)
					{
						if (opts->output != "")
						{
							if (opts->format == "") opts->format = "raw";

							print_logfile_records(disk, volume, opts->format, opts->output);
						}
						else
						{
							invalid_option(opts, "output", opts->output);
						}
					}
					else
					{
						invalid_option(opts, "volume", opts->volume);
					}
				}
				else
				{
					invalid_option(opts, "disk", opts->disk);
				}
			}

			std::cout.flags(flag_backup);
			return 0;
		}
	}
}

// AttrType
int64_t My_Decode_IndexEntry(std::string_view Entry, int AttrType, bool IsRedo)
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

    if (option.VerboseOn)
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
