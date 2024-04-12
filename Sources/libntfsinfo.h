// *****************************************************************************
// 版权所有（C）2022-2022，南京启后网络技术有限公司
// 保留所有权利
// *****************************************************************************
// 作者 : 赵海洋
// 版本 : 1.0
// 功能说明:
// 2024年4月2日 星期二
// *****************************************************************************

#ifndef __libntfsinfo_
#define __libntfsinfo_ 1

#include <sys/types.h>
#include <windows.h>
#include <WinDef.h>

typedef struct
{
    // mft索引
    uint32_t mft;

    // 该mft被重用的次数
    uint32_t update_count;
} FileIndex;

typedef struct
{
    // 更新时间,格式是FileTime
    FILETIME update_time;

    uint64_t usn;// 序号

    uint32_t reason_flags;// USN_REASON_FILE_CREATE等

    // 源flag?
    uint32_t source_flags;

    // 文件名
    wchar_t filename[MAX_PATH];

    // 文件引用
    FileIndex file_reference;

    // 父文件引用
    FileIndex parent_file_reference;

    // 文件属性
    uint32_t file_attribute;
} UsnFileRecord;

/**
 * 根据LogFile中查找的删除文件记录
 */
struct LogFileFileRecord
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

    std::wstring filename() const;

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

    uint8_t filename_length;// 文件名长度, unicode
    uint8_t filename_namespace;// 文件名类型 0-posix 1-win32 2-dos 3-dos+win32

    // 文件名变长数组,
    wchar_t filename_pointer[MAX_PATH];

    // 整个结构体大小不是8的整数的,后面需要补齐8字节
};

#if defined( __cplusplus )
extern "C" {
#endif
    __declspec(dllimport) int InitNtfsTool();
    __declspec(dllimport) void DeinitNtfsInfo();

    __declspec(dllimport) int GetDeleteRecords(int disk_index, uint64_t volume_offset, UsnFileRecord** records, int* count);

    /**
       * @disk_index disk_index
       * @param volume_offset 因为此代码库中volume仅保存大小不为0的分区,所以会比TestDisk少几个分区,不能使用volume_index来匹配分区
       */
    __declspec(dllimport) int GetDeleteRecordsByFileRecord(int disk_index, uint64_t volume_offset, LogFileFileRecord** records, int* count);


#define MFT_ERROR_OVERRIDE 1 // mft更新数变化,文件可能已经被覆盖
#define MFT_ERROR_DISK_NOT_FOUND 2 // 未找到磁盘索引
#define MFT_ERROR_VOLUME_NOT_FOUND 3 // 未找到分区索引
#define MFT_ERROR_NOT_FOUND 4 // 未找到mft索引

    /**
     * 从mft索引读取对应的文件, 返回读取结果,0 表示成功,其它值表示失败
     */
    __declspec(dllimport) int ReadFromMft(int disk_index, uint64_t volume_offset, uint64_t mft, int(*on_data)(char* buffer, int size));

#if defined( __cplusplus )
}
#endif

#endif // end of __libntfsinfo_
