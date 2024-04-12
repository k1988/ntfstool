// *****************************************************************************
// ��Ȩ���У�C��2022-2022���Ͼ��������缼�����޹�˾
// ��������Ȩ��
// *****************************************************************************
// ���� : �Ժ���
// �汾 : 1.0
// ����˵��:
// 2024��4��2�� ���ڶ�
// *****************************************************************************

#ifndef __libntfsinfo_
#define __libntfsinfo_ 1

#include <sys/types.h>
#include <windows.h>
#include <WinDef.h>

typedef struct
{
    // mft����
    uint32_t mft;

    // ��mft�����õĴ���
    uint32_t update_count;
} FileIndex;

typedef struct
{
    // ����ʱ��,��ʽ��FileTime
    FILETIME update_time;

    uint64_t usn;// ���

    uint32_t reason_flags;// USN_REASON_FILE_CREATE��

    // Դflag?
    uint32_t source_flags;

    // �ļ���
    wchar_t filename[MAX_PATH];

    // �ļ�����
    FileIndex file_reference;

    // ���ļ�����
    FileIndex parent_file_reference;

    // �ļ�����
    uint32_t file_attribute;
} UsnFileRecord;

/**
 * ����LogFile�в��ҵ�ɾ���ļ���¼
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

    uint64_t mft_parent;    // ���ļ���mft����,��λ��2�ֽڱ�ʾMFT��¼�ĸ��´���update sequence count
    FILETIME create_time; // �ļ�����ʱ��

    FILETIME access_time; // �ļ�����ʱ��
    FILETIME modify_time; // �ļ��޸�ʱ��

    FILETIME unknown_time;
    uint64_t allocate_size;// �ļ�����ռ��С

    uint64_t real_size; // �ļ���ʵ��С
    uint32_t file_flags;// �ļ����� FILE_ATTRIBUTE_ARCHIVE ��
    union {
        // file_flags��FILE_ATTRIBUTE_EAʱ,��λ�õ�ֵ��EaSize
        uint32_t EaSize;
        // file_flagsû��FILE_ATTRIBUTE_EAʱ,��λ�õ�ֵ��ReparseTag
        uint32_t ReparseTag;
    } file_flags_data;

    uint8_t filename_length;// �ļ�������, unicode
    uint8_t filename_namespace;// �ļ������� 0-posix 1-win32 2-dos 3-dos+win32

    // �ļ����䳤����,
    wchar_t filename_pointer[MAX_PATH];

    // �����ṹ���С����8��������,������Ҫ����8�ֽ�
};

#if defined( __cplusplus )
extern "C" {
#endif
    __declspec(dllimport) int InitNtfsTool();
    __declspec(dllimport) void DeinitNtfsInfo();

    __declspec(dllimport) int GetDeleteRecords(int disk_index, uint64_t volume_offset, UsnFileRecord** records, int* count);

    /**
       * @disk_index disk_index
       * @param volume_offset ��Ϊ�˴������volume�������С��Ϊ0�ķ���,���Ի��TestDisk�ټ�������,����ʹ��volume_index��ƥ�����
       */
    __declspec(dllimport) int GetDeleteRecordsByFileRecord(int disk_index, uint64_t volume_offset, LogFileFileRecord** records, int* count);


#define MFT_ERROR_OVERRIDE 1 // mft�������仯,�ļ������Ѿ�������
#define MFT_ERROR_DISK_NOT_FOUND 2 // δ�ҵ���������
#define MFT_ERROR_VOLUME_NOT_FOUND 3 // δ�ҵ���������
#define MFT_ERROR_NOT_FOUND 4 // δ�ҵ�mft����

    /**
     * ��mft������ȡ��Ӧ���ļ�, ���ض�ȡ���,0 ��ʾ�ɹ�,����ֵ��ʾʧ��
     */
    __declspec(dllimport) int ReadFromMft(int disk_index, uint64_t volume_offset, uint64_t mft, int(*on_data)(char* buffer, int size));

#if defined( __cplusplus )
}
#endif

#endif // end of __libntfsinfo_
