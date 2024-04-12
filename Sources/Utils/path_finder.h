#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include <Drive/volume.h>
#include <NTFS/ntfs.h>
#include <NTFS/ntfs_reader.h>
#include <NTFS/ntfs_mft_record.h>
#include <NTFS/ntfs_explorer.h>

class PathFinder {
private:
	std::unordered_map<DWORD64, DWORD64> _map_parent;
	std::unordered_map<DWORD64, std::string> _map_name;

	bool _delay = false;
	std::shared_ptr<Volume> _volume;
	std::shared_ptr<NTFSExplorer> _explorer;

public:
	PathFinder(std::shared_ptr<Volume> volume, bool delayLoadMft = false);

	std::string get_file_path(std::string filename, DWORD64 parent_inode);

	size_t count() { return _map_name.size(); }

private:
	bool fillNode(DWORD64 inode);
};
