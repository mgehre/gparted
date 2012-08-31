/* Copyright (C) 2012 Matthias Gehre
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "../include/GParted_Core.h"
#include "../include/Proc_Partitions_Info.h"
#include "../include/luks.h"

/*
 * The luks "filesystem" does not have a 'size' written on disk. It always uses all of its underlaying block-device (e.g. partition)
 * when luksOpen'ed.
 * You can resize an active luks device. But that information is lost when the device is luksClose'd. luksOpen'ing it
 * again will show the size of the underlaying block-device again.
 * 1. Thus resize is mainly useful when the size of the underlaying device grow after luksOpen'ing and we want to
 *    let luks use the additional space. (It would do so automatically when luksClose'd followed by luksOpen'ed.)
 * 2. Shrinking luks to make place to shrink the underlaying device afterwards.
 */

namespace GParted
{

struct crypt_mapping
{
	/** Name of the mapping */
	Glib::ustring name;
	/** Offset of payload in sectors */
	uint64_t offset;
	/** Size of payload in sectors */
	uint64_t size;
	/** Minor number of backing device */
	int minor;
	/** Major number of backing device */
	int major;
};

static crypt_mapping invalid_mapping = { "", 0, 0, -1, -1 };

/* Returns a list of all active dm-crypt mappings */
static std::vector<crypt_mapping> get_crypt_mappings(std::vector<Glib::ustring>& messages)
{
	std::vector<crypt_mapping> mappings ;
	Glib::ustring output, error ;

	/*
	 * We use dmsetup and not cryptsetup, because cryptsetup
	 * does not allow us to list all available mappings
	 */
	Glib::ustring cmd = "dmsetup table --target crypt" ;
	if ( Utils::execute_command( cmd, output, error, true ) || !error.empty())
	{
		// TO TRANSLATORS: %1 is a (shell) command, %2 its output, like "Error while executing 'echo Test': 'Test'"
		messages .push_back( Glib::ustring::compose( _("Error while executing '%1': '%2'"), cmd, output + "\n" + error) ) ;
		return mappings ;
	}

	std::vector<Glib::ustring> lines ;
	Utils::tokenize( output, lines, "\n" ) ;
	for(size_t i=0; i<lines.size(); ++i)
	{
		crypt_mapping cm ;
		// Format of table line (see Documentation/device-mapper/dm-crypt.txt in linux sources):
		// <mappingname>: <start_sector> <size> <target name> <cipher[:keycount]-chainmode-ivmode[:ivopts]> <key> <iv_offset> <device path> <offset> [<#opt_params> <opt_params>]
		std::vector<Glib::ustring> fields ;
		Utils::split(lines[i], fields, " ") ;
		if( fields.size() < 9 )
		{
			// TO TRANSLATORS: %1 is a shell command, %2 its output like "Failed parsing output of 'echo test': 'test'"
			messages .push_back( Glib::ustring::compose( _("Failed parsing output of '%1': '%2'"), cmd, lines[i]) ) ;
			continue ;
		}
		char* endptr ;
		cm.size = strtoll(fields[2].c_str(), &endptr, 10) ;
		if( *endptr != '\0' )
		{
			messages .push_back( Glib::ustring::compose( _("Failed parsing output of '%1': '%2'"), cmd, lines[i]) ) ;
			continue ;
		}

		cm.offset = strtoll(fields[8].c_str(), &endptr, 10) ;
		if( *endptr != '\0' )
		{
			messages .push_back( Glib::ustring::compose( _("Failed parsing output of '%1': '%2'"), cmd, lines[i]) ) ;
			continue ;
		}

		cm.name = fields[0] ;
		if( cm.name.empty() || cm.name.at(cm.name.length()-1) != ':' )
		{
			messages .push_back( Glib::ustring::compose( _("Failed parsing output of '%1': '%2'"), cmd, lines[i]) ) ;
			continue ;
		}
		// remove trailing ':'
		cm.name = cm.name.substr(0, cm.name.length() - 1 );

		// The <device path> field may either be a path (i.e. /dev/sda7) or a device number major:minor (i.e. 252:1)
		Glib::ustring device_path = fields[7] ;
		if( device_path[0] == '/' )
		{
			struct stat buf;
			if( lstat(device_path.c_str(),&buf) || !S_ISBLK(buf.st_mode))
			{
				messages .push_back( Glib::ustring::compose( _("Error while executing '%1': '%2'"),
							"lstat("+device_path+")", strerror(errno) ) ) ;
				continue ;
			}
			cm .major = major(buf.st_rdev) ;
			cm .minor = minor(buf.st_rdev) ;
		}
		else
		{
			// <device path> has format major:minor
			if( sscanf(device_path.c_str(), "%d:%d", &cm.major, &cm.minor) != 2 )
			{
				messages .push_back( Glib::ustring::compose( _("Failed parsing output of '%1': '%2'"), cmd, lines[i]) ) ;
				continue ;
			}
		}
		mappings.push_back(cm) ;
	}
	return mappings ;
}

/* Find the mapping, which uses the given device as backing device */
static crypt_mapping find_map_by_device(Glib::ustring device, std::vector<Glib::ustring>& messages)
{
	std::vector<crypt_mapping> mappings = get_crypt_mappings(messages) ;

	struct stat buf ;
	if( lstat(device.c_str(),&buf) || !S_ISBLK(buf.st_mode))
	{
		messages .push_back( Glib::ustring::compose( _("Error while executing '%1': '%2'"),
														"lstat("+device+")", strerror(errno) ) ) ;
		return invalid_mapping ;
	}
	int dev_major = major(buf.st_rdev) ;
	int dev_minor = minor(buf.st_rdev) ;

	for(size_t i=0; i< mappings.size(); ++i)
	{
		if( mappings[i].minor == dev_minor && mappings[i].major == dev_major )
			return mappings[i] ;
	}
	return invalid_mapping ;
}

/*
 * Find a map for the given device.
 * I.e. if /dev/sda5 caries the LUKS data and is currently
 * mapped to /dev/mapper/home (by cryptsetup luksOpen /dev/sda5 home)
 * then find_map("/dev/sda5") will return "home".
 * If mapping is not found, returns empty string.
 */
Glib::ustring luks::find_map_name_by_device(Glib::ustring device, std::vector<Glib::ustring>& messages)
{
	return find_map_by_device(device, messages).name ;
}

/*
 * Returns the mapping device for a mapping name like
 * get_mapping_device_by_mapping_name("home") = "/dev/mapper/home"
 */
Glib::ustring luks::get_mapping_device_by_mapping_name( Glib::ustring mapping_name )
{
	return Glib::build_filename( "/dev/mapper", mapping_name.raw() ) ;
}

FS luks::get_filesystem_support()
{
	FS fs ;
	fs .filesystem = FS_LUKS ;
	if( !Glib::find_program_in_path( "dmsetup" ) .empty() )
		fs .read = FS::EXTERNAL ;

	return fs ;
}

/*
 * Parse the contained filesystem and update partition.logicals
 */
void luks::set_contained_partition( Partition & partition )
{
	Glib::ustring mapping_name = find_map_name_by_device( partition .get_path(), partition .messages ) ;
	if( mapping_name .empty() )
		return ;
	Glib::ustring mapping_device = get_mapping_device_by_mapping_name( mapping_name ) ;

	Proc_Partitions_Info pp_info ;
	Device dev ;
	if( ! GParted_Core::parse_device( mapping_device, pp_info, dev ) )
		return;

	partition .logicals = dev .partitions ;
}

void luks::set_used_sectors( Partition & partition )
{
    partition .set_sector_usage( -1, 0 );

	crypt_mapping cm = find_map_by_device( partition .get_path(), partition .messages );

	if( cm.name.empty() )
	{
		//Currently unmapped, so it spans the whole underlaying partition
		partition .set_sector_usage( -1, 0 );
	}
	else
	{
		/* The LUKS "file system" contains the header + payload */
		Sector size =  cm.offset + cm.size ;
		partition .set_sector_usage( size, 0 );
	}
}

void luks::read_label( Partition & partition )
{
	return ;
}

bool luks::write_label( const Partition & partition, OperationDetail & operationdetail )
{
	return true ;
}

void luks::read_uuid( Partition & partition )
{
}

bool luks::write_uuid( const Partition & partition, OperationDetail & operationdetail )
{
	return true ;
}

bool luks::create( const Partition & new_partition, OperationDetail & operationdetail )
{
	return true ;
}

bool luks::resize( const Partition & partition_new, OperationDetail & operationdetail, bool fill_partition )
{
	return true ;
}

bool luks::move( const Partition & partition_new
                  , const Partition & partition_old
                  , OperationDetail & operationdetail
               )
{
	return true ;
}

bool luks::copy( const Glib::ustring & src_part_path
                  , const Glib::ustring & dest_part_path
                  , OperationDetail & operationdetail )
{
	return true ;
}

bool luks::check_repair( const Partition & partition, OperationDetail & operationdetail )
{
	return true ;
}

bool luks::remove( const Partition & partition, OperationDetail & operationdetail )
{
	return true;
}

} //GParted
