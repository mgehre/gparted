/* Copyright (C) 2004 Bart
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
 
 
#include "../include/fat32.h"

namespace GParted
{

FS fat32::get_filesystem_support( )
{
	FS fs ;
	
	fs .filesystem = "fat32" ;
	
	//find out if we can create fat32 filesystems
	if ( ! system( "which mkdosfs 1>/dev/null 2>/dev/null" ) ) 
		fs .create = true ;
		
	//resing of start and endpoint are provided by libparted
	fs .resize = true ;
	fs .move = true ;
	
	return fs ;
}

bool fat32::Create( const Glib::ustring device_path, const Partition & new_partition )
{
	return Execute_Command( "mkdosfs -F32 " + new_partition .partition ) ;
}

bool fat32::Resize( const Glib::ustring device_path, const Partition & partition_old, const Partition & partition_new )
{
	bool return_value = false ;
	
	PedPartition *c_part = NULL ;
	PedFileSystem *fs = NULL ;
	PedConstraint *constraint = NULL ;
	
	if ( open_device_and_disk( device_path, device, disk ) )
	{
		c_part = ped_disk_get_partition_by_sector( disk, (partition_old .sector_end + partition_old .sector_start) / 2 ) ;
		if ( c_part )
		{
			fs = ped_file_system_open ( & c_part->geom );
			if ( fs )
			{
				constraint = ped_file_system_get_resize_constraint ( fs );
				if ( constraint )
				{
					if ( 	ped_disk_set_partition_geom ( disk, c_part, constraint, partition_new .sector_start, partition_new .sector_end ) &&
						ped_file_system_resize ( fs, & c_part->geom, NULL ) )
							return_value = Commit( disk ) ;
										
					ped_constraint_destroy ( constraint );
				}
				
				ped_file_system_close ( fs );
			}
		}
		
		close_device_and_disk( device, disk) ;
	}
	
	return return_value ;
}

bool fat32::Copy( const Glib::ustring & src_part_path, const Glib::ustring & dest_part_path )
{
	return Execute_Command( "dd bs=8192 if=" + src_part_path + " of=" + dest_part_path ) ;
}

int fat32::get_estimated_time( long MB_to_Consider )
{
	return 1 + MB_to_Consider / 5000 ;
}

	


} //GParted