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


#ifndef LUKS_H_
#define LUKS_H_

#include "../include/FileSystem.h"

namespace GParted
{

class luks : public FileSystem
{
public:
	/*
	 * Tries to find the map for device created
	 * by "cryptsetup luksOpen device map".
	 * Append any errors to messages
	 */
	static Glib::ustring find_map_name_by_device(Glib::ustring device, std::vector<Glib::ustring>& messages) ;

	/*
	 * Returns the mapping device for a mapping name like
	 * get_mapping_device_by_mapping_name("home") = "/dev/mapper/home"
	 */
	static Glib::ustring get_mapping_device_by_mapping_name( Glib::ustring mapping_name ) ;
	/**
	 * Fills the partition->logical member with information
	 * about the contained file system
	 */
	static void set_contained_partition( Partition & partition ) ;

	FS get_filesystem_support() ;
	void set_used_sectors( Partition & partition ) ;
	void read_label( Partition & partition ) ;
	bool write_label( const Partition & partition, OperationDetail & operationdetail ) ;
	void read_uuid( Partition & partition ) ;
	bool write_uuid( const Partition & partition, OperationDetail & operationdetail ) ;
	bool create( const Partition & new_partition, OperationDetail & operationdetail ) ;
	bool resize( const Partition & partition_new, OperationDetail & operationdetail, bool fill_partition = false ) ;
	bool move( const Partition & partition_new
	         , const Partition & partition_old
	         , OperationDetail & operationdetail
	         ) ;
	bool copy( const Glib::ustring & src_part_path
	         , const Glib::ustring & dest_part_path
	         , OperationDetail & operationdetail ) ;
	bool check_repair( const Partition & partition, OperationDetail & operationdetail ) ;
	bool remove( const Partition & partition, OperationDetail & operationdetail ) ;
};

} //GParted

#endif /*LUKS_H_*/
