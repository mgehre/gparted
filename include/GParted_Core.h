/* Copyright (C) 2004 Bart
 * Copyright (C) 2008, 2009, 2010, 2011, 2012 Curtis Gedak
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
 
#ifndef GPARTED_CORE
#define GPARTED_CORE

#include "../include/FileSystem.h"
#include "../include/Operation.h"

#include <parted/parted.h>
#ifdef HAVE_LIBPARTED_3_1_0_PLUS
#include <parted/filesys.h>
#endif
#include <vector>
#include <fstream>

namespace GParted
{
class Proc_Partitions_Info;

class GParted_Core
{
public:
	static Glib::Thread *mainthread;
	GParted_Core() ;
	~GParted_Core() ;

	void find_supported_filesystems() ;
	void set_user_devices( const std::vector<Glib::ustring> & user_devices ) ;
	void set_devices( std::vector<Device> & devices ) ;
	void guess_partition_table(const Device & device, Glib::ustring &buff);
	
	bool snap_to_cylinder( const Device & device, Partition & partition, Glib::ustring & error ) ;
	bool snap_to_mebibyte( const Device & device, Partition & partition, Glib::ustring & error ) ;
	bool snap_to_alignment( const Device & device, Partition & partition, Glib::ustring & error ) ;
	bool apply_operation_to_disk( Operation * operation );
	
	bool set_disklabel( const Glib::ustring & device_path, const Glib::ustring & disklabel ) ;

	bool toggle_flag( const Partition & partition, const Glib::ustring & flag, bool state ) ;
	
	const std::vector<FS> & get_filesystems() const ;
	static const FS & get_fs( GParted::FILESYSTEM filesystem ) ;
	std::vector<Glib::ustring> get_disklabeltypes() ;
	std::vector<Glib::ustring> get_all_mountpoints() ;
	std::map<Glib::ustring, bool> get_available_flags( const Partition & partition ) ;
	Glib::ustring get_libparted_version() ;
	Glib::ustring get_thread_status_message() ;

	static FileSystem * get_filesystem_object( const FILESYSTEM & filesystem ) ;
	static bool filesystem_resize_disallowed( const Partition & partition ) ;
	static bool parse_device( const Glib::ustring& device_path, Device& temp_device ) ;
	static bool parse_device( const Glib::ustring& device_path, Proc_Partitions_Info& pp_info, Device& temp_device ) ;
private:
	//detectionstuff..
	void init_maps() ;
	static void set_thread_status_message( Glib::ustring msg ) ;
	void read_mountpoints_from_file( const Glib::ustring & filename,
					 std::map< Glib::ustring, std::vector<Glib::ustring> > & map ) ;
	void read_mountpoints_from_file_swaps(
		const Glib::ustring & filename,
		std::map< Glib::ustring, std::vector<Glib::ustring> > & map ) ;
	static Glib::ustring get_partition_path( PedPartition * lp_partition ) ;
	static void set_device_partitions( Device & device, PedDevice* lp_device, PedDisk* lp_disk ) ;
	static GParted::FILESYSTEM get_filesystem( PedDevice* lp_device, PedPartition* lp_partition,
	                                           std::vector<Glib::ustring>& messages ) ;
	static void read_label( Partition & partition ) ;
	static void read_uuid( Partition & partition ) ;
	static void insert_unallocated( const Glib::ustring & device_path,
				 std::vector<Partition> & partitions,
				 Sector start,
				 Sector end,
				 Byte_Value sector_size,
				 bool inside_extended ) ;

	static void set_mountpoints( std::vector<Partition> & partitions ) ;
	static void set_used_sectors( std::vector<Partition> & partitions, PedDisk* lp_disk ) ;
	static void mounted_set_used_sectors( Partition & partition ) ;
#ifdef HAVE_LIBPARTED_FS_RESIZE
	static void LP_set_used_sectors( Partition & partition, PedDisk* lp_disk ) ;
#endif
	static void set_flags( Partition & partition, PedPartition* lp_partition ) ;
	
	//operationstuff...
	bool create( const Device & device, Partition & new_partition, OperationDetail & operationdetail ) ;
	bool create_partition( Partition & new_partition, OperationDetail & operationdetail, Sector min_size = 0 ) ;
	bool create_filesystem( const Partition & partition, OperationDetail & operationdetail ) ;

	bool format( const Partition & partition, OperationDetail & operationdetail ) ;

	bool Delete( const Partition & partition, OperationDetail & operationdetail ) ;

	bool remove_filesystem( const Partition & partition, OperationDetail & operationdetail ) ;

	bool label_partition( const Partition & partition, OperationDetail & operation_detail ) ;
	
	bool change_uuid( const Partition & partition, OperationDetail & operation_detail ) ;

	bool resize_move( const Device & device,
			  const Partition & partition_old,
			  Partition & partition_new,
			  OperationDetail & operationdetail ) ;
	bool move( const Device & device, 
		   const Partition & partition_old,
		   const Partition & partition_new,
		   OperationDetail & operationdetail ) ;
	bool move_filesystem( const Partition & partition_old,
			      const Partition & partition_new,
			      OperationDetail & operationdetail ) ;
#ifdef HAVE_LIBPARTED_FS_RESIZE
	bool resize_move_filesystem_using_libparted( const Partition & partition_old,
				      		     const Partition & partition_new,
					      	     OperationDetail & operationdetail ) ;
#endif
	bool resize( const Partition & partition_old,
		     const Partition & partition_new,
		     OperationDetail & operationdetail ) ;
	bool resize_move_partition( const Partition & partition_old,
			       	    const Partition & partition_new,
				    OperationDetail & operationdetail ) ;
	bool resize_filesystem( const Partition & partition_old,
				const Partition & partition_new,
				OperationDetail & operationdetail,
				bool fill_partition = false ) ;
	bool maximize_filesystem( const Partition & partition, OperationDetail & operationdetail ) ;
				
	bool copy( const Partition & partition_src,
		   Partition & partition_dst,
		   Byte_Value min_size,
		   OperationDetail & operationdetail ) ; 
	bool copy_filesystem_simulation( const Partition & partition_src,
			      		 const Partition & partition_dst,
			      		 OperationDetail & operationdetail ) ;
	bool copy_filesystem( const Partition & partition_src,
			      const Partition & partition_dst,
			      OperationDetail & operationdetail,
			      bool readonly = false ) ;
	bool copy_filesystem( const Partition & partition_src,
			      const Partition & partition_dst,
			      OperationDetail & operationdetail,
			      Byte_Value & total_done ) ;
	bool copy_filesystem( const Glib::ustring & src_device,
			      const Glib::ustring & dst_device,
			      Sector src_start,
			      Sector dst_start,
			      Byte_Value src_sector_size,
			      Byte_Value dst_sector_size,
			      Byte_Value src_length,
			      OperationDetail & operationdetail,
			      bool readonly,
			      Byte_Value & total_done ) ;
	void rollback_transaction( const Partition & partition_src,
				   const Partition & partition_dst,
				   OperationDetail & operationdetail,
				   Byte_Value total_done ) ;

	bool check_repair_filesystem( const Partition & partition, OperationDetail & operationdetail ) ;

	bool set_partition_type( const Partition & partition, OperationDetail & operationdetail ) ;

	void set_progress_info( Sector total, Sector done, const Glib::Timer & timer, OperationDetail & operationdetail, bool readonly ) ;

	bool copy_blocks( const Glib::ustring & src_device,
			  const Glib::ustring & dst_device,
			  Sector src_start,
			  Sector dst_start,
			  Byte_Value length,
			  Byte_Value blocksize,
			  OperationDetail & operationdetail,
			  bool readonly,
			  Byte_Value & total_done ) ;

	bool copy_block( PedDevice * lp_device_src,
			 PedDevice * lp_device_dst,
			 Sector offset_src,
			 Sector offset_dst,
			 Byte_Value blocksize,
			 Glib::ustring & error_message,
			 bool readonly ) ; 
	bool calibrate_partition( Partition & partition, OperationDetail & operationdetail ) ;
	bool calculate_exact_geom( const Partition & partition_old,
			           Partition & partition_new,
				   OperationDetail & operationdetail ) ;
	static FileSystem* set_proper_filesystem( const FILESYSTEM & filesystem ) ;
#ifndef HAVE_LIBPARTED_3_0_0_PLUS
	bool erase_filesystem_signatures( const Partition & partition ) ;
#endif
	bool update_bootsector( const Partition & partition, OperationDetail & operationdetail ) ;

	//general..	
	static PedDevice* open_device( const Glib::ustring & device_path ) ;
	static bool open_device_and_disk( const Glib::ustring & device_path,
	                                  PedDevice*& lp_device, PedDisk*& lp_disk, bool strict = true) ;
	static void close_disk( PedDisk*& lp_disk ) ;
	static void close_device_and_disk( PedDevice*& lp_device, PedDisk*& lp_disk ) ;
	bool commit( PedDisk* lp_disk ) ;
	static bool commit_to_os( PedDisk* lp_disk, std::time_t timeout ) ;
	static void settle_device( std::time_t timeout ) ;

	static PedExceptionOption ped_exception_handler( PedException * e ) ;

	static std::vector<FS> FILESYSTEMS ;
	static std::map< FILESYSTEM, FileSystem * > FILESYSTEM_MAP ;
	static std::vector<PedPartitionFlag> flags;
	std::vector<Glib::ustring> device_paths ;
	bool probe_devices ;
	static Glib::ustring thread_status_message;  //Used to pass data to show_pulsebar method
	Glib::RefPtr<Glib::IOChannel> iocInput, iocOutput; // Used to send data to gpart command
	
	static std::map< Glib::ustring, std::vector<Glib::ustring> > mount_info ;
	static std::map< Glib::ustring, std::vector<Glib::ustring> > fstab_info ;
	static std::map< Glib::ustring, std::vector<Glib::ustring> >::iterator iter_mp ;
	
	char * buf ;
};

} //GParted


#endif //GPARTED_CORE
