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

#ifndef DIALOG_PARTITION_RESIZE_MOVE
#define DIALOG_PARTITION_RESIZE_MOVE

#include "../include/Dialog_Base_Partition.h"

namespace GParted
{

class Dialog_Partition_Resize_Move : public Dialog_Base_Partition
{
public:
	Dialog_Partition_Resize_Move( const FS & fs, Sector cylinder_size ) ;
	void Set_Data( const Partition & selected_partition, const std::vector <Partition> & partitions ) ;

private:
	void Resize_Move_Normal( const std::vector <Partition> & partitions ) ;
	void Resize_Move_Extended( const std::vector <Partition> & partitions ) ;
};

} //GParted

#endif //DIALOG_PARTITION_RESIZE_MOVE
