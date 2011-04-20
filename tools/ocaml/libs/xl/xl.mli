(*
 * Copyright (C) 2009-2011 Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *)

exception Error of string

type domid = int

type console_type =
	| CONSOLETYPE_XENCONSOLED
	| CONSOLETYPE_IOEMU

type disk_phystype =
	| PHYSTYPE_QCOW
	| PHYSTYPE_QCOW2
	| PHYSTYPE_VHD
	| PHYSTYPE_AIO
	| PHYSTYPE_FILE
	| PHYSTYPE_PHY

type nic_type =
	| NICTYPE_IOEMU
	| NICTYPE_VIF

type button =
	| Button_Power
	| Button_Sleep

module Domain_create_info : sig
	type t =
	{
		hvm : bool;
		hap : bool;
		oos : bool;
		ssidref : int32;
		name : string;
		uuid : int array;
		xsdata : (string * string) list;
		platformdata : (string * string) list;
		poolid : int32;
		poolname : string;
	}
end

module Device_vfb : sig
	type t =
	{
		backend_domid : domid;
		devid : int;
		vnc : bool;
		vnclisten : string;
		vncpasswd : string;
		vncdisplay : int;
		vncunused : bool;
		keymap : string;
		sdl : bool;
		opengl : bool;
		display : string;
		xauthority : string;
	}
	external add : t -> domid -> unit = "stub_xl_device_vfb_add"
	external clean_shutdown : domid -> unit = "stub_xl_device_vfb_clean_shutdown"
	external hard_shutdown : domid -> unit = "stub_xl_device_vfb_hard_shutdown"
end

module Device_vkb : sig
	type t =
	{
		backend_domid : domid;
		devid : int;
	}
	
	external add : t -> domid -> unit = "stub_xl_device_vkb_add"
	external clean_shutdown : domid -> unit = "stub_xl_device_vkb_clean_shutdown"
	external hard_shutdown : domid -> unit = "stub_xl_device_vkb_hard_shutdown"
end

module Device_console : sig
	type t =
	{
		backend_domid : domid;
		devid : int;
		consoletype : console_type;
	}

	external add : t -> domid -> unit = "stub_xl_device_console_add"
end

module Device_disk : sig
	type t =
	{
		backend_domid : domid;
		physpath : string;
		phystype : disk_phystype;
		virtpath : string;
		unpluggable : bool;
		readwrite : bool;
		is_cdrom : bool;
	}

	external add : t -> domid -> unit = "stub_xl_device_disk_add"
	external del : t -> domid -> unit = "stub_xl_device_disk_del"
end

module Device_nic : sig
	type t =
	{
		backend_domid : domid;
		devid : int;
		mtu : int;
		model : string;
		mac : int array;
		bridge : string;
		ifname : string;
		script : string;
		nictype : nic_type;
	}
	external add : t -> domid -> unit = "stub_xl_device_nic_add"
	external del : t -> domid -> unit = "stub_xl_device_nic_del"
end

module Device_pci : sig
	type t =
	{
		func : int;
		dev : int;
		bus : int;
		domain : int;
		vdevfn : int;
		msitranslate : bool;
		power_mgmt : bool;
	}

	external add : t -> domid -> unit = "stub_xl_device_pci_add"
	external remove : t -> domid -> unit = "stub_xl_device_pci_remove"
	external shutdown : domid -> unit = "stub_xl_device_pci_shutdown"
end

module Physinfo : sig
	type t =
	{
		threads_per_core: int;
		cores_per_socket: int;
		max_cpu_id: int;
		nr_cpus: int;
		cpu_khz: int;
		total_pages: int64;
		free_pages: int64;
		scrub_pages: int64;
		nr_nodes: int;
		hwcap: int32 array;
		physcap: int32;
	}
	external get : unit -> t = "stub_xl_physinfo"

end

module Sched_credit : sig
	type t =
	{
		weight: int;
		cap: int;
	}

	external domain_get : domid -> t = "stub_xl_sched_credit_domain_get"
	external domain_set : domid -> t -> unit = "stub_xl_sched_credit_domain_set"
end

module Domain_build_info : sig
	module Hvm : sig
		type t =
		{
			pae : bool;
			apic : bool;
			acpi : bool;
			nx : bool;
			viridian : bool;
			timeoffset : string;
			timer_mode : int;
			hpet : int;
			vpt_align : int;
		}
	end

	module Pv : sig
		type t =
		{
			slack_memkb : int64;
			cmdline : string;
			ramdisk : string;
			features : string;
		}
	end

	type t =
	{
		max_vcpus : int;
		cur_vcpus : int;
		max_memkb : int64;
		target_memkb : int64;
		video_memkb : int64;
		shadow_memkb : int64;
		kernel : string;
		u : [ `HVM of Hvm.t | `PV of Pv.t ];
	}
end

module Topologyinfo : sig
	type t =
	{
		core: int;
		socket: int;
		node: int;
	}
	external get : unit -> t = "stub_xl_topologyinfo"
end

external button_press : domid -> button -> unit = "stub_xl_button_press"

external send_trigger : domid -> string -> int -> unit = "stub_xl_send_trigger"
external send_sysrq : domid -> char -> unit = "stub_xl_send_sysrq"
external send_debug_keys : domid -> string -> unit = "stub_xl_send_debug_keys"
