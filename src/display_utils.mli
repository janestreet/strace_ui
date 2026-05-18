open! Core

(** Utilities for rendering strace data in the TUI. *)

(** Decode strace escape sequences into raw bytes. *)
val decode_strace_escapes : string -> string

(** Compute the best bytes-per-line for a hexdump given the available character width and
    total buffer length (which determines the offset prefix width). Returns a multiple of
    8, minimum 8. *)
val hexdump_bytes_per_line : width:int -> total_bytes:int -> int

(** Split an strace escaped string at a byte boundary. Returns [(meaningful, trailing)]. *)
val split_escaped_at_byte : string -> byte_count:int -> string * string

(** Wrap a string to fit within a given width, breaking at character boundaries. *)
val wrap_string : string -> width:int -> string list

(** Strip fd path annotations for compact display. E.g. ["3</usr/lib64/libc.so>"] becomes
    ["3"]. *)
val strip_fd_annotations : string -> string

(** Split a string at a delimiter at the top level (not inside nested brackets, braces,
    parens, or quoted strings). *)
val split_top_level : string -> on:char -> string list

(** Compact args string for the list view, stripping fd annotations. *)
val compact_args_raw : string -> string

(** Extract all IPv4 addresses from a string. *)
val extract_ip_addresses : string -> string list

(** Replace all occurrences of cached IP addresses with their resolved hostnames. The
    caller is responsible for only calling this on strings where IP replacement is
    appropriate (e.g. verbose file-descriptor annotations). *)
val resolve_ips_in_string : string -> dns_cache:string String.Map.t -> string
