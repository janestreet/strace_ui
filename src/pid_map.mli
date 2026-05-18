open! Core

(** Maps real PIDs to short sequential IDs for compact display.

    The first PID registered always gets short ID 0. Subsequent PIDs are assigned 1, 2,
    etc. in order of first appearance. *)

module Pid_info : sig
  type t =
    { cmdline : string (** Full command line (e.g. "/usr/bin/ping localhost") *)
    ; thread_name : string
    (** Thread name from [prctl PR_SET_NAME] / [/proc/pid/comm]. For the main thread this
        is typically the binary name; for subthreads it is often a descriptive label like
        "worker" or "gc". *)
    ; is_thread : bool
    (** [true] when the PID is a subthread (its tgid differs from its pid). *)
    }
  [@@deriving sexp_of]
end

type t [@@deriving sexp_of]

val empty : t

(** Register a PID and return the updated map. If the PID is already known, this is a
    no-op. *)
val register : t -> int -> t

(** Look up the short ID for a PID. Returns [None] if the PID has not been registered. *)
val short_id : t -> int -> int option

(** The number of characters needed to display the largest short ID. *)
val display_width : t -> int

(** Look up the info associated with a PID, if known. *)
val info : t -> int -> Pid_info.t option

(** Record info for a PID. *)
val set_info : t -> pid:int -> Pid_info.t -> t

(** A one-line summary suitable for the detail header. Shows cmdline, and for threads
    includes the thread name and a "thread of #N" annotation. *)
val summary : t -> int -> string option
