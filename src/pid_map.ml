open! Core

module Pid_info = struct
  type t =
    { cmdline : string
    ; thread_name : string
    ; is_thread : bool
    }
  [@@deriving sexp_of]
end

type t =
  { pid_to_short : int Int.Map.t
  ; next_id : int
  ; infos : Pid_info.t Int.Map.t
  }
[@@deriving sexp_of]

let empty = { pid_to_short = Int.Map.empty; next_id = 0; infos = Int.Map.empty }

let register t pid =
  if Map.mem t.pid_to_short pid
  then t
  else
    { t with
      pid_to_short = Map.set t.pid_to_short ~key:pid ~data:t.next_id
    ; next_id = t.next_id + 1
    }
;;

let short_id t pid = Map.find t.pid_to_short pid

let display_width t =
  let max_id = t.next_id - 1 in
  if max_id < 0 then 1 else Int.max 1 (String.length (Int.to_string max_id))
;;

let info t pid = Map.find t.infos pid
let set_info t ~pid pid_info = { t with infos = Map.set t.infos ~key:pid ~data:pid_info }

let summary t pid =
  match info t pid with
  | None -> None
  | Some { cmdline; thread_name; is_thread } ->
    if is_thread
    then Some [%string "thread: %{thread_name} (%{cmdline})"]
    else Some cmdline
;;
