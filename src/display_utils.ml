open! Core

(* Decode strace escape sequences into raw bytes. Handles backslash-n, backslash-t,
   backslash-0, hex, and plain chars. Strace is invoked with -x so all non-printable bytes
   are emitted as hex (\xNN). *)
let decode_strace_escapes s =
  let buf = Buffer.create (String.length s) in
  let len = String.length s in
  let i = ref 0 in
  while !i < len do
    if !i + 1 < len && Char.equal (String.get s !i) '\\'
    then (
      let next = String.get s (!i + 1) in
      match next with
      | 'n' ->
        Buffer.add_char buf '\n';
        i := !i + 2
      | 't' ->
        Buffer.add_char buf '\t';
        i := !i + 2
      | 'r' ->
        Buffer.add_char buf '\r';
        i := !i + 2
      | '\\' ->
        Buffer.add_char buf '\\';
        i := !i + 2
      | '"' ->
        Buffer.add_char buf '"';
        i := !i + 2
      | '0' ->
        Buffer.add_char buf '\000';
        i := !i + 2
      | 'x' when !i + 3 < len ->
        let hex = String.sub s ~pos:(!i + 2) ~len:2 in
        (match Int.of_string_opt ("0x" ^ hex) with
         | Some c ->
           Buffer.add_char buf (Char.of_int_exn c);
           i := !i + 4
         | None ->
           Buffer.add_char buf '\\';
           i := !i + 1)
      | _ ->
        Buffer.add_char buf '\\';
        Buffer.add_char buf next;
        i := !i + 2)
    else (
      Buffer.add_char buf (String.get s !i);
      i := !i + 1)
  done;
  Buffer.contents buf
;;

(* Hexdump rendering of raw bytes. Non-printable characters shown as '.' *)

(* Compute the best bytes-per-line for a hexdump given available width and total buffer
   length. The offset prefix width depends on the buffer size: 4 hex digits for <=64KB, 8
   otherwise. A line with N bytes and P-digit offset prefix is: (P+1) + 3*N +
   floor((N-1)/8) + 2 + N + 1 = (P+4) + 4*N + (N-1)/8 *)
let hexdump_bytes_per_line ~width ~total_bytes =
  let offset_digits = if total_bytes > 0xFFFF then 8 else 4 in
  let fixed = offset_digits + 1 + 1 + 1 in
  let rec try_n n =
    let line_width = fixed + (4 * n) + ((n - 1) / 8) in
    if line_width > width then try_n (n - 8) else n
  in
  let start = (((width - fixed) / 4 / 8) + 1) * 8 in
  let max_fits = try_n (Int.max 8 start) |> Int.max 8 in
  (* Pick the smallest group count (multiple of 8) that can display the whole string *)
  let max_needed =
    let groups = (total_bytes + 7) / 8 in
    Int.max 1 groups * 8
  in
  Int.min max_fits max_needed
;;

(* Split an strace escaped string at a byte boundary. Returns (meaningful, trailing) where
   meaningful is the first n bytes. *)
let split_escaped_at_byte s ~byte_count =
  let len = String.length s in
  let bytes = ref 0 in
  let i = ref 0 in
  while !i < len && !bytes < byte_count do
    if !i + 1 < len && Char.equal (String.get s !i) '\\'
    then (
      let next = String.get s (!i + 1) in
      match next with
      | 'x' -> i := !i + 4
      | _ -> i := !i + 2)
    else i := !i + 1;
    incr bytes
  done;
  let split_pos = !i in
  String.prefix s split_pos, String.drop_prefix s split_pos
;;

(* Strip fd path annotations from an argument string for compact display. E.g.
   "3</usr/lib64/libc.so>" becomes "3" *)
let strip_fd_annotations arg =
  match String.lsplit2 arg ~on:'<' with
  | Some (num, _rest) ->
    let num = String.rstrip num in
    if (not (String.is_empty num))
       && (Char.is_digit (String.get num 0)
           || Char.equal (String.get num 0) '-'
           || String.is_prefix num ~prefix:"AT_FDCWD")
    then num
    else arg
  | None -> arg
;;

(* Wrap a string to fit within a given width, breaking at character boundaries *)
let wrap_string s ~width =
  if width <= 0 || String.length s <= width
  then [ s ]
  else (
    let lines = ref [] in
    let len = String.length s in
    let pos = ref 0 in
    while !pos < len do
      let chunk_len = Int.min width (len - !pos) in
      lines := String.sub s ~pos:!pos ~len:chunk_len :: !lines;
      pos := !pos + chunk_len
    done;
    List.rev !lines)
;;

(* Extract all IP addresses from a string (e.g. from FD annotations like
   "5<UDP:[30.32.177.12:34003->30.10.253.70:0]>") *)
let extract_ip_addresses s =
  let ips = ref [] in
  let len = String.length s in
  let i = ref 0 in
  while !i < len do
    (* Look for patterns like digits.digits.digits.digits *)
    if Char.is_digit (String.get s !i)
    then (
      let start = !i in
      let dot_count = ref 0 in
      while
        !i < len && (Char.is_digit (String.get s !i) || Char.equal (String.get s !i) '.')
      do
        if Char.equal (String.get s !i) '.' then incr dot_count;
        incr i
      done;
      if !dot_count = 3
      then (
        let candidate = String.sub s ~pos:start ~len:(!i - start) in
        (* Validate it looks like an IP *)
        let parts = String.split candidate ~on:'.' in
        if List.length parts = 4
           && List.for_all parts ~f:(fun p ->
             (not (String.is_empty p))
             && Option.is_some (Int.of_string_opt p)
             && Int.of_string_opt p
                |> Option.value_map ~default:false ~f:(fun n -> n <= 255))
        then ips := candidate :: !ips))
    else incr i
  done;
  List.rev !ips |> List.dedup_and_sort ~compare:String.compare
;;

(* Replace all occurrences of cached IP addresses with their resolved hostnames. The
   caller is responsible for only calling this on strings where IP replacement is
   appropriate (e.g. verbose file-descriptor annotations like
   "3<TCP:[10.0.0.1:80->10.0.0.2:443]>"). *)
let resolve_ips_in_string s ~dns_cache =
  Map.fold dns_cache ~init:s ~f:(fun ~key:ip ~data:hostname acc ->
    String.substr_replace_all acc ~pattern:ip ~with_:hostname)
;;

(* Split a string at a delimiter, but only at the top level — not inside nested brackets,
   braces, parens, or quoted strings. *)
let split_top_level s ~on =
  let result = ref [] in
  let current = Buffer.create 64 in
  let depth = ref 0 in
  let in_string = ref false in
  let len = String.length s in
  let i = ref 0 in
  while !i < len do
    let c = String.get s !i in
    if !in_string
    then (
      Buffer.add_char current c;
      if Char.equal c '"'
      then (
        (* Check for backslash escape: count preceding backslashes *)
        let num_backslashes = ref 0 in
        let j = ref (!i - 1) in
        while !j >= 0 && Char.equal (String.get s !j) '\\' do
          incr num_backslashes;
          decr j
        done;
        if !num_backslashes % 2 = 0 then in_string := false))
    else if Char.equal c on && !depth = 0
    then (
      result := Buffer.contents current :: !result;
      Buffer.clear current)
    else (
      (match c with
       | '(' | '[' | '{' -> incr depth
       | ')' | ']' | '}' -> decr depth
       | '"' -> in_string := true
       | _ -> ());
      Buffer.add_char current c);
    i := !i + 1
  done;
  if Buffer.length current > 0 then result := Buffer.contents current :: !result;
  List.rev !result
;;

(* Produce a compact args string for the list view, stripping fd annotations *)
let compact_args_raw args_raw =
  let args =
    if String.is_empty (String.strip args_raw)
    then []
    else split_top_level args_raw ~on:',' |> List.map ~f:String.strip
  in
  let compact_args =
    List.map args ~f:(fun arg -> strip_fd_annotations (String.strip arg))
  in
  String.concat ~sep:", " compact_args
;;
