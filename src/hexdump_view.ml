open! Core
open Bonsai_term

type theme =
  { fg : Attr.Color.t
  ; bg : Attr.Color.t
  ; dim : Attr.Color.t
  ; blue : Attr.Color.t
  ; teal : Attr.Color.t
  }

let render ?(attrs = []) ?bytes_per_line (theme : theme) s =
  let offset_digits = if String.length s > 0xFFFF then 8 else 4 in
  let format_offset n =
    if offset_digits = 4 then sprintf "%04x " n else sprintf "%08x " n
  in
  let bytes_per_line =
    match bytes_per_line with
    | Some n -> n
    | None -> 16
  in
  let group_size = if bytes_per_line > 8 then 8 else bytes_per_line in
  let len = String.length s in
  let data_attrs = [ Attr.fg theme.fg; Attr.bg theme.bg ] @ attrs in
  let lines = ref [] in
  let offset = ref 0 in
  while !offset < len do
    let hex_buf = Buffer.create 64 in
    for i = 0 to bytes_per_line - 1 do
      if !offset + i < len
      then
        Buffer.add_string
          hex_buf
          (sprintf "%02x " (Char.to_int (String.get s (!offset + i))))
      else Buffer.add_string hex_buf "   ";
      if i + 1 < bytes_per_line && (i + 1) % group_size = 0
      then Buffer.add_char hex_buf ' '
    done;
    let ascii_views = ref [] in
    for i = bytes_per_line - 1 downto 0 do
      let v =
        if !offset + i < len
        then (
          let c = String.get s (!offset + i) in
          let n = Char.to_int c in
          if Char.is_print c
          then View.text ~attrs:data_attrs (String.of_char c)
          else (
            let escape_attrs = [ Attr.fg theme.teal; Attr.bg theme.bg ] in
            match c with
            | '\n' -> View.text ~attrs:escape_attrs "n"
            | '\r' -> View.text ~attrs:escape_attrs "r"
            | '\t' -> View.text ~attrs:escape_attrs "t"
            | _ ->
              if n < 16
              then
                View.text ~attrs:[ Attr.fg theme.blue; Attr.bg theme.bg ] (sprintf "%x" n)
              else View.text ~attrs:[ Attr.fg theme.dim; Attr.bg theme.bg ] "."))
        else View.text ~attrs:data_attrs " "
      in
      ascii_views := v :: !ascii_views
    done;
    let line_view =
      View.hcat
        ([ View.text
             ~attrs:[ Attr.fg theme.dim; Attr.bg theme.bg ]
             (format_offset !offset)
         ; View.text ~attrs:data_attrs (Buffer.contents hex_buf)
         ; View.text ~attrs:[ Attr.fg theme.dim; Attr.bg theme.bg ] "│"
         ]
         @ !ascii_views
         @ [ View.text ~attrs:[ Attr.fg theme.dim; Attr.bg theme.bg ] "│" ])
    in
    lines := line_view :: !lines;
    offset := !offset + bytes_per_line
  done;
  List.rev !lines
;;

let to_string_lines ?bytes_per_line s =
  let dummy_theme =
    { fg = Attr.Color.rgb ~r:255 ~g:255 ~b:255
    ; bg = Attr.Color.rgb ~r:0 ~g:0 ~b:0
    ; dim = Attr.Color.rgb ~r:128 ~g:128 ~b:128
    ; blue = Attr.Color.rgb ~r:0 ~g:0 ~b:255
    ; teal = Attr.Color.rgb ~r:0 ~g:255 ~b:255
    }
  in
  let views = render ?bytes_per_line dummy_theme s in
  List.map views ~f:(fun v ->
    let image = View.Private.notty_image v in
    (* Render the view to plain text using dumb terminal *)
    let w = Notty.I.width image in
    let buf = Buffer.create (w + 10) in
    Notty.Render.to_buffer buf Notty.Cap.dumb (0, 0) (w, 1) image;
    Buffer.contents buf)
;;
