(module
  (memory (;0;) 17)
  (data (;0;) (i32.const 1048576) "a static table")
  (func $_ZN11ferret_core7fixture7indexed17h0000000000000001E (;0;) (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
    i32.load8_u
  )
  (func $_ZN11ferret_core7fixture12masked_table17h0000000000000002E (;1;) (param i32) (result i32)
    local.get 0
    i32.const 31
    i32.and
    i32.load8_u offset=1048700
  )
  (func $_ZN11ferret_core7fixture11local_table17h0000000000000003E (;2;) (param i32) (result i32)
    local.get 0
    i32.load8_u offset=1048700
  )
  (func $_ZN11ferret_core7fixture9const_add17h0000000000000004E (;3;) (param i32) (result i32)
    local.get 0
    i32.const 1048700
    i32.add
    i32.load8_u
  )
  (func $_ZN11ferret_core7fixture6scaled17h0000000000000005E (;4;) (param i32) (result i32)
    local.get 0
    i32.const 2
    i32.shl
    i32.load offset=1048700
  )
  (func $_ZN11ferret_core7fixture8division17h0000000000000006E (;5;) (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.div_u
    local.get 1
    i32.rem_s
  )
  (func $_ZN11ferret_core7fixture8wide_rem17h0000000000000007E (;6;) (param i64 i64) (result i64)
    local.get 0
    local.get 1
    i64.rem_u
  )
  (func $_ZN11ferret_core7fixture5jumps17h0000000000000008E (;7;) (param i32) (result i32)
    block
      block
        local.get 0
        br_table 0 1
      end
      i32.const 1
      return
    end
    i32.const 2
  )
  (func $_ZN11ferret_core7fixture4root17h0000000000000009E (;8;) (param f64) (result f64)
    local.get 0
    f64.sqrt
    local.get 0
    f64.div
  )
)
