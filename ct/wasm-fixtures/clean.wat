(module
  (memory (;0;) 17)
  (data (;0;) (i32.const 1048576) "a static table")
  (func $_ZN11ferret_core7fixture5field17h00000000000000a1E (;0;) (param i32) (result i32)
    local.get 0
    i32.load offset=16
  )
  (func $_ZN11ferret_core7fixture8constant17h00000000000000a2E (;1;) (result i32)
    i32.const 1048700
    i32.load8_u
  )
  (func $_ZN11ferret_core7fixture5plain17h00000000000000a3E (;2;) (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.xor
    i32.const 7
    i32.and
  )
)
