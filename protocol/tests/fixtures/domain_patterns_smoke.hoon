::  protocol/tests/fixtures/domain_patterns_smoke.hoon
::
::  Smoke fixture for the domain-patterns library — if this file
::  fails to compile, the helpers' calling convention (wet gates over
::  a kernel's versioned state, `<graft>.state` field names) is broken.
::
::  Confirms:
::    1. Wet-gate (|*) polymorphism over a kernel-defined versioned-state
::       type-checks correctly at the call site.
::    2. The apply-<graft> field-name convention (`<graft>.state`) is
::       compatible with multi-graft kernels — i.e. a state that has
::       `counter`, `kv`, `log` fields side-by-side actually works in
::       practice (no in-tree multi-graft template demonstrates this
::       today, so this fixture is the evidence).
::    3. =^ chaining through three different apply-<graft> arms threads
::       state correctly and accumulates effects in the expected order.
::    4. audit-write produces the welded effect list in [kv-effect,
::       log-effect] order.
::
::  Compile success = all assertions passed.
::
/+  *counter-graft
/+  *kv-graft
/+  *log-graft
/+  *domain-patterns
::
::  ============================================
::  SETUP: a kernel-shaped versioned-state with three graft fields
::  ============================================
::
=>
|%
+$  smoke-state
  $:  counter=counter-state
      kv=kv-state
      log=log-state
      domain=@ud
  ==
--
::
=/  st0=smoke-state
  :*  counter=*counter-state
      kv=*kv-state
      log=*log-state
      domain=`@ud`0
  ==
::
::  ============================================
::  TEST 1: apply-counter threads state correctly
::  ============================================
::
=^  efx-c  st0  (apply-counter [%counter-increment 'hits'] st0)
?>  ?=(^ efx-c)
?>  ?=(%counter-incremented -.i.efx-c)
?>  =('hits' name.i.efx-c)
?>  =(1 value.i.efx-c)
?>  =(1 (~(got by counters.counter.st0) 'hits'))
::
::  ============================================
::  TEST 2: apply-kv threads state correctly
::  ============================================
::
=^  efx-k  st0  (apply-kv [%kv-set 'foo' `@`42] st0)
?>  ?=(^ efx-k)
?>  ?=(%kv-stored -.i.efx-k)
?>  =('foo' key.i.efx-k)
?>  =(`@`42 (~(got by store.kv.st0) 'foo'))
::
::  ============================================
::  TEST 3: =^ chain across two arms accumulates effects in order
::  ============================================
::
=^  efx-c2  st0  (apply-counter [%counter-increment 'hits'] st0)
=^  efx-l   st0  (apply-log [%log-append %step (jam 'two')] st0)
=/  combined  (weld efx-c2 efx-l)
?>  ?=(^ combined)
?>  ?=(%counter-incremented -.i.combined)
?>  ?=(^ t.combined)
?>  ?=(%log-appended -.i.t.combined)
?>  =(1 seq.i.t.combined)
::
::  ============================================
::  TEST 4: audit-write produces welded effects + threads two states
::  ============================================
::
=^  efx-a  st0  (audit-write st0 [%kv-set 'rec' `@`7] %recorded (jam 'rec=7'))
?>  ?=(^ efx-a)
?>  ?=(%kv-stored -.i.efx-a)
?>  =('rec' key.i.efx-a)
?>  ?=(^ t.efx-a)
?>  ?=(%log-appended -.i.t.efx-a)
?>  =(`@`7 (~(got by store.kv.st0) 'rec'))
?>  =(2 next-seq.log.st0)
::
::  Compile-success = smoke passed.
::
%test-domain-patterns-smoke-passed
