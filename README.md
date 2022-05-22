## bzsprof

This simple profiler collects stacktraces of all processes
and the kernel periodically.

## Dependencies

 - BlazeSym (https://github.com/ThinkerYzu1/blazesym)

## Build

Building bzsprof need Rust installed.

 - cd path/to/bzsprof/
 - git submodule init && git submodule update
 - cd src
 - make

## Output

The output of the tool looks like the following example.

    P15: value 131560674, id 207
    
    sample size = 312
    PID 2908, TID 2937
    Kernel (14):
      0 [<fffffffffffffe00>] tail.36+0x3e82cb99 :0
      1 [<00007fe9d58ab444>] auto js::MapGCThingTyped<DoCallback<JS::Value>(js::GenericTracer*, JS::Value*, char const*)::{lambda(auto:1)#1}>(JS::Value const&, DoCallback<JS::Value>(js::GenericTracer*, JS::Value*, char const*)::{lambda(auto:1)#1}&&)+0x134 :0
      2 [<00007fe9d58a3efc>] bool js::gc::TraceEdgeInternal<JS::Value>(JSTracer*, JS::Value*, char const*)+0x4c :0
      3 [<00007fe9d54dc19c>] JSObject::traceChildren(JSTracer*)+0x12c :0
      4 [<00007fe9d5871cfa>] UpdateArenaListSegmentPointers(js::gc::GCRuntime*, ArenaListSegment const&)+0xbea :0
      5 [<00007fe9d588dce6>] js::gc::ParallelWorker<ArenaListSegment, ArenasToUpdate>::run(js::AutoLockHelperThreadState&)+0x56 :0
      6 [<00007fe9d5893f7e>] js::GCParallelTask::runHelperThreadTask(js::AutoLockHelperThreadState&)+0xbe :0
      7 [<00007fe9d54a3f76>] js::GlobalHelperThreadState::runTaskLocked(js::HelperThreadTask*, js::AutoLockHelperThreadState&)+0x66 :0
      8 [<00007fe9d54a3b59>] JS::RunHelperThreadTask()+0x69 :0
      9 [<00007fe9d138f769>] HelperThreadTaskHandler::Run()+0x9 :0
      10 [<00007fe9d0ad1f28>] mozilla::TaskController::RunPoolThread()+0x3e8 :0
      11 [<00007fe9da773da9>] _pt_root+0x229 :0
      12 [<000056389c6ccac2>] set_alt_signal_stack_and_start(PthreadCreateParams*)+0xd2 :0
      13 [<00007fe9da895947>] UNKNOWN
    ABI: 2
    User BP: 0x7fe9c390e870
    User SP: 0x7fe9c390e858
    User IP: 0x7fe9d58ab444
    Userspace (128):
      000 - 07 00 00 00 00 00 00 00 80 00 07 24 89 08 00 00
      010 - 07 00 00 00 00 00 00 00 c0 e8 90 c3 e9 7f 00 00
      020 - fc 3e 8a d5 e9 7f 00 00 01 58 03 24 89 08 fb ff
      030 - 50 e9 90 c3 e9 7f 00 00 80 e8 90 c3 e9 7f 00 00
      040 - 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      050 - 00 82 f8 54 4c 8c 6a 71 80 00 07 24 89 08 00 00
      060 - 58 e9 90 c3 e9 7f 00 00 20 e9 90 c3 e9 7f 00 00
      070 - 9c c1 4d d5 e9 7f 00 00 00 82 f8 54 4c 8c 6a 71

