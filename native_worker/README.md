# QDS Vulkan worker

Build this optional worker with a Vulkan SDK and CMake:

```powershell
cmake -S native_worker -B native_worker/build
cmake --build native_worker/build --config Release
$env:QDS_VULKAN_WORKER = (Resolve-Path native_worker/build/Release/qds_vulkan_worker.exe)
```

The current executable is the device/protocol probe used by the Python runtime
to select Vulkan or CPU mode. The shader defines the first fixed-width packet
feature ABI; full PCAP staging, flow hashing, and aggregation kernels should be
added behind this ABI before enabling GPU results in production.
