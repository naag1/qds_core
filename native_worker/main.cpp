#include <cstdint>
#include <iostream>
#ifdef QDS_HAS_VULKAN
#include <vulkan/vulkan.h>
#endif
int main() {
#ifdef QDS_HAS_VULKAN
    uint32_t count = 0;
    if (vkEnumerateInstanceVersion(&count) != VK_SUCCESS) return 2;
    std::cout << "{\"status\":\"READY\",\"backend\":\"vulkan\",\"api_version\":"
              << VK_VERSION_MAJOR(count) << "." << VK_VERSION_MINOR(count) << "}\n";
#else
    std::cout << "{\"status\":\"UNAVAILABLE\",\"backend\":\"cpu\",\"reason\":\"vulkan_sdk_not_found\"}\n";
#endif
    return 0;
}
