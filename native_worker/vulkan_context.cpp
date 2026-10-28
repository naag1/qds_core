#include "vulkan_context.hpp"
#include <vector>

namespace qds {
VulkanContext::~VulkanContext() {
    if (device_) { if (fence_) vkDestroyFence(device_, fence_, nullptr); if (command_pool_) vkDestroyCommandPool(device_, command_pool_, nullptr); vkDestroyDevice(device_, nullptr); }
    if (instance_) vkDestroyInstance(instance_, nullptr);
}
bool VulkanContext::initialize(std::string& error) {
    VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO}; app.pApplicationName="qds_vulkan_worker"; app.apiVersion=VK_API_VERSION_1_2;
    VkInstanceCreateInfo ci{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO}; ci.pApplicationInfo=&app;
    if (vkCreateInstance(&ci,nullptr,&instance_)!=VK_SUCCESS) { error="vkCreateInstance failed"; return false; }
    std::uint32_t count=0; vkEnumeratePhysicalDevices(instance_,&count,nullptr); if(!count){error="no Vulkan devices";return false;}
    std::vector<VkPhysicalDevice> devices(count); vkEnumeratePhysicalDevices(instance_,&count,devices.data());
    for(auto candidate:devices){ VkPhysicalDeviceProperties p{}; vkGetPhysicalDeviceProperties(candidate,&p); std::uint32_t queues=0; vkGetPhysicalDeviceQueueFamilyProperties(candidate,&queues,nullptr); std::vector<VkQueueFamilyProperties> q(queues); vkGetPhysicalDeviceQueueFamilyProperties(candidate,&queues,q.data()); for(std::uint32_t i=0;i<queues;i++) if(q[i].queueFlags&VK_QUEUE_COMPUTE_BIT){ if(!physical_device_ || p.deviceType==VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU){physical_device_=candidate;queue_family_=i;device_name_=p.deviceName;} break; } }
    if(!physical_device_){error="no compute queue";return false;}
    float priority=1.f; VkDeviceQueueCreateInfo qci{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO}; qci.queueFamilyIndex=queue_family_;qci.queueCount=1;qci.pQueuePriorities=&priority;
    VkDeviceCreateInfo dci{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO};dci.queueCreateInfoCount=1;dci.pQueueCreateInfos=&qci;
    if(vkCreateDevice(physical_device_,&dci,nullptr,&device_)!=VK_SUCCESS){error="vkCreateDevice failed";return false;} vkGetDeviceQueue(device_,queue_family_,0,&queue_);
    VkCommandPoolCreateInfo pool{VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO};pool.queueFamilyIndex=queue_family_;pool.flags=VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    if(vkCreateCommandPool(device_,&pool,nullptr,&command_pool_)!=VK_SUCCESS){error="vkCreateCommandPool failed";return false;}
    VkFenceCreateInfo f{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO}; if(vkCreateFence(device_,&f,nullptr,&fence_)!=VK_SUCCESS){error="vkCreateFence failed";return false;} return true;
}
}
