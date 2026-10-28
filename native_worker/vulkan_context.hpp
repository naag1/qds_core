#pragma once
#include <vulkan/vulkan.h>
#include <string>

namespace qds {
class VulkanContext {
public:
    VulkanContext() = default;
    ~VulkanContext();
    VulkanContext(const VulkanContext&) = delete;
    VulkanContext& operator=(const VulkanContext&) = delete;
    bool initialize(std::string& error);
    VkDevice device() const { return device_; }
    VkPhysicalDevice physical_device() const { return physical_device_; }
    VkQueue queue() const { return queue_; }
    VkCommandPool command_pool() const { return command_pool_; }
    VkFence fence() const { return fence_; }
    std::uint32_t queue_family() const { return queue_family_; }
    const std::string& device_name() const { return device_name_; }
private:
    VkInstance instance_ = VK_NULL_HANDLE; VkPhysicalDevice physical_device_ = VK_NULL_HANDLE;
    VkDevice device_ = VK_NULL_HANDLE; VkQueue queue_ = VK_NULL_HANDLE;
    VkCommandPool command_pool_ = VK_NULL_HANDLE; VkFence fence_ = VK_NULL_HANDLE;
    std::uint32_t queue_family_ = 0; std::string device_name_;
};
}
