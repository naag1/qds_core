#pragma once
#include "vulkan_context.hpp"
#include <filesystem>
#include <vector>

namespace qds {
struct VulkanBuffer { VkBuffer buffer=VK_NULL_HANDLE; VkDeviceMemory memory=VK_NULL_HANDLE; VkDeviceSize size=0; };
class VulkanPipeline {
public:
    explicit VulkanPipeline(VulkanContext& context) : context_(context) {}
    ~VulkanPipeline();
    bool initialize(const std::filesystem::path& shader_dir, std::string& error);
    bool create_buffer(VkDeviceSize size, VkBufferUsageFlags usage, VkMemoryPropertyFlags properties, VulkanBuffer& out, std::string& error);
    void destroy_buffer(VulkanBuffer& buffer);
    VkPipeline decode_pipeline() const { return decode_pipeline_; }
    VkPipelineLayout layout() const { return layout_; }
    VkDescriptorSetLayout descriptors() const { return descriptors_; }
private:
    VkShaderModule load_shader(const std::filesystem::path&, std::string& error);
    std::uint32_t memory_type(std::uint32_t bits, VkMemoryPropertyFlags properties) const;
    VulkanContext& context_; VkDescriptorSetLayout descriptors_=VK_NULL_HANDLE; VkPipelineLayout layout_=VK_NULL_HANDLE;
    VkPipeline decode_pipeline_=VK_NULL_HANDLE; VkDescriptorPool descriptor_pool_=VK_NULL_HANDLE;
};
}
