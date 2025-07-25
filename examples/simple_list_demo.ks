// Simple List Demo - demonstrates KernelScript list functionality

struct SimpleData {
    id: u32,
    value: u64,
}

// List declaration - no flags or pinning allowed
var data_list : list<SimpleData>

@xdp
fn simple_processor(ctx: *xdp_md) -> xdp_action {
    // Create some data
    var data1 = SimpleData {
        id : 1,
        value: 100
    }
    var data2 = SimpleData {
        id : 2,
        value : 200
    }
    
    // Add data to list using eBPF list operations
    data_list.push_back(data1)
    data_list.push_front(data2)
    
    // Pop data from list
    var front_item = data_list.pop_front()
    if (front_item != none) {
        // Process the item
        if (front_item.id > 0) {
            return XDP_PASS
        }
    }
    
    var back_item = data_list.pop_back()
    if (back_item != none) {
        // Process the back item
        return XDP_PASS
    }
    
    return XDP_DROP
} 