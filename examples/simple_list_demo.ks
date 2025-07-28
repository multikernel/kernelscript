// Simple List Demo - demonstrates KernelScript list functionality

struct SimpleData {
    id: u32,
    value: u64,
}

// List declaration - C-style pointer list
var data_list : list<*SimpleData>

@xdp
fn simple_processor(ctx: *xdp_md) -> xdp_action {
    // Create some data - heap allocated for safety
    var data1 = new SimpleData()
    if (data1 == null) {
        return XDP_DROP  // Handle allocation failure
    }
    data1->id = 1
    data1->value = 100
    
    var data2 = new SimpleData()
    if (data2 == null) {
        return XDP_DROP  // Handle allocation failure
    }
    data2->id = 2
    data2->value = 200
    
    // Add pointers to list - ownership transferred to list
    data_list.push_back(data1)
    data_list.push_front(data2)
    
    // Pop data from list - ownership returned
    var front_item = data_list.pop_front()
    if (front_item != none) {
        // Process the item
        if (front_item->id > 0) {
            // Must manually free when done with popped items
            delete front_item
            return XDP_PASS
        }
        delete front_item
    }
    
    var back_item = data_list.pop_back()
    if (back_item != none) {
        // Process the back item
        delete back_item  // Manual cleanup required
        return XDP_PASS
    }
    
    return XDP_DROP
}

fn main() -> i32 {
    var prog = load(simple_processor)
    attach(prog, "lo", 0)
} 