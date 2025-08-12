#!/usr/bin/env python3
"""
Demo Python Script - Called via exec() from KernelScript

This script demonstrates the CORRECT usage pattern:
- Import the auto-generated wrapper (test_exec.py) 
- Use maps directly as module-level variables
"""

import sys

# Import the auto-generated KernelScript wrapper
# The wrapper handles all the file descriptor inheritance internally
try:
    import test_exec as ks
except ImportError:
    print("❌ Error: Could not import test_exec.py", file=sys.stderr)
    print("   Make sure the KernelScript wrapper was generated correctly", file=sys.stderr)
    sys.exit(1)

def main():
    """Main function - called via exec() from KernelScript"""
    print("🚀 KernelScript Python Integration Demo")
    print("=" * 40)
    
    # 1. Reading from maps
    print("\n📖 Reading from eBPF maps:")
    try:
        # Read from array map
        value = ks.packet_stats[0]
        print(f"   packet_stats[0] = {value}")
        
        value = ks.packet_stats[5]
        print(f"   packet_stats[5] = {value}")
    except Exception as e:
        print(f"   packet_stats read: {e}")
    
    try:
        # Read from hash map  
        value = ks.bandwidth_usage[1]
        print(f"   bandwidth_usage[1] = {value}")
    except Exception as e:
        print(f"   bandwidth_usage read: {e}")
    
    # 2. Writing to maps
    print("\n✏️ Writing to eBPF maps:")
    try:
        # Write to array map
        ks.packet_stats[0] = 100
        ks.packet_stats[1] = 200
        print("   packet_stats[0] = 100")
        print("   packet_stats[1] = 200")
        
        # Write to hash map
        ks.bandwidth_usage[10] = 1024
        ks.bandwidth_usage[20] = 2048
        print("   bandwidth_usage[10] = 1024")
        print("   bandwidth_usage[20] = 2048")
    except Exception as e:
        print(f"   Map write error: {e}")
    
    # 3. Reading back written values
    print("\n🔄 Reading back written values:")
    try:
        print(f"   packet_stats[0] = {ks.packet_stats[0]}")
        print(f"   packet_stats[1] = {ks.packet_stats[1]}")
        print(f"   bandwidth_usage[10] = {ks.bandwidth_usage[10]}")
        print(f"   bandwidth_usage[20] = {ks.bandwidth_usage[20]}")
    except Exception as e:
        print(f"   Read back error: {e}")
    
    # 4. Using auto-generated structs
    print("\n🏗️ Using auto-generated structs:")
    ctx = ks.xdp_md()
    ctx.data = 0x1000
    ctx.data_end = 0x2000
    ctx.ingress_ifindex = 5
    ctx.rx_queue_index = 2
    ctx.egress_ifindex = 8
    
    packet_size = ctx.data_end - ctx.data
    print(f"   Created xdp_md struct:")
    print(f"     data: 0x{ctx.data:x}")
    print(f"     data_end: 0x{ctx.data_end:x}")
    print(f"     packet_size: {packet_size} bytes")
    print(f"     ingress_ifindex: {ctx.ingress_ifindex}")
    print(f"     rx_queue_index: {ctx.rx_queue_index}")
    print(f"     egress_ifindex: {ctx.egress_ifindex}")
    
    # 5. Map operations
    print("\n🗑️ Map operations:")
    try:
        # Delete from hash map
        del ks.bandwidth_usage[10]
        print("   Deleted bandwidth_usage[10]")
        
        # Try to read deleted key
        try:
            value = ks.bandwidth_usage[10]
            print(f"   bandwidth_usage[10] = {value}")
        except KeyError:
            print("   bandwidth_usage[10] not found (expected after deletion)")
    except Exception as e:
        print(f"   Delete operation: {e}")
    
    print("\n✅ Demo completed successfully!")
    return 0

if __name__ == "__main__":
    exit(main())
