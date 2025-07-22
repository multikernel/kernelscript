"""
Simple network utilities for KernelScript import testing
"""

def calculate_bandwidth(packets_per_second, avg_packet_size=1500):
    """Calculate bandwidth in bytes per second"""
    return packets_per_second * avg_packet_size

def is_rate_limited(current_rate, max_rate=1000000):
    """Check if current rate exceeds maximum allowed rate"""
    return current_rate > max_rate

def get_default_mtu():
    """Get default MTU size"""
    return 1500

def format_packet_count(count):
    """Format packet count for display"""
    if count > 1000000:
        return f"{count / 1000000:.1f}M packets"
    elif count > 1000:
        return f"{count / 1000:.1f}K packets"
    else:
        return f"{count} packets"

# Configuration constants
MAX_PACKET_SIZE = 9000
DEFAULT_TIMEOUT = 30 