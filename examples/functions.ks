include "xdp.kh"

type IpAddress = u32

@helper
fn helper_function(value: u32) -> u32 {
  return value + 10
}

@helper
fn another_helper() -> u32 {
  return 42
}

@xdp fn test_functions(ctx: *xdp_md) -> xdp_action {
  var result = helper_function(5)
  var const_val = another_helper()
  return XDP_PASS
}

fn global_function(x: u32) -> u32 {
  return x * 2
}

fn add_numbers(a: i32, b: i32) -> i32 {
  return a + b
}

fn multiply_numbers(a: i32, b: i32) -> i32 {
  return a * b
}

fn subtract_numbers(a: i32, b: i32) -> i32 {
  return a - b
}

fn process_with_callback(x: i32, y: i32, callback: fn(i32, i32) -> i32) -> i32 {
  return callback(x, y)
}

// Function pointer type declaration
type BinaryOp = fn(i32, i32) -> i32

fn main() -> i32 {
  var result = global_function(21)
  
  // Assign functions to function pointers
  var add_op: BinaryOp = add_numbers
  var mul_op: BinaryOp = multiply_numbers
  var sub_op: BinaryOp = subtract_numbers
  
  // Call functions through function pointers
  var sum = add_op(10, 20)            // Result: 30
  var product = mul_op(5, 6)          // Result: 30
  var difference = sub_op(15, 7)      // Result: 8
  
  // Higher-order function with function pointer parameter
  var callback_result = process_with_callback(4, 7, add_numbers)      // Result: 11
  var callback_result2 = process_with_callback(4, 7, multiply_numbers) // Result: 28
  
  return 0
} 