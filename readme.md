# Tìm hiểu về kernel

## Nguồn tham khảo

https://hackmd.io/@ChinoKafuu/kernel

## Một số thông tin

- Thông thường khi tôi chơi ctf, quá trình debug tôi thấy rằng vùng địa chỉ từ 0x5.. đến 0x7fff mà tựa hỏi sau 0x7fff... là gì? Tại sao không đến 0xffff. Thì trong quá trình tìm hiểu kernel, tôi nhận thấy rằng, máy tính chia thành 2 phần là `user-land` và `kernel-land`. Dưới đây là vùng nhớ của 32/64 bit
  ![Alt text](bin/image.png)
- Khi chúng ta exploit các file bin, các tiến trình đang hoạt động ở user-land. Khi exploit kernel, ta có thể can thiệp cả user-land và kernel-land.
- Các thiết bị như bàn phím, chuột thường được xử lý ở user-land. Để tương tác với kernel-land, các process sẽ yêu cầu sự giúp đỡ từ kernel-land bằng `syscall`
- Có một số lớp bảo vệ nhưng chúng ta sẽ tìm hiểu sau.
### cách định nghĩa 1 fops
- Việc exploit sẽ là tương tác với 1 module kernel (file .ko - là một phần mở rộng của kernel, để có thể thêm chức năng mà không phải build lại kernel). Và như ở thông tin trên, ta chỉ có thể tương tác với kernel thông qua syscall, vậy làm sao để khi ta gọi 1 syscall read thì nó sẽ thực thi read trong kernel hay read trong module? Sau một hồi hỏi cung chatGPT thì tôi có 1 số thông tin như sau. Đầu tiên để tương tác với 1 module, ta cần mở file(hàm open(<tên file>, ...)). Thứ 2, trong module cần có một cấu trúc `file_operations` (fops) chứa các con trỏ trỏ đến các hàm xử lý trong module. Ví dụ
```
static struct file_operations fops = {
    .open = my_module_open,
    .read = my_module_read,
    .write = my_module_write,
    .release = my_module_release,
    // ...
};
```
```c
g_fd = open("/dev/hackme", O_RDWR);
read(g_fd, buf, sizeof(buf))
// thực thi hàm read trong module hackme
```
# setup debug

https://github.com/ysf/gef-bata

# Một số kĩ thuật khai thác kernel

- ret2user
  - status switch
- modify cr4 register
  - bypass smep
  - bypass smap
- kpti
  - fix cr3 register
  - swapgs_restore_regs_and_return_to_usermode()
- kernel information leak
  - useful kernel structure for UAF
- modprobe_path
- userfaultfd
  - race condition
- setxattr
  - setxattr + userfaultfd
- msg_msg
- signal handler

## ret2usr
