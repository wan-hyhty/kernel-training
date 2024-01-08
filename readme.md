# Tìm hiểu về kernel
## Nguồn tham khảo
https://hackmd.io/@ChinoKafuu/kernel

## Một số thông tin
- Thông thường khi tôi chơi ctf, quá trình debug tôi thấy rằng vùng địa chỉ từ 0x5.. đến 0x7fff mà tựa hỏi sau 0x7fff... là gì? Tại sao không đến 0xffff. Thì trong quá trình tìm hiểu kernel, tôi nhận thấy rằng, máy tính chia thành 2 phần là `user-land` và `kernel-land`. Dưới đây là vùng nhớ của 32/64 bit
![Alt text](bin/image.png)
- Khi chúng ta exploit các file bin, các tiến trình đang hoạt động ở user-land. Khi exploit kernel, ta có thể can thiệp cả user-land và kernel-land. 

## Một số file quan trọng
`vmlinuz/bzImage`