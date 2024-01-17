# ret2usr
## Demo part 1
- https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/#the-simplest-exploit---ret2usr
### Setup
- https://hackmd.io/@ChinoKafuu/kernel#2-Setup-v%C3%A0-khai-th%C3%A1c-th%E1%BB%AD
### Phân tích file hackme.ko
- Ở đây mình thấy có 2 hàm mà có tương tác user-kernel là `hackme_write` và `hackme_read`

#### hackme_read
- Ở hàm hackme_read, ta thấy hàm này sẽ copy stack của kernel vào hackme_buf (`_memcpy(hackme_buf, tmp);`), sau đó sẽ copy stack đó về stack của user (`v6 = copy_to_user(data, hackme_buf, v5) == 0;`)
=> Ta có thể leak canary để ret2usr nếu có bof
```c
ssize_t __fastcall hackme_read(file *f, char *data, size_t size, loff_t *off)
{
  unsigned __int64 v4; // rdx
  unsigned __int64 v5; // rbx
  bool v6; // zf
  ssize_t result; // rax
  int tmp[32]; // [rsp+0h] [rbp-A0h] BYREF
  unsigned __int64 v9; // [rsp+80h] [rbp-20h]

  _fentry__(f, data, size, off);
  v5 = v4;
  v9 = __readgsqword(0x28u);
  _memcpy(hackme_buf, tmp);
  if ( v5 > 0x1000 )
  {
    _warn_printk("Buffer overflow detected (%d < %lu)!\n", 4096LL, v5);
    BUG();
  }
  _check_object_size(hackme_buf, v5, 1LL);
  v6 = copy_to_user(data, hackme_buf, v5) == 0;
  result = -14LL;
  if ( v6 )
    return v5;
  return result;
}
```

#### hackme_write
- Ở hàm `hackme_write`, ta thấy hàm copy stack của user vào hackme_buf (`copy_from_user(hackme_buf, data, v5)`) và copy vào stack của kernel. Lỗ hổng ở đây là hàm không kiểm tra kích thước khi copy dẫn tới bof


```c
ssize_t __fastcall hackme_write(file *f, const char *data, size_t size, loff_t *off)
{
  unsigned __int64 v4; // rdx
  ssize_t v5; // rbx
  int tmp[32]; // [rsp+0h] [rbp-A0h] BYREF
  unsigned __int64 v8; // [rsp+80h] [rbp-20h]

  _fentry__(f, data, size, off);
  v5 = v4;
  v8 = __readgsqword(0x28u);
  if ( v4 > 0x1000 )
  {
    _warn_printk("Buffer overflow detected (%d < %lu)!\n", 4096LL, v4);
    BUG();
  }
  _check_object_size(hackme_buf, v4, 0LL);
  if ( copy_from_user(hackme_buf, data, v5) )
    return -14LL;
  _memcpy(tmp, hackme_buf);
  return v5;
}
```

###