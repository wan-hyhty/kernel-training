#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char line[] = "0xffffffffb61500f0 T prepare_kernel_cred";
    char *ptr;
    unsigned long long address;

    // Tìm vị trí đầu tiên của ký tự 'x' trong dòng
    ptr = strchr(line, 'x');
    if (ptr == NULL) {
        printf("Không tìm thấy ký tự 'x'\n");
        return 1;
    }

    // Di chuyển con trỏ đến sau ký tự 'x'
    ptr++;

    // Chuyển chuỗi hex thành số nguyên
    address = strtoull(ptr, NULL, 16);

    // In ra số đã tách lấy được
    printf("addr: %llx\n", address);

    return 0;
}