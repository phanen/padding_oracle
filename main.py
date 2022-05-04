import os
import binascii


# import time
#
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# from Crypto.Random import get_random_bytes

# 4e9bd8fb5331702fb4a7ea7e0b9ec337
# 0e4ac53f9f569e53ccb0e035f9c8ed4f
# ddc0f0c4e4d41b2d3b70a1d73fa6d7f5
# 3ac4758c8e179d4a1f1a47978c879205


# Encryption server
def encrypt_server(input_: str):
    cmd = r"bin\enc_oracle.exe " + input_
    rst = os.system(cmd)
    return rst


# Decryption server, request the sever and parse the reply
# return: Ture  -- when the PKCS#7 padding is correct
#         False -- when the PKCS#7 padding is incorrect
def decrypt_server(input_: str) -> bool:
    cmd = r"bin\dec_oracle.exe " + input_
    rst = os.system(cmd)
    return rst == 200


# 当 z != 16, 说明前面还有没恢复的明文
# a)	更新 r 的后 z 字节.
# i.	让填充均为 z+1 的块与 a 的后 z 个字节异或, 得到的是 -- 使得最终结果填充是 z+1 的 r 的后 z 字节
# ii.	穷举 r 的倒数第 z+1 个字节直到使得 r|| y 通过测试, 让 r 该字节异或 z + 1 得到 a 的倒数第 z+1 位
# b)	z = z+1


# 整个过程, 分两步:
#   - 破解中间状态 mid_state
#   - mid_state 直接异或 cur_cipher 就得到了明文
def attack(prev_cipher: int, cur_cipher: int):
    # 破解中间状态过程, 分四步:
    #   - 先找到 prev_guess 满足: prev_guess || cur_cipher 通过解密服务器返回 HTTP 200
    #   - 然后, 确定解密服务器此时解密出结果的填充长度 cur_padding_len
    #   - 根据 cur_padding_len 求出 mid_state 的后 cur_padding_len 字节
    #   - cur_padding_len != 16, 继续爆破出 mid_state 的前面字节

    # 整数形式的 val 转换为 字符形式的 val || cur_cipher, 并填充到 32 字节
    def parse(val):
        raw_req = hex((val << 128) | cur_cipher)[2:]
        return (64 - len(raw_req)) * "0" + raw_req

    # 找一个合法 prev_guess
    prev_guess = 0
    for prev_guess in range(0x100):
        if decrypt_server(parse(prev_guess)):
            break

    # 确定填充长度 cur_padding_len
    # 策略 1
    #   - 遍历 prev_guess 每一字节(从高位开始)
    #   - 对第 i 字节(从 0 开始), 再遍历每一种可能并发送请求, 如果服务器都能通过, 说明填充长度不是 16 - i
    cur_padding_len = 16
    reply = True
    adder = 0x01_00_00_00_00_00_00_00_00_00_00_00_00_00_00_00
    for cur_padding_len in range(16, 1, -1):
        tmp = prev_guess
        for cur_byte in range(0x100):
            reply = decrypt_server(parse(tmp))
            if not reply:
                break
            tmp += adder
        if not reply:
            break
        adder >>= 8
    else:
        cur_padding_len = 1

    # 根据 cur_padding_len 求出 mid_state 的后 cur_padding_len 字节
    padding_block = cur_padding_len
    for i in range(cur_padding_len - 1):
        padding_block = (padding_block << 8) + cur_padding_len
    #  mid_state 的后 cur_padding_len 字节是对的, 前面的字节暂时填 0
    mid_state = prev_guess ^ padding_block

    # cur_padding_len 未到 16, 则需要继续爆破 mid_state 的剩余高位
    while cur_padding_len != 16:
        # 更新 padding_block
        padding_block = cur_padding_len + 1
        for i in range(cur_padding_len - 1):
            padding_block = (padding_block << 8) + (cur_padding_len + 1)
        # 更新 prev_guess 的后 cur_padding_len 字节
        prev_guess = padding_block ^ mid_state
        # 更新 prev_guess 的倒数第 (cur_padding_len + 1) 字节
        adder = 1 << (cur_padding_len * 8)
        for i in range(0x100):
            reply = decrypt_server(parse(prev_guess))
            if reply:  # 找到了 prev_guess 的合法倒数第 (cur_padding_len + 1) 字节
                break
            prev_guess += adder
        # 更新 mid_state 的合法倒数第 (cur_padding_len + 1) 字节, 并递增完成的字节长
        cur_padding_len += 1
        mid_state = prev_guess ^ ((padding_block << 8) + cur_padding_len)
    return mid_state ^ prev_cipher


if __name__ == '__main__':
    # decrypt_server(hex((0xddc0f0c4e4d41b2d3b70a1d73fa6d7f5 << 128) | 0x3ac4758c8e179d4a1f1a47978c879205)[2:])
    iv, c1, c2, c3 = (
        0x4e9bd8fb5331702fb4a7ea7e0b9ec337,
        0x0e4ac53f9f569e53ccb0e035f9c8ed4f,
        0xddc0f0c4e4d41b2d3b70a1d73fa6d7f5,
        0x3ac4758c8e179d4a1f1a47978c879205
    )

    m1 = hex(attack(iv, c1))[2:]
    m2 = hex(attack(c1, c2))[2:]
    m3 = hex(attack(c2, c3))[2:]

    print()
    print("HEX:")
    print(f"m1:{m1}")
    print(f"m2:{m2}")
    print(f"m3:{m3}")
    print()

    # un-padding
    pad_len = int(m3[-2:], base=16)
    m3 = m3[:32 - (pad_len * 2)]

    print("STR:")
    print(f"m1:{binascii.a2b_hex(m1)}")
    print(f"m2:{binascii.a2b_hex(m2)}")
    print(f"m3:{binascii.a2b_hex(m3)}")
    print()
    print("MSG:")
    print(binascii.a2b_hex(m1 + m2 + m3))
