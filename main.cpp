/**
 * @file main.cpp
 * @author phanen
 * @brief Duplicate python implementation into cc
 * @date 2022-05-22
 *
 * @copyright Copyright (c) 2022. phanen
 *
 */
#include <iostream>
#include <sstream>
#include <windows.h>
#include <cctype>
#include <iomanip>
// #include <bitset>
using namespace std;

typedef pair<uint64_t, uint64_t> ci_t;

bool is_big_endian()
{
    return (*(char *)((int)1) == 0);
}

void show_ascii(uint64_t a, bool endian)
{
    char *buf_p = (char *)&a;
    int len = sizeof(uint64_t);
    if (is_big_endian())
    {
        while (len--)
            cout << *buf_p++;
    }
    else
    {
        buf_p += (len - 1);
        while (len--)
            cout << *buf_p--;
    }
    // cout.flush();
}

// Decryption server
bool oracle(const string &input)
{
    string cmd = ".\\bin\\dec_oracle.exe " + input;
    int rst = system(cmd.c_str());
    return rst == 200;
}

inline string pad(const string &a)
{
    string ret = "";
    uint64_t len = a.size();
    for (uint64_t i = 0; i < 16 - len; i++)
    {
        ret += '0';
    }
    ret += a;
    return ret;
}

inline string parse(ci_t val)
{
    string ret;
    ostringstream sh, sl;
    sh << hex << val.first;
    sl << hex << val.second;
    string high = sh.str();
    string low = sl.str();

    ret = pad(high) + pad(low);
    return ret;
}

ci_t broadcast(uint64_t unit, uint64_t times)
{

    ci_t pad_block{0, unit};

    for (uint64_t i = 1; i <= times - 1; i++)
    {
        if (i <= 7)
        {
            pad_block.second = (pad_block.second << 8) + unit;
        }
        else if (i == 8)
        {
            pad_block.first = unit;
        }
        else // i>8 --> 9th - 15th
        {
            pad_block.first = (pad_block.first << 8) + unit;
        }
    }
    return pad_block;
}

ci_t operator^(ci_t l, ci_t r)
{
    return {l.first ^ r.first, l.second ^ r.second};
}
ci_t attack(ci_t prev_cipher, ci_t cur_cipher)
{
    ci_t r{0, 0};

    string apd = parse(cur_cipher);
    uint64_t i = 0;
    for (; i < 0x100; i++)
    {
        if (oracle(parse(r) + apd))
            break;
        ++r.second;
    }

    uint64_t pad_len;
    i = 1;
    uint64_t adder = 1;
    for (; i <= 16; i++)
    {
        if (i == 9)
            adder = 1;

        ci_t tmp = r;

        if (i <= 8)
            tmp.second += adder;
        else
            tmp.first += adder;

        bool reply = oracle(parse(tmp) + apd);
        if (reply)
        {
            break;
        }
        adder <<= 8;
    }

    pad_len = i - 1;

    ci_t pad_block = broadcast(pad_len, pad_len);
    ci_t a = r ^ pad_block;
    // cout << parse(r) << endl;
    // exit(0);
    // 0100 ^  0001 -> 0x0101

    while (pad_len != 16)
    {
        pad_block = broadcast(pad_len + 1, pad_len);
        r = pad_block ^ a;

        adder = (1ull << ((pad_len % 8ull) * 8ull));
        // replace it with the followed line:
        //      adder = (1 << ((pad_len % 8ull) * 8ull));
        // to cause a horrible bug  (:

        for (uint64_t i = 0; i < 0x100; i++)
        {
            // cout << parse(r) + apd << endl;
            // exit(0);
            bool reply = oracle(parse(r) + apd);
            if (reply)
                break;
            if (pad_len < 8)
                r.second += adder;
            else
                r.first += adder;
        }
        ++pad_len;
        a = r ^ broadcast(pad_len, pad_len);
    }
    return a ^ prev_cipher;
}

int main()
{

    ci_t iv = {0x4e9bd8fb5331702fu, 0xb4a7ea7e0b9ec337u};
    ci_t c1 = {0x0e4ac53f9f569e53u, 0xccb0e035f9c8ed4fu};
    ci_t c2 = {0xddc0f0c4e4d41b2du, 0x3b70a1d73fa6d7f5u};
    ci_t c3 = {0x3ac4758c8e179d4au, 0x1f1a47978c879205u};

    ci_t m1 = attack(iv, c1);
    ci_t m2 = attack(c1, c2);
    ci_t m3 = attack(c2, c3);
    cout << hex << setfill('0')
         << setw(16) << m1.first << setw(16) << m1.second << endl
         << setw(16) << m2.first << setw(16) << m2.second << endl
         << setw(16) << m3.first << setw(16) << m3.second << endl;

    void show_ascii(uint64_t);
    show_ascii(m1.first);
    show_ascii(m1.second);
    cout.flush();
    show_ascii(m2.first);
    show_ascii(m2.second);
    cout.flush();
    show_ascii(m3.first);
    show_ascii(m3.second);
    cout.flush();
}
