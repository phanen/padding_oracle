#include <iostream>
#include <bitset>
#include <sstream>
#include <map>
#include <iomanip>
using namespace std;

map<string, string> tab{
    {string("0000"), string("0")},
    {string("0001"), string("1")},
    {string("0010"), string("2")},
    {string("0011"), string("3")},
    {string("0100"), string("4")},
    {string("0101"), string("5")},
    {string("0110"), string("6")},
    {string("0111"), string("7")},
    {string("1000"), string("8")},
    {string("1001"), string("9")},
    {string("1010"), string("a")},
    {string("1011"), string("b")},
    {string("1100"), string("c")},
    {string("1101"), string("d")},
    {string("1110"), string("e")},
    {string("1111"), string("f")},
};

int main()
{
    // cout << (1 << ((4ull % 8) * 8)); // int
    // auto a = (4ull % 8);             // ull
    // auto b = (a * 8);                // ull
    // auto c = (1 << b);               // int
    // auto d = (1u << b);              // uint
}
