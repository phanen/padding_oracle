# Introduction
- Padding oracle attack on AES-128-cbc
- C++ and python implementaion


# The test sample
Input:
```
  iv <- {0x4e9bd8fb5331702f, 0xb4a7ea7e0b9ec337u};
  c1 <- {0x0e4ac53f9f569e53, 0xccb0e035f9c8ed4fu};
  c2 <- {0xddc0f0c4e4d41b2d, 0x3b70a1d73fa6d7f5u};
  c3 <- {0x3ac4758c8e179d4a, 0x1f1a47978c879205u};
```

Output:

```
666c61677b3164613531303238353332
66326563653337666432363761356134
38663838347d0a0a0a0a0a0a0a0a0a0a

flag{1da51028532f2ece37fd267a5a48f884}
```
