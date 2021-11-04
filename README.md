# ICA-IBSE


This project provides PoC implementations to evaluate the performance of the following schemes:

1. LLZ19 - Inf. Sci. - [Designated-server identity-based authenticated encryption with keyword search for encrypted emails](https://doi.org/10.1016/j.ins.2019.01.004)
2. QCHLZ20 - Inf. Sci. - [Public-key authenticated encryption with keyword search revisited: Security model and constructions](https://doi.org/10.1016/j.ins.2019.12.063)
3. LLW21 - IEEE Trans. Ind. Informatics - [Pairing-Free Certificate-Based Searchable Encryption Supporting Privacy-Preserving Keyword Search Function for IIoTs](https://doi.org/10.1109/TII.2020.3006474)
4. LTTCM21 (Ours) - IEEE Syst. J - [Identity-certifying Authority-aided Identity-based Searchable Encryption Framework in Cloud Systems](https://ieeexplore.ieee.org/document/9551280)

For bilinear-pairing schemes (LLZ19, QCHIZ20, LTTCM21), we implement them by using PBC library with Type-A pairing (160, 512) for 80-bit security.

For pairing-free scheme (LLW21), we implement it by using MIRACL library with parameter spec160r1 for 80-bit security.


Required Library
===========
1. [GMP](https://gmplib.org/)
2. [PBC](https://crypto.stanford.edu/pbc/)
3. [MIRACL](https://github.com/miracl/MIRACL)
4. [SHA3IUF](https://github.com/brainhub/SHA3IUF)



How to complie and run?
===========
For bilinear-pairing scheme:
```
gcc -c sha.c
gcc -c file.c
gcc -o file file.o sha.o -lpbc -lgmp
./file
```

For pairing-free scheme:
```
gcc -c LLW_miracl.c
gcc -o file file.o -lmiracl
./file
```

Testing the costs of operations over bilinear groups and hash function:
```
gcc -c sha.c
gcc -c test_oper_time_for_bilinear_group_and_hash.c
gcc -o test_oper_time_for_bilinear_group_and_hash test_oper_time_for_bilinear_group_and_hash.o sha.o -lpbc -lgmp
./test_oper_time_for_bilinear_group_and_hash
```

Testing the costs of operations over elliptic groups:
```
gcc -c test_oper_time_for_ec_group.c
gcc -o test_oper_time_for_ec_group test_oper_time_for_ec_group.o -lmiracl
./test_oper_time_for_ec_group
```

Generating the cost of scheme for 1000 times:
```
python3 run.py  # change the file name in run.py first
```

Generating result.png
```
python3 enc.py/trapdoor.py/test.py
```

Result
===========
Encrypt keywords             |  Generate trapdoors       | Test
:-------------------------:|:-------------------------:|:-------------------------:
![](enc.png)  |  ![](trapdoor.png) | ![](test.png)
