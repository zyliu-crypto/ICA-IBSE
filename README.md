# Public-key Authentication Searchable Encryption


This project provides  PoC implementations of public-key authentication searchable encryption schemes:

1. LLZ19 - Inf. Sci. - [Designated-server identity-based authenticated encryption with keyword search for encrypted emails](https://doi.org/10.1016/j.ins.2019.01.004)
2. QCHLZ20 - Inf. Sci. - [Public-key authenticated encryption with keyword search revisited: Security model and constructions](https://doi.org/10.1016/j.ins.2019.12.063)
3. LLW21 - IEEE Trans. Ind. Informatics - [Pairing-Free Certificate-Based Searchable Encryption Supporting Privacy-Preserving Keyword Search Function for IIoTs](https://doi.org/10.1109/TII.2020.3006474)
4. LTTCM21 - ePrint - [Identity-certifying Authority-aided Authenticated Searchable Encryption Framework in Cloud System]()



Required Library
=======
1. [GMP](https://gmplib.org/)
2. [PBC](https://crypto.stanford.edu/pbc/)
3. [SHA3IUF](https://github.com/brainhub/SHA3IUF)


How to run?
===========

'''
gcc file.c sha3.c -L. -lpbc -lgmp
./a.out
```
