
from subprocess import check_output
import subprocess 

result1 = []
result2 = []
result3 = []
tmp1 = 0.0
tmp2 = 0.0
tmp3 = 0.0
for i in range(1000):

    if(i % 100 == 0):
        result1.append(tmp1)
        result2.append(tmp2)
        result3.append(tmp3)
    out = check_output(["./main", "-p"])
    split_out = out.split(' ')
    tmp1  = tmp1 + float(split_out[0])
    tmp2  = tmp2 + float(split_out[1])
    tmp3  = tmp3 + float(split_out[2])
result1.append(tmp1)
result2.append(tmp2)
result3.append(tmp3)

print(result1)
print(result2)
print(result3)
 