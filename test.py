
import matplotlib.pyplot as plt


number = [0,100,200,300,400,500,600,700,800,900,1000]
LHS19 =[0.0, 300.401, 607.8590000000002, 913.7990000000004, 1218.3970000000004, 1526.468000000001, 1832.5800000000008, 2141.3990000000017, 2446.5020000000045, 2752.068000000004, 3056.7800000000034]
QCH20 =[0.0, 66.418, 135.15600000000003, 203.26700000000005, 270.52599999999995, 336.72999999999985, 404.7649999999995, 473.41199999999924, 540.8989999999993, 609.5709999999991, 679.4179999999988]
LLW21 = [0.0, 206.328, 408.65400000000005, 600.8550000000004, 805.6110000000006, 1025.2970000000007, 1228.5659999999998, 1447.9569999999997, 1649.4699999999993, 1859.207, 2055.191000000001]
Ours =[0.0, 87.68, 176.52500000000018, 264.3910000000004, 351.67600000000044, 440.5170000000004, 529.5540000000005, 617.5560000000007, 705.0910000000007, 793.4930000000008, 881.8900000000015]



plt.figure(figsize=(15,10),linewidth = 2)
plt.plot(number,LHS19,'o-',color = 'g', markersize=10, label="LHS19")

plt.plot(number,QCH20,'x-',color = 'b',  markersize=10, label="QCH20")

plt.plot(number,LLW21,'s-',color = 'k', markersize=10,  label="LLW21")

plt.plot(number,Ours,'*-',color = 'r', markersize=10,  label="Ours")



plt.xticks(fontsize=20)

plt.yticks(fontsize=20)


plt.xlabel("Number of keywords", fontsize=30, labelpad = 15)

plt.xlim([0,1000])
plt.ylim([0, 4000])

plt.ylabel("Time cost of keyword encryption (ms)", fontsize=30, labelpad = 20)


plt.legend(loc = "best", fontsize=20)

plt.savefig("test.png",dpi=600)
