
import matplotlib.pyplot as plt


number = [0,100,200,300,400,500,600,700,800,900,1000]
LHS19 = [0.0, 583.5619999999998, 1177.9439999999995, 1775.4589999999992, 2363.150999999999, 2955.1240000000016, 3544.9660000000003, 4139.720000000001, 4734.643000000002, 5323.277000000005, 5916.366000000005]
QCH20 = [0.0, 549.2760000000001, 1099.5689999999997, 1648.5760000000005, 2199.3950000000004, 2763.6490000000017, 3311.0009999999993, 3867.659999999999, 4426.383999999999, 4999.264999999996, 5567.289999999998]
LLW21 = [0.0, 295.52000000000004, 602.5389999999998, 901.5059999999997, 1221.4209999999994, 1531.5149999999992, 1830.8059999999984, 2156.7379999999976, 2427.8699999999994, 2687.5119999999974, 2965.6789999999987]
Ours =[0.0, 252.9290000000001, 508.1669999999999, 761.7729999999998, 1014.3369999999999, 1269.714, 1525.8210000000013, 1780.2600000000002, 2041.327, 2294.5830000000014, 2547.229000000001]




plt.figure(figsize=(15,10),linewidth = 2)
plt.plot(number,LHS19,'o-',color = 'g', markersize=10, label="LHS19")

plt.plot(number,QCH20,'x-',color = 'b',  markersize=10, label="QCH20")

plt.plot(number,LLW21,'s-',color = 'k', markersize=10,  label="LLW21")

plt.plot(number,Ours,'*-',color = 'r', markersize=10,  label="Ours")



plt.xticks(fontsize=20)

plt.yticks(fontsize=20)


plt.xlabel("Number of keywords", fontsize=30, labelpad = 15)

plt.xlim([0,1000])
plt.ylim([0, 6000])

plt.ylabel("Time cost of keyword encryption (ms)", fontsize=30, labelpad = 20)


plt.legend(loc = "best", fontsize=20)

plt.savefig("enc.png",dpi=600)