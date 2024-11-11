import numpy as np
import pandas as pd
import csv
import torch
import torch.nn.functional as F
from sklearn import metrics
import os
import subprocess

f = open("./output.txt", 'r')
time_data = f.readlines()
f.close()

database = np.zeros((len(time_data), 3), dtype=float)

for idx, line in enumerate(time_data):
    t = line.split(',')
    database[idx][0] = float(t[0])
    database[idx][1] = float(t[1])
    database[idx][2] = float(t[2])

aver_database = np.zeros((int(len(time_data)/10), 3), dtype=float)

aver_time=0
aver_power=0
for i in range(len(database)):
    if i%10==9:
        aver_database[int(i/10)][0] = database[i][0]
        aver_database[int(i/10)][1] = aver_time/10
        aver_database[int(i/10)][2] = aver_power/10
        aver_time=0
        aver_power=0
    else:
        aver_time += database[i][1]
        aver_power += database[i][2]

df = pd.DataFrame(aver_database, columns=['percent', 'time', 'power'])

labels = df.columns.to_list()
for i in range(len(labels)):
    s = set(df[labels[i]].values)
    cut = len(s)
    lis = list(s)
    lis.sort()
    if cut < 30:
        for j in range(cut):
            cut_lis = np.where(df[labels[i]] == lis[j])
            for k in cut_lis:
                df[labels[i]].iloc[k] = j
    else:
        df[labels[i]] = pd.cut(df[labels[i]], 10, duplicates="drop", labels = np.linspace(start = 0, stop = 10, num = 10, endpoint = False, dtype=int))

target = df['percent']
origin = df['time']
confounder = df[['power']]

target_category = target.drop_duplicates()
origin_category = origin.drop_duplicates()
confounder_category = confounder.drop_duplicates()
sum = 0
P_Wa_Metric = np.zeros((int(origin_category.max())+1, int(target_category.max())+1), dtype = float)
for oc in origin_category:  #   计算P(W=w|do(A=a))
    for tc in target_category:
        for cc in confounder_category.values:
            P_cc = len(df[(df['power'] == cc[0])])/100
            P_Wac = len(df[(df['percent'] == tc) & (df['power'] == cc[0]) & (df['time'] == oc)])/100
            P_ac = len(df[(df['power'] == cc[0]) & (df['time'] == oc)])/100
            if P_ac != 0:
                P_Wa_Metric[int(oc)][int(tc)] += P_cc*P_Wac/P_ac
            else:
                P_Wa_Metric[int(oc)][int(tc)] += 0
P_WUa_Metric = np.zeros((int(target_category.max())+1), dtype = float)
for oc in origin_category:  #   计算P(W=w|UA)
    for tc in target_category:
        P_WUa_Metric[int(tc)] += (1/len(origin_category)) * P_Wa_Metric[int(oc)][int(tc)]
time_EI = 0
for oc in origin_category:
    time_EI += (1/len(origin_category))*F.cross_entropy(torch.tensor(P_Wa_Metric[int(oc)]), torch.tensor(P_WUa_Metric))

target = df['percent']
origin = df['power']
confounder = df[['time']]

target_category = target.drop_duplicates()
origin_category = origin.drop_duplicates()
confounder_category = confounder.drop_duplicates()
sum = 0
P_Wa_Metric = np.zeros((int(origin_category.max())+1, int(target_category.max())+1), dtype = float)
for oc in origin_category:  #   计算P(W=w|do(A=a))
    for tc in target_category:
        for cc in confounder_category.values:
            P_cc = len(df[(df['time'] == cc[0])])/100
            P_Wac = len(df[(df['percent'] == tc) & (df['time'] == cc[0]) & (df['power'] == oc)])/100
            P_ac = len(df[(df['time'] == cc[0]) & (df['power'] == oc)])/100
            if P_ac != 0:
                P_Wa_Metric[int(oc)][int(tc)] += P_cc*P_Wac/P_ac
            else:
                P_Wa_Metric[int(oc)][int(tc)] += 0
P_WUa_Metric = np.zeros((int(target_category.max())+1), dtype = float)
for oc in origin_category:  #   计算P(W=w|UA)
    for tc in target_category:
        P_WUa_Metric[int(tc)] += (1/len(origin_category)) * P_Wa_Metric[int(oc)][int(tc)]
power_EI = 0
for oc in origin_category:
    power_EI += (1/len(origin_category))*F.cross_entropy(torch.tensor(P_Wa_Metric[int(oc)]), torch.tensor(P_WUa_Metric))

MI_metrics = np.zeros((3, 3), dtype=float)
for i in range(len(labels)):
    for j in range(i, len(labels)):
        score = metrics.mutual_info_score(df[labels[i]], df[labels[j]])
        MI_metrics[i,j] = score
        MI_metrics[j,i] = score
time_MI = MI_metrics[0,1]
power_MI = MI_metrics[0,2]
print("time_EI, power_EI, time_MI, power_MI: ", time_EI, power_EI, time_MI, power_MI)
with open('hit_rate(1027).csv', 'a+', newline='') as f:
    csv_write = csv.writer(f)
    time_EI = time_EI.numpy()
    power_EI = power_EI.numpy()
    data_row = [time_EI, power_EI, time_MI, power_MI]
    csv_write.writerow(data_row)