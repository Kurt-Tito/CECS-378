# -*- coding: utf-8 -*-
"""
Created on Sat Apr 14 17:57:23 2018

@author: Kurt Tito
EE 381
"""

from scipy.special import comb

print("\n PART 1 \n")
# PART 1
#   Exercise 1: Calculating binomial probabiliity using its PMF.
# ------------------------------------------------
n = 5
x = 3
p = 0.7

C = comb(n, x)
q = 1 - p

prob = (C) * (p**x) * (q**(n-x))

print ('Calculated probabilty: ', prob)


#   Simulation 1: Simulating binomial probability
# ------------------------------------------------
import random

N = 10000 # The number of repititions 

n = 5
x = 3
p = 0.7

trial = [0] #single zero element list 
trial = trial*n # n elemnt list filled with zero's

j = 0 # accumulator variable initial value zero 

for k in range(N): # outer loop
    for i in range(n): #each binomial trial a sum of Bermoullie trials 
        
        r = random.uniform(0,1)
        
        if r < p:
            trial[i] = 1 # success
            #print("SUCCESS")
        else:
            trial[i] = 0 # failure
            #print("FAILURE")
            
    s = sum(trial)
    
    if s == x:
        j += 1 # recording the number of favorable trials 
        
prob = j / N # probability dtermined by frequency of favorable trials
print("")
print("Simulated Probability: ", prob) # output

print("\n PART 2 \n")
# PART 2
#   Exercise 2: Calculating Expected (Average) Value
# ------------------------------------------------

n = 5
p = 0.7

u = n*p
print("Expected (Average) Value: ", u)


#   Simulation 2: Simulating Expected value of binomial r.V. 
# ---------------------------------------------------
import random

N = 10000 # The number of repititions 

n = 5
x = 3
p = 0.7

trial = [0] #single zero element list 
trial = trial*n # n elemnt list filled with zero's

j = 0 # accumulator variable initial value zero 

for k in range(N): # outer loop
    for i in range(n): #each binomial trial a sum of Bermoullie trials 
        
        r = random.uniform(0,1)
        
        if r < p:
            trial[i] = 1 # success
            #print("SUCCESS")
        else:
            trial[i] = 0 # failure
            #print("FAILURE")
            
    s = sum(trial)
    
    if s == x:
        j += 1 # recording the number of favorable trials 
        
prob = j / N # probability dtermined by frequency of favorable trials
print("")
print("Simulated Expected (Average) Value: ", n*prob) # output


print("\n PART 3 \n")
# PART 3
# ----------------------------------------------------
import random
from scipy.stats import binom
import matplotlib.pyplot as plt
import numpy as np

N = 10000 # The number of repititions 

n = int(input("Enter number of trials "))
p = float(input("Enter Probability of Success "))

binomial_sim = data = binom.rvs(n, p, size = 10000)
print ("Average: ", np.mean(binomial_sim))
print ("SD: ", np.std(binomial_sim, ddof=1))
plt.hist(binomial_sim, bins = 10, normed = True)
plt.xlabel("x")
plt.ylabel("Probability of Succes")
plt.show()


