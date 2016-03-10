#import copy
from mc import *


#from enum import Enum
class Age:
    max = 1
    not_max = 0

    
maxSequenceNumber = 7 
    
#TODO: verify- if the router receives LSA with maxSequenceNumber, it also generates LSA with MaxAge??


class LSA:

    def __init__(self, src, dest, msg_type, LSID, AR, seqNum, linkID, metric, isOriginatedByAttacker, isMarked, counter):
        self.src = src
        self.dest = dest
        self.type = msg_type
        self.LSID = LSID
        self.AR = AR
        self.seqNum=seqNum
        self.linkID=linkID
        self.metric=metric
        self.isOriginatedByAttacker = isOriginatedByAttacker
        self.isMarked=isMarked
        self.counter=counter        
        self.age = Age.not_max
        
        
        
    def printLSA(self):
        
        print '[' + str(self.LSID) + ',' + str(self.AR) + ',' + str(self.seqNum) + ',' + str(self.linkID) + ',' + str(self.isOriginatedByAttacker)  +']'
        return
        
        



class Router:

    def __init__(self, ID ):
        self.queue = []
        self.DB = []
        self.ID = ID 
        self.timer = 0        
        self.calcRT_flag = False
        self.delayedFB = []
        self.lookup_policy = 0
        
        
    def updateTimer(self):
        if self.timer>0:
            self.timer-=1
        return
    
    def addLSA(self,lsa):
        self.DB.append(lsa)
        return
    
    
    def flood(self,m,r0,r1,r2):
        
        if self.ID==1:
            if m.src == 0:
                m.dest = 2
                m.src = 1
                #send m to 2
                r2.queue.append(m)  
            elif m.src==2:
                m.dest = 0
                m.src = 1
                r0.queue.append(m) 
        
        return
    
    
    
    def FB(self,r0,r1,r2):
        
        m = self.delayedFB.pop(0)
        if self.ID==0:
            r1.queue.append(m)
        elif self.ID==1:
            m.src=1
            m.dest=2
            r2.queue.append(m)
        elif self.ID==2:
            m.src=2
            m.dest=1
            r1.queue.append(m)
            #print 'send delayed FB to r1 with seq = ' + str(m.seqNum) + ' age = ' + str(m.age)
            
            
        
        return
    
    def RTCalc(self):
        reachables = [False]*routers_num
        if self.calcRT_flag:
            v = self.ID
            #handle router LSAs
            found = False
            for lsa in self.DB:
                if lsa.type=='routerLSA' and lsa.LSID==v:
                    found=True
                    break
            if found:
                #default database lookup
                index = 0
                delta=1
                if  self.lookup_policy==1:
                    index = len(self.DB)-1
                    delta=-1
                foundLSA=self.DB[0]
                for m in self.DB:
                    currlsa = self.DB[index]
                    if currlsa.LSID==v:
                        foundLSA=currlsa
                        break
                    index = index + delta
                

                if foundLSA.type=='routerLSA' and foundLSA.LSID==v:
                    w = foundLSA.linkID
                    w_index=0
                    delta=1
                    if self.lookup_policy==1:
                        w_index = len(self.DB)-1
                        delta=-1
                    for m in self.DB:
                        lsa = self.DB[w_index]
                        if lsa.LSID==w and lsa.linkID==v and lsa.type=='routerLSA':
                            foundLSA.isMarked=True
                            self.DB[w_index].isMarked=True
                            reachables[w]=True
                            break
                        w_index = w_index + delta
                        

                            
            for lsa in self.DB:
                if lsa.type=='summaryLSA' and reachables[lsa.AR]:
                    lsa.isMarked=True
                    
            self.calcRT_flag=False            
                
        
        
        return
    
    def handelLSAMsg(self,m,r0,r1,r2):
        #assume: m.type = 'routerLSA' or 'summaryLSA'
        #assume: m.src = 0 or 2 //valid neighbor
        
        should_flush = False
        if m.age == Age.max:
            should_flush = True
        
        #search for such LSA in DB
        found = False
        foundLSA = LSA(-1, -1, 'NA', -1, -1, -1, -1, -1, False, False, 0)
        #isGreaterSeqNum = False
        prevCounter=0
        prevIsFake=False
        index = 0
        for lsa in self.DB:
            if lsa.LSID == m.LSID and lsa.AR ==m.AR and lsa.type==m.type :
                found = True
                foundLSA = lsa
                #if m.seqNum > lsa.seqNum :
                #    isGreaterSeqNum = True
                prevCounter = lsa.counter
                prevIsFake = lsa.isOriginatedByAttacker 
                break
            index+=1
            
        if found==True and should_flush:
            #remove that LSA from the DB :
            del self.DB[index]
        
        #isGreaterSeqNum =
        #elif (found==False or isGreaterSeqNum) and (not should_flush) :  #LSA is newer than one in LSDB 
        elif (found==False or ((found==True) and (foundLSA.seqNum < m.seqNum ))) and (not should_flush) :  #LSA is newer than one in LSDB
            
            #flood m
            self.flood(m,r0,r1,r2)            
            
            if found==False:
                #add m to the DB
                self.DB.append(m)
                
            if m.AR == self.ID : #self-originated
                self.timer = MINLSINTERVAL
                #generate fight-back LSA
                #seq num incrementation  - check it doesn't reach max val, else flsuh is necessary before
                new_seq_num = m.seqNum+1
                #if m.seqNum >= maxSequenceNumber-1  : #LSA flush is needed
                print('cond from line 202 , or cond')
                if m.seqNum == maxSequenceNumber-1 or  m.seqNum == maxSequenceNumber  : #LSA flush is needed
                    #flush by setting max age
                    FlushingLSA = LSA(m.src, m.dest, m.type, m.AR, m.AR, new_seq_num, m.linkID, m.metric, False, False, 0)
                    FlushingLSA.age = Age.max
                    
                    #store Flushing LSA to be sent (delayed)
                    self.delayedFB.append(FlushingLSA)
                    
                    #distribute the flushing LSA to all neighbors 
                    
                    #generate FB msg with initial value 
                    new_seq_num = 0
                    
                print('cond from line 216') #just to check cond
                if(m.seqNum==5):
                    print 'check'
                    
                
                #generating the FB msg 
                FBM = LSA(m.src, m.dest, m.type, m.AR, m.AR, new_seq_num, m.linkID, m.metric, False, False, 0)
                self_index=0
                for l in self.DB:
                    if l.AR == self.ID and l.LSID == self.ID:
                        FBM.linkID = l.linkID
                        FBM.metric = l.metric
                        break
                    self_index = self_index+1
                
                
                
                #update self LSA entry based on FB msg 
                self.DB[self_index]=FBM
                
                
                #store fight-back LSA
                self.delayedFB.append(FBM)                
                
            
            else:
                if prevIsFake and m.isOriginatedByAttacker:  #counting consecutive occurrences of fake msgs in LSDB
                    m.counter=prevCounter
                else:
                    m.counter=0                
                self.DB[index]=m #update LSDB with the new LSA 
                
                self.calcRT_flag=True
                

        
        return
    
    def processRouterMessage(self,r0,r1,r2):
        #update counters in DB  --counters are calculated only for attacker's msgs
        for lsa in self.DB:
            if lsa.isOriginatedByAttacker :
                lsa.counter = lsa.counter+1
        
        #check if there is a message to process
        if len(self.queue) >0 :
            m = self.queue.pop(0) #TODO check
            if m.dest != self.ID :
                m.src = self.ID
                #get next hop
                nextHop=0
                if self.ID==1 :
                    if m.dest==0 :
                        nextHop = 0
                    else:
                        nextHop=2
                    
                elif self.ID==2 :
                    if m.dest<2 :
                        nextHop = 1
                    else:
                        nextHop=3
                    
                #send m to next hop
                if nextHop==1:
                    r1.addLSA(m) #TODO check
                elif nextHop==2:
                    r2.addLSA(m) #TODO check
            else:
                #handle lsa msg
                self.handelLSAMsg(m,r0,r1,r2)
            
            
        
        #handle delayed FB    
        if self.timer==0 and  len(self.delayedFB)>0 :   
            self.FB(r0,r1,r2)
            self.timer = MINLSINTERVAL
            
        
        
        #RT calculation 
        self.RTCalc()
            
        return            
                    
                
                
#def modelAttackerBehavior(seq1,seq2):    
    #(self, src, dest, msg_type, LSID, AR, seqNum, linkID, metric, isOriginatedByAttacker, isMarked, counter):
    

    
    #--------------------------------------------------------------
    
    #trigger and disguised LSA attack:
    #lsa = LSA(0,1,'routerLSA',2,2,1,1,2,True,False,0,False)
    #r1.queue.append(lsa)
    #lsa = LSA(0,1,'routerLSA',2,2,2,1,2,True,False,0,False)
    #r1.queue.append(lsa)
    #return 


MINLSINTERVAL = 2    
routers_num = 3
attacker = 0
min_counter=10
loop_bound=15





#def runModel(x,y,z,a,b,c):
def runModel(x):
    
    r0 = Router(0)
    r1 = Router(1)
    r2 = Router(2)
    
    
    seq = x
    policy = 1
    AR = 2
    lsid = 2
    linkID=1
    
    r1.lookup_policy = policy
    r2.lookup_policy = policy
    
    #init_DBs()
    lsa1 = LSA('NA','NA','routerLSA',1,1,0,2,1,False,True,0)
    lsa2 = LSA('NA','NA','routerLSA',2,2,0,1,1,False,True,0)
    
    r1.addLSA(lsa1)
    r1.addLSA(lsa2)
    
    r2.addLSA(lsa2)
    r2.addLSA(lsa1)

    for k in range(0,loop_bound):
        r0.processRouterMessage(r0,r1,r2)
        r1.processRouterMessage(r0,r1,r2)
        r2.processRouterMessage(r0,r1,r2)
        
#         #periodic injection
#         if k<13:
#             seq = k+1
#             #src, dest, msg_type, LSID, AR, seqNum, linkID, metric, isOriginatedByAttacker, isMarked, counter
#             lsa1 = LSA(0,1,'routerLSA',2,2,seq,1,2,True,False,0)
#             r1.queue.append(lsa1)
#         
        #-------------------------------------------------------------------------------------------------------------------
        
        if k==0:
#             #modelAttackerBehavior(x,y)
#             #send msg with abstract seqNum
#             #( src, dest, msg_type, LSID, AR, seqNum, linkID, metric, isOriginatedByAttacker, isMarked, counter):
            lsa = LSA(0,1,'routerLSA',lsid,AR,seq,linkID,2,True,False,0)
            r1.queue.append(lsa)
            
            #lsa = LSA(0,1,'routerLSA',a,b,c,linkID,2,True,False,0)
            #r1.queue.append(lsa)
#             #lsa1 = LSA(0,1,'routerLSA',2,2,y,1,2,True,False,0)
#             #r1.queue.append(lsa1)
#             
#             #lsa = LSA(0,1,'routerLSA',y,z,x,w,2,True,False,0)
#             #r1.queue.append(lsa)
#             
#             #A msg with LSID != AR --result depends on the lookup policy 
#             lsa = LSA(0,1,'routerLSA',2,0,1,1,2,True,False,0)
#             r1.queue.append(lsa)
#             #src, dest, msg_type, LSID, AR, seqNum, linkID, metric, isOriginatedByAttacker, isMarked, counter
        
        r0.updateTimer()
        r1.updateTimer()
        r2.updateTimer()
    

    #check if last configuration is stable indeed 
    if(len(r1.queue)>0):
        print('last configuration remains with non-empty queue for r1')
    if(len(r2.queue)>0):
        print('last configuration remains with non-empty queue for r2')        
    if(len(r1.delayedFB)>0):
        print('last configuration remains with non-empty delayedFB for r1')
    if(len(r2.delayedFB)>0):
        print('last configuration remains with non-empty delayedFB for r2')
    
    
    
    #print the final state of LSA-DBs in last configuration : 
    #noFakeLSA = True
    print('LSA DB of r1: ')    
    for lsa in r1.DB:
        lsa.printLSA()
        if lsa.isOriginatedByAttacker and lsa.isMarked and lsa.counter>min_counter:            
            print "fake lsa "

    print('LSA DB of r2: ')                
    for lsa in r2.DB:
        lsa.printLSA()
        if lsa.isOriginatedByAttacker and lsa.isMarked and lsa.counter>min_counter:            
            print "fake lsa "              
    
    print "done"
    
    return





#runModel(0,0,0,0,0,0)

#apply SE to generate test cases.
#mark each test case that represents an attack
#starting with one attacker's msg


#runModel(x)

x = BitVec("x", 4)
#y = BitVec("y", 4)
#z = BitVec("z", 4)
#a = BitVec("a", 4)
#b = BitVec("b", 4)
#c = BitVec("c", 4)
 # w = BitVec("w", 4)
 #mc_fuzz(lambda: runModel(x,y), [x,y], [0,0])
#mc_fuzz(lambda: runModel(x,y,z), [x,y,z], [0,0,0])
#mc_fuzz(lambda: runModel(x,y,z,a,b,c), [x,y,z,a,b,c], [0,0,0,0,0,0])
mc_fuzz(lambda: runModel(x), [x], [0])
 # mc_fuzz(lambda: runModel(x,y,z,w), [x,y,z,w], [0,0,0,0])

#runModel(0,0,1)    